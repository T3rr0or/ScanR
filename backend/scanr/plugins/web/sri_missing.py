"""Missing Subresource Integrity on third-party scripts and stylesheets.

Every `<script src>` a page loads from someone else's origin runs with the
page's full privileges: same DOM, same cookies, same localStorage. A stylesheet
is only slightly weaker — it can restyle a login form and exfiltrate keystroke
proxies through attribute selectors. Nothing in the browser checks that the
bytes a CDN returns today are the bytes the developer reviewed, unless the tag
carries an `integrity=` hash. Without it, whoever controls that CDN account,
that domain registration, or that npm publish key controls the application.

Scope is deliberately narrow, because the noisy version of this check is
useless:

* **Cross-origin only.** A same-origin `/static/app.js` gains nothing from SRI —
  an attacker who can rewrite it can rewrite the page's hashes too. Only a
  different host is reported.
* **Grouped per host.** One finding for the http:// resources and one for the
  https:// resources, each listing a capped sample, rather than a finding per
  `<script>` tag on a page that loads thirty of them.

Severity splits on the transport. An https:// CDN requires compromising the
provider; an http:// one requires only being on the network path, and any
coffee-shop router can rewrite the response. The http:// case is also mixed
content — modern browsers block it outright, so it is a functional bug as well.

Passive: this fetches pages as a normal client would and sends no payload.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import crawl, create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443]

# Non-greedy so adjacent comments are removed individually, and DOTALL so a
# multi-line conditional-comment block is matched whole.
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*\bsrc\s*=[^>]*>", re.I)
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"""\b([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")

_MAX_PAGES = 5      # pages inspected per port
_MAX_LISTED = 10    # resources named in one finding


def _attrs(tag: str) -> dict[str, str]:
    """Attribute map for one HTML tag, values lowercased only for the name."""
    out: dict[str, str] = {}
    for match in _ATTR_RE.finditer(tag):
        name = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        out.setdefault(name, value)
    return out


def _rel_is_stylesheet(rel: str) -> bool:
    # rel is a space-separated token list; "preload" with as=style is also
    # SRI-eligible, but only "stylesheet" is unambiguously executed as CSS.
    return "stylesheet" in rel.lower().split()


class _Resource:
    """A subresource reference, resolved against the page that loaded it."""

    __slots__ = ("url", "kind", "page", "host", "scheme")

    def __init__(self, url: str, kind: str, page: str, host: str, scheme: str) -> None:
        self.url = url
        self.kind = kind
        self.page = page
        self.host = host
        self.scheme = scheme


def _strip_comments(html: str) -> str:
    """Remove HTML comments before looking for subresources.

    A tag inside a comment is not a subresource. Conditional comments are the
    common case in the wild — `<!--[if lt IE 9]><script src=...><![endif]-->`
    still ships in a lot of vendored templates, and the browser never fetches
    it, so reporting a missing hash on it is a false positive. Found against a
    real Portainer install, whose page carries exactly that html5shim block.
    """
    return _COMMENT_RE.sub("", html)


def _extract(html: str, page_url: str) -> list[_Resource]:
    """Cross-origin scripts/stylesheets in `html` that carry no integrity hash."""
    html = _strip_comments(html)
    page_host = (urlparse(page_url).hostname or "").rstrip(".").lower()
    found: list[_Resource] = []
    seen: set[str] = set()

    candidates: list[tuple[dict[str, str], str]] = []
    for match in _SCRIPT_TAG_RE.finditer(html):
        attrs = _attrs(match.group(0))
        if attrs.get("src"):
            candidates.append((attrs, "script"))
    for match in _LINK_TAG_RE.finditer(html):
        attrs = _attrs(match.group(0))
        if attrs.get("href") and _rel_is_stylesheet(attrs.get("rel", "")):
            candidates.append((attrs, "stylesheet"))

    for attrs, kind in candidates:
        # An integrity attribute with an actual value is what we are looking
        # for; `integrity=""` is the same as having none.
        if attrs.get("integrity", "").strip():
            continue
        raw = attrs.get("src") if kind == "script" else attrs.get("href")
        if not raw:
            continue
        resolved = urljoin(page_url, raw)
        parsed = urlparse(resolved)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue  # data:, blob:, javascript: — nothing to verify
        host = parsed.hostname.rstrip(".").lower()
        if host == page_host:
            continue  # same origin: SRI adds no protection here
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append(_Resource(resolved, kind, page_url, host, parsed.scheme))
    return found


class SriMissingPlugin(PluginBase):
    id = "web.sri_missing"
    name = "Missing Subresource Integrity"
    description = (
        "Report third-party scripts and stylesheets loaded without an integrity "
        "hash, scored higher when they are fetched over plaintext HTTP"
    )
    category = PluginCategory.web
    severity = Severity.low
    intrusive = False
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        # Prefer the hostname: a name-based vhost usually serves the real app,
        # while the IP hits a default site with no third-party assets at all.
        authority = host.hostname or host.ip
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{authority}:{port.number}"
            try:
                resources = await self._collect(
                    context, base_url, host.ip, port.number, authority
                )
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("sri_missing: %s failed: %s", base_url, exc)
                continue
            findings.extend(self._build_findings(resources, port.number))
        return findings

    async def _collect(
        self, context, base_url: str, pin_ip: str, pin_port: int, authority: str
    ) -> list[_Resource]:
        resources: list[_Resource] = []
        seen: set[str] = set()
        # Pinned to the address the engine authorized. Addressing the target by
        # vhost name is deliberate (see above), but an unpinned client would
        # re-resolve that name at connect time and could be walked off-scope by
        # a low-TTL record part-way through a scan.
        async with create_web_client(
            context, pin_ip=pin_ip, pin_port=pin_port, pin_hostname=authority
        ) as client:
            crawled = await crawl(base_url, client)
            for path in (crawled.paths or ["/"])[:_MAX_PAGES]:
                page_url = f"{base_url}{path}"
                try:
                    resp = await client.get(page_url, timeout=8.0)
                except Exception:
                    continue
                if resp.status_code != 200:
                    continue
                if "html" not in resp.headers.get("content-type", "").lower():
                    continue
                for resource in _extract(resp.text, page_url):
                    if resource.url in seen:
                        continue
                    seen.add(resource.url)
                    resources.append(resource)
        return resources

    def _build_findings(self, resources: list[_Resource], port: int) -> list[FindingData]:
        insecure = [r for r in resources if r.scheme == "http"]
        secure = [r for r in resources if r.scheme == "https"]
        findings = []
        if insecure:
            findings.append(self._finding(insecure, port, over_http=True))
        if secure:
            findings.append(self._finding(secure, port, over_http=False))
        return findings

    def _finding(self, resources: list[_Resource], port: int, *, over_http: bool) -> FindingData:
        listed = resources[:_MAX_LISTED]
        hosts = sorted({r.host for r in resources})
        lines = "\n".join(f"  [{r.kind}] {r.url}\n    on page: {r.page}" for r in listed)
        overflow = (
            f"\n  ... and {len(resources) - len(listed)} more"
            if len(resources) > len(listed) else ""
        )
        transport = "over plaintext HTTP" if over_http else "over HTTPS"

        if over_http:
            severity, score = Severity.medium, 6.9
            vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N"
            risk = (
                "Because these are fetched over plaintext HTTP, no CDN compromise is "
                "needed: anyone on the network path between the visitor and the provider "
                "can rewrite the response and run their own JavaScript in this "
                "application's origin. Browsers also block this as mixed content on an "
                "HTTPS page, so the resource may already be failing to load."
            )
        else:
            severity, score = Severity.low, 3.7
            vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
            risk = (
                "TLS protects these in transit, but not from the provider itself. A "
                "compromised CDN account, an expired or hijacked provider domain, or a "
                "malicious package publish silently changes what every visitor executes, "
                "with no signal to the application."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"Third-party subresources loaded without Subresource Integrity ({transport})",
            description=(
                f"{len(resources)} cross-origin {'script/stylesheet' if len(resources) == 1 else 'scripts and stylesheets'} "
                f"loaded {transport} from {', '.join(hosts[:5])}"
                f"{' and others' if len(hosts) > 5 else ''} carry no `integrity` attribute. "
                "A third-party script runs with the same privileges as first-party code — "
                f"full DOM access, cookies, and stored tokens. {risk}"
            ),
            evidence=f"Missing integrity attribute on:\n{lines}{overflow}",
            remediation=(
                "Add `integrity=\"sha384-...\"` and `crossorigin=\"anonymous\"` to each "
                "third-party <script> and <link rel=stylesheet>, pinning an exact version "
                "so the hash stays valid (generate with `openssl dgst -sha384 -binary FILE "
                "| openssl base64 -A`). "
                + (
                    "Switch these references to https:// first — an http:// subresource "
                    "cannot be trusted even with a hash, since the browser will block it "
                    "as mixed content. "
                    if over_http else ""
                )
                + "Where a version must float, self-host the asset instead, and add a "
                "`require-sri-for script style` / restrictive `script-src` CSP as defence "
                "in depth."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                "https://www.w3.org/TR/SRI/",
                "https://cwe.mitre.org/data/definitions/494.html",
            ],
            cvss_score=score,
            cvss_vector=vector,
            port_number=port,
            protocol="tcp",
        )
