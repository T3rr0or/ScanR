"""Web cache deception through path confusion.

A CDN or reverse proxy decides what to cache from the URL's extension, while the
application behind it decides what to serve from its own routing. When those two
disagree, a request for ``/account/anything.css`` reaches the application as
``/account`` — it serves the logged-in user's page — and reaches the cache as a
stylesheet, which it stores as a public static asset.

The result is that a victim's authenticated page ends up in a shared cache under
a URL the attacker chose, and the attacker fetches it. No XSS, no CSRF token
needed, and the victim never leaves the application: the attacker only has to get
them to load one URL once.

The check proves both halves rather than inferring either:

1. The suffixed URL returns *the same dynamic page* as the clean path — that is
   the routing confusion.
2. The response is stored by a shared cache — confirmed by a second identical
   request coming back with ``Age``, ``X-Cache: HIT`` or an equivalent marker,
   or by cache-control headers that permit public storage.

The suffix is a random filename unique to this scan, so the entry this check
writes into the cache is at a URL no real user will ever request. The check is
nonetheless classified as state-changing: it deliberately stores an entry in an
intermediary the whole user base shares, and that is not something to do outside
an explicitly aggressive scan.
"""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

# Paths that usually serve per-user or otherwise dynamic content. The root is
# last because a generic landing page should not use the probe budget before
# account and other potentially private routes have been checked.
_BASE_PATHS = (
    "/account",
    "/profile",
    "/dashboard",
    "/settings",
    "/home",
    "/user",
    "/api/me",
    "/",
)

# Delimiters that separate "what the application routes on" from "what the cache
# keys on". Each is a real, documented confusion; %00 and %0a are omitted because
# a NUL or newline in a path is more likely to be rejected than confused.
_DELIMITERS = ("/", ";", "%2f", "%3f", "%23")

_STATIC_EXTENSIONS = (".css", ".js", ".jpg")

# Headers a shared cache sets when it served a stored copy.
_HIT_HEADERS = (
    "x-cache",
    "cf-cache-status",
    "x-cache-status",
    "x-drupal-cache",
    "x-varnish-cache",
    "x-proxy-cache",
    "cdn-cache",
    "x-vercel-cache",
    "x-nextjs-cache",
    "fastly-cache",
)
_HIT_VALUES = ("hit", "cached", "stale")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_VOLATILE_RE = re.compile(r"[0-9a-f]{16,}|\d", re.I)

_MAX_PROBES = 12
_MIN_BODY_BYTES = 256
_LENGTH_TOLERANCE = 0.1


@dataclass
class CacheEvidence:
    """One confirmed path-confusion result."""

    base_path: str
    probe_path: str
    status_code: int
    cached: bool
    cache_headers: dict[str, str]
    body_bytes: int


def normalise_body(body: str) -> str:
    """Strip whitespace and volatile tokens so two renders of a page compare equal.

    CSRF tokens, timestamps, request ids and counters differ between two requests
    for the same page; without removing them no dynamic page would ever match
    itself.
    """
    collapsed = re.sub(r"\s+", " ", body).strip()
    return _VOLATILE_RE.sub("", collapsed)


def bodies_match(first: str, second: str) -> bool:
    """True when two responses are the same page rather than merely both HTML.

    Requires a matching <title> when one exists, and comparable length. A generic
    error page and a real account page are both HTML of similar size, so the
    title is what keeps this from being a coincidence.
    """
    if len(first) < _MIN_BODY_BYTES or len(second) < _MIN_BODY_BYTES:
        return False

    first_title = _TITLE_RE.search(first)
    second_title = _TITLE_RE.search(second)
    if bool(first_title) != bool(second_title):
        return False
    if first_title and second_title:
        if first_title.group(1).strip() != second_title.group(1).strip():
            return False

    left, right = normalise_body(first), normalise_body(second)
    if not left or not right:
        return False
    if left == right:
        return True
    shorter, longer = sorted((len(left), len(right)))
    return longer > 0 and shorter / longer >= (1 - _LENGTH_TOLERANCE)


def cache_hit_headers(headers: dict[str, str]) -> dict[str, str]:
    """Headers showing the response came from, or was stored in, a shared cache."""
    found: dict[str, str] = {}
    lowered = {key.lower(): value for key, value in headers.items()}
    for name in _HIT_HEADERS:
        value = lowered.get(name, "")
        if value and any(marker in value.lower() for marker in _HIT_VALUES):
            found[name] = value
    age = lowered.get("age", "")
    if age.strip().isdigit() and int(age.strip()) > 0:
        found["age"] = age
    return found


def publicly_cacheable(headers: dict[str, str]) -> bool:
    """True when nothing in the response forbids a shared cache from storing it."""
    lowered = {key.lower(): value.lower() for key, value in headers.items()}
    directives = lowered.get("cache-control", "")
    if any(token in directives for token in ("no-store", "private", "no-cache")):
        return False
    if "public" in directives:
        return True
    match = re.search(r"max-age\s*=\s*(\d+)", directives)
    if match and int(match.group(1)) > 0:
        return True
    # No Cache-Control at all leaves storage to the intermediary's heuristics,
    # which for a .css URL means it is very likely to be cached.
    return not directives


def build_probe_path(base_path: str, delimiter: str, filename: str) -> str:
    """Append a static-looking filename to `base_path` after `delimiter`.

    The root path has no base segment to confuse, so the delimiter attaches
    directly to "/" — which still matters for single-page applications, where the
    server serves index.html for any unmatched path.
    """
    cleaned = base_path.rstrip("/")
    if not cleaned:
        return f"/{filename}" if delimiter == "/" else f"/{delimiter}{filename}"
    return f"{cleaned}{delimiter}{filename}"


class CacheDeceptionPlugin(PluginBase):
    id = "web.cache_deception"
    name = "Web Cache Deception"
    description = (
        "Detect path confusion where a dynamic page is served under a "
        "static-looking URL and stored by a shared cache"
    )
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        authority = getattr(host, "hostname", None) or host.ip
        for port in host.ports:
            if not is_web_port(port):
                continue
            base_url = f"{web_scheme(port)}://{authority}:{port.number}"
            try:
                evidence = await self._probe_port(
                    context, base_url, host.ip, port.number, authority
                )
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("cache_deception: %s failed: %s", base_url, exc)
                continue
            if evidence is not None:
                findings.append(self._build_finding(base_url, evidence, port.number))
        return findings

    async def _probe_port(
        self, context, base_url: str, ip: str, port: int, authority: str
    ) -> CacheEvidence | None:
        # Unique per run, so the cache entry this creates is at a URL no real
        # user will request.
        filename = f"scanr-{secrets.token_hex(6)}"
        async with create_web_client(
            context, pin_ip=ip, pin_port=port, pin_hostname=authority
        ) as client:
            baselines: list[tuple[str, str]] = []
            for base_path in _BASE_PATHS:
                baseline = await self._get(client, f"{base_url}{base_path}")
                if baseline is None:
                    continue
                status, headers, body = baseline
                if status != 200 or "html" not in headers.get("content-type", "").lower():
                    continue
                baselines.append((base_path, body))

            # Try each viable route once before spending more probes on any one
            # route. A landing page can accept every suffix while a private
            # route may need only one specific delimiter to expose a flaw.
            probes = 0
            for delimiter in _DELIMITERS:
                for extension in _STATIC_EXTENSIONS:
                    for base_path, body in baselines:
                        if probes >= _MAX_PROBES:
                            return None
                        probes += 1
                        probe_path = build_probe_path(
                            base_path, delimiter, filename + extension
                        )
                        evidence = await self._confirm(
                            client, base_url, base_path, probe_path, body
                        )
                        if evidence is not None:
                            return evidence
        return None

    async def _confirm(
        self, client, base_url: str, base_path: str, probe_path: str, baseline_body: str
    ) -> CacheEvidence | None:
        first = await self._get(client, f"{base_url}{probe_path}")
        if first is None:
            return None
        status, headers, body = first
        if status != 200:
            return None
        if not bodies_match(baseline_body, body):
            return None

        hits = cache_hit_headers(headers)
        if not hits:
            # A second identical request is what distinguishes "a cache stored
            # this" from "the origin will happily serve it twice".
            second = await self._get(client, f"{base_url}{probe_path}")
            if second is not None:
                hits = cache_hit_headers(second[1])
                headers = second[1] if hits else headers

        cached = bool(hits)
        if not cached and not publicly_cacheable(headers):
            # Path confusion without any prospect of storage is a routing quirk,
            # not a disclosure. Do not report it.
            return None

        return CacheEvidence(
            base_path=base_path,
            probe_path=probe_path,
            status_code=status,
            cached=cached,
            cache_headers=hits or {
                key: value
                for key, value in headers.items()
                if key.lower() in ("cache-control", "expires", "vary", "content-type")
            },
            body_bytes=len(body),
        )

    @staticmethod
    async def _get(client, url: str) -> tuple[int, dict[str, str], str] | None:
        try:
            response = await client.get(url, timeout=8.0)
        except Exception:
            return None
        return response.status_code, dict(response.headers), response.text

    def _build_finding(
        self, base_url: str, evidence: CacheEvidence, port: int
    ) -> FindingData:
        # Confirmed storage is the difference between "this can be cached" and
        # "this is being cached".
        severity = Severity.high if evidence.cached else Severity.medium

        header_lines = "\n".join(
            f"  {key}: {value}" for key, value in sorted(evidence.cache_headers.items())
        )
        confirmation = (
            "A second identical request returned a cache-hit marker, so a shared cache "
            "is storing this response."
            if evidence.cached
            else "No cache-hit marker was observed, but the response headers permit a "
            "shared cache to store it, so any CDN or proxy in front of this "
            "application is likely to."
        )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=(
                "Web Cache Deception — Dynamic Page Cached Under a Static URL"
                if evidence.cached
                else "Web Cache Deception — Dynamic Page Served Under a Cacheable Static URL"
            ),
            description=(
                f"Requesting {base_url}{evidence.probe_path} returns the same dynamic page "
                f"as {base_url}{evidence.base_path}. The application ignores the appended "
                "filename and routes on the base path, while a cache in front of it sees a "
                "static file extension.\n\n"
                "An attacker exploits this by getting a logged-in victim to load one such "
                "URL — a link in an email, an image tag on any page, anything that causes "
                "one request. The victim's browser sends their session cookie, the "
                "application renders their authenticated page, and the cache stores that "
                "response as a public static asset under a URL the attacker chose. The "
                "attacker then fetches the same URL, unauthenticated, and reads the "
                "victim's page: personal data, account details, and frequently a CSRF "
                "token or API key embedded in the markup.\n\n"
                f"{confirmation}"
            ),
            evidence=(
                f"GET {base_url}{evidence.base_path} → 200 (dynamic HTML, baseline)\n"
                f"GET {base_url}{evidence.probe_path} → {evidence.status_code} "
                f"({evidence.body_bytes} bytes)\n"
                "Response body matched the baseline page (title and normalised content), "
                "so the appended filename was ignored by the application.\n\n"
                "Relevant response headers:\n"
                f"{header_lines or '  (none)'}\n\n"
                "The probe filename is unique to this scan, so any entry stored in the "
                "cache is at a URL no legitimate user requests."
            ),
            remediation=(
                "Make the cache and the application agree on what the URL means. In order "
                "of durability:\n\n"
                "1. Cache on the response, not the URL. Configure the CDN to cache only "
                "responses that carry an explicit 'Cache-Control: public' and to respect "
                "'private'/'no-store' — never on file extension alone. This is the fix "
                "that holds regardless of how the application routes.\n\n"
                "2. Send correct cache directives from the application: "
                "'Cache-Control: no-store, private' on every authenticated response. Set "
                "it as a default for authenticated routes rather than per handler.\n\n"
                "3. Stop the routing confusion: return 404 for a path with an unexpected "
                "trailing segment instead of silently ignoring it, and disable path "
                "parameters (';') and duplicate-slash normalisation differences between "
                "the proxy and the application.\n\n"
                "Cloudflare: use Cache Rules with 'Respect origin cache control' and "
                "avoid 'Cache Everything' on paths that can serve authenticated content. "
                "Varnish: remove the extension-based caching shortcut from vcl_recv. "
                "Nginx proxy_cache: set 'proxy_cache_bypass' on the session cookie."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/",
                "https://portswigger.net/research/web-cache-entanglement",
                "https://cpdos.org/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -s -o /dev/null -D - '{base_url}{evidence.probe_path}' | "
                "grep -iE 'x-cache|cf-cache-status|age:|cache-control'"
            ),
        )
