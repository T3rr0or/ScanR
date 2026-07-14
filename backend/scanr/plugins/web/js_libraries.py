"""Vulnerable JavaScript library detection (retire.js-style).

Fingerprints front-end JS libraries served by a target — from the `<script src>`
URL/filename AND from the script's own content (version banners) — extracts the
version, and flags versions that fall in known-vulnerable ranges (jQuery, jQuery
UI, Bootstrap, AngularJS, lodash, Moment, Handlebars, Underscore, DOMPurify,
Axios). This is the class of finding a scanner like Burp reports ("outdated
jQuery with known CVEs") that header/TLS checks miss.

Detection is multi-signal and conservative: a library is only reported when a
concrete version is extracted, and the version is matched against curated CVE
ranges (boundaries mirror retire.js / the referenced advisories).
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443]

_MAX_SCRIPTS = 40           # external <script src> URLs to consider per page
_MAX_FETCHED = 25           # external scripts we actually download to fingerprint
_MAX_SCRIPT_BYTES = 300_000  # only scan the head of a script for a version banner
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


@dataclass
class _Lib:
    name: str
    label: str
    # Patterns matched against the script URL/filename (version in group 1).
    url_patterns: list[re.Pattern] = field(default_factory=list)
    # Patterns matched against script *content* (version in group 1).
    content_patterns: list[re.Pattern] = field(default_factory=list)


def _p(*patterns: str) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_V = r"(\d+\.\d+(?:\.\d+)?)"  # semver-ish version capture

# Order matters: more specific libraries (jquery-ui, jquery-migrate) before the
# generic jquery core so the core pattern doesn't swallow them.
_LIBS: list[_Lib] = [
    _Lib("jquery-ui", "jQuery UI",
         _p(rf"jquery[-.]ui(?:[-.][a-z]+)*[-.]{_V}", rf"/jqueryui/{_V}/", rf"/jquery\.ui/{_V}/"),
         _p(rf"jQuery UI[ -]v?{_V}", rf"\.ui\.version\s*=\s*[\"']{_V}[\"']")),
    _Lib("jquery-migrate", "jQuery Migrate",
         _p(rf"jquery[-.]migrate[-.]{_V}"),
         _p(rf"jQuery Migrate[ -]v?{_V}")),
    _Lib("jquery", "jQuery",
         _p(rf"jquery[-.]{_V}(?:\.min|\.slim)?\.js", rf"/jquery/{_V}/", rf"jquery\.min\.js\?(?:ver|v)=?{_V}"),
         _p(rf"jQuery (?:JavaScript Library )?v{_V}", rf"[\"']?jquery[\"']?\s*[:=]\s*[\"']{_V}[\"']")),
    _Lib("bootstrap", "Bootstrap",
         _p(rf"bootstrap[-.]{_V}(?:\.min)?\.js", rf"/bootstrap/{_V}/"),
         _p(rf"Bootstrap v{_V}")),
    _Lib("angularjs", "AngularJS",
         _p(rf"(?:^|[/_-])angular(?:\.min)?[-.]{_V}\.js", rf"/angular(?:js)?/{_V}/", rf"/angular\.js/{_V}/"),
         _p(rf"AngularJS v{_V}", rf"angular[\s\S]{{0,40}}?full\s*[:=]\s*[\"']{_V}[\"']")),
    _Lib("lodash", "Lodash",
         _p(rf"lodash(?:\.min)?[-.]?{_V}?\.js", rf"/lodash\.js/{_V}/", rf"/lodash/{_V}/"),
         _p(rf"@license lodash {_V}", rf"lodash[^\n]{{0,40}}?VERSION\s*=\s*[\"']{_V}[\"']")),
    _Lib("moment", "Moment.js",
         _p(rf"moment(?:\.min)?[-.]?{_V}?\.js", rf"/moment\.js/{_V}/", rf"/moment/{_V}/"),
         _p(rf"//! moment\.js[\s\S]{{0,200}}?version\s*[:=]\s*[\"']{_V}[\"']")),
    _Lib("handlebars", "Handlebars",
         _p(rf"handlebars(?:\.runtime)?(?:\.min)?[-.]?{_V}?\.js", rf"/handlebars\.js/{_V}/"),
         _p(rf"Handlebars\.VERSION\s*=\s*[\"']{_V}[\"']", rf"handlebars v{_V}")),
    _Lib("underscore", "Underscore.js",
         _p(rf"underscore(?:\.min)?[-.]?{_V}?\.js", rf"/underscore\.js/{_V}/"),
         _p(rf"underscore[^\n]{{0,40}}?VERSION\s*=\s*[\"']{_V}[\"']")),
    _Lib("dompurify", "DOMPurify",
         _p(rf"(?:dom)?purify(?:\.min)?[-.]?{_V}?\.js", rf"/dompurify/{_V}/"),
         _p(rf"DOMPurify[^\n]{{0,40}}?version\s*[:=]\s*[\"']{_V}[\"']", rf"VERSION\s*=\s*[\"']{_V}[\"'][\s\S]{{0,200}}?dompurify")),
    _Lib("axios", "Axios",
         _p(rf"axios(?:\.min)?[-.]?{_V}?\.js", rf"/axios/{_V}/"),
         _p(rf"axios[^\n]{{0,40}}?VERSION\s*[:=]\s*[\"']{_V}[\"']")),
]


@dataclass
class _Vuln:
    below: str                       # exclusive upper bound (fixed-in version)
    cves: list[str]
    summary: str
    severity: Severity
    at_or_above: str | None = None   # inclusive lower bound (range start)
    cvss: float | None = None


# Curated known-vulnerable ranges. Boundaries follow retire.js / the CVE advisories.
_VULN_DB: dict[str, list[_Vuln]] = {
    "jquery": [
        _Vuln("1.6.3", ["CVE-2011-4969"], "XSS via location.hash selector", Severity.medium, cvss=6.1),
        _Vuln("1.9.0", ["CVE-2012-6708"], "Selector interpreted as HTML → XSS", Severity.medium, cvss=6.1),
        _Vuln("3.0.0", ["CVE-2015-9251"], "Cross-domain AJAX responses executed as JS → XSS", Severity.medium, cvss=6.1),
        _Vuln("3.4.0", ["CVE-2019-11358"], "Prototype pollution via $.extend", Severity.medium, cvss=6.1),
        _Vuln("3.5.0", ["CVE-2020-11022", "CVE-2020-11023"], "XSS via htmlPrefilter passing untrusted HTML", Severity.medium, cvss=6.1),
    ],
    "jquery-ui": [
        _Vuln("1.12.0", ["CVE-2016-7103"], "XSS via dialog closeText option", Severity.medium, cvss=6.1),
        _Vuln("1.13.0", ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"], "XSS via *Text/altField/of options", Severity.medium, cvss=6.1),
    ],
    "bootstrap": [
        _Vuln("3.4.0", ["CVE-2018-14041", "CVE-2018-14042", "CVE-2019-8331"], "XSS via data-target / data-container (3.x)", Severity.medium, cvss=6.1),
        _Vuln("4.3.1", ["CVE-2019-8331"], "XSS in tooltip/popover data-template (4.x)", Severity.medium, at_or_above="4.0.0", cvss=6.1),
    ],
    "angularjs": [
        _Vuln("1.7.9", ["CVE-2019-10768"], "Prototype pollution via merge", Severity.high, cvss=7.5),
        _Vuln("1.8.0", ["CVE-2020-7676"], "XSS/content spoofing via <textarea>/SVG", Severity.medium, cvss=6.1),
        _Vuln("2.0.0", [], "AngularJS 1.x is end-of-life (unsupported since Jan 2022) — no security patches", Severity.medium, cvss=5.3),
    ],
    "lodash": [
        _Vuln("4.17.5", ["CVE-2018-3721"], "Prototype pollution", Severity.medium, cvss=6.5),
        _Vuln("4.17.11", ["CVE-2018-16487"], "Prototype pollution", Severity.medium, cvss=6.5),
        _Vuln("4.17.12", ["CVE-2019-10744"], "Prototype pollution via defaultsDeep", Severity.high, cvss=7.5),
        _Vuln("4.17.19", ["CVE-2020-8203"], "Prototype pollution via zipObjectDeep", Severity.high, cvss=7.5),
        _Vuln("4.17.21", ["CVE-2021-23337"], "Command injection via template", Severity.high, cvss=7.5),
    ],
    "moment": [
        _Vuln("2.29.2", ["CVE-2022-24785"], "Path traversal in locale loading", Severity.high, cvss=7.5),
        _Vuln("2.29.4", ["CVE-2022-31129"], "ReDoS via user-supplied date string", Severity.high, cvss=7.5),
    ],
    "handlebars": [
        _Vuln("4.3.0", ["CVE-2019-19919"], "Prototype pollution via crafted template", Severity.high, cvss=7.5),
        _Vuln("4.7.7", ["CVE-2021-23369", "CVE-2021-23383"], "RCE / prototype pollution via template compilation", Severity.high, cvss=8.1),
    ],
    "underscore": [
        _Vuln("1.12.1", ["CVE-2021-23358"], "Arbitrary code execution via template", Severity.high, at_or_above="1.3.2", cvss=7.2),
    ],
    "dompurify": [
        _Vuln("2.0.17", ["CVE-2020-26870"], "mXSS sanitization bypass", Severity.medium, cvss=6.1),
        _Vuln("2.2.4", [], "Mutation XSS sanitization bypass", Severity.medium, cvss=6.1),
    ],
    "axios": [
        _Vuln("0.21.1", ["CVE-2020-28168"], "SSRF via proxy bypass", Severity.medium, cvss=5.9),
        _Vuln("0.21.2", ["CVE-2021-3749"], "ReDoS via trim regex", Severity.medium, cvss=5.3),
        _Vuln("1.6.0", ["CVE-2023-45857"], "CSRF/SSRF token leaked via absolute URL", Severity.medium, at_or_above="0.8.1", cvss=6.5),
    ],
}

_SEV_ORDER = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}


def _ver_key(v: str) -> tuple[int, ...]:
    """Numeric version tuple for comparison. Pre-release suffixes are dropped."""
    core = re.split(r"[-+]", v.strip())[0]
    parts = []
    for chunk in core.split("."):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _in_range(version: str, vuln: _Vuln) -> bool:
    v = _ver_key(version)
    if vuln.at_or_above and v < _ver_key(vuln.at_or_above):
        return False
    return v < _ver_key(vuln.below)


def _detect(url: str, content: str | None) -> tuple[str, str] | None:
    """Return (library_name, version) detected from a script URL and/or content."""
    for lib in _LIBS:
        for pat in lib.url_patterns:
            m = pat.search(url)
            if m and m.group(1):
                return lib.name, m.group(1)
    if content:
        head = content[:_MAX_SCRIPT_BYTES]
        for lib in _LIBS:
            for pat in lib.content_patterns:
                m = pat.search(head)
                if m and m.group(1):
                    return lib.name, m.group(1)
    return None


def _label(name: str) -> str:
    for lib in _LIBS:
        if lib.name == name:
            return lib.label
    return name


class JsLibrariesPlugin(PluginBase):
    id = "web.js_libraries"
    name = "Vulnerable JavaScript Libraries"
    description = "Detect outdated front-end JS libraries (jQuery, Bootstrap, AngularJS, lodash, …) with known CVEs"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        # Prefer the hostname so name-based virtual hosts return the real app
        # (fetching by IP often hits a default/placeholder vhost with no scripts).
        authority = host.hostname or host.ip
        # Dedupe across ports: one finding per (library, version) per host.
        seen: set[tuple[str, str]] = set()
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base = f"{scheme}://{authority}:{port.number}/"
            try:
                detected = await self._scan_page(context, base)
                # If the vhost gave nothing but we used a hostname, retry by IP.
                if not detected and authority != host.ip:
                    detected = await self._scan_page(context, f"{scheme}://{host.ip}:{port.number}/")
            except Exception as exc:  # noqa: BLE001 - never let one port break the scan
                logger.debug("js_libraries: %s failed: %s", base, exc)
                continue
            for name, version, src in detected:
                key = (name, version)
                if key in seen:
                    continue
                seen.add(key)
                finding = self._build_finding(name, version, src, port.number)
                if finding:
                    findings.append(finding)
        return findings

    async def _scan_page(self, context: "ScanContext", base: str) -> list[tuple[str, str, str]]:
        """Fetch the page, extract scripts, and return (lib, version, source_url)."""
        results: list[tuple[str, str, str]] = []
        async with create_web_client(context, with_limits=True) as client:
            resp = await client.get(base, follow_redirects=True, timeout=10.0)
            html = resp.text
            page_url = str(resp.url)

            # 1) Inline scripts — some sites inline jQuery et al.
            for m in _INLINE_SCRIPT_RE.finditer(html):
                hit = _detect("", m.group(1))
                if hit:
                    results.append((hit[0], hit[1], f"{page_url} (inline)"))

            # 2) External scripts — try URL first (cheap), then fetch content.
            srcs = []
            for m in _SCRIPT_SRC_RE.finditer(html):
                srcs.append(urljoin(page_url, m.group(1)))
                if len(srcs) >= _MAX_SCRIPTS:
                    break

            # Any src not identified by URL gets its content fetched. We do NOT
            # require a .js extension — script bodies are always JS, and JSF/
            # framework resources are served as .xhtml/.faces/.js.xhtml etc.
            need_fetch: list[str] = []
            for src in srcs:
                hit = _detect(src, None)
                if hit:
                    results.append((hit[0], hit[1], src))
                else:
                    need_fetch.append(src)

            await self._fetch_and_detect(client, need_fetch[:_MAX_FETCHED], results)
        return results

    async def _fetch_and_detect(self, client, urls: list[str], results: list) -> None:
        sem = asyncio.Semaphore(8)

        async def one(u: str) -> None:
            async with sem:
                try:
                    r = await client.get(u, follow_redirects=True, timeout=6.0)
                    if r.status_code != 200:
                        return
                    hit = _detect(u, r.text)
                    if hit:
                        results.append((hit[0], hit[1], u))
                except Exception:  # noqa: BLE001 - a single script fetch failing is fine
                    return

        await asyncio.gather(*[one(u) for u in urls])

    def _build_finding(self, name: str, version: str, src: str, port: int) -> FindingData | None:
        matched = [v for v in _VULN_DB.get(name, []) if _in_range(version, v)]
        label = _label(name)
        if not matched:
            # Detected but not known-vulnerable — informational inventory entry.
            return FindingData(
                plugin_id=self.id,
                severity=Severity.info,
                title=f"JavaScript Library Detected: {label} {version}",
                description=f"{label} {version} is in use. No known vulnerabilities matched this version.",
                evidence=f"Source: {src}",
                remediation="Keep third-party libraries current and track advisories.",
                port_number=port,
                protocol="tcp",
            )
        sev = max((v.severity for v in matched), key=lambda s: _SEV_ORDER[s])
        cvss = max((v.cvss for v in matched if v.cvss is not None), default=None)
        cves: list[str] = []
        for v in matched:
            cves.extend(c for c in v.cves if c.startswith("CVE-") and c not in cves)
        issues = "; ".join(f"{', '.join(v.cves) or 'advisory'}: {v.summary}" for v in matched)
        fixed_in = max((v.below for v in matched), key=_ver_key)
        refs = ["https://github.com/RetireJS/retire.js"] + [
            f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves
        ]
        return FindingData(
            plugin_id=self.id,
            severity=sev,
            title=f"Outdated {label} {version} with known vulnerabilities",
            description=(
                f"The site serves {label} {version}, which has known security issues: {issues}. "
                "Vulnerable client-side libraries expose users to XSS, prototype pollution, and "
                "related attacks."
            ),
            evidence=f"Source: {src}\nDetected version: {version}\nAffected: {issues}",
            remediation=f"Upgrade {label} to {fixed_in} or later (latest stable recommended).",
            references=refs,
            cvss_score=cvss,
            cve_ids=cves,
            port_number=port,
            protocol="tcp",
            peer_review_command=f"curl -sk {src} | head -c 400",
        )
