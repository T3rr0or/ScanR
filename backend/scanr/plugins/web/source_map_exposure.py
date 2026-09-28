"""JavaScript source maps served in production.

A bundler turns readable source into one minified file and, optionally, a
``.map`` sidecar that reverses the transformation. The sidecar is a development
aid; shipped to production it hands an attacker the application's original
source: directory layout, unminified function and variable names, comments,
in-progress feature flags, internal API paths, and — routinely — credentials a
developer left in a file that was never meant to leave the build machine.

This is not a heuristic. A source map that parses and carries a ``sources``
array *is* the source; the check reports what it actually read back rather than
inferring risk from a filename.

Two ways in are covered: the ``sourceMappingURL`` comment a bundler appends to
the minified file, and the convention of ``<script>.map`` sitting next to it,
which is still reachable on many servers after the comment has been stripped.

The recovered ``sources`` are also scanned for secrets, because an API key that
was minified out of the bundle is frequently still sitting in the map.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import unquote_to_bytes, urljoin, urlparse

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443]

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_SOURCE_MAPPING_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.I)

_MAX_SCRIPTS = 12
_MAX_MAPS_REPORTED = 10
_MAX_SOURCES_SHOWN = 25
# Maps are large by nature; read enough to parse and stop.
_MAX_MAP_BYTES = 8 * 1024 * 1024
_MAX_SCRIPT_BYTES = 4 * 1024 * 1024

# Secrets that survive minification and turn up in recovered sources. Kept
# deliberately narrow — each pattern matches a credential format, not a word
# that merely looks credential-shaped.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
)


@dataclass
class SourceMap:
    """A source map that was actually retrieved and parsed."""

    url: str
    script_url: str
    sources: list[str] = field(default_factory=list)
    has_contents: bool = False
    size: int = 0
    secrets: list[str] = field(default_factory=list)
    inline: bool = False


def extract_script_urls(html: str, page_url: str) -> list[str]:
    """Absolute URLs for same-origin scripts referenced by the page.

    Third-party scripts are skipped: a CDN's source map is the CDN's exposure,
    not this target's, and reporting it would put another party's URL in the
    customer's report.
    """
    origin = urlparse(page_url)
    urls: list[str] = []
    seen: set[str] = set()
    for raw in _SCRIPT_SRC_RE.findall(html):
        absolute = urljoin(page_url, raw.strip())
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.hostname != origin.hostname or parsed.port != origin.port:
            continue
        if not parsed.path.endswith((".js", ".mjs", ".cjs")):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        urls.append(absolute)
    return urls


def map_candidates(script_url: str, script_tail: str) -> list[str]:
    """Candidate map URLs for a script: the declared one, then the convention.

    A data: URI sourceMappingURL means the map is inlined in the bundle that was
    just read, so it is already exposed and needs no second request.
    """
    candidates: list[str] = []
    match = _SOURCE_MAPPING_RE.search(script_tail)
    if match:
        declared = match.group(1).strip().strip('"\'')
        if declared.lower().startswith("data:"):
            candidates.append(declared)
        else:
            candidates.append(urljoin(script_url, declared))
    conventional = script_url.split("?")[0] + ".map"
    if conventional not in candidates:
        candidates.append(conventional)
    return candidates


def decode_inline_map(uri: str) -> str | None:
    """Decode a bounded data URI without issuing a network request."""
    header, separator, payload = uri.partition(",")
    if not separator or len(header) > 256 or len(payload) > 3 * _MAX_MAP_BYTES:
        return None
    try:
        raw = unquote_to_bytes(payload)
        if header.lower().endswith(";base64"):
            if len(raw) > 4 * ((_MAX_MAP_BYTES + 2) // 3):
                return None
            raw = base64.b64decode(raw, validate=True)
        if len(raw) > _MAX_MAP_BYTES:
            return None
        return raw.decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error):
        return None


def parse_source_map(body: str) -> tuple[list[str], bool] | None:
    """Return (sources, has_sourcesContent) for a real source map, else None.

    A source map is a JSON object with a ``sources`` array; anything else — an
    HTML error page served with a 200, a JSON API response, a truncated body —
    is not a map and is not reported as one.
    """
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(document, dict):
        return None
    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        return None
    names = [str(entry) for entry in sources if isinstance(entry, (str, int, float))]
    if not names:
        return None
    contents = document.get("sourcesContent")
    return names, isinstance(contents, list) and any(
        isinstance(entry, str) and entry.strip() for entry in contents
    )


def find_secrets(body: str) -> list[str]:
    """Credential formats present in a retrieved map, by name and count."""
    hits: list[str] = []
    for label, pattern in _SECRET_PATTERNS:
        matches = pattern.findall(body)
        if matches:
            hits.append(f"{label} x{len(matches)}")
    return hits


class SourceMapExposurePlugin(PluginBase):
    id = "web.source_map_exposure"
    name = "JavaScript Source Map Exposure"
    description = (
        "Retrieve production .map files and report the original source paths, "
        "inlined source contents, and credentials they expose"
    )
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        authority = getattr(host, "hostname", None) or host.ip
        for port in host.ports:
            if not is_web_port(port):
                continue
            base_url = f"{web_scheme(port)}://{authority}:{port.number}"
            try:
                maps = await self._collect(context, base_url, host.ip, port.number, authority)
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("source_map_exposure: %s failed: %s", base_url, exc)
                continue
            if maps:
                findings.append(self._build_finding(maps, port.number))
        return findings

    async def _collect(
        self, context, base_url: str, pin_ip: str, pin_port: int, authority: str
    ) -> list[SourceMap]:
        found: list[SourceMap] = []
        tried: set[str] = set()
        async with create_web_client(
            context, pin_ip=pin_ip, pin_port=pin_port, pin_hostname=authority
        ) as client:
            try:
                page = await client.get(f"{base_url}/", timeout=8.0)
            except Exception:
                return []
            if page.status_code != 200 or "html" not in page.headers.get("content-type", "").lower():
                return []

            for script_url in extract_script_urls(page.text, f"{base_url}/")[:_MAX_SCRIPTS]:
                body = await self._script_body(client, script_url)
                if body is None:
                    continue
                for candidate in map_candidates(script_url, body):
                    if candidate in tried:
                        continue
                    tried.add(candidate)
                    if candidate.lower().startswith("data:"):
                        decoded = decode_inline_map(candidate)
                        source_map = self._parse_map(decoded, script_url, script_url, inline=True)
                    else:
                        source_map = await self._fetch_map(client, candidate, script_url)
                    if source_map is not None:
                        found.append(source_map)
                        break  # one confirmed map per script is enough
        return found

    @staticmethod
    async def _script_body(client, script_url: str) -> str | None:
        """Read the bounded bundle, including inline maps larger than a short tail."""
        try:
            response = await client.get(script_url, timeout=8.0)
        except Exception:
            return None
        if response.status_code != 200:
            return None
        if len(response.content) > _MAX_SCRIPT_BYTES:
            return ""  # Still try the conventional sidecar without parsing a truncated bundle.
        return response.text

    @staticmethod
    async def _fetch_map(client, url: str, script_url: str) -> SourceMap | None:
        try:
            response = await client.get(url, timeout=10.0)
        except Exception:
            return None
        if response.status_code != 200:
            return None
        body = response.text[:_MAX_MAP_BYTES]
        source_map = SourceMapExposurePlugin._parse_map(body, url, script_url)
        if source_map is not None:
            source_map.size = len(response.content)
        return source_map

    @staticmethod
    def _parse_map(body: str | None, url: str, script_url: str, *, inline: bool = False) -> SourceMap | None:
        if body is None:
            return None
        parsed = parse_source_map(body)
        if parsed is None:
            return None
        sources, has_contents = parsed
        return SourceMap(
            url=url,
            script_url=script_url,
            sources=sources,
            has_contents=has_contents,
            size=len(body.encode("utf-8")),
            inline=inline,
            secrets=find_secrets(body),
        )

    def _build_finding(self, maps: list[SourceMap], port: int) -> FindingData:
        with_contents = [m for m in maps if m.has_contents]
        with_secrets = [m for m in maps if m.secrets]

        if with_secrets:
            severity = Severity.high
        elif with_contents:
            severity = Severity.medium
        else:
            severity = Severity.low

        evidence: list[str] = []
        for source_map in maps[:_MAX_MAPS_REPORTED]:
            if source_map.inline:
                evidence.append(f"Inline source map in {source_map.script_url} ({source_map.size} decoded bytes)")
            else:
                evidence.append(f"GET {source_map.url} → 200 ({source_map.size} bytes)")
            evidence.append(f"  referenced by: {source_map.script_url}")
            evidence.append(
                f"  sources: {len(source_map.sources)} original file(s); "
                f"sourcesContent: {'present — full source recoverable' if source_map.has_contents else 'absent'}"
            )
            for name in source_map.sources[:_MAX_SOURCES_SHOWN]:
                evidence.append(f"    {name}")
            if len(source_map.sources) > _MAX_SOURCES_SHOWN:
                evidence.append(
                    f"    [... {len(source_map.sources) - _MAX_SOURCES_SHOWN} more]"
                )
            if source_map.secrets:
                evidence.append(f"  credentials found in map: {', '.join(source_map.secrets)}")
        if len(maps) > _MAX_MAPS_REPORTED:
            evidence.append(f"[... {len(maps) - _MAX_MAPS_REPORTED} more source maps omitted]")

        description = [
            f"{len(maps)} JavaScript source map(s) are served from this host. A source "
            "map reverses minification, so these files return the application's "
            "original source rather than the shipped bundle."
        ]
        if with_contents:
            description.append(
                f"{len(with_contents)} of them include 'sourcesContent', which embeds the "
                "complete original files. The application's client-side source can be "
                "reconstructed in full from this host, with comments and original "
                "identifiers intact."
            )
        else:
            description.append(
                "These maps expose the original file and directory names but not the file "
                "bodies. That still hands an attacker the project's internal structure, "
                "framework and module layout, and the names of routes and components that "
                "minification was hiding."
            )
        if with_secrets:
            description.append(
                "At least one map contains credential material. A secret that was "
                "stripped from the minified bundle is still present in the map, so the "
                "minification provided no protection at all. Treat the listed "
                "credentials as disclosed and rotate them."
            )
        description.append(
            "Recovered source is the starting point for every other finding in a web "
            "assessment: it names the API endpoints that are not linked from any page, "
            "the parameters each one accepts, the client-side authorisation checks worth "
            "bypassing, and any feature still behind a flag."
        )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=(
                "Source Maps Expose Application Source and Credentials"
                if with_secrets
                else "JavaScript Source Maps Served in Production"
            ),
            description="\n\n".join(description),
            evidence="\n".join(evidence),
            remediation=(
                "Stop emitting maps in production builds, or stop serving them. "
                "webpack: 'devtool: false' for the production config. Vite: "
                "'build.sourcemap: false'. Next.js: 'productionBrowserSourceMaps: "
                "false' (the default). Create React App: 'GENERATE_SOURCEMAP=false'.\n\n"
                "Where maps are needed for error reporting, upload them to the error "
                "tracker at build time and keep them out of the deployed artifact — "
                "Sentry, Rollbar and Datadog all support this. If they must exist on "
                "the server, block '*.map' at the web server or CDN and confirm the "
                "block returns 404 rather than 403, so the path does not confirm the "
                "file's existence.\n\n"
                "Removing the sourceMappingURL comment alone is not sufficient: the "
                "conventional '<bundle>.js.map' path stays reachable, and this check "
                "tries it for exactly that reason. Rotate any credential the maps "
                "exposed — it is public until it is rotated."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                "https://developer.chrome.com/docs/devtools/javascript/source-maps",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -s https://<host>:{port}/<bundle>.js.map | jq '.sources | length, .[0:5]'"
            ),
        )
