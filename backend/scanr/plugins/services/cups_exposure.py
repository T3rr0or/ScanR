"""CUPS web interface exposure detection (TCP 631).

CUPS binds to localhost by default, so a CUPS interface answering on a routable
address is already a deliberate (or accidental) ``Listen *:631``. The web
interface is not a status page: /admin can add a printer, and a printer's device
URI is an arbitrary backend invocation, which is why an unauthenticated CUPS
admin interface has repeatedly been an execution primitive rather than a
disclosure. Even without /admin, /printers and /jobs disclose the printer
inventory, the internal hostnames behind each queue, and the usernames and
document titles of everything recently printed.

Everything here is a GET. We never POST, never submit an admin form, and never
touch a print queue.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

CUPS_PORT = 631

# Ordered: the first path is what identifies the service, the rest grade it.
_PATHS = ("/", "/admin", "/printers", "/jobs?which_jobs=all")

# Statuses that mean "the server handed us the page".
_OK = 200
# 401/403 = authentication or policy enforced; 426 = CUPS demanding TLS first.
# All three are the server doing its job, so none of them is a finding.
_PROTECTED = {401, 403, 426}


def _is_cups(status: int, headers: dict, body: str) -> bool:
    """Confirm we are really looking at CUPS before reporting anything."""
    server = str(headers.get("server", "")).upper()
    if "CUPS" in server:
        return True
    if status != _OK:
        return False
    lowered = body.lower()
    # The stock templates all carry this pairing; requiring two markers keeps a
    # random web app that merely mentions "cups" from matching.
    return "cups" in lowered and ("common unix printing system" in lowered or "cups.org" in lowered)


class CupsExposurePlugin(PluginBase):
    id = "services.cups_exposure"
    name = "CUPS Web Interface Exposure"
    description = "Detect CUPS print server web interfaces reachable without authentication"
    category = PluginCategory.services
    severity = Severity.high
    ports = [CUPS_PORT]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number != CUPS_PORT or port.state != "open":
                continue
            results: dict[str, tuple[str, int, dict, str]] = {}
            try:
                for path in _PATHS:
                    fetched = await self._fetch(context, host.ip, port.number, path)
                    if fetched is not None:
                        results[path] = fetched
                    if path == "/" and not results:
                        # Nothing answered at all — no point walking the rest.
                        break
            except Exception:
                logger.debug("cups_exposure: probe failed for %s:%d", host.ip, port.number, exc_info=True)
                continue
            finding = self._analyze(host.ip, port.number, results)
            if finding:
                findings.append(finding)
        return findings

    async def _fetch(
        self, context, ip: str, port: int, path: str
    ) -> tuple[str, int, dict, str] | None:
        """GET one path, trying HTTPS first (CUPS often enforces TLS on 631)."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config()
                ) as client:
                    resp = await client.get(url)
                    return url, resp.status_code, dict(resp.headers), resp.text
            except Exception:
                continue
        return None

    def _analyze(
        self, ip: str, port: int, results: dict[str, tuple[str, int, dict, str]]
    ) -> FindingData | None:
        root = results.get("/")
        confirmed = any(
            _is_cups(status, headers, body) for _url, status, headers, body in results.values()
        )
        if not confirmed:
            # Something is listening on 631 but it is not CUPS (or it refused
            # everything) — reporting it would be a guess.
            return None

        server_banner = ""
        if root:
            server_banner = str(root[2].get("server", "")) or ""

        reachable = {
            path: value for path, value in results.items() if value[1] == _OK
        }
        if not reachable:
            # CUPS answered, but every page was 401/403/426 — correctly locked down.
            return None

        admin_open = "/admin" in reachable
        evidence_parts = []
        for _path, (url, status, _headers, body) in reachable.items():
            evidence_parts.append(f"GET {url} -> HTTP {status} ({len(body)} bytes)")
        for _path, (url, status, _headers, _body) in results.items():
            if status in _PROTECTED:
                evidence_parts.append(f"GET {url} -> HTTP {status} (protected)")
        if server_banner:
            evidence_parts.append(f"Server: {server_banner}")

        if admin_open:
            severity = Severity.high
            title = "CUPS Administration Interface Reachable Without Authentication"
            impact = (
                "The /admin page was served without credentials. From there an attacker can "
                "add a printer whose device URI points at an arbitrary backend or host, "
                "change server configuration, and cancel or redirect other users' print "
                "jobs. Adding a queue with an attacker-chosen device URI or PPD has "
                "historically been the pivot from an exposed CUPS interface to command "
                "execution on the print server."
            )
        else:
            severity = Severity.medium
            title = "CUPS Web Interface Reachable Without Authentication"
            impact = (
                "The administration page itself is protected, but the printer and job "
                "listings were served without credentials. These disclose the printer "
                "inventory, the internal hostnames and device URIs behind each queue, and "
                "the usernames and document titles of recent print jobs — useful "
                "reconnaissance for mapping the internal network and its users."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=(
                f"A CUPS print server on port {port} serves its web interface to "
                f"unauthenticated requests. {impact} CUPS listens on localhost only in its "
                "default configuration, so reachability from the network means the "
                "'Listen'/'Port' directive was widened."
            ),
            evidence="; ".join(evidence_parts),
            remediation=(
                "In cupsd.conf, replace 'Listen *:631' / 'Port 631' with "
                "'Listen localhost:631' so the interface is not exposed to the network. "
                "If remote administration is genuinely needed, wrap the /admin, /admin/conf "
                "and /admin/log locations in a Policy requiring 'AuthType Default' with "
                "'Require user @SYSTEM', and add 'Encryption Required'. "
                "Restrict the remaining Locations with 'Order allow,deny' and an explicit "
                "'Allow from' list rather than 'Allow from all'. "
                "Firewall TCP and UDP 631 at the perimeter, and keep cups up to date."
            ),
            references=[
                "https://openprinting.github.io/cups/doc/man-cupsd.conf.html",
                "https://openprinting.github.io/cups/doc/security.html",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
            port_number=port,
            protocol="tcp",
        )
