"""WinRM access test — verify if domain credentials grant remote PowerShell access.

Windows Remote Management (WinRM) on port 5985/5986 allows remote
command execution. Finding that domain credentials work here is HIGH severity.
"""
from __future__ import annotations
import asyncio, logging
from typing import TYPE_CHECKING
from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class WinRMAccessPlugin(PluginBase):
    id = "services.winrm_access"
    name = "WinRM Authenticated Access"
    description = "Test if domain credentials grant WinRM remote execution access"
    category = PluginCategory.services
    severity = Severity.high
    requires_auth = True
    ports = [5985, 5986]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        open_ports = [p.number for p in host.ports if p.state == "open" and p.number in (5985, 5986)]
        if not open_ports:
            return []
        creds = context.credential("primary_domain") or context.credential("local_admin") or context.credential_data
        if not creds or not creds.get("username"):
            return []

        results = await asyncio.get_event_loop().run_in_executor(
            None, self._test_winrm, host.ip, creds.get("username", ""), creds.get("password", ""), creds.get("domain", ""), open_ports[0]
        )
        return results

    def _test_winrm(self, ip: str, username: str, password: str, domain: str, port: int) -> list[FindingData]:
        try:
            import httpx
        except ImportError:
            return []

        use_ssl = port == 5986
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{ip}:{port}/wsman"

        try:
            # WinRM uses NTLM/Kerberos — test by sending a basic SOAP envelope
            # A 401 with WWW-Authenticate: Negotiate/NTLM means WinRM is listening
            resp = httpx.get(url, timeout=10, verify=False)
            auth_header = resp.headers.get("www-authenticate", "").lower()

            if resp.status_code == 401 and ("ntlm" in auth_header or "negotiate" in auth_header or "basic" in auth_header):
                # Try NTLM auth
                try:
                    import requests
                    from requests_ntlm import HttpNtlmAuth
                    session = requests.Session()
                    session.verify = False
                    if domain:
                        ntlm_user = f"{domain}\\{username}"
                    else:
                        ntlm_user = username
                    auth = HttpNtlmAuth(ntlm_user, password)
                    test_resp = session.get(url, auth=auth, timeout=10)
                    if test_resp.status_code in (200, 405, 500):
                        return [FindingData(
                            plugin_id=self.id,
                            severity=Severity.high,
                            title="WinRM Access Confirmed with Domain Credentials",
                            description=(
                                f"The provided domain credentials successfully authenticated to WinRM on {ip}:{port}. "
                                "An attacker with these credentials could execute arbitrary commands remotely "
                                "via PowerShell remoting."
                            ),
                            evidence=f"WinRM endpoint: {url}\nAuthentication: NTLM\nUser: {ntlm_user}\nHTTP status: {test_resp.status_code}",
                            port_number=port,
                            protocol="tcp",
                            remediation="Restrict WinRM access to jump hosts and management networks via Windows Firewall. "
                                        "Enforce PowerShell Constrained Language Mode and script block logging.",
                        )]
                except Exception:
                    # Can't test NTLM auth — just report WinRM is exposed
                    return [FindingData(
                        plugin_id=self.id,
                        severity=Severity.medium,
                        title="WinRM Service Exposed — Requires Authentication",
                        description=f"WinRM is listening on {ip}:{port} and requires NTLM/Negotiate authentication.",
                        evidence=f"URL: {url}\nHTTP status: {resp.status_code}\nWWW-Authenticate: {auth_header}",
                        port_number=port,
                        protocol="tcp",
                        remediation="Restrict WinRM access to authorised management networks only.",
                    )]
        except Exception as exc:
            logger.debug("WinRM test failed on %s:%s — %s", ip, port, exc)

        return []
