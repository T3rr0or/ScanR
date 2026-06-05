"""FTP cleartext protocol detection.

FTP transmits credentials and data in plaintext. Unless the server negotiates
FTPS (AUTH TLS / explicit TLS), all traffic including passwords is interceptable
by any on-path observer. This check flags FTP services that do not support or
enforce TLS, regardless of whether anonymous access is permitted.
"""
from __future__ import annotations

import asyncio
import ftplib
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class FtpCleartextPlugin(PluginBase):
    id = "services.ftp_cleartext"
    name = "FTP Cleartext Protocol"
    description = "Detect FTP services that transmit credentials without TLS encryption"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [21]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in host.ports:
            if port.number != 21 or port.state != "open":
                continue
            result = await asyncio.get_running_loop().run_in_executor(
                None, self._check_tls, host.ip
            )
            if result is not None:
                banner, tls_supported = result
                if not tls_supported:
                    return [FindingData(
                        plugin_id=self.id,
                        severity=Severity.medium,
                        title="Insecure Protocol - FTP (Cleartext)",
                        description=(
                            "The FTP service does not negotiate TLS encryption (FTPS). "
                            "All data transferred over this connection — including usernames, "
                            "passwords, and file contents — is transmitted in plaintext and can "
                            "be intercepted by any on-path observer or captured from network taps."
                        ),
                        evidence=(
                            f"FTP service on {host.ip}:21 responded without TLS support. "
                            + (f"Banner: {banner}" if banner else "No banner captured.")
                        ),
                        remediation=(
                            "Migrate to SFTP (SSH File Transfer Protocol, port 22) or enforce "
                            "explicit FTPS by requiring AUTH TLS before any credentials are sent. "
                            "If FTP must be retained, configure the server to require AUTH TLS "
                            "('ssl_enable=YES', 'force_local_logins_ssl=YES' in vsftpd). "
                            "Disable plain FTP access entirely via firewall if SFTP is available."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1040/",
                            "https://cwe.mitre.org/data/definitions/319.html",
                            "https://datatracker.ietf.org/doc/html/rfc4217",
                        ],
                        port_number=21,
                        protocol="tcp",
                    )]
        return []

    def _check_tls(self, ip: str) -> tuple[str, bool] | None:
        """Connect to FTP, grab banner, probe AUTH TLS. Returns (banner, tls_ok) or None on connect failure."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=8)
            banner = ftp.getwelcome() or ""
            tls_supported = self._probe_auth_tls(ip, banner, ftp)
            try:
                ftp.quit()
            except Exception:
                pass
            return (banner.strip(), tls_supported)
        except OSError:
            return None
        except Exception as exc:
            logger.debug("FTP cleartext check failed for %s: %s", ip, exc)
            return None

    def _probe_auth_tls(self, ip: str, banner: str, ftp: ftplib.FTP) -> bool:
        """Return True if AUTH TLS succeeds or FEAT lists TLS/SSL."""
        # Check FEAT response first (no side-effects)
        try:
            feat_resp = ftp.sendcmd("FEAT")
            feat_upper = feat_resp.upper()
            if "AUTH TLS" in feat_upper or "AUTH SSL" in feat_upper:
                return True
        except Exception:
            pass

        # Try issuing AUTH TLS directly
        try:
            resp = ftp.sendcmd("AUTH TLS")
            if resp.startswith("234"):
                return True
        except ftplib.error_perm as e:
            # 502 = not implemented, 500/501 = syntax error
            code = str(e)[:3]
            if code in ("500", "501", "502", "530"):
                return False
        except Exception:
            pass

        return False
