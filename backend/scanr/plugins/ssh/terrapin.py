"""Terrapin prefix-truncation exposure (CVE-2023-48795).

SSH's binary packet protocol numbers packets across the key exchange boundary,
but the transcript hash that the exchange signs does not cover that sequence
number. An attacker who can sit in the connection path can therefore delete
packets the client sent before the exchange completed, and the connection
continues with both sides believing the transcript matched.

The consequence is not decryption — it is silent removal of the messages that
negotiate *extensions*. Deleting the client's EXT_INFO strips
``server-sig-algs``, which can force a downgrade to SHA-1 signatures, and on
OpenSSH it strips the keystroke-timing countermeasure. Both sides see a clean,
authenticated session.

Two negotiable modes carry the flaw:

  * ``chacha20-poly1305@openssh.com`` — always affected;
  * any ``*-cbc`` cipher paired with an ``*-etm@openssh.com`` MAC.

The fix is the strict key exchange extension, which the server advertises as the
pseudo-algorithm ``kex-strict-s-v00@openssh.com``. A server offering that marker
is protected regardless of which ciphers it supports, so its presence is the
whole verdict and nothing else needs to be inferred.

Entirely passive: the check reads the server's KEXINIT and disconnects. No key
exchange is completed, nothing is authenticated, and no packet is ever modified.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssh._kexinit import KexInit, read_server_kexinit

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SSH_PORTS = [22, 2222]

STRICT_KEX_MARKER = "kex-strict-s-v00@openssh.com"
CHACHA_CIPHER = "chacha20-poly1305@openssh.com"
_CBC_SUFFIX = "-cbc"
_ETM_SUFFIX = "-etm@openssh.com"


def affected_modes(kexinit: KexInit) -> list[str]:
    """Negotiable modes that carry the prefix-truncation flaw.

    Each direction is evaluated on its own: CBC-EtM is only reachable when the
    same direction offers both a CBC cipher and an EtM MAC.
    """
    modes: list[str] = []

    if CHACHA_CIPHER in kexinit.encryption_c2s or CHACHA_CIPHER in kexinit.encryption_s2c:
        modes.append(CHACHA_CIPHER)

    for ciphers, macs, direction in (
        (kexinit.encryption_c2s, kexinit.mac_c2s, "client→server"),
        (kexinit.encryption_s2c, kexinit.mac_s2c, "server→client"),
    ):
        cbc = sorted(c for c in ciphers if c.endswith(_CBC_SUFFIX))
        etm = sorted(m for m in macs if m.endswith(_ETM_SUFFIX))
        if cbc and etm:
            modes.append(
                f"CBC-EtM ({direction}): {', '.join(cbc)} with {', '.join(etm)}"
            )
    return modes


def is_vulnerable(kexinit: KexInit) -> bool:
    """Strict key exchange closes the flaw outright, whatever the cipher list."""
    if kexinit.supports_kex(STRICT_KEX_MARKER):
        return False
    return bool(affected_modes(kexinit))


class TerrapinPlugin(PluginBase):
    id = "ssh.terrapin"
    name = "SSH Terrapin Prefix Truncation (CVE-2023-48795)"
    description = (
        "Detect SSH servers missing strict key exchange while offering "
        "ChaCha20-Poly1305 or CBC-EtM — the negotiable modes affected by Terrapin"
    )
    category = PluginCategory.ssh
    severity = Severity.medium
    cve_ids = ["CVE-2023-48795"]
    cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
    ports = SSH_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in SSH_PORTS or port.state != "open":
                continue
            kexinit = await self._read_kexinit(host.ip, port.number)
            if kexinit is None:
                continue
            if not is_vulnerable(kexinit):
                continue
            findings.append(self._build_finding(host.ip, port.number, kexinit))
        return findings

    @staticmethod
    async def _read_kexinit(ip: str, port: int) -> KexInit | None:
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, read_server_kexinit, ip, port)
        except Exception as exc:
            logger.debug("Terrapin KEXINIT read failed %s:%d: %s", ip, port, exc)
            return None

    def _build_finding(self, ip: str, port: int, kexinit: KexInit) -> FindingData:
        modes = affected_modes(kexinit)
        evidence = [
            f"{kexinit.banner or 'SSH server'} at {ip}:{port}",
            f"Strict key exchange ({STRICT_KEX_MARKER}) is NOT advertised in the "
            "server's kex_algorithms.",
            "Affected modes the server is willing to negotiate:",
            *(f"  - {mode}" for mode in modes),
            "",
            f"kex_algorithms: {', '.join(kexinit.kex_algorithms) or '(none read)'}",
            f"ciphers (s→c): {', '.join(kexinit.encryption_s2c) or '(none read)'}",
            f"MACs (s→c): {', '.join(kexinit.mac_s2c) or '(none read)'}",
        ]
        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="SSH Vulnerable to Terrapin Prefix Truncation (CVE-2023-48795)",
            description=(
                f"The SSH server on {ip}:{port} does not implement strict key exchange "
                "and still offers at least one cipher mode affected by the Terrapin "
                "attack. An attacker positioned in the connection path can delete "
                "packets sent before the key exchange completes without either side "
                "detecting a transcript mismatch.\n\n"
                "This does not decrypt the session. It silently removes the extension "
                "negotiation: dropping the client's EXT_INFO strips 'server-sig-algs' "
                "and can force public-key authentication down to SHA-1 signatures, and "
                "on OpenSSH it disables the keystroke-timing countermeasure. The "
                "session then proceeds looking entirely normal to both ends.\n\n"
                "Exploitation requires an active machine-in-the-middle position, which "
                "is why this is rated medium rather than high — but that position is "
                "exactly what an attacker already holds on a network where the other "
                "findings in this report apply."
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Upgrade both ends to an implementation with strict key exchange: "
                "OpenSSH 9.6+, PuTTY 0.80+, libssh 0.10.6/0.9.8+, Dropbear 2024.83+, "
                "AsyncSSH 2.14.2+, Go x/crypto/ssh from January 2024. Strict KEX is "
                "negotiated automatically once both sides support it, so no "
                "configuration change is needed after the upgrade.\n\n"
                "Where an endpoint cannot be upgraded, remove the affected modes from "
                "sshd_config instead — keep only AES-GCM "
                "('Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com'), which is "
                "unaffected. Note that dropping ChaCha20-Poly1305 alone is not "
                "sufficient if CBC ciphers and EtM MACs remain enabled together."
            ),
            references=[
                "https://terrapin-attack.com/",
                "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
                "https://www.openssh.com/txt/release-9.6",
            ],
            cve_ids=self.cve_ids,
            cvss_vector=self.cvss_vector,
            cvss_score=5.9,
            port_number=port,
            protocol="tcp",
            peer_review_command=f"ssh -vv -o BatchMode=yes {ip} -p {port} 2>&1 | grep -E 'kex-strict|cipher|MAC'",
        )
