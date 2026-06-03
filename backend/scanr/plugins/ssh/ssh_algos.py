from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-gex-sha1-", "gss-group1-sha1-"}
WEAK_CIPHERS = {"3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-32@openssh.com"}


class SshAlgosPlugin(PluginBase):
    id = "ssh.ssh_algos"
    name = "Weak SSH Algorithms"
    description = "Detect weak KEX, cipher, and MAC algorithms in SSH configuration"
    category = PluginCategory.ssh
    severity = Severity.medium
    ports = [22, 2222]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (22, 2222) or port.state != "open":
                continue
            algos = await self._get_ssh_algos(host.ip, port.number)
            if not algos:
                continue

            weak_kex = [a for a in algos.get("kex_algorithms", []) if any(w in a for w in WEAK_KEX)]
            weak_ciphers = [a for a in algos.get("encryption_algorithms_server_to_client", []) if a in WEAK_CIPHERS]
            if weak_kex:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Weak SSH Key Exchange Algorithms",
                    description="The SSH server supports weak KEX algorithms vulnerable to cryptographic attacks.",
                    evidence=f"Weak KEX: {', '.join(weak_kex)}",
                    remediation="Remove SHA-1 and diffie-hellman-group1-sha1 KEX algorithms from sshd_config.",
                    port_number=port.number,
                    protocol="tcp",
                ))
            if weak_ciphers:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Weak SSH Encryption Ciphers",
                    description="The SSH server supports deprecated or weak encryption ciphers.",
                    evidence=f"Weak ciphers: {', '.join(weak_ciphers)}",
                    remediation="Configure sshd to use only AES-GCM and ChaCha20 ciphers.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _get_ssh_algos(self, ip: str, port: int) -> dict | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._ssh_sync, ip, port)

    def _ssh_sync(self, ip: str, port: int) -> dict | None:
        """Read the server's SSH_MSG_KEXINIT directly to get its advertised algorithms.

        paramiko.get_security_options() returns the *client's* preferences, not the
        server's — using it causes false positives on every SSH host regardless of
        what the server actually supports. Instead we parse the raw KEXINIT packet.
        """
        import socket
        import struct

        try:
            s = socket.create_connection((ip, port), timeout=5)
            # Read server banner (ends with \n)
            banner = b""
            while b"\n" not in banner and len(banner) < 512:
                banner += s.recv(1)
            # Send minimal client banner
            s.sendall(b"SSH-2.0-ScanR_probe\r\n")
            # Read one SSH packet (the server's KEXINIT, message type 20)
            # Packet: uint32 length | byte padding_len | payload | padding
            raw_len = b""
            while len(raw_len) < 4:
                chunk = s.recv(4 - len(raw_len))
                if not chunk:
                    break
                raw_len += chunk
            if len(raw_len) < 4:
                return None
            pkt_len = struct.unpack(">I", raw_len)[0]
            if pkt_len > 65536:
                return None
            rest = b""
            while len(rest) < pkt_len:
                chunk = s.recv(pkt_len - len(rest))
                if not chunk:
                    break
                rest += chunk
            s.close()
            if len(rest) < 18:
                return None
            padding_len = rest[0]
            msg_type = rest[1]
            if msg_type != 20:  # SSH_MSG_KEXINIT
                return None
            # payload starts at index 1, skip msg_type (1) + cookie (16)
            payload = rest[1: pkt_len - padding_len]
            pos = 17  # skip msg_type + 16-byte cookie

            def read_name_list(p: int) -> tuple[list[str], int]:
                if p + 4 > len(payload):
                    return [], p
                length = struct.unpack(">I", payload[p:p + 4])[0]
                p += 4
                if p + length > len(payload):
                    return [], p + length
                names = payload[p:p + length].decode("ascii", errors="ignore").split(",")
                return [n.strip() for n in names if n.strip()], p + length

            kex_algos,  pos = read_name_list(pos)
            _,          pos = read_name_list(pos)  # server_host_key_algorithms
            _,          pos = read_name_list(pos)  # encryption c→s
            enc_s2c,    pos = read_name_list(pos)  # encryption s→c
            _,          pos = read_name_list(pos)  # mac c→s
            mac_s2c,    pos = read_name_list(pos)  # mac s→c

            return {
                "kex_algorithms": kex_algos,
                "encryption_algorithms_server_to_client": enc_s2c,
                "mac_algorithms_server_to_client": mac_s2c,
            }
        except Exception as exc:
            logger.debug("SSH algo check failed %s:%d: %s", ip, port, exc)
            return None
