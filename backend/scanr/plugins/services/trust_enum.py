"""Active Directory domain/forest trust enumeration.

Enumerates trust relationships between domains and forests.
Critical for mapping cross-domain attack paths in multi-domain
and multi-forest Active Directory environments.

Uses LDAP queries against trustedDomain objects and nltest/dsquery
where available.
"""
from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# AD ports for DC communication
TRUST_PORTS = [389, 636, 3268, 3269, 445, 135]


class TrustEnumPlugin(PluginBase):
    id = "services.trust_enum"
    name = "AD Domain / Forest Trust Enumeration"
    description = (
        "Enumerate Active Directory trust relationships between domains "
        "and forests to map cross-domain attack paths"
    )
    category = PluginCategory.services
    severity = Severity.medium
    ports = TRUST_PORTS
    requires_auth = True

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []

        cred = context.credential("windows") or context.credential("generic")
        if not cred:
            return []

        for port in host.ports:
            if port.number not in (TRUST_PORTS if self.ports is None else self.ports):
                continue
            result = await self._enumerate_trusts(host.ip, port.number, cred, context)
            if result:
                findings.append(result)
                break  # one finding per host is sufficient

        return findings

    async def _enumerate_trusts(
        self, ip: str, port: int, cred: dict, context: "ScanContext"
    ) -> FindingData | None:
        """Enumerate trusts via LDAP query or nltest."""
        loop = asyncio.get_running_loop()

        trusts: list[dict] = []

        # Method 1: nltest (requires domain-joined or explicit DC)
        trusts = await self._nltest_trusts(ip, cred)

        # Method 2: LDAP trustedDomain objects
        if not trusts and cred.get("domain"):
            trusts = await self._ldap_trusts(ip, port, cred)

        if not trusts:
            return None

        # Analyze trusts for attack paths
        bidirectional = [t for t in trusts if t.get("direction") == "bidirectional"]
        forest_trusts = [t for t in trusts if t.get("type") == "forest"]
        external_trusts = [t for t in trusts if t.get("type") == "external"]
        sid_filtering = [t for t in trusts if t.get("sid_filtering") == "disabled"]
        transitive = [t for t in trusts if t.get("transitive") is True]

        severity = Severity.info
        issues: list[str] = []

        if external_trusts:
            severity = Severity.high
            issues.append(
                f"External trust(s) found to {len(external_trusts)} domain(s). "
                "External trusts to untrusted forests are high-risk."
            )

        if sid_filtering:
            severity = Severity.high
            issues.append(
                f"SID filtering is DISABLED on {len(sid_filtering)} trust(s). "
                "This enables SID history injection attacks across trusts."
            )

        if bidirectional and len(bidirectional) > 3:
            severity = Severity.medium
            issues.append(
                f"{len(bidirectional)} bidirectional trusts — large trust web "
                "increases lateral movement surface."
            )

        if forest_trusts and transitive:
            severity = max(severity, Severity.medium)
            issues.append(
                "Transitive forest trust(s) found — compromise of any domain "
                "in the forest propagates to this domain."
            )

        evidence_lines = [f"DC: {ip}", f"Port: {port}", f"Trusts discovered: {len(trusts)}"]
        for t in trusts:
            evidence_lines.append(
                f"  {t.get('target', '?')} — "
                f"type={t.get('type', '?')}, "
                f"dir={t.get('direction', '?')}, "
                f"transitive={t.get('transitive', '?')}, "
                f"SID filtering={t.get('sid_filtering', '?')}"
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"AD Trust Enumeration — {len(trusts)} trust(s) discovered",
            description="\n".join(issues) if issues else (
                f"{len(trusts)} domain/forest trust(s) enumerated. "
                "No high-risk trust configurations detected."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "Trust hardening recommendations:\n"
                "1. Enable SID filtering on all external/forest trusts\n"
                "2. Audit external trusts — remove if not needed\n"
                "3. Use selective authentication for forest trusts\n"
                "4. Monitor trust changes via Windows Event ID 4716/4717\n"
                "5. Apply tiered admin model across trust boundaries"
            ),
            references=[
                "https://attack.mitre.org/techniques/T1482/",
                "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/understanding-trusts",
                "https://posts.specterops.io/a-pentesters-guide-to-active-directory-trusts-8b9c6e2f9ea4",
            ],
            port_number=port,
            protocol="tcp",
        )

    async def _nltest_trusts(self, dc_ip: str, cred: dict) -> list[dict]:
        """Use nltest to enumerate trusts (requires domain creds)."""
        loop = asyncio.get_running_loop()
        domain = cred.get("domain", "")
        username = cred.get("username", "")
        password = cred.get("password", "")

        if not domain or not username:
            return []

        trusts: list[dict] = []
        try:
            # nltest /domain_trusts /server:<DC>
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["nltest", "/domain_trusts", f"/server:{dc_ip}"],
                    capture_output=True, text=True, timeout=30,
                    env={**__import__("os").environ,
                         "USER": f"{domain}\\{username}",
                         "PASSWORD": password},
                ),
            )
            if proc.returncode == 0:
                trusts.extend(self._parse_nltest_output(proc.stdout))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return trusts

    async def _ldap_trusts(self, ip: str, port: int, cred: dict) -> list[dict]:
        """Query LDAP for trustedDomain objects."""
        trusts: list[dict] = []
        try:
            import asyncio
            reader, writer = await asyncio.open_connection(ip, port)

            # Simple bind if credentials available
            domain = cred.get("domain", "")
            username = cred.get("username", "")
            password = cred.get("password", "")

            bind_dn = f"{username}@{domain}" if domain else username
            self._send_ldap_bind(writer, bind_dn, password)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            if b"\x00" not in response[8:]:  # resultCode != 0 (success)
                writer.close()
                return []

            # Search for trustedDomain objects
            search_filter = b"(objectClass=trustedDomain)"
            base_dn = b"CN=System," + b",".join(
                b"DC=" + part.encode() for part in domain.split(".")
            ) if domain else b""

            self._send_ldap_search(writer, base_dn, search_filter)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(32768), timeout=10.0)
            trusts = self._parse_ldap_trust_response(response)

            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            logger.debug("LDAP trust enumeration failed: %s", exc)

        return trusts

    @staticmethod
    def _send_ldap_bind(writer, dn: str, password: str):
        """Send simple LDAP bind."""
        import struct
        dn_bytes = dn.encode("utf-8")
        pw_bytes = password.encode("utf-8")
        body = (
            b"\x02\x01\x03"  # LDAPv3
            + b"\x04" + struct.pack("B", len(dn_bytes)) + dn_bytes
            + b"\x80" + struct.pack("B", len(pw_bytes)) + pw_bytes
        )
        pdu = b"\x60" + struct.pack("B", len(body)) + body
        msg = b"\x30" + struct.pack("B", len(pdu) + 4) + b"\x02\x01\x01" + pdu
        writer.write(msg)

    @staticmethod
    def _send_ldap_search(writer, base_dn: bytes, filt: bytes, msg_id: int = 2):
        """Send LDAP search request."""
        import struct
        search = (
            base_dn + b"\x00"  # base DN
            + b"\x0a\x01\x02"  # scope: wholeSubtree
            + b"\x0a\x01\x00"  # deref: never
            + b"\x02\x01\x00"  # sizeLimit: 0
            + b"\x02\x01\x00"  # timeLimit: 0
            + b"\x01\x01\x00"  # typesOnly: false
            + b"\x87" + struct.pack("B", len(filt)) + filt
            + b"\x30\x00"  # no attributes
        )
        pdu = b"\x63" + struct.pack("B", len(search)) + search
        msg = b"\x30" + struct.pack("B", len(pdu) + 4) + b"\x02\x01" + struct.pack("B", msg_id) + pdu
        writer.write(msg)

    def _parse_nltest_output(self, output: str) -> list[dict]:
        """Parse nltest /domain_trusts output."""
        trusts: list[dict] = []
        current: dict = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    trusts.append(current)
                    current = {}
                continue

            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower().replace(" ", "_")
                v = v.strip()

                if "trusted_domain" in k:
                    current["target"] = v
                elif "trust_type" in k:
                    current["type"] = v.lower()
                    if "forest" in v.lower():
                        current["type"] = "forest"
                    elif "external" in v.lower():
                        current["type"] = "external"
                    else:
                        current["type"] = "parent_child"
                elif "trust_direction" in k:
                    current["direction"] = v.lower()
                elif "transitive" in k:
                    current["transitive"] = "yes" in v.lower()
                elif "sid_filtering" in k:
                    current["sid_filtering"] = "enabled" if "enabled" in v.lower() else "disabled"

        if current:
            trusts.append(current)
        return trusts

    def _parse_ldap_trust_response(self, data: bytes) -> list[dict]:
        """Parse LDAP search result entries for trust info."""
        trusts: list[dict] = []
        text = data.decode("latin-1", errors="replace")

        # Simple string-based parsing of trustedDomain attributes
        trust_names = re.findall(r"CN=([^,]+),CN=System", text)
        for name in trust_names:
            trust: dict = {"target": name, "type": "unknown", "direction": "unknown"}
            # Infer type from common naming patterns
            if name.endswith("$"):
                trust["target"] = name.rstrip("$")

            # Check for trust attributes in the response
            if "trustType" in text:
                type_match = re.search(r"trustType.*?(\d+)", text)
                if type_match:
                    type_val = int(type_match.group(1))
                    types = {1: "downlevel", 2: "up-level", 3: "mit", 4: "dce"}
                    trust["type"] = types.get(type_val, "unknown")

            if "trustDirection" in text:
                dir_match = re.search(r"trustDirection.*?(\d+)", text)
                if dir_match:
                    dir_val = int(dir_match.group(1))
                    dirs = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
                    trust["direction"] = dirs.get(dir_val, "unknown")

            trusts.append(trust)
        return trusts
