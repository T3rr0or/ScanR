from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class SmbGuestAccessPlugin(PluginBase):
    id = "services.smb_guest_access"
    name = "SMB Guest Access"
    description = "Detect SMB guest or anonymous share access"
    category = PluginCategory.services
    severity = Severity.high
    ports = [445, 139]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not _open(host, {445, 139}):
            return []
        try:
            from impacket.smbconnection import SMBConnection
            def _run():
                conn = SMBConnection(host.ip, host.ip, sess_port=445, timeout=5)
                conn.login("guest", "")
                shares = [s["shi1_netname"][:-1] for s in conn.listShares()]
                conn.close()
                return shares
            shares = await asyncio.to_thread(_run)
            if shares:
                return [_finding(self.id, Severity.high, "SMB Guest Share Access", "SMB accepts guest authentication and exposes share names, which can allow unauthenticated data access or lateral movement reconnaissance.", f"guest login succeeded; shares={', '.join(shares[:10])}", "Disable guest access, require SMB authentication, and review share ACLs.", 445)]
        except Exception:
            pass
        return []

