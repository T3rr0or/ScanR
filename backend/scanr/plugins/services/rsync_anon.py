"""rsync daemon anonymous module access detection.

An rsync daemon (rsync://, port 873) exports named "modules" — directory trees.
Each module independently decides whether it needs auth: a module with no
``auth users`` line is world-readable, and if ``read only = no`` it is also
world-writable. Backup servers and distro mirrors are the usual offenders, and
the payload is whole filesystem trees, so an anonymous module is a bulk data
disclosure rather than a configuration nit.

The probe is strictly read-only. We complete the version handshake, ask for the
module list (the empty module name), and then for each module we send the module
name and read the daemon's *first* reply: ``@RSYNCD: OK`` means it let us in
without a challenge, ``@RSYNCD: AUTH REQUIRED`` means it did not. We never send
a file-list request, so no directory contents are ever transferred.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

RSYNC_PORT = 873
_GREETING = "@RSYNCD:"
# Protocol 29 is understood by every rsync since 2.6.x; the daemon negotiates
# down if it is older, so announcing 29 is the safest common denominator.
_CLIENT_VERSION = b"@RSYNCD: 29.0\n"

# Cap how many modules we follow up on: a mirror can export hundreds and each
# one costs a TCP connection. The listing itself is already in the evidence.
_MAX_MODULES = 12


def _parse_module_list(raw: bytes | None) -> list[tuple[str, str]]:
    """Parse the daemon's module listing into (name, comment) pairs.

    Returns an empty list when the response is not an rsync daemon greeting,
    which is what keeps a non-rsync service from ever being reported.
    """
    if not raw:
        return []
    text = raw.decode("utf-8", errors="replace")
    if _GREETING not in text:
        return []
    modules: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line or line.startswith(_GREETING):
            # Skips the version banner and the trailing "@RSYNCD: EXIT".
            continue
        if "\t" in line:
            name, _, comment = line.partition("\t")
        else:
            name, comment = line, ""
        name = name.strip()
        if name:
            modules.append((name, comment.strip()))
    return modules


def _module_is_open(raw: bytes | None) -> bool | None:
    """True = module entered with no auth, False = challenged, None = unknown."""
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    if "@RSYNCD: AUTH REQUIRED" in text:
        return False
    if "@RSYNCD: OK" in text:
        return True
    return None


class RsyncAnonPlugin(PluginBase):
    id = "services.rsync_anon"
    name = "rsync Daemon Anonymous Module Access"
    description = "Detect rsync daemon modules readable without authentication"
    category = PluginCategory.services
    severity = Severity.high
    ports = [RSYNC_PORT]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number != RSYNC_PORT or port.state != "open":
                continue
            try:
                probed = await self._probe(host.ip, port.number)
            except Exception:
                logger.debug("rsync_anon: probe failed for %s:%d", host.ip, port.number, exc_info=True)
                continue
            if probed is None:
                continue
            listing, module_replies = probed
            finding = self._analyze(host.ip, port.number, listing, module_replies)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int) -> tuple[bytes, dict[str, bytes]] | None:
        """Return (raw module listing, {module name: raw first reply})."""
        listing = await self._exchange(ip, port, b"\n")
        if listing is None:
            return None
        replies: dict[str, bytes] = {}
        for name, _comment in _parse_module_list(listing)[:_MAX_MODULES]:
            reply = await self._exchange(ip, port, name.encode("utf-8", "ignore") + b"\n")
            if reply is not None:
                replies[name] = reply
        return listing, replies

    async def _exchange(self, ip: str, port: int, request: bytes) -> bytes | None:
        """One handshake + one request. The daemon closes after the module list,
        so each module has to be asked on its own connection."""
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=6.0
            )
            greeting = await asyncio.wait_for(reader.read(256), timeout=5.0)
            if not greeting or _GREETING.encode() not in greeting:
                return None
            writer.write(_CLIENT_VERSION)
            await writer.drain()
            writer.write(request)
            await writer.drain()

            # Read until the daemon stops talking or we have enough to decide.
            buf = b""
            while len(buf) < 65536:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=4.0)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                buf += chunk
                if b"@RSYNCD: EXIT" in buf or b"@RSYNCD: AUTH REQUIRED" in buf or b"@RSYNCD: OK" in buf:
                    break
            return buf
        except Exception:
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _analyze(
        self, ip: str, port: int, listing: bytes | None, module_replies: dict[str, bytes]
    ) -> FindingData | None:
        modules = _parse_module_list(listing)
        if not modules:
            # No rsync greeting, or a daemon that exports nothing — nothing to report.
            return None

        open_modules = [
            (name, comment)
            for name, comment in modules
            if _module_is_open(module_replies.get(name)) is True
        ]
        if not open_modules:
            return None

        listed = ", ".join(
            f"{name}" + (f" ({comment})" if comment else "") for name, comment in open_modules
        )
        evidence = (
            f"rsync://{ip}:{port}/ advertises {len(modules)} module(s); "
            f"{len(open_modules)} returned '@RSYNCD: OK' with no credentials: {listed}"
        )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="rsync Daemon Exports Modules Without Authentication",
            description=(
                f"The rsync daemon on port {port} exports {len(open_modules)} module(s) that "
                "can be entered without credentials. An attacker can mirror the entire "
                "directory tree behind each module in a single command "
                f"(rsync -a rsync://{ip}/{open_modules[0][0]} ./). rsync modules commonly "
                "back onto backup stores, home directories, or web roots, so this typically "
                "means bulk disclosure of source code, database dumps, private keys and "
                "configuration files. If any of these modules is also configured with "
                "'read only = no', the same anonymous session can overwrite the contents."
            ),
            evidence=evidence,
            remediation=(
                "Add 'auth users' and 'secrets file' to every module in rsyncd.conf and set "
                "restrictive permissions (0600) on the secrets file. "
                "Set 'read only = true' on any module that does not need to accept uploads. "
                "Restrict reachability with 'hosts allow'/'hosts deny' and a firewall rule on "
                "port 873. "
                "Where the transfer only ever runs between known hosts, drop the daemon "
                "entirely and use rsync over SSH with a forced command instead."
            ),
            references=[
                "https://download.samba.org/pub/rsync/rsyncd.conf.5",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
            port_number=port,
            protocol="tcp",
        )
