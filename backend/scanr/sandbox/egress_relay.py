"""Per-run SOCKS5 egress relay — the sandbox's only path to a scan target.

Why a relay and not firewall rules
----------------------------------
The original design had the runner program nftables/iptables rules for the
scan's authorized CIDRs. That requires the runner to hold ``NET_ADMIN`` and the
host network namespace *on top of* the Docker socket it already has, and it makes
the sandbox network non-``internal`` — so a failure to apply the rules would fail
**open**, with the sandbox on the full network. That is the wrong trade for the
one component that is already root-equivalent on the host.

Instead the sandbox network stays Docker-``internal`` (no route anywhere) and this
relay is dual-homed: one leg on the internal sandbox network, one leg where
targets are reachable. The sandbox reaches a target only by asking the relay, and
the relay refuses anything outside the scan's scope. Properties that follow:

* **Fail-closed by construction.** No relay container, or an empty allowlist, and
  nothing is reachable — there is no route to fall back to.
* **No new privileges anywhere.** No ``NET_ADMIN``, no host networking, no
  firewall manipulation.
* **One auditable choke point.** Every destination passes ``_check_destination``.
* **Enforced on the resolved address.** A hostname destination is resolved *here*
  and every address it resolves to is checked, so DNS cannot be used to point an
  in-scope name at an out-of-scope host.

Consequence worth knowing: SOCKS5 relays TCP, so raw-socket scans (nmap ``-sS``)
cannot traverse it. That costs nothing in practice — the sandbox already runs
non-root, so it was always limited to TCP connect scans.

Run with:  python -m scanr.sandbox.egress_relay
Config:    SCANR_ALLOWED_CIDRS (comma-separated), SCANR_RELAY_PORT (default 1080)
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import struct

from scanr.utils.ip_utils import canonical_ip, is_forbidden_target

logger = logging.getLogger("scanr.sandbox.egress_relay")

_PORT = int(os.environ.get("SCANR_RELAY_PORT", "1080"))
_ALLOWED_RAW = os.environ.get("SCANR_ALLOWED_CIDRS", "")
_CONNECT_TIMEOUT = float(os.environ.get("SCANR_RELAY_CONNECT_TIMEOUT", "10"))
_IDLE_TIMEOUT = float(os.environ.get("SCANR_RELAY_IDLE_TIMEOUT", "300"))
# Bound concurrent relayed connections so a scan loop inside the sandbox cannot
# exhaust the relay's file descriptors.
_MAX_CONNS = int(os.environ.get("SCANR_RELAY_MAX_CONNS", "256"))

_SOCKS_VERSION = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04

# SOCKS5 reply codes (RFC 1928 §6)
_REP_OK = 0x00
_REP_GENERAL_FAILURE = 0x01
_REP_NOT_ALLOWED = 0x02
_REP_HOST_UNREACHABLE = 0x04
_REP_CMD_UNSUPPORTED = 0x07
_REP_ATYP_UNSUPPORTED = 0x08


def parse_allowlist(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse the configured scope into networks.

    Accepts CIDRs, bare IPs, and the legacy numeric IP encodings that
    ``canonical_ip`` normalizes. Unparseable entries are dropped with a warning
    rather than silently widening or narrowing the scope — a hostname cannot be
    an egress rule, because the address behind it can change.
    """
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                nets.append(ipaddress.ip_network(entry, strict=False))
                continue
            canon = canonical_ip(entry)
            if canon is None:
                logger.warning("Dropping non-address scope entry %r from egress allowlist", entry)
                continue
            nets.append(ipaddress.ip_network(canon, strict=False))
        except ValueError:
            logger.warning("Dropping unparseable scope entry %r from egress allowlist", entry)
    return nets


class Relay:
    def __init__(self, allowed: list[ipaddress.IPv4Network | ipaddress.IPv6Network]):
        self._allowed = allowed
        self._sem = asyncio.Semaphore(_MAX_CONNS)

    # ── authorization ─────────────────────────────────────────────────────────

    def _in_scope(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in net for net in self._allowed)

    def _check_destination(self, addr: str) -> tuple[bool, str]:
        """Single authorization choke point. Returns (allowed, reason)."""
        if not self._allowed:
            return False, "egress allowlist is empty (fail-closed)"
        canon = canonical_ip(addr)
        if canon is None:
            return False, f"{addr!r} is not an address"
        # Infrastructure guard first: loopback / link-local (cloud metadata) /
        # reserved must be refused even if a scope entry somehow covers them.
        if is_forbidden_target(canon):
            return False, f"{canon} is forbidden infrastructure"
        if not self._in_scope(canon):
            return False, f"{canon} is outside the scan's authorized scope"
        return True, ""

    async def _resolve(self, host: str) -> list[str]:
        """Resolve a destination name to addresses, here rather than in the
        sandbox: the sandbox has no DNS route, and resolving at the choke point is
        what lets us authorize the address actually connected to."""
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                timeout=_CONNECT_TIMEOUT,
            )
        except (OSError, UnicodeError, asyncio.TimeoutError):
            return []
        seen: list[str] = []
        for info in infos:
            addr = str(info[4][0])
            if addr not in seen:
                seen.append(addr)
        return seen

    # ── SOCKS5 ────────────────────────────────────────────────────────────────

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            async with self._sem:
                await self._handle(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
            pass
        except Exception:  # noqa: BLE001 - one bad client must not kill the relay
            logger.exception("relay error for %s", peer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Greeting: VER, NMETHODS, METHODS...
        ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if ver != _SOCKS_VERSION:
            return
        await reader.readexactly(nmethods)
        # No authentication: the relay is only reachable from the internal sandbox
        # network, and it authorizes by destination, not by identity.
        writer.write(struct.pack("!BB", _SOCKS_VERSION, 0x00))
        await writer.drain()

        # Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
        ver, cmd, _rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if ver != _SOCKS_VERSION:
            return
        if cmd != _CMD_CONNECT:
            # No BIND/UDP ASSOCIATE: both would let the sandbox receive or send
            # traffic the relay never authorized.
            await self._reply(writer, _REP_CMD_UNSUPPORTED)
            return

        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == _ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        elif atyp == _ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            # utf-8, not idna: the idna codec rejects errors='replace' outright,
            # so a malformed name would raise instead of being refused cleanly.
            # getaddrinfo applies IDNA itself when resolving a str.
            host = (await reader.readexactly(length)).decode("utf-8", errors="replace")
        else:
            await self._reply(writer, _REP_ATYP_UNSUPPORTED)
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]

        candidates = [host] if canonical_ip(host) else await self._resolve(host)
        if not candidates:
            logger.info("DENY %s:%s — does not resolve", host, port)
            await self._reply(writer, _REP_HOST_UNREACHABLE)
            return

        # Every address the destination resolves to must be authorized, so a name
        # with one in-scope and one out-of-scope answer is refused outright rather
        # than gambling on which one connect() picks.
        for addr in candidates:
            ok, reason = self._check_destination(addr)
            if not ok:
                logger.info("DENY %s:%s — %s", host, port, reason)
                await self._reply(writer, _REP_NOT_ALLOWED)
                return

        target = candidates[0]
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=_CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError) as exc:
            logger.info("FAIL %s:%s — %s", target, port, exc)
            await self._reply(writer, _REP_HOST_UNREACHABLE)
            return

        logger.info("ALLOW %s:%s (%s)", host, port, target)
        await self._reply(writer, _REP_OK)
        try:
            await self._pump(reader, writer, t_reader, t_writer)
        finally:
            t_writer.close()
            try:
                await t_writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _reply(self, writer: asyncio.StreamWriter, rep: int) -> None:
        # BND.ADDR/BND.PORT are unused by clients for CONNECT; reply 0.0.0.0:0.
        writer.write(struct.pack("!BBBB", _SOCKS_VERSION, rep, 0x00, _ATYP_IPV4) + b"\x00" * 4 + b"\x00\x00")
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

    async def _pump(
        self,
        c_reader: asyncio.StreamReader,
        c_writer: asyncio.StreamWriter,
        t_reader: asyncio.StreamReader,
        t_writer: asyncio.StreamWriter,
    ) -> None:
        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await asyncio.wait_for(src.read(65536), timeout=_IDLE_TIMEOUT)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:  # noqa: BLE001
                    pass

        await asyncio.gather(
            copy(c_reader, t_writer), copy(t_reader, c_writer), return_exceptions=True
        )


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    allowed = parse_allowlist(_ALLOWED_RAW)
    if not allowed:
        # Still serve, so the sandbox gets a clean SOCKS refusal rather than a
        # connection error it might mistake for a firewall quirk.
        logger.warning("No egress scope configured — every destination will be refused")
    else:
        logger.info("Egress allowlist: %s", ", ".join(str(n) for n in allowed))
    relay = Relay(allowed)
    server = await asyncio.start_server(relay.handle, "0.0.0.0", _PORT)
    logger.info("SOCKS5 egress relay listening on 0.0.0.0:%d", _PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
