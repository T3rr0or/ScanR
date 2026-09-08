"""Open X11 display detection (TCP 6000-6005).

An X server that accepts a connection setup request carrying no authorisation
name and no authorisation data has host-based access control disabled — the
classic ``xhost +``, or an X server started with ``-nolisten`` removed and no
MIT-MAGIC-COOKIE-1 in play. This is not an information leak: the X protocol
gives any connected client the whole session. An attacker can grab the keyboard
and read every keystroke including sudo and SSH passphrases, screenshot the
display, inject synthetic key and button events into whatever window has focus,
and read the clipboard. That is interactive control of the logged-in user's
desktop, hence critical.

The probe sends only the 12-byte connection setup request and reads the reply;
it opens no window, grabs nothing, and sends no further requests.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# 6000 + display number; :0 through :5 covers essentially every real deployment.
X11_PORTS = [6000, 6001, 6002, 6003, 6004, 6005]

_X_PROTOCOL_MAJOR = 11

# byte order 'l' (little endian), pad, major=11, minor=0,
# auth-protocol-name length 0, auth-protocol-data length 0, 2 pad bytes.
_SETUP_REQUEST = struct.pack("<BBHHHH2x", 0x6C, 0, _X_PROTOCOL_MAJOR, 0, 0, 0)

_STATUS_FAILED = 0
_STATUS_SUCCESS = 1
_STATUS_AUTHENTICATE = 2

# Offset of the vendor string inside a Success reply, per the X11 core protocol
# connection setup: 8-byte header + 32 bytes of fixed fields.
_VENDOR_OFFSET = 40


def _parse_setup_reply(raw: bytes | None) -> dict | None:
    """Parse an X11 connection setup reply.

    Returns a dict with at least ``status``, or None when the bytes are not an
    X11 setup reply at all — an unrelated service on 6000 must never be
    reported as an open display.
    """
    if not raw or len(raw) < 8:
        return None
    status = raw[0]
    if status not in (_STATUS_FAILED, _STATUS_SUCCESS, _STATUS_AUTHENTICATE):
        return None

    if status == _STATUS_AUTHENTICATE:
        # "Authenticate" carries no version fields; the server wants further
        # authentication, so the display is not open.
        return {"status": status}

    major, minor = struct.unpack("<HH", raw[2:6])
    if major != _X_PROTOCOL_MAJOR:
        # Every X server since X11R1 answers 11; anything else is not X11.
        return None

    if status == _STATUS_FAILED:
        reason_len = raw[1]
        reason = raw[8:8 + reason_len].decode("latin-1", errors="replace").strip()
        return {"status": status, "major": major, "minor": minor, "reason": reason}

    if len(raw) < _VENDOR_OFFSET:
        return None
    release = struct.unpack("<I", raw[8:12])[0]
    vendor_len = struct.unpack("<H", raw[24:26])[0]
    screens = raw[28]
    if screens < 1:
        # A Success reply always describes at least one screen.
        return None
    vendor = raw[_VENDOR_OFFSET:_VENDOR_OFFSET + vendor_len].decode("latin-1", errors="replace").strip()
    return {
        "status": status,
        "major": major,
        "minor": minor,
        "release": release,
        "vendor": vendor,
        "screens": screens,
    }


class X11OpenPlugin(PluginBase):
    id = "services.x11_open"
    name = "Open X11 Display"
    description = "Detect X servers that accept connections without MIT-MAGIC-COOKIE authorisation"
    category = PluginCategory.services
    severity = Severity.critical
    ports = X11_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in X11_PORTS or port.state != "open":
                continue
            try:
                raw = await self._probe(host.ip, port.number)
            except Exception:
                logger.debug("x11_open: probe failed for %s:%d", host.ip, port.number, exc_info=True)
                continue
            finding = self._analyze(host.ip, port.number, raw)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int) -> bytes | None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=6.0
            )
            writer.write(_SETUP_REQUEST)
            await writer.drain()
            # The fixed part of a Success reply plus a vendor string fits well
            # inside 1 KiB; we never need the screen/format tail.
            return await asyncio.wait_for(reader.read(1024), timeout=5.0)
        except Exception:
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _analyze(self, ip: str, port: int, raw: bytes | None) -> FindingData | None:
        parsed = _parse_setup_reply(raw)
        if parsed is None or parsed["status"] != _STATUS_SUCCESS:
            # Failed/Authenticate both mean the server demanded authorisation we
            # did not supply, which is the desired configuration.
            return None

        display = port - 6000
        vendor = parsed.get("vendor") or "unknown vendor"
        evidence = (
            f"X11 connection setup with empty authorisation name/data -> Success on "
            f"{ip}:{port} (display :{display}); server '{vendor}', "
            f"protocol {parsed['major']}.{parsed['minor']}, release {parsed.get('release')}, "
            f"{parsed.get('screens')} screen(s)"
        )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title=f"Open X11 Display :{display} (No Authorisation Required)",
            description=(
                f"The X server on port {port} (display :{display}) completed a connection "
                "setup that supplied no authorisation protocol and no MIT-MAGIC-COOKIE-1 "
                "cookie. The X11 core protocol grants every connected client full access to "
                "the session, so any host that can reach this port can log all keystrokes "
                "(including passwords typed into sudo, SSH and browser login forms) via "
                "XGrabKeyboard or a passive key-event selection, capture the screen contents "
                "with XGetImage, read and overwrite the clipboard, and synthesise keyboard "
                "and mouse input with XTEST — which is arbitrary command execution as the "
                "logged-in user through any open terminal window."
            ),
            evidence=evidence,
            remediation=(
                "Stop the X server from listening on TCP at all: pass '-nolisten tcp' "
                "(or set the display manager option, e.g. GDM's DisallowTCP=true / "
                "Xorg's ListenTcp=false) so X is reachable only over its local socket. "
                "Never run 'xhost +' or 'xhost +<host>'; use 'xhost -' and rely on the "
                "per-user MIT-MAGIC-COOKIE-1 cookie in ~/.Xauthority. "
                "Tunnel remote GUI sessions over SSH X11 forwarding ('ssh -X'), which "
                "handles the cookie for you, instead of exporting DISPLAY over the network. "
                "Block TCP 6000-6063 at the firewall as a defence in depth measure."
            ),
            references=[
                "https://www.x.org/releases/current/doc/man/man1/Xsecurity.1.xhtml",
                "https://www.x.org/releases/current/doc/man/man1/xhost.1.xhtml",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
            port_number=port,
            protocol="tcp",
        )
