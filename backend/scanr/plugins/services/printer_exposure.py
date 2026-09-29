"""Unauthenticated raw print service (JetDirect / PJL on 9100).

Port 9100 is a raw socket into the printer's language interpreter. There is no
authentication in the protocol — anything written to it is interpreted, and PJL
(Printer Job Language) is a control language, not just a page description.

That makes an exposed 9100 more than a nuisance:

* PJL reads and writes the device's control panel, default settings and, on many
  models, its filesystem, where spooled jobs are retained. Printed documents can
  be recovered after the fact.
* Job capture: an attacker who can talk to the interpreter can also cause
  subsequent jobs to be retained or redirected.
* Printers are full network hosts with credentials in them — the LDAP or SMB
  account configured for address-book lookup and scan-to-folder is often a domain
  account, and it is retrievable from the device's own configuration.
* They are rarely patched, rarely monitored, and almost never in the asset
  inventory, which makes them a durable foothold.

The probe sends only ``@PJL INFO`` queries, which are read-only status requests
wrapped in the Universal Exit Language sequence so the job terminates cleanly.
Nothing is printed: no page description language data is sent, so there is no
output tray to collect. Filesystem commands (``FSDIRLIST``, ``FSUPLOAD``) are
deliberately *not* sent, even though they are usually available — reading a
printer's stored documents is beyond a scan's remit.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

RAW_PRINT_PORTS = [9100, 9101, 9102]

# Universal Exit Language: leaves whatever language the interpreter was in and
# enters PJL, then returns cleanly. Without the trailing UEL the printer may wait
# for more job data.
_UEL = b"\x1b%-12345X"

# Read-only status queries. INFO ID returns the model, INFO STATUS the current
# device state. Nothing here changes a setting or produces output.
_PJL_PROBE = (
    _UEL
    + b"@PJL INFO ID\r\n"
    + b"@PJL INFO STATUS\r\n"
    + _UEL
)

_TIMEOUT = 6.0
_READ_LIMIT = 8192

_ID_RE = re.compile(r"@PJL\s+INFO\s+ID\s*\r?\n\s*\"?([^\"\r\n]+)", re.I)
_CODE_RE = re.compile(r"^\s*CODE\s*=\s*(\d+)", re.I | re.M)
_DISPLAY_RE = re.compile(r"^\s*DISPLAY\s*=\s*\"?([^\"\r\n]*)", re.I | re.M)

_VENDOR_HINTS = (
    ("hp ", "HP"),
    ("laserjet", "HP LaserJet"),
    ("officejet", "HP OfficeJet"),
    ("kyocera", "Kyocera"),
    ("ricoh", "Ricoh"),
    ("brother", "Brother"),
    ("lexmark", "Lexmark"),
    ("canon", "Canon"),
    ("xerox", "Xerox"),
    ("epson", "Epson"),
    ("sharp", "Sharp"),
    ("konica", "Konica Minolta"),
    ("oki", "OKI"),
    ("zebra", "Zebra"),
    ("dell", "Dell"),
)


@dataclass
class PjlInfo:
    """What the interpreter told us about itself."""

    raw: str = ""
    model: str = ""
    status_code: str = ""
    display: str = ""
    vendor: str = ""
    lines: list[str] = field(default_factory=list)

    @property
    def answered_pjl(self) -> bool:
        """True only on evidence this is a printer interpreter, not any listener.

        Fail closed: a bare line of text on 9100 could be any service's banner, so
        an unrecognised reply is not credited. Either the device echoed PJL, or it
        returned a PJL status field, or it named a printer vendor.
        """
        return bool("@PJL" in self.raw.upper() or self.status_code or self.vendor)


def parse_pjl(raw: bytes) -> PjlInfo:
    """Parse a PJL INFO reply. An empty PjlInfo means the peer did not speak PJL."""
    if not raw:
        return PjlInfo()
    text = raw.decode("latin-1", errors="replace")
    info = PjlInfo(raw=text, lines=[line.strip() for line in text.splitlines() if line.strip()])

    code = _CODE_RE.search(text)
    if code:
        info.status_code = code.group(1)
    display = _DISPLAY_RE.search(text)
    if display:
        info.display = display.group(1).strip()

    lowered = text.lower()
    for needle, label in _VENDOR_HINTS:
        if needle in lowered:
            info.vendor = label
            break

    match = _ID_RE.search(text)
    if match:
        info.model = match.group(1).strip()
    elif info.lines and (info.vendor or info.status_code):
        # Some firmware answers INFO ID with the bare model string and no echo of
        # the command. Only trusted once something else has established that this
        # really is a printer.
        first = info.lines[0].strip('"')
        if first and not first.upper().startswith("@PJL"):
            info.model = first
    return info


class PrinterExposurePlugin(PluginBase):
    id = "services.printer_exposure"
    name = "Unauthenticated Raw Print Service (PJL)"
    description = (
        "Detect raw JetDirect print ports that accept PJL control commands "
        "without authentication, and identify the device from its own reply"
    )
    category = PluginCategory.services
    severity = Severity.medium
    ports = RAW_PRINT_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in RAW_PRINT_PORTS or port.state != "open":
                continue
            info = await self._probe(host.ip, port.number)
            if not info.answered_pjl:
                continue
            findings.append(self._build_finding(host.ip, port.number, info))
        return findings

    async def _probe(self, ip: str, port: int) -> PjlInfo:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=_TIMEOUT
            )
            writer.write(_PJL_PROBE)
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)
            raw = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=_TIMEOUT)
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("PJL probe failed %s:%d: %s", ip, port, exc)
            return PjlInfo()
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass
        return parse_pjl(raw)

    def _build_finding(self, ip: str, port: int, info: PjlInfo) -> FindingData:
        # A device that names itself is confirmed beyond doubt and gives the
        # reader something to act on, so it is rated a step higher than a port
        # that merely answers.
        severity = Severity.medium if info.model else Severity.low
        label = info.model or info.vendor or "Unidentified device"

        evidence = [
            f"Connected to {ip}:{port} and sent read-only PJL queries "
            "(@PJL INFO ID, @PJL INFO STATUS) wrapped in UEL.",
            "Device replied:",
            *(f"  {line}" for line in info.lines[:12]),
        ]
        if info.model:
            evidence.append(f"\nModel: {info.model}")
        if info.vendor:
            evidence.append(f"Vendor: {info.vendor}")
        if info.status_code:
            evidence.append(f"PJL status code: {info.status_code}")
        if info.display:
            evidence.append(f"Front-panel display: {info.display}")
        evidence.append(
            "\nNo page description language data was sent, so nothing was printed. "
            "Filesystem commands were deliberately not sent."
        )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"Unauthenticated Raw Print Service on {port}/tcp ({label})",
            description=(
                f"The raw print port {ip}:{port} accepts PJL commands from any client with "
                "no authentication. The device identified itself in reply, so this is the "
                "printer's own language interpreter answering, not a generic listener.\n\n"
                "PJL is a control language. Beyond submitting print jobs, an "
                "unauthenticated client can read and change the device's default settings "
                "and control panel, and on most models enumerate and read the device "
                "filesystem — which is where spooled and retained jobs live. Documents "
                "printed earlier can therefore be recoverable, and jobs printed later can "
                "be captured.\n\n"
                "The device also holds credentials. A multifunction printer configured for "
                "address-book lookup or scan-to-folder stores an LDAP or SMB account, "
                "frequently a domain account with more access than anyone intended, and "
                "that configuration is readable from the device. Printers are seldom "
                "patched, seldom monitored and often missing from the asset inventory, "
                "which makes them a persistent foothold rather than a one-off leak.\n\n"
                "Physical output is its own consideration: an attacker who can reach this "
                "port can print, which has been used for both nuisance and for social "
                "engineering that relies on a document appearing to come from inside."
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Close port 9100 to everything except the print servers that need it. Raw "
                "printing has no authentication to enable, so network restriction is the "
                "control — put printers on their own VLAN and route jobs through a print "
                "server or IPPS rather than direct socket printing.\n\n"
                "On the device: disable raw/port-9100 printing if the fleet prints via IPP "
                "or a server, set an administrator password and a PJL password where the "
                "firmware supports one, disable unused protocols (Telnet, FTP, SNMP v1/v2c "
                "with default communities), and turn off job retention unless it is needed.\n\n"
                "Then check what credentials this device holds. Any LDAP, SMB or SMTP "
                "account configured on it should be a dedicated least-privilege account, "
                "never a domain administrator or a shared service account — and if the port "
                "has been exposed, rotate it. Keep the firmware current; printer firmware "
                "carries remote code execution advisories like any other network device."
            ),
            references=[
                "http://hacking-printers.net/wiki/index.php/Main_Page",
                "https://attack.mitre.org/techniques/T1200/",
                "https://www.cisa.gov/news-events/alerts",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"printf '\\x1b%%-12345X@PJL INFO ID\\r\\n\\x1b%%-12345X' | nc {ip} {port}"
            ),
        )
