from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)


class ArpScan:
    """Layer 2 ARP discovery for internal networks (requires root/CAP_NET_RAW)."""

    async def discover(self, cidr: str, context: "ScanContext") -> list[str]:
        """Return list of IP strings that responded to ARP."""
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
        except ImportError:
            logger.warning("Scapy not available, skipping ARP scan")
            return []

        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
            answered, _ = srp(pkt, timeout=2, verbose=False)
            return [rcv.psrc for _, rcv in answered]
        except PermissionError:
            logger.warning("ARP scan requires root — falling back")
            return []
        except Exception as exc:
            logger.warning("ARP scan failed: %s", exc)
            return []
