"""Explicit port lists for "top-N" scans.

``nmap --top-ports N`` only covers ports listed in nmap-services, and a ``-p``
list given alongside it narrows the selection rather than adding to it. Ports
that ScanR plugins target but nmap-services omits (ArangoDB's 8529, for one)
were therefore never scanned, so their plugins never ran. Resolving the top-N
list here lets the engine scan it together with every plugin port.
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Iterable

logger = logging.getLogger(__name__)

NMAP_SERVICES_PATHS = (
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
    "/opt/homebrew/share/nmap/nmap-services",
)


@functools.lru_cache(maxsize=8)
def top_tcp_ports(n: int) -> tuple[int, ...] | None:
    """The ``n`` most frequent TCP ports from nmap-services, or None if unreadable."""
    for path in NMAP_SERVICES_PATHS:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return _parse_top_tcp(fh, n)
        except OSError:
            continue
    logger.info("nmap-services not found; top-ports scans cannot include plugin ports")
    return None


def _parse_top_tcp(lines: Iterable[str], n: int) -> tuple[int, ...]:
    ranked: list[tuple[float, int]] = []
    for line in lines:
        if line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        port, _, proto = fields[1].partition("/")
        if proto != "tcp" or not port.isdigit():
            continue
        try:
            ranked.append((float(fields[2]), int(port)))
        except ValueError:
            continue
    # Same order nmap uses: frequency descending; ties by port number.
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return tuple(port for _, port in ranked[:n])


def compress_ports(ports: Iterable[int]) -> str:
    """Render ports as an nmap/masscan spec, collapsing runs: 1-3,8,10-11."""
    ordered = sorted({p for p in ports if 0 < p < 65536})
    spans: list[str] = []
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        spans.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(spans)


def summarize_port_spec(args: str, limit: int = 120) -> str:
    """Shorten a long ``-p`` list inside a logged command line.

    Top-N lists with plugin ports run to thousands of ports; the console gets
    the port count instead of a 15 KB line.
    """
    tokens = args.split(" ")
    for i, token in enumerate(tokens[:-1]):
        spec = tokens[i + 1]
        if token == "-p" and len(spec) > limit:
            count = 0
            for part in spec.split(","):
                lo, _, hi = part.partition("-")
                count += int(hi) - int(lo) + 1 if hi.isdigit() and lo.isdigit() else 1
            tokens[i + 1] = f"<{count} ports>"
    return " ".join(tokens)
