"""TLS port detection — mirrors plugins.web._ports.

The TLS plugins used to gate on a hardcoded SSL_PORTS list, so a TLS service on
a non-standard port (e.g. LDAPS on 10636, a TLS-wrapped app port) had every TLS
check skipped. nmap already records a definitive TLS signal on the service —
``tunnel="ssl"`` and/or a ``ssl/…`` service name — so we promote any such port to
the TLS plugins. This is false-positive-free: the plugins each perform a real
TLS handshake and simply return nothing on a non-TLS port.
"""
from __future__ import annotations

from typing import Any

# Well-known TLS-wrapped ports (used even when nmap didn't fingerprint the port).
COMMON_TLS_PORTS: set[int] = {
    443, 8443, 9443, 4443, 10443, 993, 995, 465, 587, 636, 3269, 989, 990,
    5061, 5986, 6697, 8883, 2376, 2083, 2087, 2096, 5443, 7443, 8834,
}

_TLS_NAME_HINTS = ("ssl", "https", "tls")


def _is_tls(state: str | None, number: int | None, name: str, tunnel: str) -> bool:
    if state != "open":
        return False
    if number in COMMON_TLS_PORTS:
        return True
    # Definitive nmap signals: a TLS tunnel, or a service named ssl/https/…-over-ssl.
    if tunnel in {"ssl", "tls"}:
        return True
    return name.startswith(_TLS_NAME_HINTS) or "https" in name or "/ssl" in name or name.endswith("-ssl")


def is_tls_port(port: Any) -> bool:
    service = getattr(port, "service", None)
    name = (getattr(service, "name", None) or "").lower() if service else ""
    tunnel = (getattr(service, "tunnel", None) or "").lower() if service else ""
    return _is_tls(getattr(port, "state", None), getattr(port, "number", None), name, tunnel)


def is_tls_port_data(port: dict[str, Any]) -> bool:
    service = port.get("service") or {}
    name = str(service.get("name") or "").lower()
    tunnel = str(service.get("tunnel") or "").lower()
    return _is_tls(port.get("state"), port.get("number"), name, tunnel)
