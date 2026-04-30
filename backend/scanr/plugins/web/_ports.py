from __future__ import annotations

from typing import Any

COMMON_HTTP_PORTS = {
    80, 81, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2083, 2087,
    2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712,
    4993, 5000, 5104, 5108, 5357, 5800, 6543, 7000, 7396, 7474,
    8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090,
    8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443,
    8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090,
    9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092,
    20720, 28017,
}

COMMON_HTTPS_PORTS = {443, 8443, 9443, 4993, 2096, 2087, 2083, 8834, 5108}


def is_web_port(port: Any) -> bool:
    if getattr(port, "state", None) != "open":
        return False
    if getattr(port, "number", None) in COMMON_HTTP_PORTS:
        return True

    service = getattr(port, "service", None)
    if service is None:
        return False

    name = (getattr(service, "name", None) or "").lower()
    product = (getattr(service, "product", None) or "").lower()
    tunnel = (getattr(service, "tunnel", None) or "").lower()
    return (
        name in {"http", "https", "http-alt", "http-proxy", "ssl/http"}
        or name.startswith(("http", "https"))
        or "http" in product
        or tunnel in {"ssl", "tls"} and "http" in name
    )


def is_web_port_data(port: dict[str, Any]) -> bool:
    if port.get("state") != "open":
        return False
    if port.get("number") in COMMON_HTTP_PORTS:
        return True

    service = port.get("service") or {}
    name = str(service.get("name") or "").lower()
    product = str(service.get("product") or "").lower()
    tunnel = str(service.get("tunnel") or "").lower()
    return (
        name in {"http", "https", "http-alt", "http-proxy", "ssl/http"}
        or name.startswith(("http", "https"))
        or "http" in product
        or tunnel in {"ssl", "tls"} and "http" in name
    )


def web_scheme(port: Any) -> str:
    service = getattr(port, "service", None)
    tunnel = (getattr(service, "tunnel", None) or "").lower() if service else ""
    name = (getattr(service, "name", None) or "").lower() if service else ""
    if tunnel in {"ssl", "tls"} or name.startswith("https"):
        return "https"
    return "https" if getattr(port, "number", None) in COMMON_HTTPS_PORTS else "http"
