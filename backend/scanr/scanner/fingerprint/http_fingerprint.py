from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)
TIMEOUT = 5.0


async def http_fingerprint(ip: str, port: int, use_ssl: bool = False) -> dict[str, Any]:
    """Probe an HTTP(S) port and return server/tech info."""
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{ip}:{port}/"
    result: dict[str, Any] = {"url": url, "headers": {}, "server": None, "technologies": []}

    try:
        async with httpx.AsyncClient(verify=False, timeout=TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["server"] = resp.headers.get("server")

            # Basic tech detection
            techs = []
            powered_by = resp.headers.get("x-powered-by", "")
            if powered_by:
                techs.append(powered_by)
            body = resp.text[:4096]
            if "wp-content" in body:
                techs.append("WordPress")
            if "Drupal" in body:
                techs.append("Drupal")
            if "Joomla" in body:
                techs.append("Joomla")
            result["technologies"] = techs
    except Exception as exc:
        logger.debug("HTTP fingerprint failed %s:%d: %s", ip, port, exc)

    return result
