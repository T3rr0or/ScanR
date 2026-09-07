"""Web screenshot plugin — Aquatone-style headless browser capture.

For every open HTTP/HTTPS port, asks the isolated browser service to capture a
1280×800 screenshot and records it in the
``screenshots`` table.  Results appear in the scan console, the
ScanDetail gallery, and embedded in HTML/PDF reports.

This plugin does NOT produce findings (severity=info) — it produces
Screenshot records only.  The ``check`` method returns an empty list.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 81, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095,
              2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993,
              5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001,
              8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118,
              8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834,
              8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200,
              9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720, 28017]
MAX_CAPTURE_CONCURRENCY = 4


class ScreenshotPlugin(PluginBase):
    id = "web.screenshot"
    name = "Web Screenshot"
    description = "Capture Aquatone-style screenshots of all HTTP/HTTPS services"
    category = PluginCategory.web
    severity = Severity.info
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        open_http = [
            p for p in host.ports
            if is_web_port(p)
        ]
        if not open_http:
            return []

        screenshots_dir = _screenshots_dir(context.scan_id)
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        slots = asyncio.Semaphore(MAX_CAPTURE_CONCURRENCY)

        async def bounded_capture(port) -> None:
            async with slots:
                await self._capture(host, port, screenshots_dir, context)

        tasks = [
            bounded_capture(port)
            for port in open_http
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        return []  # screenshots stored in DB, no findings

    async def _capture(self, host, port, screenshots_dir: Path, context: "ScanContext"):
        scheme = web_scheme(port)
        url = f"{scheme}://{host.ip}:{port.number}"
        out_path = screenshots_dir / f"{host.ip}_{port.number}.png"
        await _capture_to(context, host, port.number, url, out_path)


async def capture_urls(context: "ScanContext", host: "Host", targets: list[tuple[int, str]], *, limit: int = 15) -> int:
    """Screenshot specific URLs discovered during enumeration (e.g. directory
    bruteforce hits) so they show up in the Screenshots tab alongside the
    host:port roots. ``targets`` is a list of (port_number, url). Best-effort:
    never raises; returns how many were captured."""
    import hashlib

    targets = targets[:limit]
    if not targets:
        return 0
    screenshots_dir = _screenshots_dir(context.scan_id)
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    captured = 0
    for port_number, url in targets:
        slug = hashlib.md5(url.encode()).hexdigest()[:8]
        out_path = screenshots_dir / f"{host.ip}_{port_number}_{slug}.png"
        if await _capture_to(context, host, port_number, url, out_path):
            captured += 1
    return captured


async def _capture_to(
    context: "ScanContext", host, port_number: int, url: str, out_path: Path
) -> bool:
    """Render one URL to ``out_path`` and persist a Screenshot row. Returns True
    on a successful capture, False on failure."""
    try:
        from scanr.core.browser import observe_url

        obs = await observe_url(
            url,
            "",
            timeout_ms=20_000,
            settle_seconds=2.0,
            screenshot_path=str(out_path),
            java_script_enabled=False,
        )
        if not obs.get("screenshot"):
            raise RuntimeError(obs.get("error") or "browser service returned no screenshot")
        title = obs.get("title")
        status = obs.get("status")

        await _save_screenshot(
            context=context,
            host=host,
            port_number=port_number,
            url=url,
            file_path=str(out_path),
            title=title,
            status_code=status,
            content_type=obs.get("content_type"),
        )
        await context.log.info(
            f"Screenshot: {url} [{status}] \"{title}\"",
            phase="plugin",
            host=host.ip,
        )
        return True

    except Exception as exc:
        await _save_screenshot(
            context=context,
            host=host,
            port_number=port_number,
            url=url,
            file_path=None,
            title=None,
            status_code=None,
            content_type=None,
            error=str(exc)[:256],
        )
        await context.log.debug(
            f"Screenshot failed {url}: {exc}",
            phase="plugin",
            host=host.ip,
        )
        return False


async def _save_screenshot(*, context, host, port_number, url,
                           file_path, title, status_code, content_type, error=None):
    from scanr.models import Screenshot
    from scanr.models.base import new_uuid
    shot = Screenshot(
        id=new_uuid(),
        scan_id=context.scan_id,
        host_id=host.id,
        port_number=port_number,
        url=url,
        file_path=file_path,
        title=title,
        status_code=status_code,
        content_type=content_type,
        error=error,
    )
    async with context.db_lock:
        context.db.add(shot)
        await context.db.flush()


def _screenshots_dir(scan_id: str) -> Path:
    from scanr.config import get_settings
    return get_settings().reports_dir / "screenshots" / scan_id
