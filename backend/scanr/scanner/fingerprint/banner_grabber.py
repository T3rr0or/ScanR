from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

TIMEOUT = 3.0
MAX_BANNER_BYTES = 1024


async def grab_banner(ip: str, port: int, use_ssl: bool = False) -> str | None:
    """Connect to ip:port, grab the initial banner bytes, return as string or None."""
    try:
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=TIMEOUT,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=TIMEOUT,
            )

        try:
            data = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout=TIMEOUT)
            return data.decode(errors="replace").strip() if data else None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except asyncio.TimeoutError:
        return None
    except Exception as exc:
        logger.debug("Banner grab failed %s:%d: %s", ip, port, exc)
        return None
