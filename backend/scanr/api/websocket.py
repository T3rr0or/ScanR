"""WebSocket endpoint for live scan progress.

Architecture:
  - Celery worker runs ScanEngine which calls ScanLogger.emit()
  - ScanLogger publishes JSON events to Redis pub/sub channel ``scanr:events:{scan_id}``
  - This WS endpoint subscribes to that channel and streams events to the browser
  - Multiple browser tabs connecting to the same scan all receive the same events
"""
from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from scanr.auth.jwt_handler import decode_token
from scanr.config import get_settings
from scanr.db.session import AsyncSessionLocal
from scanr.models import Scan

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

_HISTORY_LIMIT = 2000  # max events replayed on connect


@router.websocket("/ws/scans/{scan_id}/progress")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
    token: str | None = Query(None),
):
    await websocket.accept()

    # --- Auth: require valid JWT passed as ?token= query param ---
    if not token:
        await websocket.send_text(json.dumps({"type": "error", "msg": "authentication required"}))
        await websocket.close(code=4401)
        return
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub", "")
        if not user_id or payload.get("type") != "access":
            raise ValueError("invalid token type")
    except ValueError:
        await websocket.send_text(json.dumps({"type": "error", "msg": "invalid token"}))
        await websocket.close(code=4401)
        return

    # --- Authorization: verify user owns this scan ---
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            await websocket.send_text(json.dumps({"type": "error", "msg": "scan not found"}))
            await websocket.close(code=4404)
            return
        await websocket.send_text(json.dumps({
            "type": "status",
            "scan_id": scan_id,
            "status": scan.status,
            "hosts_total": scan.hosts_total,
            "hosts_up": scan.hosts_up,
        }))

    import redis.asyncio as aioredis
    settings = get_settings()
    channel = f"scanr:events:{scan_id}"
    history_key = f"scanr:history:{scan_id}"

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)

    # Replay persisted history (capped) before subscribing to live events
    try:
        history = await redis_client.lrange(history_key, -_HISTORY_LIMIT, -1)
        for item in history:
            await websocket.send_text(item)
        await websocket.send_text(json.dumps({"type": "history_end", "count": len(history)}))
    except Exception as exc:
        logger.debug("WS history replay failed: %s", exc)

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel)

    try:
        async def _redis_reader():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        await websocket.send_text(message["data"])
                    except Exception:
                        return

        async def _ws_reader():
            """Keep connection alive; handle client pings/disconnects."""
            try:
                while True:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                pass

        await asyncio.gather(_redis_reader(), _ws_reader(), return_exceptions=True)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS scan_progress error: %s", exc)
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await redis_client.aclose()
