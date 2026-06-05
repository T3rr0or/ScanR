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

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from scanr.auth.jwt_handler import decode_token
from scanr.db.session import AsyncSessionLocal
from scanr.models import Scan

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

_HISTORY_LIMIT = 2000  # max events replayed on connect


def _extract_token(websocket: WebSocket) -> str | None:
    """Extract JWT from Sec-WebSocket-Protocol subprotocol header.
    Format: token.<jwt>"""
    subprotocol_header = websocket.headers.get("sec-websocket-protocol", "")
    for part in subprotocol_header.split(","):
        part = part.strip()
        if part.startswith("token."):
            return part[len("token."):]
    return None


@router.websocket("/ws/scans/{scan_id}/progress")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
):
    raw_token = _extract_token(websocket)

    # Accept, echoing the subprotocol if the client sent one
    subprotocol_header = websocket.headers.get("sec-websocket-protocol", "")
    accepted_subprotocol = None
    for part in subprotocol_header.split(","):
        part = part.strip()
        if part.startswith("token."):
            accepted_subprotocol = part
            break
    await websocket.accept(subprotocol=accepted_subprotocol)

    # --- Auth: require valid access JWT ---
    if not raw_token:
        await websocket.send_text(json.dumps({"type": "error", "msg": "authentication required"}))
        await websocket.close(code=4401)
        return
    try:
        payload = decode_token(raw_token)
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

    from scanr.db.redis import get_redis
    channel = f"scanr:events:{scan_id}"
    history_key = f"scanr:history:{scan_id}"

    redis_client = get_redis()

    # Fix M28: subscribe FIRST, buffer into queue, then fetch LRANGE.
    # Messages published between LRANGE and SUBSCRIBE are captured in the queue
    # and deduplicated against history before forwarding to the client.
    queue: asyncio.Queue[str] = asyncio.Queue()

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel)

    async def _drain_pubsub_to_queue():
        async for message in pubsub.listen():
            if message["type"] == "message":
                await queue.put(message["data"])

    drain_task = asyncio.create_task(_drain_pubsub_to_queue())

    try:
        # Fetch and replay history
        history: list[str] = []
        try:
            history = await redis_client.lrange(history_key, -_HISTORY_LIMIT, -1)
            for item in history:
                await websocket.send_text(item)
            await websocket.send_text(json.dumps({"type": "history_end", "count": len(history)}))
        except Exception as exc:
            logger.debug("WS history replay failed: %s", exc)

        history_set = set(history)

        # Flush any buffered live events that arrived during history fetch, deduped
        while not queue.empty():
            item = queue.get_nowait()
            if item not in history_set:
                try:
                    await websocket.send_text(item)
                except Exception:
                    return

        async def _redis_reader():
            while True:
                item = await queue.get()
                try:
                    await websocket.send_text(item)
                except Exception:
                    drain_task.cancel()
                    return

        async def _ws_reader():
            try:
                while True:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                drain_task.cancel()

        await asyncio.gather(_redis_reader(), _ws_reader(), return_exceptions=True)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS scan_progress error: %s", exc)
    finally:
        drain_task.cancel()
        await pubsub.unsubscribe(channel)
        try:
            await pubsub.aclose()
        except Exception:
            pass
        await redis_client.aclose()
