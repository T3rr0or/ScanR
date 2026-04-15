from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.models.webhook import Webhook

logger = logging.getLogger(__name__)


async def dispatch(event: str, payload: dict, user_id: str, db: AsyncSession) -> None:
    """Fire all enabled webhooks for the given user that match the event."""
    result = await db.execute(
        select(Webhook).where(
            Webhook.user_id == user_id,
            Webhook.enabled == True,
        )
    )
    webhooks = result.scalars().all()

    for webhook in webhooks:
        events = json.loads(webhook.events) if webhook.events else []
        if event not in events and "*" not in events:
            continue
        await _send(webhook, event, payload, db)


async def _send(webhook: Webhook, event: str, payload: dict, db: AsyncSession) -> None:
    delivery_id = secrets.token_hex(16)
    body = json.dumps({
        "event": event,
        "delivery_id": delivery_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    })
    headers = {
        "Content-Type": "application/json",
        "X-ScanR-Event": event,
        "X-ScanR-Delivery": delivery_id,
    }

    if webhook.secret:
        sig = hmac.new(webhook.secret.encode(), body.encode(), hashlib.sha256).hexdigest()  # type: ignore[attr-defined]
        headers["X-ScanR-Signature"] = f"sha256={sig}"

    status_code: int = 0
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook.url, content=body, headers=headers)
            status_code = resp.status_code
            if not resp.is_success:
                await asyncio.sleep(1)
                resp = await client.post(webhook.url, content=body, headers=headers)
                status_code = resp.status_code
    except Exception as exc:
        logger.warning("Webhook %s delivery failed: %s", webhook.id, exc)
        status_code = 0

    webhook.last_status = status_code
    webhook.last_triggered_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("Webhook %s fired event=%s delivery=%s status=%s", webhook.id, event, delivery_id, status_code)
