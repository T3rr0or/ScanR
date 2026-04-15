from __future__ import annotations

import hashlib
import hmac
import json
import logging
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
    body = json.dumps({"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), "data": payload})
    headers = {"Content-Type": "application/json", "X-ScanR-Event": event}

    if webhook.secret:
        sig = hmac.new(webhook.secret.encode(), body.encode(), hashlib.sha256).hexdigest()  # type: ignore[attr-defined]
        headers["X-ScanR-Signature"] = f"sha256={sig}"

    status_code: int | None = None
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook.url, content=body, headers=headers)
            status_code = resp.status_code
            if not resp.is_success:
                # Retry once
                resp = await client.post(webhook.url, content=body, headers=headers)
                status_code = resp.status_code
    except Exception as exc:
        logger.warning("Webhook %s delivery failed: %s", webhook.id, exc)

    webhook.last_status = status_code
    webhook.last_triggered_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("Webhook %s fired event=%s status=%s", webhook.id, event, status_code)
