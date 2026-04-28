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
    # Filter in SQL: only fetch webhooks that match the event or subscribe to '*'
    result = await db.execute(
        select(Webhook).where(
            Webhook.user_id == user_id,
            Webhook.enabled == True,
            Webhook.events.contains(event) | Webhook.events.contains("*"),
        )
    )
    webhooks = result.scalars().all()

    for webhook in webhooks:
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
    _RETRY_DELAYS = [1, 5]  # seconds between attempts (3 total)
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            for attempt, delay in enumerate([0] + _RETRY_DELAYS):
                if delay:
                    await asyncio.sleep(delay)
                try:
                    resp = await client.post(webhook.url, content=body, headers=headers)
                    status_code = resp.status_code
                    if resp.is_success:
                        break
                    # Honour Retry-After on 429 / 503
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after and attempt < len(_RETRY_DELAYS):
                        try:
                            _RETRY_DELAYS[attempt] = min(int(retry_after), 30)
                        except ValueError:
                            pass
                except Exception as exc:
                    logger.warning("Webhook %s attempt %d failed: %s", webhook.id, attempt + 1, exc)
                    status_code = 0
    except Exception as exc:
        logger.warning("Webhook %s delivery error: %s", webhook.id, exc)
        status_code = 0

    webhook.last_status = status_code
    webhook.last_triggered_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("Webhook %s fired event=%s delivery=%s status=%s", webhook.id, event, delivery_id, status_code)
