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


def encrypt_secret(secret: str | None) -> str | None:
    """Encrypt a webhook HMAC secret for storage.

    The secret authenticates ScanR to the customer's endpoint, so a database read
    should not yield a usable signing key. Falls back to plaintext when VAULT_KEY
    is unconfigured (it is optional) rather than refusing to save the webhook —
    decrypt_secret reads both forms.
    """
    if not secret:
        return None
    from scanr.credentials import vault
    from scanr.utils.exceptions import VaultError

    try:
        return vault.encrypt({"v": secret})
    except VaultError:
        logger.warning(
            "VAULT_KEY is not set — storing the webhook signing secret in plaintext. "
            "Set VAULT_KEY to encrypt secrets at rest."
        )
        return secret


def decrypt_secret(stored: str | None) -> str | None:
    """Return the usable secret from a stored value.

    Accepts both Fernet ciphertext and legacy plaintext, so rows written before
    encryption keep working without a data migration.
    """
    if not stored:
        return None
    from scanr.credentials import vault

    try:
        return vault.decrypt(stored).get("v") or None
    except Exception:
        return stored  # legacy plaintext, or no VAULT_KEY configured


async def _validate_webhook_host(hostname: str) -> None:
    """Re-validate webhook host at dispatch time to prevent TOCTOU SSRF.

    An attacker could register a domain resolving to a safe public IP,
    then change DNS to an internal IP after creation. Re-resolving at
    dispatch time closes this window.

    Uses the loop's resolver rather than socket.getaddrinfo: this runs on the
    async request/worker path, and a slow or hanging DNS lookup would otherwise
    block the event loop for every other request.
    """
    import ipaddress
    import socket

    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError):  # gaierror is an OSError subclass
        return  # unresolvable — allow, will fail naturally
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        ):
            raise ValueError(
                f"Webhook target {hostname} resolves to internal address {addr}"
            )


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
    # Re-validate DNS at dispatch time (TOCTOU protection)
    from urllib.parse import urlparse
    hostname = urlparse(webhook.url).hostname
    if hostname:
        try:
            await _validate_webhook_host(hostname)
        except ValueError:
            logger.warning("Webhook %s blocked: %s resolves to internal IP", webhook.id, hostname)
            webhook.last_status = 403
            webhook.last_triggered_at = datetime.now(timezone.utc)
            await db.commit()
            return

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

    signing_secret = decrypt_secret(webhook.secret)
    if signing_secret:
        sig = hmac.new(signing_secret.encode(), body.encode(), hashlib.sha256).hexdigest()
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
