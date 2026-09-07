from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from contextlib import nullcontext
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.models.webhook import Webhook
from scanr.utils.exceptions import VaultError
from scanr.utils import safe_http

logger = logging.getLogger(__name__)

_SECRET_CIPHERTEXT_PREFIX = "enc:v1:"


def encrypt_secret(secret: str | None) -> str | None:
    """Encrypt a webhook HMAC secret for storage.

    The secret authenticates ScanR to the customer's endpoint, so a database read
    must not yield a usable signing key. Encryption failures deliberately abort
    the write: silently storing plaintext would turn an availability/configuration
    problem into credential disclosure.
    """
    if not secret:
        return None
    from scanr.credentials import vault

    return _SECRET_CIPHERTEXT_PREFIX + vault.encrypt({"v": secret})


def decrypt_secret(stored: str | None) -> str | None:
    """Return the usable secret from a stored value.

    New values carry an explicit format/version marker. Raw Fernet ciphertext is
    accepted only for rollback compatibility with the pre-0026 schema. Legacy
    plaintext is migrated by Alembic and is never guessed at runtime.
    """
    if not stored:
        return None
    from scanr.credentials import vault
    if stored.startswith(_SECRET_CIPHERTEXT_PREFIX):
        ciphertext = stored.removeprefix(_SECRET_CIPHERTEXT_PREFIX)
    elif stored.startswith("gAAAA"):
        ciphertext = stored
    else:
        raise VaultError(
            "Webhook secret has an unversioned storage format; run database "
            "migration 0026 with the configured VAULT_KEY"
        )

    try:
        payload = vault.decrypt(ciphertext)
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("Webhook secret ciphertext has an invalid payload") from exc
    value = payload.get("v")
    if not isinstance(value, str) or not value:
        raise VaultError("Decrypted webhook secret has an invalid payload")
    return value


async def _validate_webhook_host(hostname: str) -> None:
    """Best-effort early validation used while configuring a webhook.

    This gives an operator immediate feedback, but it is not the dispatch-time
    security boundary: the delivery client resolves once, validates every DNS
    answer, and pins its TCP connection to that approved answer.

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


async def dispatch(
    event: str,
    payload: dict,
    user_id: str,
    db: AsyncSession,
    db_lock: "asyncio.Lock | None" = None,
) -> None:
    """Fire all enabled webhooks for the given user that match the event.

    `db_lock` is the caller's session lock, when the session is shared with
    concurrent work (a running scan). It is held only across database access:
    delivery can take tens of seconds across retries, and holding a scan-wide
    lock for that long stalls every other host and plugin writing findings.
    """
    lock = db_lock or nullcontext()
    # Filter in SQL: only fetch webhooks that match the event or subscribe to '*'
    async with lock:
        result = await db.execute(
            select(Webhook).where(
                Webhook.user_id == user_id,
                Webhook.enabled == True,
                Webhook.events.contains(event) | Webhook.events.contains("*"),
            )
        )
        webhooks = result.scalars().all()

    for webhook in webhooks:
        await _send(webhook, event, payload, db, lock)


async def _send(
    webhook: Webhook,
    event: str,
    payload: dict,
    db: AsyncSession,
    lock=None,
) -> None:
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

    try:
        signing_secret = decrypt_secret(webhook.secret)
    except VaultError as exc:
        # A missing/wrong vault key or malformed ciphertext must never degrade to
        # an unsigned delivery. Record a failed attempt without exposing either
        # the stored value or decrypted secret in logs.
        logger.error("Webhook %s not sent: signing secret could not be decrypted: %s", webhook.id, exc)
        webhook.last_status = 0
        webhook.last_triggered_at = datetime.now(timezone.utc)
        async with (lock or nullcontext()):
            await db.commit()
        return
    if signing_secret:
        sig = hmac.new(signing_secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-ScanR-Signature"] = f"sha256={sig}"

    status_code: int = 0
    _RETRY_DELAYS = [1, 5]  # seconds between attempts (3 total)
    try:
        # Validation and connection use the same DNS answer. A normal httpx
        # client would resolve again after a preflight check, leaving a DNS-
        # rebinding window between authorization and TCP connect.
        client = await safe_http.pinned_async_client(
            webhook.url,
            extra_denylist=get_settings().scan_denylist,
            verify=True,
            # Webhooks are user-configurable and their creation-time check
            # rejects RFC1918 destinations. Enforce the same rule on the DNS
            # answer actually used for the connection so a later DNS change
            # cannot turn a public hook into an internal SSRF primitive.
            forbid_private=True,
        )
        async with client:
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
    except safe_http.UnsafeHTTPDestination as exc:
        logger.warning("Webhook %s blocked: %s", webhook.id, exc)
        status_code = 403
    except Exception as exc:
        logger.warning("Webhook %s delivery error: %s", webhook.id, exc)
        status_code = 0

    webhook.last_status = status_code
    webhook.last_triggered_at = datetime.now(timezone.utc)
    async with (lock or nullcontext()):
        await db.commit()
    logger.info("Webhook %s fired event=%s delivery=%s status=%s", webhook.id, event, delivery_id, status_code)
