"""Tamper-evident record of when each scan was active and from which address.

Entries form a chain: each HMAC covers its own fields and the previous
entry's hash. Changing, inserting or deleting an entry breaks every later
hash. The key is derived from VAULT_KEY, which the API and workers share.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import socket
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.models.scan_activity import ScanActivity

logger = logging.getLogger(__name__)

GENESIS = "0" * 64


def _key() -> bytes:
    return hashlib.sha256(b"scanr-activity-log|" + get_settings().vault_key.encode()).digest()


def _digest(prev_hash: str, entry: ScanActivity) -> str:
    at = entry.at if entry.at.tzinfo else entry.at.replace(tzinfo=timezone.utc)
    message = "|".join([
        prev_hash, entry.scan_id, at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
        entry.event, entry.detail or "", entry.source_ip or "", entry.actor or "",
    ])
    return hmac.new(_key(), message.encode(), hashlib.sha256).hexdigest()


def source_address(target: str | None = None) -> str:
    """The address scan traffic leaves from, as configured or as seen locally."""
    configured = get_settings().scanner_source_ips.strip()
    if configured:
        return configured
    probe = target if target and not target.startswith("http") else "192.0.2.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((probe.split("/")[0], 9))  # UDP connect sends nothing
            return f"{sock.getsockname()[0]} (local)"
    except OSError:
        return "unknown"


async def record(db: AsyncSession, scan_id: str, event: str, *, detail: str | None = None,
                 actor: str | None = None, source_ip: str | None = None) -> None:
    """Append an entry. The caller commits."""
    last = (await db.execute(
        select(ScanActivity.hash).where(ScanActivity.scan_id == scan_id)
        .order_by(ScanActivity.at.desc(), ScanActivity.id.desc()).limit(1)
    )).scalar_one_or_none()
    entry = ScanActivity(scan_id=scan_id, at=datetime.now(timezone.utc), event=event, detail=detail,
                         source_ip=source_ip, actor=actor, prev_hash=last or GENESIS, hash="")
    entry.hash = _digest(entry.prev_hash, entry)
    db.add(entry)


async def entries(db: AsyncSession, scan_id: str) -> tuple[list[ScanActivity], bool]:
    """All entries in order, and whether the chain verifies."""
    rows = list((await db.execute(
        select(ScanActivity).where(ScanActivity.scan_id == scan_id).order_by(ScanActivity.at, ScanActivity.id)
    )).scalars().all())
    prev = GENESIS
    ok = True
    for row in rows:
        if row.prev_hash != prev or not hmac.compare_digest(row.hash, _digest(prev, row)):
            ok = False
        prev = row.hash
    return rows, ok
