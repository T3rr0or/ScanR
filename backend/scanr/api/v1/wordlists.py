"""Wordlist management — upload, list, preview, delete."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.user import User
from scanr.models.wordlist import Wordlist
from scanr.models.base import new_uuid

router = APIRouter(prefix="/wordlists", tags=["wordlists"])

WORDLIST_DIR = Path(os.getenv("WORDLIST_DIR", "/app/wordlists"))
MAX_UPLOAD_MB = 250


class WordlistRead(BaseModel):
    id: str
    name: str
    description: str | None
    type: str
    source: str
    entry_count: int
    is_builtin: bool
    model_config = {"from_attributes": True}


@router.get("", response_model=list[WordlistRead])
async def list_wordlists(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List built-in wordlists and user's own wordlists."""
    result = await db.execute(
        select(Wordlist).where(
            or_(Wordlist.is_builtin == True, Wordlist.user_id == current_user.id)
        ).order_by(Wordlist.is_builtin.desc(), Wordlist.name)
    )
    return result.scalars().all()


@router.post("", response_model=WordlistRead, status_code=status.HTTP_201_CREATED)
async def upload_wordlist(
    file: UploadFile = File(...),
    name: str = Form(...),
    type: str = Form(...),  # "usernames" | "passwords" | "credentials" | "paths"
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if type not in ("usernames", "passwords", "credentials", "paths"):
        raise HTTPException(status_code=400, detail="type must be usernames, passwords, credentials, or paths")

    content = await file.read()
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_UPLOAD_MB}MB limit")

    # Count non-empty, non-comment lines
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text")

    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    entry_count = len(lines)

    if entry_count == 0:
        raise HTTPException(status_code=400, detail="File contains no valid entries")

    # Save to disk
    user_dir = WORDLIST_DIR / "user" / current_user.id
    user_dir.mkdir(parents=True, exist_ok=True)
    wl_id = new_uuid()
    file_path = user_dir / f"{wl_id}.txt"
    file_path.write_text("\n".join(lines), encoding="utf-8")

    wl = Wordlist(
        id=wl_id,
        user_id=current_user.id,
        name=name,
        description=description or None,
        type=type,
        source="custom",
        file_path=str(file_path),
        entry_count=entry_count,
        is_builtin=False,
    )
    db.add(wl)
    await db.commit()
    await db.refresh(wl)
    return wl


@router.get("/{wordlist_id}/preview")
async def preview_wordlist(
    wordlist_id: str,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    wl = await _get_accessible(wordlist_id, current_user.id, db)
    path = Path(wl.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Wordlist file not found on disk")
    lines = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            lines.append(line.rstrip())
    return {"id": wl.id, "name": wl.name, "type": wl.type, "entry_count": wl.entry_count, "preview": lines}


@router.delete("/{wordlist_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_wordlist(
    wordlist_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    wl = await _get_accessible(wordlist_id, current_user.id, db)
    if wl.is_builtin:
        raise HTTPException(status_code=403, detail="Cannot delete built-in wordlists")
    if wl.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your wordlist")
    path = Path(wl.file_path)
    await db.delete(wl)
    await db.commit()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


async def _get_accessible(wordlist_id: str, user_id: str, db: AsyncSession) -> Wordlist:
    result = await db.execute(
        select(Wordlist).where(
            Wordlist.id == wordlist_id,
            or_(Wordlist.is_builtin == True, Wordlist.user_id == user_id),
        )
    )
    wl = result.scalar_one_or_none()
    if not wl:
        raise HTTPException(status_code=404, detail="Wordlist not found")
    return wl
