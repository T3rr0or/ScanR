"""Evidence file storage for finding attachments.

Files are typed by their content, never by the uploaded name or the client's
Content-Type, and only a small set of formats is accepted: raster images (for
reports), PDF, and UTF-8 text such as saved HTTP requests, tool output, HAR
files or an XSS proof-of-concept page. Anything textual, HTML and SVG included,
is stored and served as text/plain with nosniff, so a browser never renders it.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path

from scanr.config import get_settings

logger = logging.getLogger(__name__)

IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}


class EvidenceError(ValueError):
    pass


def detect_type(data: bytes) -> str:
    """Return the MIME type for allowed content, or raise EvidenceError."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    head = data[:8192]
    if b"\x00" not in head:
        text = None
        # Trim up to three bytes: a multi-byte character cut at the boundary is still text.
        for cut in range(4):
            try:
                text = head[: len(head) - cut].decode("utf-8")
                break
            except UnicodeDecodeError:
                continue
        if text is not None and _looks_textual(text):
            return "text/plain"
    raise EvidenceError("Unsupported file type: use PNG, JPEG, GIF, WebP, PDF or UTF-8 text")


# Control characters other than tab, newline, carriage return, form feed and ESC
# (ANSI colours in tool output) mean a binary file that happens to decode.
_ALLOWED_CONTROL = {"\t", "\n", "\r", "\x0c", "\x1b"}


def _looks_textual(text: str) -> bool:
    controls = [c for c in text if (ord(c) < 32 or ord(c) == 127) and c not in _ALLOWED_CONTROL]
    if any((ord(c) < 32 or ord(c) == 127) and c not in _ALLOWED_CONTROL for c in text[:64]):
        return False
    return len(controls) <= len(text) // 100


def root() -> Path:
    return get_settings().evidence_dir


def path_for(finding_id: str, attachment_id: str) -> Path:
    # Both parts are server-generated UUIDs; resolve-and-check is defence in depth.
    base = root().resolve()
    path = (base / finding_id / attachment_id).resolve()
    if base not in path.parents:
        raise EvidenceError("Invalid evidence path")
    return path


def save(finding_id: str, attachment_id: str, data: bytes) -> str:
    path = path_for(finding_id, attachment_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def delete(finding_id: str, attachment_id: str) -> None:
    try:
        path_for(finding_id, attachment_id).unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Could not delete evidence %s/%s: %s", finding_id, attachment_id, exc)


def remove_orphans(known_ids: set[str]) -> int:
    """Delete stored files whose attachment row is gone (finding, scan or user
    deleted). Returns the number of files removed."""
    base = root()
    if not base.exists():
        return 0
    removed = 0
    for folder in base.iterdir():
        if not folder.is_dir():
            continue
        for file in folder.iterdir():
            if file.is_file() and file.name not in known_ids:
                file.unlink(missing_ok=True)
                removed += 1
        if not any(folder.iterdir()):
            shutil.rmtree(folder, ignore_errors=True)
    return removed
