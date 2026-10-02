"""RFC 6238 time-based one-time passwords and single-use recovery codes.

Implemented on the standard library rather than a dependency: TOTP is a few
lines of HMAC, and the compatible parameters (SHA-1, 6 digits, 30 s step) are
what every authenticator app defaults to.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
STEP_SECONDS = 30
# Accept the neighbouring steps so a phone clock a few seconds off, or a code
# typed just as it rolls over, still works.
DRIFT_STEPS = 1
RECOVERY_CODE_COUNT = 10


def generate_secret() -> str:
    """A 160-bit base32 secret, the size RFC 4226 recommends for SHA-1."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def code_for(secret: str, now: float | None = None) -> str:
    """The code an authenticator app shows at ``now`` (used by tests)."""
    return _code_at(secret, current_step(now))


def verify(secret: str, code: str, last_used_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None.

    A step at or before ``last_used_step`` is refused, so a code that was seen
    (shoulder-surfed, phished, logged) cannot be replayed inside its window.
    """
    code = "".join(code.split())
    if len(code) != DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    for candidate in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        if last_used_step is not None and candidate <= last_used_step:
            continue
        if hmac.compare_digest(_code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "ScanR") -> str:
    """The otpauth:// URI authenticator apps import (usually via QR code)."""
    label = quote(f"{issuer}:{account}")
    query = urlencode({"secret": secret, "issuer": issuer, "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"


def _normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.lower() if ch.isalnum())


def hash_recovery_code(code: str) -> str:
    # Recovery codes carry 50 bits of randomness, so an unsalted fast hash is
    # enough: there is no dictionary to precompute against.
    return hashlib.sha256(_normalize_recovery_code(code).encode()).hexdigest()


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Human-typable codes like ``k7m2p-q9xw4``."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def consume_recovery_code(code: str, stored_hashes: list[str]) -> list[str] | None:
    """Return the remaining hashes if ``code`` matched one, else None."""
    candidate = hash_recovery_code(code)
    for index, stored in enumerate(stored_hashes):
        if hmac.compare_digest(stored, candidate):
            return stored_hashes[:index] + stored_hashes[index + 1:]
    return None
