import bcrypt
import logging

logger = logging.getLogger(__name__)

_TARGET_ROUNDS = 14

# bcrypt hashes at most 72 bytes of input and (since bcrypt 5.0) *raises* on
# anything longer rather than silently truncating. The ceiling belongs to the
# algorithm, not to any one endpoint, so callers validate against this constant.
#
# It is a *byte* limit, not a character one: pydantic's max_length counts
# characters, and ~24 emoji or ~36 CJK characters already exceed 72 bytes while
# passing a max_length=72 check. Always measure the UTF-8 encoding.
MAX_PASSWORD_BYTES = 72


def password_within_bcrypt_limit(plain: str) -> bool:
    """True if ``plain`` is short enough for bcrypt to hash."""
    return len(plain.encode("utf-8")) <= MAX_PASSWORD_BYTES


def hash_password(plain: str) -> str:
    # Backstop for callers that skipped validation (config seeding, future call
    # sites). Raising a clear error beats bcrypt's raw one, but the request-facing
    # paths should reject over-long input at the schema layer so the client gets
    # a 422 rather than a 500.
    if not password_within_bcrypt_limit(plain):
        raise ValueError(
            f"password must be at most {MAX_PASSWORD_BYTES} bytes when UTF-8 encoded "
            f"(got {len(plain.encode('utf-8'))})"
        )
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=_TARGET_ROUNDS)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception as exc:
        logger.error("bcrypt verify failed (corrupted hash?): %s", exc)
        return False


def needs_rehash(hashed: str) -> bool:
    """Return True if the stored hash uses fewer rounds than the current target."""
    try:
        parts = hashed.split("$")
        # Format: $2b$<rounds>$<salt+hash>
        return len(parts) >= 3 and int(parts[2]) < _TARGET_ROUNDS
    except (ValueError, IndexError):
        return False
