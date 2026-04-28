import bcrypt
import logging

logger = logging.getLogger(__name__)

_TARGET_ROUNDS = 14


def hash_password(plain: str) -> str:
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
