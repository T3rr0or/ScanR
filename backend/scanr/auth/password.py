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


# A real hash at _TARGET_ROUNDS, used to spend the same time verifying a
# password for an account that does not exist as for one that does. Without it,
# an unknown email returns in microseconds while a known email costs a full
# bcrypt verify, and that gap alone enumerates accounts. Kept as a constant
# because generating it at import would cost a bcrypt round-trip per process;
# test_password_dummy_verify_matches_target_cost pins it to _TARGET_ROUNDS.
_DUMMY_HASH = "$2b$14$2Qk/OpH0P7t9cIf6OZ5a6eOraEQZBCI230dOhsdNG5AIZiFuu/Z7K"


def dummy_verify(plain: str) -> None:
    """Burn one bcrypt verification and discard the result.

    Call on the "no such user" branch of a login so both branches take the same
    observable time.
    """
    try:
        bcrypt.checkpw(plain.encode()[:MAX_PASSWORD_BYTES], _DUMMY_HASH.encode())
    except Exception:
        pass


def needs_rehash(hashed: str) -> bool:
    """Return True if the stored hash uses fewer rounds than the current target."""
    try:
        parts = hashed.split("$")
        # Format: $2b$<rounds>$<salt+hash>
        return len(parts) >= 3 and int(parts[2]) < _TARGET_ROUNDS
    except (ValueError, IndexError):
        return False
