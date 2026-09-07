"""bcrypt's 72-byte input ceiling, enforced as a byte limit rather than a
character one.

bcrypt 5.0 raises on over-long input instead of truncating it, so an
unvalidated passphrase reaches the hasher and surfaces as a 500. The limit is
counted in UTF-8 bytes: a max_length check would count characters and let a
short multi-byte passphrase through.
"""
import pytest

from scanr.auth.password import (
    MAX_PASSWORD_BYTES,
    hash_password,
    password_within_bcrypt_limit,
    verify_password,
)


def test_limit_is_measured_in_bytes_not_characters():
    # 24 emoji = 96 bytes but only 24 characters: a character-based check would
    # wave this through and bcrypt would then raise.
    emoji = "🔒" * 24
    assert len(emoji) < MAX_PASSWORD_BYTES
    assert len(emoji.encode("utf-8")) > MAX_PASSWORD_BYTES
    assert not password_within_bcrypt_limit(emoji)


def test_exact_boundary_is_allowed():
    assert password_within_bcrypt_limit("A" * MAX_PASSWORD_BYTES)
    assert not password_within_bcrypt_limit("A" * (MAX_PASSWORD_BYTES + 1))


def test_boundary_password_round_trips():
    pw = "A" * MAX_PASSWORD_BYTES
    assert verify_password(pw, hash_password(pw))


def test_hash_password_rejects_over_long_input_with_a_clear_error():
    with pytest.raises(ValueError, match="at most 72 bytes"):
        hash_password("A" * 80)


def test_password_dummy_verify_matches_target_cost():
    """The dummy hash must cost the same as a real one.

    dummy_verify exists so a login for an unknown email spends the same time as
    one for a known email. A hash at fewer rounds than _TARGET_ROUNDS would be
    cheaper to verify and reopen the enumeration timing gap it closes.
    """
    from scanr.auth.password import _DUMMY_HASH, _TARGET_ROUNDS, dummy_verify

    assert _DUMMY_HASH.split("$")[2] == f"{_TARGET_ROUNDS:02d}"
    # Real hashes and the dummy agree on cost, so neither branch is faster.
    assert hash_password("x").split("$")[2] == _DUMMY_HASH.split("$")[2]
    # Never matches, never raises — including on input bcrypt would reject.
    dummy_verify("anything")
    dummy_verify("A" * 200)
