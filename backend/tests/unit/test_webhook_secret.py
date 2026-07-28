"""Webhook HMAC secrets are encrypted at rest, and legacy plaintext still works.

The secret authenticates ScanR to the customer's endpoint, so a database read
should not hand over a usable signing key. Rows written before encryption must
keep working — there is no data migration.
"""
import pytest

from scanr.core.webhook_dispatcher import decrypt_secret, encrypt_secret


def test_secret_is_not_stored_in_plaintext():
    stored = encrypt_secret("super-secret-signing-key")
    assert stored is not None
    assert "super-secret-signing-key" not in stored
    assert stored.startswith("gAAAAA"), "expected Fernet ciphertext"


def test_roundtrip():
    assert decrypt_secret(encrypt_secret("s3cr3t")) == "s3cr3t"


def test_ciphertext_is_salted_per_write():
    """Two writes of the same secret must not produce an identical blob."""
    assert encrypt_secret("same") != encrypt_secret("same")


def test_legacy_plaintext_is_still_readable():
    """Pre-encryption rows hold the raw secret; reading must not break them."""
    assert decrypt_secret("legacy-plaintext-secret") == "legacy-plaintext-secret"


@pytest.mark.parametrize("empty", [None, ""])
def test_empty_secret_means_no_signing(empty):
    assert encrypt_secret(empty) is None
    assert decrypt_secret(empty) is None


def test_falls_back_to_plaintext_without_vault_key(monkeypatch, caplog):
    """VAULT_KEY is optional — a missing key must not stop webhooks being saved,
    but it must be logged."""
    from scanr.utils.exceptions import VaultError

    import scanr.credentials.vault as vault_mod

    def boom(_data):
        raise VaultError("VAULT_KEY is not set")

    monkeypatch.setattr(vault_mod, "encrypt", boom)
    with caplog.at_level("WARNING", logger="scanr.core.webhook_dispatcher"):
        assert encrypt_secret("plain") == "plain"
    assert any("VAULT_KEY" in r.getMessage() for r in caplog.records)


def test_signature_uses_the_decrypted_secret():
    """The wire signature must be computed over the plaintext secret, so existing
    receivers keep verifying after the storage change."""
    import hashlib
    import hmac

    secret, body = "shared-secret", '{"event":"test"}'
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    stored = encrypt_secret(secret)
    actual = hmac.new(
        decrypt_secret(stored).encode(), body.encode(), hashlib.sha256
    ).hexdigest()
    assert actual == expected
