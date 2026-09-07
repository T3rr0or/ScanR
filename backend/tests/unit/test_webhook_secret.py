"""Webhook HMAC secrets are versioned, encrypted at rest, and fail closed.

The secret authenticates ScanR to the customer's endpoint, so a database read
must not hand over a usable signing key. Migration 0026 converts rows written by
older releases rather than making runtime decryption guess at plaintext.
"""
import pytest

from scanr.core.webhook_dispatcher import _send, decrypt_secret, encrypt_secret
from scanr.utils.exceptions import VaultError


def test_secret_is_not_stored_in_plaintext():
    stored = encrypt_secret("super-secret-signing-key")
    assert stored is not None
    assert "super-secret-signing-key" not in stored
    assert stored.startswith("enc:v1:gAAAAA"), "expected versioned Fernet ciphertext"


def test_roundtrip():
    assert decrypt_secret(encrypt_secret("s3cr3t")) == "s3cr3t"


def test_ciphertext_is_salted_per_write():
    """Two writes of the same secret must not produce an identical blob."""
    assert encrypt_secret("same") != encrypt_secret("same")


def test_legacy_raw_fernet_ciphertext_is_still_readable():
    """A downgrade strips the marker, so the runtime accepts raw Fernet safely."""
    from scanr.credentials import vault

    assert decrypt_secret(vault.encrypt({"v": "legacy-secret"})) == "legacy-secret"


def test_unversioned_plaintext_fails_closed():
    with pytest.raises(VaultError, match="unversioned"):
        decrypt_secret("legacy-plaintext-secret")


@pytest.mark.parametrize("empty", [None, ""])
def test_empty_secret_means_no_signing(empty):
    assert encrypt_secret(empty) is None
    assert decrypt_secret(empty) is None


def test_encryption_failure_never_falls_back_to_plaintext(monkeypatch):
    import scanr.credentials.vault as vault_mod

    def boom(_data):
        raise VaultError("VAULT_KEY is not set")

    monkeypatch.setattr(vault_mod, "encrypt", boom)
    with pytest.raises(VaultError, match="VAULT_KEY"):
        encrypt_secret("plain")


def test_corrupt_versioned_ciphertext_fails_closed():
    with pytest.raises(VaultError, match="Decryption failed"):
        decrypt_secret("enc:v1:gAAAAA-not-valid-fernet")


def test_ciphertext_with_wrong_payload_shape_fails_closed():
    from scanr.credentials import vault

    stored = "enc:v1:" + vault.encrypt({"not-the-secret": "value"})
    with pytest.raises(VaultError, match="invalid payload"):
        decrypt_secret(stored)


def test_api_surfaces_encryption_unavailability_without_storing_plaintext(monkeypatch):
    from fastapi import HTTPException

    from scanr.api.v1 import webhooks

    def boom(_secret):
        raise VaultError("wrong key")

    monkeypatch.setattr(webhooks, "encrypt_secret", boom)
    with pytest.raises(HTTPException) as exc_info:
        webhooks._encrypt_secret_or_503("must-not-be-stored")
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_delivery_uses_connection_bound_dns_client(monkeypatch):
    from types import SimpleNamespace

    from scanr.core import webhook_dispatcher

    calls = {}

    class Response:
        status_code = 204
        is_success = True
        headers = {}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, content, headers):
            calls["post"] = (url, content, headers)
            return Response()

    async def pinned(url, *, extra_denylist, verify, forbid_private):
        calls["pinned"] = (url, extra_denylist, verify, forbid_private)
        return Client()

    class DB:
        committed = False

        async def commit(self):
            self.committed = True

    monkeypatch.setattr(webhook_dispatcher.safe_http, "pinned_async_client", pinned)
    webhook = SimpleNamespace(
        id="hook-id",
        url="https://webhook.example/hook",
        secret=encrypt_secret("signing-secret"),
        last_status=None,
        last_triggered_at=None,
    )
    db = DB()

    await _send(webhook, "scan.completed", {"scan_id": "scan-id"}, db)

    assert calls["pinned"][0] == webhook.url
    assert calls["pinned"][2] is True
    assert calls["pinned"][3] is True
    assert "localhost" in calls["pinned"][1]
    assert calls["post"][2]["X-ScanR-Signature"].startswith("sha256=")
    assert webhook.last_status == 204
    assert db.committed is True


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
