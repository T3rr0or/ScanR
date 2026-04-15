from __future__ import annotations

import base64
import json
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken

from scanr.config import get_settings
from scanr.utils.exceptions import VaultError

settings = get_settings()


def _get_fernet() -> Fernet:
    import logging as _logging
    _log = _logging.getLogger(__name__)
    key = settings.vault_key
    if not key:
        _log.critical(
            "VAULT_KEY is not set — generating a random key. "
            "Credentials encrypted now CANNOT be decrypted after restart. "
            "Set the VAULT_KEY environment variable in production."
        )
        key = Fernet.generate_key().decode()
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        raise VaultError("Invalid vault key") from exc


def encrypt(data: dict) -> str:
    """Encrypt a dict and return URL-safe base64 ciphertext string."""
    f = _get_fernet()
    plaintext = json.dumps(data).encode()
    return f.encrypt(plaintext).decode()


def decrypt(ciphertext: str) -> dict:
    """Decrypt ciphertext back to dict."""
    f = _get_fernet()
    try:
        plaintext = f.decrypt(ciphertext.encode())
        return json.loads(plaintext)
    except InvalidToken as exc:
        raise VaultError("Decryption failed — wrong key or corrupted data") from exc
