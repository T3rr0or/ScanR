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
    key = settings.vault_key
    if not key:
        raise VaultError(
            "VAULT_KEY is not set. Generate one with: "
            "python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        raise VaultError("Invalid vault key — must be a valid Fernet key") from exc


def encrypt(data: dict) -> str:
    """Encrypt a dict and return URL-safe base64 ciphertext string.
    
    Supports hash_type field for NTLM hash credentials:
      encrypt({"password": "...", "hash_type": "ntlm"})
    """
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
