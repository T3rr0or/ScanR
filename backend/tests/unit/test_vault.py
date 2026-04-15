import pytest
from cryptography.fernet import Fernet

from scanr.credentials.vault import decrypt, encrypt
from scanr.utils.exceptions import VaultError


def test_encrypt_decrypt_roundtrip(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr("scanr.credentials.vault.settings.vault_key", key)

    data = {"username": "admin", "password": "s3cr3t"}
    ciphertext = encrypt(data)
    assert isinstance(ciphertext, str)
    assert ciphertext != str(data)

    recovered = decrypt(ciphertext)
    assert recovered == data


def test_decrypt_wrong_key(monkeypatch):
    key1 = Fernet.generate_key().decode()
    key2 = Fernet.generate_key().decode()

    monkeypatch.setattr("scanr.credentials.vault.settings.vault_key", key1)
    ciphertext = encrypt({"secret": "value"})

    monkeypatch.setattr("scanr.credentials.vault.settings.vault_key", key2)
    with pytest.raises(VaultError):
        decrypt(ciphertext)


def test_decrypt_garbage():
    with pytest.raises(VaultError):
        decrypt("not-valid-fernet-data")
