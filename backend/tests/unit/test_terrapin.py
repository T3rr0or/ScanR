"""SSH Terrapin (CVE-2023-48795) exposure.

Pins the vulnerability logic: strict key exchange closes it whatever the ciphers,
and only the affected modes (ChaCha20-Poly1305, or CBC+EtM in the same direction)
count.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.ssh._kexinit import KexInit, parse_kexinit
from scanr.plugins.ssh.terrapin import (
    CHACHA_CIPHER,
    STRICT_KEX_MARKER,
    TerrapinPlugin,
    affected_modes,
    is_vulnerable,
)


def _port(number=22, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.40"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


# ── vulnerability logic ──────────────────────────────────────────────────────

def test_chacha_without_strict_kex_is_vulnerable():
    k = KexInit(encryption_s2c=[CHACHA_CIPHER], encryption_c2s=[CHACHA_CIPHER])
    assert is_vulnerable(k)
    assert CHACHA_CIPHER in affected_modes(k)


def test_strict_kex_closes_it_regardless_of_ciphers():
    k = KexInit(kex_algorithms=[STRICT_KEX_MARKER], encryption_s2c=[CHACHA_CIPHER])
    assert not is_vulnerable(k)


def test_cbc_with_etm_in_same_direction_is_vulnerable():
    k = KexInit(
        encryption_c2s=["aes256-cbc"],
        mac_c2s=["hmac-sha2-256-etm@openssh.com"],
    )
    assert is_vulnerable(k)


def test_cbc_and_etm_in_different_directions_do_not_combine():
    k = KexInit(
        encryption_c2s=["aes256-cbc"],
        mac_c2s=["hmac-sha2-256"],
        encryption_s2c=["aes256-gcm@openssh.com"],
        mac_s2c=["hmac-sha2-256-etm@openssh.com"],
    )
    assert not is_vulnerable(k)


def test_modern_only_server_is_not_vulnerable():
    k = KexInit(
        kex_algorithms=["curve25519-sha256"],
        encryption_s2c=["aes256-gcm@openssh.com"],
        mac_s2c=["hmac-sha2-256"],
    )
    assert not is_vulnerable(k)


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vulnerable_server_is_reported(monkeypatch):
    async def fake_read(ip, port):
        return KexInit(banner="SSH-2.0-OpenSSH_8.4", encryption_s2c=[CHACHA_CIPHER])
    monkeypatch.setattr(TerrapinPlugin, "_read_kexinit", staticmethod(fake_read))
    findings = await TerrapinPlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].cve_ids == ["CVE-2023-48795"]
    assert findings[0].port_number == 22


@pytest.mark.asyncio
async def test_patched_server_is_silent(monkeypatch):
    async def fake_read(ip, port):
        return KexInit(kex_algorithms=[STRICT_KEX_MARKER], encryption_s2c=[CHACHA_CIPHER])
    monkeypatch.setattr(TerrapinPlugin, "_read_kexinit", staticmethod(fake_read))
    assert await TerrapinPlugin().check(None, _host([_port()])) == []


@pytest.mark.asyncio
async def test_unreadable_server_is_silent(monkeypatch):
    async def fake_read(ip, port):
        return None
    monkeypatch.setattr(TerrapinPlugin, "_read_kexinit", staticmethod(fake_read))
    assert await TerrapinPlugin().check(None, _host([_port()])) == []


# ── KEXINIT parsing ──────────────────────────────────────────────────────────

def test_parse_kexinit_rejects_non_kexinit():
    assert parse_kexinit(b"\x14" * 4) is None    # too short
    assert parse_kexinit(b"\x15" + b"\x00" * 40) is None  # wrong message type


def test_parse_kexinit_reads_name_lists():
    import struct
    payload = bytes([20]) + b"\x00" * 16          # type + cookie
    lists = [b"curve25519-sha256", b"ssh-ed25519", b"aes256-gcm@openssh.com",
             b"chacha20-poly1305@openssh.com", b"hmac-sha2-256", b"hmac-sha2-512",
             b"none", b"none", b"", b""]
    for item in lists:
        payload += struct.pack(">I", len(item)) + item
    parsed = parse_kexinit(payload)
    assert parsed is not None
    assert parsed.kex_algorithms == ["curve25519-sha256"]
    assert parsed.encryption_s2c == ["chacha20-poly1305@openssh.com"]
