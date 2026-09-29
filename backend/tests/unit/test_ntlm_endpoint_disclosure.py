"""HTTP NTLM information disclosure.

Pins the Type 1 message construction (no credential in it) and the Type 2
challenge decoder that recovers the internal AD names and OS build.
"""
from __future__ import annotations

import base64
import struct

from scanr.plugins.web.ntlm_endpoint_disclosure import (
    build_type1_message,
    parse_challenge,
)


def _av(av_id: int, text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<HH", av_id, len(raw)) + raw


def _challenge(*, with_version=True) -> str:
    target = "CORP".encode("utf-16-le")
    info = (
        _av(2, "CORP") + _av(1, "EXCH01") + _av(4, "corp.example.com")
        + _av(3, "exch01.corp.example.com") + _av(5, "example.com")
        + struct.pack("<HH", 0, 0)
    )
    flags = 0x02800000 if with_version else 0x00800000
    header_len = 56
    name_off = header_len
    info_off = name_off + len(target)
    msg = b"NTLMSSP\x00" + struct.pack("<I", 2)
    msg += struct.pack("<HHI", len(target), len(target), name_off)
    msg += struct.pack("<I", flags)
    msg += b"\x11" * 8 + b"\x00" * 8
    msg += struct.pack("<HHI", len(info), len(info), info_off)
    msg += struct.pack("<BBH", 10, 0, 17763) + b"\x00\x00\x00\x0f"
    assert len(msg) == header_len
    msg += target + info
    return base64.b64encode(msg).decode()


def test_type1_message_carries_no_credential():
    raw = base64.b64decode(build_type1_message())
    assert raw[:8] == b"NTLMSSP\x00"
    assert struct.unpack("<I", raw[8:12])[0] == 1     # negotiate
    assert len(raw) == 32                             # header only, no name/hash


def test_challenge_decodes_domain_computer_and_version():
    c = parse_challenge("NTLM " + _challenge())
    disclosed = c.disclosed()
    assert disclosed["NetBIOS domain"] == "CORP"
    assert disclosed["DNS domain"] == "corp.example.com"
    assert disclosed["DNS computer"] == "exch01.corp.example.com"
    assert "17763" in disclosed["Windows version"]


def test_negotiate_prefix_is_accepted():
    assert parse_challenge("Negotiate " + _challenge()) is not None


def test_non_ntlm_schemes_are_rejected():
    assert parse_challenge("Basic realm=x") is None
    assert parse_challenge("NTLM !!!not-base64") is None
    assert parse_challenge("") is None


def test_challenge_without_version_still_decodes_names():
    c = parse_challenge("NTLM " + _challenge(with_version=False))
    assert c.netbios_domain == "CORP"
    assert c.os_version == ""
