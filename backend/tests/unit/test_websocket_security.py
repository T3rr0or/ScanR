"""WebSocket handshake security.

Pins the Sec-WebSocket-Accept computation (RFC 6455 test vector), the strict
handshake-acceptance check, the ws:// endpoint extraction and the session-cookie
heuristic.
"""
from __future__ import annotations

from scanr.plugins.web.websocket_security import (
    expected_accept,
    extract_ws_targets,
    looks_like_session_cookie,
    parse_handshake_response,
)


def test_accept_matches_rfc6455_vector():
    # RFC 6455 §1.3 worked example.
    assert expected_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_valid_101_with_correct_accept_is_accepted():
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    raw = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        f"Sec-WebSocket-Accept: {expected_accept(key)}\r\n\r\n"
    ).encode()
    result = parse_handshake_response(raw, key)
    assert result.accepted


def test_101_with_wrong_accept_is_not_accepted():
    raw = b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n"
    assert not parse_handshake_response(raw, "dGhlIHNhbXBsZSBub25jZQ==").accepted


def test_403_is_not_accepted():
    result = parse_handshake_response(b"HTTP/1.1 403 Forbidden\r\n\r\n", "k")
    assert result is not None and not result.accepted


def test_non_http_reply_is_none():
    assert parse_handshake_response(b"\x16\x03\x01\x00", "k") is None
    assert parse_handshake_response(b"", "k") is None


def test_extract_ws_targets_finds_paths_and_plaintext():
    body = (
        'new WebSocket("wss://t.example/ws");'
        'var u = "ws://t.example/live";'
        'connect("wss://other.net/skip");'   # cross-origin, skipped as a path
    )
    paths, plaintext = extract_ws_targets(body, "https://t.example:443")
    assert "/ws" in paths and "/live" in paths
    assert "ws://t.example/live" in plaintext


def test_session_cookie_heuristic():
    assert looks_like_session_cookie(["JSESSIONID=abc; Path=/"]) == ["JSESSIONID"]
    assert looks_like_session_cookie(["theme=dark"]) == []
