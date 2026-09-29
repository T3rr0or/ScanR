"""ASP.NET ViewState protection.

Pins the plaintext-marker detection, the corruption used for the MAC probe, and
the fail-closed reading of the server's reply to that probe.
"""
from __future__ import annotations

import base64

from scanr.plugins.web.aspnet_viewstate import (
    corrupt_viewstate,
    decode_viewstate,
    is_plaintext,
    mac_is_validated,
    parse_hidden_fields,
    readable_strings,
    sensitive_content,
)


def _plaintext_vs(payload: bytes) -> str:
    return base64.b64encode(b"\xff\x01" + payload + b"\x00" * 8).decode()


def test_parse_hidden_fields():
    html = (
        '<input type="hidden" name="__VIEWSTATE" value="/wEP" />'
        "<input type=hidden name=__VIEWSTATEGENERATOR value=CA0B0334>"
    )
    fields = parse_hidden_fields(html)
    assert fields["__VIEWSTATE"] == "/wEP"
    assert fields["__VIEWSTATEGENERATOR"] == "CA0B0334"


def test_plaintext_marker_detection():
    assert is_plaintext(decode_viewstate(_plaintext_vs(b"x")))
    # Encrypted ViewState does not start with 0xFF01.
    assert not is_plaintext(base64.b64decode("YWJjZGVmZ2g="))


def test_sensitive_content_and_readable_strings():
    vs = _plaintext_vs(b"Data Source=sql01;Password=secret;")
    raw = decode_viewstate(vs)
    assert "SQL connection string" in sensitive_content(raw)
    assert "embedded password" in sensitive_content(raw)
    assert any("Data Source" in s for s in readable_strings(raw))


def test_corrupt_viewstate_changes_bytes_but_stays_base64():
    vs = _plaintext_vs(b"some reasonably long payload for the probe")
    corrupted = corrupt_viewstate(vs)
    assert corrupted != vs
    # Still valid base64 (decodes without error).
    assert decode_viewstate(corrupted) is not None


def test_mac_validation_fails_closed():
    # A rejection — the protection works.
    assert mac_is_validated(500, "")
    assert mac_is_validated(200, "Validation of viewstate MAC failed")
    assert mac_is_validated(403, "")
    # A clean render — the protection is not enforced.
    assert not mac_is_validated(200, "<html><body>Welcome</body></html>")
