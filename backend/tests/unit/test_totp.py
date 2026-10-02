import base64

from scanr.auth import totp

# RFC 6238 Appendix B, SHA-1 seed. The RFC lists 8-digit codes; authenticator
# apps show the last 6 digits.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = {59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}


def test_rfc6238_vectors():
    for timestamp, expected in RFC_VECTORS.items():
        assert totp.code_for(RFC_SECRET, now=timestamp) == expected


def test_verify_accepts_neighbouring_steps_and_refuses_replays():
    now = 1_700_000_000
    step = totp.current_step(now)
    previous = totp._code_at(RFC_SECRET, step - 1)
    assert totp.verify(RFC_SECRET, previous, None, now=now) == step - 1
    assert totp.verify(RFC_SECRET, previous, step - 1, now=now) is None
    assert totp.verify(RFC_SECRET, totp._code_at(RFC_SECRET, step - 2), None, now=now) is None
    assert totp.verify(RFC_SECRET, " " + totp.code_for(RFC_SECRET, now)[:3] + " " + totp.code_for(RFC_SECRET, now)[3:], None, now=now) == step
    assert totp.verify(RFC_SECRET, "abcdef", None, now=now) is None


def test_recovery_codes_normalise_and_consume_once():
    codes = totp.generate_recovery_codes()
    assert len(set(codes)) == len(codes) == totp.RECOVERY_CODE_COUNT
    hashes = [totp.hash_recovery_code(c) for c in codes]
    remaining = totp.consume_recovery_code(codes[3].upper().replace("-", " "), hashes)
    assert remaining is not None and len(remaining) == len(hashes) - 1
    assert totp.consume_recovery_code(codes[3], remaining) is None


def test_provisioning_uri():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "a@b.example")
    assert uri.startswith("otpauth://totp/ScanR%3Aa%40b.example?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri and "issuer=ScanR" in uri
