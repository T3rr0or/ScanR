"""Anti-CSRF tokens are not leaked secrets.

Every server-rendered framework puts a per-session CSRF token in the page — that
is the point of it. The generic `token="..."` pattern matches them, so without a
guard this plugin reports a *critical* "hardcoded secret" on most of the web.
Caught against a real Nextcloud instance during network validation.
"""
from scanr.plugins.web.api_key_exposure import ApiKeyExposurePlugin


def _hits(html: str) -> list:
    found: list = []
    ApiKeyExposurePlugin()._scan_content(html, "http://192.0.2.10/", found)
    return found


# ── framework CSRF tokens must not be reported ───────────────────────────────

def test_nextcloud_request_token_is_not_a_secret():
    """The exact markup that produced a false critical on a live host."""
    html = (
        '<html lang="en" data-locale="en"><head '
        'data-requesttoken="uKjpRUWZepRaCcZSsS2sOHkRCWpSLw0okPd5nEMePBs=:weahDw7VG8YwZK" >'
    )
    assert _hits(html) == []


def test_rails_style_csrf_meta_tag_is_not_a_secret():
    html = '<meta name="csrf-token" content="aB3xY9zQ1mN7pR4tK8wL2vC6">'
    assert _hits(html) == []


def test_aspnet_verification_token_is_not_a_secret():
    html = '<input name="__RequestVerificationToken" value="Kj8dLm2Qx7Rv4Tn8Wz1Yb3Hc9">'
    assert _hits(html) == []


def test_laravel_xsrf_token_is_not_a_secret():
    html = '<meta name="xsrf-token" content="eyJpdiI6IkxtMlF4N1J2NFRuOFd6MVliM0hjIn0">'
    assert _hits(html) == []


# ── real secrets must still be caught ────────────────────────────────────────

def test_a_genuine_api_key_is_still_reported():
    html = 'var config = { api_key: "sk9dLm2Qx7Rv4Tn8Wz1Yb3Hc" };'
    hits = _hits(html)
    assert len(hits) == 1
    assert hits[0]["pattern"] == "Generic Secret"


def test_a_real_secret_near_unrelated_text_is_still_reported():
    """The guard reads a narrow window, so it must not swallow nearby secrets."""
    html = '<div>some page copy</div><script>var secret = "Zx91QmLp44RtYv7Kd2Nw";</script>'
    assert len(_hits(html)) == 1


def test_a_vendor_prefixed_key_is_unaffected_by_the_guard():
    """Vendor patterns do not go through the CSRF check at all."""
    assert len(_hits('const k = "AKIAIOSFODNN7EXAMPLE";')) == 1


def test_the_secret_value_is_masked_in_the_hit():
    """Evidence must not reproduce the secret it is reporting."""
    html = 'api_key: "sk9dLm2Qx7Rv4Tn8Wz1Yb3Hc"'
    masked = _hits(html)[0]["masked"]
    assert "sk9dLm2Qx7Rv4Tn8Wz1Yb3Hc" not in masked
    assert "..." in masked
