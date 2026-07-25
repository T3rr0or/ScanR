"""Rate-limit keying: X-Forwarded-For must only be honoured from a trusted peer.

The bundled deployment puts nginx in front of the API, so without TRUSTED_PROXIES
covering the Docker network the API keys every request by nginx's IP — one shared
bucket, so a single client can exhaust the login limit for everyone.
"""
import pytest

from scanr.core import limiter as limiter_mod


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, peer, headers=None):
        self.client = _FakeClient(peer) if peer else None
        self.headers = headers or {}


@pytest.fixture(autouse=True)
def _reset_caches():
    limiter_mod._trusted_networks.cache_clear()
    limiter_mod._warned_untrusted_xff = False
    yield
    limiter_mod._trusted_networks.cache_clear()
    limiter_mod._warned_untrusted_xff = False


def _with_trusted(monkeypatch, value: str):
    """Point the limiter's settings lookup at a specific TRUSTED_PROXIES value."""
    from scanr.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(
        type(settings), "trusted_proxy_list",
        property(lambda self: [p.strip() for p in value.split(",") if p.strip()]),
    )


def test_xff_ignored_from_untrusted_peer(monkeypatch):
    _with_trusted(monkeypatch, "")
    req = _FakeRequest("172.18.0.5", {"X-Forwarded-For": "1.2.3.4"})
    assert limiter_mod._real_ip(req) == "172.18.0.5"


def test_xff_honoured_from_trusted_peer(monkeypatch):
    _with_trusted(monkeypatch, "172.16.0.0/12")
    req = _FakeRequest("172.18.0.5", {"X-Forwarded-For": "1.2.3.4"})
    assert limiter_mod._real_ip(req) == "1.2.3.4"


def test_leftmost_xff_entry_wins(monkeypatch):
    _with_trusted(monkeypatch, "172.16.0.0/12")
    req = _FakeRequest("172.18.0.5", {"X-Forwarded-For": "1.2.3.4, 10.0.0.1, 172.18.0.5"})
    assert limiter_mod._real_ip(req) == "1.2.3.4"


def test_spoofed_xff_from_outside_the_trusted_range_is_ignored(monkeypatch):
    """A client that can reach the API directly must not choose its own key."""
    _with_trusted(monkeypatch, "172.16.0.0/12")
    req = _FakeRequest("203.0.113.9", {"X-Forwarded-For": "1.2.3.4"})
    assert limiter_mod._real_ip(req) == "203.0.113.9"


def test_no_client_falls_back_to_unknown(monkeypatch):
    _with_trusted(monkeypatch, "172.16.0.0/12")
    assert limiter_mod._real_ip(_FakeRequest(None)) == "unknown"


def test_unparseable_trusted_entry_is_skipped_not_fatal(monkeypatch):
    _with_trusted(monkeypatch, "not-a-cidr,172.16.0.0/12")
    req = _FakeRequest("172.18.0.5", {"X-Forwarded-For": "1.2.3.4"})
    assert limiter_mod._real_ip(req) == "1.2.3.4"


def test_untrusted_xff_warns_once(monkeypatch, caplog):
    """The shared-bucket misconfiguration must be visible in the logs."""
    _with_trusted(monkeypatch, "")
    req = _FakeRequest("172.18.0.5", {"X-Forwarded-For": "1.2.3.4"})
    with caplog.at_level("WARNING", logger="scanr.core.limiter"):
        limiter_mod._real_ip(req)
        limiter_mod._real_ip(req)
    warnings = [r for r in caplog.records if "TRUSTED_PROXIES" in r.getMessage()]
    assert len(warnings) == 1, "should warn exactly once, not per request"


def test_no_warning_when_there_is_no_proxy(monkeypatch, caplog):
    """Direct exposure with no XFF is a valid setup — don't cry wolf."""
    _with_trusted(monkeypatch, "")
    with caplog.at_level("WARNING", logger="scanr.core.limiter"):
        assert limiter_mod._real_ip(_FakeRequest("203.0.113.9")) == "203.0.113.9"
    assert not [r for r in caplog.records if "TRUSTED_PROXIES" in r.getMessage()]


def test_limiter_uses_shared_redis_storage():
    """Per-process memory storage would make limits per-worker."""
    from scanr.config import get_settings

    assert limiter_mod.limiter._storage_uri == get_settings().redis_url
    assert limiter_mod.limiter._storage_uri.startswith("redis://")
