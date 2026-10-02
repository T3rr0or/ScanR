import gzip

import pytest

from scanr.core import priority
from scanr.plugins.cve import epss


def _score(**kw):
    defaults = dict(severity="high", cvss_score=None, cve_ids=None, epss={}, kev=frozenset())
    return priority.compute(**{**defaults, **kw})


def test_exploited_medium_on_internet_outranks_theoretical_internal_critical():
    exploited = _score(severity="medium", cvss_score=6.5, cve_ids=["CVE-2024-1"],
                       kev={"CVE-2024-1"}, host_ip="8.8.8.8")
    theoretical = _score(severity="critical", cvss_score=9.8, cve_ids=["CVE-2024-2"],
                         epss={"CVE-2024-2": (0.001, 0.2)}, host_ip="10.0.0.5")
    assert exploited.score > theoretical.score
    assert exploited.is_kev and priority.band(exploited.score) == "fix now"
    assert any("CISA KEV" in r for r in exploited.reasons)
    assert "internet-facing host" in exploited.reasons


def test_epss_curve_and_reasons():
    low = _score(cvss_score=7.5, cve_ids=["CVE-1"], epss={"CVE-1": (0.01, 0.5)})
    high = _score(cvss_score=7.5, cve_ids=["CVE-1"], epss={"CVE-1": (0.81, 0.99)})
    assert low.score == pytest.approx(30 + 4)
    assert high.score == pytest.approx(30 + 36)
    assert high.epss_score == 0.81 and high.epss_percentile == 0.99
    assert "EPSS 81.0% chance of exploitation (CVE-1)" in high.reasons
    assert "EPSS >99.9% chance of exploitation (CVE-1)" in _score(cvss_score=7.5, cve_ids=["CVE-1"], epss={"CVE-1": (0.99999, 1.0)}).reasons
    assert "no exploitation data" in _score(cvss_score=7.5).reasons


def test_highest_epss_among_several_cves_wins():
    result = _score(cvss_score=5.0, cve_ids=["cve-a", "CVE-B"], epss={"CVE-A": (0.04, 0.1), "CVE-B": (0.25, 0.9)})
    assert result.epss_score == 0.25


def test_unknown_exploitation_validated_and_tags():
    plain = _score(severity="high")
    assert plain.score == 28 + 12
    assert _score(severity="high", validated=True).score == 28 + 35
    tagged = _score(severity="high", host_ip="192.168.1.4", host_tags={"Crown-Jewel"})
    assert tagged.score == pytest.approx(28 + 12 + 20 * (28 / 40) ** 0.5, abs=0.05)
    assert "host tagged crown-jewel" in tagged.reasons


def test_exposure_does_not_lift_minor_issues_over_internal_criticals():
    header = _score(severity="medium", host_ip="93.184.216.34")
    internal_critical = _score(severity="critical", cvss_score=9.1, host_ip="10.0.4.20")
    assert internal_critical.score > header.score


def test_info_is_capped_and_private_ips_are_not_exposed():
    assert _score(severity="info", cve_ids=["X"], kev={"X"}, host_ip="1.1.1.1").score == 10
    assert not priority.is_public_ip("10.1.2.3")
    assert not priority.is_public_ip("not-an-ip")
    assert priority.is_public_ip("2606:4700::1111")


def test_bands():
    assert [priority.band(s) for s in (95, 60, 41, 3)] == ["fix now", "fix soon", "plan", "low"]
    assert priority.band(None) is None


def test_parse_epss_feed():
    raw = gzip.compress(
        b"#model_version:v2026.06.15,score_date:2026-10-02T12:00:20Z\n"
        b"cve,epss,percentile\nCVE-1999-0001,0.03351,0.88299\ncve-2021-44228,0.94,0.9999\nbad,row,x\n"
    )
    date, rows = epss.parse_feed(raw)
    assert date == "2026-10-02T12:00:20Z"
    assert rows == [("CVE-1999-0001", 0.03351, 0.88299), ("CVE-2021-44228", 0.94, 0.9999)]


def test_epss_store_and_lookup(tmp_path, monkeypatch):
    from scanr.config import get_settings

    monkeypatch.setattr(get_settings(), "nvd_cache_dir", tmp_path)
    feed = "cve,epss,percentile\n" + "".join(f"CVE-2020-{i},0.{i:04d},0.5\n" for i in range(1500))
    raw = gzip.compress(("#score_date:2026-10-01T00:00:00Z\n" + feed).encode())

    class Resp:
        content = raw
        is_redirect = False

        def raise_for_status(self):
            pass

    class Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            return Resp()

    monkeypatch.setattr(epss.httpx, "Client", Client)
    assert epss.download_epss() == 1500
    assert epss.lookup(["cve-2020-12", "CVE-0000-0"]) == {"CVE-2020-12": (0.0012, 0.5)}
    status = epss.status()
    assert status["count"] == 1500 and status["score_date"] == "2026-10-01T00:00:00Z"


def test_truncated_epss_feed_keeps_previous_data(tmp_path, monkeypatch):
    from scanr.config import get_settings

    monkeypatch.setattr(get_settings(), "nvd_cache_dir", tmp_path)

    class Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            class R:
                content = gzip.compress(b"cve,epss,percentile\nCVE-1,0.1,0.1\n")
                is_redirect = False

                def raise_for_status(self):
                    pass
            return R()

    monkeypatch.setattr(epss.httpx, "Client", Client)
    with pytest.raises(ValueError):
        epss.download_epss()


def test_epss_redirects_must_stay_on_the_feed_host(monkeypatch):
    import httpx

    hops = {
        epss.EPSS_URL: httpx.Response(302, headers={"location": "/epss_scores-2026-10-02.csv.gz"}),
        "https://epss.empiricalsecurity.com/epss_scores-2026-10-02.csv.gz": httpx.Response(200, content=b"ok"),
        "https://evil.example/x": httpx.Response(200, content=b"no"),
    }

    def handler(request):
        return hops[str(request.url)]

    real_client = httpx.Client
    monkeypatch.setattr(epss.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    assert epss._fetch_feed() == b"ok"

    hops[epss.EPSS_URL] = httpx.Response(302, headers={"location": "https://evil.example/x"})
    with pytest.raises(ValueError, match="off-site"):
        epss._fetch_feed()
