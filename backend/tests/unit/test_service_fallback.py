"""Unit tests for the service-on-non-standard-port fallback (pure logic)."""
from scanr.core.plugin_base import Severity
from scanr.plugins.services.service_fallback import ServiceFallbackPlugin, _classify_banner


def test_classify_banner_definitive_only():
    assert _classify_banner("RFB 003.008") == "vnc"
    assert _classify_banner("220 mail.example.com ESMTP Postfix") == "smtp"
    assert _classify_banner("220 (vsFTPd 3.0.3)") == "ftp"
    assert _classify_banner("220 ProFTPD 1.3.5 Server ready") == "ftp"
    assert _classify_banner("220 Welcome FTP service") == "ftp"
    # ambiguous / non-target → no classification (no false positive)
    assert _classify_banner("220 some-service ready") is None
    assert _classify_banner("HTTP/1.1 400 Bad Request") is None
    assert _classify_banner("") is None
    assert _classify_banner(None) is None


def test_banner_findings():
    p = ServiceFallbackPlugin()
    fs = p._banner_findings("ftp", "192.0.2.1", 2100, "220 (vsFTPd 3.0.3)")
    assert len(fs) == 1
    assert "FTP" in fs[0].title and "2100" in fs[0].title
    assert fs[0].port_number == 2100
    assert fs[0].severity == Severity.low
    assert "vsFTPd" in fs[0].evidence

    vnc = p._banner_findings("vnc", "192.0.2.1", 15900, "RFB 003.008")
    assert vnc[0].severity == Severity.low and "VNC" in vnc[0].title


def test_redis_findings_unauth_is_high():
    p = ServiceFallbackPlugin()
    hi = p._redis_findings("unauth", "192.0.2.1", 16379)
    assert hi[0].severity == Severity.high
    assert "Unauthenticated Redis" in hi[0].title
    lo = p._redis_findings("auth", "192.0.2.1", 16379)
    assert lo[0].severity == Severity.low
