"""Unit tests for the service-on-non-standard-port fallback (pure logic)."""
import struct

from scanr.core.plugin_base import Severity
from scanr.plugins.services.service_fallback import (
    ServiceFallbackPlugin,
    _classify_banner,
    _match_mongo,
    _match_mysql,
    _match_postgres,
    _match_rdp,
)


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


def test_match_mysql():
    greeting = b"\x36\x00\x00" + b"\x00" + b"\x0a" + b"8.0.32\x00" + b"\x00" * 10
    assert _match_mysql(greeting) == "8.0.32"
    assert _match_mysql(b"HTTP/1.1 200 OK\r\n") is None
    assert _match_mysql(b"\x00\x00") is None


def test_match_postgres():
    assert _match_postgres(b"S") is True
    assert _match_postgres(b"N") is True
    assert _match_postgres(b"SS") is False
    assert _match_postgres(b"HTTP") is False


def test_match_rdp():
    cc = b"\x03\x00\x00\x13\x0e\xd0" + b"\x00" * 10  # TPKT + X.224 Connection Confirm
    assert _match_rdp(cc) is True
    assert _match_rdp(b"\x03\x00\x00\x08\x00\x00") is False  # not a CC
    assert _match_rdp(b"HTTP/1.1") is False


def test_match_mongo():
    reply = b"\x00" * 12 + struct.pack("<i", 1) + b"\x00" * 8   # opcode 1 = OP_REPLY
    assert _match_mongo(reply) is True
    op_msg = b"\x00" * 12 + struct.pack("<i", 2013)
    assert _match_mongo(op_msg) is True
    op_query = b"\x00" * 12 + struct.pack("<i", 2004)
    assert _match_mongo(op_query) is False
    assert _match_mongo(b"short") is False


def test_redis_state():
    p = ServiceFallbackPlugin()
    assert p._redis_state(b"+PONG\r\n") == "unauth"
    assert p._redis_state(b"-NOAUTH Authentication required.\r\n") == "auth"
    assert p._redis_state(b"+OK\r\n") is None
    assert p._redis_state(b"") is None


def test_finding_builders():
    p = ServiceFallbackPlugin()
    ftp = p._banner_findings("ftp", "192.0.2.1", 2100, "220 (vsFTPd 3.0.3)")
    assert ftp[0].severity == Severity.low and "FTP" in ftp[0].title and "2100" in ftp[0].title

    my = p._db_findings("mysql", "192.0.2.1", 13306, "MySQL 8.0.32")
    assert my[0].severity == Severity.medium and "MySQL" in my[0].title

    rdp = p._db_findings("rdp", "192.0.2.1", 13389, "rdp handshake confirmed")
    assert "RDP" in rdp[0].title and rdp[0].severity == Severity.medium

    hi = p._redis_findings("unauth", "192.0.2.1", 16379)
    assert hi[0].severity == Severity.high and "Unauthenticated Redis" in hi[0].title
