"""Authenticated LDAP: which certificates are trusted, and failing loudly."""
import ssl
from types import SimpleNamespace

import pytest

from scanr.plugins.services import _ldap_secure
from scanr.plugins.services._ldap_secure import LdapTlsError, run_ldap_check, secure_ldap_connection
from scanr.plugins.services.kerberoastable import KerberoastablePlugin
from scanr.plugins.services.ldap_user_enum import LdapUserEnumPlugin


class _FakeLdap3:
    ALL = object()

    class Tls:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class Server:
        def __init__(self, ip, **kwargs):
            self.ip = ip
            self.kwargs = kwargs
            self.info = None

    class Connection:
        def __init__(self, server, **kwargs):
            self.server = server

        def open(self):
            return True

        def start_tls(self):
            return True

        def bind(self):
            return True

        def unbind(self):
            return True


class _Log:
    def __init__(self):
        self.warnings = []

    async def warn(self, message, **_kwargs):
        self.warnings.append(message)


@pytest.fixture
def no_ca_file(monkeypatch):
    settings = SimpleNamespace(ldap_ca_file=None)
    monkeypatch.setattr("scanr.config.get_settings", lambda: settings)
    return settings


def test_certificate_may_name_the_dc_hostname(no_ca_file):
    conn = secure_ldap_connection(
        _FakeLdap3, "192.0.2.10", 389, "u", "p",
        hostnames=("dc01.corp.example.", None, "dc01.corp.example"),
    )
    tls = conn.server.kwargs["tls"].kwargs
    assert tls["validate"] == ssl.CERT_REQUIRED
    assert tls["valid_names"] == ["192.0.2.10", "dc01.corp.example"]


def test_internal_ca_bundle_is_trusted_when_configured(no_ca_file, tmp_path):
    no_ca_file.ldap_ca_file = tmp_path / "corp-root.pem"
    no_ca_file.ldap_ca_file.write_text("-----BEGIN CERTIFICATE-----\n")
    conn = secure_ldap_connection(_FakeLdap3, "192.0.2.10", 636, "u", "p")
    tls = conn.server.kwargs["tls"].kwargs
    assert tls["ca_certs_file"] == str(tmp_path / "corp-root.pem")
    assert tls["validate"] == ssl.CERT_REQUIRED


def test_missing_ca_file_fails_with_an_actionable_error(no_ca_file, tmp_path):
    no_ca_file.ldap_ca_file = tmp_path / "missing.pem"
    with pytest.raises(LdapTlsError, match="LDAP_CA_FILE"):
        secure_ldap_connection(_FakeLdap3, "192.0.2.10", 636, "u", "p")


def test_empty_setting_means_no_extra_ca(monkeypatch):
    from scanr.config import Settings

    assert Settings._empty_ca_file_is_unset("") is None
    assert Settings._empty_ca_file_is_unset("  ") is None
    assert Settings._empty_ca_file_is_unset("/app/certs/ca.pem") == "/app/certs/ca.pem"


def test_ldaps_certificate_rejection_is_a_tls_error(no_ca_file):
    class Rejected(_FakeLdap3.Connection):
        def bind(self):
            raise Exception("socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED]")

    class Fake(_FakeLdap3):
        Connection = Rejected

    with pytest.raises(LdapTlsError, match="CERTIFICATE_VERIFY_FAILED"):
        secure_ldap_connection(Fake, "192.0.2.10", 636, "u", "p")


def test_wrong_password_is_not_reported_as_tls(no_ca_file):
    class BadCreds(_FakeLdap3.Connection):
        def bind(self):
            return False

    class Fake(_FakeLdap3):
        Connection = BadCreds

    with pytest.raises(RuntimeError) as exc:
        secure_ldap_connection(Fake, "192.0.2.10", 389, "u", "p")
    assert not isinstance(exc.value, LdapTlsError)


@pytest.mark.asyncio
async def test_tls_rejection_is_explained_in_the_scan_log():
    context = SimpleNamespace(log=_Log())

    def blocking():
        raise LdapTlsError("LDAP StartTLS negotiation failed")

    assert await run_ldap_check(context, "services.kerberoastable", "192.0.2.10", blocking) == []
    assert len(context.log.warnings) == 1
    assert "LDAP_CA_FILE" in context.log.warnings[0]
    assert "192.0.2.10" in context.log.warnings[0]


def _dc(*ports, hostname="dc01.corp.example"):
    return SimpleNamespace(
        ip="192.0.2.10", hostname=hostname,
        ports=[SimpleNamespace(number=p, state="open") for p in ports],
    )


def _ctx():
    creds = {"username": "auditor", "password": "pw", "domain": "corp.example"}
    return SimpleNamespace(log=_Log(), credential=lambda _role: creds, credential_data=creds)


@pytest.mark.asyncio
async def test_plugin_passes_hostname_and_warns_on_rejection(monkeypatch):
    seen = {}

    def reject(*args, hostnames=(), **kwargs):
        seen["hostnames"] = hostnames
        raise LdapTlsError("LDAP StartTLS negotiation failed")

    monkeypatch.setattr(_ldap_secure, "secure_ldap_connection", reject)
    context = _ctx()
    assert await KerberoastablePlugin().check(context, _dc(88, 389)) == []
    assert seen["hostnames"] == ("dc01.corp.example",)
    assert len(context.log.warnings) == 1


@pytest.mark.asyncio
async def test_user_enum_falls_back_to_starttls_without_warning(monkeypatch):
    attempts = []

    def connect(ldap3, ip, port, *args, **kwargs):
        attempts.append(port)
        if port == 636:
            raise LdapTlsError("LDAPS TLS handshake failed")
        raise RuntimeError("LDAP bind failed")  # 389 reached: TLS was fine

    monkeypatch.setattr(_ldap_secure, "secure_ldap_connection", connect)
    context = _ctx()
    assert await LdapUserEnumPlugin().check(context, _dc(389, 636)) == []
    assert attempts == [636, 389]
    assert context.log.warnings == []


@pytest.mark.asyncio
async def test_trust_enum_warns_once_only_when_every_port_fails_tls(monkeypatch):
    from scanr.plugins.services.trust_enum import TrustEnumPlugin

    tls_ok_ports: set[int] = set()

    def connect(ldap3, ip, port, *args, **kwargs):
        if port in tls_ok_ports:
            raise RuntimeError("LDAP bind failed")
        raise LdapTlsError("LDAP StartTLS negotiation failed")

    monkeypatch.setattr(_ldap_secure, "secure_ldap_connection", connect)

    context = _ctx()
    assert await TrustEnumPlugin().check(context, _dc(389, 636, 3268)) == []
    assert len(context.log.warnings) == 1

    tls_ok_ports.add(3268)
    context = _ctx()
    assert await TrustEnumPlugin().check(context, _dc(389, 636, 3268)) == []
    assert context.log.warnings == []
