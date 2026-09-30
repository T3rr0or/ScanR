from types import SimpleNamespace

import pytest
import ssl
import shlex

from scanr.plugins.authenticated.ssh_audit import SshAuditPlugin
from scanr.plugins.services._ldap_secure import secure_ldap_connection
from scanr.plugins.services.ldap_signing import LdapSigningPlugin
from scanr.plugins.services.trust_enum import parse_trust_entries


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
            self.kwargs = kwargs
            self.calls = []

        def open(self):
            self.calls.append("open")
            return True

        def start_tls(self):
            self.calls.append("start_tls")
            return True

        def bind(self):
            self.calls.append("bind")
            return True

        def unbind(self):
            self.calls.append("unbind")
            return True


def test_ldap_389_negotiates_tls_before_sending_credentials():
    conn = secure_ldap_connection(_FakeLdap3, "192.0.2.1", 389, "u", "p")
    assert conn.calls == ["open", "start_tls", "bind"]
    assert conn.kwargs["auto_bind"] is False
    assert conn.server.kwargs["tls"].kwargs == {
        "validate": ssl.CERT_REQUIRED, "valid_names": ["192.0.2.1"]
    }


def test_ldap_636_uses_tls_transport():
    conn = secure_ldap_connection(_FakeLdap3, "192.0.2.1", 636, "u", "p")
    assert conn.server.kwargs["use_ssl"] is True
    assert conn.calls == ["bind"]


def test_failed_starttls_never_attempts_bind():
    class FailedTLS(_FakeLdap3.Connection):
        def start_tls(self):
            self.calls.append("start_tls")
            return False

    class Fake(_FakeLdap3):
        Connection = FailedTLS

    with pytest.raises(RuntimeError, match="StartTLS"):
        secure_ldap_connection(Fake, "192.0.2.1", 389, "u", "p")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "expected"), [(8, True), (0, None), (49, None), (7, None), (50, None)]
)
async def test_ldap_signing_requires_known_result_code(monkeypatch, code, expected):
    class Reader:
        async def read(self, count):
            return bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0A, 0x01, code,
                          0x04, 0x00, 0x04, 0x00])

    class Writer:
        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def open_connection(ip, port):
        return Reader(), Writer()

    monkeypatch.setattr("scanr.plugins.services.ldap_signing.asyncio.open_connection", open_connection)
    assert await LdapSigningPlugin()._test_simple_bind("192.0.2.1", 389) is expected


def test_trust_entry_parser_maps_each_entry_without_cross_entry_bleed():
    def entry(name, direction, trust_type, attrs):
        return SimpleNamespace(
            trustPartner=name,
            trustDirection=direction,
            trustType=trust_type,
            trustAttributes=attrs,
            entry_dn=f"CN={name},CN=System,DC=example,DC=com",
        )

    result = parse_trust_entries([
        entry("child.example", 3, 2, 0),
        entry("forest.example", 1, 2, 0x8),
    ])
    assert result == [
        {"target": "child.example", "type": "up-level", "direction": "bidirectional", "transitive": True},
        {"target": "forest.example", "type": "forest", "direction": "inbound", "transitive": True},
    ]


def test_sshd_effective_config_parser_ignores_comments_and_unrelated_text():
    parsed = SshAuditPlugin._parse_sshd_t(
        "# permitrootlogin yes\npermitrootlogin prohibit-password\npasswordauthentication no\n"
    )
    assert parsed["permitrootlogin"] == "prohibit-password"
    assert parsed["passwordauthentication"] == "no"


def test_sshd_command_quotes_user_and_requests_effective_match_config():
    command = SshAuditPlugin._effective_config_command(
        "192.0.2.5", 22, {"username": "example\\operator"}
    )
    assert command.startswith("sshd -T -C ")
    assert "laddr=192.0.2.5" in command
    assert "lport=22" in command
    parts = shlex.split(command)
    assert len(parts) == 5
    assert parts[3].startswith("user=example\\operator,")


def test_sshd_criteria_username_cannot_inject_extra_match_fields():
    command = SshAuditPlugin._effective_config_command(
        "192.0.2.5", 22, {"username": "x,addr=attacker; id"}
    )
    assert command == "sshd -T 2>/dev/null"
    assert "attacker" not in command
