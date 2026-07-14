"""TLS-on-any-port: is_tls_port promotes nmap-confirmed TLS services, and the
engine dispatches ssl_tls plugins to those ports (definitive signal, no guesses)."""
from types import SimpleNamespace

from scanr.core.engine import _plugin_applies_to_host_data
from scanr.core.plugin_base import PluginCategory
from scanr.plugins.ssl_tls._ports import is_tls_port, is_tls_port_data


def _port(number, state="open", name=None, tunnel=None):
    svc = SimpleNamespace(name=name, tunnel=tunnel) if (name or tunnel) else None
    return SimpleNamespace(number=number, state=state, service=svc)


def test_is_tls_port_signals():
    assert is_tls_port(_port(443))                                  # well-known
    assert is_tls_port(_port(10636, tunnel="ssl"))                  # nmap TLS tunnel
    assert is_tls_port(_port(7002, name="ssl/http"))               # ssl service name
    assert is_tls_port(_port(9999, name="https"))
    assert not is_tls_port(_port(8080, name="http"))               # plain HTTP → not TLS
    assert not is_tls_port(_port(80, name=None))                   # unknown, non-TLS port
    assert not is_tls_port(_port(443, state="closed"))             # closed


def test_is_tls_port_data_variant():
    assert is_tls_port_data({"number": 10443, "state": "open", "service": {"tunnel": "ssl"}})
    assert not is_tls_port_data({"number": 3306, "state": "open", "service": {"name": "mysql"}})


def test_engine_dispatches_ssl_plugin_to_nonstandard_tls_port():
    ssl_plugin = SimpleNamespace(category=PluginCategory.ssl_tls, ports=[443, 8443])
    # host exposes TLS only on a non-standard port that nmap flagged tunnel=ssl
    ports = [{"number": 10443, "state": "open", "service": {"tunnel": "ssl"}}]
    assert _plugin_applies_to_host_data(ssl_plugin, ports) is True

    # a non-TLS service on an odd port must NOT pull in the TLS plugin
    plain = [{"number": 9000, "state": "open", "service": {"name": "http"}}]
    assert _plugin_applies_to_host_data(ssl_plugin, plain) is False


def test_engine_service_plugin_not_promoted():
    # services category has no promotion — still strict port match
    ftp = SimpleNamespace(category=PluginCategory.services, ports=[21])
    ports = [{"number": 2121, "state": "open", "service": {"name": "ftp"}}]
    assert _plugin_applies_to_host_data(ftp, ports) is False
    assert _plugin_applies_to_host_data(ftp, [{"number": 21, "state": "open", "service": None}]) is True
