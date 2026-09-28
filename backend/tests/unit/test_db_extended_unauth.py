"""Analytics / distributed database unauthenticated access.

Pins the shared confirmation logic for these platforms and their severities.
"""
from __future__ import annotations

from scanr.plugins.services._http_platform import anon_access_confirmed, identifies
from scanr.plugins.services.db_extended_unauth import PLATFORMS


def _by_name(fragment: str):
    return next(p for p in PLATFORMS if fragment.lower() in p.name.lower())


def test_trino_identified_and_query_api_is_critical():
    trino = _by_name("trino")
    assert identifies(trino, '{"coordinator":true,"environment":"prod"}', {})
    query_probe = next(p for p in trino.anon_probes if p.path == "/v1/query")
    assert query_probe.severity.value == "critical"


def test_druid_datasource_confirmation():
    druid = _by_name("druid")
    probe = next(p for p in druid.anon_probes if "datasources" in p.path)
    assert anon_access_confirmed(probe, 200, '["wikipedia","clickstream"]')
    assert not anon_access_confirmed(probe, 200, "<html>login</html>")


def test_arango_database_list_is_critical():
    arango = _by_name("arango")
    assert arango.anon_probes[0].severity.value == "critical"


def test_all_platforms_have_impact_and_remediation():
    for platform in PLATFORMS:
        assert platform.impact and platform.remediation
        assert platform.anon_probes    # each defines a confirming probe
