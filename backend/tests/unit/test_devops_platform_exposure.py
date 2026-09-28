"""DevOps platform exposure.

Pins the shared HTTP-platform fingerprinting: identification by marker, and the
strict anonymous-access confirmation that a 200 alone is not enough.
"""
from __future__ import annotations

from scanr.plugins.services._http_platform import (
    anon_access_confirmed,
    extract_version,
    identifies,
)
from scanr.plugins.services.devops_platform_exposure import PLATFORMS


def _by_name(fragment: str):
    return next(p for p in PLATFORMS if fragment.lower() in p.name.lower())


def test_nexus_identified_by_body_marker():
    nexus = _by_name("nexus")
    assert identifies(nexus, "<title>Nexus Repository Manager</title>", {})


def test_version_extracted_from_server_header_text():
    nexus = _by_name("nexus")
    assert extract_version(nexus, "Server: Nexus/3.61.0-02") == "3.61.0-02"


def test_anon_access_requires_all_markers():
    nexus = _by_name("nexus")
    probe = nexus.anon_probes[0]
    real = '[{"name":"maven","format":"maven2","type":"hosted"}]'
    assert anon_access_confirmed(probe, 200, real)


def test_login_page_returned_with_200_is_not_confirmed():
    nexus = _by_name("nexus")
    probe = nexus.anon_probes[0]
    assert not anon_access_confirmed(probe, 200, "<html>please log in</html>")


def test_401_is_never_confirmed():
    nexus = _by_name("nexus")
    probe = nexus.anon_probes[0]
    assert not anon_access_confirmed(probe, 401, '[{"format":"x","type":"y"}]')


def test_argocd_anon_is_critical():
    argo = _by_name("argo")
    assert argo.anon_probes[0].severity.value == "critical"


def test_every_platform_has_identify_markers_and_remediation():
    for platform in PLATFORMS:
        assert platform.identify_markers
        assert platform.remediation and platform.reference
