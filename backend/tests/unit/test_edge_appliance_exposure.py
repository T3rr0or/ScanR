"""Edge appliance fingerprinting for known-exploited CVEs."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import edge_appliance_exposure as ea


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, routes, default=(404, "not found", None)):
    def handler(request):
        entry = routes.get(request.url.path, default)
        status, text, hdrs = (list(entry) + [None, None])[:3]
        return httpx.Response(status, text=text or "", headers=hdrs or {})

    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(ea, "_client", factory)


def _host(port=443):
    return SimpleNamespace(ip="192.0.2.60", hostname=None,
                           ports=[SimpleNamespace(number=port, state="open", banner=None, service=None)])


async def _run(host):
    return await ea.EdgeApplianceExposurePlugin().check(_Ctx(), host)


@pytest.mark.asyncio
async def test_sonicwall_sma_detected_high(monkeypatch):
    _install(monkeypatch, {
        "/cgi-bin/welcome": (200, "<html>SonicWall Virtual Office</html>", None),
    })
    findings = await _run(_host())
    sw = [f for f in findings if "SonicWall" in f.title]
    assert len(sw) == 1
    assert sw[0].severity is Severity.high
    assert sw[0].cve_ids == []
    assert "CVE-" not in sw[0].description
    assert "sonicwall.com" in " ".join(sw[0].references)


@pytest.mark.asyncio
async def test_vcenter_version_extracted(monkeypatch):
    _install(monkeypatch, {
        "/": (200, "<title>vSphere Client</title> VMware vCenter 8.0.2 build", None),
    })
    findings = await _run(_host())
    vc = [f for f in findings if "vCenter" in f.title]
    assert len(vc) == 1
    assert "8.0.2" in vc[0].title
    assert vc[0].cve_ids == []
    assert "broadcom.com/support/vmware-security-advisories" in vc[0].references[0]


@pytest.mark.asyncio
async def test_current_or_unknown_build_is_not_attributed_to_known_cves(monkeypatch):
    # A product marker is not evidence that its firmware falls in any CVE's
    # affected range, even when the server exposes a version string.
    _install(monkeypatch, {
        "/": (200, "SonicWall SMA 100 Series current firmware", None),
    })
    findings = await _run(_host())
    assert len(findings) == 1
    assert findings[0].cve_ids == []
    assert "exact model or firmware build" in findings[0].description


@pytest.mark.asyncio
async def test_server_header_marker_matches(monkeypatch):
    _install(monkeypatch, {
        "/": (200, "generic login", {"server": "Zyxel"}),
    })
    findings = await _run(_host())
    assert any("Zyxel" in f.title for f in findings)


@pytest.mark.asyncio
async def test_generic_page_no_false_positive(monkeypatch):
    _install(monkeypatch, {
        "/": (200, "<html><title>Welcome to nginx</title></html>", {"server": "nginx"}),
    })
    assert await _run(_host()) == []


@pytest.mark.asyncio
async def test_one_finding_per_appliance_not_per_path(monkeypatch):
    # Marker present on the first path AND a later path — must dedupe.
    _install(monkeypatch, {
        "/client/index.php": (200, "Ivanti Cloud Services Appliance", None),
        "/gsb/": (200, "Ivanti Cloud Services Appliance", None),
    })
    findings = await _run(_host())
    ivanti = [f for f in findings if "Ivanti" in f.title]
    assert len(ivanti) == 1


def test_match_signature_is_case_insensitive():
    sig = ea.SIGNATURES[0]
    assert ea.match_signature(sig, "SONICWALL virtual office", "") is not None
    assert ea.match_signature(sig, "nothing here", "") is None
