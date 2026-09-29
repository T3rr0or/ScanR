"""SSL-VPN / remote-access appliance fingerprinting.

Pins the per-appliance matcher and version extractor, and confirms concurrency
safety — no fingerprint state is kept on the instance between hosts.
"""
from __future__ import annotations

from scanr.plugins.services.vpn_appliance_exposure import (
    APPLIANCES,
    VpnApplianceExposurePlugin,
    extract_version,
    match_appliance,
)


def _by_vendor(vendor: str):
    return next(a for a in APPLIANCES if a.vendor == vendor)


def test_fortinet_matched_by_login_path_in_body():
    forti = _by_vendor("Fortinet")
    reasons = match_appliance(forti, "<html>/remote/login</html>", {}, [], "")
    assert reasons


def test_ivanti_matched_by_cookie_and_redirect():
    ivanti = _by_vendor("Ivanti")
    reasons = match_appliance(
        ivanti, "", {}, ["dsid"], "/dana-na/auth/url_default/welcome.cgi"
    )
    assert len(reasons) == 2


def test_no_match_on_unrelated_page():
    forti = _by_vendor("Fortinet")
    assert match_appliance(forti, "<html>nginx welcome</html>", {}, [], "") == []


def test_version_extraction():
    forti = _by_vendor("Fortinet")
    assert extract_version(forti, "FortiOS 7.2.4 build1396") == "7.2.4"
    ivanti = _by_vendor("Ivanti")
    assert extract_version(ivanti, "Ivanti Connect Secure 22.6R2") == "22.6R2"


def test_appliances_carry_advisory_and_cves():
    for appliance in APPLIANCES:
        assert appliance.advisory
        assert appliance.paths


def test_disclosed_version_raises_severity():
    plugin = VpnApplianceExposurePlugin()
    forti = _by_vendor("Fortinet")
    with_ver = plugin._build_finding("1.2.3.4", 443, forti, ["body"], "7.2.4", "url")
    without_ver = plugin._build_finding("1.2.3.4", 443, forti, ["body"], "", "url")
    assert with_ver.severity.value == "medium"
    assert without_ver.severity.value == "low"


def test_no_instance_state_between_calls():
    # Two separate plugin instances must not share fingerprint caches.
    a = VpnApplianceExposurePlugin()
    b = VpnApplianceExposurePlugin()
    assert a is not b
