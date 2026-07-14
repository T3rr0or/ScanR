"""Unit tests for the vulnerable-JS-library plugin: detection, version ranges,
and finding construction (no network — pure logic)."""
from scanr.core.plugin_base import Severity
from scanr.plugins.web.js_libraries import (
    JsLibrariesPlugin,
    _detect,
    _in_range,
    _ver_key,
    _VULN_DB,
)


def test_detect_from_url():
    assert _detect("https://x/js/jquery-3.4.1.min.js", None) == ("jquery", "3.4.1")
    # jQuery UI must win over jQuery core (order matters)
    assert _detect("https://x/jquery-ui-1.12.1.min.js", None) == ("jquery-ui", "1.12.1")
    assert _detect("https://x/jquery.migrate-3.0.0.js", None) == ("jquery-migrate", "3.0.0")
    # CDN-style version-in-path
    assert _detect("https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js", None) == ("jquery", "1.12.4")
    # cache-busting query string
    assert _detect("https://x/jquery.min.js?ver=3.3.1", None) == ("jquery", "3.3.1")
    assert _detect("https://x/bootstrap-4.1.3.min.js", None) == ("bootstrap", "4.1.3")
    assert _detect("https://x/style.css", None) is None


def test_detect_from_content():
    assert _detect("", "/*! jQuery v3.4.1 | (c) JS Foundation */") == ("jquery", "3.4.1")
    assert _detect("", "/*! jQuery JavaScript Library v1.12.4 */") == ("jquery", "1.12.4")
    assert _detect("", "/*! Bootstrap v4.3.1 (https://getbootstrap.com/) */") == ("bootstrap", "4.3.1")
    assert _detect("", 'Handlebars.VERSION = "4.7.6";') == ("handlebars", "4.7.6")
    # minified libraries (no banner, version in a property) — e.g. bundled JSF
    assert _detect("", 'a.fn.jquery="1.12.4",') == ("jquery", "1.12.4")
    assert _detect("", 't.ui.version="1.12.1";') == ("jquery-ui", "1.12.1")


def test_version_ranges():
    assert _ver_key("3.4.1") < _ver_key("3.5.0")
    # jquery 3.4.1 is vulnerable to the <3.5.0 XSS, 3.5.1 is not
    v3411 = [v for v in _VULN_DB["jquery"] if _in_range("3.4.1", v)]
    assert any("CVE-2020-11022" in v.cves for v in v3411)
    assert not any(_in_range("3.5.1", v) for v in _VULN_DB["jquery"])
    # underscore range has a lower bound (at_or_above)
    assert any(_in_range("1.9.0", v) for v in _VULN_DB["underscore"])
    assert not any(_in_range("1.13.0", v) for v in _VULN_DB["underscore"])
    # bootstrap 4.x range doesn't fire on a 3.x fixed version
    assert not any(_in_range("3.4.0", v) and v.at_or_above == "4.0.0" for v in _VULN_DB["bootstrap"])


def test_build_finding_vulnerable():
    p = JsLibrariesPlugin()
    f = p._build_finding("jquery", "3.4.1", "https://x/jquery-3.4.1.min.js", 443)
    assert f is not None
    assert f.severity == Severity.medium
    assert "CVE-2020-11022" in f.cve_ids and "CVE-2020-11023" in f.cve_ids
    assert "3.5.0" in f.remediation  # fixed-in version
    assert f.cvss_score is not None
    assert f.peer_review_command and "curl" in f.peer_review_command


def test_build_finding_consolidates_and_takes_max_severity():
    p = JsLibrariesPlugin()
    # lodash 4.17.4 matches several ranges incl. high-severity ones
    f = p._build_finding("lodash", "4.17.4", "https://x/lodash.js", 443)
    assert f is not None
    assert f.severity == Severity.high
    assert "CVE-2021-23337" in f.cve_ids  # command injection, fixed in 4.17.21
    assert "4.17.21" in f.remediation


def test_build_finding_current_version_is_info():
    p = JsLibrariesPlugin()
    f = p._build_finding("jquery", "3.7.1", "https://x/jquery.js", 443)
    assert f is not None
    assert f.severity == Severity.info
    assert not f.cve_ids
