import pytest
from scanr.utils.cvss import calculate_cvss3, severity_from_score


def test_known_cvss_heartbleed():
    # CVE-2014-0160: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
    score = calculate_cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert score is not None
    assert 7.0 <= score <= 8.0


def test_cvss_critical():
    score = calculate_cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert score >= 9.0


def test_cvss_info():
    score = calculate_cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0


def test_cvss_invalid():
    assert calculate_cvss3("not-a-vector") is None


def test_severity_from_score():
    assert severity_from_score(9.5) == "critical"
    assert severity_from_score(7.5) == "high"
    assert severity_from_score(5.0) == "medium"
    assert severity_from_score(2.0) == "low"
    assert severity_from_score(0.0) == "info"
