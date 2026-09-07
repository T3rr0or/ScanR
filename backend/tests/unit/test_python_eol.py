"""End-of-life Python runtime detection.

The support table is keyed by date rather than a hand-maintained flag, so these
tests pin the *rule* (past EOL -> reported, escalating with age) against fixed
dates instead of whatever today happens to be.
"""
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.python_eol import (
    PYTHON_EOL,
    PythonEolPlugin,
    assess,
    parse_python_version,
)


# ── version parsing ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("banner,expected", [
    ("SimpleHTTP/0.6 Python/3.6.9", (3, 6, "3.6.9")),
    ("Werkzeug/2.0.1 Python/3.7.9", (3, 7, "3.7.9")),
    ("Python/3.9", (3, 9, "3.9")),
    ("python 2.7.18", (2, 7, "2.7.18")),
    ("PYTHON/3.11.2", (3, 11, "3.11.2")),
])
def test_parses_version_from_banner(banner, expected):
    assert parse_python_version(banner) == expected


@pytest.mark.parametrize("banner", [
    None,
    "",
    "nginx/1.24.0",
    "gunicorn/20.1.0",          # Python stack, but announces no interpreter
    "Jython/2.7 something",     # not CPython's advertised form
    "Monty Python/Flying 3.6",  # 'Python/' preceded by another word
])
def test_ignores_banners_without_a_python_version(banner):
    assert parse_python_version(banner) is None


def test_does_not_match_a_bare_version_number():
    assert parse_python_version("3.6.9") is None


# ── support-window classification ────────────────────────────────────────────

def test_long_dead_series_is_high():
    sev, days = assess(2, 7, date(2026, 9, 8))
    assert sev is Severity.high and days > 730


def test_recently_expired_series_is_medium():
    """Past EOL but under the two-year mark."""
    eol = PYTHON_EOL[(3, 9)]
    sev, days = assess(3, 9, date(eol.year, eol.month, eol.day))
    assert sev is Severity.medium and days == 0


def test_approaching_eol_is_low():
    eol = PYTHON_EOL[(3, 12)]
    sev, days = assess(3, 12, eol - timedelta(days=30))
    assert sev is Severity.low and days < 0


def test_comfortably_supported_series_is_not_reported():
    assert assess(3, 14, date(2026, 9, 8)) is None


def test_unknown_future_series_is_not_reported():
    """A release newer than the table must not be guessed at."""
    assert assess(3, 99, date(2026, 9, 8)) is None
    assert assess(4, 0, date(2026, 9, 8)) is None


def test_every_table_entry_is_a_real_date():
    assert PYTHON_EOL, "support table must not be empty"
    for (major, minor), eol in PYTHON_EOL.items():
        assert isinstance(eol, date)
        assert major in (2, 3)
        assert 0 <= minor < 100


# ── plugin behaviour ─────────────────────────────────────────────────────────

def _port(number, banner=None, state="open", service=None):
    return SimpleNamespace(number=number, state=state, banner=banner, service=service)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


@pytest.mark.asyncio
async def test_reports_an_eol_runtime_from_a_banner():
    host = _host([_port(8000, "SimpleHTTP/0.6 Python/3.6.9")])
    findings = await PythonEolPlugin().check(None, host)

    assert len(findings) == 1
    assert findings[0].severity is Severity.high
    assert "3.6" in findings[0].title
    assert "3.6.9" in findings[0].description
    assert findings[0].port_number == 8000


@pytest.mark.asyncio
async def test_reads_the_service_record_when_the_banner_is_empty():
    service = SimpleNamespace(
        product="Werkzeug httpd", version="2.0.1", extra_info="Python/3.7.9"
    )
    host = _host([_port(5000, banner=None, service=service)])
    findings = await PythonEolPlugin().check(None, host)

    assert len(findings) == 1
    assert "3.7" in findings[0].title


@pytest.mark.asyncio
async def test_one_finding_per_series_even_across_many_ports():
    """The same interpreter usually backs several ports."""
    banner = "SimpleHTTP/0.6 Python/3.6.9"
    host = _host([_port(8000, banner), _port(8001, banner), _port(8002, banner)])
    findings = await PythonEolPlugin().check(None, host)

    assert len(findings) == 1


@pytest.mark.asyncio
async def test_distinct_series_are_reported_separately():
    host = _host([
        _port(8000, "SimpleHTTP/0.6 Python/3.6.9"),
        _port(9000, "Werkzeug/2.0.1 Python/3.8.1"),
    ])
    findings = await PythonEolPlugin().check(None, host)

    assert {f.port_number for f in findings} == {8000, 9000}


@pytest.mark.asyncio
async def test_closed_ports_are_ignored():
    host = _host([_port(8000, "Python/3.6.9", state="closed")])
    assert await PythonEolPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_supported_runtime_produces_no_finding():
    host = _host([_port(8000, "Werkzeug/3.0.1 Python/3.14.0")])
    assert await PythonEolPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_host_with_no_python_anywhere_produces_nothing():
    host = _host([_port(80, "nginx/1.24.0"), _port(22, "OpenSSH_9.6p1")])
    assert await PythonEolPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_evidence_is_bounded():
    host = _host([_port(8000, "Python/3.6.9 " + "x" * 5000)])
    findings = await PythonEolPlugin().check(None, host)
    assert len(findings[0].evidence) < 400
