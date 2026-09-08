"""MongoDB-style NoSQL operator injection ($ne/$gt/$regex/$where).

The differential guards are the whole check: a target must show a real,
reproducible behaviour change caused specifically by an operator payload, not
merely respond differently from one request to the next. The false-positive
trap below (an endpoint with no stable baseline at all) is the case the guards
exist to rule out, and is the single most important test in this file -- a
scanner that flags every noisy backend is worse than a scanner that flags
nothing.
"""
from __future__ import annotations

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import nosql_injection as ns
from scanr.plugins.web._crawler import CrawlResult


class _Ctx:
    def proxy_config(self):
        return {}

    def web_auth_headers(self):
        return {}


@pytest.fixture(autouse=True)
def _no_crawl(monkeypatch):
    """Exercise the plugin's own candidate-parameter list, not a crawl result."""
    async def fake_crawl(base_url, client):
        return CrawlResult(paths=["/"], get_params=[])
    monkeypatch.setattr(ns, "crawl", fake_crawl)


def _install(monkeypatch, handler):
    def factory(*_a, **_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ns, "create_web_client", factory)


async def _run(base="http://192.0.2.10:80"):
    from scanr.plugins.web._budget import Budget
    return await ns.NoSqlInjectionPlugin()._test_host(_Ctx(), base, 80, Budget(300.0))


_LOGIN_FAILED = "<html>Login failed. Please try again.</html>"
_LOGIN_SUCCESS = "<html>Welcome back, admin! You are now logged in to the dashboard.</html>"


# ── true positive ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_ne_operator_auth_bypass_via_differential(monkeypatch):
    """An app that logs an attacker in for `username[$ne]=...` regardless of
    the value is the canonical NoSQL auth bypass."""
    def handler(request):
        for key in request.url.params.keys():
            if key == "username[$ne]":
                return httpx.Response(200, text=_LOGIN_SUCCESS)
        return httpx.Response(200, text=_LOGIN_FAILED)

    _install(monkeypatch, handler)
    finding = await _run()

    assert finding is not None
    assert finding.severity is Severity.critical
    assert finding.title == "NoSQL Injection"
    assert "$ne" in finding.evidence
    assert "username" in finding.evidence


# ── clean application ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_application_produces_nothing(monkeypatch):
    _install(monkeypatch, lambda r: httpx.Response(200, text=_LOGIN_FAILED))
    assert await _run() is None


# ── false-positive trap: no usable oracle ────────────────────────────────────

@pytest.mark.asyncio
async def test_response_that_differs_on_every_request_is_not_reported(monkeypatch):
    """A backend whose body changes run-to-run (a rotating nonce, a timestamp,
    a load-balanced replica) has no stable baseline to diff against. That is
    noise, not an injection signal -- reporting it would be a false positive
    on a huge share of real applications."""
    counter = {"n": 0}

    def handler(request):
        counter["n"] += 1
        # Alternate between two very different, fixed body lengths. Every
        # consecutive pair of requests then differs by far more than the 30%
        # equivalence tolerance, for as many requests as the plugin makes --
        # a growing (e.g. exponential) padding scheme would eventually run
        # away in both time and memory instead.
        padding = "x" * (200 if counter["n"] % 2 else 4000)
        return httpx.Response(200, text=f"<html>{padding}</html>")

    _install(monkeypatch, handler)
    assert await _run() is None


# ── transport errors ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connection_errors_do_not_propagate(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")

    _install(monkeypatch, handler)
    assert await _run() is None
