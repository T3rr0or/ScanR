from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.query
import dns.resolver
import dns.zone
import pytest

import scanr.plugins.network.dns_zone_transfer as network_axfr
import scanr.plugins.services.dns_zone_transfer as service_axfr
from scanr.scanner.discovery.dns_resolver import attempt_zone_transfer


@pytest.mark.asyncio
async def test_zone_transfer_contacts_only_the_authorized_scanned_ip(monkeypatch):
    contacted: list[tuple[str, str, int]] = []

    def forbidden_resolve(*args, **kwargs):
        raise AssertionError("AXFR must not discover or contact authoritative NS hosts")

    def fake_xfr(server: str, domain: str, *, timeout: int):
        contacted.append((server, domain, timeout))
        return object()

    monkeypatch.setattr(dns.resolver, "resolve", forbidden_resolve)
    monkeypatch.setattr(dns.query, "xfr", fake_xfr)
    monkeypatch.setattr(
        dns.zone,
        "from_xfr",
        lambda _response: SimpleNamespace(nodes={"@": object(), "www": object()}),
    )

    records = await attempt_zone_transfer("example.com", "192.0.2.53")

    assert contacted == [("192.0.2.53", "example.com", 5)]
    assert records == ["@.example.com", "www.example.com"]


@pytest.mark.asyncio
async def test_zone_transfer_rejects_a_nameserver_hostname(monkeypatch):
    contacted = False

    def fake_xfr(*args, **kwargs):
        nonlocal contacted
        contacted = True
        return object()

    monkeypatch.setattr(dns.query, "xfr", fake_xfr)

    assert await attempt_zone_transfer("example.com", "ns1.third-party.example") == []
    assert contacted is False


@pytest.mark.asyncio
async def test_domain_plugin_passes_scanned_ip_and_reports_scoped_review_command(monkeypatch):
    transfer = AsyncMock(return_value=["www.example.com"])
    monkeypatch.setattr(network_axfr, "attempt_zone_transfer", transfer)
    host = SimpleNamespace(hostname="app.example.com", ip="192.0.2.53")

    findings = await network_axfr.DomainZoneTransferPlugin().check(None, host)

    transfer.assert_awaited_once_with("example.com", "192.0.2.53")
    assert findings[0].peer_review_command == "dig AXFR example.com @192.0.2.53"


@pytest.mark.asyncio
async def test_service_plugin_passes_scanned_dns_server_ip(monkeypatch):
    transfer = AsyncMock(return_value=[])
    monkeypatch.setattr(service_axfr, "attempt_zone_transfer", transfer)
    host = SimpleNamespace(
        hostname="ns1.example.com",
        ip="192.0.2.53",
        ports=[SimpleNamespace(number=53, state="open")],
    )

    await service_axfr.DnsZoneTransferPlugin().check(None, host)

    transfer.assert_awaited_once_with("example.com", "192.0.2.53")
