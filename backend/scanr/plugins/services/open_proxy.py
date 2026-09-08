"""Open forward proxy detection (TCP 3128, 8080, 8888, 1080).

An open forward proxy lets anyone on the internet source traffic from this
host's address. In practice that means the proxy is used to launder credential
stuffing, spam and scanning traffic onto the owner's IP reputation, and — far
worse for the owner — to reach whatever the proxy itself can reach: internal
web apps, admin panels bound to the RFC1918 side, and cloud instance metadata
endpoints. It turns a perimeter host into an SSRF gateway.

How we prove it without becoming an abuser
------------------------------------------
The obvious test — proxy a request for a real third-party site and see if the
body comes back — actually sends traffic through someone else's infrastructure
to an unrelated third party. We refuse to do that.

Instead we ask the proxy to fetch ``http://scanr-open-proxy-check.invalid/``.
``.invalid`` is reserved by RFC 2606 and can never resolve, so no packet leaves
the proxy for anyone else. The reply still separates the two cases cleanly,
because the *decision to try* happens before name resolution:

  * a proxy that accepted the relay must resolve the name first, fails, and
    answers with its own error page — 502/503/504, or a body saying "unable to
    resolve"/"unknown host"/"Bad Gateway". That is proof it attempted to relay
    for us, which is exactly the capability we are testing for;
  * a proxy that refuses unauthenticated or off-net clients answers before it
    ever looks at the URL — 403 Forbidden, 407 Proxy Authentication Required,
    or 400 Bad Request — and never reaches resolution;
  * a plain web server that is not a proxy at all treats the absolute-form URI
    as a path on itself and answers 200/404 for its own site. Not a proxy.

For port 1080 (and any of these ports that turns out to be SOCKS) we send only
the SOCKS5 greeting and read the method selection. ``0x05 0x00`` — "no
authentication required" — is itself the finding; we never send a CONNECT, so
not a single byte is relayed anywhere.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

PROXY_PORTS = [3128, 8080, 8888, 1080]

# RFC 2606 reserves .invalid — guaranteed never to resolve, so the proxy's
# attempt to relay costs the internet nothing.
_CANARY_HOST = "scanr-open-proxy-check.invalid"
_CANARY_URL = f"http://{_CANARY_HOST}/"

_HTTP_PROXY_REQUEST = (
    f"GET {_CANARY_URL} HTTP/1.1\r\n"
    f"Host: {_CANARY_HOST}\r\n"
    "User-Agent: ScanR/1.0 (open-proxy-check)\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n\r\n"
).encode()

# Version 5, one method offered, method 0x00 = no authentication.
_SOCKS5_GREETING = b"\x05\x01\x00"

# Statuses a proxy returns once it has taken the request and failed upstream.
_RELAY_ATTEMPTED_STATUS = {502, 503, 504}
# Statuses that mean the request was rejected before any relay was attempted.
_REFUSED_STATUS = {400, 401, 403, 405, 407}

_RESOLUTION_FAILURE_MARKERS = (
    "unable to resolve",
    "unable to determine ip address",
    "cannot resolve",
    "could not resolve",
    "unknown host",
    "name or service not known",
    "dns lookup",
    "dnserror",
    "host not found",
    "bad gateway",
    "gateway timeout",
    "err_name_not_resolved",
)

_STATUS_RE = re.compile(rb"^HTTP/1\.[01] (\d{3})")


def _parse_http_status(raw: bytes | None) -> int | None:
    """Extract the status code, or None when this is not an HTTP response."""
    if not raw:
        return None
    match = _STATUS_RE.match(raw)
    if not match:
        return None
    return int(match.group(1))


def _looks_like_relay_attempt(raw: bytes) -> bool:
    """True when the body reads like the proxy tried and failed to resolve."""
    text = raw.decode("utf-8", errors="replace").lower()
    return any(marker in text for marker in _RESOLUTION_FAILURE_MARKERS)


def _socks5_no_auth(raw: bytes | None) -> bool:
    """True when a SOCKS5 server selected method 0x00 (no authentication)."""
    if not raw or len(raw) < 2:
        return False
    # 0x05 0x00 = SOCKS5, no auth. 0x05 0xFF = no acceptable methods (good).
    return raw[0] == 0x05 and raw[1] == 0x00


class OpenProxyPlugin(PluginBase):
    id = "services.open_proxy"
    name = "Open Forward Proxy"
    description = "Detect HTTP and SOCKS proxies that relay for unauthenticated clients"
    category = PluginCategory.services
    severity = Severity.high
    ports = PROXY_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in PROXY_PORTS or port.state != "open":
                continue

            finding = None
            try:
                http_reply = await self._probe_http(host.ip, port.number)
                finding = self._analyze_http(host.ip, port.number, http_reply)
                if finding is None:
                    socks_reply = await self._probe_socks(host.ip, port.number)
                    finding = self._analyze_socks(host.ip, port.number, socks_reply)
            except Exception:
                logger.debug("open_proxy: probe failed for %s:%d", host.ip, port.number, exc_info=True)
                continue

            if finding:
                findings.append(finding)
        return findings

    async def _probe_http(self, ip: str, port: int) -> bytes | None:
        """Send an absolute-form GET for the non-resolving canary domain."""
        return await self._exchange(ip, port, _HTTP_PROXY_REQUEST, 8192)

    async def _probe_socks(self, ip: str, port: int) -> bytes | None:
        """Send only the SOCKS5 method-negotiation greeting."""
        return await self._exchange(ip, port, _SOCKS5_GREETING, 16)

    async def _exchange(self, ip: str, port: int, payload: bytes, read_bytes: int) -> bytes | None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=6.0
            )
            writer.write(payload)
            await writer.drain()
            return await asyncio.wait_for(reader.read(read_bytes), timeout=8.0)
        except Exception:
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _analyze_http(self, ip: str, port: int, raw: bytes | None) -> FindingData | None:
        status = _parse_http_status(raw)
        if status is None or raw is None:
            return None
        if status in _REFUSED_STATUS:
            # Rejected before resolution — the proxy is not open to us.
            return None
        relay_attempted = status in _RELAY_ATTEMPTED_STATUS or _looks_like_relay_attempt(raw)
        if not relay_attempted:
            # 200/301/404 here means a normal web server answered for itself.
            return None

        first_line = raw.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        return self._finding(
            ip,
            port,
            kind="HTTP",
            evidence=(
                f"GET {_CANARY_URL} (absolute-form) to {ip}:{port} -> {first_line}. "
                "The domain is RFC 2606 .invalid and cannot resolve, so an upstream "
                "resolution failure proves the proxy accepted the request and tried to "
                "relay it rather than refusing it (a refusal would be 403/407/400)."
            ),
            detail=(
                "The service accepted an absolute-form HTTP request for an external "
                "hostname from an unauthenticated client and attempted to fetch it."
            ),
        )

    def _analyze_socks(self, ip: str, port: int, raw: bytes | None) -> FindingData | None:
        if not _socks5_no_auth(raw):
            return None
        return self._finding(
            ip,
            port,
            kind="SOCKS5",
            evidence=(
                f"SOCKS5 greeting 05 01 00 to {ip}:{port} -> 05 00 "
                "(server selected 'no authentication required'). No CONNECT was sent, "
                "so nothing was relayed."
            ),
            detail=(
                "The SOCKS5 server offers the 'no authentication' method to arbitrary "
                "clients, so any host that can reach this port can open TCP connections "
                "through it."
            ),
        )

    def _finding(self, ip: str, port: int, *, kind: str, evidence: str, detail: str) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"Open {kind} Forward Proxy",
            description=(
                f"An open {kind} forward proxy is listening on port {port}. {detail} "
                "Anyone on the internet can therefore source traffic from this host's IP "
                "address, which gets the address used for credential stuffing, spam and "
                "scanning and onto blocklists. More seriously, the proxy relays to "
                "whatever it can reach, so an external attacker gains a request path into "
                "the internal network behind it — intranet applications, management "
                "interfaces bound to private addresses, and cloud instance metadata "
                "endpoints such as 169.254.169.254, which can hand over instance role "
                "credentials."
            ),
            evidence=evidence,
            remediation=(
                "Bind the proxy to an internal interface only and firewall the port so it "
                "is unreachable from untrusted networks. "
                "Restrict relaying to known client networks with an explicit ACL "
                "(Squid: 'acl localnet src ...' plus 'http_access deny all' as the final "
                "rule; the default 'http_access deny all' must stay last). "
                "Require authentication (proxy_auth) for any client that is not on a "
                "trusted network. "
                "Deny outbound requests to link-local and RFC1918 destinations from the "
                "proxy so it cannot be used to reach metadata services or internal hosts."
            ),
            references=[
                "https://wiki.squid-cache.org/SquidFaq/SecurityPitfalls",
                "https://datatracker.ietf.org/doc/html/rfc1928",
                "https://cwe.mitre.org/data/definitions/441.html",
            ],
            port_number=port,
            protocol="tcp",
        )
