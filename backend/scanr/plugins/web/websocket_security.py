"""WebSocket handshake security: cross-origin acceptance and plaintext transport.

The same-origin policy does not apply to WebSockets. A page on any domain can
open a connection to ``wss://target/ws``, and the browser will attach the
target's cookies to the handshake exactly as it would for a normal request.
There is no CORS preflight and no opt-in: the only thing standing between an
attacker's page and an authenticated WebSocket session is the server checking the
``Origin`` header itself.

Servers routinely do not. The result is Cross-Site WebSocket Hijacking: a victim
visits an attacker's page, the page opens a socket to this application, and the
attacker reads and writes on the victim's authenticated channel for as long as
the victim stays on the page. Because the socket is bidirectional, that is not
limited to reading one response — it is a live session.

Two things are measured here:

* whether the handshake completes when the ``Origin`` header names a domain that
  has nothing to do with the target;
* whether the application points browsers at ``ws://`` from an ``https://`` page,
  which strips the transport protection the rest of the site has.

The check completes the HTTP upgrade handshake and closes the connection. No
WebSocket frame is ever sent, so no application message is delivered.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000]

# RFC 6455 §1.3 — the constant the server must combine with our key.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# A domain that cannot belong to the target. .invalid is reserved by RFC 2606,
# so it can never be registered and the header cannot accidentally be legitimate.
FOREIGN_ORIGIN = "https://cross-origin-check.invalid"

_WS_URL_RE = re.compile(r"""["'`](wss?://[^"'`\s]+)["'`]""", re.I)
_WS_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-/.]{0,60}(?:ws|websocket|socket|cable|hub)[A-Za-z0-9_\-/.]{0,20})["'`]""", re.I)

# Endpoints worth trying when the page does not name one.
_CANDIDATE_PATHS = (
    "/ws",
    "/websocket",
    "/socket",
    "/cable",
    "/socket.io/?EIO=4&transport=websocket",
    "/graphql",
    "/hub",
    "/api/ws",
)

_MAX_CANDIDATES = 10
_MAX_SCRIPTS = 6
_TIMEOUT = 6.0

# Cookie names that indicate the application authenticates with a cookie, which
# is what makes a cross-origin handshake exploitable rather than merely untidy.
_SESSION_COOKIE_HINTS = (
    "session", "sessid", "sid", "auth", "token", "jwt", "asp.net_sessionid",
    "jsessionid", "phpsessid", "connect.sid", "_csrf", "remember",
)


@dataclass
class HandshakeResult:
    path: str
    accepted: bool
    status_line: str
    accept_header_valid: bool


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def expected_accept(key: str) -> str:
    """The Sec-WebSocket-Accept value a compliant server must return."""
    digest = hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()  # noqa: S324 - protocol-mandated
    return base64.b64encode(digest).decode("ascii")


def build_handshake(path: str, authority: str, origin: str, key: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        "\r\n"
    ).encode("latin-1")


def parse_handshake_response(raw: bytes, key: str) -> HandshakeResult | None:
    """Interpret a raw upgrade response. None when nothing HTTP came back.

    An upgrade is only credited when the server both answers 101 *and* returns
    the correct Sec-WebSocket-Accept digest. A 101 without the digest is not a
    WebSocket server agreeing to talk to us.
    """
    if not raw:
        return None
    try:
        text = raw.decode("latin-1")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    status_line = lines[0].strip()
    if not status_line.upper().startswith("HTTP/"):
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    is_101 = " 101" in status_line
    accept = headers.get("sec-websocket-accept", "")
    valid = accept == expected_accept(key)
    return HandshakeResult(
        path="",
        accepted=bool(is_101 and valid),
        status_line=status_line,
        accept_header_valid=valid,
    )


def looks_like_session_cookie(set_cookie_values: list[str]) -> list[str]:
    """Cookie names suggesting the application authenticates with a cookie."""
    names = []
    for value in set_cookie_values:
        name = value.split("=", 1)[0].strip()
        if name and any(hint in name.lower() for hint in _SESSION_COOKIE_HINTS):
            names.append(name)
    return names


def extract_ws_targets(body: str, base_url: str) -> tuple[list[str], list[str]]:
    """(paths to try, plaintext ws:// URLs found) from a page's markup and inline JS."""
    origin = urlparse(base_url)
    paths: list[str] = []
    plaintext: list[str] = []
    for url in _WS_URL_RE.findall(body):
        parsed = urlparse(url)
        if parsed.scheme.lower() == "ws":
            plaintext.append(url)
        if parsed.hostname and parsed.hostname != origin.hostname:
            continue  # someone else's socket endpoint
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if path not in paths:
            paths.append(path)
    for path in _WS_PATH_RE.findall(body):
        if path not in paths:
            paths.append(path)
    return paths, plaintext


class WebSocketSecurityPlugin(PluginBase):
    id = "web.websocket_security"
    name = "WebSocket Handshake Security"
    description = (
        "Detect WebSocket endpoints that complete a handshake from a foreign "
        "Origin (cross-site hijacking) or are addressed over plaintext ws://"
    )
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        authority = getattr(host, "hostname", None) or host.ip
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{authority}:{port.number}"
            try:
                findings.extend(
                    await self._check_port(
                        context, base_url, host.ip, port.number, authority, scheme == "https"
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("websocket_security: %s failed: %s", base_url, exc)
        return findings

    async def _check_port(
        self,
        context,
        base_url: str,
        ip: str,
        port: int,
        authority: str,
        tls: bool,
    ) -> list[FindingData]:
        discovered, plaintext, cookies = await self._discover(
            context, base_url, ip, port, authority
        )

        findings: list[FindingData] = []
        if plaintext and tls:
            findings.append(self._plaintext_finding(base_url, plaintext, port))

        host_header = f"{authority}:{port}"
        for path in discovered[:_MAX_CANDIDATES]:
            result = await self._handshake(ip, port, tls, path, host_header)
            if result is None or not result.accepted:
                continue
            findings.append(
                self._cross_origin_finding(base_url, path, result, cookies, port)
            )
            break  # one confirmed endpoint per port is the finding
        return findings

    async def _discover(
        self, context, base_url: str, ip: str, port: int, authority: str
    ) -> tuple[list[str], list[str], list[str]]:
        """Candidate paths, plaintext ws:// URLs, and session cookie names."""
        paths: list[str] = []
        plaintext: list[str] = []
        cookies: list[str] = []
        async with create_web_client(
            context, pin_ip=ip, pin_port=port, pin_hostname=authority
        ) as client:
            try:
                page = await client.get(f"{base_url}/", timeout=8.0)
            except Exception:
                return list(_CANDIDATE_PATHS), plaintext, cookies

            cookies = looks_like_session_cookie(
                page.headers.get_list("set-cookie") if hasattr(page.headers, "get_list") else []
            )
            if page.status_code == 200:
                found_paths, found_plaintext = extract_ws_targets(page.text, base_url)
                paths.extend(found_paths)
                plaintext.extend(found_plaintext)
                for script_url in self._inline_scripts(page.text, base_url)[:_MAX_SCRIPTS]:
                    try:
                        script = await client.get(script_url, timeout=8.0)
                    except Exception:
                        continue
                    if script.status_code != 200:
                        continue
                    script_paths, script_plaintext = extract_ws_targets(script.text, base_url)
                    paths.extend(p for p in script_paths if p not in paths)
                    plaintext.extend(script_plaintext)

        for path in _CANDIDATE_PATHS:
            if path not in paths:
                paths.append(path)
        return paths, sorted(set(plaintext)), cookies

    @staticmethod
    def _inline_scripts(html: str, base_url: str) -> list[str]:
        from urllib.parse import urljoin

        origin = urlparse(base_url)
        urls = []
        for raw in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I):
            absolute = urljoin(f"{base_url}/", raw.strip())
            parsed = urlparse(absolute)
            if parsed.hostname != origin.hostname or parsed.port != origin.port:
                continue
            if absolute not in urls:
                urls.append(absolute)
        return urls

    async def _handshake(
        self, ip: str, port: int, tls: bool, path: str, host_header: str
    ) -> HandshakeResult | None:
        key = _ws_key()
        request = build_handshake(path, host_header, FOREIGN_ORIGIN, key)
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                self._open_connection(ip, port, tls), timeout=_TIMEOUT
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)
            raw = await asyncio.wait_for(reader.read(8192), timeout=_TIMEOUT)
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
            logger.debug("websocket handshake failed %s:%d%s: %s", ip, port, path, exc)
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError, ssl.SSLError):
                    pass

        result = parse_handshake_response(raw, key)
        if result is not None:
            result.path = path
        return result

    @staticmethod
    async def _open_connection(ip: str, port: int, tls: bool):
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return await asyncio.open_connection(ip, port, ssl=context)
        return await asyncio.open_connection(ip, port)

    def _cross_origin_finding(
        self,
        base_url: str,
        path: str,
        result: HandshakeResult,
        cookies: list[str],
        port: int,
    ) -> FindingData:
        # Cookie-based auth is what turns this from untidy into exploitable: the
        # browser attaches the cookie to the attacker's handshake automatically.
        severity = Severity.high if cookies else Severity.medium

        cookie_note = ""
        if cookies:
            cookie_note = (
                "\n\nThis application sets cookies that look like session "
                f"credentials ({', '.join(cookies)}). A browser attaches those cookies "
                "to a WebSocket handshake regardless of which site initiated it, so an "
                "attacker's page gets an authenticated socket without ever seeing the "
                "cookie value. That is why this is rated high rather than as a "
                "configuration observation."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="WebSocket Endpoint Accepts Cross-Origin Handshake",
            description=(
                f"The WebSocket endpoint at {base_url}{path} completed an upgrade "
                f"handshake for a request whose Origin was {FOREIGN_ORIGIN} — a domain "
                "with no relationship to this application. The server is not validating "
                "the Origin header.\n\n"
                "WebSockets are exempt from the same-origin policy and have no CORS "
                "preflight, so origin checking is entirely the server's responsibility. "
                "Without it, any page a victim visits can open a socket to this "
                "application in the victim's browser and then read and write on that "
                "connection for as long as the page stays open. Unlike a CSRF request, "
                "the channel is bidirectional: the attacker sees the responses."
                + cookie_note
            ),
            evidence=(
                f"GET {path} HTTP/1.1 with:\n"
                f"  Host: {urlparse(base_url).netloc}\n"
                "  Upgrade: websocket\n"
                "  Sec-WebSocket-Version: 13\n"
                f"  Origin: {FOREIGN_ORIGIN}\n\n"
                f"Response: {result.status_line}\n"
                "Sec-WebSocket-Accept matched the SHA-1 digest of our key — the server "
                "genuinely agreed to open a WebSocket, it did not merely return a 101.\n"
                + (f"Session-like cookies observed: {', '.join(cookies)}\n" if cookies else "")
                + "\nNo WebSocket frame was sent; the connection was closed after the "
                "handshake."
            ),
            remediation=(
                "Validate the Origin header on every WebSocket handshake against an "
                "allowlist of the application's own origins, and reject the connection "
                "with 403 when it does not match. Do not accept a missing Origin from a "
                "browser context.\n\n"
                "Origin checking alone is a defence against browsers, not against "
                "non-browser clients, which can set any Origin they like. So also "
                "authenticate the socket itself: require a token supplied in the first "
                "message or in the subprotocol and validate it server-side, rather than "
                "relying on the cookie the browser attached. A token the attacker's page "
                "cannot read is a token it cannot replay.\n\n"
                "Framework specifics: ws/Node — check 'info.origin' in "
                "'verifyClient'. Socket.IO — set the 'cors.origin' option (its default "
                "is permissive). Django Channels — configure "
                "'AllowedHostsOriginValidator'. Spring — 'setAllowedOrigins' with "
                "explicit values, never '*'. ASP.NET SignalR — configure CORS explicitly "
                "rather than 'AllowAnyOrigin'."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
                "https://christian-schneider.net/CrossSiteWebSocketHijacking.html",
                "https://datatracker.ietf.org/doc/html/rfc6455#section-10.2",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' "
                f"-H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: {_ws_key()}' "
                f"-H 'Origin: {FOREIGN_ORIGIN}' {base_url}{path}"
            ),
        )

    def _plaintext_finding(
        self, base_url: str, plaintext: list[str], port: int
    ) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="WebSocket Addressed Over Plaintext ws:// From an HTTPS Page",
            description=(
                f"Pages served over HTTPS from {base_url} point browsers at plaintext "
                "ws:// WebSocket URLs. The socket therefore carries its data — including "
                "any session token in the handshake — unencrypted, on a site that is "
                "otherwise protected in transit.\n\n"
                "Anyone on the network path reads and modifies the channel. Because a "
                "WebSocket is long-lived, this is not a single exposed request but a "
                "continuous stream. Modern browsers block mixed-content WebSocket "
                "connections from a secure page outright, so this is usually also a "
                "functional defect: the feature is failing for users while appearing to "
                "work in development over HTTP."
            ),
            evidence=(
                f"Page {base_url}/ is served over HTTPS and references plaintext "
                "WebSocket URL(s):\n"
                + "\n".join(f"  {url}" for url in plaintext[:10])
            ),
            remediation=(
                "Use wss:// everywhere the page is served over HTTPS. Derive the scheme "
                "from the page rather than hardcoding it — "
                "\"(location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host\" "
                "— so it cannot drift. Add 'upgrade-insecure-requests' to the "
                "Content-Security-Policy, and terminate TLS for the WebSocket at the same "
                "proxy that terminates it for the site so no plaintext hop remains behind "
                "the load balancer."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc6455#section-10.6",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            ],
            port_number=port,
            protocol="tcp",
        )
