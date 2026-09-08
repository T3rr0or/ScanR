from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
HTTP_PORTS = [80, 443, 8080, 8443, 8000]


class CorsMisconfigPlugin(PluginBase):
    id = "web.cors_misconfig"
    name = "CORS Misconfiguration"
    description = "Detect wildcard CORS or credential-allowing wildcard origin"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            url = f"{scheme}://{host.ip}:{port.number}/"
            result = await self._check_cors(context, url)
            if result:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=result["severity"],
                    title=result["title"],
                    description=result["description"],
                    evidence=result["evidence"],
                    remediation=result["remediation"],
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _check_cors(self, context, url: str) -> dict | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, **context.proxy_config()) as client:
                resp = await client.get(url, headers={"Origin": "https://evil.example.com"})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                # Severity turns on one question: can another origin read a
                # response that carries this user's session?
                #
                # A wildcard alone cannot. Browsers refuse to send credentials to
                # `ACAO: *`, so it is how every CDN and public API serves assets
                # and is not a finding in its own right. Reflecting the caller's
                # origin *with* credentials is the dangerous shape: any site the
                # victim visits can read their authenticated responses.
                if acao == "*":
                    if acac == "true":
                        # Browsers reject this pair, so it is not exploitable —
                        # but it means the policy was not thought through.
                        return {
                            "severity": Severity.low,
                            "title": "CORS Wildcard Combined With Credentials",
                            "description": (
                                "The server sends Access-Control-Allow-Origin: * together with "
                                "Access-Control-Allow-Credentials: true. Browsers reject this "
                                "combination, so it is not directly exploitable, but it indicates "
                                "the CORS policy is not doing what its author intended."
                            ),
                            "evidence": f"ACAO: {acao}, ACAC: {acac}",
                            "remediation": (
                                "Decide which the endpoint needs. For public data drop the "
                                "credentials header; for authenticated data replace the wildcard "
                                "with an explicit allowlist of trusted origins."
                            ),
                        }
                    return {
                        "severity": Severity.info,
                        "title": "CORS Wildcard Policy (Public Endpoint)",
                        "description": (
                            "The server sends Access-Control-Allow-Origin: *, allowing any origin "
                            "to read responses. Credentials are not permitted, so no session data "
                            "is exposed — this is the normal configuration for public assets and "
                            "APIs. Recorded so the exposure is deliberate rather than accidental."
                        ),
                        "evidence": f"ACAO: {acao}",
                        "remediation": (
                            "No action needed if this endpoint is intended to be public. If it "
                            "serves anything non-public, replace the wildcard with an allowlist."
                        ),
                    }
                if acao == "https://evil.example.com":
                    if acac == "true":
                        return {
                            "severity": Severity.high,
                            "title": "CORS Reflects Any Origin With Credentials",
                            "description": (
                                "The server echoes back whatever Origin it is given and sets "
                                "Access-Control-Allow-Credentials: true. Any site a logged-in user "
                                "visits can therefore make authenticated requests to this host and "
                                "read the responses — session data, account details, and anything "
                                "else the user's cookies grant access to."
                            ),
                            "evidence": f"Origin: evil.example.com → ACAO: {acao}, ACAC: {acac}",
                            "remediation": (
                                "Never reflect the Origin header. Validate it against an explicit "
                                "allowlist of trusted origins and send that exact value, or omit "
                                "the CORS headers entirely."
                            ),
                        }
                    return {
                        "severity": Severity.medium,
                        "title": "CORS Reflects Any Origin",
                        "description": (
                            "The server echoes back whatever Origin it is given. Credentials are "
                            "not allowed, so authenticated responses stay protected, but any origin "
                            "can read unauthenticated responses — including any data reachable "
                            "from the network position of a victim's browser."
                        ),
                        "evidence": f"Origin: evil.example.com → ACAO: {acao}, ACAC: {acac}",
                        "remediation": (
                            "Validate Origin against an allowlist rather than reflecting it, so "
                            "adding credentials later cannot silently turn this into a session leak."
                        ),
                    }
        except Exception:
            pass
        return None
