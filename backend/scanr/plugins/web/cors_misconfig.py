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
                    severity=Severity.high,
                    title="CORS Misconfiguration Detected",
                    description=result["description"],
                    evidence=result["evidence"],
                    remediation="Configure CORS to only allow specific trusted origins. Never use '*' with credentials.",
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

                if acao == "*":
                    return {
                        "description": "Server uses wildcard CORS (Access-Control-Allow-Origin: *), allowing any origin to make cross-origin requests.",
                        "evidence": f"ACAO: {acao}",
                    }
                if acao == "https://evil.example.com":
                    msg = "Server reflects arbitrary Origin header"
                    if acac == "true":
                        msg += " WITH credentials allowed — high-severity attack vector"
                    return {
                        "description": msg,
                        "evidence": f"Origin: evil.example.com → ACAO: {acao}, ACAC: {acac}",
                    }
        except Exception:
            pass
        return None
