from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

JUPYTER_PORTS = [8888, 8889, 8890, 9999, 8080, 8000]


class JupyterUnauthPlugin(PluginBase):
    id = "services.jupyter_unauth"
    name = "Jupyter Notebook Unauthenticated Access"
    description = "Detect Jupyter Notebook/Lab instances accessible without a token or password"
    category = PluginCategory.services
    severity = Severity.critical
    ports = JUPYTER_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in JUPYTER_PORTS or port.state != "open":
                continue
            result = await self._probe(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True,
                **context.proxy_config()
            ) as client:
                # Check /api endpoint (Jupyter REST API)
                api_resp = await client.get(f"http://{ip}:{port}/api")
                if api_resp.status_code == 200:
                    try:
                        data = api_resp.json()
                        version = data.get("version", "unknown")
                        if "version" in data:
                            # Confirm no token needed by checking /api/kernels
                            kernels_resp = await client.get(f"http://{ip}:{port}/api/kernels")
                            if kernels_resp.status_code == 200:
                                kernel_count = len(kernels_resp.json())
                                return FindingData(
                                    plugin_id=self.id,
                                    severity=Severity.critical,
                                    title="Jupyter Notebook — Unauthenticated Access",
                                    description=(
                                        f"A Jupyter Notebook server (v{version}) on port {port} is accessible "
                                        f"without a token or password. {kernel_count} kernel(s) running. "
                                        "An attacker can execute arbitrary Python code on the server."
                                    ),
                                    evidence=(
                                        f"GET http://{ip}:{port}/api → Jupyter {version}; "
                                        f"/api/kernels → {kernel_count} kernel(s) accessible"
                                    ),
                                    remediation=(
                                        "Configure Jupyter with a strong token or password "
                                        "(c.NotebookApp.token or c.NotebookApp.password). "
                                        "Bind Jupyter to localhost only and use SSH tunneling for remote access."
                                    ),
                                    references=[
                                        "https://jupyter-notebook.readthedocs.io/en/stable/security.html",
                                    ],
                                    port_number=port,
                                    protocol="tcp",
                                )
                    except Exception:
                        pass

                # Fallback: check if /tree redirects to login or is accessible
                tree_resp = await client.get(f"http://{ip}:{port}/tree")
                if tree_resp.status_code == 200 and "jupyter" in tree_resp.text.lower():
                    return FindingData(
                        plugin_id=self.id,
                        severity=Severity.critical,
                        title="Jupyter Notebook — Unauthenticated Web Interface",
                        description=(
                            f"A Jupyter Notebook web interface on port {port} is accessible without authentication. "
                            "An attacker can execute arbitrary code on the server."
                        ),
                        evidence=f"GET http://{ip}:{port}/tree → HTTP 200 with Jupyter UI",
                        remediation=(
                            "Configure Jupyter with a token or password and bind to localhost only."
                        ),
                        port_number=port,
                        protocol="tcp",
                    )
        except Exception:
            pass
        return None
