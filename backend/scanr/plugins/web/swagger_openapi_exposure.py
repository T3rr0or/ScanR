from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class SwaggerOpenApiExposurePlugin(PluginBase):
    id = "web.swagger_openapi_exposure"
    name = "Swagger / OpenAPI Exposure"
    description = "Detect exposed API documentation and OpenAPI schemas"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    PATHS = [
        "/swagger", "/swagger/", "/swagger-ui/", "/swagger-ui.html", "/api-docs",
        "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml", "/docs",
        "/redoc", "/api/swagger.json", "/swagger.json",
    ]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        async for port, url, resp in _web_responses(context, host, self.PATHS):
            text = resp.text[:5000].lower()
            ctype = resp.headers.get("content-type", "").lower()
            if resp.status_code < 400 and (
                "openapi" in text or "swagger" in text or "swagger-ui" in text or "application/json" in ctype and "paths" in text
            ):
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Exposed API Documentation",
                    description="Public Swagger/OpenAPI documentation can reveal hidden endpoints, schemas, auth flows, and internal object names.",
                    evidence=f"{url} returned HTTP {resp.status_code} with Swagger/OpenAPI indicators",
                    remediation="Restrict API documentation to authenticated users or trusted networks, or disable it in production.",
                    references=["https://owasp.org/API-Security/"],
                    port_number=port,
                    protocol="tcp",
                ))
                break
        return findings

