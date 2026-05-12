"""Insecure deserialization detection.

Sends safe, non-exploiting probes to detect deserialization endpoints:
- Java: serialization magic bytes (0xACED0005) in X-Java-Deserialization header
- PHP: object injection via __PHP_Incomplete_Class in POST body / cookie
- Python: safe pickle probe in POST data field

Detects via stack traces / error messages in responses.
Gate: intrusive:true (sends non-standard headers and POST bodies).
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme
from scanr.plugins.web._http_evidence import format_from_httpx

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 8080, 4848, 9200]

# Java serialization magic (safe prefix — no gadget chain, just the header bytes)
_JAVA_MAGIC = base64.b64encode(b"\xac\xed\x00\x05t\x00\x04test").decode()

# PHP object injection payload — safe __PHP_Incomplete_Class (no __wakeup gadgets)
_PHP_PAYLOAD = 'O:22:"__PHP_Incomplete_Class":1:{s:27:"__PHP_Incomplete_Class_Name";s:4:"Test";}'

# Python: safe pickle of integer 0 — no code execution
_PYTHON_PICKLE_SAFE = base64.b64encode(b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x00.").decode()

_JAVA_ERRORS = [re.compile(p, re.I) for p in [
    r"java\.io\.InvalidClassException",
    r"java\.lang\.ClassNotFoundException",
    r"ObjectInputStream",
    r"ClassCastException.*Deseri",
    r"javax\.management",
    r"sun\.reflect\.annotation",
    r"aced0005",
]]

_PHP_ERRORS = [re.compile(p, re.I) for p in [
    r"unserialize\(\)",
    r"__wakeup",
    r"__destruct",
    r"PHP Fatal error.*unserialize",
    r"Notice:.*unserialize",
    r"Invalid serialization format",
]]

_PYTHON_ERRORS = [re.compile(p, re.I) for p in [
    r"_pickle\.UnpicklingError",
    r"pickle\.loads",
    r"cPickle",
    r"module_from_name",
]]

_XML_ENDPOINTS = ["/", "/api", "/service", "/ws", "/rpc", "/endpoint", "/upload"]


class DeseriProbePlugin(PluginBase):
    id = "web.deserial_probe"
    name = "Insecure Deserialization Probe"
    description = "Detect deserialization endpoints via safe Java/PHP/Python probes (stack trace detection)"
    category = PluginCategory.web
    severity = Severity.critical
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        _pj: dict = {}
        if context.scan.profile_json:
            try:
                _pj = json.loads(context.scan.profile_json) if isinstance(context.scan.profile_json, str) else context.scan.profile_json
            except Exception:
                pass
        if not _pj.get("intrusive", False):
            return []

        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"

            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True,
                **context.proxy_config()
            ) as client:
                result = await asyncio.gather(
                    self._probe_java(client, base_url, port.number),
                    self._probe_php(client, base_url, port.number),
                    self._probe_python(client, base_url, port.number),
                    return_exceptions=True,
                )
                for r in result:
                    if isinstance(r, FindingData):
                        findings.append(r)
        return findings

    async def _probe_java(self, client, base_url: str, port: int) -> FindingData | None:
        for path in _XML_ENDPOINTS:
            try:
                resp = await client.post(
                    f"{base_url}{path}",
                    headers={
                        "Content-Type": "application/x-java-serialized-object",
                        "X-Java-Deserialization": _JAVA_MAGIC,
                    },
                    content=base64.b64decode(_JAVA_MAGIC),
                )
                for pattern in _JAVA_ERRORS:
                    if pattern.search(resp.text):
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="Insecure Java Deserialization Detected",
                            description=(
                                f"The endpoint {base_url}{path} appears to deserialize Java objects. "
                                "A Java deserialization error was triggered by sending serialization magic bytes. "
                                "This enables remote code execution via ysoserial gadget chains if a vulnerable library is on the classpath."
                            ),
                            evidence=f"Pattern: {pattern.pattern}\n\n{format_from_httpx(resp)}",
                            remediation=(
                                "Do not deserialize untrusted data. Use JSON or XML instead of Java serialization. "
                                "If serialization is required, use a deserialization filter (JEP 290). "
                                "Update all libraries on the classpath (Commons Collections, Spring, etc.)."
                            ),
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                                "https://github.com/frohoff/ysoserial",
                            ],
                            port_number=port, protocol="tcp",
                        )
            except Exception:
                pass
        return None

    async def _probe_php(self, client, base_url: str, port: int) -> FindingData | None:
        for path in _XML_ENDPOINTS:
            try:
                # POST body injection
                resp = await client.post(f"{base_url}{path}", data={"data": _PHP_PAYLOAD, "object": _PHP_PAYLOAD})
                for pattern in _PHP_ERRORS:
                    if pattern.search(resp.text):
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="Insecure PHP Deserialization Detected",
                            description=(
                                f"The endpoint {base_url}{path} appears to call unserialize() on POST data. "
                                "PHP object injection enables code execution if vulnerable magic methods (__wakeup, __destruct) "
                                "are present in any loaded class."
                            ),
                            evidence=f"Pattern: {pattern.pattern}\nPayload: {_PHP_PAYLOAD}\n\n{format_from_httpx(resp)}",
                            remediation=(
                                "Replace unserialize() with json_decode(). "
                                "If unserialize is required, use allowed_classes parameter to restrict deserialized types."
                            ),
                            references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                            port_number=port, protocol="tcp",
                        )
            except Exception:
                pass
        return None

    async def _probe_python(self, client, base_url: str, port: int) -> FindingData | None:
        for path in _XML_ENDPOINTS:
            try:
                resp = await client.post(
                    f"{base_url}{path}",
                    data={"data": _PYTHON_PICKLE_SAFE, "payload": _PYTHON_PICKLE_SAFE},
                    headers={"X-Pickle-Data": _PYTHON_PICKLE_SAFE},
                )
                for pattern in _PYTHON_ERRORS:
                    if pattern.search(resp.text):
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="Insecure Python Deserialization (Pickle) Detected",
                            description=(
                                f"The endpoint {base_url}{path} appears to call pickle.loads() on user input. "
                                "Python pickle deserialization executes arbitrary code when loading a crafted payload."
                            ),
                            evidence=f"Pattern: {pattern.pattern}\n\n{format_from_httpx(resp)}",
                            remediation=(
                                "Never use pickle.loads() on untrusted data. "
                                "Use JSON or msgpack for data serialization. "
                                "If pickle must be used, restrict to trusted sources only."
                            ),
                            references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                            port_number=port, protocol="tcp",
                        )
            except Exception:
                pass
        return None
