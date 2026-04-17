"""Error-based SQL injection detection.

Tests common URL parameters for SQL injection by injecting payloads
and checking for database error signatures in responses.
Only performs error-based detection — no blind/time-based techniques.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]

_PAYLOADS = ["'", "''", "`", "1 AND 1=2", "1' AND '1'='1", "1; SELECT 1--"]

_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"ORA-\d{4,5}",
        r"Oracle.*?Driver",
        r"SQLite.*?Exception",
        r"System\.Data\.SQLite",
        r"Microsoft.*?SQL Server",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"PostgreSQL.*?ERROR",
        r"pg_query\(\).*?failed",
        r"Syntax error.*?in query expression",
        r"ODBC.*?SQL Server",
        r"SQLSyntaxErrorException",
        r"Npgsql\.",
    ]
]

_TEST_PARAMS = ["id", "q", "search", "query", "page", "cat", "user", "product", "item", "name"]


class SqliDetectPlugin(PluginBase):
    id = "web.sqli_detect"
    name = "SQL Injection (Error-Based)"
    description = "Detect error-based SQL injection in URL parameters"
    category = PluginCategory.web
    severity = Severity.critical
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._test_sqli(base_url, port.number, host.ip)
            if result:
                findings.append(result)
        return findings

    async def _test_sqli(self, base_url: str, port: int, ip: str) -> FindingData | None:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=8.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            ) as client:
                for param in _TEST_PARAMS:
                    for payload in _PAYLOADS:
                        url = f"{base_url}/?{param}={payload}"
                        try:
                            resp = await client.get(url)
                            for pattern in _ERROR_PATTERNS:
                                if pattern.search(resp.text):
                                    return FindingData(
                                        plugin_id=self.id,
                                        severity=Severity.critical,
                                        title="SQL Injection (Error-Based) Detected",
                                        description=(
                                            f"The parameter '{param}' at {base_url} is vulnerable to "
                                            "error-based SQL injection. Database error messages are exposed "
                                            "in the response, indicating unsanitised input reaches a SQL query."
                                        ),
                                        evidence=f"URL: {url}\nPattern matched: {pattern.pattern}\nResponse snippet: {resp.text[:500]}",
                                        remediation=(
                                            "Use parameterised queries or prepared statements. "
                                            "Never concatenate user input into SQL strings. "
                                            "Suppress database error messages in production."
                                        ),
                                        references=[
                                            "https://owasp.org/www-community/attacks/SQL_Injection",
                                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                        ],
                                        port_number=port,
                                        protocol="tcp",
                                    )
                        except Exception:
                            continue
        except Exception as exc:
            logger.debug("SQLi test failed for %s: %s", base_url, exc)
        return None
