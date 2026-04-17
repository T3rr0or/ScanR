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
from scanr.plugins.web._crawler import crawl

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]

_PAYLOADS = ["'", "''", "`", "1 AND 1=2", "1' AND '1'='1", "1; SELECT 1--"]

_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"SQL syntax.*?(MySQL|MariaDB)",
        r"SQL Error:.*?syntax",
        r"error in your SQL syntax",
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

# POST login endpoints to probe with SQLi in username/password fields
_LOGIN_PATHS = [
    "/login", "/login.php", "/index.php", "/signin", "/signin.php",
    "/admin", "/admin.php", "/admin/login", "/user/login", "/login2.php",
    "/wp-login.php", "/account/login",
]
_LOGIN_FIELDS = [
    {"username": "'", "password": "x"},           # syntax error trigger
    {"username": "' OR '1'='1", "password": "x"},
    {"username": "admin'--", "password": "x"},
    {"email": "'", "password": "x"},
    {"email": "' OR '1'='1", "password": "x"},
    {"user": "'", "pass": "x"},
    {"user": "' OR '1'='1", "pass": "x"},
]


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
        sem = asyncio.Semaphore(20)
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=8.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            ) as client:
                crawled = await crawl(base_url, client)

                # GET param testing — crawled params + fallback, with concurrency limit
                params = list(dict.fromkeys(crawled.get_params + _TEST_PARAMS))
                paths = crawled.paths or ["/"]

                async def probe_get(path: str, param: str, payload: str) -> FindingData | None:
                    url = f"{base_url}{path}?{param}={payload}"
                    async with sem:
                        try:
                            resp = await client.get(url)
                            for pattern in _ERROR_PATTERNS:
                                if pattern.search(resp.text):
                                    return FindingData(
                                        plugin_id=self.id,
                                        severity=Severity.critical,
                                        title="SQL Injection (Error-Based) Detected",
                                        description=(
                                            f"Parameter '{param}' at {base_url}{path} is vulnerable to "
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
                            pass
                    return None

                get_tasks = [
                    probe_get(path, param, payload)
                    for path in paths
                    for param in params
                    for payload in _PAYLOADS
                ]
                for coro in asyncio.as_completed(get_tasks):
                    result = await coro
                    if result:
                        return result

                # POST form probing — crawled form paths + fallback login paths
                post_paths = list(dict.fromkeys(crawled.form_paths + _LOGIN_PATHS))

                # Build POST field combos: standard sets + crawled field names
                # Use full combos (not single-field) so we don't hit "required field" validation
                field_combos = list(_LOGIN_FIELDS)
                if crawled.form_fields:
                    # Make a combo using all crawled fields, with first set to "'"
                    for primary in crawled.form_fields:
                        combo = {f: ("'" if f == primary else "x") for f in crawled.form_fields}
                        field_combos.insert(0, combo)

                for path in post_paths:
                    for fields in field_combos:
                        async with sem:
                            try:
                                resp = await client.post(f"{base_url}{path}", data=fields)
                                for pattern in _ERROR_PATTERNS:
                                    if pattern.search(resp.text):
                                        field_str = next(
                                            k for k, v in fields.items() if v == "'"
                                        )
                                        return FindingData(
                                            plugin_id=self.id,
                                            severity=Severity.critical,
                                            title="SQL Injection (Error-Based) Detected — POST Form",
                                            description=(
                                                f"POST parameter '{field_str}' at {base_url}{path} is vulnerable to "
                                                "error-based SQL injection. Database error messages are exposed "
                                                "in the response, indicating unsanitised input reaches a SQL query."
                                            ),
                                            evidence=f"URL: POST {base_url}{path}\nFields: {fields}\nPattern matched: {pattern.pattern}\nResponse snippet: {resp.text[:500]}",
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
