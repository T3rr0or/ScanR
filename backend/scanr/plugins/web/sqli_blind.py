"""Blind and time-based SQL injection detection.

Complements sqli_detect.py (error-based). Uses:
- Time-based: dialect-specific SLEEP/WAITFOR/pg_sleep payloads, measures response delay
- Boolean-based: true vs false condition, diffs response length

Gated behind profile_json.intrusive:true — sends non-standard SQL payloads.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme
from scanr.plugins.web._crawler import crawl

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]
_SLEEP_SECS = 3  # 5 dialects × 8 params × 5 paths × 3s = ~600s max with intrusive mode

# (dialect_name, true_payload, false_payload, time_payload)
_DIALECTS = [
    ("MySQL",    "1' AND 1=1-- -",  "1' AND 1=2-- -",  f"1' AND SLEEP({_SLEEP_SECS})-- -"),
    ("MSSQL",    "1' AND 1=1--",    "1' AND 1=2--",    f"1'; WAITFOR DELAY '0:0:{_SLEEP_SECS}'--"),
    ("Postgres", "1' AND 1=1--",    "1' AND 1=2--",    f"1'; SELECT pg_sleep({_SLEEP_SECS})--"),
    ("Oracle",   "1' AND 1=1--",    "1' AND 1=2--",    f"1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{_SLEEP_SECS})--"),
    ("SQLite",   "1' AND 1=1--",    "1' AND 1=2--",    "1' AND typeof(randomblob(100000000))='blob'-- -"),
]

_TEST_PARAMS = ["id", "q", "search", "query", "page", "cat", "user", "product", "item", "name", "pid", "uid"]


class SqliBlindPlugin(PluginBase):
    id = "web.sqli_blind"
    name = "SQL Injection (Blind/Time-Based)"
    description = "Detect blind and time-based SQL injection using per-dialect SLEEP/WAITFOR payloads and boolean response diffing"
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
            result = await self._test_blind(context, base_url, port.number, host.ip)
            if result:
                findings.append(result)
        return findings

    async def _test_blind(self, context, base_url: str, port: int, ip: str) -> FindingData | None:
        sem = asyncio.Semaphore(5)  # lower concurrency for timing accuracy
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=_SLEEP_SECS + 7.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            **context.proxy_config(),
            ) as client:
                crawled = await crawl(base_url, client)
                params = list(dict.fromkeys(crawled.get_params + _TEST_PARAMS))
                paths = crawled.paths or ["/"]

                for path in paths[:5]:
                    for param in params[:8]:
                        # Boolean diff first (fast, no delay)
                        result = await self._boolean_check(client, base_url, path, param, port, sem)
                        if result:
                            return result
                        # Time-based check
                        result = await self._time_check(client, base_url, path, param, port, sem)
                        if result:
                            return result
        except Exception as exc:
            logger.debug("Blind SQLi test failed for %s: %s", base_url, exc)
        return None

    async def _boolean_check(self, client, base_url, path, param, port, sem) -> FindingData | None:
        for dialect, true_p, false_p, _ in _DIALECTS:
            async with sem:
                try:
                    r_true = await client.get(f"{base_url}{path}?{param}={true_p}")
                    r_false = await client.get(f"{base_url}{path}?{param}={false_p}")
                    len_diff = abs(len(r_true.text) - len(r_false.text))
                    # Significant length difference between true/false conditions
                    if len_diff > 50 and r_true.status_code == r_false.status_code:
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title=f"SQL Injection (Boolean-Based Blind) — {dialect}",
                            description=(
                                f"Parameter '{param}' at {base_url}{path} responds differently "
                                f"to true ({true_p!r}) vs false ({false_p!r}) SQL conditions "
                                f"({dialect} dialect). Response length delta: {len_diff} bytes. "
                                "This indicates unsanitised input reaches a SQL query."
                            ),
                            evidence=(
                                f"True condition: GET {base_url}{path}?{param}={true_p} → {len(r_true.text)} bytes\n"
                                f"False condition: GET {base_url}{path}?{param}={false_p} → {len(r_false.text)} bytes\n"
                                f"Length delta: {len_diff} bytes"
                            ),
                            remediation="Use parameterised queries. Never concatenate user input into SQL strings.",
                            references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                            port_number=port,
                            protocol="tcp",
                        )
                except Exception:
                    pass
        return None

    async def _time_check(self, client, base_url, path, param, port, sem) -> FindingData | None:
        # Baseline request to measure normal response time
        try:
            t0 = time.monotonic()
            await client.get(f"{base_url}{path}?{param}=1")
            baseline_ms = (time.monotonic() - t0) * 1000
        except Exception:
            return None

        for dialect, _, _, time_p in _DIALECTS:
            async with sem:
                try:
                    t0 = time.monotonic()
                    resp = await client.get(f"{base_url}{path}?{param}={time_p}")
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    # Triggered if response took ≥ sleep_secs - 0.5s longer than baseline
                    if elapsed_ms >= ((_SLEEP_SECS - 0.5) * 1000) and elapsed_ms > baseline_ms + 3000:
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title=f"SQL Injection (Time-Based Blind) — {dialect}",
                            description=(
                                f"Parameter '{param}' at {base_url}{path} caused a {elapsed_ms/1000:.1f}s delay "
                                f"when injected with a {dialect} time-based payload ({time_p!r}). "
                                f"Baseline response: {baseline_ms:.0f}ms. "
                                "This confirms the database processes injected SQL."
                            ),
                            evidence=(
                                f"Payload: {time_p}\n"
                                f"Baseline: {baseline_ms:.0f}ms\n"
                                f"Injected response: {elapsed_ms:.0f}ms\n"
                                f"Delta: {elapsed_ms - baseline_ms:.0f}ms"
                            ),
                            remediation="Use parameterised queries. Never concatenate user input into SQL strings.",
                            references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                            port_number=port,
                            protocol="tcp",
                        )
                except Exception:
                    pass
        return None
