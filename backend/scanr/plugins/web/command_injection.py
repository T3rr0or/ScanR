"""OS command injection detection.

The one major injection class the suite did not cover. SQLi, SSTI, XXE and
deserialization all reach code execution by a specific route; this covers the
direct one — user input concatenated into a shell command.

Two independent signals, because either alone produces noise:

* **Echo**: inject a shell separator followed by `echo <marker>` and look for a
  marker that is not in the baseline response. Cheap and unambiguous when it
  lands, but blind to applications that discard command output.
* **Time**: inject a `sleep`/`ping` delay and require the response to slow by a
  margin over a measured per-endpoint baseline, then confirm with a second
  request. Catches blind injection, where nothing is reflected.

Intrusive but not destructive: `echo` and `sleep` read nothing and change no
state, and no payload here chains a write, delete, or network callback.
"""
from __future__ import annotations

import logging
import secrets
import time
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._budget import Budget
from scanr.plugins.web._crawler import crawl, create_web_client
from scanr.plugins.web._http_evidence import format_from_httpx
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# Parameters that most often feed a shell (host tools, converters, exporters).
_TEST_PARAMS = [
    "cmd", "exec", "command", "run", "ping", "host", "hostname", "ip", "addr",
    "target", "url", "domain", "file", "filename", "path", "query", "search",
    "name", "action", "op", "process", "download",
]

_SLEEP_SECONDS = 5
# The response must slow by at least this much over baseline to count. Generous
# so ordinary jitter, a slow backend, or a shared-host hiccup cannot trip it.
_DELAY_MARGIN = 3.0
_BASELINE_VALUE = "scanr_cmdi_baseline"
# Wall-clock allowance per host, comfortably inside the plugin's own 300s
# timeout so we stop deliberately rather than being cancelled by the engine.
# Measured need: paths x params x the timing oracle can otherwise reach ~50 min.
_HOST_BUDGET = 210.0


def _echo_payloads(marker: str) -> list[tuple[str, str]]:
    """(payload, human label) pairs that print `marker` if a shell runs them."""
    return [
        (f";echo {marker};", "; echo"),
        (f"|echo {marker}", "| echo"),
        (f"&&echo {marker}", "&& echo"),
        (f"`echo {marker}`", "backtick echo"),
        (f"$(echo {marker})", "$() echo"),
        (f"%0aecho {marker}", "newline echo"),
        # Windows: cmd.exe has no `echo` separator problem, & chains reliably.
        (f"&echo {marker}", "& echo (Windows)"),
    ]


def _delay_payloads() -> list[tuple[str, str]]:
    """(payload, label) pairs that stall a shell for _SLEEP_SECONDS."""
    return [
        (f";sleep {_SLEEP_SECONDS};", "; sleep"),
        (f"|sleep {_SLEEP_SECONDS}", "| sleep"),
        (f"&&sleep {_SLEEP_SECONDS}", "&& sleep"),
        (f"`sleep {_SLEEP_SECONDS}`", "backtick sleep"),
        (f"$(sleep {_SLEEP_SECONDS})", "$() sleep"),
        # Windows has no sleep; ping to loopback is the standard stand-in.
        (f"&ping -n {_SLEEP_SECONDS + 1} 127.0.0.1", "& ping (Windows)"),
    ]


class CommandInjectionPlugin(PluginBase):
    id = "web.command_injection"
    name = "OS Command Injection"
    description = (
        "Detect OS command injection via shell metacharacters, using an echo "
        "marker and a timing oracle for blind cases"
    )
    category = PluginCategory.web
    intrusive = True
    severity = Severity.critical
    ports = HTTP_PORTS
    timeout = 300

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        budget = Budget(_HOST_BUDGET)
        for port in host.ports:
            if budget.spent():
                logger.info("command_injection: %s budget spent, %s", host.ip, budget.note())
                break
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            try:
                finding = await self._test_host(context, base_url, port.number, budget)
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("command_injection: %s failed: %s", base_url, exc)
                continue
            if finding:
                findings.append(finding)
        return findings

    async def _test_host(
        self, context, base_url: str, port: int, budget: Budget
    ) -> FindingData | None:
        async with create_web_client(context) as client:
            crawled = await crawl(base_url, client)
            params = list(dict.fromkeys(crawled.get_params + _TEST_PARAMS))[:10]
            paths = (crawled.paths or ["/"])[:5]

            for path in paths:
                for param in params:
                    if budget.spent():
                        return None
                    hit = await self._test_param(client, base_url, path, param, port, budget)
                    if hit:
                        return hit
        return None

    async def _test_param(
        self, client, base_url: str, path: str, param: str, port: int, budget: Budget
    ) -> FindingData | None:
        url = f"{base_url}{path}"
        try:
            baseline = await client.get(url, params={param: _BASELINE_VALUE}, timeout=8.0)
        except Exception:
            return None
        baseline_text = baseline.text

        # 1) Echo marker — unambiguous, but only on an endpoint that does not
        # simply reflect its input. Establish that with a control request first:
        # the marker is sent alone, with no shell metacharacters, so nothing can
        # execute it. If it comes back anyway the endpoint echoes user input, and
        # any later "marker in response" would be that echo rather than a shell.
        # Comparing strings against the payload is not enough — a reflected query
        # string is URL-encoded and would slip past it.
        marker = f"scanr{secrets.token_hex(6)}"
        if not await self._reflects_input(client, url, param, marker):
            for payload, label in _echo_payloads(marker):
                try:
                    resp = await client.get(url, params={param: payload}, timeout=8.0)
                except Exception:
                    continue
                if marker in resp.text and marker not in baseline_text:
                    return self._finding(
                        url, param, payload, label, port,
                        proof=f"Marker {marker!r} appeared in the response body",
                        evidence_extra=format_from_httpx(resp),
                    )

        # 2) Timing oracle — the blind case, and by far the expensive half:
        # every delay payload costs a real stall. Skip it rather than start one
        # we cannot finish.
        if budget.remaining < _SLEEP_SECONDS * 3:
            return None
        timing = await self._timing_probe(client, url, param)
        if timing is not None:
            payload, label, baseline_s, slow_s = timing
            return self._finding(
                url, param, payload, label, port,
                proof=(
                    f"Response time rose from {baseline_s:.1f}s to {slow_s:.1f}s when a "
                    f"{_SLEEP_SECONDS}s delay was injected, confirmed on a second request"
                ),
                evidence_extra=f"Baseline: {baseline_s:.2f}s\nWith delay payload: {slow_s:.2f}s",
            )
        return None

    @staticmethod
    async def _reflects_input(client, url: str, param: str, marker: str) -> bool:
        """True if the endpoint echoes an inert value back into its response."""
        try:
            control = await client.get(url, params={param: marker}, timeout=8.0)
        except Exception:
            return True  # cannot establish a clean control -> do not use this oracle
        return marker in control.text

    async def _timing_probe(
        self, client, url: str, param: str
    ) -> tuple[str, str, float, float] | None:
        """Return (payload, label, baseline, delayed) when a delay reproduces."""
        baseline_s = await self._timed_get(client, url, {param: _BASELINE_VALUE})
        if baseline_s is None:
            return None

        for payload, label in _delay_payloads():
            first = await self._timed_get(client, url, {param: payload})
            if first is None or first < baseline_s + _DELAY_MARGIN:
                continue
            # Confirm: one slow response is a coincidence, two is a signal.
            second = await self._timed_get(client, url, {param: payload})
            if second is not None and second >= baseline_s + _DELAY_MARGIN:
                return payload, label, baseline_s, second
        return None

    @staticmethod
    async def _timed_get(client, url: str, params: dict) -> float | None:
        started = time.monotonic()
        try:
            await client.get(url, params=params, timeout=_SLEEP_SECONDS + 10)
        except httpx.TimeoutException:
            # A timeout is itself evidence of a stall, but an unbounded one —
            # report it as the full budget rather than guessing.
            return float(_SLEEP_SECONDS + 10)
        except Exception:
            return None
        return time.monotonic() - started

    def _finding(
        self, url: str, param: str, payload: str, label: str, port: int,
        *, proof: str, evidence_extra: str,
    ) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="OS Command Injection",
            description=(
                f"The {param!r} parameter at {url} passes user input into an operating "
                f"system command. A {label} payload was executed by the underlying shell. "
                "An attacker can run arbitrary commands as the web server user — reading "
                "application secrets, pivoting to internal systems, or establishing "
                "persistence."
            ),
            evidence=f"Parameter: {param}\nPayload: {payload!r}\n{proof}\n\n{evidence_extra}",
            remediation=(
                "Do not build shell commands from user input. Use language APIs that take "
                "an argument list and bypass the shell entirely (execve-style, or Python's "
                "subprocess with shell=False). Where a shell is unavoidable, validate input "
                "against a strict allowlist rather than escaping metacharacters."
            ),
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            port_number=port,
            protocol="tcp",
        )
