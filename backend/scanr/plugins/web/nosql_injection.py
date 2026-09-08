"""MongoDB-style NoSQL operator injection.

The SQL injection plugins do not cover this at all: a document store has no SQL
syntax to break, so quote-and-comment payloads are inert against it. What breaks
instead is the *type* of a value. A framework that drops a parsed query string or
JSON body straight into a Mongo filter turns

    {"username": "alice", "password": "hunter2"}      # what the app meant
    {"username": "alice", "password": {"$ne": null}}  # what the attacker sends

from an equality match into "any password that is not null" — an authentication
bypass with no credentials at all. The same trick against a filter parameter
(`$gt`, `$regex`, `$nin`) leaks rows the caller was never scoped to see.

Both wire formats are tested, because they are handled by different code paths:

* **Query string** — `param[$ne]=1`. Express's `qs` parser (and Rails, PHP, and
  friends) turns bracket syntax into a nested object before the app ever sees it.
* **JSON body** — `{"param": {"$ne": null}}` posted to the same endpoint.

Detection is purely differential, never a single response. Three guards, because
each one alone produces noise on real systems:

1. **Stability.** Two *different* inert control values must produce equivalent
   responses. An endpoint that already varies run-to-run (a timestamp, a CSRF
   token, a rotating ad slot, load-balanced backends) has no usable oracle, and
   is skipped rather than guessed at.
2. **Shape.** A *non-operator* object (`param[scanr_ctl]=…`) must behave like
   the plain string. An API that legitimately takes an object there — a search
   endpoint whose `filter` really is a document — answers differently to a
   string for reasons that have nothing to do with injection, and would
   otherwise be reported on every scan.
3. **Success.** The payload response must be 2xx/3xx. A 400 or 500 means the
   operator object was *rejected* — the opposite of a vulnerability — and that
   is exactly the differential a naive length/status diff would report.
4. **Reproducibility.** The differential is re-measured before reporting. One
   diverging response is noise; two in a row is a signal.

Intrusive but not destructive: every payload is a read-side filter. Nothing here
writes, drops, or updates a document, and the `$where` probe is `return true` —
a predicate, not a script with side effects.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import crawl, create_web_client
from scanr.plugins.web._http_evidence import format_from_httpx
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# Parameters that most often reach a document-store filter directly.
_TEST_PARAMS = [
    "username", "user", "email", "login", "password", "pass", "id", "_id",
    "q", "search", "query", "filter", "name", "role", "token",
]

# Two *different* inert values. Equivalent responses to both is what licenses
# the rest of the check; see guard 1 in the module docstring.
_CONTROL_A = "scanr_nosql_control_a"
_CONTROL_B = "scanrnosqlcontrolb2"
# A nested key that is *not* a Mongo operator — see guard 2 in the docstring.
_CONTROL_KEY = "scanr_ctl"

# Bodies stay under 30% length divergence for "equivalent". Generous: a page
# that embeds a request id or a rotating nonce still compares equal, while an
# authenticated dashboard versus a login form does not.
_LENGTH_TOLERANCE = 0.30

# (operator, value, human label). Values are read-side filters only.
_OPERATORS: list[tuple[str, object, str]] = [
    # Classic auth bypass: "not equal to a value the field never holds".
    ("$ne", "scanr_nomatch", "$ne (not-equal) operator injection"),
    # Ordering comparison against the empty string matches every string.
    ("$gt", "", "$gt (greater-than) operator injection"),
    # A catch-all regular expression; anchored to stay cheap on the server.
    ("$regex", "^", "$regex operator injection"),
    # Server-side JS evaluation. `return true` is a pure predicate: it reads,
    # it does not write, and it cannot persist anything on the target.
    ("$where", "return true", "$where server-side JavaScript injection"),
]


def _equivalent(status_a: int, body_a: str, status_b: int, body_b: str) -> bool:
    """True when two responses are close enough to be the same answer."""
    if status_a != status_b:
        return False
    longest = max(len(body_a), len(body_b))
    if longest == 0:
        return True
    return abs(len(body_a) - len(body_b)) / longest <= _LENGTH_TOLERANCE


class _Probe:
    """A response reduced to the two things the differential compares."""

    __slots__ = ("status", "body", "resp")

    def __init__(self, resp) -> None:
        self.status = resp.status_code
        self.body = resp.text
        self.resp = resp


class NoSqlInjectionPlugin(PluginBase):
    id = "web.nosql_injection"
    name = "NoSQL Injection"
    description = (
        "Detect MongoDB-style operator injection ($ne/$gt/$regex/$where) in query "
        "strings and JSON bodies via a reproducible behavioural differential"
    )
    category = PluginCategory.web
    intrusive = True
    severity = Severity.critical
    ports = HTTP_PORTS
    timeout = 300

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            try:
                finding = await self._test_host(context, base_url, port.number)
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("nosql_injection: %s failed: %s", base_url, exc)
                continue
            if finding:
                findings.append(finding)
        return findings

    async def _test_host(self, context, base_url: str, port: int) -> FindingData | None:
        async with create_web_client(context) as client:
            crawled = await crawl(base_url, client)
            candidates = crawled.get_params + crawled.form_fields + _TEST_PARAMS
            params = list(dict.fromkeys(candidates))[:8]
            paths = (crawled.paths or ["/"])[:4]

            for path in paths:
                url = f"{base_url}{path}"
                for param in params:
                    hit = await self._test_query_param(client, url, param, port)
                    if hit:
                        return hit
                    hit = await self._test_json_body(client, url, param, port)
                    if hit:
                        return hit
        return None

    # ── query-string vector: param[$ne]=value ────────────────────────────────

    async def _test_query_param(
        self, client, url: str, param: str, port: int
    ) -> FindingData | None:
        baseline = await self._get(client, url, {param: _CONTROL_A})
        if baseline is None:
            return None
        if not await self._is_stable_get(client, url, param, baseline):
            return None
        # Guard 2: a nested non-operator key must not move the needle by itself.
        shape_control = await self._get(
            client, url, {f"{param}[{_CONTROL_KEY}]": _CONTROL_A}
        )
        if self._is_hit(baseline, shape_control):
            return None

        for operator, value, label in _OPERATORS:
            key = f"{param}[{operator}]"
            probe = await self._get(client, url, {key: value})
            if not self._is_hit(baseline, probe):
                continue
            # Re-measure: a single divergence is noise on a live application.
            confirm = await self._get(client, url, {key: value})
            if not self._is_hit(baseline, confirm):
                continue
            return self._finding(
                url, param, port,
                vector="query string",
                payload=f"{key}={value}",
                label=label,
                baseline=baseline,
                probe=confirm,
            )
        return None

    async def _is_stable_get(self, client, url: str, param: str, baseline: _Probe) -> bool:
        """A second inert value must give the same answer as the first."""
        control = await self._get(client, url, {param: _CONTROL_B})
        if control is None:
            return False
        return _equivalent(baseline.status, baseline.body, control.status, control.body)

    # ── JSON body vector: {"param": {"$ne": null}} ───────────────────────────

    async def _test_json_body(
        self, client, url: str, param: str, port: int
    ) -> FindingData | None:
        baseline = await self._post_json(client, url, {param: _CONTROL_A})
        if baseline is None:
            return None
        # An endpoint that does not take a JSON body at all answers 404/405 to
        # everything; that is uniform, so the stability check passes and the
        # success guard below is what stops it from ever being reported.
        control = await self._post_json(client, url, {param: _CONTROL_B})
        if control is None:
            return None
        if not _equivalent(baseline.status, baseline.body, control.status, control.body):
            return None
        # Guard 2, body edition: an endpoint whose field is genuinely a document
        # ({"filter": {...}}) accepts any object here, operator or not.
        shape_control = await self._post_json(
            client, url, {param: {_CONTROL_KEY: _CONTROL_A}}
        )
        if self._is_hit(baseline, shape_control):
            return None

        for operator, value, label in _OPERATORS:
            # `$ne: null` is the canonical auth-bypass body; the query-string
            # vector cannot express a JSON null, so it uses a sentinel instead.
            payload_value: object = None if operator == "$ne" else value
            body = {param: {operator: payload_value}}
            probe = await self._post_json(client, url, body)
            if not self._is_hit(baseline, probe):
                continue
            confirm = await self._post_json(client, url, body)
            if not self._is_hit(baseline, confirm):
                continue
            return self._finding(
                url, param, port,
                vector="JSON request body",
                payload=json.dumps(body),
                label=label,
                baseline=baseline,
                probe=confirm,
            )
        return None

    # ── differential ─────────────────────────────────────────────────────────

    @staticmethod
    def _is_hit(baseline: _Probe, probe: _Probe | None) -> bool:
        """True when `probe` is a *successful* response unlike the baseline.

        The success requirement is the important half. A server that rejects an
        unexpected object with 400, or blows up on it with 500, produces a large
        status and body differential — and reporting that as injection is the
        single most common false positive in this check.
        """
        if probe is None:
            return False
        if not 200 <= probe.status < 400:
            return False
        return not _equivalent(baseline.status, baseline.body, probe.status, probe.body)

    # ── transport ────────────────────────────────────────────────────────────

    @staticmethod
    async def _get(client, url: str, params: dict) -> _Probe | None:
        try:
            return _Probe(await client.get(url, params=params, timeout=8.0))
        except Exception:
            return None

    @staticmethod
    async def _post_json(client, url: str, body: dict) -> _Probe | None:
        try:
            return _Probe(await client.post(url, json=body, timeout=8.0))
        except Exception:
            return None

    # ── reporting ────────────────────────────────────────────────────────────

    def _finding(
        self, url: str, param: str, port: int, *,
        vector: str, payload: str, label: str, baseline: _Probe, probe: _Probe,
    ) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="NoSQL Injection",
            description=(
                f"The {param!r} parameter at {url} is passed into a document-store query "
                f"without type validation. A {label} sent in the {vector} changed the "
                f"application's behaviour: the inert control returned HTTP {baseline.status} "
                f"({len(baseline.body)} bytes) while the operator payload returned HTTP "
                f"{probe.status} ({len(probe.body)} bytes), reproducibly. An attacker can "
                "replace a value with a query operator to bypass authentication, read "
                "documents outside their scope, or — with $where — evaluate JavaScript "
                "inside the database engine."
            ),
            evidence=(
                f"Parameter: {param}\nVector: {vector}\nPayload: {payload}\n"
                f"Control ({_CONTROL_A}): HTTP {baseline.status}, {len(baseline.body)} bytes\n"
                f"Payload:  HTTP {probe.status}, {len(probe.body)} bytes\n"
                "A second inert control produced an equivalent response, and the payload "
                "differential reproduced on a repeat request.\n\n"
                f"{format_from_httpx(probe.resp)}"
            ),
            remediation=(
                "Validate and coerce request values to their expected scalar type before "
                "they reach the database: reject a parameter that arrives as an object or "
                "array where a string was expected. In Express, disable extended query "
                "parsing (`app.set('query parser', 'simple')`) or validate with a schema "
                "library; in Mongoose, keep `sanitizeFilter` enabled. Disable server-side "
                "JavaScript in MongoDB (`--noscripting`, or `security.javascriptEnabled: "
                "false`) so `$where` cannot be reached at all."
            ),
            references=[
                "https://owasp.org/www-community/attacks/NoSQL_injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/943.html",
            ],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            port_number=port,
            protocol="tcp",
        )
