"""JBoss and Oracle WebLogic unauthenticated management/deserialization surface.

Both application servers ship admin and RPC endpoints that, when reachable
without authentication, are the exact entry points behind a string of
known-exploited CVEs:

  * JBoss ``/jmx-console/`` and ``/web-console/`` — authentication-bypass
    deploy consoles (CVE-2010-0738, CVE-2010-1428) that lead to MBean-deploy RCE.
  * JBoss ``/invoker/JMXInvokerServlet`` and ``/invoker/EJBInvokerServlet`` —
    unauthenticated Java-serialized-object invokers, deserialization RCE.
  * WebLogic ``/console/`` — the admin console exposed to the network.
  * WebLogic ``/wls-wsat/CoordinatorPortType`` and ``/_async/AsyncResponseService``
    — WS-Atomic/async SOAP deserialization endpoints (CVE-2017-10271,
    CVE-2019-2725).

The check only issues GETs and matches on server-emitted markers (a Java
serialized-object magic header, the console's own HTML, the WSAT SOAP surface).
It sends no exploit payload — it reports that the surface is reachable, which is
what Nessus reported here and ScanR did not. WebLogic's T3 protocol on 7001 is a
separate, non-HTTP surface covered by ``nuclei.network_runner``.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

APPSERVER_PORTS = [80, 443, 7001, 8080, 8443, 9990, 8000, 9080, 7002]

_HTTPS_PORTS = {443, 8443, 7002}

# Java serialized-object stream magic: 0xAC 0xED 0x00 0x05.
_JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"

REF_JBOSS = [
    "https://nvd.nist.gov/vuln/detail/CVE-2010-0738",
    "https://nvd.nist.gov/vuln/detail/CVE-2010-1428",
    "https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization",
]
REF_WEBLOGIC = [
    "https://nvd.nist.gov/vuln/detail/CVE-2017-10271",
    "https://nvd.nist.gov/vuln/detail/CVE-2019-2725",
    "https://www.oracle.com/security-alerts/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Client factory so tests can swap in an httpx.MockTransport.

    verify=False: internal app servers routinely front an untrusted certificate,
    and a TLS error would hide the endpoint entirely.
    """
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _scheme(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


class JavaAppserverExposurePlugin(PluginBase):
    id = "services.java_appserver_exposure"
    name = "JBoss / WebLogic Management Exposure"
    description = "Detect unauthenticated JBoss consoles/invokers and WebLogic console/deserialization endpoints"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2010-0738", "CVE-2010-1428", "CVE-2017-10271", "CVE-2019-2725"]
    ports = APPSERVER_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.state != "open" or port.number not in APPSERVER_PORTS:
                continue
            findings.extend(await self._probe(context, host.ip, port.number))
        return findings

    async def _get(self, context, url: str) -> httpx.Response | None:
        try:
            async with _client(context) as client:
                return await client.get(url)
        except Exception:
            return None

    async def _probe(self, context, ip: str, port: int) -> list[FindingData]:
        base = f"{_scheme(port)}://{ip}:{port}"
        out: list[FindingData] = []

        # ── JBoss consoles ────────────────────────────────────────────────
        for path, cve, name in (
            ("/jmx-console/", "CVE-2010-0738", "JMX console"),
            ("/web-console/", "CVE-2010-1428", "web console"),
        ):
            resp = await self._get(context, base + path)
            if resp is None:
                continue
            body = resp.text[:20000].lower()
            # A reachable console answers 200 with its own HTML. A login prompt
            # (401/403, or a form) means auth is enforced — not this finding.
            if resp.status_code == 200 and ("jboss" in body or "mbean" in body) and "j_username" not in body:
                out.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title=f"JBoss {name} exposed without authentication",
                    description=(
                        f"The JBoss {name} answered on {base}{path} without authentication. This console can "
                        "deploy MBeans and applications, which is a direct path to remote code execution on the "
                        "server. It corresponds to the JBoss authentication-bypass class of vulnerabilities that "
                        "remain actively exploited."
                    ),
                    evidence=f"GET {base}{path} -> HTTP 200, JBoss console markup returned",
                    remediation=(
                        "Require authentication on the JMX and web consoles (secure the jmx-console and "
                        "web-console security-constraints), or remove them entirely on production servers, and "
                        "block management ports at the network boundary. Upgrade off end-of-life JBoss AS."
                    ),
                    references=REF_JBOSS,
                    cve_ids=[cve],
                    port_number=port,
                    protocol="tcp",
                ))

        # ── JBoss invoker servlets (unauth serialized-object RPC) ─────────
        for path in ("/invoker/JMXInvokerServlet", "/invoker/EJBInvokerServlet"):
            resp = await self._get(context, base + path)
            if resp is None:
                continue
            ctype = resp.headers.get("content-type", "").lower()
            if resp.status_code in (200, 500) and (
                "java-serialized-object" in ctype or resp.content[:4] == _JAVA_SERIAL_MAGIC
            ):
                out.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="JBoss invoker servlet exposed (unauthenticated deserialization)",
                    description=(
                        f"{base}{path} returned a Java serialized object to an unauthenticated request. The JBoss "
                        "invoker accepts serialized MarshalledInvocation objects, so an exposed invoker is a "
                        "well-known unauthenticated Java deserialization remote-code-execution surface."
                    ),
                    evidence=f"GET {base}{path} -> HTTP {resp.status_code}, java-serialized-object response",
                    remediation=(
                        "Block or authenticate the /invoker/* endpoints, remove the http-invoker if unused, and "
                        "upgrade off end-of-life JBoss AS. Restrict the port to trusted management networks."
                    ),
                    references=REF_JBOSS,
                    cve_ids=["CVE-2010-0738"],
                    port_number=port,
                    protocol="tcp",
                ))

        # ── WebLogic deserialization SOAP endpoints ──────────────────────
        for path, cve in (
            ("/wls-wsat/CoordinatorPortType", "CVE-2017-10271"),
            ("/_async/AsyncResponseService", "CVE-2019-2725"),
        ):
            resp = await self._get(context, base + path)
            if resp is None:
                continue
            body = resp.text[:8000].lower()
            marker = any(m in body for m in ("wsat", "coordinatorporttype", "asyncresponseservice", "soap:envelope", "web services"))
            if resp.status_code in (200, 500) and marker:
                out.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Oracle WebLogic deserialization endpoint reachable",
                    description=(
                        f"The WebLogic SOAP endpoint {base}{path} is reachable without authentication. This "
                        "endpoint has repeatedly been the vector for unauthenticated XMLDecoder/deserialization "
                        "remote code execution, and it is enabled by default on affected builds."
                    ),
                    evidence=f"GET {base}{path} -> HTTP {resp.status_code}, WebLogic SOAP endpoint present",
                    remediation=(
                        "Apply the current Oracle Critical Patch Update for WebLogic. If the WSAT and async "
                        "components are unused, remove or block /wls-wsat/* and /_async/*, and keep the console "
                        "and these endpoints off untrusted networks."
                    ),
                    references=REF_WEBLOGIC,
                    cve_ids=[cve],
                    port_number=port,
                    protocol="tcp",
                ))

        # ── WebLogic admin console exposed ───────────────────────────────
        server_hdr = ""
        resp = await self._get(context, base + "/console/login/LoginForm.jsp")
        if resp is not None:
            server_hdr = resp.headers.get("server", "").lower()
            body = resp.text[:8000].lower()
            if resp.status_code in (200, 302) and ("weblogic" in body or "weblogic" in server_hdr or "wl_login" in body):
                out.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Oracle WebLogic administration console exposed",
                    description=(
                        f"The WebLogic admin console login page is reachable on {base}/console/. Exposing the "
                        "administration console to the network broadens the attack surface for credential "
                        "attacks and for the deserialization CVEs that target WebLogic management endpoints."
                    ),
                    evidence=f"GET {base}/console/login/LoginForm.jsp -> HTTP {resp.status_code}, WebLogic console",
                    remediation=(
                        "Restrict the WebLogic admin console to a management network, enforce strong "
                        "administrator credentials and lockout, and keep current with Oracle CPUs."
                    ),
                    references=REF_WEBLOGIC,
                    port_number=port,
                    protocol="tcp",
                ))
        return out
