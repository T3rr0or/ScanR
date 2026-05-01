from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex

from sqlalchemy.ext.asyncio import AsyncSession

from scanr.core.compliance import tags_for_plugin
from scanr.core.mitre import mitre_tags_for_plugin
from scanr.core.plugin_base import FindingData
from scanr.models import Finding, Host, Scan
from scanr.models.base import new_uuid

logger = logging.getLogger(__name__)

# Severity → stat column map
_SEVERITY_COLS = {
    "critical": "findings_critical",
    "high": "findings_high",
    "medium": "findings_medium",
    "low": "findings_low",
    "info": "findings_info",
}

_PEER_REVIEW_LABEL = "Peer review command:"
_URL_RE = re.compile(r"https?://[^\s)'\"<>]+")


def _compute_vpr(cvss_score: float | None, cve_ids: list[str] | None) -> float | None:
    """Vulnerability Priority Rating: CVSS × KEV multiplier, capped at 10."""
    if cvss_score is None:
        return None
    try:
        from scanr.plugins.cve.nvd_loader import get_kev_cve_ids
        kev = get_kev_cve_ids()
        is_kev = bool(cve_ids and any(c in kev for c in cve_ids))
    except Exception:
        is_kev = False
    return round(min(cvss_score * (2.0 if is_kev else 1.0), 10.0), 2)


class ResultCollector:
    """Thread-safe accumulator that flushes findings to the DB and updates scan stats."""

    def __init__(
        self,
        scan_id: str,
        db: AsyncSession,
        scan_log=None,
        user_id: str | None = None,
        db_lock: asyncio.Lock | None = None,
    ):
        self.scan_id = scan_id
        self.db = db
        self._scan_log = scan_log
        self._user_id = user_id
        self._lock = db_lock or asyncio.Lock()
        self._cached_scan: "Scan | None" = None
        self._host_ip_cache: dict[str, str | None] = {}

    async def add_finding(self, host_id: str | None, data: FindingData) -> None:
        async with self._lock:
            compliance_tags = tags_for_plugin(data.plugin_id)
            mitre_tags = mitre_tags_for_plugin(data.plugin_id)
            evidence = await self._evidence_with_peer_review_command(host_id, data)

            # Triage carryforward: look up a prior finding with same plugin/host/port
            # across any previous scan for this user, and carry forward triage state.
            prior = await self._find_prior_triage(host_id, data)

            cve_ids_list = data.cve_ids if data.cve_ids else None
            finding = Finding(
                id=new_uuid(),
                scan_id=self.scan_id,
                host_id=host_id,
                plugin_id=data.plugin_id,
                severity=data.severity.value,
                title=data.title,
                description=data.description,
                evidence=evidence,
                remediation=data.remediation,
                references=json.dumps(data.references) if data.references else None,
                cvss_score=data.cvss_score,
                cvss_vector=data.cvss_vector,
                vpr_score=_compute_vpr(data.cvss_score, cve_ids_list),
                cve_ids=json.dumps(cve_ids_list) if cve_ids_list else None,
                port_number=data.port_number,
                protocol=data.protocol,
                compliance_tags=json.dumps(compliance_tags) if compliance_tags else None,
                mitre_tags=json.dumps(mitre_tags) if mitre_tags else None,
                first_seen_scan_id=self.scan_id,
                last_seen_scan_id=self.scan_id,
                # Carry forward triage state from prior scan if available
                false_positive=prior.false_positive if prior else False,
                remediation_status=prior.remediation_status if prior else "open",
                analyst_notes=prior.analyst_notes if prior else None,
                triaged_by=prior.triaged_by if prior else None,
            )
            self.db.add(finding)

            # Update scan stats (cached to avoid N+1 queries)
            from sqlalchemy import select
            if self._cached_scan is None:
                result = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
                self._cached_scan = result.scalar_one_or_none()
            scan = self._cached_scan
            if scan:
                col = _SEVERITY_COLS.get(data.severity.value, "findings_info")
                setattr(scan, col, getattr(scan, col) + 1)

            await self.db.flush()
            logger.debug("Finding recorded: %s [%s] on host %s", data.title, data.severity, host_id)

            # Fire webhook for critical findings (was dead code — fixed)
            if data.severity.value == "critical" and self._user_id:
                try:
                    from scanr.core.webhook_dispatcher import dispatch
                    await dispatch("finding.critical", {
                        "scan_id": self.scan_id,
                        "finding_id": finding.id,
                        "title": data.title,
                        "plugin_id": data.plugin_id,
                        "severity": data.severity.value,
                    }, self._user_id, self.db)
                except Exception as exc:
                    logger.debug("Webhook dispatch error: %s", exc)

    async def _find_prior_triage(self, host_id: str | None, data: "FindingData") -> "Finding | None":
        """Look up the most recent triaged finding with the same canonical key."""
        if not host_id:
            return None
        try:
            from sqlalchemy import select
            from scanr.models import Host
            result = await self.db.execute(
                select(Finding)
                .join(Host, Finding.host_id == Host.id)
                .where(
                    Finding.plugin_id == data.plugin_id,
                    Finding.port_number == data.port_number,
                    Finding.scan_id != self.scan_id,
                    (Finding.false_positive == True)
                    | (Finding.remediation_status != "open")
                    | (Finding.analyst_notes.isnot(None)),
                )
                .order_by(Finding.created_at.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()
        except Exception:
            return None

    async def _evidence_with_peer_review_command(self, host_id: str | None, data: FindingData) -> str:
        """Prefix evidence with a reproducible command when ScanR can infer one."""
        evidence = data.evidence or ""
        if _PEER_REVIEW_LABEL in evidence:
            return evidence

        command = data.peer_review_command or await self._infer_peer_review_command(host_id, data, evidence)
        if not command:
            return evidence

        if evidence:
            return f"{_PEER_REVIEW_LABEL}\n{command}\n\n{evidence}"
        return f"{_PEER_REVIEW_LABEL}\n{command}"

    async def _infer_peer_review_command(
        self,
        host_id: str | None,
        data: FindingData,
        evidence: str,
    ) -> str | None:
        host_ip = await self._host_ip(host_id)
        port = data.port_number
        plugin_id = data.plugin_id

        url = _first_url(evidence)
        if plugin_id.startswith("web.") or plugin_id == "nuclei.runner":
            if plugin_id == "web.http_methods" and url:
                method = "TRACE" if "TRACE" in evidence else "OPTIONS"
                return _curl_command(url, method=method)
            if plugin_id == "web.default_creds_web" and url:
                creds = _creds_from_text(evidence) or _creds_from_title(data.title)
                if creds:
                    username, password = creds
                    return (
                        f"curl -k -i --max-time 15 -X POST "
                        f"-u {_q(f'{username}:{password}')} "
                        f"-d {_q(f'username={username}')} -d {_q(f'password={password}')} "
                        f"-d {_q(f'user={username}')} -d {_q(f'pass={password}')} "
                        f"{_q(url)}"
                    )
            if url:
                method = "POST" if evidence.lstrip().startswith("POST ") else "GET"
                return _curl_command(url, method=method)
            if host_ip and port:
                return _curl_command(_default_url(host_ip, port), method="GET")

        if plugin_id == "network.open_ports_info" and host_ip:
            ports = _ports_from_open_ports_evidence(evidence)
            if ports:
                return f"nmap -Pn -sV -p {_q(','.join(ports))} {_q(host_ip)}"
            return f"nmap -Pn -sV {_q(host_ip)}"

        if plugin_id == "network.subdomain_enum":
            names = _subdomains_from_evidence(evidence)
            if names:
                quoted = " ".join(_q(name) for name in names[:50])
                return f"for host in {quoted}; do printf '%s ' \"$host\"; dig +short \"$host\"; done"

        if plugin_id.startswith("ssh.") and host_ip and port:
            if plugin_id == "ssh.ssh_default_creds":
                creds = _creds_from_title(data.title)
                if creds:
                    username, password = creds
                    return (
                        f"sshpass -p {_q(password)} ssh "
                        f"-o StrictHostKeyChecking=no "
                        f"-o UserKnownHostsFile=/dev/null "
                        f"-o PreferredAuthentications=password "
                        f"-o PubkeyAuthentication=no "
                        f"-p {_q(str(port))} {_q(f'{username}@{host_ip}')} {_q('id')}"
                    )
            if plugin_id == "ssh.ssh_algos":
                return f"nmap -Pn -p {_q(str(port))} --script ssh2-enum-algos {_q(host_ip)}"
            return f"nmap -Pn -sV -p {_q(str(port))} {_q(host_ip)}"

        if plugin_id.startswith("ssl_tls.") and host_ip and port:
            return f"nmap -Pn -p {_q(str(port))} --script ssl-enum-ciphers {_q(host_ip)}"

        if plugin_id == "services.nfs_shares" and host_ip:
            return f"showmount -e {_q(host_ip)}"

        if plugin_id.startswith("services.") and host_ip and port:
            return f"nmap -Pn -sV -p {_q(str(port))} {_q(host_ip)}"

        return None

    async def _host_ip(self, host_id: str | None) -> str | None:
        if not host_id:
            return None
        if host_id in self._host_ip_cache:
            return self._host_ip_cache[host_id]
        try:
            from sqlalchemy import select
            result = await self.db.execute(select(Host.ip).where(Host.id == host_id))
            host_ip = result.scalar_one_or_none()
        except Exception:
            host_ip = None
        self._host_ip_cache[host_id] = host_ip
        return host_ip


def _q(value: str) -> str:
    return shlex.quote(str(value))


def _first_url(text: str) -> str | None:
    match = _URL_RE.search(text or "")
    if not match:
        return None
    return match.group(0).rstrip(".,;]")


def _curl_command(url: str, method: str = "GET") -> str:
    method_part = "" if method == "GET" else f"-X {_q(method)} "
    return f"curl -k -i --max-time 15 {method_part}{_q(url)}"


def _default_url(host_ip: str, port: int) -> str:
    scheme = "https" if port in {443, 8443, 9443, 9444, 10443} else "http"
    return f"{scheme}://{host_ip}:{port}/"


def _creds_from_title(title: str) -> tuple[str, str] | None:
    marker = ": "
    if marker not in title:
        return None
    tail = title.split(marker, 1)[1]
    if ":" not in tail:
        return None
    username, password = tail.split(":", 1)
    return username, "" if password == "(empty)" else password


def _creds_from_text(text: str) -> tuple[str, str] | None:
    marker = " with "
    if marker not in text:
        return None
    tail = text.rsplit(marker, 1)[1].strip()
    if ":" not in tail:
        return None
    username, password = tail.split(":", 1)
    return username.strip(), password.strip()


def _ports_from_open_ports_evidence(evidence: str) -> list[str]:
    ports: list[str] = []
    for line in (evidence or "").splitlines():
        match = re.match(r"\s*(\d+)/(tcp|udp)\b", line)
        if match:
            ports.append(match.group(1))
    return ports


def _subdomains_from_evidence(evidence: str) -> list[str]:
    names: list[str] = []
    for line in (evidence or "").splitlines():
        match = re.match(r"\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[→-]", line)
        if match:
            names.append(match.group(1))
    return names
