"""Parse other tools' output into one normalised shape.

Supported: Nessus (.nessus v2), Nmap XML (-oX), Nuclei (JSON / JSON lines),
Burp Suite issues XML and OWASP ZAP JSON. XML goes through safe_xml, which
refuses entity declarations (billion-laughs) and external entities.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse
from xml.etree.ElementTree import Element

from scanr.utils import safe_xml

FORMATS = ("nessus", "nmap", "nuclei", "burp", "zap")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class ImportFormatError(ValueError):
    pass


@dataclass
class ImportedPort:
    number: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class ImportedHost:
    address: str  # IP when known, otherwise hostname
    hostname: str | None = None
    os_name: str | None = None
    ports: dict[tuple[int, str], ImportedPort] = field(default_factory=dict)

    def add_port(self, port: ImportedPort) -> None:
        existing = self.ports.get((port.number, port.protocol))
        if existing is None:
            self.ports[(port.number, port.protocol)] = port
        else:
            existing.service = existing.service or port.service
            existing.product = existing.product or port.product
            existing.version = existing.version or port.version


@dataclass
class ImportedFinding:
    address: str | None
    plugin_id: str
    severity: str
    title: str
    description: str | None = None
    remediation: str | None = None
    evidence: str | None = None
    port: int | None = None
    protocol: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class ImportResult:
    source: str
    hosts: dict[str, ImportedHost] = field(default_factory=dict)
    findings: list[ImportedFinding] = field(default_factory=list)

    def host(self, address: str, hostname: str | None = None) -> ImportedHost:
        host = self.hosts.get(address)
        if host is None:
            host = self.hosts[address] = ImportedHost(address=address, hostname=hostname)
        elif hostname and not host.hostname:
            host.hostname = hostname
        return host


def _text(el: Element | None, path: str) -> str | None:
    if el is None:
        return None
    value = el.findtext(path)
    return value.strip() if value and value.strip() else None


def _float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _cves(*values: object) -> list[str]:
    found: list[str] = []
    for value in values:
        for match in _CVE.findall(str(value or "")):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def _severity(value: str | int | None, default: str = "medium") -> str:
    v = str(value if value is not None else "").strip().lower()
    mapping = {
        "4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info",
        "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
        "low": "low", "info": "info", "informational": "info", "information": "info",
        "none": "info", "unknown": "info",
    }
    return mapping.get(v, default)


def detect(report: str) -> str:
    head = report.lstrip()[:4000]
    if head.startswith("<"):
        if "<NessusClientData_v2" in head:
            return "nessus"
        if "<nmaprun" in head:
            return "nmap"
        if "<issues" in head:
            return "burp"
        raise ImportFormatError("Unrecognised XML: expected a .nessus, Nmap -oX or Burp issues export")
    if head.startswith("{") and '"site"' in head and ("@generated" in head or "@version" in head):
        return "zap"
    if head.startswith("{") or head.startswith("["):
        if '"template-id"' in head or '"templateID"' in head:
            return "nuclei"
        if '"site"' in head:
            return "zap"
    raise ImportFormatError("Unrecognised report: expected Nessus, Nmap XML, Nuclei JSON, Burp XML or ZAP JSON")


def _xml(report: str) -> Element:
    try:
        return safe_xml.fromstring(report)
    except safe_xml.XmlSecurityError:
        raise
    except Exception as exc:
        raise ImportFormatError(f"Invalid XML: {exc}") from exc


def parse_nessus(report: str) -> ImportResult:
    root = _xml(report)
    result = ImportResult(source="nessus")
    for report_host in root.iter("ReportHost"):
        props = {t.get("name"): (t.text or "").strip() for t in report_host.iter("tag")}
        address = props.get("host-ip") or report_host.get("name") or ""
        if not address:
            continue
        host = result.host(address, props.get("host-fqdn") or props.get("hostname"))
        host.os_name = host.os_name or props.get("operating-system")
        for item in report_host.iter("ReportItem"):
            port = int(item.get("port") or 0)
            protocol = (item.get("protocol") or "tcp").lower()
            service = item.get("svc_name")
            if port:
                host.add_port(ImportedPort(port, protocol, service if service not in ("general", "unknown") else None))
            severity = _severity(item.get("severity"), "info")
            cvss = _float(_text(item, "cvss3_base_score")) or _float(_text(item, "cvss_base_score"))
            vector = _text(item, "cvss3_vector") or _text(item, "cvss_vector")
            result.findings.append(ImportedFinding(
                address=address,
                plugin_id=f"nessus.{item.get('pluginID') or 'unknown'}",
                severity=severity,
                title=(item.get("pluginName") or _text(item, "plugin_name") or "Nessus finding")[:512],
                description=_text(item, "description") or _text(item, "synopsis"),
                remediation=_text(item, "solution"),
                evidence=_text(item, "plugin_output"),
                port=port or None,
                protocol=protocol if port else None,
                cvss_score=cvss,
                cvss_vector=vector,
                cve_ids=_cves(*[c.text for c in item.findall("cve")]),
                references=[r for r in (_text(item, "see_also") or "").split() if r.startswith("http")],
            ))
    return result


def parse_nmap(report: str) -> ImportResult:
    root = _xml(report)
    result = ImportResult(source="nmap")
    for host_el in root.iter("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a.get("addr") for a in host_el.iter("address")}
        address = addresses.get("ipv4") or addresses.get("ipv6")
        if not address:
            continue
        names = [h.get("name") for h in host_el.iter("hostname") if h.get("name")]
        host = result.host(address, names[0] if names else None)
        osmatch = host_el.find("os/osmatch")
        if osmatch is not None:
            host.os_name = osmatch.get("name")
        open_ports = []
        for port_el in host_el.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_el.find("service")
            port = ImportedPort(
                number=int(port_el.get("portid") or 0),
                protocol=(port_el.get("protocol") or "tcp").lower(),
                service=svc.get("name") if svc is not None else None,
                product=svc.get("product") if svc is not None else None,
                version=svc.get("version") if svc is not None else None,
            )
            host.add_port(port)
            open_ports.append(port)
            # NSE vulnerability scripts (vulners, smb-vuln-*, ssl-*) say VULNERABLE.
            for script in port_el.iter("script"):
                output = script.get("output") or ""
                if "VULNERABLE" not in output.upper() or "NOT VULNERABLE" in output.upper():
                    continue
                cves = _cves(output, script.get("id"))
                result.findings.append(ImportedFinding(
                    address=address, plugin_id=f"nmap.{script.get('id')}", severity="high",
                    title=f"Nmap {script.get('id')}: vulnerable", description=output[:4000],
                    evidence=output[:8000], port=port.number, protocol=port.protocol, cve_ids=cves,
                ))
        if open_ports:
            listing = ", ".join(
                f"{p.number}/{p.protocol} {p.service or ''} {(p.product or '')} {(p.version or '')}".strip()
                for p in open_ports
            )
            result.findings.append(ImportedFinding(
                address=address, plugin_id="nmap.open_ports", severity="info",
                title=f"Open ports: {len(open_ports)} port(s) discovered",
                description="Open ports reported by an imported Nmap scan.", evidence=listing,
            ))
    return result


def _json_records(report: str) -> list[dict]:
    text = report.strip()
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ImportFormatError(f"Invalid JSON on line {number}") from exc
    return [r for r in records if isinstance(r, dict)]


def parse_nuclei(report: str) -> ImportResult:
    result = ImportResult(source="nuclei")
    for record in _json_records(report):
        info = record.get("info") or {}
        classification = info.get("classification") or {}
        target = record.get("matched-at") or record.get("host") or ""
        parsed = urlparse(target if "://" in target else f"//{target}")
        hostname = parsed.hostname
        address = record.get("ip") or hostname
        if not address:
            continue
        port_text = record.get("port") or parsed.port
        try:
            port = int(port_text) if port_text else ({"https": 443, "http": 80}.get(parsed.scheme or ""))
        except (TypeError, ValueError):
            port = None
        host = result.host(address, hostname if hostname != address else None)
        if port:
            host.add_port(ImportedPort(port, "tcp", parsed.scheme or None))
        cve_field = classification.get("cve-id") or []
        refs = info.get("reference") or []
        extracted = record.get("extracted-results") or []
        evidence = "\n".join(filter(None, [
            f"Matched at: {target}" if target else None,
            f"Matcher: {record.get('matcher-name')}" if record.get("matcher-name") else None,
            "Extracted: " + ", ".join(map(str, extracted)) if extracted else None,
            f"Reproduce: {record.get('curl-command')}" if record.get("curl-command") else None,
        ]))
        result.findings.append(ImportedFinding(
            address=address,
            plugin_id=f"nuclei.{record.get('template-id') or record.get('templateID') or 'unknown'}",
            severity=_severity(info.get("severity"), "info"),
            title=(info.get("name") or record.get("template-id") or "Nuclei finding")[:512],
            description=info.get("description"),
            remediation=info.get("remediation"),
            evidence=evidence or None,
            port=port,
            protocol="tcp" if port else None,
            cvss_score=_float(str(classification.get("cvss-score") or "")),
            cvss_vector=classification.get("cvss-metrics"),
            cve_ids=_cves(*(cve_field if isinstance(cve_field, list) else [cve_field])),
            references=[r for r in (refs if isinstance(refs, list) else [refs]) if isinstance(r, str)],
        ))
    return result


def parse_burp(report: str) -> ImportResult:
    root = _xml(report)
    result = ImportResult(source="burp")
    for item in root.iter("issue"):
        host_el = item.find("host")
        url = (host_el.text or "").strip() if host_el is not None else ""
        parsed = urlparse(url)
        address = (host_el.get("ip") if host_el is not None else None) or parsed.hostname
        port = parsed.port or {"https": 443, "http": 80}.get(parsed.scheme or "")
        if address:
            host = result.host(address, parsed.hostname if parsed.hostname != address else None)
            if port:
                host.add_port(ImportedPort(port, "tcp", parsed.scheme or None))
        severity = _severity(_text(item, "severity"), "medium")
        evidence = []
        for label, tag in (("REQUEST", "request"), ("RESPONSE", "response")):
            for el in item.iter(tag):
                body = _burp_body(el)
                if body:
                    evidence.append(f"=== {label} ===\n{body[:20000]}")
        path = _text(item, "path") or ""
        result.findings.append(ImportedFinding(
            address=address,
            plugin_id=f"burp.{_text(item, 'type') or 'issue'}",
            severity=severity,
            title=(_text(item, "name") or "Burp issue")[:512],
            description="\n\n".join(filter(None, [_text(item, "issueBackground"), _text(item, "issueDetail"),
                                                  f"Location: {url}{path}" if url else None])) or None,
            remediation=_text(item, "remediationBackground") or _text(item, "remediationDetail"),
            evidence="\n\n".join(evidence) or None,
            port=port or None,
            protocol="tcp" if port else None,
            cve_ids=_cves(_text(item, "issueDetail"), _text(item, "references")),
        ))
    return result


def _burp_body(el: Element) -> str | None:
    text = (el.text or "").strip()
    if not text:
        return None
    if el.get("base64") == "true":
        import base64
        import binascii

        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return None
    return text


def parse_zap(report: str) -> ImportResult:
    result = ImportResult(source="zap")
    for record in _json_records(report):
        for site in record.get("site") or []:
            address = site.get("@host") or urlparse(site.get("@name") or "").hostname
            if not address:
                continue
            try:
                port = int(site.get("@port") or 0) or None
            except ValueError:
                port = None
            host = result.host(address)
            scheme = "https" if str(site.get("@ssl")).lower() == "true" else "http"
            if port:
                host.add_port(ImportedPort(port, "tcp", scheme))
            for alert in site.get("alerts") or []:
                instances = alert.get("instances") or []
                evidence = "\n".join(
                    f"{i.get('method', '')} {i.get('uri', '')}" + (f"\n  evidence: {i['evidence']}" if i.get("evidence") else "")
                    for i in instances[:20]
                )
                result.findings.append(ImportedFinding(
                    address=address,
                    plugin_id=f"zap.{alert.get('pluginid') or 'alert'}",
                    severity=_severity({"3": "high", "2": "medium", "1": "low", "0": "info"}.get(str(alert.get("riskcode")), "medium")),
                    title=(alert.get("alert") or alert.get("name") or "ZAP alert")[:512],
                    description=_strip_html(alert.get("desc")),
                    remediation=_strip_html(alert.get("solution")),
                    evidence=evidence or None,
                    port=port,
                    protocol="tcp" if port else None,
                    cve_ids=_cves(alert.get("reference"), alert.get("otherinfo")),
                    references=re.findall(r"https?://[^\s<]+", alert.get("reference") or ""),
                ))
    return result


def _strip_html(value: str | None) -> str | None:
    if not value:
        return None
    return re.sub(r"<[^>]+>", "", value).strip() or None


PARSERS = {"nessus": parse_nessus, "nmap": parse_nmap, "nuclei": parse_nuclei, "burp": parse_burp, "zap": parse_zap}


def parse(report: str, fmt: str = "auto") -> ImportResult:
    fmt = detect(report) if fmt == "auto" else fmt
    if fmt not in PARSERS:
        raise ImportFormatError(f"Unknown format {fmt!r}")
    result = PARSERS[fmt](report)
    if not result.hosts and not result.findings:
        raise ImportFormatError(f"No hosts or findings found in the {fmt} report")
    return result
