from pathlib import Path

import pytest

from scanr.importers.parsers import ImportFormatError, detect, parse
from scanr.utils import safe_xml

FIXTURES = Path(__file__).parents[1] / "fixtures" / "imports"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.mark.parametrize("name,fmt", [
    ("sample.nessus", "nessus"), ("sample-nmap.xml", "nmap"), ("sample-nuclei.jsonl", "nuclei"),
    ("sample-burp.xml", "burp"), ("sample-zap.json", "zap"),
])
def test_detects_format(name, fmt):
    assert detect(load(name)) == fmt


def test_nessus():
    result = parse(load("sample.nessus"))
    host = result.hosts["10.10.1.5"]
    assert host.hostname == "fs01.corp.example" and host.os_name.startswith("Microsoft Windows")
    assert set(host.ports) == {(445, "tcp"), (3389, "tcp")}
    eternal = next(f for f in result.findings if f.plugin_id == "nessus.97833")
    assert eternal.severity == "critical" and eternal.port == 445
    assert eternal.cvss_score == 8.1 and eternal.cvss_vector.startswith("CVSS:3.0/")
    assert eternal.cve_ids == ["CVE-2017-0143", "CVE-2017-0144"]
    assert eternal.references[0].startswith("https://docs.microsoft.com")
    assert eternal.evidence.startswith("Sent:") and eternal.remediation
    rdp = next(f for f in result.findings if f.plugin_id == "nessus.18405")
    assert rdp.severity == "medium" and rdp.cvss_score == 5.1
    info = next(f for f in result.findings if f.plugin_id == "nessus.19506")
    assert info.severity == "info" and info.port is None


def test_nmap():
    result = parse(load("sample-nmap.xml"))
    assert set(result.hosts) == {"10.10.1.5"}  # the down host is ignored
    host = result.hosts["10.10.1.5"]
    assert host.hostname == "fs01.corp.example" and host.os_name == "Linux 5.4"
    assert set(host.ports) == {(22, "tcp"), (445, "tcp")}  # closed 8080 ignored
    assert host.ports[(22, "tcp")].product == "OpenSSH" and host.ports[(22, "tcp")].version == "8.2p1"
    vuln = next(f for f in result.findings if f.plugin_id == "nmap.smb-vuln-ms17-010")
    assert vuln.severity == "high" and vuln.cve_ids == ["CVE-2017-0143"] and vuln.port == 445
    ports = next(f for f in result.findings if f.plugin_id == "nmap.open_ports")
    assert "22/tcp ssh OpenSSH 8.2p1" in ports.evidence


def test_nuclei():
    result = parse(load("sample-nuclei.jsonl"))
    host = result.hosts["10.10.1.20"]
    assert host.hostname == "app.corp.example" and (8443, "tcp") in host.ports
    log4j = result.findings[0]
    assert log4j.plugin_id == "nuclei.CVE-2021-44228" and log4j.severity == "critical"
    assert log4j.cve_ids == ["CVE-2021-44228"] and log4j.cvss_score == 10.0 and log4j.port == 8443
    assert "Reproduce: curl" in log4j.evidence and log4j.remediation.startswith("Upgrade")
    assert result.findings[1].severity == "info" and "nginx" in result.findings[1].evidence


def test_nuclei_json_array_also_works():
    import json
    lines = [json.loads(line) for line in load("sample-nuclei.jsonl").splitlines()]
    assert len(parse(json.dumps(lines), "nuclei").findings) == 2


def test_burp_decodes_base64_request():
    result = parse(load("sample-burp.xml"))
    assert "203.0.113.40" in result.hosts and (443, "tcp") in result.hosts["203.0.113.40"].ports
    finding = result.findings[0]
    assert finding.title == "Cross-site scripting (reflected)" and finding.severity == "high"
    assert "GET /search?q=%3Cscript%3E" in finding.evidence
    assert "Location: https://shop.example.com/search" in finding.description


def test_zap():
    result = parse(load("sample-zap.json"))
    finding = result.findings[0]
    assert finding.plugin_id == "zap.10038" and finding.severity == "medium" and finding.port == 443
    assert finding.description == "CSP is an added layer of security."
    assert finding.references == ["https://developer.mozilla.org/docs/Web/HTTP/CSP"]


def test_rejects_unknown_and_hostile_input():
    with pytest.raises(ImportFormatError):
        parse("hello world")
    with pytest.raises(ImportFormatError):
        parse("<other/>")
    bomb = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><nmaprun>&b;</nmaprun>'
    with pytest.raises(safe_xml.XmlSecurityError):
        parse(bomb, "nmap")
    with pytest.raises(ImportFormatError, match="No hosts or findings"):
        parse('<?xml version="1.0"?><nmaprun></nmaprun>', "nmap")
