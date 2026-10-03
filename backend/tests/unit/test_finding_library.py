import json

from scanr.core import finding_library as lib
from scanr.models import Finding
from scanr.models.finding_template import FindingTemplate


def tpl(**kw):
    defaults = dict(id="t1", title="T", severity="medium", description="Library text", plugin_ids=json.dumps(["web.x"]))
    return FindingTemplate(**{**defaults, **kw})


def test_matching_prefers_title_specific_entries_and_refuses_ambiguity():
    general = tpl(id="g", title="general")
    specific = tpl(id="s", title="specific", title_match="CSP")
    assert lib.find_match([general, specific], "web.x", "Missing CSP header").id == "s"
    assert lib.find_match([general, specific], "web.x", "Something else").id == "g"
    assert lib.find_match([general, specific], "web.other", "Missing CSP") is None
    twin = tpl(id="g2", title="general 2")
    assert lib.find_match([general, twin], "web.x", "anything") is None


def test_apply_keeps_title_and_scanner_detail():
    finding = Finding(title="Scanner title", severity="low", description="Header X missing on /login",
                      evidence="HTTP/1.1 200", references=json.dumps(["https://a"]), plugin_id="web.x")
    template = tpl(severity="high", impact="Bad things", remediation="Fix it", cvss_score=6.5, cvss_vector="CVSS:3.1/x",
                   references=json.dumps(["https://a", "https://b"]), cve_ids=json.dumps(["CVE-2020-1"]))
    lib.apply(finding, template)
    assert finding.title == "Scanner title" and finding.severity == "low"
    assert finding.description == "Library text" and finding.impact == "Bad things" and finding.remediation == "Fix it"
    assert finding.evidence.startswith("Scanner details:\nHeader X missing on /login\n\nHTTP/1.1 200")
    assert json.loads(finding.references) == ["https://a", "https://b"]
    assert json.loads(finding.cve_ids) == ["CVE-2020-1"]
    assert finding.cvss_score == 6.5 and finding.template_id == "t1"
    lib.apply(finding, template)  # re-applying does not stack scanner details
    assert finding.evidence.count("Scanner details:") == 1
    lib.apply(finding, template, use_severity=True)
    assert finding.severity == "high"


def test_starter_library_is_well_formed():
    titles = [e["title"] for e in lib.STARTER]
    assert len(titles) == len(set(titles)) >= 15
    for entry in lib.STARTER:
        assert entry["severity"] in {"critical", "high", "medium", "low", "info"}
        assert entry["description"] and entry["impact"] and entry["remediation"] and entry["plugin_ids"]
