import io
import zipfile

import pytest
from docx import Document
from docxtpl import DocxTemplate

from scanr.reporting import docx_renderer as d


def _docx_with(document_xml: str, extra: dict[str, bytes] | None = None) -> bytes:
    base = io.BytesIO(d.build_default_template())
    out = io.BytesIO()
    with zipfile.ZipFile(base) as src, zipfile.ZipFile(out, "w") as dst:
        for item in src.infolist():
            data = document_xml.encode() if item.filename == "word/document.xml" else src.read(item.filename)
            dst.writestr(item, data)
        for name, data in (extra or {}).items():
            dst.writestr(name, data)
    return out.getvalue()


def _replace_body(text: str) -> bytes:
    original = zipfile.ZipFile(io.BytesIO(d.build_default_template())).read("word/document.xml").decode()
    start = original.index("<w:body>") + len("<w:body>")
    end = original.index("<w:sectPr")
    paragraph = f'<w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>'
    return _docx_with(original[:start] + paragraph + original[end:])


def test_default_template_validates_and_renders_tricky_text():
    assert d.validate_template(d.build_default_template()) == []
    tpl = DocxTemplate(io.BytesIO(d.build_default_template()))
    ctx = d.sample_context(tpl)
    ctx["findings"][0]["title"] = "XSS in <search> & co"
    tpl.render(ctx, jinja_env=d._sandbox(), autoescape=True)
    out = io.BytesIO()
    tpl.save(out)
    text = "\n".join(p.text for p in Document(out).paragraphs)
    assert "F-01  XSS in <search> & co" in text and "{{" not in text and "{%" not in text


def test_sandbox_blocks_code_execution_in_uploaded_templates():
    evil = _replace_body("{{ ''.__class__.__mro__[1].__subclasses__() }}")
    with pytest.raises(d.TemplateError, match="cannot be rendered"):
        d.validate_template(evil)


def test_syntax_errors_are_reported():
    with pytest.raises(d.TemplateError, match="cannot be rendered"):
        d.validate_template(_replace_body("{% for x in %}"))


def test_unknown_variables_are_listed_not_fatal():
    assert d.validate_template(_replace_body("{{ customer_logo }} {{ report.title }}")) == ["customer_logo"]


@pytest.mark.parametrize("data,message", [
    (b"not a zip", "Not a .docx"),
    (b"PK\x05\x06" + b"\x00" * 18, "Not a .docx|Not a Word"),
])
def test_rejects_non_docx(data, message):
    with pytest.raises(d.TemplateError, match=message):
        d.check_template_bytes(data)


def test_rejects_entities_and_macros():
    original = zipfile.ZipFile(io.BytesIO(d.build_default_template())).read("word/document.xml").decode()
    doctype = original.replace("<w:document", '<!DOCTYPE x [<!ENTITY a "aaaa">]><w:document', 1)
    with pytest.raises(d.TemplateError, match="DTD or entities"):
        d.check_template_bytes(_docx_with(doctype))
    with pytest.raises(d.TemplateError, match="Macro"):
        d.check_template_bytes(_docx_with(original, {"word/vbaProject.bin": b"x"}))


def test_rejects_zip_bombs(monkeypatch):
    monkeypatch.setattr(d, "_MAX_UNCOMPRESSED", 1000)
    with pytest.raises(d.TemplateError, match="expands"):
        d.check_template_bytes(d.build_default_template())


class F:
    def __init__(self, **kw):
        defaults = dict(id="f", plugin_id="p", title="T", severity="high", priority_score=50.0, cvss_score=None,
                        cvss_vector=None, description="desc", impact=None, remediation=None, evidence=None,
                        references=None, cve_ids=None, validated=False, is_kev=False, host_ip="10.0.0.1", port_number=None)
        self.__dict__.update({**defaults, **kw})


def test_grouping_merges_hosts_orders_by_priority_and_hides_info():
    findings = [
        F(id="a", title="SMB signing", severity="medium", priority_score=33, host_ip="10.0.0.2", port_number=445, evidence="ev2"),
        F(id="b", title="SMB signing", severity="medium", priority_score=35, host_ip="10.0.0.1", port_number=445, evidence="ev1",
          references='["https://x"]'),
        F(id="c", title="Log4Shell", severity="critical", priority_score=90, is_kev=True, cve_ids='["CVE-2021-44228"]'),
        F(id="d", title="Open ports", severity="info", priority_score=5),
    ]
    entries = d.group_findings(findings, {}, include_info=False)
    assert [e["title"] for e in entries] == ["Log4Shell", "SMB signing"]
    assert [e["ref"] for e in entries] == ["F-01", "F-02"]
    smb = entries[1]
    assert smb["affected"] == ["10.0.0.1:445", "10.0.0.2:445"] and smb["priority"] == 35
    assert smb["evidence"].startswith("[10.0.0.1:445]\nev1") and "[10.0.0.2:445]\nev2" in smb["evidence"]
    assert entries[0]["kev"] and entries[0]["cve_ids"] == ["CVE-2021-44228"]
    assert len(d.group_findings(findings, {}, include_info=True)) == 3
