"""Word (.docx) reports from a template with placeholders (docxtpl / Jinja).

The default template is generated in code (build_default_template) and can be
downloaded, branded and uploaded back as a custom template. Templates are
rendered in Jinja's SandboxedEnvironment: a template is a document someone
uploaded, and an ordinary Environment would let it run Python in the worker.

Placeholders available to templates are documented in PLACEHOLDERS.
"""
from __future__ import annotations

import io
import json
import logging
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2.sandbox import SandboxedEnvironment

from scanr.config import get_settings

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {"critical": "B0124B", "high": "D9381E", "medium": "C77C02", "low": "1A7F8E", "info": "6B7280"}
_MAX_TEMPLATE_BYTES = 10 * 1024 * 1024
_MAX_UNCOMPRESSED = 100 * 1024 * 1024

PLACEHOLDERS = {
    "report.title / client / author / classification / date": "From the report options",
    "scan.name / started / finished / targets (list) / hosts_up / hosts_total": "The scan",
    "summary.text": "Executive summary paragraph",
    "summary.counts.critical … .info, summary.total, summary.fix_now, summary.kev": "Totals",
    "findings (list)": "One entry per issue, highest priority first",
    "f.ref / title / severity / severity_rt (coloured) / priority / cvss_score / cvss_vector": "Per finding",
    "f.description / impact / remediation / evidence": "Per finding text",
    "f.affected (list) / affected_text / references (list) / cve_ids (list) / validated": "Per finding",
    "f.images (list of {image, caption})": "Evidence screenshots",
    "hosts (list of {ip, hostname, os, ports})": "Appendix data",
    "testing.window / testing.verified / testing.activity (list of {time, event, source_ip, actor})": "When testing took place",
}


class TemplateError(ValueError):
    pass


# ── Template validation ─────────────────────────────────────────────────────

def check_template_bytes(data: bytes) -> None:
    """Reject anything that is not a sane .docx before parsing it."""
    if len(data) > _MAX_TEMPLATE_BYTES:
        raise TemplateError("Template is larger than 10 MB")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise TemplateError("Not a .docx file") from exc
    with archive:
        names = archive.namelist()
        if "word/document.xml" not in names:
            raise TemplateError("Not a Word document (word/document.xml missing)")
        if sum(i.file_size for i in archive.infolist()) > _MAX_UNCOMPRESSED:
            raise TemplateError("Template expands to more than 100 MB")
        for name in names:
            if name.endswith((".xml", ".rels")):
                head = archive.read(name)[:4096]
                if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
                    raise TemplateError(f"{name} declares a DTD or entities, which is not allowed")
        if any(n.lower().endswith(".docm") or "vbaProject" in n for n in names):
            raise TemplateError("Macro-enabled documents are not accepted")


def validate_template(data: bytes) -> list[str]:
    """Render the template against sample data. Returns undeclared variable names
    it uses (for a warning), raises TemplateError if it cannot render."""
    check_template_bytes(data)
    from docxtpl import DocxTemplate

    try:
        tpl = DocxTemplate(io.BytesIO(data))
        unknown = sorted(tpl.get_undeclared_template_variables(_sandbox()) - set(sample_context(tpl)))
        tpl.render(sample_context(tpl), jinja_env=_sandbox(), autoescape=True)
        tpl.save(io.BytesIO())
    except TemplateError:
        raise
    except Exception as exc:  # Jinja syntax errors, sandbox violations, bad XML
        raise TemplateError(f"Template cannot be rendered: {exc}") from exc
    return unknown


def _sandbox() -> SandboxedEnvironment:
    return SandboxedEnvironment(autoescape=False)


# ── Context ─────────────────────────────────────────────────────────────────

def _list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%d %B %Y") if dt else ""


def _summary_text(scan, findings: list[dict], counts: dict[str, int]) -> str:
    serious = counts["critical"] + counts["high"]
    if not findings:
        return (f"Testing of {scan.name} identified no security findings above informational level "
                f"in the agreed scope.")
    top = ", ".join(f["title"] for f in findings[:3])
    parts = [
        f"Testing of {scan.name} identified {len(findings)} distinct security issue{'s' if len(findings) != 1 else ''}"
        f", of which {serious} {'is' if serious == 1 else 'are'} rated critical or high.",
    ]
    fix_now = sum(1 for f in findings if (f["priority"] or 0) >= 80)
    if fix_now:
        parts.append(f"{fix_now} issue{'s' if fix_now != 1 else ''} should be fixed immediately because "
                     "they are severe and known or likely to be exploited.")
    parts.append(f"The most important findings are: {top}.")
    return " ".join(parts)


def group_findings(findings: list, attachments: dict[str, list], include_info: bool) -> list[dict[str, Any]]:
    """Collapse the same issue on several hosts into one report entry."""
    buckets: dict[tuple, list] = defaultdict(list)
    for f in findings:
        if f.severity == "info" and not include_info:
            continue
        buckets[(f.plugin_id, f.title)].append(f)

    entries = []
    for (_plugin, title), group in buckets.items():
        lead = max(group, key=lambda f: (f.priority_score or 0, -SEVERITY_ORDER.get(f.severity, 9)))
        affected = sorted({f"{f.host_ip}{f':{f.port_number}' if f.port_number else ''}" for f in group if getattr(f, "host_ip", None)})
        evidence_blocks = []
        for f in sorted(group, key=lambda f: (getattr(f, "host_ip", "") or "", f.port_number or 0)):
            if f.evidence:
                label = f"{f.host_ip}{f':{f.port_number}' if f.port_number else ''}" if getattr(f, "host_ip", None) else ""
                evidence_blocks.append((f"[{label}]\n" if label and len(group) > 1 else "") + f.evidence.strip())
        refs: list[str] = []
        cves: list[str] = []
        for f in group:
            refs += [r for r in _list(f.references) if r not in refs]
            cves += [c for c in _list(f.cve_ids) if c not in cves]
        entries.append({
            "title": title,
            "severity": lead.severity,
            "priority": round(lead.priority_score) if lead.priority_score is not None else None,
            "cvss_score": lead.cvss_score,
            "cvss_vector": lead.cvss_vector or "",
            "description": lead.description or "",
            "impact": lead.impact or "",
            "remediation": lead.remediation or "",
            "evidence": "\n\n".join(evidence_blocks)[:20000],
            "affected": affected,
            "affected_text": ", ".join(affected) if affected else "—",
            "references": refs,
            "cve_ids": cves,
            "validated": any(f.validated for f in group),
            "kev": any(f.is_kev for f in group),
            "attachments": [a for f in group for a in attachments.get(f.id, [])],
        })
    entries.sort(key=lambda e: (-(e["priority"] or 0), SEVERITY_ORDER.get(e["severity"], 9), e["title"]))
    for number, entry in enumerate(entries, 1):
        entry["ref"] = f"F-{number:02d}"
    return entries


_EVENT_LABELS = {
    "started": "Scan started", "completed": "Scan completed", "failed": "Scan failed", "cancelled": "Scan cancelled",
    "paused": "Paused by tester", "resumed": "Resumed by tester", "cancel_requested": "Cancelled by tester",
    "window_closed": "Paused: testing window closed", "window_opened": "Resumed: testing window opened",
}


def build_context(tpl, data: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    from docx.shared import Mm
    from docxtpl import InlineImage, Listing, RichText

    from scanr.core import evidence

    scan = data["scan"]
    findings = group_findings(data["findings"], data.get("attachments", {}), bool(options.get("include_info")))
    for f in findings:
        # Listing keeps line breaks (evidence, multi-paragraph text) and escapes XML.
        for key in ("description", "impact", "remediation", "evidence"):
            f[key] = Listing(f[key]) if f[key] else ""
        rt = RichText()
        rt.add(f["severity"].upper(), bold=True, color=SEVERITY_COLORS.get(f["severity"], "000000"))
        f["severity_rt"] = rt
        images = []
        for a in f.pop("attachments"):
            if a.content_type not in evidence.IMAGE_TYPES or a.content_type == "image/webp":
                continue  # Word cannot embed WebP
            path = evidence.path_for(a.finding_id, a.id)
            if path.exists():
                images.append({"image": InlineImage(tpl, str(path), width=Mm(150)), "caption": a.caption or a.filename})
        f["images"] = images
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    targets = [t.value for t in getattr(scan, "targets", [])]
    return {
        "report": {
            "title": options.get("title") or f"Security assessment: {scan.name}",
            "client": options.get("client") or "",
            "author": options.get("author") or "",
            "classification": options.get("classification") or "Confidential",
            "date": _fmt(datetime.now(timezone.utc)),
        },
        "scan": {
            "name": scan.name,
            "started": _fmt(scan.started_at),
            "finished": _fmt(scan.finished_at),
            "targets": targets,
            "hosts_up": scan.hosts_up or 0,
            "hosts_total": scan.hosts_total or 0,
        },
        "summary": {
            "text": _summary_text(scan, findings, counts),
            "counts": counts,
            "total": len(findings),
            "fix_now": sum(1 for f in findings if (f["priority"] or 0) >= 80),
            "kev": sum(1 for f in findings if f["kev"]),
        },
        "findings": findings,
        "testing": {
            "window": data.get("testing_window") or "Not restricted",
            "verified": bool(data.get("activity_verified", True)),
            "activity": [
                {
                    "time": a.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "event": _EVENT_LABELS.get(a.event, a.event),
                    "source_ip": a.source_ip or "",
                    "actor": a.actor or "",
                }
                for a in data.get("activity", [])
            ],
        },
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname or "",
                "os": h.os_name or "",
                "ports": ", ".join(
                    f"{p.number}/{p.protocol}{f' {p.service.name}' if getattr(p, 'service', None) and p.service.name else ''}"
                    for p in sorted(h.ports, key=lambda p: p.number) if p.state == "open"
                ),
            }
            for h in sorted(data["hosts"], key=lambda h: h.ip)
        ],
    }


def sample_context(tpl) -> dict[str, Any]:
    """Representative data, used to validate uploaded templates."""
    from docxtpl import RichText

    rt = RichText()
    rt.add("HIGH", bold=True)
    finding = {
        "ref": "F-01", "title": "Sample finding", "severity": "high", "severity_rt": rt, "priority": 72,
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N", "description": "Description", "impact": "Impact",
        "remediation": "Remediation", "evidence": "Evidence", "affected": ["10.0.0.1:443"],
        "affected_text": "10.0.0.1:443", "references": ["https://example.com"], "cve_ids": ["CVE-2024-0001"],
        "validated": False, "kev": False, "images": [],
    }
    return {
        "report": {"title": "Title", "client": "Client", "author": "Author", "classification": "Confidential", "date": "1 January 2026"},
        "scan": {"name": "Scan", "started": "1 January 2026", "finished": "2 January 2026", "targets": ["10.0.0.0/24"], "hosts_up": 1, "hosts_total": 1},
        "summary": {"text": "Summary", "counts": {s: 1 for s in SEVERITY_ORDER}, "total": 1, "fix_now": 0, "kev": 0},
        "findings": [finding],
        "hosts": [{"ip": "10.0.0.1", "hostname": "host", "os": "Linux", "ports": "443/tcp https"}],
        "testing": {"window": "Mon–Fri 09:00–17:00 (Europe/Amsterdam)", "verified": True,
                    "activity": [{"time": "2026-01-01 09:00:00 UTC", "event": "Scan started", "source_ip": "203.0.113.5", "actor": ""}]},
    }


# ── Rendering ───────────────────────────────────────────────────────────────

def template_dir() -> Path:
    return get_settings().reports_dir / "templates"


def render(data: dict[str, Any], options: dict[str, Any], template_path: Path | None, out_path: Path) -> Path:
    from docxtpl import DocxTemplate

    source: io.BytesIO | str
    if template_path is not None:
        raw = template_path.read_bytes()
        check_template_bytes(raw)
        source = io.BytesIO(raw)
    else:
        source = io.BytesIO(build_default_template())
    tpl = DocxTemplate(source)
    tpl.render(build_context(tpl, data, options), jinja_env=_sandbox(), autoescape=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tpl.save(str(out_path))
    return out_path


# ── Default template ────────────────────────────────────────────────────────

def build_default_template() -> bytes:
    """A clean, editable report template using every placeholder."""
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_BREAK
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    doc = Document()
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    for level, size in ((1, 16), (2, 13), (3, 11.5)):
        style = doc.styles[f"Heading {level}"]
        style.font.name = "Calibri"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor(0x1F, 0x29, 0x37)

    from docx.shared import Cm

    def widths(table, *cm: float) -> None:
        # Word reads cell widths, LibreOffice the table grid: set both.
        table.autofit = False
        for column, width in zip(table.columns, cm):
            column.width = Cm(width)
        for row in table.rows:
            for cell, width in zip(row.cells, cm):
                cell.width = Cm(width)

    def shade(cell, hex_color: str) -> None:
        props = cell._tc.get_or_add_tcPr()
        fill = OxmlElement("w:shd")
        fill.set(qn("w:val"), "clear")
        fill.set(qn("w:color"), "auto")
        fill.set(qn("w:fill"), hex_color)
        props.append(fill)

    def para(text: str = "", bold: bool = False, size: float | None = None, color: str | None = None, style: str | None = None):
        p = doc.add_paragraph(style=style)
        if text:
            run = p.add_run(text)
            run.bold = bold
            if size:
                run.font.size = Pt(size)
            if color:
                run.font.color.rgb = RGBColor.from_string(color)
        return p

    # Cover
    for _ in range(6):
        para()
    para("{{ report.classification }}", bold=True, size=9, color="B0124B")
    para("{{ report.title }}", bold=True, size=26, color="111827")
    para("{{ report.client }}", size=14, color="374151")
    para()
    para("Date: {{ report.date }}", size=10.5, color="374151")
    para("{% if report.author %}Prepared by: {{ report.author }}{% endif %}", size=10.5, color="374151")
    para("Testing period: {{ scan.started }}{% if scan.finished %} – {{ scan.finished }}{% endif %}", size=10.5, color="374151")
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # 1. Executive summary
    doc.add_heading("1. Executive summary", level=1)
    para("{{ summary.text }}")
    table = doc.add_table(rows=2, cols=5)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, sev in enumerate(("critical", "high", "medium", "low", "info")):
        head = table.rows[0].cells[i]
        head.text = sev.capitalize()
        head.paragraphs[0].runs[0].bold = True
        head.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        shade(head, SEVERITY_COLORS[sev])
        table.rows[1].cells[i].text = "{{ summary.counts." + sev + " }}"
    para()
    para("{% if summary.fix_now %}{{ summary.fix_now }} issue(s) need immediate attention (fix-first priority 80 or higher){% if summary.kev %}, including {{ summary.kev }} with known exploitation in the wild (CISA KEV){% endif %}.{% endif %}")

    # 2. Scope
    doc.add_heading("2. Scope and approach", level=1)
    para("The following targets were in scope:")
    para("{%p for target in scan.targets %}")
    para("{{ target }}", style="List Bullet")
    para("{%p endfor %}")
    para("{{ scan.hosts_up }} of {{ scan.hosts_total }} hosts responded. Findings are ranked by fix-first priority, "
         "which combines severity, evidence of real-world exploitation (CISA KEV, EPSS) and exposure.")

    # 3. Overview
    doc.add_heading("3. Findings overview", level=1)
    overview = doc.add_table(rows=3, cols=5)
    overview.style = "Table Grid"
    for i, label in enumerate(("Ref", "Finding", "Severity", "Priority", "Affected")):
        cell = overview.rows[0].cells[i]
        cell.text = label
        cell.paragraphs[0].runs[0].bold = True
        shade(cell, "E5E7EB")
    overview.rows[1].cells[0].text = "{%tr for f in findings %}"
    row = overview.rows[2].cells
    row[0].text = "{{ f.ref }}"
    row[1].text = "{{ f.title }}"
    row[2].text = "{{r f.severity_rt }}"
    row[3].text = "{{ f.priority if f.priority is not none else '' }}"
    row[4].text = "{{ f.affected|length }}"
    end = overview.add_row().cells
    end[0].text = "{%tr endfor %}"
    widths(overview, 1.6, 9.0, 2.4, 1.8, 1.8)

    # 4. Details
    doc.add_heading("4. Detailed findings", level=1)
    para("{%p for f in findings %}")
    heading = doc.add_heading("{{ f.ref }}  {{ f.title }}", level=2)
    heading.paragraph_format.page_break_before = True  # one finding per page
    meta = doc.add_table(rows=4, cols=2)
    meta.style = "Table Grid"
    for i, (label, value) in enumerate((
        ("Severity", "{{r f.severity_rt }}{% if f.kev %}  (known exploited){% endif %}"),
        ("CVSS", "{{ f.cvss_score if f.cvss_score is not none else 'n/a' }} {{ f.cvss_vector }}"),
        ("Fix-first priority", "{{ f.priority if f.priority is not none else 'n/a' }}"),
        ("Affected", "{{ f.affected_text }}"),
    )):
        meta.rows[i].cells[0].text = label
        meta.rows[i].cells[0].paragraphs[0].runs[0].bold = True
        shade(meta.rows[i].cells[0], "F3F4F6")
        meta.rows[i].cells[1].text = value
    widths(meta, 3.6, 13.0)
    doc.add_heading("Description", level=3)
    para("{{ f.description }}")
    para("{%p if f.impact %}")
    doc.add_heading("Impact", level=3)
    para("{{ f.impact }}")
    para("{%p endif %}")
    doc.add_heading("Recommendation", level=3)
    para("{{ f.remediation or 'See references.' }}")
    para("{%p if f.evidence %}")
    doc.add_heading("Evidence", level=3)
    ev = para("{{ f.evidence }}")
    ev.runs[0].font.name = "Consolas"
    ev.runs[0].font.size = Pt(8.5)
    para("{%p endif %}")
    para("{%p for img in f.images %}")
    para("{{ img.image }}")
    para("{{ img.caption }}", size=9, color="6B7280")
    para("{%p endfor %}")
    para("{%p if f.references or f.cve_ids %}")
    doc.add_heading("References", level=3)
    para("{%p for c in f.cve_ids %}")
    para("{{ c }}", style="List Bullet")
    para("{%p endfor %}")
    para("{%p for r in f.references %}")
    para("{{ r }}", style="List Bullet")
    para("{%p endfor %}")
    para("{%p endif %}")
    para("{%p endfor %}")

    # Appendix
    doc.add_heading("Appendix A. Hosts", level=1).paragraph_format.page_break_before = True
    hosts = doc.add_table(rows=3, cols=4)
    hosts.style = "Table Grid"
    for i, label in enumerate(("Address", "Name", "Operating system", "Open ports")):
        cell = hosts.rows[0].cells[i]
        cell.text = label
        cell.paragraphs[0].runs[0].bold = True
        shade(cell, "E5E7EB")
    hosts.rows[1].cells[0].text = "{%tr for h in hosts %}"
    cells = hosts.rows[2].cells
    cells[0].text, cells[1].text, cells[2].text, cells[3].text = "{{ h.ip }}", "{{ h.hostname }}", "{{ h.os }}", "{{ h.ports }}"
    hosts.add_row().cells[0].text = "{%tr endfor %}"
    widths(hosts, 3.0, 4.2, 4.0, 5.4)

    doc.add_heading("Appendix B. Testing activity", level=1).paragraph_format.page_break_before = True
    para("Agreed testing window: {{ testing.window }}")
    para("{% if not testing.activity %}No scan activity was recorded for these results (for example, findings imported from another tool).{% elif testing.verified %}The activity record below is intact (integrity check passed).{% else %}Warning: the activity record failed its integrity check.{% endif %}")
    activity = doc.add_table(rows=3, cols=4)
    activity.style = "Table Grid"
    for i, label in enumerate(("Time", "Event", "Source address", "By")):
        cell = activity.rows[0].cells[i]
        cell.text = label
        cell.paragraphs[0].runs[0].bold = True
        shade(cell, "E5E7EB")
    activity.rows[1].cells[0].text = "{%tr for a in testing.activity %}"
    cells = activity.rows[2].cells
    cells[0].text, cells[1].text, cells[2].text, cells[3].text = "{{ a.time }}", "{{ a.event }}", "{{ a.source_ip }}", "{{ a.actor }}"
    activity.add_row().cells[0].text = "{%tr endfor %}"
    widths(activity, 4.2, 5.0, 4.0, 3.4)

    buffer = io.BytesIO()
    doc.save(buffer)
    return buffer.getvalue()


def safe_template_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")[:120] or "template"
