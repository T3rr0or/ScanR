from __future__ import annotations

import json
from pathlib import Path

import aiofiles
from jinja2 import Environment, FileSystemLoader

from scanr.config import get_settings

settings = get_settings()
_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)


def _from_json(value):
    """Jinja2 filter: parse a JSON string → Python object. Returns [] on failure."""
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []


_env.filters["from_json"] = _from_json


async def render_html(context: dict, report_id: str) -> Path:
    template = _env.get_template("report.html.j2")
    html = template.render(**context)
    out = settings.reports_dir / f"{report_id}.html"
    async with aiofiles.open(out, "w") as f:
        await f.write(html)
    return out
