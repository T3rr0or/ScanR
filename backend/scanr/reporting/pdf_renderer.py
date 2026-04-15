from __future__ import annotations

from pathlib import Path

from scanr.config import get_settings
from scanr.reporting.html_renderer import render_html

settings = get_settings()


async def render_pdf(context: dict, report_id: str) -> Path:
    # Generate HTML first, then convert
    html_path = await render_html(context, f"{report_id}_tmp")
    out = settings.reports_dir / f"{report_id}.pdf"

    import asyncio
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _weasyprint_convert, str(html_path), str(out))

    # Clean up temp HTML
    try:
        html_path.unlink()
    except Exception:
        pass

    return out


def _weasyprint_convert(html_path: str, pdf_path: str) -> None:
    from weasyprint import HTML
    HTML(filename=html_path).write_pdf(pdf_path)
