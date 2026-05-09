"""HTML + PDF report generator for DFIR-Auto triage results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

_TEMPLATE_DIR = Path(__file__).parent


def generate_html(report: Any, raw_dict: dict, output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("template.html")
    html = template.render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        report=raw_dict,
        version="0.1.0",
    )
    output.write_text(html, encoding="utf-8")
    return output


def generate_pdf(report: Any, raw_dict: dict, output_path: str | Path) -> Path:
    output = Path(output_path)
    try:
        import weasyprint  # type: ignore
    except ImportError:
        html_path = output.with_suffix(".html")
        return generate_html(report, raw_dict, html_path)
    html_path = output.with_suffix(".html")
    generate_html(report, raw_dict, html_path)
    weasyprint.HTML(filename=str(html_path)).write_pdf(str(output))
    return output
