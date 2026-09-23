"""Output formats: table (terminal), json, sarif, csv, markdown, html."""

from __future__ import annotations

from collections.abc import Callable

from shadowscan.models import ScanResult
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.sarif import render_sarif

RENDERERS: dict[str, Callable[[ScanResult], str]] = {
    "json": render_json,
    "sarif": render_sarif,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
}

FORMATS = ["table", *sorted(k for k in RENDERERS if k != "md")]


def render(result: ScanResult, fmt: str) -> str:
    try:
        return RENDERERS[fmt](result)
    except KeyError as exc:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from exc


__all__ = ["RENDERERS", "FORMATS", "render"]
