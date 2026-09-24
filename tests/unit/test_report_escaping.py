from __future__ import annotations

from shadowscan.models import Evidence, Finding, Kind, ScanResult, Surface
from shadowscan.reporters.html import render_html
from shadowscan.reporters.markdown import render_markdown


def _finding() -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="x' onfocus='alert(1) <script>alert(1)</script> # injected",
        resource="repo/`evil`|[click](https://evil.example)",
        resource_type="agent",
        owner="o'connor",
        evidence=[Evidence("t", "desc `break`", location="path", snippet="```\nowned\n```", weight=0.4)],
    )


def test_html_report_escapes_attribute_and_text_payloads():
    html = render_html(ScanResult(findings=[_finding()]))
    escaped_script = "&" + "lt;script&" + "gt;"
    assert "onfocus='" not in html
    assert 'onfocus="' not in html
    assert "<script>alert(1)</script>" not in html
    assert "&#x27;" in html
    assert escaped_script in html
    assert 'data-title="' in html
    assert "Content-Security-Policy" in html


def test_markdown_report_neutralizes_structure_injection():
    md = render_markdown(ScanResult(findings=[_finding()]))
    escaped_script = "&" + "lt;script&" + "gt;"
    assert "<script>" not in md
    assert escaped_script in md
    assert "\n# injected" not in md
    assert "[click](https://evil.example)" not in md
    assert "## Findings" in md
