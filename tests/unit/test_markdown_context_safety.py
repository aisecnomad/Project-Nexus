"""Untrusted discovery data must never become report structure or active HTML."""

from __future__ import annotations

from markdown_it import MarkdownIt

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import (
    Evidence,
    Finding,
    Kind,
    Risk,
    RiskFactor,
    RiskLevel,
    ScanResult,
    ScanStats,
    Surface,
)
from shadowscan.reporters.markdown import render_markdown


def _html_and_headings(report: str) -> tuple[str, list[str]]:
    markdown = MarkdownIt("default").enable("table")
    tokens = markdown.parse(report)
    headings = [tokens[i + 1].content for i, token in enumerate(tokens) if token.type == "heading_open"]
    return markdown.render(report), headings


def test_real_hostile_repository_name_remains_resource_text(tmp_path):
    root = tmp_path / "repository\n## SECURITY APPROVED"
    root.mkdir()
    (root / "agent.py").write_text("from langchain.agents import create_agent\n")
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(root)})])).run()

    assert result.complete and result.findings
    assert any("SECURITY APPROVED" in finding.resource for finding in result.findings)
    report = render_markdown(result)
    html, headings = _html_and_headings(report)

    assert "SECURITY APPROVED" in html  # still readable in the resource value
    assert "SECURITY APPROVED" not in headings
    assert "\n## SECURITY APPROVED" not in report
    assert r"\n## SECURITY APPROVED" in report


def test_untrusted_fields_are_plain_text_and_snippets_cannot_close_fence():
    attack = "\n## SECURITY APPROVED\n<img src=x onerror=alert(1)>"
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem" + attack, kind=Kind.AGENT,
        title="Agent | fake" + attack, resource="root`" + attack, resource_type="repository" + attack,
        owner="owner[click](https://attacker.invalid)\x1b[31m\u202e" + attack,
        frameworks=["framework.langchain" + attack], models=["model" + attack],
        permissions=["perm" + attack],
        evidence=[Evidence(
            signal="code", description="description" + attack,
            location="name`more" + attack,
            snippet="normal line\n\x1b[31m\n``````\n## SECURITY APPROVED\n<img src=x onerror=alert(1)>\n",
        )],
    )
    finding.metadata["runtime_activity"] = {"status": "unobserved" + attack, "limitations": attack}
    finding.risk = Risk(42, RiskLevel.MEDIUM, [RiskFactor("factor", "risk" + attack, 10)])
    result = ScanResult(
        findings=[finding], version="v1" + attack,
        stats=[ScanStats("code.filesystem" + attack, "2026-01-01", errors=["diagnostic" + attack])],
    )

    report = render_markdown(result)
    html, headings = _html_and_headings(report)

    assert "SECURITY APPROVED" in html  # evidence preserved as inert text
    assert len(headings) == 6  # only the report headings and this finding's heading
    assert headings[4].startswith("🟡 Agent")
    assert '<h2>SECURITY APPROVED</h2>' not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "<a href=\"https://attacker.invalid\"" not in html
    assert "\x1b" not in report and "\u202e" not in report
    assert report.count(r"\u001b") >= 2 and r"\u202e" in report
    assert "```````text" in report  # longer than the six attacker controlled backticks
    assert "Agent \\| fake" in report  # malicious title stays in one table cell
    assert html.count("<td>") == 14  # eight finding cells and six statistics cells
