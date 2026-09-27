"""Untrusted discovery data must never become report structure or active HTML."""

from __future__ import annotations

import html as html_module
import re

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
from shadowscan.reporters.html import render_html
from shadowscan.reporters.markdown import render_markdown


def _html_and_headings(report: str) -> tuple[str, list[str]]:
    markdown = MarkdownIt("default").enable("table")
    tokens = markdown.parse(report)
    headings = [tokens[i + 1].content for i, token in enumerate(tokens) if token.type == "heading_open"]
    return markdown.render(report), headings


def test_real_hostile_repository_name_remains_resource_text(tmp_path, index):
    root = tmp_path / "repository\n## SECURITY APPROVED"
    root.mkdir()
    (root / "agent.py").write_text("from langchain.agents import create_agent\n")
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(root)})]), index).run()

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


_UNICODE_BREAKS = {"\x85": r"\u0085", "\u2028": r"\u2028", "\u2029": r"\u2029"}


def test_unicode_line_and_paragraph_separators_stay_visible_escapes():
    breaks = "".join(_UNICODE_BREAKS)
    attack = f"{breaks}## SECURITY APPROVED"
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem" + attack, kind=Kind.AGENT,
        title="Agent" + attack, resource="repo" + attack, resource_type="repository" + attack,
        owner="owner" + attack, frameworks=["framework.langchain" + attack], tags=["tag" + attack],
        evidence=[Evidence(
            signal="code", description="description" + attack, location="agent.py" + attack,
            snippet=f"line one{attack}\nline two",
        )],
    )
    finding.risk = Risk(42, RiskLevel.MEDIUM, [RiskFactor("factor", "risk" + attack, 10)])
    result = ScanResult(
        findings=[finding],
        stats=[ScanStats("code.filesystem" + attack, "2026-01-01", errors=["diagnostic" + attack])],
    )

    report = render_markdown(result)
    _, headings = _html_and_headings(report)

    for char, escape in _UNICODE_BREAKS.items():
        assert char not in report, repr(char)
        # Every untrusted field above keeps the separator as visible text.
        assert report.count(escape) >= 11, escape
    assert "SECURITY APPROVED" not in headings
    assert len(headings) == 6  # only the report headings and this finding's heading


_MENTION = re.compile(r"(?:^|\W)@[A-Za-z0-9]")  # GitHub @user and @org/team mentions
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")  # GFM extended e-mail autolinks


def _prose(rendered_html: str) -> str:
    """Rendered text outside code spans and blocks, where GitHub adds links."""
    without_code = re.sub(r"<code>.*?</code>|<pre>.*?</pre>", " ", rendered_html, flags=re.S)
    return html_module.unescape(re.sub(r"<[^>]+>", " ", without_code))


def _mention_finding() -> Finding:
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Agent owned by @acme/platform-team, ask @octocat", resource="git@github.com:acme/agent.git",
        resource_type="repository", owner="@acme/security", frameworks=["@langchain/core"],
        evidence=[Evidence(signal="code", description="Contact admin@example.com or mailto:ops@example.org")],
    )
    finding.risk = Risk(30, RiskLevel.MEDIUM, [RiskFactor("factor", "reviewed by @acme/reviewers", 10)])
    return finding


def test_markdown_report_neutralises_mentions_and_email_autolinks():
    result = ScanResult(
        findings=[_mention_finding()],
        stats=[ScanStats("code.filesystem", "2026-01-01", warnings=["reported by @bot to sec@example.com"])],
    )

    report = render_markdown(result)
    rendered, _ = _html_and_headings(report)
    prose = _prose(rendered)

    assert _MENTION.search(prose) is None, prose
    assert _EMAIL.search(prose) is None, prose
    # Still readable, in the same bracket style as a defanged "www[.]" host.
    assert "[@]acme/platform-team" in prose and "[@]octocat" in prose
    assert "admin[@]example.com" in prose and "sec[@]example.com" in prose
    assert "[@]acme/security" in prose and "[@]langchain/core" in prose
    # Code spans are never linkified or mentioned, so identifiers stay verbatim.
    assert "`git@github.com:acme/agent.git`" in report


def test_html_report_has_no_link_or_mention_surface_for_the_same_values():
    finding = _mention_finding()
    report = render_html(ScanResult(findings=[finding], stats=[ScanStats("code.filesystem", "2026-01-01")]))

    # Browsers render escaped text; there is no autolinking or @-mention step.
    assert "<a " not in report and "href=" not in report
    assert "Agent owned by @acme/platform-team, ask @octocat" in report
    assert "admin@example.com" in report
