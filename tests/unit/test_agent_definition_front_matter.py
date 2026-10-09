"""Agent definitions with a plain description that contains ": " are read, as coding agents read them."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code.filesystem import _quote_glob_values, _quote_plain_values

ERROR = "invalid agent definition YAML"

_DESCRIPTION = (
    "Use this agent when you need a review. Examples: <example>Context: User has finished a feature. "
    "user: 'Can you check it?' assistant: 'I will use the reviewer agent.'</example>"
)


def _definitions(findings) -> list[dict]:
    return [item for finding in findings for item in finding.metadata.get("agent_definitions", [])]


def _write(tmp_path, front: str) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "reviewer.md").write_text(f"---\n{front}\n---\nReview code.\n", encoding="utf-8")


def test_a_plain_description_containing_colons_is_read(tmp_path, run_connector):
    _write(tmp_path, f"name: reviewer\ndescription: {_DESCRIPTION}\ntools: Read, Grep\nmodel: sonnet")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert any("agent definition front matter quoted to parse" in warning for warning in ctx.stats.warnings)
    [definition] = _definitions(findings)
    assert definition["name"] == "reviewer"
    assert definition["description"].startswith("Use this agent when you need a review. Examples:")
    assert definition["tools"] == "Read, Grep"
    assert definition["model"] == "sonnet"


@pytest.mark.parametrize(
    "front",
    [
        # Explicit tags and repeated fields are the loader's integrity checks: quoting must not bypass them.
        "name: reviewer\nvalue: !!int >\ndescription: a: b",
        "name: reviewer\nname: other\ndescription: a: b",
        # A value that is already quoted but not terminated, a flow collection never closed.
        'name: reviewer\ndescription: "unterminated: here\ntools: Bash',
        "name: reviewer\ndescription: [unterminated: here\ntools: Bash",
        # Structure that quoting a one-line value cannot repair.
        "name: reviewer\ndescription: a: b\n  - stray item",
    ],
    ids=["explicit-tag", "repeated-field", "unterminated-quote", "unterminated-flow", "stray-block"],
)
def test_front_matter_that_quoting_cannot_repair_is_still_an_error(tmp_path, run_connector, front):
    _write(tmp_path, front)
    (tmp_path / "agent.py").write_text("from crewai import Agent\nAgent(role='r')\n", encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert ctx.stats.errors == [f"code.filesystem: .claude/agents/reviewer.md: {ERROR}"]
    assert any("framework.crewai" in finding.frameworks for finding in findings)


def test_values_that_already_parse_are_left_alone():
    front = "name: reviewer\nalwaysApply: true\nmodel: 'a: b'\ntools: [Read, Grep]\ndescription: |\n  a: b\n"
    assert _quote_plain_values(front) == front


def test_only_one_line_plain_values_with_a_colon_are_quoted():
    front = 'name: x\ndescription: say "hi": now\nglobs: **/*.ts\nnote: ends with:\nodd: @mention\nnested:\n  key: a: b'
    assert _quote_plain_values(_quote_glob_values(front)).split("\n") == [
        "name: x",
        'description: "say \\"hi\\": now"',
        "globs: '**/*.ts'",
        'note: "ends with:"',
        'odd: "@mention"',
        "nested:",
        "  key: a: b",
    ]


def test_backslashes_stay_literal_in_the_quoted_value():
    assert _quote_plain_values("description: a\\nb: c") == 'description: "a\\\\nb: c"'


def test_a_trailing_comment_with_a_colon_does_not_trigger_the_lenient_retry(tmp_path, run_connector):
    _write(tmp_path, "name: reviewer\ndescription: Reviews code\nmodel: sonnet # note: fast")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert not any("quoted to parse" in warning for warning in ctx.stats.warnings)
    [definition] = _definitions(findings)
    assert definition["model"] == "sonnet"
