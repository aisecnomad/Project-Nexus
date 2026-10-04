"""Literal-dead JavaScript alternatives cannot establish agent construction."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import javascript_reachability
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import (
    SourceBudgetExceeded,
    _javascript_bindings,
    bound_source_matches,
)
from shadowscan.models import Kind

IMPORT = "import { Agent as Worker } from '@openai/agents';\n"
CONSTRUCT = "new Worker({name: 'candidate'});"


def _code_lines(index, source: str) -> list[int | None]:
    ignored, _ = noncode_ranges(source, "javascript")
    matches = bound_source_matches(index, source, "javascript", ignored)
    return [
        match.line
        for match in matches
        if match.signature_id == "framework.openai-agents-sdk" and match.signal.type == "code"
    ]


@pytest.mark.parametrize("suffix", [".js", ".ts"])
@pytest.mark.parametrize(
    "body",
    [
        f"if (false) {{ {CONSTRUCT} }}",
        f"if (false) {CONSTRUCT}",
        f"if (false) {CONSTRUCT.removesuffix(';')}",
        f"if (true) {{ log('live'); }} else {{ {CONSTRUCT} }}",
        f"if (true) log('live'); else {CONSTRUCT}",
        f"if (true) {{}} else if (dynamic()) {{ {CONSTRUCT} }}",
        f"if (dynamic()) {{ if (false) {{ {CONSTRUCT} }} }}",
        f"while (false) {{ {CONSTRUCT} }}",
        f"if (false) if (true) {CONSTRUCT} else {CONSTRUCT}",
    ],
)
def test_dead_constructions_remain_framework_usage(tmp_path, run_connector, suffix, body):
    (tmp_path / f"app{suffix}").write_text(IMPORT + body)
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False
    )
    assert not context.stats.incomplete, context.stats.errors
    assert findings and all(finding.kind == Kind.FRAMEWORK_USAGE for finding in findings)


@pytest.mark.parametrize(
    "condition",
    [
        "false",
        "null",
        "0",
        "-0",
        "+0",
        "0.0",
        "0e9",
        "1e-999",
        "0x0",
        "0b0",
        "0o0",
        "0n",
        "''",
        '""',
        "!true",
        "!!false",
        "(!((true)))",
    ],
)
def test_literal_falsy_conditions_have_no_bound_agent_call(index, condition):
    assert _code_lines(index, IMPORT + f"if ({condition}) {{ {CONSTRUCT} }}") == []


@pytest.mark.parametrize(
    "condition",
    ["true", "1", "-1", "+1", "1e999", "0x1", "0b1", "0o1", "1n", "'false'", "!null", "!!true", "((true))"],
)
def test_literal_truthy_conditions_keep_then_and_exclude_else(index, condition):
    source = IMPORT + f"if ({condition}) {{\n{CONSTRUCT}\n}} else {{\n{CONSTRUCT}\n}}"
    assert _code_lines(index, source) == [3]


@pytest.mark.parametrize(
    "condition",
    [
        "enabled",
        "check()",
        "undefined",
        "NaN",
        "Infinity",
        "false || enabled",
        "true && enabled",
        "false === enabled",
        "'\\n'",
        "`text`",
        "/regex/",
        "+'text'",
        "+1n",
    ],
)
def test_unknown_guards_preserve_both_alternatives(index, condition):
    source = IMPORT + f"if ({condition}) {{\n{CONSTRUCT}\n}} else {{\n{CONSTRUCT}\n}}"
    assert _code_lines(index, source) == [3, 5]


def test_dead_body_does_not_swallow_live_alternative_or_following_statement(index):
    source = IMPORT + (f"if (false) {{\n{CONSTRUCT}\n}} else {{\n{CONSTRUCT}\n}}\n{CONSTRUCT}\n")
    assert _code_lines(index, source) == [5, 7]


def test_nested_unbraced_if_follows_dangling_else(index):
    source = IMPORT + (f"if (true) if (false) {CONSTRUCT} else {CONSTRUCT}\nelse {CONSTRUCT}\n{CONSTRUCT}\n")
    assert _code_lines(index, source) == [2, 4]


def test_asi_dependent_dead_body_keeps_following_live_call(index):
    source = IMPORT + f"if (false) {CONSTRUCT.removesuffix(';')}\n{CONSTRUCT}"
    # The lexical check intentionally cannot prove this ASI-dependent boundary.
    # Both remain possible; the live construction is never masked accidentally.
    assert _code_lines(index, source) == [2, 3]


@pytest.mark.parametrize("terminator", ["\n", "\r", "\u2028", "\u2029"])
def test_every_javascript_line_terminator_preserves_asi_live_following_call(index, terminator):
    source = IMPORT + f"if (false) {CONSTRUCT.removesuffix(';')}" + terminator + CONSTRUCT
    assert len(_code_lines(index, source)) == 2


def test_semicolon_body_can_contain_multiline_call_arguments(index):
    source = IMPORT + "if (false) new Worker({\nname: 'dead'\n});\n" + CONSTRUCT
    assert _code_lines(index, source) == [5]


def test_unbraced_body_can_end_at_an_enclosing_block_boundary(index):
    source = IMPORT + "function build() { if (false) " + CONSTRUCT.removesuffix(";") + "\n}\n" + CONSTRUCT
    assert _code_lines(index, source) == [4]


@pytest.mark.parametrize(
    "loop",
    [
        "do { tick(); } while (false)\n",
        "do { tick(); } while (false) ",
        "do { tick(); } while (false);\n",
        "do tick(); while (false)\n",
        "do tick()\nwhile (false)\n",
        "do do tick(); while (false); while (false)\n",
        "do if (dynamic) tick(); else tick(); while (false)\n",
    ],
)
def test_do_while_tail_cannot_prune_the_following_live_construction(index, loop):
    source = IMPORT + loop + CONSTRUCT
    assert _code_lines(index, source) == [source.count("\n") + 1]


def test_genuine_dead_while_still_filters_beside_a_proven_do_tail(index):
    source = IMPORT + "do { tick(); } while (false)\n" + f"while (false) {{ {CONSTRUCT} }}\n" + CONSTRUCT
    assert _code_lines(index, source) == [4]


def test_labeled_inner_if_else_cannot_be_stolen_by_an_outer_if(index):
    source = IMPORT + f"if (true) label: if (false) {CONSTRUCT} else {CONSTRUCT}\n"
    assert _code_lines(index, source) == [2]


def test_comments_and_strings_do_not_create_branches(index):
    source = IMPORT + "// if (false) {\nconst text = 'if (false) {';\n" + CONSTRUCT
    assert _code_lines(index, source) == [4]


def test_dead_require_declaration_cannot_bind_a_live_call(index):
    source = "if (false) { const { Agent: Worker } = require('@openai/agents'); }\n" + CONSTRUCT
    assert _code_lines(index, source) == []


def test_dead_hoisted_var_still_shadows_an_import(index):
    source = IMPORT + f"function build() {{ if (false) {{ var Worker = local; }} {CONSTRUCT} }}"
    assert _code_lines(index, source) == []


@pytest.mark.parametrize(
    "source",
    [
        IMPORT + f"if (false {{ {CONSTRUCT} }}",
        IMPORT + f"if (false) {{ {CONSTRUCT}",
        IMPORT + f"object.if(false); {{ {CONSTRUCT} }}",
        IMPORT + f"do {{ {CONSTRUCT} }} while (false);",
    ],
)
def test_unsupported_shapes_and_do_while_do_not_hide_calls(index, source):
    assert _code_lines(index, source)


@pytest.mark.parametrize("condition", ["false", "0", "''", "!((true))", "/*comment*/false"])
def test_dead_branch_token_budget_is_reported_as_partial(index, monkeypatch, condition):
    monkeypatch.setattr(javascript_reachability, "MAX_TOKENS", 20)
    source = IMPORT + f"if ({condition}) {{ {CONSTRUCT} }}\n" + "const x = 1;\n" * 20
    with pytest.raises(SourceBudgetExceeded, match="JavaScript token limit"):
        _code_lines(index, source)


def test_only_dynamic_guards_need_no_literal_branch_token_budget(monkeypatch):
    monkeypatch.setattr(javascript_reachability, "MAX_TOKENS", 20)
    source = IMPORT + f"if (item.type === 'dynamic') {{ {CONSTRUCT} }}\n" + "const x = 1;\n" * 20
    ignored, _ = noncode_ranges(source, "javascript")
    calls, _ = _javascript_bindings(source, ignored)
    assert [(call.line, call.binding.symbol) for call in calls] == [(2, "Agent")]


def test_dead_branch_statement_nesting_is_bounded(index, monkeypatch):
    monkeypatch.setattr(javascript_reachability, "MAX_NESTING", 4)
    source = IMPORT + "if (false) " * 5 + CONSTRUCT
    with pytest.raises(SourceBudgetExceeded, match="JavaScript statement nesting limit"):
        _code_lines(index, source)
