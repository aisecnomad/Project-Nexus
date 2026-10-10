"""A JavaScript binding that a method parameter shadows is dropped, without rescanning the rest of the text."""

from __future__ import annotations

import json
import random
import re
import time

import pytest
import regex
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code.source_semantics import (
    _Binding,
    _drop_uncertain_bindings,
    _named_as_method_parameter,
)

# The whole-source pattern that ``_named_as_method_parameter`` replaced. It defines what shadowing means.
_ORIGINAL = r"(?:^|[;{{}}\n])\s*(?:async\s+)?[\w$]+\s*\([^)]*\b{name}\b[^)]*\)\s*(?::[^{{}};]+)?\{{"


def _original(text: str, name: str, timeout: float = 5) -> bool:
    pattern = _ORIGINAL.format(name=re.escape(name))
    return bool(regex.search(pattern, text, timeout=timeout, concurrent=False))


def _windowed(text: str, name: str) -> bool:
    parentheses = [match.start() for match in re.finditer(r"\)", text)]
    terminals = [match.start() for match in re.finditer(r"[{};]", text)]
    return _named_as_method_parameter(text, re.escape(name), parentheses, terminals)


def _kept(text: str, name: str = "Name") -> bool:
    bindings = {name: _Binding("module", name)}
    _drop_uncertain_bindings(bindings, text, [])
    return name in bindings


@pytest.mark.parametrize(
    "text",
    [
        "class A {\n  async run(Name: string, y) {\n  }\n}",
        "foo(Name) {",
        "}\nfoo(a, Name): Promise<void> {\n",
        "async foo(Name) : T {",
        "if (Name) {",
        "  get(first, Name = 1) {",
    ],
)
def test_a_method_declaring_the_name_as_a_parameter_shadows_the_binding(text: str):
    assert _original(text, "Name")
    assert _windowed(text, "Name")
    assert not _kept(text)


@pytest.mark.parametrize(
    "text",
    [
        "x = foo(Name) {",  # an expression, not a statement start
        ") foo(Name) {",  # the declaration does not start a statement
        "a.b(Name) {",  # a member call
        "foo(Namex) {",
        "foo(xName) {",
        "foo(Name);",  # a call, not a declaration
        "foo(Name)",  # nothing follows the parameters
        "foo(Name) : T;",
        "run(a(b), Name)\n{",  # a ")" before the name ends the parameter list the pattern reads
    ],
)
def test_other_uses_of_the_name_keep_the_binding(text: str):
    assert not _original(text, "Name")
    assert not _windowed(text, "Name")
    assert _kept(text)


def test_windowed_check_agrees_with_the_original_pattern_on_generated_source():
    rng = random.Random(20261008)
    pieces = [
        "Name",
        "foo",
        "async ",
        "(",
        ")",
        "{",
        "}",
        ";",
        "\n",
        " ",
        ", ",
        ": T",
        "get ",
        "x.",
        "=>",
        "if ",
    ]
    matches = 0
    for _ in range(4000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 30)))
        expected = _original(text, "Name")
        matches += expected
        assert _windowed(text, "Name") == expected, text
    assert matches > 0  # the generator reaches the pattern


def test_statement_starts_that_never_close_do_not_exhaust_the_pattern_budget():
    # Twenty thousand statement starts that open a parenthesis and never close it made the original
    # pattern rescan the rest of the text from each one: it timed out at the 0.1 s pattern budget.
    text = "const client = new OpenAI();\n" + "f(\n" * 20_000
    with pytest.raises(TimeoutError):
        _original(text, "OpenAI", timeout=0.1)
    assert _kept(text, "OpenAI")


def test_a_large_typescript_file_keeps_its_analysis(tmp_path):
    # 5,000 unclosed calls: the original check timed out here, and the whole scan takes a fraction of a second.
    (tmp_path / "big.ts").write_text(
        'import OpenAI from "openai";\n'
        "const client = new OpenAI();\n"
        'await client.chat.completions.create({ model: "gpt-4o", messages: [] });\n' + "f(\n" * 5_000,
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    errors = [error for stat in report["stats"] for error in stat["errors"]]
    assert not [error for error in errors if "TimeoutError" in error], errors
    assert any("provider.openai" in finding["model_providers"] for finding in report["findings"])


def test_windowed_check_agrees_with_the_original_pattern_on_more_generated_source():
    rng = random.Random(8101009)
    pieces = [
        "Name",
        "foo",
        "async ",
        "(",
        ")",
        "{",
        "}",
        ";",
        "\n",
        " ",
        ", ",
        ": T",
        "if ",
        "x(",
        "=> {",
        "\t",
    ]
    for _ in range(6000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 40)))
        assert _windowed(text, "Name") == _original(text, "Name"), text


_QUADRATIC_SHAPES = {
    "closing-parens": lambda: "x OpenAI ) " * 30_000 + "{",
    "or-chain": lambda: "if (" + "isOk(OpenAI) || " * 20_000 + "z) {",
    "then-chain": lambda: "p" + ".then(OpenAI)" * 20_000 + ".then(function () {\n})",
}


@pytest.mark.parametrize("shape", sorted(_QUADRATIC_SHAPES))
def test_the_quadratic_shapes_found_in_review_stay_fast(shape: str):
    source = _QUADRATIC_SHAPES[shape]()
    started = time.perf_counter()
    _kept(source, "OpenAI")
    assert time.perf_counter() - started < 2.0


def test_windowed_check_agrees_with_the_original_pattern_on_declaration_shaped_source():
    # The unstructured generator rarely forms a declaration; this one does about half the time.
    rng = random.Random(99)
    heads = ["foo(", "async foo(", "\nbar(", ";baz(", "{ qux(", "} run(", "if (", "x.y(", "a = b(", "get("]
    mids = ["Name", "a, Name", "Name = 1", "a(b), Name", "x, Name, y", "Namex", "(Name)", "{ Name }", "", " "]
    tails = [")", " ) {", ") : T {", ") {", "); ", ")\n{", ") => {", "): Promise<void> {", ") ;", "))"]
    seams = ["", "\n", " ", "x;", "}"]
    matches = 0
    for _ in range(3000):
        text = "".join(
            rng.choice(heads) + rng.choice(mids) + rng.choice(tails) + rng.choice(seams)
            for _ in range(rng.randint(1, 4))
        )
        expected = _original(text, "Name")
        matches += expected
        assert _windowed(text, "Name") == expected, text
    assert matches > 500
