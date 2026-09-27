"""The Python import binder is skipped only when it provably finds nothing.

The binder has a structural budget (``MAX_AST_NODES``). A file none of whose
imports can resolve to a signature cannot yield import-bound evidence at any
size, so the budget must not make an ordinary large module incomplete. Every
other over-budget file stays incomplete exactly as before. The proof is
checked against the binder itself, run without a budget, on every Python
input in the repository: the evaluation corpora, the fixtures and the
scanner's own sources.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code import source_semantics
from shadowscan.connectors.code.source_semantics import (
    MAX_AST_NODES,
    SourceBudgetExceeded,
    bound_source_matches,
)
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import signature_from_dict

REPOSITORY = Path(__file__).resolve().parents[2]
UNLIMITED = sys.maxsize


def _filler(lines: int) -> str:
    return "".join(f"value_{i} = [{i}, {i} + 1]\n" for i in range(lines))


PLAIN_MODULE = (
    "import os\nimport collections.abc as abc\n\n"
    "def join(parts: abc.Sequence[str]) -> str:\n    return os.path.join(*parts)\n\n"
) + _filler(6000)
OPENAI_MODULE = (
    "from openai import OpenAI\n\nclient = OpenAI()\n"
    "reply = client.chat.completions.create(model='gpt-4o', messages=[])\n"
) + _filler(6000)

# Inputs where the proof's handling of Python syntax matters, with whether a
# binding can resolve to a signature.
EDGE_CASES = {
    "attribute-of-plain-import": (
        "import transformers\nagent = transformers.ReactCodeAgent(tools=[])\n", True,
    ),
    "attribute-names-the-module": ("import google\nclient = google.genai.Client()\n", True),
    "aliased-import": ("import swarm as s\nteam = s.Swarm(client=None)\n", True),
    "bare-module-import": ("import agents\n", True),
    "nfkc-normalized-identifier": ("import ｏｐｅｎａｉ\nopenai.OpenAI()\n", True),
    "spaced-dotted-name": ("from google . adk import Agent\nAgent(name='a')\n", True),
    "continued-dotted-name": ("from google.\\\n    adk import Agent\nAgent(name='a')\n", True),
    "names-only-in-strings": (
        '"""from openai import OpenAI"""\nimport os\nkey = os.environ["OPENAI_API_KEY"]\n', False,
    ),
    "near-miss-attributes": ("import os\nos.nat_tool = 1\nos.signature_eval()\nos.path.cli_agent()\n", False),
    "relative-import": ("from .openai import OpenAI\nOpenAI()\n", False),
    "star-import": ("from openai import *\nOpenAI()\n", False),
    "dynamic-import": ('openai = __import__("openai")\nopenai.OpenAI()\n', False),
}


def _key(match: Match) -> tuple[Any, ...]:
    extra = tuple(sorted((name, repr(value)) for name, value in match.extra.items()))
    return (match.signature_id, match.signal.type, match.signal.description, match.value, match.weight,
            match.line, extra)


def _bound(index: SignatureIndex, text: str) -> list[tuple[Any, ...]] | str:
    try:
        return sorted(map(_key, bound_source_matches(index, text, "python", [], max_ast_nodes=UNLIMITED)))
    except Exception as exc:  # noqa: BLE001 - both runs must fail the same way
        return type(exc).__name__


def _repository_sources() -> list[tuple[str, str]]:
    sources = []
    for corpus in sorted((REPOSITORY / "tools" / "evaluation").glob("*corpus.json")):
        for case in json.loads(corpus.read_text(encoding="utf-8"))["cases"]:
            for name, text in case["files"].items():
                if name.endswith(".py"):
                    sources.append((f"{corpus.stem}:{case['id']}:{name}", text))
    for directory in ("tests/fixtures", "shadowscan", "tools"):
        for path in sorted((REPOSITORY / directory).rglob("*.py")):
            sources.append((path.relative_to(REPOSITORY).as_posix(), path.read_text(encoding="utf-8")))
    return sources


def _compare(
    index: SignatureIndex, text: str, monkeypatch: pytest.MonkeyPatch,
) -> tuple[bool | None, Any, Any]:
    """Return the proof's verdict and the binder's results with and without it, unbudgeted."""
    verdicts: list[bool] = []
    proof = source_semantics._python_bindable

    def recorded(index: SignatureIndex, tree: ast.AST) -> bool:
        verdicts.append(proof(index, tree))
        return verdicts[-1]

    monkeypatch.setattr(source_semantics, "_python_bindable", recorded)
    actual = _bound(index, text)
    monkeypatch.setattr(source_semantics, "_python_bindable", lambda index, tree: True)
    reference = _bound(index, text)
    monkeypatch.setattr(source_semantics, "_python_bindable", proof)
    return (verdicts[0] if verdicts else None), actual, reference


def test_proof_is_lossless_on_every_repository_python_input(index, monkeypatch):
    proven = bindable = 0
    for name, text in _repository_sources():
        verdict, actual, reference = _compare(index, text, monkeypatch)
        assert actual == reference, name
        if verdict is False:
            assert reference == [], name
            proven += 1
        elif verdict:
            bindable += 1
    # Both outcomes are exercised: corpus agents bind, the scanner's own code does not.
    assert proven >= 100 and bindable >= 40, (proven, bindable)


@pytest.mark.parametrize(("text", "expected"), EDGE_CASES.values(), ids=list(EDGE_CASES))
def test_proof_follows_python_import_semantics(index, monkeypatch, text, expected):
    verdict, actual, reference = _compare(index, text, monkeypatch)
    assert verdict is expected
    assert actual == reference
    if not expected:
        assert reference == []


@pytest.mark.parametrize("pattern", [
    r"(?i)^[^\S\r\n]*from\s+os\s+import\s+Agent\b",  # case-insensitive: no literal hints
    r"^from os import Agent$",  # the literal may span the module and the name
])
def test_patterns_the_proof_cannot_rule_out_keep_the_binder(pattern):
    index = SignatureIndex([signature_from_dict({
        "id": "framework.custom",
        "category": "framework",
        "signals": [
            {"type": "import", "languages": ["python"], "patterns": [pattern]},
            {"type": "code", "languages": ["python"], "patterns": [r"\bAgent\("]},
        ],
    })])
    text = "import os\nos.Agent()\n"
    assert source_semantics._python_bindable(index, ast.parse(text))
    assert [m.signature_id for m in bound_source_matches(index, text, "python", [])] == ["framework.custom"]


def test_too_many_candidate_names_keep_the_binder():
    index = SignatureIndex([signature_from_dict({
        "id": "framework.custom",
        "category": "framework",
        "signals": [
            {"type": "import", "languages": ["python"], "patterns": [r"^from\s+os\s+import\s+Agent\w*X\b"]},
        ],
    })])
    names = "".join(f"os.AgentX{number}()\n" for number in range(source_semantics._MAX_PROOF_STATEMENTS + 1))
    assert source_semantics._python_bindable(index, ast.parse("import os\n" + names))
    assert not source_semantics._python_bindable(index, ast.parse("import os\nos.AgentX1()\n"))


def test_default_budget_applies_only_when_a_binding_can_resolve(index):
    assert sum(1 for _ in ast.walk(ast.parse(PLAIN_MODULE))) > MAX_AST_NODES
    assert sum(1 for _ in ast.walk(ast.parse(OPENAI_MODULE))) > MAX_AST_NODES
    assert bound_source_matches(index, PLAIN_MODULE, "python", []) == []
    with pytest.raises(SourceBudgetExceeded, match="source binding AST limit exceeded"):
        bound_source_matches(index, OPENAI_MODULE, "python", [])


def test_nesting_budget_applies_only_when_a_binding_can_resolve(index):
    # Deep enough for the binder's recursion, shallow enough for the parser.
    chain = "value = os" + ".attribute" * 2000 + "\n"
    assert bound_source_matches(index, "import os\n" + chain, "python", []) == []
    with pytest.raises(SourceBudgetExceeded, match="source binding recursion limit exceeded"):
        bound_source_matches(index, "import os\nimport openai\nopenai.OpenAI()\n" + chain, "python", [])


def _scan(tmp_path: Path, text: str) -> tuple[int, dict[str, Any]]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "service.py").write_text(text)
    report = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["code", str(repository), "--format", "json", "-o", str(report)])
    return result.exit_code, json.loads(report.read_text())


def test_oversized_module_without_signature_imports_is_complete(tmp_path):
    exit_code, report = _scan(tmp_path, PLAIN_MODULE)
    assert exit_code == 0
    assert report["summary"]["complete"] and report["findings"] == []
    assert report["stats"][0]["errors"] == [] and report["stats"][0]["warnings"] == []


def test_oversized_module_with_provider_import_stays_incomplete(tmp_path):
    exit_code, report = _scan(tmp_path, OPENAI_MODULE)
    assert exit_code == 3
    assert not report["summary"]["complete"]
    assert report["stats"][0]["errors"] == [
        "code.filesystem: service.py: import-bound analysis skipped (source binding AST limit exceeded); "
        "lexical evidence retained",
    ]
    assert any("provider.openai" in finding["model_providers"] for finding in report["findings"])
