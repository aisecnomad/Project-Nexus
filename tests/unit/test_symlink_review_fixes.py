"""Review of the symbolic-link, mention and plugin changes: inputs that lost evidence or the scan.

An independent review proved each case below on a minimal repository: a
directory link that dropped the permission checks its folder name triggers, a
document alias whose target is never read, a test-code link into excluded
content, a file of many names that timed the scan out, a plugin MCP file that
discarded every finding, a link farm, an undecodable name under a link and a
GitHub token titled as an LLM provider credential.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from shadowscan.models import Kind

pytestmark = pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")

OPENAI_KEY = "sk-proj-" + "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk9Lz0Xc" * 2
AGENT = 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="gpt-4o", messages=[])\n'
SKILL = "---\nname: translate\ndescription: Translate strings\n---\nTranslate the UI strings.\n"


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


@pytest.mark.parametrize(
    ("link", "target", "name", "text"),
    [
        (
            ".claude",
            "shared/claude",
            "settings.json",
            json.dumps({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}}),
        ),
        (".codex", "shared/codex", "config.toml", 'approval_policy = "never"\n'),
        (".gemini", "shared/gemini", "settings.json", json.dumps({"approvalMode": "yolo"})),
    ],
    ids=["claude", "codex", "gemini"],
)
def test_directory_link_whose_name_selects_settings_checks_is_a_gap(
    tmp_path: Path, run_connector, link: str, target: str, name: str, text: str
) -> None:
    _write(tmp_path, {f"{target}/{name}": text})
    _link(tmp_path, link, target)
    _, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete


def test_document_alias_to_a_file_that_is_never_read_is_a_gap(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {"docs/index.rst": f"Use OPENAI_API_KEY={OPENAI_KEY}\n"})
    _link(tmp_path, "README.md", "docs/index.rst")
    findings, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete or any(f.kind == Kind.SECRET for f in findings)


@pytest.mark.parametrize(
    ("link", "target", "files"),
    [
        ("tests/agent.py", "../node_modules/agentpkg/agent.py", {"node_modules/agentpkg/agent.py"}),
        ("tests/gen", "../node_modules/gen", {"node_modules/gen/agent.py"}),
    ],
    ids=["file", "directory"],
)
def test_test_code_link_into_excluded_content_is_a_gap(
    tmp_path: Path, run_connector, link: str, target: str, files: set[str]
) -> None:
    _write(tmp_path, dict.fromkeys(files, AGENT + f'KEY = "{OPENAI_KEY}"\n'))
    _link(tmp_path, link, target)
    _, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete
    assert not any("its target is analyzed at its real path" in w for w in ctx.stats.warnings)


def test_test_code_link_to_a_walked_file_follows_the_test_code_policy(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {"src/agent.py": AGENT})
    _link(tmp_path, "tests/agent.py", "../src/agent.py")
    _, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete
    assert any("its target is analyzed at its real path" in w for w in ctx.stats.warnings)


def test_many_distinct_names_in_one_data_file_stay_linear(tmp_path: Path, run_connector) -> None:
    lines = "".join(f"- description: LLM_V{n:06d}\n" for n in range(30_000))
    _write(tmp_path, {"catalog.yaml": lines})
    started = time.monotonic()
    _, ctx = _scan(run_connector, tmp_path)
    assert time.monotonic() - started < 30
    assert not any("deadline" in e or "timed out" in e for e in ctx.stats.errors)


def test_plugin_mcp_file_failure_is_isolated_to_that_file(tmp_path: Path, run_connector) -> None:
    # Too many keys to sanitize: the error belongs to that file, not to the scan.
    _write(
        tmp_path,
        {
            ".claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "./bad.json"}),
            "bad.json": json.dumps({f"k{n}": 0 for n in range(70_000)}, separators=(",", ":")),
            "requirements.txt": "openai\n",
            "agent.py": AGENT,
        },
    )
    findings, ctx = _scan(run_connector, tmp_path, max_file_size=4 * 1024 * 1024)
    assert ctx.stats.incomplete
    assert any("provider.openai" in f.model_providers for f in findings)


def test_plugin_mcp_file_named_many_times_is_read_once(tmp_path: Path, run_connector) -> None:
    _write(
        tmp_path,
        {".claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": ["./missing.json"] * 600})},
    )
    _, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete
    assert sum("missing.json" in e for e in ctx.stats.errors) == 1


def test_plugin_mcp_file_is_read_up_to_the_data_limit(tmp_path: Path, run_connector) -> None:
    # A bare table of servers: only the plugin manifest makes it MCP configuration.
    servers = {"db": {"command": "uvx", "args": ["mcp-server-postgres", "--note", "x" * 5_000]}}
    _write(
        tmp_path,
        {
            ".claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "./config/db.json"}),
            "config/db.json": json.dumps(servers),
        },
    )
    findings, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(f.kind == Kind.MCP_SERVER for f in findings)


def test_link_farm_is_a_bounded_gap(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {f"shared/files/f{n:04d}.txt": "x\n" for n in range(500)})
    for n in range(60):
        _link(tmp_path, f"links/l{n:03d}", "../shared/files")
    started = time.monotonic()
    _, ctx = _scan(run_connector, tmp_path)
    assert time.monotonic() - started < 30
    assert ctx.stats.incomplete
    assert not any("max_entries" in e for e in ctx.stats.errors)


def test_undecodable_name_under_a_directory_link_is_reported_escaped(tmp_path: Path, run_connector) -> None:
    skills = tmp_path / ".agents" / "skills"
    skills.mkdir(parents=True)
    try:
        (Path(os.fsdecode(bytes(skills) + b"/tr\xffx"))).mkdir()
    except (OSError, UnicodeError):
        pytest.skip("filesystem rejects undecodable names")
    (Path(os.fsdecode(bytes(skills) + b"/tr\xffx/SKILL.md"))).write_text(SKILL)
    _link(tmp_path, ".claude/skills", "../.agents/skills")
    findings, _ = _scan(run_connector, tmp_path)
    locations = [e.location or "" for f in findings for e in f.evidence]
    assert any(".claude/skills/tr\\xffx/SKILL.md" in loc for loc in locations)
    json.dumps([f.to_dict() for f in findings], ensure_ascii=False).encode("utf-8")


def test_github_token_is_not_titled_an_llm_provider_credential(tmp_path: Path, run_connector) -> None:
    token = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7c"
    _write(tmp_path, {"settings.py": f'TOKEN = "{token}"\n'})
    findings, _ = _scan(run_connector, tmp_path)
    assert [f.title for f in findings] == ["Hard-coded credential in settings.py"]
