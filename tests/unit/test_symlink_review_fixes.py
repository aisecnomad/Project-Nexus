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


def test_github_token_is_not_titled_an_llm_provider_credential(tmp_path: Path, run_connector) -> None:
    token = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7c"
    _write(tmp_path, {"settings.py": f'TOKEN = "{token}"\n'})
    findings, _ = _scan(run_connector, tmp_path)
    assert [f.title for f in findings] == ["Hard-coded credential in settings.py"]
