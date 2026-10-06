"""runtime.processes: AI tools seen running, and lifecycle links to endpoint findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.runtime import processes as runtime_processes
from shadowscan.connectors.runtime.processes import RuntimeProcessConnector, _split, classify
from shadowscan.correlation import correlate_lifecycle
from shadowscan.engine import Engine
from shadowscan.models import Kind, Surface

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.parametrize(
    ("exe", "argv", "tool", "package"),
    [
        (None, ["/home/dana/.local/bin/claude", "--resume"], "claude-code", None),
        (None, ["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"], "claude-code", None),
        (
            "C:\\Program Files\\nodejs\\node.exe",
            ["node.exe", "C:\\Users\\sam\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\bin\\codex.js"],
            "codex",
            None,
        ),
        (None, ["npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"], "mcp:@modelcontextprotocol/server-github",
         "@modelcontextprotocol/server-github"),
        (None, ["uv", "tool", "run", "mcp-server-fetch"], "mcp:mcp-server-fetch", "mcp-server-fetch"),
        (None, ["uvx", "--from", "git+https://x/y", "mcp-server-git"], "mcp:mcp-server-git", "mcp-server-git"),
        (None, ["python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "x"], "vllm", None),
        (None, ["python", "-m", "aider", "--model", "sonnet"], "aider", None),
        (None, ["python", "agent.py"], None, None),
        (None, ["npm", "install", "-g", "mcp-server-fetch"], None, None),
        (None, ["uv", "pip", "install", "mcp-server-git"], None, None),
        (None, ["npm", "exec", "@modelcontextprotocol/server-github"], "mcp:@modelcontextprotocol/server-github",
         "@modelcontextprotocol/server-github"),
        (None, ["ollama", "serve"], "ollama", None),
        (None, ["ollama", "list"], None, None),
        ("/Applications/Claude.app/Contents/MacOS/Claude", [], "claude-desktop", None),
        ("C:\\Users\\sam\\AppData\\Local\\AnthropicClaude\\app-0.9.3\\claude.exe", [], "claude-desktop", None),
        ("/usr/share/cursor/cursor", ["/usr/share/cursor/cursor"], "cursor", None),
        (None, ["bash", "-c", "claude"], None, None),
        (None, [], None, None),
    ],
)  # fmt: skip
def test_classify(exe, argv, tool, package):
    match = classify(exe, argv)
    if tool is None:
        assert match is None
        return
    assert match is not None
    assert (match[0].tool, match[1]) == (tool, package)


def test_command_lines_are_never_exported():
    from shadowscan.connectors.base import _NoDump

    assert issubclass(RuntimeProcessConnector, _NoDump)


def test_split_honours_quotes():
    assert _split("\"C:\\Program Files\\nodejs\\node.exe\" cli.js --name 'a b'") == [
        "C:\\Program Files\\nodejs\\node.exe",
        "cli.js",
        "--name",
        "a b",
    ]


def _rows(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "processes.json"
    path.write_text(json.dumps(rows))
    return path


def test_osquery_defender_and_generic_rows(run_connector, tmp_path):
    rows = [
        {"hostIdentifier": "dev-laptop-07", "columns": {"pid": "4242", "name": "node", "uid": "1000",
         "cmdline": "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js --api-key sk-ant-secret",
         "start_time": "1759132800"}},
        {"hostIdentifier": "dev-laptop-07", "columns": {"pid": "4300", "name": "npx", "uid": "1000",
         "cmdline": "npx -y @modelcontextprotocol/server-github"}},
        {"DeviceName": "WIN-22.corp.example", "AccountName": "sam", "FileName": "ollama.exe",
         "FolderPath": "C:\\Users\\sam\\AppData\\Local\\Programs\\Ollama",
         "ProcessCommandLine": "\"ollama.exe\" serve", "Timestamp": "2025-09-29T08:00:00Z"},
        {"host": "build-01", "user": "ci", "command_line": "python -m pytest"},
        {"host": "build-01", "user": "ci"},
    ]  # fmt: skip
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert ctx.stats.incomplete and any("no command line" in w for w in ctx.stats.warnings)
    by = {f.title: f for f in findings}
    assert set(by) == {
        "Claude Code running on dev-laptop-07 (uid-1000)",
        "MCP server: @modelcontextprotocol/server-github running on dev-laptop-07 (uid-1000)",
        "Ollama running on WIN-22.corp.example (sam)",
    }
    claude = by["Claude Code running on dev-laptop-07 (uid-1000)"]
    assert claude.surface == Surface.RUNTIME and claude.kind == Kind.RUNTIME_PROCESS
    assert claude.frameworks == ["coding-agent.claude-code"] and "observed-running" in claude.tags
    assert claude.metadata["pids"] == [4242] and claude.first_seen == "2025-09-29T08:00:00+00:00"
    assert "sk-ant-secret" not in json.dumps(claude.to_dict())
    ollama = by["Ollama running on WIN-22.corp.example (sam)"]
    assert ollama.model_providers == ["provider.ollama"] and ollama.account == "WIN-22.corp.example"


def test_live_mode_reads_proc(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    for pid, argv in {"10": [b"/usr/bin/bash"], "11": [b"claude", b"-p", b"x"], "x": [b"no"]}.items():
        (proc / pid).mkdir(parents=True)
        (proc / pid / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert not ctx.stats.warnings
    assert [f.title.split(" running on ")[0] for f in findings] == ["Claude Code"]
    assert findings[0].account == "box"


def test_live_mode_outside_linux_is_refused(run_connector, monkeypatch):
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Darwin")
    _, ctx = run_connector("runtime.processes")
    assert ctx.stats.skipped and ctx.stats.incomplete


def test_lifecycle_links_endpoint_configuration_to_running_processes(index, tmp_path):
    rows = [
        {"hostIdentifier": "dev-laptop-07.corp.example", "columns": {"pid": "1", "uid": "1000",
         "cmdline": "/home/dana/.local/bin/claude", "name": "claude"}},
        {"host": "dev-laptop-07", "user": "dana",
         "cmdline": "npx -y @modelcontextprotocol/server-github@2025.4.8"},
        {"host": "dev-laptop-07", "user": "dana", "cmdline": "npx -y mcp-server-unrelated"},
        {"host": "dev-laptop-07", "user": "dana", "cmdline": "ollama serve"},
        {"host": "other-host", "user": "dana", "cmdline": "codex exec"},
    ]  # fmt: skip
    processes = _rows(tmp_path, rows)
    config = ScanConfig(
        connectors=[
            ConnectorSpec("endpoint.inventory", {"input": str(FIXTURES / "endpoint" / "inventory.jsonl")}),
            ConnectorSpec("runtime.processes", {"input": str(processes)}),
        ]
    )
    result = Engine(config, index).run()
    by = {f.title: f for f in result.findings}
    claude = by["Claude Code configured on dev-laptop-07 (~dana)"]
    assert "observed-running" in claude.tags
    assert claude.metadata["lifecycle"]["states"] == ["configured", "running"]
    assert claude.metadata["lifecycle"]["same_user"] is False
    assert any(e.signal == "lifecycle:observed-running" and e.weight == 0.0 for e in claude.evidence)
    cursor_mcp = by["MCP servers configured for Cursor on dev-laptop-07 (~dana)"]
    assert cursor_mcp.metadata["lifecycle"]["same_user"] is True
    assert "mcp-package:@modelcontextprotocol/server-github" in cursor_mcp.metadata["lifecycle"]["subjects"]
    assert "observed-running" in by["Local models stored for Ollama on dev-laptop-07 (~dana)"].tags
    assert "lifecycle" not in by["OpenAI Codex CLI running on other-host (dana)"].metadata
    assert "lifecycle" not in by["MCP server: mcp-server-unrelated running on dev-laptop-07 (dana)"].metadata
    running = by["Claude Code running on dev-laptop-07.corp.example (uid-1000)"]
    assert running.metadata["lifecycle"]["states"] == ["configured", "running"]

    # Idempotent: a second pass replaces, never duplicates.
    correlate_lifecycle(result.findings)
    assert sum(e.signal == "lifecycle:observed-running" for e in claude.evidence) == 1
