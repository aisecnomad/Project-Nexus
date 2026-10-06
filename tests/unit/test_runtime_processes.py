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
from shadowscan.models import Finding, Kind, Surface

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


ROOT_STATUS = "Gid:\t0\t0\t0\t0\nGroups:\t\n"
HOST_GIDS = "         0          0 4294967295\n"


def _proc_self(
    proc,
    monkeypatch,
    *,
    initial=True,
    options="rw",
    status=ROOT_STATUS,
    gid_map=HOST_GIDS,
    mountinfo=None,
):
    """The parts of /proc/self that the restricted-view check reads, for a fake /proc tree."""
    (proc / "self" / "ns").mkdir(parents=True, exist_ok=True)
    link = proc / "self" / "ns" / "pid"
    link.write_text("pid")
    if initial:
        # Stands in for the initial PID namespace's fixed inode number.
        monkeypatch.setattr(runtime_processes, "_INIT_PID_NS_INO", link.stat().st_ino)
    if mountinfo is None:
        mountinfo = f"22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc {options}\n"
    (proc / "self" / "mountinfo").write_text(mountinfo)
    (proc / "self" / "status").write_text(status)
    (proc / "self" / "gid_map").write_text(gid_map)


def test_live_mode_reads_proc(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
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


@pytest.mark.parametrize(
    ("value", "pid"),
    [
        (4242, 4242),
        ("4242", 4242),
        ("٤٢", None),
        ("²", None),
        (True, None),
        (-1, None),
        ("4419516131012", 4419516131012),  # CrowdStrike's TargetProcessId is a 64-bit id
        (2**64 - 1, 2**64 - 1),
        (2**64, None),
        ("1" * 21, None),
        (None, None),
    ],
)
def test_export_pids_are_plain_decimal(value, pid):
    assert runtime_processes._pid(value) == pid


def test_non_decimal_pid_does_not_lose_the_export(run_connector, tmp_path):
    rows = [
        {"host": "box", "user": "dana", "pid": "²", "cmdline": "claude -p hi"},
        {"host": "box", "user": "dana", "pid": "7", "cmdline": "codex exec fix"},
    ]
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert not ctx.stats.errors
    assert sorted(f.title.split(" running on ")[0] for f in findings) == ["Claude Code", "OpenAI Codex CLI"]


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ({}, None),
        # A container's own /proc shows a single NSpid entry, as the host's does; the inode tells them apart.
        ({"initial": False}, "separate PID namespace"),
        ({"options": "rw,subset=pid"}, None),  # hides only entries that are not processes
        ({"options": "rw,hidepid=off"}, None),
        ({"options": "rw,hidepid=invisible"}, None),  # root is in the default gid=0 group
        ({"options": "rw,hidepid=2"}, None),  # older kernels print the number
        ({"options": "rw,hidepid=invisible,gid=1000"}, "hidepid=invisible"),
        (
            {
                "options": "rw,hidepid=invisible,gid=1000",
                "status": "Gid:\t1000\t1000\t1000\t1000\nGroups:\t27\n",
            },
            None,
        ),
        (
            {"options": "rw,hidepid=noaccess", "status": "Gid:\t1000\t1000\t1000\t1000\nGroups:\t\n"},
            "noaccess",
        ),
        (
            {"options": "rw,hidepid=ptraceable"},
            "hidepid=ptraceable",
        ),  # hides untraceable processes from root too
        ({"options": "rw,hidepid=invisible", "gid_map": "0 100000 65536\n"}, "hidepid=invisible"),
        ({"options": "rw,hidepid=invisible,gid=1000", "status": "Gid:\t0\t0\t0\t0\nGroups:\t1000\n"}, None),
        (
            {
                "mountinfo": (
                    "22 1 0:21 / /proc rw - proc proc rw,hidepid=invisible,gid=1000\n"
                    "40 22 0:35 / /proc rw - proc proc rw\n"
                )
            },
            None,  # the last mount on /proc is the one that is read
        ),
        ({"mountinfo": "22 1 0:21 / /sys rw - sysfs sysfs rw\n"}, "mount options of /proc"),
    ],
)
def test_restricted_proc_view(monkeypatch, tmp_path, setup, reason):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch, **setup)
    found = runtime_processes._restricted_view(proc)
    assert (found is None) if reason is None else (reason in found)


def test_proc_namespace_is_read_from_pid_one_when_visible(monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch, initial=False)
    (proc / "1" / "ns").mkdir(parents=True)
    init = proc / "1" / "ns" / "pid"
    init.write_text("pid")
    # /proc/1 is the init of the namespace this procfs belongs to; it decides over /proc/self.
    monkeypatch.setattr(runtime_processes, "_INIT_PID_NS_INO", init.stat().st_ino)
    assert runtime_processes._restricted_view(proc) is None
    monkeypatch.setattr(runtime_processes, "_INIT_PID_NS_INO", 0xEFFFFFFC)
    assert "separate PID namespace" in runtime_processes._restricted_view(proc)
    init.unlink()
    (proc / "self" / "ns" / "pid").unlink()
    assert "could not be determined" in runtime_processes._restricted_view(proc)


def test_live_scan_in_a_container_is_incomplete_not_empty(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch, initial=False)
    (proc / "11").mkdir()
    (proc / "11" / "cmdline").write_bytes(b"claude\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert len(findings) == 1
    assert ctx.stats.incomplete
    assert any("not every process is visible" in w and "PID namespace" in w for w in ctx.stats.warnings)


def test_lifecycle_links_tools_without_a_signature_by_tool_id(index, tmp_path):
    home = tmp_path / "dana"
    (home / ".config" / "Claude").mkdir(parents=True)
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    )
    (home / ".kiro" / "settings").mkdir(parents=True)
    (home / ".kiro" / "settings" / "mcp.json").write_text(json.dumps({"mcpServers": {}}))
    rows = [
        {"host": "lap", "user": "dana", "path": "/Applications/Claude.app/Contents/MacOS/Claude"},
        {"host": "lap", "user": "dana", "cmdline": "kiro-cli chat"},
    ]
    config = ScanConfig(
        connectors=[
            ConnectorSpec("endpoint.inventory", {"path": str(home), "label": "lap"}),
            ConnectorSpec("runtime.processes", {"input": str(_rows(tmp_path, rows))}),
        ]
    )
    result = Engine(config, index).run()
    configured = {f.title: f for f in result.findings if f.resource_type == "agent-config"}
    claude = next(f for t, f in configured.items() if t.startswith("Claude Desktop configured"))
    assert (
        "observed-running" in claude.tags
        and "tool:claude-desktop" in claude.metadata["lifecycle"]["subjects"]
    )
    kiro = next(f for t, f in configured.items() if t.startswith("Kiro configured"))
    assert "observed-running" in kiro.tags


def test_lifecycle_ignores_malformed_server_args(index, tmp_path):
    record = {
        "device": "lap",
        "home": "dana",
        "record_type": "agent_config",
        "client": "cursor",
        "product": "Cursor",
        "signature": "coding-agent.cursor",
        "mcp_servers": [{"name": "github", "command": "npx", "args": 5}],
    }
    records = tmp_path / "records.jsonl"
    records.write_text(json.dumps(record))
    rows = [{"host": "lap", "user": "dana", "cmdline": "npx -y @modelcontextprotocol/server-github"}]
    config = ScanConfig(
        connectors=[
            ConnectorSpec("endpoint.inventory", {"input": str(records)}),
            ConnectorSpec("runtime.processes", {"input": str(_rows(tmp_path, rows))}),
        ]
    )
    result = Engine(config, index).run()
    assert not result.complete
    assert not any(s.errors for s in result.stats)
    # The malformed server is dropped with a warning; the rest of the record is kept.
    assert any(f.title.startswith("Cursor configured") for f in result.findings)
    # The engine's lifecycle pass also tolerates such a server if one ever reaches it.
    rogue = Finding(
        surface=Surface.ENDPOINT,
        connector="endpoint.inventory",
        kind=Kind.MCP_SERVER,
        title="MCP servers configured for Cursor on lap (~dana)",
        resource="endpoint:lap:dana:mcp-config:cursor",
        resource_type="mcp-config",
        account="lap",
        metadata={"servers": [{"name": "github", "args": 5}, {"name": "x", "args": ["@scope/pkg"]}]},
    )
    correlate_lifecycle([rogue, *result.findings])
    assert "lifecycle" not in rogue.metadata
