"""endpoint.inventory: home directory and osquery inventory of AI tools, agents and models."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.endpoint.inventory import (
    EndpointInventoryConnector,
    _history_tool,
    _home_from_path,
    _osquery_extension_id,
    _valid_server,
    _version_key,
)
from shadowscan.models import Kind, Surface
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "endpoint"
needs_symlinks = pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")


def write(root: Path, rel: str, text: str | bytes = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text)
    return path


def scan(run_connector, home: Path, **config):
    findings, ctx = run_connector("endpoint.inventory", path=str(home), label="laptop", **config)
    return {f.title.split(" on laptop")[0]: f for f in findings}, ctx.stats


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "dana"
    write(h, ".bashrc", "alias ll='ls -l'\n")
    write(h, ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}))
    write(h, ".claude/agents/reviewer.md", "---\nname: reviewer\n---\n")
    write(
        h,
        ".claude.json",
        json.dumps(
            {
                "numStartups": 4,
                "mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}},
                "projects": {
                    "/home/dana/app": {"mcpServers": {"db": {"url": "http://db.internal:9000/mcp"}}}
                },
            }
        ),
    )
    write(
        h,
        ".cursor/mcp.json",
        json.dumps({"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-mcp"]}}}),
    )
    write(
        h,
        ".codex/config.toml",
        'approval_policy = "never"\n[mcp_servers.docs]\nurl = "https://mcp.example.com/mcp"\n',
    )
    write(
        h,
        ".config/goose/config.yaml",
        "GOOSE_MODE: auto\nextensions:\n  developer:\n    type: builtin\n    enabled: true\n"
        "  github:\n    type: stdio\n    cmd: npx\n    args: ['-y', '@modelcontextprotocol/server-github']\n"
        "    enabled: true\n  remote:\n    type: sse\n    uri: https://mcp.example.org/sse\n    enabled: false\n",
    )
    write(h, ".aider.conf.yml", "model: sonnet\n")
    write(h, ".kiro/steering/notes.md", "x\n")
    write(h, ".vscode/extensions/github.copilot-1.388.0/package.json", "{}")
    write(h, ".vscode/extensions/ms-python.python-2025.14.0/package.json", "{}")
    write(h, ".cursor/extensions/saoudrizwan.claude-dev-3.31.0-linux-x64/package.json", "{}")
    write(h, ".vscode/extensions/extensions.json", "[]")
    chrome = ".config/google-chrome/Default/Extensions"
    write(h, f"{chrome}/aaaa/1.0.0_0/manifest.json", json.dumps({"name": "Claude", "version": "1.0.0"}))
    write(h, f"{chrome}/aaaa/1.2.0_0/manifest.json", json.dumps({"name": "Claude", "version": "1.2.0"}))
    write(
        h,
        f"{chrome}/bbbb/2.0_0/manifest.json",
        json.dumps({"name": "__MSG_appName__", "default_locale": "en"}),
    )
    write(
        h,
        f"{chrome}/bbbb/2.0_0/_locales/en/messages.json",
        json.dumps({"APPNAME": {"message": "Sider: ChatGPT Sidebar"}}),
    )
    write(h, f"{chrome}/cccc/3.0_0/manifest.json", json.dumps({"name": "uBlock Origin"}))
    write(h, ".config/google-chrome/Local State", "{}")
    write(
        h,
        ".mozilla/firefox/abc.default/extensions.json",
        json.dumps(
            {
                "addons": [
                    {
                        "id": "p@ai",
                        "type": "extension",
                        "version": "2",
                        "defaultLocale": {"name": "Perplexity AI Companion"},
                    },
                    {"id": "dr@x", "type": "extension", "defaultLocale": {"name": "Dark Reader"}},
                    {"id": "t@x", "type": "theme", "defaultLocale": {"name": "ChatGPT Theme"}},
                ]
            }
        ),
    )
    write(h, ".ollama/models/manifests/registry.ollama.ai/library/llama3.1/8b", "{}")
    write(h, ".ollama/models/manifests/registry.ollama.ai/acme/coder/latest", "{}")
    write(h, ".lmstudio/models/lmstudio-community/Meta-Llama/model.Q4_K_M.gguf", b"GGUF")
    write(h, ".lmstudio/models/README.txt", "x")
    write(h, ".cache/huggingface/hub/models--Qwen--Qwen2.5-7B/refs/main", "abc")
    write(h, ".cache/huggingface/hub/datasets--x--y/refs/main", "abc")
    write(
        h,
        ".zsh_history",
        ": 1727690000:0;claude -p 'explain'\n: 1727690001:0;git status\n: 1727690002:0;sudo ollama run llama3.1\n",
    )
    write(h, ".bash_history", "FOO=1 aider app.py\ngh copilot suggest x\n/usr/local/bin/codex exec fix\n")
    write(h, ".local/share/fish/fish_history", "- cmd: gemini\n  when: 1727690000\n- cmd: ls\n")
    return h


def test_home_inventory_finds_configs_extensions_models_and_history(run_connector, home):
    found, stats = scan(run_connector, home, shell_history=True)
    assert not stats.errors and not stats.warnings and not stats.incomplete

    claude = found["Claude Code configured"]
    assert claude.surface == Surface.ENDPOINT and claude.kind == Kind.AGENT_CONFIG
    assert "posture-permissions-bypassed" in claude.tags
    assert claude.metadata["files"] == ["~/.claude.json", "~/.claude/agents", "~/.claude/settings.json"]
    assert claude.metadata["shell_history_count"] == 1
    assert claude.owner == "dana" and claude.account == "laptop"

    claude_mcp = found["MCP servers configured for Claude Code"]
    assert {s["name"] for s in claude_mcp.metadata["servers"]} == {"fetch", "db"}
    assert {"mcp-unpinned-package", "mcp-insecure-transport"} <= set(claude_mcp.tags)

    goose_mcp = found["MCP servers configured for Goose"]
    assert {s["name"]: s["disabled"] for s in goose_mcp.metadata["servers"]} == {
        "github": False,
        "remote": True,
    }
    assert "posture-permissions-bypassed" in found["Goose configured"].tags
    assert "posture-permissions-bypassed" in found["OpenAI Codex CLI configured"].tags
    assert found["Kiro configured"].kind == Kind.AI_APP
    assert found["Aider configured"].metadata["shell_history_count"] == 1

    assert found["AI editor extension installed: GitHub Copilot"].kind == Kind.AI_APP
    cline = found["AI editor extension installed: Cline"]
    assert cline.kind == Kind.AGENT_CONFIG and cline.metadata["editors"] == ["Cursor"]
    assert not any("Python" in title for title in found)

    claude_ext = found["AI browser extension installed: Claude (Chrome)"]
    assert claude_ext.kind == Kind.AI_APP and claude_ext.metadata["versions"] == ["1.2.0"]
    assert "AI browser extension installed: Sider: ChatGPT Sidebar (Chrome)" in found
    assert "AI browser extension installed: Perplexity AI Companion (Firefox)" in found
    assert not any("uBlock" in t or "Dark Reader" in t or "Theme" in t for t in found)

    ollama = found["Local models stored for Ollama"]
    assert ollama.kind == Kind.LOCAL_MODEL and ollama.models == ["acme/coder:latest", "llama3.1:8b"]
    assert ollama.model_providers == ["provider.ollama"]
    assert found["Local models stored for LM Studio"].metadata["models"] == ["model.Q4_K_M.gguf"]
    assert found["Local models stored for Hugging Face cache"].metadata["models"] == ["Qwen/Qwen2.5-7B"]

    assert found["AI command-line tool used: GitHub Copilot CLI"].metadata["shell_history_count"] == 1
    assert "OpenAI Codex CLI configured" in found and "Gemini CLI configured" not in found
    assert found["AI command-line tool used: Gemini CLI"].kind == Kind.AI_APP


def test_shell_history_is_opt_in(run_connector, home):
    found, _ = scan(run_connector, home)
    assert not any(t.startswith("AI command-line tool used") for t in found)
    assert "shell_history_count" not in found["Claude Code configured"].metadata


def test_empty_home_has_no_findings_and_is_complete(run_connector, tmp_path):
    found, stats = scan(run_connector, tmp_path)
    assert found == {} and not stats.incomplete


@needs_symlinks
def test_symlinked_config_and_extension_entry_are_gaps_not_followed(run_connector, tmp_path):
    target = write(
        tmp_path, "dotfiles/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    )
    (tmp_path / "home" / ".claude").mkdir(parents=True)
    (tmp_path / "home" / ".claude" / "settings.json").symlink_to(target)
    (tmp_path / "home" / ".vscode" / "extensions").mkdir(parents=True)
    (tmp_path / "home" / ".vscode" / "extensions" / "github.copilot-1.0.0").symlink_to(tmp_path / "dotfiles")
    found, stats = scan(run_connector, tmp_path / "home")
    assert stats.incomplete
    assert any("symbolic link not followed" in w for w in stats.warnings)
    assert any("symbolic link(s) not followed" in w for w in stats.warnings)
    assert found == {}


@needs_symlinks
def test_symlinked_home_is_refused(run_connector, tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    found, stats = scan(run_connector, tmp_path / "link")
    assert found == {} and stats.incomplete and stats.errors


def test_missing_home_is_an_error(run_connector, tmp_path):
    found, stats = scan(run_connector, tmp_path / "absent")
    assert found == {} and stats.incomplete and "cannot open home directory" in stats.errors[0]


def test_unreadable_location_and_oversized_config_are_gaps(run_connector, tmp_path):
    write(tmp_path, ".cursor/mcp.json", "{" + " " * (1024 * 1024 + 10) + "}")
    fifo_parent = tmp_path / ".codex"
    fifo_parent.mkdir()
    os.mkfifo(fifo_parent / "config.toml")
    write(tmp_path, ".gemini", "a file where a directory is expected")
    found, stats = scan(run_connector, tmp_path)
    assert stats.incomplete
    warnings = " ".join(stats.warnings)
    assert "larger than" in warnings and "not a regular file" in warnings
    assert found == {}


def test_entry_budget_is_reported(run_connector, home):
    _, stats = scan(run_connector, home, max_entries=3)
    assert stats.incomplete and any("entry budget" in w for w in stats.warnings)


def test_invalid_mcp_configuration_is_a_gap(run_connector, tmp_path):
    write(tmp_path, ".cursor/mcp.json", '{"mcpServers": {"x": {"command": 7}}}')
    write(tmp_path, ".claude.json", "not json")
    write(tmp_path, ".config/goose/config.yaml", "extensions: [unclosed")
    found, stats = scan(run_connector, tmp_path)
    assert stats.incomplete
    assert "Cursor configured" in found and "Claude Code configured" in found


@pytest.mark.parametrize(
    "config",
    [
        {"path": "/a", "paths": ["/b"]},
        {"paths": []},
        {"paths": "/home"},
        {"paths": [""]},
        {"path": ""},
        {"path": 3},
        {"max_entries": 0},
        {"shell_history": "yes"},
    ],
)
def test_invalid_configuration_is_refused(config):
    with pytest.raises(ConnectorError):
        EndpointInventoryConnector(ConnectorContext(config=config, index=get_index()))


def test_paths_and_default_home(run_connector, home, tmp_path, monkeypatch):
    other = tmp_path / "sam"
    write(
        other, ".cursor/mcp.json", json.dumps({"mcpServers": {"x": {"url": "https://mcp.example.com/mcp"}}})
    )
    findings, ctx = run_connector("endpoint.inventory", paths=[str(home), str(other)], label="lab")
    assert {f.owner for f in findings} == {"dana", "sam"}
    monkeypatch.setenv("HOME", str(other))
    findings, ctx = run_connector("endpoint.inventory", label="lab")
    assert {f.owner for f in findings} == {"sam"} and not ctx.stats.incomplete


def test_scanned_local_paths():
    assert EndpointInventoryConnector.scanned_local_paths({"path": "/home/a"}) == ["/home/a"]
    assert EndpointInventoryConnector.scanned_local_paths({"paths": ["/h/a", 3]}) == ["/h/a"]
    assert EndpointInventoryConnector.scanned_local_paths({"input": "x.json", "path": "/h"}) == []
    assert EndpointInventoryConnector.scanned_local_paths({}) == []


def test_replayed_records(run_connector):
    findings, ctx = run_connector("endpoint.inventory", input=str(FIXTURES / "inventory.jsonl"))
    assert not ctx.stats.warnings and not ctx.stats.errors
    by_title = {f.title: f for f in findings}
    mcp = by_title["MCP servers configured for Cursor on dev-laptop-07 (~dana)"]
    assert {"mcp-unpinned-package", "mcp-broad-filesystem", "mcp-auto-approve"} <= set(mcp.tags)
    assert by_title["Claude Code configured on dev-laptop-07 (~dana)"].metadata["shell_history_count"] == 41
    assert "AI command-line tool used: Ollama on dev-laptop-07 (~dana)" in by_title
    assert len(findings) == 9


def test_osquery_rows_keep_only_ai_products(run_connector):
    findings, ctx = run_connector(
        "endpoint.inventory", input=str(FIXTURES / "osquery_results.json"), label="fleet"
    )
    assert not ctx.stats.warnings
    assert sorted(f.title for f in findings) == [
        "AI browser extension installed: Monica - Your ChatGPT AI Assistant (Chrome) on fleet (~sam)",
        "AI browser extension installed: Perplexity - AI Companion (Firefox) on fleet (~sam)",
        "AI editor extension installed: GitHub Copilot on fleet (~sam)",
    ]


def test_osquery_logger_envelope_and_unknown_rows(run_connector, tmp_path):
    rows = [
        {
            "hostIdentifier": "mac-12",
            "columns": {
                "name": "claude-dev",
                "publisher": "saoudrizwan",
                "uuid": "u",
                "uid": "501",
                "version": "3",
            },
        },
        {
            "hostIdentifier": "mac-12",
            "columns": {
                "username": "lee",
                "browser_type": "chrome",
                "identifier": "abc",
                "name": "ChatGPT for Google",
                "path": "/Users/shared/Library/Application Support/Google/Chrome/Default/Extensions/abc",
            },
        },
        {"something": "else"},
        {"record_type": "local_model", "runtime": 5},
        {"record_type": "shell_history", "tool": "claude", "count": "many"},
        {
            "record_type": "agent_config",
            "client": "codex",
            "posture": [{"id": "bogus"}, "x"],
            "mcp_servers": ["x"],
        },
    ]
    path = write(tmp_path, "rows.json", json.dumps(rows))
    findings, ctx = run_connector("endpoint.inventory", input=str(path), label="fleet")
    titles = sorted(f.title for f in findings)
    assert titles == [
        "AI browser extension installed: ChatGPT for Google (Chrome) on mac-12 (~lee)",
        "AI editor extension installed: Cline on mac-12 (~uid-501)",
        "codex configured on fleet (~unknown)",
    ]
    assert sum("malformed endpoint record" in w for w in ctx.stats.warnings) == 2
    assert any("skipped 1 record(s)" in w for w in ctx.stats.warnings)


@pytest.mark.parametrize(
    ("line", "shell", "tool"),
    [
        (": 1727690000:0;claude -p x", "zsh", "claude"),
        ("- cmd: ollama run x", "fish", "ollama"),
        ("  when: 123", "fish", None),
        ("sudo env A=1 time codex", "bash", "codex"),
        ("C:\\tools\\aider.exe --yes", "powershell", "aider"),
        ("gh copilot explain", "bash", "copilot"),
        ("gh pr list", "bash", None),
        ("q chat", "bash", None),
        ("sudo", "bash", None),
        ("", "bash", None),
    ],
)
def test_history_tool(line, shell, tool):
    assert _history_tool(line, shell) == tool


def test_small_helpers():
    assert _home_from_path("/Users/kim/.vscode/extensions/x") == "kim"
    assert _home_from_path("C:\\Users\\kim\\x") == "kim"
    assert _home_from_path("/opt/x") is None
    assert (
        _osquery_extension_id({"path": "/h/.vscode/extensions/github.copilot-chat-0.2.0"})
        == "github.copilot-chat"
    )
    assert _osquery_extension_id({"publisher": "GitHub", "name": "copilot"}) == "github.copilot"
    assert _version_key("1.10.0_0") > _version_key("1.9.3_0")


@needs_symlinks
def test_chromium_own_links_are_not_gaps_but_other_links_are(run_connector, tmp_path):
    h = tmp_path / "home"
    root = h / ".config" / "google-chrome"
    write(root, "Default/Preferences", "{}")
    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        (root / name).symlink_to(tmp_path / "elsewhere")
    found, stats = scan(run_connector, h)
    assert not stats.incomplete and not stats.warnings
    (root / "Profile 9").symlink_to(tmp_path / "elsewhere")
    found, stats = scan(run_connector, h)
    assert stats.incomplete
    assert any("1 symbolic link(s) not followed" in w for w in stats.warnings)


@needs_symlinks
def test_symlinked_directory_component_is_a_gap_not_absent(run_connector, tmp_path):
    write(tmp_path, "dotfiles/cursor/mcp.json", json.dumps({"mcpServers": {"fs": {"command": "npx"}}}))
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".cursor").symlink_to(tmp_path / "dotfiles" / "cursor")
    found, stats = scan(run_connector, tmp_path / "home")
    assert found == {}
    assert stats.incomplete
    assert any(".cursor/mcp.json" in w and "symbolic link not followed" in w for w in stats.warnings)


def test_unparseable_agent_settings_are_a_gap(run_connector, tmp_path):
    write(tmp_path, ".claude/settings.json", '{"permissions": {"defaultMode": ')
    found, stats = scan(run_connector, tmp_path)
    assert "Claude Code configured" in found
    assert stats.incomplete
    assert any("invalid configuration syntax" in w for w in stats.warnings)


def test_long_shell_history_reports_the_unread_part(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.endpoint.inventory.MAX_HISTORY_BYTES", 64)
    write(tmp_path, ".bash_history", "aider old.py\n" + "ls -la\n" * 40 + "codex exec fix\n")
    found, stats = scan(run_connector, tmp_path, shell_history=True)
    assert "AI command-line tool used: OpenAI Codex CLI" in found
    assert "AI command-line tool used: Aider" not in found
    assert stats.incomplete
    assert any("only the last 64 bytes read" in w for w in stats.warnings)


def test_claude_json_keeps_project_servers_that_reuse_a_user_scope_name(run_connector, tmp_path):
    write(
        tmp_path,
        ".claude.json",
        json.dumps(
            {
                "mcpServers": {"db": {"command": "uvx", "args": ["mcp-server-sqlite"]}},
                "projects": {
                    "/home/dana/app": {"mcpServers": {"db": {"url": "http://db.internal:9000/mcp"}}},
                    "/home/dana/other": {
                        "mcpServers": {"db": {"command": "uvx", "args": ["mcp-server-sqlite"]}}
                    },
                },
            }
        ),
    )
    found, _ = scan(run_connector, tmp_path)
    servers = found["MCP servers configured for Claude Code"].metadata["servers"]
    assert sorted(s["name"] for s in servers) == ["db", "db#2"]
    assert "mcp-insecure-transport" in found["MCP servers configured for Claude Code"].tags


def test_mcp_risks_cite_the_file_that_holds_the_servers(run_connector, tmp_path):
    write(tmp_path, ".codex/AGENTS.md", "Be careful.\n")
    write(
        tmp_path,
        ".codex/config.toml",
        '[mcp_servers.fs]\ncommand = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem", "/"]\n',
    )
    found, _ = scan(run_connector, tmp_path)
    mcp = found["MCP servers configured for OpenAI Codex CLI"]
    locations = {
        e.location for e in mcp.evidence if e.signal.startswith(("mcp-risk:", "endpoint:mcp-config"))
    }
    assert locations == {"~/.codex/config.toml"}


def test_malformed_replayed_entries_are_dropped_with_a_warning(run_connector, tmp_path):
    records = [
        {
            "device": "lap",
            "home": "dana",
            "record_type": "agent_config",
            "client": "cursor",
            "product": "Cursor",
            "location": "~/.cursor/mcp.json",
            "mcp_servers": [{"name": "a", "urls": 5}, {"name": "b", "args": 5}, "junk", {"name": "ok"}],
            "posture": ["junk", {"id": ["unhashable"], "client": "cursor", "setting": "s", "value": "v"}],
            # An approval entry with an unknown scope can never gate an action.
            "approval": ["junk", {"client": "cursor", "setting": "s", "value": "v", "scope": "all"}],
        },
        {
            "device": "lap",
            "home": "dana",
            "record_type": "agent_config",
            "client": "codex",
            "product": "Codex",
        },
        # An unhashable record type is skipped like any unknown record, not a crash.
        {"device": "lap", "home": "dana", "record_type": ["agent_config"], "client": "goose"},
    ]
    path = tmp_path / "records.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records))
    findings, ctx = run_connector("endpoint.inventory", input=str(path))
    assert not ctx.stats.errors and ctx.stats.incomplete
    assert any(
        "dropped 7 malformed server, posture, approval or model entries" in w for w in ctx.stats.warnings
    )
    titles = {f.title for f in findings}
    assert "Codex configured on lap (~dana)" in titles
    assert not [f for f in findings if "approval_gate" in f.metadata]
    mcp = next(f for f in findings if f.kind == Kind.MCP_SERVER)
    assert [s["name"] for s in mcp.metadata["servers"]] == ["ok"]


@pytest.mark.parametrize(
    ("damage", "same_group"),
    [({"entry_count": "x"}, True), ({"version": 5}, True), ({"client": ["claude-code"]}, False)],
)
def test_replay_that_skips_a_malformed_settings_record_never_claims_every_action(
    run_connector, tmp_path, damage, same_group
):
    # Regression: a whole agent_config record of the same client (here a settings file that
    # bypasses approval) was skipped as malformed, and the client's remaining every-action
    # entry still recorded an every-action gate. A skipped record whose client cannot be
    # read leaves every client's gate partial.
    base = {"device": "lap", "home": "dana", "record_type": "agent_config", "client": "claude-code"}
    gate = {
        "client": "claude-code",
        "setting": "permissions.defaultMode",
        "value": "default",
        "scope": "every-action",
        "file": "~/.claude/settings.json",
    }
    valid = {**base, "product": "Claude Code", "location": "~/.claude/settings.json", "approval": [gate]}
    bypass = {
        "id": "posture-permissions-bypassed",
        "client": "claude-code",
        "setting": "permissions.defaultMode",
        "value": "bypassPermissions",
    }
    skipped = {**base, "location": "~/.claude/settings.local.json", "posture": [bypass], **damage}
    path = tmp_path / "records.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in (valid, skipped)))
    findings, ctx = run_connector("endpoint.inventory", input=str(path))
    assert ctx.stats.incomplete
    assert any("skipped a malformed endpoint record" in w for w in ctx.stats.warnings)
    [agent] = [f for f in findings if "approval_gate" in f.metadata]
    assert agent.metadata["approval_gate"]["scope"] == "some-actions"
    assert same_group or agent.metadata["client"] == "Claude Code"


@pytest.mark.parametrize(
    "lost",
    [
        {"approval": ["junk"]},
        {"approval": [{"client": "claude-code", "setting": "permissions.allow", "value": "rules"}]},
        {"posture": [{"id": "posture-made-up", "client": "claude-code", "setting": "s", "value": "v"}]},
    ],
)
def test_replay_that_drops_approval_or_posture_entries_never_claims_every_action(
    run_connector, tmp_path, lost
):
    # Regression: the dropped entry could have been a loosening setting, yet the valid
    # every-action entry left behind recorded an every-action gate.
    gate = {
        "client": "claude-code",
        "setting": "permissions.defaultMode",
        "value": "default",
        "scope": "every-action",
        "file": "~/.claude/settings.json",
    }
    record = {
        "device": "lap",
        "home": "dana",
        "record_type": "agent_config",
        "client": "claude-code",
        "product": "Claude Code",
        "location": "~/.claude/settings.json",
        "approval": [gate, *lost.get("approval", [])],
        "posture": lost.get("posture", []),
    }
    path = tmp_path / "records.jsonl"
    path.write_text(json.dumps(record))
    findings, _ = run_connector("endpoint.inventory", input=str(path))
    [agent] = [f for f in findings if "approval_gate" in f.metadata]
    assert agent.metadata["approval_gate"]["scope"] == "some-actions"
    # The same record without the lost entry keeps its every-action gate.
    path.write_text(json.dumps({**record, "approval": [gate], "posture": []}))
    findings, _ = run_connector("endpoint.inventory", input=str(path))
    [agent] = [f for f in findings if "approval_gate" in f.metadata]
    assert agent.metadata["approval_gate"]["scope"] == "every-action"


@pytest.mark.parametrize(
    ("packages", "valid"),
    [
        (None, True),
        ([], True),
        ([{"registry_type": "npm", "identifier": "x", "version": None, "registry_base_url": None}], True),
        ("npm", False),
        (["npm"], False),
        ([{"registry_type": "npm", "identifier": 5}], False),
    ],
)
def test_replayed_manifest_packages_must_have_the_parsed_shape(packages, valid):
    server: dict[str, object] = {"name": "io.example/tool", "transport": "unknown", "disabled": False}
    if packages is not None:
        server["packages"] = packages
    assert _valid_server(server) is valid
