"""Endpoint mode: well-known AI client locations under a profile, scanned without walking the home directory."""

from __future__ import annotations

import json
import os
from pathlib import Path

from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.endpoint import CLIENTS, default_label, describe, endpoint_paths

MCP = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"]}}}\n'
SKILL = "---\nname: formatter\ndescription: Format SQL before pasting it into tickets.\n---\n# Formatter\nUse sqlfluff.\n"


def _profile(home: Path) -> None:
    (home / ".config" / "Claude").mkdir(parents=True)
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(MCP)
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(MCP)
    (home / ".claude" / "skills" / "formatter").mkdir(parents=True)
    (home / ".claude" / "skills" / "formatter" / "SKILL.md").write_text(SKILL)
    (home / ".claude.json").write_text(MCP)
    (home / "Documents").mkdir()
    (home / "Documents" / "notes.txt").write_text("groceries\n")


def test_endpoint_paths_lists_existing_locations_in_a_stable_order(tmp_path: Path):
    _profile(tmp_path)
    found = endpoint_paths(tmp_path, env={})
    assert [(client, path.relative_to(tmp_path).as_posix()) for client, path in found] == [
        ("claude-desktop", ".config/Claude/claude_desktop_config.json"),
        ("claude-code", ".claude.json"),
        ("claude-code", ".claude/skills"),
        ("cursor", ".cursor/mcp.json"),
    ]
    assert endpoint_paths(tmp_path, env={}) == found


def test_endpoint_paths_honours_windows_bases_and_skips_links(tmp_path: Path):
    appdata = tmp_path / "AppData" / "Roaming"
    (appdata / "Claude").mkdir(parents=True)
    (appdata / "Claude" / "claude_desktop_config.json").write_text(MCP)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "mcp.json").write_text(MCP)
    (tmp_path / ".cursor").mkdir()
    os.symlink(tmp_path / "elsewhere" / "mcp.json", tmp_path / ".cursor" / "mcp.json")
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "settings.json").write_text(MCP)
    found = endpoint_paths(tmp_path, env={"APPDATA": str(appdata)})
    assert [(client, path.name) for client, path in found] == [
        ("claude-desktop", "claude_desktop_config.json"),
        ("gemini-cli", "settings.json"),
    ]
    assert "cursor" in CLIENTS
    assert describe(found, tmp_path)[1].endswith(".gemini/settings.json")


def test_default_label_is_a_safe_resource_prefix():
    assert default_label("dev-laptop.corp") == "endpoint:dev-laptop.corp"
    assert default_label("bad host/name") == "endpoint:bad-host-name"
    assert default_label("") == "endpoint:host"


def test_endpoint_command_scans_only_the_known_locations(tmp_path: Path):
    _profile(tmp_path)
    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        main,
        [
            "endpoint",
            "--home",
            str(tmp_path),
            "--label",
            "endpoint:laptop-1",
            "--format",
            "json",
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text())
    assert report["summary"]["complete"] is True
    kinds = {f["kind"] for f in report["findings"]}
    assert "mcp-server" in kinds and "agent-config" in kinds
    assert all(f["resource"].startswith("endpoint:laptop-1") for f in report["findings"])
    titles = " ".join(f["title"] for f in report["findings"])
    assert (
        "claude_desktop_config.json" in titles and ".cursor/mcp.json" in titles and ".claude.json" in titles
    )


def test_endpoint_list_prints_locations_without_scanning(tmp_path: Path):
    _profile(tmp_path)
    result = CliRunner().invoke(main, ["endpoint", "--home", str(tmp_path), "--list"])
    assert result.exit_code == 0, result.output
    assert "claude-desktop" in result.output and ".cursor/mcp.json" in result.output
    assert "Documents" not in result.output


def test_endpoint_without_known_locations_is_a_complete_empty_scan(tmp_path: Path):
    (tmp_path / "Documents").mkdir()
    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        main, ["endpoint", "--home", str(tmp_path), "--format", "json", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text())
    assert report["findings"] == [] and report["summary"]["complete"] is True
    assert any("no known AI client configuration" in w for s in report["stats"] for w in s["warnings"])
