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
    found = endpoint_paths(tmp_path)
    assert [(client, path.relative_to(tmp_path).as_posix()) for client, path in found] == [
        ("claude-desktop", ".config/Claude/claude_desktop_config.json"),
        ("claude-code", ".claude.json"),
        ("claude-code", ".claude/skills"),
        ("cursor", ".cursor/mcp.json"),
    ]
    assert endpoint_paths(tmp_path) == found


def test_endpoint_paths_find_the_profiles_appdata_and_skip_links(tmp_path: Path):
    appdata = tmp_path / "AppData" / "Roaming"
    (appdata / "Claude").mkdir(parents=True)
    (appdata / "Claude" / "claude_desktop_config.json").write_text(MCP)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "mcp.json").write_text(MCP)
    (tmp_path / ".cursor").mkdir()
    os.symlink(tmp_path / "elsewhere" / "mcp.json", tmp_path / ".cursor" / "mcp.json")
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "settings.json").write_text(MCP)
    errors: list[str] = []
    found = endpoint_paths(tmp_path, errors=errors)
    assert [(client, path.name) for client, path in found] == [
        ("claude-desktop", "claude_desktop_config.json"),
        ("gemini-cli", "settings.json"),
    ]
    assert "cursor" in CLIENTS
    assert describe(found, tmp_path)[1].endswith(".gemini/settings.json")
    assert errors == ["cursor: .cursor/mcp.json: known configuration location could not be inspected safely"]


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


def test_endpoint_linked_configuration_is_incomplete(tmp_path: Path):
    target = tmp_path / "elsewhere.json"
    target.write_text(MCP)
    (tmp_path / ".mcp.json").symlink_to(target)
    result = CliRunner().invoke(main, ["endpoint", "--home", str(tmp_path), "--format", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False


def test_endpoint_denied_configuration_is_incomplete(tmp_path: Path, monkeypatch):
    from shadowscan import endpoint as module

    def denied(path, home):
        raise PermissionError("private configuration")

    monkeypatch.setattr(module, "_exists_without_links", denied)
    result = CliRunner().invoke(main, ["endpoint", "--home", str(tmp_path), "--format", "json"])
    assert result.exit_code == 3, result.output
    assert json.loads(result.output)["summary"]["complete"] is False
    assert "private configuration" not in result.output


def test_endpoint_include_does_not_read_unselected_auxiliary_files(tmp_path: Path, monkeypatch):
    from shadowscan.connectors.code import walk

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text("{}")
    (tmp_path / ".claude/setup.py").write_text("from setuptools import setup\nsetup()\n")
    (tmp_path / ".gitmodules").write_text("malformed [submodule")
    (tmp_path / "CODEOWNERS").symlink_to(tmp_path / "absent")

    def forbidden_read(path):
        raise AssertionError("unselected packaging script was read")

    monkeypatch.setattr(walk, "_packaging_setup_script", forbidden_read)
    result = CliRunner().invoke(main, ["endpoint", "--home", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["summary"]["complete"] is True


def _endpoint_report(home: Path, out: Path, *extra: str) -> tuple[int, dict]:
    args = ["endpoint", "--home", str(home), "--format", "json", "-o", str(out), *extra]
    result = CliRunner().invoke(main, args)
    return result.exit_code, json.loads(out.read_text())


def test_endpoint_home_reads_the_profiles_own_appdata(tmp_path: Path, monkeypatch):
    # A mounted Windows profile: its AppData, never the scanning process's %APPDATA%.
    home = tmp_path / "Users" / "bob"
    (home / "AppData" / "Roaming" / "Claude").mkdir(parents=True)
    (home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json").write_text(MCP)
    operator = tmp_path / "operator" / "AppData" / "Roaming"
    (operator / "Claude").mkdir(parents=True)
    (operator / "Claude" / "claude_desktop_config.json").write_text(
        MCP.replace("filesystem", "operator-only")
    )
    for appdata in (None, str(operator)):
        if appdata is None:
            monkeypatch.delenv("APPDATA", raising=False)
        else:
            monkeypatch.setenv("APPDATA", appdata)
        listed = CliRunner().invoke(main, ["endpoint", "--home", str(home), "--list"])
        assert listed.exit_code == 0, listed.output
        assert "AppData/Roaming/Claude/claude_desktop_config.json" in listed.output
        assert str(operator) not in listed.output
        code, report = _endpoint_report(home, tmp_path / "bob.json", "--label", "endpoint:bob")
        assert code == 0
        assert report["summary"]["complete"] is True
        resources = [f["resource"] for f in report["findings"]]
        assert any("AppData/Roaming/Claude/claude_desktop_config.json" in r for r in resources), resources
        assert "operator-only" not in json.dumps(report)


def test_endpoint_incremental_reads_no_file_outside_the_known_locations(tmp_path: Path, monkeypatch):
    from shadowscan import incremental

    home = tmp_path / "home"
    home.mkdir()
    _profile(home)
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("not a real key\n")
    (home / "Documents" / "diary.txt").write_text("private\n")
    opened: list[Path] = []
    original = incremental._file_digest

    def recorded(path, *args, **kwargs):
        opened.append(Path(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(incremental, "_file_digest", recorded)
    state = ["--incremental", "--state-dir", str(tmp_path / "state")]
    for _ in range(2):
        code, report = _endpoint_report(home, tmp_path / "report.json", *state)
        assert code == 0
        assert report["summary"]["complete"] is True and report["findings"]
    private = {
        home / ".ssh" / "id_ed25519",
        home / "Documents" / "diary.txt",
        home / "Documents" / "notes.txt",
    }
    assert not private & set(opened)


def test_endpoint_reports_without_known_locations_stay_comparable(tmp_path: Path):
    busy, empty = tmp_path / "busy", tmp_path / "empty"
    for home in (busy, empty):
        home.mkdir()
    _profile(busy)
    (empty / "Documents").mkdir()
    reports = []
    for name, home in (("busy", busy), ("empty", empty)):
        out = tmp_path / f"{name}.json"
        code, report = _endpoint_report(home, out, "--label", f"endpoint:{name}")
        assert code == 0
        assert report["collection_scope"]["comparable"] is True
        reports.append(str(out))
    fleet = tmp_path / "fleet.json"
    merged = CliRunner().invoke(main, ["merge", *reports, "--format", "json", "-o", str(fleet)])
    assert merged.exit_code == 0, merged.output
    assert json.loads(fleet.read_text())["collection_scope"]["comparable"] is True
    compared = CliRunner().invoke(main, ["diff", str(fleet), str(fleet)])
    assert compared.exit_code == 0, compared.output
    # A client configured later is a new finding, not a change of collection scope.
    (empty / ".cursor").mkdir()
    (empty / ".cursor" / "mcp.json").write_text(MCP)
    code, _ = _endpoint_report(empty, tmp_path / "later.json", "--label", "endpoint:empty")
    assert code == 0
    compared = CliRunner().invoke(main, ["diff", "--json", reports[1], str(tmp_path / "later.json")])
    assert compared.exit_code == 0, compared.output
    comparison = json.loads(compared.output)
    assert comparison["comparable"] is True and comparison["new"]


def test_endpoint_covers_every_endpoint_inventory_configuration_location():
    from shadowscan.connectors.endpoint.catalog import CONFIG_LOCATIONS
    from shadowscan.endpoint import CLIENT_DIRECTORIES, LOCATIONS

    covered = [location.relative for location in LOCATIONS]
    assert len(covered) == len(set(covered))
    for location in CONFIG_LOCATIONS:
        # Whole client directories (session logs, caches, agent memory) are
        # never walked; only their configuration files are listed.
        assert location.path in covered or (location.directory and location.path in CLIENT_DIRECTORIES), (
            location.path
        )
    assert {".copilot/mcp-config.json", ".kiro/settings/mcp.json", ".openclaw/openclaw.json"} <= set(covered)
    assert not CLIENT_DIRECTORIES & set(covered)


def test_endpoint_reads_cline_inside_cursor(tmp_path: Path):
    home = tmp_path / "home"
    settings = home / ".config/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings"
    settings.mkdir(parents=True)
    (settings / "cline_mcp_settings.json").write_text(MCP)
    code, report = _endpoint_report(home, tmp_path / "report.json")
    assert code == 0
    assert any("cline_mcp_settings.json" in f["resource"] for f in report["findings"])


def test_endpoint_default_home_may_pass_through_a_symlink(tmp_path: Path, monkeypatch):
    # FreeBSD (/home -> /usr/home) and image-based Fedora (/home -> var/home).
    real = tmp_path / "var" / "home" / "dev"
    real.mkdir(parents=True)
    _profile(real)
    (tmp_path / "home").symlink_to(tmp_path / "var" / "home")
    monkeypatch.setenv("HOME", str(tmp_path / "home" / "dev"))
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["endpoint", "--format", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text())
    assert report["summary"]["complete"] is True and report["findings"]


def test_endpoint_scans_safe_locations_beside_a_linked_one(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    _profile(home)
    (tmp_path / "dotfiles").mkdir()
    (tmp_path / "dotfiles" / "settings.json").write_text("{}")
    (home / ".claude" / "settings.json").symlink_to(tmp_path / "dotfiles" / "settings.json")
    code, report = _endpoint_report(home, tmp_path / "report.json")
    assert code == 3
    assert report["summary"]["complete"] is False
    resources = " ".join(f["resource"] for f in report["findings"])
    assert ".cursor/mcp.json" in resources and "claude_desktop_config.json" in resources
    errors = [e for s in report["stats"] for e in s["errors"]]
    assert any("could not be inspected safely" in e for e in errors), errors


def test_endpoint_linked_directory_without_known_locations_stays_complete(tmp_path: Path):
    # GNU stow can fold a whole ~/.config into one link. Nothing the scan looks
    # for exists through it, so the profile scan is complete; a known location
    # behind the link still makes it incomplete, and is not read.
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(MCP)
    config = tmp_path / "dotfiles" / "config"
    (config / "nvim").mkdir(parents=True)
    (config / "nvim" / "init.vim").write_text("set number\n")
    (home / ".config").symlink_to(config)
    code, report = _endpoint_report(home, tmp_path / "report.json")
    assert code == 0, report["stats"]
    assert report["summary"]["complete"] is True and report["findings"]
    (config / "Claude").mkdir()
    (config / "Claude" / "claude_desktop_config.json").write_text(MCP)
    code, report = _endpoint_report(home, tmp_path / "report.json")
    assert code == 3
    assert report["summary"]["complete"] is False
    assert "claude_desktop_config.json" not in " ".join(f["resource"] for f in report["findings"])


def test_include_walk_passes_over_a_link_with_no_selected_path_behind_it(tmp_path: Path, run_connector):
    root, shared = tmp_path / "root", tmp_path / "shared"
    root.mkdir()
    (shared / "guides").mkdir(parents=True)
    (shared / "guides" / "style.md").write_text("Use tabs.\n")
    (root / "docs").symlink_to(shared)
    (root / ".mcp.json").write_text(MCP)
    include = ["docs/agents/AGENTS.md", ".mcp.json"]
    findings, ctx = run_connector("code.filesystem", path=str(root), include=include, use_git=False)
    assert findings and not ctx.stats.incomplete and not ctx.stats.errors, ctx.stats.warnings
    (shared / "agents").mkdir()
    (shared / "agents" / "AGENTS.md").write_text("Run the tests before committing.\n")
    findings, ctx = run_connector("code.filesystem", path=str(root), include=include, use_git=False)
    assert ctx.stats.incomplete
    assert not any("AGENTS.md" in finding.resource for finding in findings)
