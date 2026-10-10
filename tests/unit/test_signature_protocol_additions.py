"""MCP servers written without an SDK, MCP directory manifests and Claude Code project files are found."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main


def _report(tmp_path) -> dict:
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    return json.loads(result.stdout)


def _frameworks(tmp_path) -> set[str]:
    report = _report(tmp_path)
    return {framework for finding in report["findings"] for framework in finding["frameworks"]}


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "server.js",
            "switch (msg.method) {\n  case 'initialize': return init();\n  case 'tools/list': return tools();\n"
            "  case 'tools/call': return call(msg.params);\n}\n",
        ),
        ("server.py", 'if message["method"] == "tools/list":\n    reply(tools())\n'),
        ("client.ts", 'send({ jsonrpc: "2.0", id: 1, method: "tools/list" });\n'),
        ("dispatch.py", 'HANDLERS = {\n    "resources/read": read,\n    "prompts/get": get,\n}\n'),
    ],
)
def test_a_hand_written_json_rpc_mcp_dispatcher_is_an_mcp_finding(tmp_path, name, source):
    (tmp_path / name).write_text(source, encoding="utf-8")
    assert "protocol.mcp" in _frameworks(tmp_path)


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "mcp.rs",
            'match method {\n    "initialize" => Ok(init()),\n    "tools/list" => Ok(tools()),\n'
            '    "tools/call" => call(&params).await,\n    _ => Err(not_found()),\n}\n',
        ),
        ("main.go", 'switch req.Method {\ncase "tools/list":\n\treturn tools()\n}\n'),
    ],
)
def test_a_lexical_only_dispatcher_without_library_evidence_is_named_not_dropped(tmp_path, name, source):
    # Languages without an import binder match code lexically. Without an MCP
    # import or dependency in the project, the dispatcher does not establish
    # protocol.mcp on its own, but the scan names the file instead of dropping it.
    (tmp_path / name).write_text(source, encoding="utf-8")
    report = _report(tmp_path)
    assert not report["findings"]
    notes = [warning for stats in report["stats"] for warning in stats["warnings"]]
    assert any("establishes a technology" in note and name in note for note in notes)
    (tmp_path / "go.mod").write_text("module x\n\nrequire github.com/mark3labs/mcp-go v0.40.0\n")
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "x"\n\n[dependencies]\nrmcp = "0.6"\n')
    assert "protocol.mcp" in _frameworks(tmp_path)


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("notes.js", '// the server answers "tools/list" and "tools/call"\nconst x = 1;\n'),
        ("notes.py", 'DOC = "Methods: tools/list, tools/call"\nNAMES = ["tools/list", "tools/call"]\n'),
        ("lsp.ts", 'send({ method: "textDocument/definition" });\nsend({ method: "initialize" });\n'),
        ("README.md", "```\ncase 'tools/list':\n```\n"),
    ],
)
def test_the_method_names_in_comments_strings_lists_and_prose_are_not(tmp_path, name, source):
    (tmp_path / name).write_text(source, encoding="utf-8")
    assert "protocol.mcp" not in _frameworks(tmp_path)


@pytest.mark.parametrize(
    "rel",
    [
        ".claude/launch.json",
        ".claude/rules/style.md",
        ".claude/output-styles/terse.md",
        ".claude-plugin/plugin.json",
        ".claude-plugin/marketplace.json",
    ],
)
def test_claude_code_project_files_identify_claude_code(tmp_path, rel):
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_text('{"name": "x"}\n' if rel.endswith(".json") else "Be terse.\n", encoding="utf-8")
    assert "coding-agent.claude-code" in _frameworks(tmp_path)


def test_a_launch_json_elsewhere_is_not_claude_code(tmp_path):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "launch.json").write_text('{"version": "0.2.0", "configurations": []}\n')
    assert "coding-agent.claude-code" not in _frameworks(tmp_path)
