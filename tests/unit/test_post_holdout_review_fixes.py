"""Independent review of the post-holdout changes: inputs that hid code, misclassified or lost coverage.

Each case was reproduced on a minimal input. Ruby division by a local read as
a regular expression masked code across lines while the scan stayed complete;
MCP clients matched server markers; test files crowded out a server file;
scripts with many requests exhausted the dispatch budget; long JavaScript calls
timed out inside the matching iterator; and summarized agent definitions kept
list values.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _scan(run_connector, root: Path, **config):
    return run_connector("code.filesystem", path=str(root), use_git=False, scan_secrets=False, **config)


def _visible(source: str, spans, needle: str) -> bool:
    at = source.index(needle)
    return not any(start <= at < end for start, end in spans)


@pytest.mark.parametrize(
    "source",
    [
        'require "openai"\ntotal = 10\navg = total /count\nclient = OpenAI::Client.new\nhalf = total / 2\n',
        "def f(n)\n  n /2\nend\nclient = OpenAI::Client.new\ndef g(n) = n / 3\n",
        "[1].each { |v| p v /2 }\nclient = OpenAI::Client.new\nz = 1 / 2\n",
        "x = 3\ny = x /2 # half\nclient = OpenAI::Client.new\nz = x / 4\n",
        "a = 5\nb = a %(\n  OpenAI::Client.new.x\n)\n",
    ],
    ids=["local", "parameter", "block-parameter", "comment", "percent"],
)
def test_ruby_local_division_never_hides_code_silently(source: str) -> None:
    spans, incomplete = noncode_ranges(source, "ruby", ".rb")
    assert incomplete or _visible(source, spans, "OpenAI::Client")


def test_ruby_backtick_method_definitions_are_code() -> None:
    source = (
        "class A\n  def `(cmd)\n    1\n  end\nend\nclient = OpenAI::Client.new\n"
        "class B\n  def self.`(cmd)\n    2\n  end\nend\n"
    )
    spans, incomplete = noncode_ranges(source, "ruby", ".rb")
    assert not incomplete and _visible(source, spans, "OpenAI::Client")


def test_ruby_percent_string_with_equals_delimiters_is_text() -> None:
    source = "x = %=OpenAI::Client.new=\ny = 1\ny %= 3\nclient = RubyLLM.chat\n"
    spans, incomplete = noncode_ranges(source, "ruby", ".rb")
    assert not incomplete
    assert not _visible(source, spans, "OpenAI::Client")
    assert _visible(source, spans, "RubyLLM.chat")


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "main.go",
            'package main\n\nimport (\n\t"github.com/mark3labs/mcp-go/client"\n'
            '\t"example.com/app/internal/server"\n)\n\n'
            'func main() {\n\tc, _ := client.NewStdioMCPClient("srv", nil)\n\t_ = server.NewServer(c)\n}\n',
        ),
        (
            "report.js",
            'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
            "const client = new Client({ name: 'x', version: '1' });\nreporter.tool(name, tools);\n",
        ),
        (
            "Program.cs",
            "using ModelContextProtocol.Client;\n\nvar client = await McpClientFactory.CreateAsync(t);\n"
            "builder.WithTools(tools);\n",
        ),
    ],
    ids=["go-client", "javascript-client", "dotnet-client"],
)
def test_mcp_clients_are_not_servers(tmp_path: Path, run_connector, name: str, source: str) -> None:
    _write(tmp_path, {name: source})
    findings, _ = _scan(run_connector, tmp_path)
    assert not any(f.kind == Kind.MCP_SERVER for f in findings)


def test_test_files_do_not_crowd_out_the_server_file(tmp_path: Path, run_connector) -> None:
    server = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        "const server = new McpServer({ name: 'x', version: '1' });\n"
        "for (const tool of TOOLS) server.registerTool(tool.name, {}, tool.run);\n"
    )
    files = {f"__tests__/s{n:03d}.test.ts": server for n in range(300)}
    files["src/server.ts"] = server
    files["package.json"] = '{"name": "srv"}'
    _write(tmp_path, files)
    findings, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete, ctx.stats.errors[:3]
    assert any(f.kind == Kind.MCP_SERVER for f in findings)


def test_many_requests_in_one_script_stay_within_the_dispatch_budget(tmp_path: Path, run_connector) -> None:
    lines = [
        "from openai import OpenAI",
        "client = OpenAI()",
        'TOOLS = [{"type": "function", "function": {"name": "lookup"}}]',
    ]
    for n in range(50):
        lines.append(f'r{n} = client.chat.completions.create(model="m", messages=[], tools=TOOLS)')
        lines.extend(f"print({n}, {k})" for k in range(25))
    _write(tmp_path, {"notebook_script.py": "\n".join(lines) + "\n"})
    findings, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any("tool-use" in f.capabilities for f in findings)


def test_long_javascript_calls_use_the_allowance_without_timing_out(tmp_path: Path, run_connector) -> None:
    calls = "".join(
        f'const a{n} = new Agent({{ name: "a{n}", instructions: "{"x" * 120_000}" }});\n' for n in range(8)
    )
    _write(tmp_path, {"agents.js": 'import { Agent } from "@openai/agents";\n' + calls})
    started = time.monotonic()
    findings, ctx = _scan(run_connector, tmp_path, max_file_size=4 * 1024 * 1024)
    assert time.monotonic() - started < 60
    assert not any("TimeoutError" in error for error in ctx.stats.errors), ctx.stats.errors
    assert any(f.kind == Kind.AGENT for f in findings)


def test_summarized_agent_definitions_keep_short_strings_only(tmp_path: Path, run_connector) -> None:
    modes = "".join(f"  - {'m' * 150}{n}\n" for n in range(60))
    _write(
        tmp_path,
        {
            **{
                f".claude/agents/a{n:03d}.md": f"---\nname: a{n}\npermissionMode:\n{modes}mode: plan\n---\nbody\n"
                for n in range(80)
            },
            "app.py": "import openai\n",
        },
    )
    findings, _ = _scan(run_connector, tmp_path)
    project = next(f for f in findings if f.resource_type == "project")
    summaries = project.metadata["agent_definitions"][50:]
    assert len(summaries) == 30
    assert all(set(d) == {"file", "name", "mode"} for d in summaries)
    assert len(json.dumps(summaries)) < 30 * 200
