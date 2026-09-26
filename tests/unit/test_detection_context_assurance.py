"""Evidence must come from executable code or structurally valid configuration."""

from __future__ import annotations

import json
from pathlib import Path

from shadowscan.connectors.code.manifests import parse_pom
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind


def test_generic_server_filename_does_not_confirm_mcp(tmp_path: Path, run_connector, index):
    (tmp_path / "server.json").write_text(json.dumps({"name": "ordinary web service"}))
    assert not [m for m in index.match_file("server.json") if m.signature_id == "protocol.mcp"]
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "protocol.mcp" in f.frameworks or f.kind == Kind.MCP_SERVER]

    (tmp_path / "server.json").write_text(json.dumps({
        "name": "ordinary web service",
        "remotes": [{"url": "https://replica.example.test"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "protocol.mcp" in f.frameworks or f.kind == Kind.MCP_SERVER]


def test_mcp_registry_manifest_requires_structural_package_or_remote(tmp_path: Path, run_connector):
    (tmp_path / "server.json").write_text(json.dumps({
        "name": "io.github.acme/tools",
        "packages": [{"registryType": "npm", "identifier": "@acme/mcp-tools"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    assert mcp[0].metadata["servers"][0]["name"] == "io.github.acme/tools"

    (tmp_path / "server.json").write_text(json.dumps({
        "name": "io.github.acme/tools",
        "remotes": [{"type": "streamable-http", "url": "https://tools.example.test/mcp"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [f.metadata["servers"][0]["url"] for f in findings if f.kind == Kind.MCP_SERVER] == [
        "https://tools.example.test/mcp"
    ]


def test_readme_examples_do_not_confirm_framework_or_agent(tmp_path: Path, run_connector):
    (tmp_path / "README.md").write_text(
        "Example: create_agent(model, tools)\n"
        "```python\nfrom langchain.agents import create_agent\n"
        "agent = create_agent(model, tools)\n```\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.AGENT or "framework.langchain" in f.frameworks]

    (tmp_path / "agent.py").write_text("from langchain.agents import create_agent\nagent = create_agent(model, tools)\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [f for f in findings if f.kind == Kind.AGENT and "framework.langchain" in f.frameworks]


def test_python_comments_strings_and_docstrings_do_not_confirm_agent(tmp_path: Path, run_connector):
    (tmp_path / "examples.py").write_text(
        "# StateGraph(\n"
        "# create_react_agent(model, tools)\n"
        "example = 'StateGraph(' # create_react_agent(\n"
        "docs = '''\nStateGraph(\ncreate_react_agent(\n'''\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not findings


def test_python_examples_do_not_exhaust_live_match_quota(tmp_path: Path, run_connector):
    (tmp_path / "agent.py").write_text(
        "# create_agent(model, tools)\n" * 10
        + "from langchain.agents import create_agent\n"
        + "agent = create_agent(model, tools)\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert len(agents) == 1
    assert any(e.signal == "code:framework.langchain" and e.location == "agent.py:12" for e in agents[0].evidence)


def test_typescript_comments_literals_and_templates_do_not_confirm_agent(tmp_path: Path, run_connector):
    (tmp_path / "examples.ts").write_text(
        "// StateGraph(\n"
        "/* create_react_agent( */\n"
        "const example = 'StateGraph(';\n"
        "const docs = `create_react_agent(\\n${'ignored'}\\nStateGraph(`;\n"
        "const importExample = 'from \"@langchain/langgraph\"';\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not findings


def test_typescript_live_import_and_template_interpolation_remain_detected(tmp_path: Path, run_connector):
    (tmp_path / "agent.ts").write_text(
        'import { StateGraph } from "@langchain/langgraph";\n'
        "const graph = `${StateGraph({})}`;\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agent = next(f for f in findings if f.kind == Kind.AGENT)
    assert "framework.langgraph" in agent.frameworks
    assert {"import:framework.langgraph", "code:framework.langgraph"} <= {e.signal for e in agent.evidence}


def test_typescript_regex_quotes_do_not_hide_live_agent(tmp_path: Path, run_connector):
    (tmp_path / "agent.ts").write_text(
        'import { StateGraph } from "@langchain/langgraph";\n'
        "const single = /'/;\n"
        'const double = /"/;\n'
        "const escaped = /a\\/'b/;\n"
        'const klass = /[\\/"\']+/;\n'
        "const graph = StateGraph({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


def test_typescript_regex_body_does_not_confirm_agent(tmp_path: Path, run_connector):
    (tmp_path / "example.ts").write_text(
        "const pattern = /StateGraph(example)/;\n"
        "const matcher = /[/'\\\"]StateGraph(example)/;\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not findings


def test_typescript_division_does_not_swallow_following_code(tmp_path: Path, run_connector):
    (tmp_path / "agent.ts").write_text(
        'import { StateGraph } from "@langchain/langgraph";\n'
        "const ratio = numerator / denominator;\n"
        "const quotient = value / 'example';\n"
        "const graph = StateGraph({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


def test_typescript_regex_after_control_header_and_in_interpolation():
    text = 'if (ready) /"/ .test(value); const v = `${/\'/ .test(input) ? StateGraph({}) : ""}`;'
    ignored, incomplete = noncode_ranges(text, "javascript")
    assert not incomplete
    assert any(text[start:end] == '/"/' for start, end in ignored)
    assert any(text[start:end] == "/'/" for start, end in ignored)
    assert not any(start <= text.index("StateGraph(") < end for start, end in ignored)


def test_unterminated_javascript_regex_reports_incomplete_and_retains_next_line():
    text = 'const pattern = /"unterminated\nconst graph = StateGraph({});'
    ignored, incomplete = noncode_ranges(text, "javascript")
    assert incomplete
    assert not any(start <= text.index("StateGraph(") < end for start, end in ignored)


def test_jsx_nested_text_nodes_do_not_confirm_agent(tmp_path: Path, run_connector):
    (tmp_path / "Help.tsx").write_text(
        "export function Help() { return (\n"
        "  <main>StateGraph( <span>create_react_agent(</span>\n"
        "    <p title=\"StateGraph(\">createReactAgent(</p>\n"
        "  </main>\n"
        "); }\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not findings


def test_jsx_attribute_and_child_expressions_remain_detected(tmp_path: Path, run_connector):
    (tmp_path / "Agent.jsx").write_text(
        'import { StateGraph } from "@langchain/langgraph";\n'
        "const view = <main>StateGraph( <span data-graph={StateGraph({})}>\n"
        "  create_react_agent( {StateGraph({})}\n"
        "</span></main>;\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert len(agents) == 1
    assert "framework.langgraph" in agents[0].frameworks
    assert any(e.signal == "code:framework.langgraph" for e in agents[0].evidence)


def test_tsx_generic_arrow_does_not_swallow_following_agent(tmp_path: Path, run_connector):
    (tmp_path / "Agent.tsx").write_text(
        'import { StateGraph } from "@langchain/langgraph";\n'
        "const identity = <T>(value: T): T => value;\n"
        "const constrained = <T extends object>(value: T): T => value;\n"
        "const defaulted = <T = string>(value: T): T => value;\n"
        "const graph = StateGraph({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


def test_unclosed_jsx_reports_incomplete():
    ignored, incomplete = noncode_ranges("const view = <div>StateGraph(", "javascript", jsx=True)
    assert incomplete
    assert any(start <= 18 < end for start, end in ignored)


def test_framework_dependency_without_executable_agent_remains_framework_usage(tmp_path: Path, run_connector):
    (tmp_path / "requirements.txt").write_text("langgraph==0.5.0\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "framework.langgraph" in findings[0].frameworks


def test_empty_and_disabled_mcp_configs_do_not_claim_active_servers(tmp_path: Path, run_connector):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"old": {"command": "npx", "disabled": True}}}))
    (tmp_path / "server.json").write_text(json.dumps({"mcpServers": {}}))
    (tmp_path / "smithery.yaml").write_text('mcpServers:\n  archived:\n    command: npx\n    enabled: false\n')
    (tmp_path / "config.toml").write_text('[mcp_servers.archived]\ncommand = "npx"\ndisabled = true\n')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind in {Kind.MCP_SERVER, Kind.AGENT} or "protocol.mcp" in f.frameworks]


def test_mixed_mcp_config_counts_only_enabled_servers(tmp_path: Path, run_connector):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "archived": {"command": "bash", "disabled": True, "url": "https://mcp.zapier.com/example"},
        "live": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
    }}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    assert [server["name"] for server in mcp[0].metadata["servers"]] == ["live"]
    assert mcp[0].metadata["server_count"] == 1
    assert mcp[0].metadata["disabled_server_count"] == 1
    assert not mcp[0].metadata["remote_urls"]
    assert "code-exec" not in mcp[0].capabilities


def test_mcp_placeholder_and_disabled_example_commands_are_not_agents(tmp_path: Path, run_connector):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "placeholder": {},
        "example": {"command": "create_agent(model, tools)", "disabled": True},
    }}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not [f for f in findings if f.kind in {Kind.MCP_SERVER, Kind.AGENT}]
    assert any("no command, URL, or valid package" in error for error in ctx.stats.errors)


def test_mcp_tool_server_code_does_not_imply_autonomous_agent(tmp_path: Path, run_connector):
    (tmp_path / "server.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new McpServer({name: "tools"});\n'
        'server.tool("lookup", async () => ({content: []}));\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "protocol.mcp" in findings[0].frameworks


def test_maven_comments_are_neither_dependencies_nor_code(tmp_path: Path, run_connector):
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <!-- <dependency><groupId>dev.langchain4j</groupId>
       <artifactId>langchain4j</artifactId></dependency>
       create_agent(model, tools) -->
  <dependencies><dependency><groupId>org.example</groupId>
    <artifactId>web-service</artifactId></dependency></dependencies>
</project>"""
    parsed = parse_pom(pom)
    assert [(d.ecosystem, d.name) for d in parsed.deps] == [("maven", "org.example:web-service")]
    assert not parsed.errors
    (tmp_path / "pom.xml").write_text(pom)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "framework.langchain4j" in f.frameworks or "framework.langchain" in f.frameworks]


def test_pom_cdata_examples_do_not_confirm_agent_but_active_dependencies_do(tmp_path: Path, run_connector):
    path = tmp_path / "pom.xml"
    description = "<description><![CDATA[Example: create_agent(model, tools)]]></description>"
    path.write_text(f"<project>{description}</project>")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.AGENT or "framework.langchain" in f.frameworks]

    path.write_text(
        f"<project>{description}<dependencies><dependency>"
        "<groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId>"
        "</dependency></dependencies></project>"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [f for f in findings if "framework.langchain4j" in f.frameworks]
    assert not [f for f in findings if "framework.langchain" in f.frameworks]


def test_pom_xml_entities_fail_closed():
    result = parse_pom(
        '<!DOCTYPE project [<!ENTITY x "dev.langchain4j">]>'
        '<project><dependencies><dependency><groupId>&x;</groupId>'
        '<artifactId>langchain4j</artifactId></dependency></dependencies></project>'
    )
    assert not result.deps
    assert result.errors


def test_text_after_an_unlexable_python_fstring_cannot_establish_an_agent(tmp_path, run_connector):
    import sys

    if sys.version_info >= (3, 12):
        import pytest
        pytest.skip("Python 3.12+ tokenizes PEP 701 f-strings natively")
    (tmp_path / "app.py").write_text(
        "import openai\n"
        "quote = f\"{'\"'}\"\n"
        'EXAMPLE = """\nfrom crewai import Agent\nagent = Agent(role="r", goal="g", backstory="b")\n"""\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert not any(f.kind == Kind.AGENT for f in findings)
    assert not any("framework.crewai" in f.frameworks for f in findings)
