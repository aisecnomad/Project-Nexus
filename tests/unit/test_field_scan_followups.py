"""Regressions for defects found by the 2026-10-01 field scan of public repositories.

Every input is written from scratch to reproduce a pattern observed in the
field; none is copied from the scanned projects.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.connectors.code.filesystem import _parse_mcp_servers
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind

# --- JSX lexer -----------------------------------------------------------------

VALID_TSX = {
    "type-arguments-on-child": (
        "export const A = () => (\n  <Box>\n    <Select<Option> value={v} onChange={set} />\n  </Box>\n);\n"
    ),
    "literal-type-arguments": (
        "export const B = () => (\n  <Box>\n    <Picker<'day' | 'hour'> value={u}>\n"
        "      <Item />\n    </Picker>\n  </Box>\n);\n"
    ),
    "object-type-arguments-at-expression": (
        "export const C = () => (\n  <Form<{ email: string; name: string }> onSubmit={go}>\n"
        "    <input />\n  </Form>\n);\n"
    ),
    "line-comment-with-apostrophe": (
        "export const D = () => (\n  <ul\n    // the browser's default list role\n"
        '    role="list"\n  >\n    <li>x</li>\n  </ul>\n);\n'
    ),
    "commented-out-attribute-expression": (
        "export const E = () => (\n  <input\n    // style={{\n    //   width: 1,\n    // }}\n"
        "    size={3}\n  />\n);\n"
    ),
    "block-comment-in-tag": "export const F = () => <input /* it's fine */ size={3} />;\n",
    "child-text-starting-with-parenthesis": "export const G = ({ n }: { n: number }) => <Text>({n})</Text>;\n",
}


@pytest.mark.parametrize("source", VALID_TSX.values(), ids=VALID_TSX.keys())
def test_valid_tsx_constructs_are_lexed_completely(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


def test_jsx_text_after_typed_element_stays_masked() -> None:
    source = (
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const View = () => (\n  <Box>\n    <Select<Option>\n"
        "      // the user's choice\n      value={v}\n    />\n"
        "    <Text>(createReactAgent( is documented here)</Text>\n  </Box>\n);\n"
        "const graph = createReactAgent({});\n"
    )
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    prose = source.index("createReactAgent( is")
    code = source.rindex("createReactAgent(")
    assert any(start <= prose < end for start, end in ignored)
    assert not any(start <= code < end for start, end in ignored)


@pytest.mark.parametrize(
    "source",
    [
        "const identity = <T>(value: T): T => value;\n",
        "const identity = <T>(value: T) => value;\n",
        "const constrained = <T extends object>(value: T): T => value;\n",
    ],
)
def test_generic_arrow_functions_are_not_jsx(source: str) -> None:
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert not any(start <= source.index("value") < end for start, end in ignored)


def test_unbalanced_type_arguments_still_fail_closed() -> None:
    _, ambiguous = noncode_ranges(
        "const v = (\n  <Box>\n    <Select<Option value={v} />\n", "javascript", ".tsx", jsx=True
    )
    assert ambiguous


def test_typed_jsx_component_file_scans_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "Agent.tsx").write_text(
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const Panel = () => (\n  <Box>\n    <Select<Option> value={v} />\n"
        "    <Text>({count})</Text>\n  </Box>\n);\n"
        "export const graph = createReactAgent({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


# --- MCP configuration ----------------------------------------------------------


def test_gemini_http_url_is_an_mcp_endpoint(tmp_path: Path, run_connector) -> None:
    (tmp_path / "gemini-extension.json").write_text(
        json.dumps(
            {
                "name": "tracker",
                "version": "1.0.0",
                "mcpServers": {
                    "tracker": {
                        "httpUrl": "https://mcp.example.test/mcp/",
                        "headers": {"Authorization": "Bearer $TRACKER_TOKEN"},
                    }
                },
            }
        )
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    server = mcp[0].metadata["servers"][0]
    assert server["url"] == "https://mcp.example.test/mcp/"
    assert server["transport"] == "http"
    # A shell-style variable reference is not an inline credential.
    assert server["secrets_inline"] is False


def test_conflicting_mcp_url_aliases_are_ambiguous() -> None:
    errors: list[str] = []
    text = json.dumps(
        {"mcpServers": {"x": {"httpUrl": "https://a.example.test/mcp", "url": "https://a.example.test/sse"}}}
    )
    assert _parse_mcp_servers("gemini-extension.json", text, errors) == []
    assert errors == ["MCP server entry contains ambiguous field aliases"]


def test_literal_bearer_token_is_still_inline() -> None:
    errors: list[str] = []
    text = json.dumps(
        {
            "mcpServers": {
                "x": {
                    "httpUrl": "https://a.example.test/mcp",
                    "headers": {"Authorization": "Bearer Zq7xV2mK9pL4wR8tY3nB6cD1"},
                }
            }
        }
    )
    servers = _parse_mcp_servers("gemini-extension.json", text, errors)
    assert not errors
    assert servers[0]["secrets_inline"] is True


WORKFLOW = """name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: example/agent-action@v1
        with:
          prompt: Summarize the new issue.
          settings: |-
            {
              "mcpServers": {
                "tracker": {
                  "command": "docker",
                  "args": ["run", "-i", "--rm", "example/tracker-server"],
                  "env": {"TRACKER_TOKEN": "${{ secrets.TRACKER_TOKEN }}"}
                }
              }
            }
"""


def test_workflow_with_embedded_mcp_settings_reports_the_server(tmp_path: Path, run_connector) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(WORKFLOW)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    server = mcp[0].metadata["servers"][0]
    assert (server["name"], server["command"]) == ("tracker", "docker")
    assert server["env_names"] == ["TRACKER_TOKEN"]
    assert server["secrets_inline"] is False


def test_workflow_prose_mentioning_mcp_servers_is_not_a_config() -> None:
    errors: list[str] = []
    text = 'on: push\njobs:\n  a:\n    steps:\n      - with:\n          prompt: Explain how "mcpServers" works.\n'
    assert _parse_mcp_servers(".github/workflows/docs.yml", text, errors) == []
    assert not errors


def test_unparseable_embedded_mcp_settings_fail_closed() -> None:
    errors: list[str] = []
    text = (
        "on: push\njobs:\n  a:\n    steps:\n      - with:\n          settings: |\n"
        '            {"mcpServers": {"x": ${{ vars.SERVER }} }}\n'
    )
    assert _parse_mcp_servers(".github/workflows/agent.yml", text, errors) == []
    assert errors == ["invalid embedded MCP configuration syntax"]


def test_repeated_embedded_server_names_are_kept_apart() -> None:
    errors: list[str] = []
    text = (
        "on: push\njobs:\n  a:\n    steps:\n      - with:\n"
        '          settings: \'{"mcpServers": {"s": {"command": "docker"}}}\'\n'
        "  b:\n    steps:\n      - with:\n"
        '          mcp_config: \'{"mcpServers": {"s": {"command": "npx"}}}\'\n'
    )
    servers = _parse_mcp_servers(".github/workflows/agent.yml", text, errors)
    assert not errors
    assert [(s["name"], s["command"]) for s in servers] == [("s", "docker"), ("s#2", "npx")]


# --- Signatures -----------------------------------------------------------------


def test_genai_vertex_switch_is_not_agent_development_kit_evidence(index) -> None:
    vertex = {m.signature_id for m in index.match_env("GOOGLE_GENAI_USE_VERTEXAI")}
    assert "framework.google-adk" not in vertex
    assert "provider.google-vertex-ai" in vertex
    assert "framework.google-adk" in {m.signature_id for m in index.match_env("ADK_API_KEY")}
