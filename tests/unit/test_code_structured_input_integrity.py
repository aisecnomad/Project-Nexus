"""Ambiguous repository configuration must never look like complete coverage."""

from __future__ import annotations

import pytest

from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.code.filesystem import _NO_STRUCTURE, _parse_mcp_servers, _structured_context
from shadowscan.connectors.code.manifests import parse_manifest
from shadowscan.connectors.code.semantic_config import parse_agent_manifest, structured_code_matches
from shadowscan.models import Kind
from shadowscan.risk import assess
from shadowscan.utils.jsonc import load_json_lenient
from shadowscan.utils.safe_json import JSONIntegrityError
from shadowscan.utils.safe_yaml import (
    YAMLIntegrityError,
    strict_bounded_safe_load,
    strict_bounded_safe_load_all,
)
from shadowscan.utils.text import notebook_to_source


@pytest.mark.parametrize(
    "text",
    [
        '{"servers":{"first":{}},"servers":{}}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":1e999}',
        '{// JSONC remains supported\n"value":1,"value":2,}',
    ],
)
def test_lenient_json_still_rejects_ambiguous_or_nonfinite_data(text):
    with pytest.raises(JSONIntegrityError):
        load_json_lenient(text)


@pytest.mark.parametrize(
    "text",
    [
        "agents: {first: {}}\nagents: {}\n",
        "agents: .nan\n",
        "---\nagents: {}\n---\nvalue: .inf\n",
        "value: !!pairs [score: .nan]\n",
        "value: !!omap [score: .inf]\n",
    ],
)
def test_strict_yaml_stream_rejects_ambiguous_or_nonfinite_data(text):
    with pytest.raises(YAMLIntegrityError):
        strict_bounded_safe_load_all(text)


@pytest.mark.parametrize("duplicate", ["1: first\ntrue: second\n", "0: first\nfalse: second\n"])
def test_repository_yaml_accepts_github_actions_on_key_without_weakening_integrity(duplicate):
    assert strict_bounded_safe_load("on: {push: null}\n", require_string_keys=False) == {True: {"push": None}}
    with pytest.raises(YAMLIntegrityError):
        strict_bounded_safe_load("on: {}\ntrue: {}\n", require_string_keys=False)
    with pytest.raises(YAMLIntegrityError):
        strict_bounded_safe_load("value: !!set {.nan: null}\n", require_string_keys=False)
    with pytest.raises(YAMLIntegrityError):
        strict_bounded_safe_load(duplicate, require_string_keys=False)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("package.json", '{"dependencies":{"crewai":"1"},"dependencies":{}}'),
        ("package.json", '{"dependencies":{},"private":NaN}'),
        ("composer.json", '{"require":{"openai/client":"1"},"require":{}}'),
        ("composer.json", '{"require":{},"metadata":1e999}'),
        ("environment.yml", "dependencies: [crewai]\ndependencies: []\n"),
        ("environment.yml", "dependencies: []\nmetadata: .nan\n"),
    ],
)
def test_dependency_manifests_reject_integrity_failures(name, text):
    result = parse_manifest(name, text)

    assert result is not None
    assert result.deps == []
    assert result.errors


@pytest.mark.parametrize(
    "duplicate",
    [
        "<groupId>dev.langchain4j</groupId><groupId>org.example</groupId>"
        "<artifactId>langchain4j</artifactId>",
        "<groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId>"
        "<artifactId>ordinary</artifactId>",
        "<groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId>"
        "<version>1</version><version>2</version>",
        "<groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId>"
        "<scope>compile</scope><scope>test</scope>",
    ],
)
def test_pom_dependencies_reject_repeated_meaningful_children_without_losing_neighbors(duplicate):
    result = parse_manifest(
        "pom.xml",
        "<project><dependencies>"
        f"<dependency>{duplicate}</dependency>"
        "<dependency><groupId>io.modelcontextprotocol.sdk</groupId><artifactId>mcp</artifactId></dependency>"
        "</dependencies></project>",
    )

    assert result is not None
    assert [(dependency.ecosystem, dependency.name) for dependency in result.deps] == [
        ("maven", "io.modelcontextprotocol.sdk:mcp")
    ]
    assert result.errors == ["POM dependency contains a duplicate meaningful field"]


def test_nuget_xml_is_order_independent_and_ignores_comments():
    result = parse_manifest(
        "Agent.csproj",
        "<Project><ItemGroup>"
        '<!-- <PackageReference Include="Hidden.AI" Version="9" /> -->'
        '<PackageReference Version="1.0" Include="Microsoft.Agents.AI" />'
        '<PackageVersion Version="0.10" Include="ModelContextProtocol" />'
        "</ItemGroup></Project>",
    )

    assert result is not None and not result.errors
    assert [(dependency.name, dependency.spec) for dependency in result.deps] == [
        ("Microsoft.Agents.AI", "1.0"),
        ("ModelContextProtocol", "0.10"),
    ]


@pytest.mark.parametrize(
    "element",
    [
        '<PackageReference Include="Microsoft.Agents.AI" id="ordinary" Version="1" />',
        '<PackageReference Include="Microsoft.Agents.AI" include="ordinary" Version="1" />',
        '<PackageReference Include="Microsoft.Agents.AI" Version="1" version="2" />',
    ],
)
def test_nuget_xml_rejects_ambiguous_attributes_without_losing_neighbors(element):
    result = parse_manifest(
        "Agent.csproj",
        "<Project><ItemGroup>"
        f"{element}"
        '<PackageReference Include="ModelContextProtocol" Version="0.10" />'
        "</ItemGroup></Project>",
    )

    assert result is not None
    assert [(dependency.name, dependency.spec) for dependency in result.deps] == [
        ("ModelContextProtocol", "0.10")
    ]
    assert result.errors == ["NuGet dependency contains ambiguous attributes"]


@pytest.mark.parametrize(
    "text",
    [
        '<!DOCTYPE Project [<!ENTITY hidden "Microsoft.Agents.AI">]><Project />',
        '<Project><PackageReference Include="Microsoft.Agents.AI"></Project>',
    ],
)
def test_nuget_xml_rejects_entities_and_malformed_documents(text):
    result = parse_manifest("Agent.csproj", text)

    assert result is not None
    assert result.deps == []
    assert result.errors


@pytest.mark.parametrize(
    ("rel", "text", "kind"),
    [
        ("langgraph.json", '{"graphs":{"agent":"app.py:graph"},"graphs":{}}', "langgraph"),
        ("langgraph.json", '{"graphs":{"agent":"app.py:graph"},"value":NaN}', "langgraph"),
        (
            "config/agents.yaml",
            "researcher: {role: Researcher, goal: Find, backstory: Careful}\nresearcher: {}\n",
            "crewai",
        ),
        (
            "config/agents.yaml",
            "researcher: {role: Researcher, goal: Find, backstory: Careful}\nvalue: .inf\n",
            "crewai",
        ),
    ],
)
def test_agent_manifests_reject_integrity_failures(rel, text, kind):
    result = parse_agent_manifest(rel, text, kind)

    assert not result.valid
    assert result.data is None
    assert result.errors == ["invalid agent manifest syntax"]


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("workflow.json", '{"nodes":[{"type":"agent"}],"nodes":[]}'),
        ("workflow.jsonc", '{// comment\n"nodes":[],"value":Infinity,}'),
        ("workflow.yaml", "nodes: [{type: agent}]\nnodes: []\n"),
        ("workflow.yml", "nodes: []\nvalue: -.inf\n"),
        ("workflow.yaml", "---\nnodes: []\n---\nvalue: .nan\n"),
    ],
)
def test_structured_matching_routes_integrity_failures_to_incomplete_errors(index, rel, text):
    errors: list[str] = []
    incomplete: list[str] = []

    assert structured_code_matches(index, rel, text, errors, incomplete) == []
    assert not errors
    assert incomplete == ["structured configuration contains ambiguous or non-finite data"]


@pytest.mark.parametrize(
    "text",
    [
        '{"code":[],"steps":[{"provider":"workato_genai","operation":"generate"}]}',
        '{"code":[{"provider":"workato_genai","name":"","operation":"generate"}]}',
        '{"definition":{},"properties":{"definition":{"actions":{"agent":{"type":"Agent","inputs":{}}}}}}',
    ],
)
def test_structured_matching_rejects_projection_alias_ambiguity(index, text):
    errors: list[str] = []
    incomplete: list[str] = []

    assert structured_code_matches(index, "workflow.json", text, errors, incomplete) == []
    assert not errors
    assert incomplete == ["structured configuration contains ambiguous field aliases"]


@pytest.mark.parametrize(
    "text",
    [
        '{"cells":[{"cell_type":"code","source":"from crewai import Agent"}],"cells":[]}',
        '{"cells":[],"metadata":{"score":NaN}}',
        '{"cells":[{"cell_type":"code","cell_type":"markdown","source":"hidden"}]}',
    ],
)
def test_notebooks_reject_integrity_failures(text):
    errors: list[str] = []

    assert notebook_to_source(text, errors) == ""
    assert errors == ["notebook contains invalid JSON"]


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (".mcp.json", '{"mcpServers":{"first":{"command":"tool"}},"mcpServers":{}}'),
        (".mcp.json", '{"mcpServers":{},"value":Infinity}'),
        ("mcp.yaml", "mcpServers: {first: {command: tool}}\nmcpServers: {}\n"),
        ("mcp.yaml", "mcpServers: {}\nvalue: .nan\n"),
    ],
)
def test_mcp_configuration_rejects_integrity_failures(rel, text):
    errors: list[str] = []

    assert _parse_mcp_servers(rel, text, errors) == []
    assert errors == ["invalid MCP configuration syntax"]


@pytest.mark.parametrize(
    "text",
    [
        '{"mcp_servers":{},"mcpServers":{"active":{"command":"tool"}}}',
        '{"mcpServers":{},"servers":{"active":{"command":"tool"}}}',
        '{"mcp":{"servers":{}},"mcpServers":{"active":{"command":"tool"}}}',
        '{"mcp":{"servers":{}},"servers":{"active":{"command":"tool"}}}',
    ],
)
def test_mcp_configuration_rejects_multiple_alias_containers(text):
    errors: list[str] = []

    assert _parse_mcp_servers(".mcp.json", text, errors) == []
    assert errors == ["multiple MCP server containers are ambiguous"]


def test_mcp_configuration_rejects_duplicate_names_in_list_form():
    errors: list[str] = []
    text = '{"servers":[{"name":"same","command":"tool"},{"name":"same","command":"tool","disabled":true}]}'

    assert _parse_mcp_servers(".mcp.json", text, errors) == []
    assert errors == ["duplicate MCP server names are ambiguous"]


@pytest.mark.parametrize(
    "server",
    [
        '{"command":"tool","env":{},"environment":{"API_KEY":"opaque-value"}}',
        '{"url":"https://api.openai.com/mcp","endpoint":"http://api.anthropic.com/mcp"}',
        '{"command":"tool","type":"stdio","transport":"http"}',
        '{"command":"tool","autoApprove":[],"alwaysAllow":["dangerous"]}',
    ],
)
def test_mcp_configuration_rejects_inner_alias_ambiguity_and_keeps_valid_sibling(server):
    errors: list[str] = []
    text = '{"mcpServers":{"ambiguous":' + server + ',"valid":{"command":"safe-tool"}}}'

    parsed = _parse_mcp_servers(".mcp.json", text, errors)

    assert [entry["name"] for entry in parsed] == ["valid"]
    assert errors == ["MCP server entry contains ambiguous field aliases"]


def test_mcp_registry_preserves_every_remote_for_detection_and_risk(tmp_path, run_connector, index):
    (tmp_path / "server.json").write_text(
        '{"name":"registry-server","remotes":['
        '{"url":"https://api.openai.com/mcp","type":"streamable-http"},'
        '{"url":"http://api.anthropic.com/mcp","type":"streamable-http"}]}'
    )

    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)

    assert not ctx.stats.errors
    finding = next(item for item in findings if item.kind == Kind.MCP_SERVER)
    assert finding.metadata["remote_urls"] == [
        "https://api.openai.com/mcp",
        "http://api.anthropic.com/mcp",
    ]
    assert {"provider.openai", "provider.anthropic"} <= set(finding.model_providers)
    assert "mcp-plain-http" in {factor.id for factor in assess(finding, index).factors}


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("package.json", '{"dependencies":{"crewai":"1"},"dependencies":{}}'),
        ("composer.json", '{"require":{},"metadata":1e999}'),
        (
            "research.ipynb",
            '{"cells":[{"cell_type":"code","source":"from crewai import Agent"}],"cells":[]}',
        ),
        ("workflow.yaml", "nodes: [{type: agent}]\nnodes: []\n"),
        ("workflow-nonfinite.yaml", "nodes: []\nvalue: .nan\n"),
        ("settings.jsonc", '{// accepted comment\n"nodes":[],"value":NaN,}'),
        (".mcp.json", '{"mcpServers":{"first":{"command":"tool"}},"mcpServers":{}}'),
        (".mcp.json", '{"mcp_servers":{},"mcpServers":{"active":{"command":"tool"}}}'),
        (
            ".mcp.json",
            '{"servers":[{"name":"same","command":"tool"},{"name":"same","command":"tool","disabled":true}]}',
        ),
        (
            "pom.xml",
            "<project><dependencies><dependency>"
            "<groupId>dev.langchain4j</groupId><groupId>org.example</groupId>"
            "<artifactId>langchain4j</artifactId>"
            "</dependency></dependencies></project>",
        ),
        (
            "Agent.csproj",
            "<Project><ItemGroup>"
            '<PackageReference Include="Microsoft.Agents.AI" id="ordinary" Version="1" />'
            "</ItemGroup></Project>",
        ),
        (
            "workato.json",
            '{"code":[],"steps":[{"provider":"workato_genai","operation":"generate"}]}',
        ),
        (
            "logic-app.json",
            '{"definition":{},"properties":{"definition":{"actions":{"agent":{"type":"Agent",'
            '"inputs":{}}}}}}',
        ),
        (
            ".mcp.json",
            '{"mcpServers":{"ambiguous":{"command":"tool","env":{},'
            '"environment":{"API_KEY":"opaque-value"}}}}',
        ),
        (
            ".claude/agents/ambiguous.md",
            "---\nname: first\nname: second\n---\nAgent instructions.\n",
        ),
        (
            ".claude/agents/nonfinite.md",
            "---\nname: helper\nmetadata: .inf\n---\nAgent instructions.\n",
        ),
    ],
)
def test_repository_scan_marks_structured_integrity_failures_incomplete(tmp_path, run_connector, name, text):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    (tmp_path / "neighbor.py").write_text("from crewai import Agent\n", encoding="utf-8")

    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)

    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.incomplete
    assert any(name in error for error in ctx.stats.errors)


# Unrendered Helm/Go templates are not YAML: a placeholder reads as a mapping
# key and conditional branches repeat fields.
_UNRENDERED_TEMPLATES = [
    "spec:\n  containers:\n    - image: {{ .Values.image }}\n",
    'spec:\n  logLevel: "{{ .Values.logLevel }}"\n  logLevel: info\n',
]


@pytest.mark.parametrize("text", _UNRENDERED_TEMPLATES)
def test_unrendered_templates_use_lexical_redaction_while_plain_yaml_fails_closed(text):
    assert _structured_context("chart/templates/deployment.yaml", text) is _NO_STRUCTURE
    plain = text.replace('"{{ .Values.logLevel }}"', "debug").replace("{{ .Values.image }}", "{[a]: b}")
    with pytest.raises(YAMLIntegrityError):
        _structured_context("chart/values.yaml", plain)


@pytest.mark.parametrize("text", _UNRENDERED_TEMPLATES)
def test_repository_scan_keeps_unrendered_templates_complete(tmp_path, run_connector, text):
    target = tmp_path / "chart" / "templates" / "deployment.yaml"
    target.parent.mkdir(parents=True)
    target.write_text(text, encoding="utf-8")
    (tmp_path / "neighbor.py").write_text("from crewai import Agent\n", encoding="utf-8")

    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)

    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert not ctx.stats.incomplete, ctx.stats.errors


@pytest.mark.parametrize(
    "record",
    [
        '{"Name":"OpenAI ChatGPT","NAME":"calculator"}',
        '{"name":"calculator","app_name":"OpenAI ChatGPT"}',
        '{"name":"OpenAI ChatGPT","scopes":[],"permissions":["admin"]}',
    ],
)
def test_generic_saas_rejects_conflicting_case_and_field_aliases(tmp_path, run_connector, record):
    source = tmp_path / "apps.json"
    source.write_text("[" + record + "]", encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert any("ambiguous field aliases" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize(
    "record",
    [
        '{"Name":"OpenAI ChatGPT","NAME":"OpenAI ChatGPT"}',
        '{"Name":"OpenAI ChatGPT","NAME":""}',
    ],
)
def test_generic_saas_allows_identical_or_empty_aliases(tmp_path, run_connector, record):
    source = tmp_path / "apps.json"
    source.write_text("[" + record + "]", encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert len(findings) == 1
    assert not ctx.stats.incomplete


def test_case_colliding_csv_headers_fail_closed_in_streaming_and_legacy_paths(tmp_path, run_connector):
    text = "Name,OK,ok\nOpenAI ChatGPT,false,true\n"
    source = tmp_path / "apps.csv"
    source.write_text(text, encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert any("unique, nonempty column names" in error for error in ctx.stats.errors)

    errors: list[str] = []
    assert list(BaseConnector._csv_records(text, errors.append)) == []
    assert errors == ["CSV export needs unique, nonempty column names"]
