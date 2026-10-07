"""Regression tests for executable structure versus descriptions and filenames."""

from __future__ import annotations

import json

import pytest
import yaml

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.semantic_config import (
    agent_manifest_kind,
    parse_agent_manifest,
    structured_code_matches,
)
from shadowscan.models import Kind


@pytest.mark.parametrize(
    "path,kind",
    [
        ("web/.well-known/agent.json", "a2a"),
        ("agent-card.json", "a2a"),
        ("langgraph.json", "langgraph"),
        ("appPackage/declarativeAgent.json", "m365"),
        ("src/config/agents.yaml", "crewai"),
        ("agent.json", None),
        ("configuration/agents.yaml", None),
    ],
)
def test_manifest_kind_uses_path_components(path, kind):
    assert agent_manifest_kind(path) == kind


@pytest.mark.parametrize(
    "path",
    [
        "agent-card.json",
        "langgraph.json",
        "declarativeAgent.json",
        "config/agents.yaml",
    ],
)
@pytest.mark.parametrize("value", [{}, [], None, {"description": "create_react_agent(model, tools)"}])
def test_recognized_manifest_needs_declarations(path, value):
    kind = agent_manifest_kind(path)
    parsed = parse_agent_manifest(path, json.dumps(value), kind)
    assert not parsed.valid
    assert parsed.errors


@pytest.mark.parametrize(
    "path,data",
    [
        ("langgraph.json", {"graphs": {"agent": "./agent.py:graph"}}),
        ("langgraph.json", {"graphs": {"agent": "package.agent:build"}, "env": ".env"}),
        (
            "agent-card.json",
            {
                "name": "Read-only assistant",
                "version": "1.0",
                "url": "https://agent.example.test/a2a",
                "capabilities": {},
                "skills": [{"id": "summary", "name": "Summarize"}],
            },
        ),
        (
            "agent-card.json",
            {
                "name": "Read-only assistant",
                "version": "1.0",
                "supportedInterfaces": [
                    {"url": "https://agent.example.test/a2a", "protocolBinding": "JSONRPC"}
                ],
                "capabilities": {},
                "skills": [{"id": "summary", "name": "Summarize"}],
            },
        ),
        (
            "declarativeAgent.json",
            {
                "name": "Assistant",
                "version": "v1.6",
                "description": "Summarize documents",
                "instructions": "Read documents and report their key points.",
            },
        ),
        (
            "config/agents.yaml",
            {
                "researcher": {
                    "role": "Researcher",
                    "goal": "Find references",
                    "backstory": "A careful researcher",
                }
            },
        ),
    ],
)
def test_meaningful_agent_manifests_are_discovered(path, data):
    parsed = parse_agent_manifest(path, json.dumps(data), agent_manifest_kind(path))
    assert parsed.valid
    assert parsed.data == data
    assert not parsed.errors


@pytest.mark.parametrize(
    "graphs",
    [
        {},
        [],
        {"agent": ""},
        {"agent": "This is documentation"},
        {"agent": "module:"},
        {"agent": 1},
        {"": "app:graph"},
    ],
)
def test_langgraph_entry_points_require_structure(graphs):
    result = parse_agent_manifest("langgraph.json", json.dumps({"graphs": graphs}), "langgraph")
    assert not result.valid


@pytest.mark.parametrize(
    "data",
    [
        {"name": "An agent", "description": "This sample mentions create_react_agent(model, tools)"},
        {"metadata": {"nodes": [{"type": "@n8n/n8n-nodes-langchain.agent"}]}},
        {"description": '"module": "make-ai-agents:RunAgent"'},
        {"category": "Agents", "name": "toolAgent"},
        {"nodes": [{"name": "Example", "description": "@n8n/n8n-nodes-langchain.agent"}]},
        {"nodes": [{"type": "@n8n/n8n-nodes-langchain.agent", "disabled": True}]},
        {"description": "kind: app\nmode: agent-chat"},
        {"kind": "app", "app": {"mode": "agent-chat"}},
        {"model_list": []},
        {"tool_choice": "auto"},
    ],
)
@pytest.mark.parametrize("extension", ["json", "yaml", "yml"])
def test_descriptions_and_bare_keys_do_not_count_as_code(index, data, extension):
    text = json.dumps(data) if extension == "json" else yaml.safe_dump(data)
    errors = []
    assert structured_code_matches(index, "metadata." + extension, text, errors) == []
    assert not errors


@pytest.mark.parametrize(
    "data,signature",
    [
        ({"nodes": [{"name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent"}]}, "platform.n8n"),
        ({"nodes": [{"data": {"category": "Agents", "name": "toolAgent"}}]}, "platform.flowise"),
        (
            {"data": {"edges": [], "nodes": [{"data": {"type": "Agent", "node": {"template": {}}}}]}},
            "platform.langflow",
        ),
        (
            {
                "kind": "app",
                "app": {"mode": "agent-chat"},
                "model_config": {"model": {"provider": "openai", "name": "gpt-4o"}},
            },
            "platform.dify",
        ),
        ({"flow": [{"id": 1, "module": "make-ai-agents:RunAgent"}]}, "platform.make"),
        ({"code": [{"name": "generate", "provider": "workato_genai"}]}, "platform.workato"),
        (
            {"kind": "AdaptiveDialog", "beginDialog": {"kind": "OnRecognizedIntent", "actions": []}},
            "platform.copilot-studio",
        ),
        (
            {"model_list": [{"model_name": "primary", "litellm_params": {"model": "openai/gpt-4o"}}]},
            "platform.litellm",
        ),
        (
            {"plugins": [{"name": "ai-proxy", "config": {"route_type": "llm/v1/chat"}}]},
            "platform.kong-ai-gateway",
        ),
        (
            {"definition": {"actions": {"answer": {"type": "Agent", "inputs": {"parameters": {}}}}}},
            "cloud.azure-logic-apps-ai",
        ),
        (
            {
                "definition": {
                    "actions": {
                        "answer": {
                            "type": "OpenApiConnection",
                            "inputs": {"host": {"operationId": "ChatCompletion"}},
                        }
                    }
                }
            },
            "platform.power-platform-ai",
        ),
        ({"queries": [{"type": "AIAgentQuery", "name": "answer"}]}, "platform.retool"),
    ],
)
def test_operational_configuration_retains_product_evidence(index, data, signature):
    matches = structured_code_matches(index, "workflow.json", json.dumps(data))
    assert signature in {match.signature_id for match in matches}
    assert all(match.line is None and match.extra["structured_config"] for match in matches)
    assert not any(match.signature.category in {"framework", "heuristic"} for match in matches)


def test_operational_config_does_not_scan_embedded_instructions(index):
    data = {
        "nodes": [
            {
                "type": "@n8n/n8n-nodes-langchain.agent",
                "parameters": {
                    "systemMessage": "Create a script: create_react_agent(model, tools); subprocess.run(command)"
                },
            }
        ]
    }
    matches = structured_code_matches(index, "flow.json", json.dumps(data))
    assert {match.signature_id for match in matches} == {"platform.n8n"}


def test_xml_requires_active_product_root(index):
    assert (
        structured_code_matches(
            index,
            "ordinary.xml",
            "<metadata><![CDATA[<GenAiPlanner><name>A</name></GenAiPlanner>]]></metadata>",
        )
        == []
    )
    matches = structured_code_matches(
        index,
        "agent.genAiPlanner-meta.xml",
        '<GenAiPlanner xmlns="http://soap.sforce.com/2006/04/metadata"><name>Agent</name></GenAiPlanner>',
    )
    assert {match.signature_id for match in matches} == {"platform.salesforce-agentforce"}


@pytest.mark.parametrize(
    "path,text",
    [("workflow.json", "{"), ("workflow.yaml", "x: ["), ("workflow.toml", "["), ("workflow.xml", "<")],
)
def test_malformed_structured_config_is_diagnosed(index, path, text):
    errors = []
    assert structured_code_matches(index, path, text, errors) == []
    assert errors == ["invalid structured configuration syntax"]


@pytest.mark.parametrize("filename", ["langgraph.json", "agent-card.json", "declarativeAgent.json"])
def test_empty_manifest_does_not_emit_agent(tmp_path, run_connector, filename):
    (tmp_path / filename).write_text("{}")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not any(finding.kind == Kind.AGENT for finding in findings)
    assert any("manifest" in error or "card" in error for error in ctx.stats.errors)


_INCOMPLETE_CARD = {
    "name": "catalog-agent",
    "url": "https://agent.example.test/a2a",
    "skills": [{"id": "lookup", "name": "Lookup"}],
}


@pytest.mark.parametrize(
    ("card", "incomplete"),
    [
        (_INCOMPLETE_CARD, True),
        ({"name": "catalog-agent", "capabilities": {}}, True),
        ({"name": "catalog-agent", "supportedInterfaces": [{"url": "https://agent.example.test"}]}, True),
        ({**_INCOMPLETE_CARD, "version": "1.0", "capabilities": {}}, False),  # valid
        ({}, False),
        ({"name": "invalid", "skills": 42}, False),
        ({"url": "https://agent.example.test/a2a", "skills": [{"id": "x", "name": "X"}]}, False),
    ],
)
def test_incomplete_a2a_card_is_recognized_only_when_card_shaped(card, incomplete):
    result = parse_agent_manifest("agent-card.json", json.dumps(card), "a2a")
    assert result.incomplete is incomplete
    assert result.valid is (not result.errors)


def test_incomplete_a2a_card_is_reported_unverified_and_keeps_the_scan_incomplete(tmp_path, run_connector):
    (tmp_path / "agent-card.json").write_text(json.dumps(_INCOMPLETE_CARD))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    [card] = findings
    assert card.kind == Kind.FRAMEWORK_USAGE and card.frameworks == ["protocol.a2a"]
    assert card.title == "Incomplete A2A agent card: catalog-agent"
    assert "incomplete-agent-card" in card.tags and not card.capabilities
    assert [e.location for e in card.evidence] == ["agent-card.json"]
    assert card.metadata["card_errors"] == [
        "A2A card requires a nonempty version",
        "A2A card requires a capabilities object",
    ]
    # The validation errors keep the scan incomplete, each recorded once.
    errors = [error for error in ctx.stats.errors if "agent-card.json" in error]
    assert len(errors) == 2 and len(set(errors)) == 2


def test_incomplete_card_beside_a_valid_card_never_joins_an_agent_finding(tmp_path, run_connector):
    (tmp_path / ".well-known").mkdir()
    (tmp_path / "other").mkdir()
    valid = {**_INCOMPLETE_CARD, "name": "travel-agent", "version": "1.0", "capabilities": {}}
    (tmp_path / ".well-known" / "agent-card.json").write_text(json.dumps(valid))
    (tmp_path / "other" / "agent-card.json").write_text(json.dumps(_INCOMPLETE_CARD))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    by_kind = sorted((f.kind.value, f.title, sorted({e.location for e in f.evidence})) for f in findings)
    assert by_kind == [
        ("agent", "A2A agent card: travel-agent", [".well-known/agent-card.json"]),
        ("framework-usage", "Incomplete A2A agent card: catalog-agent", ["other/agent-card.json"]),
    ]


@pytest.mark.parametrize("filename", ["metadata.json", "metadata.yaml"])
def test_prose_config_cannot_promote_agent_in_end_to_end_scan(tmp_path, run_connector, filename):
    (tmp_path / filename).write_text(json.dumps({"description": "Example: create_react_agent(model, tools)"}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize("value", [None, False, 0, [], {}])
def test_schema_type_confusion_cannot_promote_configuration(index, value):
    data = {
        "kind": value,
        "app": {"mode": value},
        "model_config": value,
        "nodes": [{"type": value, "data": {"type": value, "category": value, "name": value}}],
        "queries": [{"type": value}],
        "plugins": [{"name": value, "config": value}],
        "model_list": [{"model_name": value, "litellm_params": value}],
    }
    assert structured_code_matches(index, "metadata.json", json.dumps(data)) == []


@pytest.mark.parametrize(
    "data",
    [
        {"kind": "app", "app": {"mode": "agent-chat"}, "model_config": {"description": "An example"}},
        {"kind": "app", "app": {"mode": "workflow"}, "workflow": {"graph": {}}},
        {"model_list": [{"model_name": "sample", "litellm_params": {}}]},
        {"definition": {"actions": {"example": {"inputs": {"host": {"description": "AI Builder"}}}}}},
        {"nodes": [{"type": "@n8n/n8n-nodes-langchain.agent", "disabled": "true"}]},
    ],
)
def test_incomplete_or_descriptive_operational_shapes_are_not_evidence(index, data):
    assert structured_code_matches(index, "metadata.json", json.dumps(data)) == []


@pytest.mark.parametrize(
    "path,text,signature",
    [
        (
            ".claude/settings.json",
            '{"permissions":{"defaultMode":"bypassPermissions"}}',
            "coding-agent.claude-code",
        ),
        (".claude/settings.json", '{"permissions":{"allow":["Bash(*)"]}}', "coding-agent.claude-code"),
        (".codex/config.toml", 'approval_policy = "never"', "coding-agent.openai-codex"),
        (".gemini/settings.json", '{"approvalMode":"yolo"}', "coding-agent.gemini-cli"),
    ],
)
def test_coding_agent_authority_requires_product_path_and_config(index, path, text, signature):
    matches = structured_code_matches(index, path, text)
    assert {match.signature_id for match in matches} == {signature}
    assert any("autonomous" in match.capabilities() for match in matches)
    assert structured_code_matches(index, "metadata" + path[path.rfind(".") :], text) == []


def test_codex_inactive_profile_does_not_add_autonomous_authority(index):
    text = 'approval_policy = "on-request"\n[profiles.danger]\napproval_policy = "never"'
    assert structured_code_matches(index, ".codex/config.toml", text) == []
    assert structured_code_matches(index, ".codex/config.toml", 'profile = "danger"\n' + text)


def test_langgraph_accepts_documented_object_entry_point():
    data = {"graphs": {"agent": {"path": "./agent.py:graph", "config": {}}}}
    assert parse_agent_manifest("langgraph.json", json.dumps(data), "langgraph").valid


@pytest.mark.parametrize(
    "key,interface",
    [
        ("supportedInterfaces", {"url": "agent.example.test:443", "protocolBinding": "GRPC"}),
        ("supported_interfaces", {"url": "agent.example.test:443", "protocol_binding": "GRPC"}),
        ("additionalInterfaces", {"url": "agent.example.test:443", "transport": "GRPC"}),
    ],
)
def test_a2a_accepts_documented_grpc_interfaces(key, interface):
    data = {
        "name": "Assistant",
        "version": "1.0",
        "capabilities": {},
        "skills": [{"id": "x", "name": "Summarize"}],
        key: [interface],
    }
    assert parse_agent_manifest("agent-card.json", json.dumps(data), "a2a").valid


@pytest.mark.parametrize(
    "data",
    [
        {"nodes": [{"type": "@n8n/n8n-nodes-langchain.chainLlm"}]},
        {
            "kind": "app",
            "app": {"mode": "completion"},
            "model_config": {"model": {"provider": "openai", "name": "gpt-4o"}},
        },
        {
            "kind": "app",
            "app": {"mode": "chat"},
            "model_config": {"model": {"provider": "openai", "name": "gpt-4o"}},
        },
    ],
)
def test_ai_only_workflows_are_not_agents(tmp_path, run_connector, index, data):
    matches = structured_code_matches(index, "workflow.json", json.dumps(data))
    assert matches and all(match.extra.get("verified_agent") is False for match in matches)
    (tmp_path / "workflow.json").write_text(json.dumps(data))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(finding.kind == Kind.WORKFLOW for finding in findings)
    assert not any(finding.kind == Kind.AGENT for finding in findings)


LIMITS = "structured configuration exceeds parser limits"
ENTITIES = "structured configuration declares XML entities or attribute defaults; not parsed"


def _scan(index, root, files: dict[str, str], **config):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


# Python 3.12+ parses a few thousand JSON levels; this depth exceeds the C
# recursion limit on every supported version.
DEEP_JSON = '{"nodes": [], "pinData": ' + "[" * 200_000 + "]" * 200_000 + "}"
XML_BOMB = (
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
    + "".join(f'<!ENTITY {chr(98 + i)} "' + f"&{chr(97 + i)};" * 10 + '">' for i in range(8))
    + "]><GenAiPlanner>&i;</GenAiPlanner>"
)


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("flows/workflow.json", DEEP_JSON),
        ("flows/workflow.yaml", "a: " + "[" * 3000 + "]" * 3000),
        ("flows/workflow.toml", "x = " + "[" * 5000 + "]" * 5000),
        ("force-app/agent.genAiPlanner-meta.xml", XML_BOMB),
    ],
    ids=["json-depth", "yaml-depth", "toml-depth", "xml-expansion"],
)
def test_parser_limits_are_not_syntax_errors(index, rel, text):
    # XML entity declarations are refused before parsing, so the bomb never
    # depends on the runtime Expat's amplification limit.
    expected = [ENTITIES if rel.endswith(".xml") else LIMITS]
    errors: list[str] = []
    limits: list[str] = []
    assert structured_code_matches(index, rel, text, errors, limits) == []
    assert limits == expected and errors == []
    # A caller that does not separate them still fails closed.
    fallback: list[str] = []
    structured_code_matches(index, rel, text, fallback)
    assert fallback == expected


@pytest.mark.parametrize(
    "text",
    [
        '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY n "Planner">]><GenAiPlanner><a>&n;</a></GenAiPlanner>',
        '<!DOCTYPE p [<!ENTITY % ext "x">]><GenAiPlanner><a/></GenAiPlanner>',
        # Attribute defaults are applied to every element: the same amplification.
        '<!DOCTYPE GenAiPlanner [<!ATTLIST a v CDATA "xxxxxxxx">]><GenAiPlanner><a/><a/></GenAiPlanner>',
    ],
    ids=["general-entity", "parameter-entity", "attribute-default"],
)
def test_xml_entity_declarations_are_refused_without_parsing(index, monkeypatch, text):
    def fail(*_: object) -> None:
        raise AssertionError("entity-declaring XML must not reach the parser")

    monkeypatch.setattr("shadowscan.connectors.code.semantic_config.ET.fromstring", fail)
    errors: list[str] = []
    limits: list[str] = []
    assert structured_code_matches(index, "force-app/agent.genAiPlanner-meta.xml", text, errors, limits) == []
    assert limits == [ENTITIES] and errors == []


@pytest.mark.parametrize(
    "text",
    [
        '<!DOCTYPE project [<!ENTITY common SYSTEM "common.xml">]><project>&common;</project>',
        '<?xml version="1.0"?><!DOCTYPE book [<!ENTITY product "Widget">]><book>&product;</book>',
        '<!DOCTYPE x [<!ATTLIST item id CDATA "0">]><x><item/></x>',
    ],
    ids=["ant-build", "docbook", "attribute-default"],
)
def test_other_xml_declaring_entities_is_skipped_unparsed(index, monkeypatch, text):
    def fail(*_: object) -> None:
        raise AssertionError("entity-declaring XML must not reach the parser")

    monkeypatch.setattr("shadowscan.connectors.code.semantic_config.ET.fromstring", fail)
    errors: list[str] = []
    limits: list[str] = []
    assert structured_code_matches(index, "build/build.xml", text, errors, limits) == []
    assert not errors and not limits


def test_ordinary_xml_with_entities_keeps_the_scan_complete(tmp_path, index):
    _, ctx = _scan(
        index,
        tmp_path,
        {
            "build.xml": '<!DOCTYPE project [<!ENTITY common SYSTEM "common.xml">]><project>&common;</project>',
            "docs/manual.xml": '<!DOCTYPE book [<!ENTITY product "Widget">]><book>&product;</book>',
        },
    )
    assert not ctx.stats.incomplete and not ctx.stats.errors


def test_xml_doctype_without_entities_is_still_parsed(index):
    text = '<?xml version="1.0"?><!DOCTYPE GenAiPlanner SYSTEM "x.dtd"><GenAiPlanner><a/></GenAiPlanner>'
    errors: list[str] = []
    limits: list[str] = []
    matches = structured_code_matches(index, "force-app/agent.genAiPlanner-meta.xml", text, errors, limits)
    assert [m.signature_id for m in matches] == ["platform.salesforce-agentforce"]
    assert not errors and not limits


def test_parser_limits_keep_an_ordinary_config_scan_incomplete(tmp_path, index):
    _, ctx = _scan(index, tmp_path, {"flows/workflow.json": DEEP_JSON})
    assert ctx.stats.incomplete
    assert any("flows/workflow.json" in error and LIMITS in error for error in ctx.stats.errors)


def test_syntax_errors_in_ordinary_configs_still_only_warn(tmp_path, index):
    _, ctx = _scan(index, tmp_path, {"flows/workflow.json": '{"nodes": '})
    assert not ctx.stats.incomplete and not ctx.stats.errors
