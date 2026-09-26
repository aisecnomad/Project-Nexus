"""SARIF output must stay valid for the 2.1.0 schema and for GitHub code scanning."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, RiskLevel, ScanResult, ScanStats, Surface
from shadowscan.reporters.sarif import _physical_locations, render_sarif

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "tests" / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
RULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")  # GitHub code scanning requirement for rule names
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")  # SARIF section 3.9
LEVELS = {"none", "note", "warning", "error"}
STARTED = "2026-01-01T00:00:00+00:00"


def _stats(**overrides: Any) -> ScanStats:
    return ScanStats(connector="code.filesystem", started_at=STARTED, **overrides)


def _finding(*evidence: Evidence, **overrides: Any) -> Finding:
    fields: dict[str, Any] = dict(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE, title="Agent project",
        resource="/repo/app", resource_type="project", frameworks=["framework.langchain"],
    )
    fields.update(overrides)
    finding = Finding(**fields)
    for item in evidence:
        finding.add_evidence(item)
    finding.metadata.setdefault("scan_root", "/repo")
    return finding


def _render(*findings: Finding, stats: list[ScanStats] | None = None, **result_fields: Any) -> dict[str, Any]:
    result = ScanResult(findings=list(findings), stats=stats if stats is not None else [_stats()], **result_fields)
    return json.loads(render_sarif(result))


def _nulls(node: Any, path: str = "$") -> list[str]:
    """Paths of every key whose value is null."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if value is None:
                found.append(f"{path}.{key}")
            found.extend(_nulls(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found.extend(_nulls(value, f"{path}[{i}]"))
    return found


def _assert_spec_rules(document: dict[str, Any]) -> None:
    """Constraints from the SARIF spec and GitHub that the JSON schema does not express."""
    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert document["version"] == "2.1.0"
    assert _nulls(document) == []
    for run in document["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            assert RULE_NAME.match(rule["name"]), rule["name"]
            assert rule["defaultConfiguration"]["level"] in LEVELS
            assert 0.0 <= float(rule["properties"]["security-severity"]) <= 10.0
        for res in run["results"]:
            assert res["level"] in LEVELS
            assert res["partialFingerprints"] and all(isinstance(v, str) for v in res["partialFingerprints"].values())
            assert res["locations"]
            for location in res["locations"]:
                physical = location.get("physicalLocation", {})
                if "region" in physical:
                    # Section 3.30: a region is a text region or a binary region, never a bare snippet.
                    assert {"startLine", "charOffset", "byteOffset"} & set(physical["region"]), physical["region"]
                artifact = physical.get("artifactLocation")
                if artifact and artifact["uri"].startswith("file://"):
                    assert "uriBaseId" not in artifact, artifact
                for logical in location.get("logicalLocations", []):
                    assert logical["name"] and logical.get("kind", "x")
        for invocation in run["invocations"]:
            assert isinstance(invocation["executionSuccessful"], bool)
            for key in ("startTimeUtc", "endTimeUtc"):
                if key in invocation:
                    assert UTC_TIMESTAMP.match(invocation[key]), invocation[key]
            for notification in invocation.get("toolExecutionNotifications", []):
                assert notification["level"] in LEVELS and notification["message"]["text"]


def _validate(document: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = [f"{'/'.join(map(str, error.absolute_path))}: {error.message}" for error in validator.iter_errors(document)]
    assert not errors, "\n".join(errors)
    _assert_spec_rules(document)


# ----------------------------------------------------------------- regions


def test_snippet_without_line_yields_no_region():
    evidence = Evidence(signal="dependency:pypi:langchain", description="dependency", location="/repo/requirements.txt", snippet="langchain==0.3.0")
    (location,) = _physical_locations(_finding(evidence))
    assert location["physicalLocation"] == {"artifactLocation": {"uri": "requirements.txt", "uriBaseId": "%SRCROOT%"}}
    assert location["properties"] == {"snippet": "langchain==0.3.0"}


def test_line_yields_text_region_with_snippet():
    evidence = Evidence(signal="import", description="import", location="/repo/app.py:3", snippet="from langchain.agents import x")
    (location,) = _physical_locations(_finding(evidence))
    assert location["physicalLocation"]["region"] == {"startLine": 3, "snippet": {"text": "from langchain.agents import x"}}
    assert "properties" not in location


def test_region_edge_cases():
    finding = _finding(
        Evidence(signal="import", description="import", location="/repo/app.py:7"),
        Evidence(signal="dependency", description="dependency", location="/repo/go.mod:0", snippet="go: example.com/mcp v1"),
        Evidence(signal="config", description="config", location="/repo/agent.yaml"),
        Evidence(signal="import", description="import", location="/repo/long.py:2", snippet="x" * 300),
    )
    plain, zero, bare, long = _physical_locations(finding)
    assert plain["physicalLocation"]["region"] == {"startLine": 7}
    # Line 0 is not a valid startLine (minimum 1): treat it like a missing line.
    assert "region" not in zero["physicalLocation"] and zero["properties"] == {"snippet": "go: example.com/mcp v1"}
    assert bare == {"physicalLocation": {"artifactLocation": {"uri": "agent.yaml", "uriBaseId": "%SRCROOT%"}}}
    assert long["physicalLocation"]["region"]["snippet"] == {"text": "x" * 200}


def test_metadata_path_fallback_has_no_region():
    finding = _finding(Evidence(signal="remote", description="remote", location="https://example.invalid/agent", snippet="x"))
    finding.metadata["path"] = "/repo/services/agent"
    assert _physical_locations(finding) == [{"physicalLocation": {"artifactLocation": {"uri": "services/agent", "uriBaseId": "%SRCROOT%"}}}]


# ----------------------------------------------------------- other fields


@pytest.mark.parametrize("kind,signature", [
    (Kind.MCP_SERVER, "protocol.mcp"), (Kind.AGENT_CONFIG, "coding-agent.claude-code"),
    (Kind.INFRA, "cloud.aws-bedrock-agents"), (Kind.AGENT, "framework.langchain"),
])
def test_rule_names_match_github_pattern(kind, signature):
    document = _render(_finding(kind=kind, frameworks=[signature]))
    (rule,) = document["runs"][0]["tool"]["driver"]["rules"]
    assert rule["id"] == f"shadowscan/{kind.value}/{signature}"
    assert RULE_NAME.match(rule["name"]), rule["name"]
    assert rule["name"].startswith("shadowscan_")


@pytest.mark.parametrize("started,finished,expected_start,expected_end", [
    (STARTED, "2026-01-01T00:00:05+00:00", "2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z"),
    ("2026-01-01T02:00:00+02:00", None, "2026-01-01T00:00:00Z", None),
    ("2026-01-01T00:00:00", "2026-01-01T00:00:00.250000Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.250000Z"),
    ("not a timestamp", "", None, None),
])
def test_invocation_timestamps_are_utc_or_omitted(started, finished, expected_start, expected_end):
    (invocation,) = _render(started_at=started, finished_at=finished)["runs"][0]["invocations"]
    assert invocation.get("startTimeUtc") == expected_start
    assert invocation.get("endTimeUtc") == expected_end
    assert invocation["executionSuccessful"] is True and invocation["toolExecutionNotifications"] == []


def test_null_values_are_omitted_and_tags_are_distinct():
    finding = _finding(Evidence(signal="import", description="import", location="/repo/app.py:1"),
                       provider=None, owner=None, shadow=None, tags=["a", "a", "b"])
    document = _render(finding, finished_at=None)
    assert _nulls(document) == []
    (res,) = document["runs"][0]["results"]
    assert res["properties"]["tags"] == ["a", "b"]
    assert "owner" not in res["properties"] and "shadow" not in res["properties"]
    assert "endTimeUtc" not in document["runs"][0]["invocations"][0]


def test_non_code_findings_carry_logical_locations():
    cloud = _finding(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.CLOUD_RESOURCE, resource="bedrock-agent/ABC123", resource_type="bedrock-agent")
    untyped = _finding(surface=Surface.SAAS, connector="saas.slack", kind=Kind.BOT_APP, resource="bot/one", resource_type="")
    first, second = _render(cloud, untyped)["runs"][0]["results"]
    assert first["locations"] == [{"logicalLocations": [{"name": "bedrock-agent/ABC123", "kind": "bedrock-agent", "fullyQualifiedName": "bedrock-agent/ABC123"}]}]
    assert second["locations"] == [{"logicalLocations": [{"name": "bot/one", "fullyQualifiedName": "bot/one"}]}]


# ------------------------------------------------------- schema validation


def test_schema_rejects_an_invalid_document():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    broken = {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [{"message": {"text": "x"}, "level": "fatal"}]}]}
    messages = {error.message for error in validator.iter_errors(broken)}
    assert any("'name' is a required property" in m for m in messages)
    assert any("'fatal' is not one of" in m for m in messages)


def test_sample_scan_sarif_is_schema_valid(fixtures):
    cfg = ScanConfig(connectors=[ConnectorSpec(name="code.filesystem", config={"path": str(fixtures / "sample_repo"), "label": "repo"})],
                     inventory=[str(fixtures / "inventory" / "ops-provisioning-04.yaml")])
    result = Engine(cfg).run()
    assert result.complete and result.findings
    document = json.loads(render_sarif(result))
    _validate(document)
    physical = [loc["physicalLocation"] for res in document["runs"][0]["results"] for loc in res["locations"] if "physicalLocation" in loc]
    properties = [loc.get("properties", {}) for res in document["runs"][0]["results"] for loc in res["locations"] if "physicalLocation" in loc]
    # Manifest evidence carries a snippet without a line: the sample scan must exercise that path.
    assert any("region" not in loc and props.get("snippet") for loc, props in zip(physical, properties, strict=True))
    assert any("startLine" in loc.get("region", {}) for loc in physical)


def test_incomplete_scan_sarif_is_schema_valid():
    stats = [
        _stats(finished_at="2026-01-01T00:00:03+00:00"),
        ScanStats(connector="cloud.aws", started_at=STARTED, errors=["cannot enumerate scope"], warnings=["partial listing"], skipped=True, skip_reason="denied"),
    ]
    code = _finding(Evidence(signal="import", description="import", location="/repo/app.py:1", snippet="import openai"),
                    Evidence(signal="dependency", description="dependency", location="/repo/pyproject.toml", snippet="openai>=1"),
                    Evidence(signal="import", description="import", location="/elsewhere/agent.py:4"),
                    owner=None)
    cloud = _finding(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.CLOUD_RESOURCE, resource="bedrock-agent/ABC123", resource_type="bedrock-agent")
    code.risk.level = RiskLevel.CRITICAL
    document = _render(code, cloud, stats=stats, started_at=STARTED, finished_at="2026-01-01T00:00:09+00:00")
    _validate(document)
    (invocation,) = document["runs"][0]["invocations"]
    assert invocation["executionSuccessful"] is False
    assert [n["level"] for n in invocation["toolExecutionNotifications"]] == ["error", "error", "error"]
    assert invocation["startTimeUtc"] == "2026-01-01T00:00:00Z" and invocation["endTimeUtc"] == "2026-01-01T00:00:09Z"
