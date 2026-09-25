"""Cloud exports must distinguish valid absence from unsupported records."""
from __future__ import annotations

import copy
import json

import pytest

from shadowscan.cli import _exit_code
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.engine import Engine
from shadowscan.models import ScanResult
from shadowscan.reporters.sarif import render_sarif

CASES = [
    (AwsConnector, {"_kind": "bedrock-agent", "agentId": "one", "agentName": "Agent"}, "agentId", {"_action_groups": [1]}),
    (AzureConnector, {"_kind": "resource", "id": "one", "name": "OpenAI", "type": "microsoft.cognitiveservices/accounts", "kind": "OpenAI"}, "id", {"tags": [1]}),
    (GcpConnector, {"_kind": "reasoning-engine", "name": "one", "displayName": "Agent"}, "name", {"spec": 1}),
    (OciConnector, {"_kind": "genai-agent", "id": "one"}, "id", {"_tools": [1]}),
]


def _scan(cls, path, index):
    connector = cls(ConnectorContext({"input": str(path)}, index=index))
    findings = connector.run()
    return ScanResult(findings=findings, stats=[connector.ctx.stats])


def _incomplete(result):
    assert not result.complete
    assert _exit_code(result, None) == 3
    assert json.loads(render_sarif(result))["runs"][0]["invocations"][0]["executionSuccessful"] is False


@pytest.mark.parametrize("cls,valid,identity,nested", CASES)
@pytest.mark.parametrize("bad_kind", [None, "future-secret-kind", "", 1, True, ["bedrock-agent"], {"kind": "agent"}])
def test_unrecognized_cloud_record_is_incomplete_and_preserves_neighbors(tmp_path, index, cls, valid, identity, nested, bad_kind):
    path = tmp_path / "export.json"
    second = {**valid, identity: "two"}
    malformed = {"untrusted": "OPAQUE-sensitive-value"}
    if bad_kind is not None:
        malformed["_kind"] = bad_kind
    path.write_text(json.dumps([valid, malformed, second]))
    result = _scan(cls, path, index)
    assert {finding.resource for finding in result.findings} == {"one", "two"}
    _incomplete(result)
    assert "OPAQUE-sensitive-value" not in repr(result.stats)
    assert "future-secret-kind" not in repr(result.stats)


@pytest.mark.parametrize("cls,valid,identity,nested", CASES)
@pytest.mark.parametrize("defect", ["missing-id", "wrong-id-type", "nested-shape"])
def test_malformed_cloud_fields_do_not_hide_valid_neighbors(tmp_path, index, cls, valid, identity, nested, defect):
    malformed = copy.deepcopy(valid)
    if defect == "missing-id":
        malformed.pop(identity)
    elif defect == "wrong-id-type":
        malformed[identity] = ["not-a-string"]
    else:
        malformed.update(nested)
    path = tmp_path / "export.json"
    path.write_text(json.dumps([valid, malformed, {**valid, identity: "two"}]))
    result = _scan(cls, path, index)
    assert {finding.resource for finding in result.findings} == {"one", "two"}
    _incomplete(result)


@pytest.mark.parametrize("cls,valid,identity,nested", CASES)
def test_unknown_cloud_records_are_never_cached(tmp_path, index, cls, valid, identity, nested):
    path = tmp_path / "export.json"
    path.write_text(json.dumps([valid, {"_kind": "unsupported"}]))
    config = ScanConfig(connectors=[ConnectorSpec(cls.name, {"input": str(path)})], incremental=True, state_dir=str(tmp_path / "state"), parallel=1)
    for _ in range(2):
        result = Engine(config, index).run()
        _incomplete(result)
        assert len(result.findings) == 1
        assert not result.stats[0].cached
    assert not list((tmp_path / "state").glob("*.json"))


@pytest.mark.parametrize("cls,record", [
    (AwsConnector, {"_kind": "account", "account": "123456789012"}),
    (AwsConnector, {"_kind": "bedrock-guardrail", "guardrailId": "known"}),
    (AzureConnector, {"_kind": "diagnostics", "_account": "/account", "settings": []}),
    (AzureConnector, {"_kind": "deployment", "_account": "/account", "properties": {}}),
    (GcpConnector, {"_kind": "project", "project": "test", "ai_services": []}),
    (OciConnector, {"_kind": "tenancy", "tenancy": "ocid1.tenancy.example"}),
    (OciConnector, {"_kind": "genai-agent-endpoint", "agent_id": "known"}),
])
def test_recognized_metadata_and_nonfinding_cloud_records_remain_valid(tmp_path, index, cls, record):
    path = tmp_path / "export.json"
    path.write_text(json.dumps([record]))
    result = _scan(cls, path, index)
    assert result.complete
    assert not result.findings
