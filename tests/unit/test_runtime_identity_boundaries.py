"""Runtime attribution requires intact and unambiguous workload identities."""

from __future__ import annotations

import json

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector
from shadowscan.correlation import correlate_runtime
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface


def _code(resource="github:acme/agent", **identity):
    return Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
        title="LangChain dependencies", resource=resource, resource_type="project",
        frameworks=["framework.langchain"], **identity,
    )


def _event():
    return {
        "service": "workload-one", "model": "gpt-4o", "provider": "openai",
        "user_agent": "langchain/0.3", "timestamp": "2026-01-01T00:00:00Z",
        "environment": "production",
    }


def _gateway(index, resource="github:acme/agent"):
    config = {"input": "export.jsonl", "correlation_bindings": [
        {"code_resource": resource, "caller": "principal:workload-one", "scope": {}},
    ]}
    findings = list(GatewayLogConnector(ConnectorContext(config=config, index=index)).analyze([_event()]))
    for finding in findings:
        finding.sanitize()
    return findings


def test_engine_never_attributes_colliding_redacted_resource_bindings(tmp_path, index):
    specs = []
    resources = ["github:acme/private?api_key=first-private-resource-value",
                 "github:acme/private?api_key=second-private-resource-value"]
    for number, resource in enumerate(resources):
        repo = tmp_path / f"repo-{number}"
        repo.mkdir()
        (repo / "requirements.txt").write_text("langchain==0.3.0\n")
        specs.append(ConnectorSpec("code.filesystem", {"path": str(repo)}, label=resource))
    export = tmp_path / "gateway.jsonl"
    export.write_text(json.dumps(_event()) + "\n")
    specs.append(ConnectorSpec("gateway.logs", {
        "input": str(export), "correlation_bindings": [
            {"code_resource": resources[0], "caller": "principal:workload-one", "scope": {}},
        ],
    }))

    result = Engine(ScanConfig(connectors=specs), index=index).run()
    code = [finding for finding in result.findings if finding.surface == Surface.CODE]
    assert result.complete and len(code) == 2
    assert len({finding.id for finding in code}) == 2
    assert len({finding.resource for finding in code}) == 1
    for finding in code:
        activity = finding.metadata["runtime_activity"]
        assert activity["status"] == "unknown"
        assert activity["reason"] == "redacted-or-missing-code-identity"
        assert not activity["production_observed"]
    assert "first-private-resource-value" not in result.to_json()
    assert "second-private-resource-value" not in result.to_json()


@pytest.mark.parametrize("field", ["provider", "account", "region"])
def test_redacted_code_scope_cannot_establish_runtime_binding(index, field):
    code = _code(**{field: "[REDACTED]"})
    correlate_runtime([code, *_gateway(index)])
    assert code.metadata["runtime_activity"]["status"] == "unknown"
    assert code.metadata["runtime_activity"]["reason"] == "redacted-or-missing-code-identity"


def test_region_distinguishes_ambiguous_code_resources(index):
    first = _code(provider="github", account="acme", region="region-one")
    second = _code(provider="github", account="acme", region="region-two")
    correlate_runtime([first, second, *_gateway(index)])
    for finding in (first, second):
        assert finding.metadata["runtime_activity"]["status"] == "unknown"
        assert finding.metadata["runtime_activity"]["reason"] == "ambiguous-code-resource"


@pytest.mark.parametrize("assurance", [None, "", "unknown", "unverified", [], {}])
def test_runtime_binding_requires_recognized_identity_assurance(index, assurance):
    code = _code()
    gateways = _gateway(index)
    observation = gateways[0].metadata["runtime_observations"][0]
    if assurance is None:
        observation.pop("identity_assurance")
    else:
        observation["identity_assurance"] = assurance
    correlate_runtime([code, *gateways])
    assert code.metadata["runtime_activity"]["status"] == "unknown"
    assert not code.metadata["runtime_activity"]["production_observed"]


def test_recorrelation_clears_activity_when_static_framework_is_removed(index):
    code = _code()
    findings = [code, *_gateway(index)]
    correlate_runtime(findings)
    assert code.metadata["runtime_activity"]["status"] == "observed"
    code.frameworks.clear()
    correlate_runtime(findings)
    assert "runtime_activity" not in code.metadata
    assert not any(evidence.signal == "runtime:gateway-observed" for evidence in code.evidence)
