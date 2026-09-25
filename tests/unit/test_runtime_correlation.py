import json

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector, normalise
from shadowscan.correlation import correlate_runtime
from shadowscan.models import Finding, Kind, Surface
from shadowscan.utils.redaction import credential_id


def static(resource="github:acme/agent", framework="framework.langchain"):
    return Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
                   title="LangChain dependencies", resource=resource, resource_type="project",
                   frameworks=[framework], model_providers=["provider.openai"])


def event(**kwargs):
    return {"service": "workload-1", "model": "gpt-4o", "provider": "openai",
            "user_agent": "langchain/0.3", "timestamp": "2026-01-01T00:00:00Z", **kwargs}


def gateways(index, records, bindings=None):
    config = {"label": "gateway-one", "input": "test-export.jsonl"}
    if bindings is not None:
        config["correlation_bindings"] = bindings
    return list(GatewayLogConnector(ConnectorContext(config=config, index=index)).analyze(records))


def binding(scope=None):
    return {"code_resource": "github:acme/agent", "caller": "principal:workload-1", "scope": scope or {}}


def test_global_provider_framework_or_display_name_is_not_a_workload_binding(index):
    code = static()
    logs = gateways(index, [event(service=code.resource)])
    code.metadata["caller"] = logs[0].metadata["caller"]
    code.metadata["related"] = [logs[0].id]
    correlate_runtime([code, *logs])
    assert code.metadata["runtime_activity"]["status"] == "unknown"


def test_exact_binding_records_window_provenance_and_explicit_production(index):
    code = static()
    logs = gateways(index, [event(environment="production"), event(environment="production", timestamp="2026-01-02T00:00:00Z")], [binding()])
    correlate_runtime([code, *logs])
    activity = code.metadata["runtime_activity"]
    assert activity["status"] == "observed" and activity["events"] == 2
    assert activity["production_observed"] and activity["production_events"] == 2
    assert activity["window"]["start"] == "2026-01-01T00:00:00+00:00"
    assert activity["last_seen"] == "2026-01-02T00:00:00+00:00"
    assert activity["sources"][0]["source"]["input"] == "test-export.jsonl"
    assert code.confidence == 0.0  # attribution is not a new independent static signal
    correlate_runtime([code, *logs])
    assert len([ev for ev in code.evidence if ev.signal == "runtime:gateway-observed"]) == 1


def test_production_cannot_be_inferred_from_caller_name_or_label(index):
    code = static()
    logs = gateways(index, [event(service="prod-agent")], [{**binding(), "caller": "principal:prod-agent"}])
    correlate_runtime([code, *logs])
    assert code.metadata["runtime_activity"]["status"] == "observed"
    assert not code.metadata["runtime_activity"]["production_observed"]


def test_timestamp_must_belong_to_matching_framework_event(index):
    code = static()
    logs = gateways(index, [event(timestamp=None), event(user_agent="other/1.0")], [binding()])
    correlate_runtime([code, *logs])
    assert code.metadata["runtime_activity"]["status"] == "unknown"
    assert code.metadata["runtime_activity"]["reason"] == "missing-event-timestamps"


def test_shared_provider_without_runtime_framework_is_unobserved(index):
    code = static()
    correlate_runtime([code, *gateways(index, [event(user_agent="OpenAI/Python 1.0")], [binding()])])
    assert code.metadata["runtime_activity"]["status"] == "unobserved"


def test_tenant_collisions_are_separate_and_cannot_bypass_binding(index):
    code = static()
    logs = gateways(index, [event(tenant_id="a"), event(tenant_id="b", environment="production")], [binding({"tenant": "a"})])
    assert len(logs) == 2 and logs[0].id != logs[1].id
    correlate_runtime([code, *logs])
    activity = code.metadata["runtime_activity"]
    assert activity["events"] == 1 and not activity["production_observed"]
    assert activity["sources"][0]["scope"] == {"tenant": "a"}
    code = static()
    correlate_runtime([code, *gateways(index, [event(tenant_id="b")], [binding({"tenant": "a"})])])
    assert code.metadata["runtime_activity"]["status"] == "unknown"


def test_missing_or_incomplete_scope_never_matches(index):
    for record in (event(tenant_id="a"), event(tenant_id="a", account_id="one")):
        code = static()
        correlate_runtime([code, *gateways(index, [record], [binding()])])
        assert code.metadata["runtime_activity"]["status"] == "unknown"


def test_invalid_binding_fails_with_explicit_configuration_error(index):
    from shadowscan.connectors.base import ConnectorError
    with pytest.raises(ConnectorError, match="scope"):
        gateways(index, [], [{"caller": "principal:workload-1", "code_resource": "github:acme/agent"}])


def test_ambiguous_static_resource_across_accounts_does_not_attribute_both(index):
    first, second = static(), static()
    first.account, second.account = "one", "two"
    correlate_runtime([first, second, *gateways(index, [event()], [binding()])])
    for code in (first, second):
        assert code.metadata["runtime_activity"]["status"] == "unknown"
        assert code.metadata["runtime_activity"]["reason"] == "ambiguous-code-resource"


@pytest.mark.parametrize("schema,extra", [("generic", {}), ("litellm", {"spend": 1}), ("portkey", {"trace_id": "t"}), ("access-log", {})])
def test_gateway_raw_credentials_never_survive_normalisation_or_report(index, schema, extra):
    secret = "opaque-key-that-has-no-vendor-pattern-123456"
    record = {**event(), "api_key": secret, "metadata": {"note": secret}, **extra}
    result = normalise(record, schema)
    assert secret not in str(result)
    assert result.caller_redacted
    assert "credential:hmac-sha256:" in result.caller
    assert credential_id(secret) not in result.caller
    connector = GatewayLogConnector(ConnectorContext(config={"format": schema}, index=index))
    findings = list(connector.analyze([record]))
    report = json.dumps([finding.to_dict() for finding in findings])
    assert findings and secret not in report and credential_id(secret) not in report
    assert findings[0].metadata["runtime_observations"][0]["code_resources"] == []


def test_exact_private_api_key_fingerprint_can_bind_without_report_disclosure(index):
    key = "opaque-key-with-an-explicit-fingerprint"
    code = static()
    mapping = {**binding(), "caller": "api-key:" + credential_id(key)}
    findings = gateways(index, [event(api_key=key)], [mapping])
    correlate_runtime([code, *findings])
    assert code.metadata["runtime_activity"]["status"] == "observed"
    assert findings[0].metadata["runtime_observations"][0]["code_resources"] == [code.resource]
    assert credential_id(key) not in json.dumps([finding.to_dict() for finding in findings])
