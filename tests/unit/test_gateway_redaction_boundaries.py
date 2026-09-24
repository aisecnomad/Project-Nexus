"""Redaction preserves gateway identity boundaries and trusted Event types."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import (
    GatewayLogConnector,
    _restore_scope,
    normalise,
    normalise_with_record,
)
from shadowscan.correlation import correlate_runtime
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanStats, Surface
from shadowscan.utils.redaction import credential_id


def _scan(index, records, **config):
    ctx = ConnectorContext(index=index, config={"format": "generic", **config})
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    return list(GatewayLogConnector(ctx).analyze(records)), ctx


def test_short_credential_cannot_merge_different_tenant_scopes(index):
    records = [{"api_key": "a", "tenant_id": tenant, "model": "gpt-4o"}
               for tenant in ("tenant-1", "tenant-2", "tenant-1")]
    findings, ctx = _scan(index, records, correlation_bindings=[{
        "caller": f"api-key:{credential_id('a')}", "scope": {}, "code_resource": "github:org/app",
    }])
    assert len(findings) == 2
    by_scope = {f.metadata["correlation_scope"]["tenant"]: f for f in findings}
    assert len(by_scope) == 2
    assert all(scope.startswith("scope:hmac-sha256:") for scope in by_scope)
    assert sorted(f.metadata["events"] for f in by_scope.values()) == [1, 2]
    assert len({f.id for f in findings}) == 2
    assert all(f.metadata["correlation_scope_redacted"] for f in findings)
    assert all(obs["identity_assurance"] == "unverified" and not obs["code_resources"]
               for f in findings for obs in f.metadata["runtime_observations"])
    serialized = json.dumps([f.to_dict() for f in findings])
    assert "tenant-1" not in serialized and "tenant-2" not in serialized
    assert ctx.stats.incomplete
    assert any("scope labels were redacted" in warning for warning in ctx.stats.warnings)


def test_credential_shaped_tenant_label_cannot_impersonate_a_redacted_scope(index):
    records = [{"api_key": "a", "tenant_id": tenant, "model": "gpt-4o"}
               for tenant in ("tenant-1", credential_id("tenant-1"))]
    findings, ctx = _scan(index, records)
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2
    assert len({f.metadata["correlation_scope"]["tenant"] for f in findings}) == 2
    assert all(f.metadata["events"] == 1 for f in findings)
    assert all(f.metadata["correlation_scope_redacted"] for f in findings)
    assert ctx.stats.incomplete


def test_literal_generated_scope_label_is_rehashed_even_without_secret_overlap(index):
    record = {"api_key": "opaque-test-key", "token": "secret-tenant",
              "tenant_id": "secret-tenant", "model": "gpt-4o"}
    first = normalise(record, "generic").scope["tenant"]
    second_record = {**record, "tenant_id": first}
    second = normalise(second_record, "generic").scope["tenant"]
    findings, ctx = _scan(index, [record, second_record, {**record, "tenant_id": second}])
    assert first != second
    assert len(findings) == 3
    assert len({f.id for f in findings}) == 3
    assert len({f.metadata["correlation_scope"]["tenant"] for f in findings}) == 3
    assert all(f.metadata["events"] == 1 for f in findings)
    assert all(f.metadata["correlation_scope_redacted"] for f in findings)
    assert ctx.stats.incomplete


def test_redacted_low_entropy_scopes_group_without_public_dictionary_hash(index):
    records = [{"service": "worker", "token": tenant, "tenant_id": tenant,
                "model": "gpt-4o", "timestamp": "2026-09-24T12:00:00Z",
                "user_agent": "langchain/0.3"} for tenant in ("t1", "t2", "t1")]
    binding = {"code_resource": "github:org/app", "caller": "principal:worker", "scope": {"tenant": "t1"}}
    findings, ctx = _scan(index, records, correlation_bindings=[binding])
    assert len(findings) == 2
    assert sorted(f.metadata["events"] for f in findings) == [1, 2]
    assert len({f.id for f in findings}) == 2
    assert ctx.stats.incomplete
    serialized = json.dumps([f.to_dict() for f in findings])
    assert "t1" not in serialized and "t2" not in serialized
    source_id = findings[0].metadata["runtime_source"]["id"]
    assert all(f.metadata["runtime_source"]["id"] == source_id for f in findings)
    # The source ID must not be an unkeyed hash of the binding config either:
    # that config itself may contain the short credential-bearing scope label.
    for guess in ("t1", "t2", "a", "b"):
        guessed_binding = {**binding, "scope": {"tenant": guess}}
        source_preimage = json.dumps(
            ["", None, "generic", 1, True, 5_000_000, [guessed_binding]], sort_keys=True,
        )
        assert source_id != hashlib.sha256(source_preimage.encode()).hexdigest()
    for finding in findings:
        scope = finding.metadata["correlation_scope"]["tenant"]
        assert scope.startswith("scope:hmac-sha256:")
        assert len(scope.removeprefix("scope:hmac-sha256:")) == 64
        for guess in ("t1", "t2", "a", "b"):
            preimage = json.dumps(["shadowscan.gateway.scope.v1", "tenant", guess], separators=(",", ":"))
            assert scope != "scope:hmac-sha256:" + hashlib.sha256(preimage.encode()).hexdigest()
        assert finding.metadata["runtime_observations"][0]["identity_assurance"] == "unverified"
        assert finding.metadata["runtime_observations"][0]["code_resources"] == []

    code = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
        title="LangChain", resource="github:org/app", resource_type="project",
        frameworks=["framework.langchain"],
    )
    correlate_runtime([code, *findings])
    assert code.metadata["runtime_activity"]["status"] == "unknown"

    repeated, _ = _scan(index, records, correlation_bindings=[binding])
    # Distinct scanner instances use independent secrets. Cross-run finding
    # IDs for redacted scopes cannot be used to infer remediation or compare.
    assert {f.metadata["correlation_scope"]["tenant"] for f in findings}.isdisjoint(
        {f.metadata["correlation_scope"]["tenant"] for f in repeated},
    )
    assert source_id != repeated[0].metadata["runtime_source"]["id"]


def test_legacy_public_scope_hash_cannot_impersonate_a_redacted_label(index):
    guessed = "scope:sha256:" + "a" * 64
    record = {"service": "worker", "tenant_id": guessed, "model": "gpt-4o"}
    finding, = _scan(index, [record])[0]
    assert finding.metadata["correlation_scope"]["tenant"].startswith("scope:hmac-sha256:")
    assert finding.metadata["correlation_scope"]["tenant"] != guessed
    assert finding.metadata["correlation_scope_redacted"] is True


def test_current_opaque_scope_label_cannot_impersonate_generated_label():
    key = b"fixed-private-test-only-key"
    first, redacted = _restore_scope({"tenant": "tiny"}, [("[REDACTED]",)], key)
    second, redacted_again = _restore_scope(
        {"tenant": first["tenant"]}, [(first["tenant"],)], key,
    )
    assert redacted and redacted_again
    assert first["tenant"] != second["tenant"]


def test_overlapping_short_key_and_scope_never_publish_guessable_fingerprints(index):
    records = [
        {"api_key": key, "token": key, "tenant_id": key, "model": "gpt-4o"}
        for key in ("t1", "t2", "t1")
    ]
    findings, ctx = _scan(index, records)
    assert len(findings) == 2
    assert sorted(f.metadata["events"] for f in findings) == [1, 2]
    assert len({f.resource for f in findings}) == 2
    assert all(f.metadata["correlation_scope_redacted"] for f in findings)
    assert all(f.metadata["runtime_observations"][0]["identity_assurance"] == "unverified" for f in findings)
    report = json.dumps([f.to_dict() for f in findings])
    for key in ("t1", "t2"):
        assert key not in report and credential_id(key) not in report
    for finding in findings:
        assert finding.resource.startswith("api-key:credential:hmac-sha256:")
        assert finding.metadata["correlation_scope"]["tenant"].startswith("scope:hmac-sha256:")
    assert ctx.stats.incomplete


def test_short_secret_in_principal_keeps_callers_distinct_without_public_hash(index):
    records = [
        {"service": key, "token": key, "tenant_id": "other", "model": "gpt-4o"}
        for key in ("t1", "t2", "t1")
    ]
    findings, ctx = _scan(index, records)
    assert len(findings) == 2
    assert sorted(f.metadata["events"] for f in findings) == [1, 2]
    assert all(f.resource.startswith("principal:caller:hmac-sha256:") for f in findings)
    report = json.dumps([f.to_dict() for f in findings])
    for key in ("t1", "t2"):
        assert key not in report and credential_id(f"principal:{key}") not in report
    assert all(f.metadata["runtime_observations"][0]["identity_assurance"] == "unverified" for f in findings)
    assert not ctx.stats.incomplete


def test_binding_scope_cannot_be_guessed_from_source_id_when_event_is_filtered(index):
    binding = {"code_resource": "github:org/app", "caller": "principal:worker", "scope": {"tenant": "t1"}}
    records = [
        {"service": "worker", "token": "t1", "tenant_id": "t1", "path": "/favicon.ico"},
        {"service": "worker", "tenant_id": "other", "model": "gpt-4o"},
    ]
    first, ctx = _scan(index, records, correlation_bindings=[binding])
    second, _ = _scan(index, records, correlation_bindings=[binding])
    assert len(first) == len(second) == 1
    assert first[0].metadata["events"] == 1
    assert first[0].metadata["correlation_scope"] == {"tenant": "other"}
    source_id = first[0].metadata["runtime_source"]["id"]
    assert source_id != second[0].metadata["runtime_source"]["id"]
    assert first[0].id != second[0].id
    source_preimage = json.dumps(["", None, "generic", 1, True, 5_000_000, [binding]], sort_keys=True)
    assert source_id != hashlib.sha256(source_preimage.encode()).hexdigest()
    assert "t1" not in json.dumps(first[0].to_dict())
    assert not ctx.stats.incomplete


def test_gateway_dump_records_does_not_export_raw_short_key_ids(tmp_path, index):
    source = tmp_path / "gateway.jsonl"
    source.write_text(json.dumps({"api_key_id": "t1", "model": "gpt-4o"}) + "\n")
    export = tmp_path / "export"
    result = Engine(ScanConfig(
        connectors=[ConnectorSpec("gateway.logs", {"input": str(source), "format": "generic"})],
        dump_records=str(export),
    ), index=index).run()
    assert result.complete and len(result.findings) == 1
    assert "t1" not in json.dumps(result.findings[0].to_dict())
    manifest = json.loads((export / "manifest.json").read_text())
    assert manifest["exports"][0]["filename"] is None
    assert manifest["exports"][0]["exported"] is False
    assert list(export.glob("*.jsonl")) == []


@pytest.mark.parametrize("record", [
    {"api_key_id": "t1", "user_id": "alias-t1", "model": "gpt-4o", "n_requests": 1},
    {"api_key_id": "t1", "model": "gpt-4o-t1", "metadata": {"note": "t1"}, "n_requests": 1},
])
def test_short_key_id_embedded_in_other_fields_is_removed_from_report(index, record):
    event, clean_record = normalise_with_record(record, "openai-usage")
    assert event is not None and clean_record is not None
    assert "t1" not in str(event) and "t1" not in json.dumps(clean_record)
    findings, ctx = _scan(index, [record], format="openai-usage")
    assert len(findings) == 1 and findings[0].metadata["events"] == 1
    assert "t1" not in json.dumps(findings[0].to_dict())
    assert not ctx.stats.incomplete


def test_imported_public_fingerprint_is_withheld_without_losing_exact_binding(index):
    public_id = credential_id("t1")
    record = {"api_key_id": public_id, "model": public_id,
              "metadata": {"note": public_id, f"label-{public_id}": "secret"}, "n_requests": 1}
    event, clean_record = normalise_with_record(record, "openai-usage")
    assert event is not None and clean_record is not None
    assert public_id not in str(event) and public_id not in json.dumps(clean_record)
    findings, ctx = _scan(index, [record], format="openai-usage", correlation_bindings=[{
        "caller": f"openai:{public_id}", "scope": {}, "code_resource": "github:org/app",
    }])
    assert len(findings) == 1
    assert public_id not in json.dumps(findings[0].to_dict())
    observation = findings[0].metadata["runtime_observations"][0]
    assert observation["code_resources"] == ["github:org/app"]
    assert observation["identity_assurance"] == "provider-authenticated-field"
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("context,scope", [
    ({"tenant_id": "org-one"}, {"tenant": "org-one"}),
    ({"metadata": {"tenant_id": "org-one"}}, {"tenant": "org-one"}),
    ({"account_id": "org-one"}, {"account": "org-one"}),
    ({"metadata": {"project_id": "proj-one"}}, {"project": "proj-one"}),
    ({"workspace_id": "work-one"}, {"workspace": "work-one"}),
])
def test_short_secret_in_source_field_names_does_not_erase_safe_scope_values(index, context, scope):
    findings, ctx = _scan(index, [{"api_key": "a", "model": "gpt-4o", **context}])
    assert len(findings) == 1
    assert findings[0].metadata["correlation_scope"] == scope
    assert findings[0].metadata["correlation_scope_redacted"] is False
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("label", ["--token", "--password", "--api-key"])
def test_argument_like_labels_do_not_redact_neighboring_event_timestamps(index, label):
    record = {"service": label, "timestamp": "2026-09-24T12:00:00Z", "model": "gpt-4o"}
    event = normalise(record, "generic")
    assert event.timestamp == datetime(2026, 9, 24, 12, tzinfo=UTC)
    findings, ctx = _scan(index, [record])
    assert len(findings) == 1 and findings[0].metadata["events"] == 1
    assert findings[0].first_seen == "2026-09-24T12:00:00+00:00"
    assert not ctx.stats.incomplete


def test_argument_like_model_does_not_redact_neighboring_provider(index):
    record = {"service": "worker", "model": "--token", "provider": "openai"}
    event = normalise(record, "generic")
    assert event.model == "--token" and event.provider == "openai"
    findings, ctx = _scan(index, [record])
    assert len(findings) == 1
    assert findings[0].metadata["providers"] == {"openai": 1}
    assert not ctx.stats.incomplete
