"""Redaction preserves gateway identity boundaries and trusted Event types."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector, normalise
from shadowscan.models import ScanStats
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
    assert all(scope.startswith("scope:sha256:") for scope in by_scope)
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
