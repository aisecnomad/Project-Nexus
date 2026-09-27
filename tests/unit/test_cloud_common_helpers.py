"""Contracts of the helpers shared by the four cloud connectors."""

from __future__ import annotations

from typing import Any

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.common import (
    RecordDispatch,
    aggregate_caller_event,
    credential_name_matches,
    first_tag,
    string_list,
)
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import ScanStats


def context(index: Any) -> ConnectorContext:
    ctx = ConnectorContext(config={}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-27")
    return ctx


class _ExtendedGcp(GcpConnector):
    def _h_custom_agent_kind(self, rec: dict[str, Any]) -> None:
        return None


def test_record_dispatch_maps_handler_methods_to_record_kinds(index):
    dispatch = RecordDispatch(_ExtendedGcp(context(index)), "audit-event")
    assert {"reasoning-engine", "cloud-run-service", "custom-agent-kind"} <= set(dispatch.handlers)
    assert dispatch.kinds == set(dispatch.handlers) | {"audit-event"}
    assert dispatch.handlers["custom-agent-kind"].__name__ == "_h_custom_agent_kind"
    for cls, extra in ((AwsConnector, "account"), (AzureConnector, "resource"), (OciConnector, "tenancy")):
        assert extra not in RecordDispatch(cls(context(index))).kinds  # envelope kinds are never handlers


def test_record_dispatch_counts_every_record_and_rejects_unknown_kinds(index):
    scanner = GcpConnector(context(index))
    dispatch = RecordDispatch(scanner, "audit-event")
    kinds = [dispatch.kind(rec) for rec in (
        {"_kind": "audit-event"}, {"_kind": "reasoning-engine"}, {"_kind": "vcn"}, {"_kind": 3}, {}, ["list"],
    )]
    assert kinds == ["audit-event", "reasoning-engine", None, None, None, None]
    stats = scanner.ctx.stats
    assert stats.objects_examined == 6
    assert stats.warnings == ["cloud.gcp: record has missing, invalid, or unsupported _kind"] * 4
    assert stats.incomplete
    dispatch.invalid("agent fields")
    assert stats.warnings[-1] == "cloud.gcp: record has invalid agent fields"


def test_aggregate_caller_event_folds_counters_window_and_seed():
    callers: dict[tuple[str, str], dict[str, Any]] = {}
    key = ("project", "agent@example.com")
    first = aggregate_caller_event(
        callers, key, time="2025-09-02T00:00:00Z", tally={"methods": None}, tally_present={"agents": "adk/1"},
        seed={"project": "project", "regions": set()},
    )
    second = aggregate_caller_event(
        callers, key, time="2025-09-01T00:00:00Z", tally={"methods": "Predict"}, tally_present={"agents": ""},
        seed={"project": "ignored-after-creation", "regions": {"replaced"}},
    )
    third = aggregate_caller_event(callers, key, time=None, tally={"methods": "Predict"},
                                   tally_present={"agents": "adk/1"})
    assert first is second is third and list(callers) == [key]
    assert first["events"] == 3
    assert first["methods"] == {None: 1, "Predict": 2}  # tally counts a missing value too
    assert first["agents"] == {"adk/1": 2}  # tally_present skips empty values
    assert (first["first"], first["last"]) == ("2025-09-01T00:00:00Z", "2025-09-02T00:00:00Z")
    assert first["project"] == "project" and first["regions"] == set()


def test_first_tag_keeps_or_chain_semantics():
    assert first_tag({"owner": "", "Owner": "ops"}, "owner", "Owner") == "ops"
    assert first_tag({"owner": "", "team": None}, "owner", "team") is None
    assert first_tag({"owner": None, "team": ""}, "owner", "team") == ""
    assert first_tag(None, "owner") is None


def test_credential_name_matches_uses_env_names_then_provider_keywords(index):
    # "openai-api-key" is matched as the variable OPENAI_API_KEY, without any keyword.
    matches = credential_name_matches(index, "openai-api-key", ())
    assert matches and any(m.signature.category == "provider" for m in matches)
    assert credential_name_matches(index, "db-password", ("openai", "llm")) is None
    # A provider keyword alone qualifies the name, with no signature matches to apply.
    assert credential_name_matches(index, "team-llm-notes", ("llm",)) == []


def test_string_list_coercion():
    assert string_list("lambda", "services") == ["lambda"]
    assert string_list(["a", " b "], "x") == ["a", "b"]
    assert string_list("", "x") is None and string_list(None, "x") is None
    assert string_list("us-east-1", "regions", pattern=r"[a-z0-9-]+") == ["us-east-1"]
    with pytest.raises(ValueError):
        string_list(["a", 1], "x")
    with pytest.raises(ValueError):
        string_list("US East", "regions", pattern=r"[a-z0-9-]+")


def test_scope_values_are_deduplicated_without_reordering():
    assert string_list(["us-east-1", "us-west-2", " us-east-1 "], "regions") == ["us-east-1", "us-west-2"]
