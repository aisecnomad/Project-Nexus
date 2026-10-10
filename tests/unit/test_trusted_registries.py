"""options.trusted_registries and the engine's registry pass, end to end through fake connectors."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

import shadowscan.engine as engine_module
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig, validate_trusted_registries
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.registries import (
    MAX_TRUSTED_REGISTRIES,
    RECONCILIATION_KEY,
    RECORD_KEY,
    RECORD_SCHEMA,
    TrustedRegistry,
    registry_evidence,
)
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.redaction import REDACTED

ACCOUNT = "123456789012"
REGION = "us-east-1"
RUNTIME = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/agent-a1"
SHADOW_RUNTIME = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/agent-zz"
REGISTRY = "aws-agent-registry"
REGISTRY_ARN = f"arn:aws:agent-registry:{REGION}:{ACCOUNT}:registry/abcd1234abcd"
TRUSTED = [{"registry": REGISTRY, "id": REGISTRY_ARN}]


def _record(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "registry": REGISTRY,
        "registry_id": REGISTRY_ARN,
        "record_id": "rec-1",
        "status": "approved",
        "descriptor_type": "agent",
        "bindings": [
            {
                "resource": RUNTIME,
                "provider": "aws",
                "account": ACCOUNT,
                "region": REGION,
                "coverage": "in-scope",
            }
        ],
        "publisher": "platform-team",
        "listing_complete": True,
        # A person approved it; other approval modes need allow_auto_approved.
        "approval_mode": "manual",
    }
    value.update(overrides)
    return value


def _record_finding(value: Any) -> Finding:
    finding = Finding(
        surface=Surface.CLOUD,
        connector="test.registry",
        kind=Kind.AGENT,
        title="Registry record rec-1",
        resource=f"{REGISTRY_ARN}/record/rec-1",
        resource_type="agent-registry-record",
        provider="aws",
        account=ACCOUNT,
        region=REGION,
        evidence=[registry_evidence(REGISTRY, "listed in the agent registry")],
        metadata={RECORD_KEY: value},
    )
    finding.recompute_confidence()
    return finding


def _runtime(resource: str = RUNTIME) -> Finding:
    finding = Finding(
        surface=Surface.CLOUD,
        connector="test.observed",
        kind=Kind.AGENT,
        title=f"AgentCore runtime {resource.rsplit('/', 1)[-1]}",
        resource=resource,
        resource_type="agentcore-runtime",
        provider="aws",
        account=ACCOUNT,
        region=REGION,
        evidence=[Evidence("cloud:agentcore-runtime", "runtime listed", weight=0.9)],
    )
    finding.recompute_confidence()
    return finding


def _engine(
    monkeypatch: pytest.MonkeyPatch,
    records: Callable[[], list[Finding]],
    *,
    emits: bool = True,
    builtin: bool = True,
    types: frozenset[str] = frozenset({REGISTRY}),
    observed: Callable[[], list[Finding]] = lambda: [_runtime(), _runtime(SHADOW_RUNTIME)],
    offline: Path | None = None,
    **options: Any,
) -> Engine:
    class Registry(BaseConnector):
        name: ClassVar[str] = "test.registry"
        surface: ClassVar[Surface] = Surface.CLOUD
        emits_registry_records: ClassVar[bool] = emits
        registry_record_types: ClassVar[frozenset[str]] = types

        def collect(self) -> Iterator[dict[str, Any]]:
            yield {}

        def analyze(self, items: Any) -> list[Finding]:
            list(items)
            return records()

    class Observed(BaseConnector):
        name: ClassVar[str] = "test.observed"
        surface: ClassVar[Surface] = Surface.CLOUD

        def collect(self) -> Iterator[dict[str, Any]]:
            yield {}

        def analyze(self, items: Any) -> list[Finding]:
            list(items)
            return observed()

    classes = {"test.registry": Registry, "test.observed": Observed}
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: classes[name])
    # The engine honours the registry-record hook only for built-in connectors.
    names = frozenset(classes) if builtin else frozenset()
    monkeypatch.setattr(engine_module, "builtin_connector_names", lambda: names)
    # With ``offline``, the registry connector replays an export (its records still come from
    # ``records``): the engine treats them as offline because the job has ``input``.
    registry = ConnectorSpec("test.registry", {"input": str(offline)} if offline else {})
    specs = [registry, ConnectorSpec("test.observed")]
    return Engine(ScanConfig(connectors=specs, **options), SignatureIndex([]))


def _export(tmp_path: Path) -> Path:
    path = tmp_path / "registry-export.jsonl"
    path.write_text('{"exported": true}\n', encoding="utf-8")
    return path


def _by_resource(result: ScanResult) -> dict[str, Finding]:
    return {finding.resource: finding for finding in result.findings}


def _stats(result: ScanResult, connector: str) -> ScanStats | None:
    return next((stats for stats in result.stats if stats.connector == connector), None)


# ------------------------------------------------------------------ engine


def test_an_approved_record_of_a_trusted_registry_sanctions_its_exact_binding(monkeypatch):
    result = _engine(monkeypatch, lambda: [_record_finding(_record())], trusted_registries=TRUSTED).run()
    assert result.complete and result.inventory_present and result.inventory_size == 1
    findings = _by_resource(result)
    runtime, shadow, record = (
        findings[RUNTIME],
        findings[SHADOW_RUNTIME],
        findings[f"{REGISTRY_ARN}/record/rec-1"],
    )
    assert (runtime.shadow, runtime.registry_match, runtime.owner) == (
        False,
        "aws-agent-registry:rec-1",
        "platform-team",
    )
    assert "registered" in {factor.id for factor in runtime.risk.factors}
    assert (record.shadow, record.registry_match) == (False, "aws-agent-registry:rec-1")
    assert shadow.shadow is True and shadow.registry_match is None
    assert "shadow" in {factor.id for factor in shadow.risk.factors}
    assert runtime.metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    assert shadow.metadata[RECONCILIATION_KEY]["status"] == "observed-not-registered"
    assert record.metadata[RECONCILIATION_KEY] == {
        "status": "registered-and-observed",
        "observed": [runtime.id],
    }
    assert _stats(result, "engine.inventory") is None and _stats(result, "engine.registries") is None


def test_without_trusted_registries_a_vendor_approval_sanctions_nothing(monkeypatch):
    result = _engine(monkeypatch, lambda: [_record_finding(_record())]).run()
    assert result.complete and not result.inventory_present and result.inventory_size == 0
    assert {finding.shadow for finding in result.findings} == {None}
    # Reconciliation is informational and runs without any inventory.
    assert _by_resource(result)[RUNTIME].metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"


# ``registered`` is covered with its own warning by test_registered_only_records_need_allow_registered_only.
@pytest.mark.parametrize("status", ["pending", "draft", "rejected", "deprecated", "blocked", "unknown"])
def test_records_that_are_not_approved_leave_trusted_findings_shadow(monkeypatch, status):
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record(status=status))], trusted_registries=TRUSTED
    ).run()
    assert result.complete and result.inventory_present and result.inventory_size == 0
    assert {finding.shadow for finding in result.findings} == {True}
    assert _stats(result, "engine.inventory") is None


def test_an_approval_from_another_registry_instance_sanctions_nothing(monkeypatch):
    other = f"arn:aws:agent-registry:{REGION}:{ACCOUNT}:registry/ffff0000ffff"
    result = _engine(
        monkeypatch,
        lambda: [_record_finding(_record(registry_id=other))],
        trusted_registries=TRUSTED,
    ).run()
    assert {finding.shadow for finding in result.findings} == {True}
    inventory = _stats(result, "engine.inventory")
    assert result.complete and inventory is not None and not inventory.incomplete
    assert inventory.warnings == [
        "trusted registry aws-agent-registry ...try/abcd1234abcd produced no records; "
        "its approvals were not applied"
    ]


def test_trusted_registry_notices_join_the_existing_inventory_entry(monkeypatch, tmp_path):
    cards = tmp_path / "agents.yaml"
    cards.write_text("agents:\n  - id: everything\n    resources: ['*']\n", encoding="utf-8")
    result = _engine(monkeypatch, list, trusted_registries=TRUSTED, inventory=[str(cards)]).run()
    inventory = _stats(result, "engine.inventory")
    assert result.complete and inventory is not None and len(inventory.warnings) == 2
    assert [stats.connector for stats in result.stats].count("engine.inventory") == 1


def test_a_card_and_a_trusted_record_approving_one_resource_are_ambiguous(monkeypatch, tmp_path):
    cards = tmp_path / "agents.yaml"
    cards.write_text(f"agents:\n  - id: card\n    resources: ['{RUNTIME}']\n", encoding="utf-8")
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record())], trusted_registries=TRUSTED, inventory=[str(cards)]
    ).run()
    runtime = _by_resource(result)[RUNTIME]
    assert (
        runtime.shadow is True and runtime.metadata["registry_match_reason"] == "ambiguous-resource-approval"
    )
    assert result.inventory_size == 2


@pytest.mark.parametrize(
    "binding",
    [
        {"resource": RUNTIME.replace("agent-a1", "agent-*"), "provider": "aws", "account": ACCOUNT},
        {"resource": RUNTIME, "provider": "aws", "account": "210987654321"},
        {"resource": RUNTIME, "region": "eu-west-1"},
        {"resource": RUNTIME.upper()},
        {"resource": f"{RUNTIME}{REDACTED}"},
    ],
)
def test_only_an_exact_binding_in_scope_sanctions_a_finding(monkeypatch, binding):
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record(bindings=[binding]))], trusted_registries=TRUSTED
    ).run()
    assert _by_resource(result)[RUNTIME].shadow is True


def test_a_record_binding_one_resource_twice_registers_it_once(monkeypatch):
    bindings = [
        {
            "resource": RUNTIME,
            "provider": "aws",
            "account": ACCOUNT,
            "region": REGION,
            "coverage": "in-scope",
        },
        {"resource": RUNTIME, "provider": "aws", "account": ACCOUNT, "coverage": "in-scope"},
    ]
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record(bindings=bindings))], trusted_registries=TRUSTED
    ).run()
    runtime = _by_resource(result)[RUNTIME]
    assert (runtime.shadow, runtime.registry_match) == (False, "aws-agent-registry:rec-1")
    assert "registry_match_reason" not in runtime.metadata
    assert result.inventory_size == 1


def test_a_revoked_approval_stops_applying_on_the_next_run(monkeypatch):
    state = {"status": "approved"}
    engine = _engine(
        monkeypatch, lambda: [_record_finding(_record(status=state["status"]))], trusted_registries=TRUSTED
    )
    assert _by_resource(engine.run())[RUNTIME].shadow is False
    state["status"] = "rejected"
    second = engine.run()
    assert _by_resource(second)[RUNTIME].shadow is True and second.inventory_size == 0


def test_removing_a_trusted_registry_between_runs_revokes_its_approvals(monkeypatch):
    engine = _engine(monkeypatch, lambda: [_record_finding(_record())], trusted_registries=TRUSTED)
    assert _by_resource(engine.run())[RUNTIME].shadow is False
    engine.config.trusted_registries = []
    second = engine.run()
    assert not second.inventory_present and _by_resource(second)[RUNTIME].shadow is None


def test_malformed_records_make_the_scan_incomplete(monkeypatch):
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record(status="live"))], trusted_registries=TRUSTED
    ).run()
    registries = _stats(result, "engine.registries")
    assert not result.complete and registries is not None and registries.incomplete
    assert registries.warnings == ["malformed registry record metadata on 1 finding(s)"]
    assert _by_resource(result)[RUNTIME].shadow is True


def test_records_from_a_connector_that_does_not_declare_them_are_ignored(monkeypatch):
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record())], emits=False, trusted_registries=TRUSTED
    ).run()
    registry = _stats(result, "test.registry")
    assert result.complete and registry is not None and not registry.incomplete
    assert registry.warnings == [
        "registry record metadata ignored on 1 finding(s): the connector does not declare registry records"
    ]
    assert all(RECORD_KEY not in finding.metadata for finding in result.findings)
    assert {finding.shadow for finding in result.findings} == {True}


@pytest.mark.parametrize("cached", [False, True])
def test_a_plugin_that_declares_registry_records_cannot_approve(monkeypatch, cached):
    # Regression: any class declaring the hook, a third-party plugin included, could emit an
    # approved record naming a trusted registry and approve other connectors' resources.
    if cached:

        def reuse(self, spec, resolved, ctx, started_at, fs):
            if spec.name == "test.registry":
                fs.extend([_record_finding(_record())])
            else:
                fs.extend([_runtime(), _runtime(SHADOW_RUNTIME)])
            return ScanStats(connector=spec.id, started_at=started_at, cached=True), True

        monkeypatch.setattr(engine_module._ConnectorRunner, "_collect", reuse)
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record())], builtin=False, trusted_registries=TRUSTED
    ).run()
    registry = _stats(result, "test.registry")
    assert result.complete and registry is not None and not registry.incomplete
    assert registry.warnings == [
        "registry record metadata ignored on 1 finding(s): only built-in connectors may emit registry records"
    ]
    assert all(RECORD_KEY not in finding.metadata for finding in result.findings)
    assert {finding.shadow for finding in result.findings} == {True}
    assert result.inventory_size == 0


def test_cached_results_are_also_held_to_the_declaration(monkeypatch):
    def reuse(self, spec, resolved, ctx, started_at, fs):
        fs.extend([_record_finding(_record())])
        return ScanStats(connector=spec.id, started_at=started_at, cached=True), True

    monkeypatch.setattr(engine_module._ConnectorRunner, "_collect", reuse)
    result = _engine(monkeypatch, list, emits=False, trusted_registries=TRUSTED).run()
    assert all(RECORD_KEY not in finding.metadata for finding in result.findings)
    assert all(finding.shadow is True for finding in result.findings)


def test_plugin_supplied_reconciliation_and_approval_state_is_recomputed(monkeypatch):
    def forged() -> list[Finding]:
        finding = _runtime(SHADOW_RUNTIME)
        finding.metadata[RECONCILIATION_KEY] = {"status": "registered-and-observed"}
        finding.metadata["registry_match_reason"] = "forged"
        finding.registry_match, finding.shadow = "forged", False
        return [finding]

    result = _engine(monkeypatch, list, observed=forged, trusted_registries=TRUSTED).run()
    finding = _by_resource(result)[SHADOW_RUNTIME]
    assert finding.shadow is True and finding.registry_match is None
    assert RECONCILIATION_KEY not in finding.metadata and "registry_match_reason" not in finding.metadata


def test_confidence_filtering_prunes_links_but_keeps_statuses(monkeypatch):
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record())], trusted_registries=TRUSTED, min_confidence=0.6
    ).run()
    runtime = _by_resource(result)[RUNTIME]
    # The record (confidence 0.5) is below the threshold; the approval it conferred stands.
    assert f"{REGISTRY_ARN}/record/rec-1" not in _by_resource(result)
    assert runtime.shadow is False
    assert runtime.metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    assert runtime.metadata[RECONCILIATION_KEY]["records"] == []


def test_postprocess_keeps_its_signature_and_reports_registry_problems_through_the_outcome(monkeypatch):
    engine = _engine(monkeypatch, list, trusted_registries=TRUSTED)
    findings, errors = engine._postprocess([_record_finding(_record(status="live")), _runtime()])
    assert errors == [] and {finding.shadow for finding in findings} == {True}
    outcome = engine_module._RegistryOutcome()
    engine._postprocess([_record_finding(_record()), _runtime()], registries=outcome)
    assert outcome.approval_entries == 1 and outcome.warnings == [] and outcome.inventory_warnings == []


# ------------------------------------------------------------------ offline replays

OFFLINE_WARNING = (
    "trusted registry aws-agent-registry ...try/abcd1234abcd: {count} offline-replayed "
    "(set allow_offline_records to accept them) record(s) were not treated as sanctioned"
)


def test_records_replayed_from_an_offline_export_do_not_approve_by_default(monkeypatch, tmp_path):
    # Regression: a line in an export (untrusted input) naming a trusted registry sanctioned the
    # resources it binds exactly as a live record of that registry would.
    result = _engine(
        monkeypatch,
        lambda: [_record_finding(_record())],
        offline=_export(tmp_path),
        trusted_registries=TRUSTED,
    ).run()
    assert result.complete and result.inventory_present and result.inventory_size == 0
    assert {finding.shadow for finding in result.findings} == {True}
    runtime = _by_resource(result)[RUNTIME]
    assert runtime.registry_match is None
    # The record still reconciles; only its approval is withheld, and never silently.
    assert runtime.metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    inventory = _stats(result, "engine.inventory")
    assert inventory is not None and not inventory.incomplete
    assert inventory.warnings == [OFFLINE_WARNING.format(count=1)]


def test_allow_offline_records_accepts_replayed_records(monkeypatch, tmp_path):
    allowed = [{**TRUSTED[0], "allow_offline_records": True}]
    result = _engine(
        monkeypatch,
        lambda: [_record_finding(_record())],
        offline=_export(tmp_path),
        trusted_registries=allowed,
    ).run()
    runtime = _by_resource(result)[RUNTIME]
    assert (runtime.shadow, runtime.registry_match) == (False, "aws-agent-registry:rec-1")
    assert result.inventory_size == 1 and _stats(result, "engine.inventory") is None


def test_only_a_replayed_record_that_would_approve_is_reported_as_offline(monkeypatch, tmp_path):
    export = _export(tmp_path)
    pending = _engine(
        monkeypatch,
        lambda: [_record_finding(_record(status="pending"))],
        offline=export,
        trusted_registries=TRUSTED,
    ).run()
    assert _stats(pending, "engine.inventory") is None
    auto = _engine(
        monkeypatch,
        lambda: [_record_finding(_record(approval_mode="auto"))],
        offline=export,
        trusted_registries=TRUSTED,
    ).run()
    inventory = _stats(auto, "engine.inventory")
    assert inventory is not None and len(inventory.warnings) == 1
    assert "1 auto-approved" in inventory.warnings[0]


def test_a_cached_replay_is_still_offline(monkeypatch, tmp_path):
    def reuse(self, spec, resolved, ctx, started_at, fs):
        if spec.name == "test.registry":
            fs.extend([_record_finding(_record())])
        else:
            fs.extend([_runtime(), _runtime(SHADOW_RUNTIME)])
        return ScanStats(connector=spec.id, started_at=started_at, cached=True), True

    monkeypatch.setattr(engine_module._ConnectorRunner, "_collect", reuse)
    result = _engine(monkeypatch, list, offline=_export(tmp_path), trusted_registries=TRUSTED).run()
    assert {finding.shadow for finding in result.findings} == {True}
    inventory = _stats(result, "engine.inventory")
    assert inventory is not None and inventory.warnings == [OFFLINE_WARNING.format(count=1)]


def test_a_record_seen_live_and_replayed_offline_counts_as_offline(monkeypatch, tmp_path):
    engine = _engine(monkeypatch, lambda: [_record_finding(_record())], trusted_registries=TRUSTED)
    live, observed = engine.config.connectors
    replay = ConnectorSpec("test.registry", {"input": str(_export(tmp_path))}, label="replay")
    for connectors in ([live, replay, observed], [replay, live, observed]):
        engine.config.connectors = connectors
        result = engine.run()
        assert result.complete and _by_resource(result)[RUNTIME].shadow is True


def test_a_forged_line_in_an_aws_registry_export_cannot_sanction_a_runtime(index, tmp_path):
    # Regression (review repro): an APPROVED, auto-detected record added to an export of a
    # trusted AWS Agent Registry, with DETECTED_FROM provenance naming an arbitrary runtime,
    # sanctioned that runtime.
    fixture = Path(__file__).parents[1] / "fixtures" / "cloud" / "aws_registry_records.jsonl"
    lines = fixture.read_text(encoding="utf-8").splitlines()
    [genuine] = [json.loads(line) for line in lines if json.loads(line).get("recordId") == "rec000000001"]
    target = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/shadow_agent-KlMnO13579"
    forged = {
        **genuine,
        "recordId": "frg000000001",
        "recordArn": f"{REGISTRY_ARN}/record/frg000000001",
        "name": "forged",
        "provenance": [{**genuine["provenance"][0], "sourceId": target}],
    }
    export = tmp_path / "export.jsonl"
    export.write_text("\n".join([*lines, json.dumps(forged)]) + "\n", encoding="utf-8")

    def scan(**flags: bool) -> ScanResult:
        spec = ConnectorSpec("cloud.aws", {"input": str(export)})
        trusted = [{**TRUSTED[0], **flags}]
        return Engine(ScanConfig(connectors=[spec], trusted_registries=trusted), index).run()

    result = scan()
    assert result.complete and result.inventory_size == 0
    findings = _by_resource(result)
    assert (findings[target].shadow, findings[target].registry_match) == (True, None)
    assert findings[f"{REGISTRY_ARN}/record/frg000000001"].shadow is True
    inventory = _stats(result, "engine.inventory")
    assert inventory is not None and OFFLINE_WARNING.format(count=2) in inventory.warnings
    # An operator who keeps exports where only operators can write them may opt in.
    accepted = _by_resource(scan(allow_offline_records=True))
    assert accepted[target].registry_match == "aws-agent-registry:frg000000001"


# ------------------------------------------------------------------- config


def test_trusted_registries_parse_from_options():
    config = ScanConfig.from_dict({"options": {"trusted_registries": TRUSTED}})
    assert config.trusted_registries == [TrustedRegistry(REGISTRY, REGISTRY_ARN)]
    assert ScanConfig.from_dict({}).trusted_registries == []


def test_trusted_registries_load_from_yaml_with_environment_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_REGISTRY_ARN", REGISTRY_ARN)
    path = tmp_path / "shadowscan.yaml"
    path.write_text(
        "options:\n  trusted_registries:\n    - registry: aws-agent-registry\n      id: ${AGENT_REGISTRY_ARN}\n",
        encoding="utf-8",
    )
    assert ScanConfig.from_yaml(path).trusted_registries == [TrustedRegistry(REGISTRY, REGISTRY_ARN)]


def test_library_callers_may_pass_mappings_or_trusted_registry_objects():
    config = ScanConfig(
        trusted_registries=[dict(TRUSTED[0]), TrustedRegistry("microsoft-agent-365", "tenant")]
    )
    assert config.trusted_registries == [
        TrustedRegistry(REGISTRY, REGISTRY_ARN),
        TrustedRegistry("microsoft-agent-365", "tenant"),
    ]


SECRET = "sk-proj-" + "q" * 40


@pytest.mark.parametrize(
    "value,message",
    [
        (None, "must be a list"),
        ("aws-agent-registry", "must be a list"),
        ({"registry": REGISTRY, "id": REGISTRY_ARN}, "must be a list"),
        (["aws-agent-registry"], "entry 1 must be a mapping"),
        ([{"registry": REGISTRY}], "entry 1 requires both registry and id"),
        (
            [{"registry": REGISTRY, "id": REGISTRY_ARN, "provider": "aws"}],
            "entry 1 contains an unsupported field",
        ),
        ([{"registry": REGISTRY, "id": REGISTRY_ARN, SECRET: 1}], "entry 1 contains an unsupported field"),
        ([{"registry": "aws", "id": REGISTRY_ARN}], "entry 1.registry must be one of"),
        (
            [{"registry": "entra-agent-registry", "id": "tenant"}],
            "entry 1.registry entra-agent-registry is a deprecated source",
        ),
        (
            [{"registry": REGISTRY, "id": REGISTRY_ARN, "allow_auto_approved": "true"}],
            "must be a YAML boolean",
        ),
        ([{"registry": REGISTRY, "id": REGISTRY_ARN, "allow_registered_only": 1}], "must be a YAML boolean"),
        (
            [{"registry": REGISTRY, "id": REGISTRY_ARN, "allow_offline_records": "yes"}],
            "allow_offline_records must be a YAML boolean",
        ),
        (
            [TRUSTED[0], {"registry": REGISTRY, "id": REGISTRY_ARN, "allow_auto_approved": True}],
            "entry 2 duplicates",
        ),
        ([{"registry": None, "id": REGISTRY_ARN}], "entry 1.registry must be one of"),
        ([{"registry": REGISTRY, "id": ""}], "entry 1.id must be a nonempty single-line string"),
        ([{"registry": REGISTRY, "id": 123456789012}], "entry 1.id must be a nonempty single-line string"),
        (
            [{"registry": REGISTRY, "id": f" {REGISTRY_ARN}"}],
            "entry 1.id must be a nonempty single-line string",
        ),
        (
            [{"registry": REGISTRY, "id": f"{REGISTRY_ARN}\nx"}],
            "entry 1.id must be a nonempty single-line string",
        ),
        ([{"registry": REGISTRY, "id": "x" * 2049}], "entry 1.id must be a nonempty single-line string"),
        ([{"registry": REGISTRY, "id": REGISTRY_ARN.replace("abcd1234abcd", "*")}], "wildcard characters"),
        ([{"registry": REGISTRY, "id": REGISTRY_ARN + "?"}], "wildcard characters"),
        ([{"registry": REGISTRY, "id": REGISTRY_ARN + "[0-9]"}], "wildcard characters"),
        ([{"registry": REGISTRY, "id": REDACTED}], "wildcard characters"),
        ([{"registry": REGISTRY, "id": SECRET}], "would be redacted"),
        ([TRUSTED[0], {"registry": "aws-agentcore-registry", "id": "x"}, TRUSTED[0]], "entry 3 duplicates"),
        ([{"registry": REGISTRY, "id": f"r{n}"} for n in range(MAX_TRUSTED_REGISTRIES + 1)], "at most 64"),
    ],
)
def test_invalid_trusted_registries_are_rejected_without_echoing_values(value, message):
    with pytest.raises(ConfigValidationError, match="options.trusted_registries") as raised:
        ScanConfig.from_dict({"options": {"trusted_registries": value}})
    assert message in str(raised.value)
    assert SECRET not in str(raised.value) and "abcd1234abcd" not in str(raised.value)
    with pytest.raises(ConfigValidationError):
        validate_trusted_registries(value)


def test_the_entry_cap_is_inclusive():
    trusted = [{"registry": REGISTRY, "id": f"r{n}"} for n in range(MAX_TRUSTED_REGISTRIES)]
    assert len(validate_trusted_registries(trusted)) == MAX_TRUSTED_REGISTRIES


def test_a_mutated_trusted_registry_list_fails_before_any_connector_runs(monkeypatch):
    constructed: list[str] = []

    class Probe(BaseConnector):
        name: ClassVar[str] = "test.probe"

        def __init__(self, ctx: Any) -> None:
            constructed.append("probe")
            super().__init__(ctx)

        def collect(self) -> Iterator[dict[str, Any]]:
            yield from ()

        def analyze(self, items: Any) -> list[Finding]:
            return []

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: Probe)
    engine = Engine(ScanConfig(connectors=[ConnectorSpec("test.probe")]), SignatureIndex([]))
    engine.config.trusted_registries = [{"registry": REGISTRY, "id": "registry/*"}]  # type: ignore[list-item]
    with pytest.raises(ConfigValidationError, match="wildcard"):
        engine.run()
    assert constructed == []


def test_the_documented_configuration_example_is_valid():
    text = (
        Path(__file__)
        .parents[2]
        .joinpath("docs/getting-started/configuration.md")
        .read_text(encoding="utf-8")
    )
    section = text.split("## Trusted vendor registries", 1)[1]
    example = section.split("```yaml\n", 1)[1].split("```", 1)[0]
    config = ScanConfig.from_dict(yaml.safe_load(example))
    assert config.trusted_registries == [TrustedRegistry(REGISTRY, REGISTRY_ARN)]


# ------------------------------------------------------------------ contract extension


def test_an_auto_approved_record_needs_allow_auto_approved(monkeypatch):
    records = lambda: [_record_finding(_record(approval_mode="auto"))]  # noqa: E731
    result = _engine(monkeypatch, records, trusted_registries=TRUSTED).run()
    assert result.complete and result.inventory_size == 0
    assert {finding.shadow for finding in result.findings} == {True}
    inventory = _stats(result, "engine.inventory")
    assert inventory is not None and not inventory.incomplete
    assert any(
        "1 auto-approved" in warning and "allow_auto_approved" in warning for warning in inventory.warnings
    )
    allowed = [{**TRUSTED[0], "allow_auto_approved": True}]
    result = _engine(monkeypatch, records, trusted_registries=allowed).run()
    assert _by_resource(result)[RUNTIME].registry_match == "aws-agent-registry:rec-1"


def test_only_a_manual_approval_sanctions_without_allow_auto_approved(monkeypatch):
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record(approval_mode="manual"))], trusted_registries=TRUSTED
    ).run()
    assert _by_resource(result)[RUNTIME].shadow is False


@pytest.mark.parametrize("mode", ["unknown", "none"])
def test_an_approval_without_a_known_reviewer_needs_allow_auto_approved(monkeypatch, mode):
    records = lambda: [_record_finding(_record(approval_mode=mode))]  # noqa: E731
    result = _engine(monkeypatch, records, trusted_registries=TRUSTED).run()
    assert {finding.shadow for finding in result.findings} == {True}
    inventory = _stats(result, "engine.inventory")
    assert inventory is not None and not inventory.incomplete
    assert any("approved without a known reviewer" in warning for warning in inventory.warnings)
    allowed = [{**TRUSTED[0], "allow_auto_approved": True}]
    result = _engine(monkeypatch, records, trusted_registries=allowed).run()
    assert _by_resource(result)[RUNTIME].registry_match == "aws-agent-registry:rec-1"


def test_registered_only_records_need_allow_registered_only(monkeypatch):
    records = lambda: [_record_finding(_record(status="registered", approval_mode="none"))]  # noqa: E731
    result = _engine(monkeypatch, records, trusted_registries=TRUSTED).run()
    assert _by_resource(result)[RUNTIME].shadow is True
    inventory = _stats(result, "engine.inventory")
    assert inventory is not None and any("registered-only" in warning for warning in inventory.warnings)
    allowed = [{**TRUSTED[0], "allow_registered_only": True}]
    result = _engine(monkeypatch, records, trusted_registries=allowed).run()
    assert _by_resource(result)[RUNTIME].registry_match == "aws-agent-registry:rec-1"


def test_allow_registered_only_never_accepts_other_statuses(monkeypatch):
    allowed = [{**TRUSTED[0], "allow_registered_only": True, "allow_auto_approved": True}]
    result = _engine(
        monkeypatch, lambda: [_record_finding(_record(status="pending"))], trusted_registries=allowed
    ).run()
    assert {finding.shadow for finding in result.findings} == {True}


def test_a_caller_scoped_listing_is_never_complete(monkeypatch):
    records = lambda: [_record_finding(_record(listing_scope="caller"))]  # noqa: E731
    result = _engine(monkeypatch, records).run()
    # The matched runtime is still reconciled; the unmatched one is not called unregistered.
    assert _by_resource(result)[RUNTIME].metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    assert RECONCILIATION_KEY not in _by_resource(result)[SHADOW_RUNTIME].metadata


@pytest.mark.parametrize(
    "field,value", [("approval_mode", "maybe"), ("listing_scope", "tenant"), ("approval_mode", 1)]
)
def test_unknown_approval_modes_and_listing_scopes_are_malformed(monkeypatch, field, value):
    result = _engine(monkeypatch, lambda: [_record_finding(_record(**{field: value}))]).run()
    assert not result.complete
    assert _stats(result, "engine.registries") is not None


def test_a_connector_keeps_only_records_of_the_registry_types_it_declares(monkeypatch):
    result = _engine(
        monkeypatch,
        lambda: [_record_finding(_record())],
        types=frozenset({"aws-agentcore-registry"}),
        trusted_registries=TRUSTED,
    ).run()
    assert {finding.shadow for finding in result.findings} == {True}
    registry_stats = _stats(result, "test.registry")
    assert registry_stats is not None
    assert any("does not declare that registry type" in warning for warning in registry_stats.warnings)
    assert all(RECORD_KEY not in finding.metadata for finding in result.findings)


def test_a_malformed_record_type_from_a_declaring_connector_is_reported_as_malformed(monkeypatch):
    result = _engine(monkeypatch, lambda: [_record_finding(_record(registry="aws-registry"))]).run()
    assert not result.complete and _stats(result, "engine.registries") is not None


def test_trusted_registry_objects_carry_their_flags():
    config = ScanConfig(
        trusted_registries=[TrustedRegistry(REGISTRY, REGISTRY_ARN, allow_auto_approved=True)]
    )
    assert config.trusted_registries == [TrustedRegistry(REGISTRY, REGISTRY_ARN, True, False)]
    offline = TrustedRegistry(REGISTRY, REGISTRY_ARN, allow_offline_records=True)
    assert ScanConfig(trusted_registries=[offline]).trusted_registries == [offline]
    parsed = ScanConfig.from_dict(
        {"options": {"trusted_registries": [{**TRUSTED[0], "allow_offline_records": True}]}}
    )
    assert parsed.trusted_registries == [offline]
    assert TrustedRegistry(REGISTRY, REGISTRY_ARN).allow_offline_records is False
