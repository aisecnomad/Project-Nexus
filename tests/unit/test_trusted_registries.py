"""options.trusted_registries and the engine's registry pass, end to end through fake connectors."""

from __future__ import annotations

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
    observed: Callable[[], list[Finding]] = lambda: [_runtime(), _runtime(SHADOW_RUNTIME)],
    **options: Any,
) -> Engine:
    class Registry(BaseConnector):
        name: ClassVar[str] = "test.registry"
        surface: ClassVar[Surface] = Surface.CLOUD
        emits_registry_records: ClassVar[bool] = emits

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
    specs = [ConnectorSpec("test.registry"), ConnectorSpec("test.observed")]
    return Engine(ScanConfig(connectors=specs, **options), SignatureIndex([]))


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
