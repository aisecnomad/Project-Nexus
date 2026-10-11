"""Autonomy tiers: the observed L0-L5 interval and its comparison with a declared level."""

from __future__ import annotations

import copy
import itertools
from typing import Any

import pytest

from shadowscan.autonomy import (
    APPLICABLE_KINDS,
    LEVELS,
    MAX_BASIS,
    RULES,
    SCHEMA,
    UNDERSTATED_TAG,
    apply_autonomy,
    classify,
    level_title,
    observed_floor,
    valid_autonomy,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.registry import InventoryEntry

NOT_APPLICABLE = sorted(set(Kind) - APPLICABLE_KINDS, key=lambda kind: kind.value)


def finding(
    kind: Kind = Kind.CLOUD_RESOURCE,
    caps: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
    metadata: dict[str, Any] | None = None,
    surface: Surface = Surface.CLOUD,
    resource_type: str = "thing",
    signatures: tuple[str, ...] = (),
) -> Finding:
    f = Finding(
        surface=surface,
        connector="test.connector",
        kind=kind,
        title="AI thing",
        resource="res-1",
        resource_type=resource_type,
        capabilities=list(caps),
        tags=list(tags),
        metadata=dict(metadata or {}),
    )
    for signature in signatures:
        f.add_evidence(Evidence(signal=f"code:{signature}", description="matched", signature=signature))
    return f


def rules(autonomy: dict[str, Any], bound: str) -> dict[str, Any]:
    return {item["rule"]: item["value"] for item in autonomy["basis"] if item["bound"] == bound}


def interval(f: Finding) -> tuple[int, int, str, str]:
    autonomy = classify(f)
    assert autonomy is not None
    return autonomy["floor"], autonomy["ceiling"], autonomy["oversight"], autonomy["initiation"]


# ------------------------------------------------------------------ taxonomy


def test_levels_use_the_maintainer_scale_and_stable_names():
    assert [(level.number, level.name, level.title) for level in LEVELS] == [
        (0, "chatbot", "L0 Chatbot"),
        (1, "copilot", "L1 Copilot"),
        (2, "supervised", "L2 Supervised"),
        (3, "semi-autonomous", "L3 Semi-Autonomous / Agentic Workflow"),
        (4, "high-autonomy", "L4 High Autonomy"),
        (5, "fully-autonomous", "L5 Fully Autonomous"),
    ]
    assert level_title(3) == "L3 Semi-Autonomous / Agentic Workflow"


def test_applicable_kinds_are_the_documented_set():
    assert {kind.value for kind in APPLICABLE_KINDS} == {
        "agent",
        "framework-usage",
        "agent-config",
        "mcp-server",
        "workflow",
        "bot-app",
        "gateway-caller",
        "ai-app",
        "runtime-process",
        "cloud-resource",
    }
    assert {kind.value for kind in NOT_APPLICABLE} == {
        "secret",
        "token",
        "oauth-grant",
        "service-identity",
        "iam-grant",
        "infra",
        "local-model",
        "network-contact",
    }


@pytest.mark.parametrize("kind", NOT_APPLICABLE)
def test_autonomy_is_absent_for_kinds_it_does_not_describe(kind):
    f = finding(kind, caps=("code-exec", "autonomous"), tags=("scheduled", UNDERSTATED_TAG))
    f.metadata["autonomy"] = {"schema": SCHEMA, "floor": 5}
    assert classify(f) is None and observed_floor(f) is None
    apply_autonomy(f, InventoryEntry(agent_id="declared", autonomy_level=0))
    assert "autonomy" not in f.metadata and UNDERSTATED_TAG not in f.tags


# --------------------------------------------------------------- floor rules


@pytest.mark.parametrize(
    "kind", [Kind.FRAMEWORK_USAGE, Kind.CLOUD_RESOURCE, Kind.AI_APP, Kind.GATEWAY_CALLER]
)
def test_absence_of_capabilities_is_not_evidence_of_low_autonomy(kind):
    autonomy = classify(finding(kind))
    assert autonomy is not None
    assert (autonomy["floor"], autonomy["ceiling"]) == (0, 5)
    assert autonomy["floor_label"] == "L0 Chatbot" and autonomy["ceiling_label"] == "L5 Fully Autonomous"
    assert rules(autonomy, "floor") == {"ai-system": 0}
    assert rules(autonomy, "ceiling") == {"no-restriction-evidence": 5}
    assert (autonomy["oversight"], autonomy["initiation"]) == ("unknown", "unknown")


@pytest.mark.parametrize("capability", ["tool-use", "rag", "browsing", "data-access", "memory"])
def test_read_type_tools_set_the_copilot_floor(capability):
    autonomy = classify(finding(caps=(capability,)))
    assert autonomy is not None and autonomy["floor"] == 1
    assert rules(autonomy, "floor") == {"ai-system": 0, "tool-access": 1}


@pytest.mark.parametrize(
    ("caps", "tags"),
    [(("saas-actions",), ()), (("code-exec",), ()), (("delegated-identity",), ()), ((), ("write-access",))],
)
def test_side_effecting_tools_set_the_supervised_floor(caps, tags):
    autonomy = classify(finding(caps=caps, tags=tags))
    assert autonomy is not None and autonomy["floor"] == 2
    assert rules(autonomy, "floor")["side-effect-tools"] == 2


@pytest.mark.parametrize(
    ("kind", "caps", "floor"),
    [
        (Kind.WORKFLOW, (), 3),
        (Kind.CLOUD_RESOURCE, ("multi-agent",), 3),
        (Kind.AGENT, ("tool-use",), 3),
        # A configuration that lists tools is not proof that a model chooses them in a loop.
        (Kind.AGENT_CONFIG, ("tool-use",), 1),
        (Kind.AGENT, (), 0),
    ],
)
def test_agentic_execution_floor(kind, caps, floor):
    autonomy = classify(finding(kind, caps=caps))
    assert autonomy is not None and autonomy["floor"] == floor
    assert ("agentic-execution" in rules(autonomy, "floor")) is (floor == 3)


@pytest.mark.parametrize(
    ("kind", "caps", "tags", "metadata", "signatures"),
    [
        (Kind.AGENT_CONFIG, ("code-exec",), ("posture-permissions-bypassed",), {}, ()),
        (Kind.MCP_SERVER, ("data-access",), ("mcp-auto-approve",), {}, ()),
        (Kind.MCP_SERVER, ("data-access",), (), {"servers": [{"name": "fs", "auto_approve": True}]}, ()),
        (Kind.MCP_SERVER, ("code-exec",), (), {"servers": [{"name": "sh", "auto_approve": ["run"]}]}, ()),
        (Kind.AGENT, ("autonomous", "saas-actions"), (), {}, ()),
        (Kind.FRAMEWORK_USAGE, ("autonomous", "delegated-identity"), (), {}, ()),
        (
            Kind.AGENT_CONFIG,
            ("code-exec",),
            ("posture-unrestricted-shell",),
            {"posture": [{"id": "posture-unrestricted-shell", "setting": "permissions.allow"}]},
            (),
        ),
        # A disabling pattern in code explains the capability even next to a trigger.
        (Kind.WORKFLOW, ("autonomous", "code-exec"), (), {}, ("heuristic.autonomy",)),
    ],
)
def test_bypassed_approval_with_side_effects_sets_the_high_autonomy_floor(
    kind, caps, tags, metadata, signatures
):
    autonomy = classify(finding(kind, caps=caps, tags=tags, metadata=metadata, signatures=signatures))
    assert autonomy is not None
    assert autonomy["floor"] == 4 and autonomy["oversight"] == "bypassed"
    assert rules(autonomy, "floor")["unapproved-side-effects"] == 4
    assert rules(autonomy, "oversight") == {"approval-bypassed": "bypassed"}


@pytest.mark.parametrize(
    ("kind", "caps", "tags", "metadata", "signatures"),
    [
        # Bypass without a side-effecting capability proves no more than the tools do.
        (Kind.AGENT_CONFIG, ("tool-use",), ("posture-permissions-bypassed",), {}, ()),
        # A disabled server's auto-approval runs nothing.
        (
            Kind.MCP_SERVER,
            ("data-access",),
            (),
            {"servers": [{"name": "fs", "auto_approve": True, "disabled": True}]},
            (),
        ),
        (Kind.MCP_SERVER, ("data-access",), (), {"servers": [{"name": "fs", "auto_approve": []}]}, ()),
        # OpenClaw shell access grants a capability; it says nothing about approval.
        (
            Kind.AGENT_CONFIG,
            ("code-exec",),
            ("posture-unrestricted-shell",),
            {"posture": [{"id": "posture-unrestricted-shell", "setting": "capabilities.shell_access"}]},
            (),
        ),
        # Triggers, schedules and an unattended workflow definition explain the capability.
        (Kind.WORKFLOW, ("autonomous", "saas-actions"), (), {}, ()),
        (Kind.AGENT, ("autonomous", "code-exec"), ("scheduled",), {}, ()),
        (Kind.AGENT, ("autonomous", "code-exec"), ("event-triggered",), {}, ()),
        (
            Kind.GATEWAY_CALLER,
            ("autonomous", "code-exec"),
            ("always-on",),
            {"activity": {"always_on_corroborated": True}},
            (),
        ),
        (Kind.CLOUD_RESOURCE, ("autonomous", "code-exec"), (), {"trigger": "google.cloud.pubsub.v1"}, ()),
        (Kind.AGENT, ("autonomous", "code-exec"), (), {}, ("heuristic.scheduled-agent",)),
    ],
)
def test_evidence_that_does_not_prove_unapproved_side_effects(kind, caps, tags, metadata, signatures):
    autonomy = classify(finding(kind, caps=caps, tags=tags, metadata=metadata, signatures=signatures))
    assert autonomy is not None and autonomy["floor"] < 4
    assert "unapproved-side-effects" not in rules(autonomy, "floor")
    assert autonomy["ceiling"] == 5


@pytest.mark.parametrize(
    ("tags", "metadata", "initiation"),
    [
        (("scheduled",), {}, "schedule"),
        (("always-on",), {"activity": {"always_on_corroborated": True}}, "schedule"),
        (("event-triggered",), {}, "event"),
        ((), {"trigger_type": "Scheduled"}, "schedule"),
        ((), {"trigger_type": "RecordAfterSave"}, "event"),
        ((), {"trigger_types": ["Recurrence"]}, "schedule"),
        ((), {"trigger_types": ["OpenApiConnectionWebhook"]}, "event"),
        ((), {"trigger": "google.cloud.storage.object.v1.finalized"}, "event"),
    ],
)
def test_self_initiated_unapproved_side_effects_are_fully_autonomous(tags, metadata, initiation):
    f = finding(
        Kind.AGENT_CONFIG,
        caps=("code-exec",),
        tags=("posture-permissions-bypassed", *tags),
        metadata=metadata,
    )
    autonomy = classify(f)
    assert autonomy is not None
    assert (autonomy["floor"], autonomy["ceiling"], autonomy["initiation"]) == (5, 5, initiation)
    assert rules(autonomy, "floor")["self-initiated"] == 5
    assert autonomy["floor_label"] == "L5 Fully Autonomous"


def test_person_started_high_autonomy_stays_below_fully_autonomous():
    f = finding(
        Kind.AGENT_CONFIG,
        caps=("code-exec",),
        tags=("posture-permissions-bypassed",),
        surface=Surface.ENDPOINT,
        resource_type="ide-extension",
    )
    assert interval(f) == (4, 5, "bypassed", "human")


# -------------------------------------------------------------- ceiling rules


def test_every_side_effecting_action_approved_caps_the_interval_at_supervised():
    gate = {"approval_gate": {"scope": "every-action", "settings": []}}
    autonomy = classify(finding(Kind.AGENT_CONFIG, caps=("code-exec", "tool-use"), metadata=gate))
    assert autonomy is not None
    assert (autonomy["floor"], autonomy["ceiling"], autonomy["oversight"]) == (2, 2, "gated")
    assert rules(autonomy, "ceiling") == {"per-action-approval": 2}
    assert autonomy["ceiling_label"] == "L2 Supervised"


def test_a_model_loop_that_asks_before_every_action_is_supervised():
    gate = {"approval_gate": {"scope": "every-action"}}
    assert interval(finding(Kind.AGENT, caps=("tool-use", "code-exec"), metadata=gate)) == (
        2,
        2,
        "gated",
        "unknown",
    )


def test_conflicting_evidence_restores_the_ceiling_to_the_floor():
    gate = {"approval_gate": {"scope": "every-action"}}
    autonomy = classify(finding(Kind.WORKFLOW, caps=("saas-actions",), metadata=gate))
    assert autonomy is not None and (autonomy["floor"], autonomy["ceiling"]) == (3, 3)
    assert rules(autonomy, "ceiling") == {"per-action-approval": 2, "conflicting-evidence": 3}


def test_approval_gating_next_to_bypass_evidence_rules_nothing_out():
    gate = {"approval_gate": {"scope": "every-action"}}
    f = finding(Kind.AGENT_CONFIG, caps=("code-exec",), tags=("posture-permissions-bypassed",), metadata=gate)
    autonomy = classify(f)
    assert autonomy is not None
    assert (autonomy["floor"], autonomy["ceiling"], autonomy["oversight"]) == (4, 5, "bypassed")
    assert rules(autonomy, "ceiling") == {"conflicting-evidence": 5}


@pytest.mark.parametrize(
    ("tags", "metadata"),
    [
        ((), {"approval_gate": {"scope": "some-actions"}}),
        (("asks-user",), {}),
    ],
)
def test_partial_gating_marks_oversight_without_lowering_the_ceiling(tags, metadata):
    autonomy = classify(finding(Kind.AGENT, caps=("tool-use", "code-exec"), tags=tags, metadata=metadata))
    assert autonomy is not None
    assert (autonomy["floor"], autonomy["ceiling"], autonomy["oversight"]) == (3, 5, "gated")
    assert rules(autonomy, "oversight") == {"approval-gated": "gated"}


@pytest.mark.parametrize("gate", ["every-action", {"scope": "everything"}, {"scope": None}, ["every-action"]])
def test_malformed_approval_gates_are_not_evidence(gate):
    assert interval(finding(Kind.AGENT_CONFIG, caps=("code-exec",), metadata={"approval_gate": gate})) == (
        2,
        5,
        "unknown",
        "unknown",
    )


@pytest.mark.parametrize("status", ["disabled", "inactive", "suspended"])
def test_lifecycle_tags_do_not_change_the_bounds(status):
    base = finding(Kind.WORKFLOW, caps=("saas-actions", "autonomous"), tags=("scheduled",))
    stopped = finding(Kind.WORKFLOW, caps=("saas-actions", "autonomous"), tags=("scheduled", status))
    assert classify(base) == classify(stopped)


# ---------------------------------------------------------------- initiation


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"activity": {"always_on": True, "always_on_corroborated": False}},
        {"activity": {"always_on_corroborated": "true"}},
        {"activity": "corroborated"},
    ],
)
def test_uncorroborated_always_on_tag_is_not_initiation_evidence(metadata):
    # Regression: the gateway tags every round-the-clock caller always-on, corroborated or not, and
    # the tag alone was read as a schedule. A team sharing one key across time zones is also active
    # around the clock, so only the connector's corroboration makes the cadence initiation evidence.
    f = finding(Kind.GATEWAY_CALLER, caps=("tool-use",), tags=("always-on",), metadata=metadata)
    autonomy = classify(f)
    assert autonomy is not None and autonomy["initiation"] == "unknown"
    assert rules(autonomy, "initiation") == {"no-initiation-evidence": "unknown"}
    corroborated = finding(
        Kind.GATEWAY_CALLER,
        caps=("tool-use", "autonomous"),
        tags=("always-on",),
        metadata={"activity": {"always_on": True, "always_on_corroborated": True}},
    )
    assert interval(corroborated) == (1, 5, "unknown", "schedule")


@pytest.mark.parametrize(
    ("surface", "resource_type", "tags", "metadata", "initiation", "rule"),
    [
        (Surface.ENDPOINT, "ide-extension", (), {}, "human", "interactive-client"),
        (Surface.ENDPOINT, "browser-extension", (), {}, "human", "interactive-client"),
        (Surface.ENDPOINT, "cli-usage", (), {}, "human", "interactive-client"),
        # A configured client can also run unattended (a personal agent gateway, a CI job).
        (Surface.ENDPOINT, "agent-config", (), {}, "unknown", "no-initiation-evidence"),
        (Surface.CODE, "ide-extension", (), {}, "unknown", "no-initiation-evidence"),
        # A trigger outweighs interactive use.
        (Surface.ENDPOINT, "ide-extension", ("scheduled",), {}, "schedule", "schedule-trigger"),
        (Surface.CLOUD, "x", ("scheduled", "event-triggered"), {}, "schedule", "schedule-trigger"),
        (Surface.CLOUD, "x", (), {"trigger": "https"}, "unknown", "no-initiation-evidence"),
        (Surface.CLOUD, "x", (), {"trigger": " "}, "unknown", "no-initiation-evidence"),
        (Surface.CLOUD, "x", (), {"trigger_type": "Screen"}, "unknown", "no-initiation-evidence"),
        (Surface.CLOUD, "x", (), {"trigger_types": ["Request"]}, "unknown", "no-initiation-evidence"),
        (
            Surface.CLOUD,
            "x",
            (),
            {"trigger_types": "Recurrence", "trigger": 5},
            "unknown",
            "no-initiation-evidence",
        ),
        (Surface.CLOUD, "x", (), {"trigger_type": "platform_event"}, "event", "event-trigger"),
    ],
)
def test_initiation(surface, resource_type, tags, metadata, initiation, rule):
    f = finding(Kind.AI_APP, tags=tags, metadata=metadata, surface=surface, resource_type=resource_type)
    autonomy = classify(f)
    assert autonomy is not None and autonomy["initiation"] == initiation
    assert rules(autonomy, "initiation") == {rule: initiation}


# ------------------------------------------------------------------- basis


def test_basis_is_deterministic_bounded_and_from_the_closed_rule_set():
    caps = ["code-exec", "tool-use", "multi-agent", "saas-actions"]
    tags = ["posture-permissions-bypassed", "scheduled", "write-access"]
    results = []
    for order in itertools.permutations(range(4)):
        f = finding(Kind.AGENT, caps=tuple(caps[i] for i in order), tags=tuple(reversed(tags)))
        results.append(classify(f))
    assert all(result == results[0] for result in results)
    autonomy = results[0]
    assert autonomy is not None and valid_autonomy(autonomy)
    assert len(autonomy["basis"]) <= MAX_BASIS
    assert [item["rule"] for item in autonomy["basis"]] == [
        "ai-system",
        "tool-access",
        "side-effect-tools",
        "agentic-execution",
        "unapproved-side-effects",
        "self-initiated",
        "no-restriction-evidence",
        "approval-bypassed",
        "schedule-trigger",
    ]
    for item in autonomy["basis"]:
        assert set(item) == {"bound", "rule", "value"} and RULES[item["rule"]] == item["bound"]


def test_basis_never_carries_finding_text():
    text = "orders-topic-acme-prod"
    f = finding(Kind.AGENT, caps=("tool-use",), metadata={"trigger": text, "name": text})
    autonomy = classify(f)
    assert autonomy is not None and autonomy["initiation"] == "event"
    assert text not in repr(autonomy)


def test_unexpected_metadata_shapes_are_ignored():
    f = finding(
        Kind.MCP_SERVER,
        caps=("data-access",),
        metadata={"servers": "fs", "posture": {"id": "x"}, "approval_gate": 3, "trigger_types": [1, None]},
    )
    f.metadata["servers"] = [1, "fs", {"auto_approve": "yes"}]
    assert interval(f) == (1, 5, "unknown", "unknown")


# --------------------------------------------------------- declared level


def entry(level: int | None) -> InventoryEntry:
    return InventoryEntry(agent_id="ops-agent", resources=["res-1"], autonomy_level=level)


def test_declared_level_below_the_floor_is_understated():
    f = finding(Kind.AGENT, caps=("tool-use", "code-exec"))
    apply_autonomy(f, entry(1))
    autonomy = f.metadata["autonomy"]
    assert (autonomy["floor"], autonomy["declared"], autonomy["declared_source"]) == (3, 1, "ops-agent")
    assert UNDERSTATED_TAG in f.tags and valid_autonomy(autonomy)


def test_declared_level_inside_the_interval_is_consistent():
    f = finding(Kind.AGENT, caps=("tool-use",))
    apply_autonomy(f, entry(4))
    assert f.metadata["autonomy"]["declared"] == 4 and UNDERSTATED_TAG not in f.tags
    assert "declared-above-ceiling" not in rules(f.metadata["autonomy"], "ceiling")


def test_declared_level_above_the_ceiling_is_a_basis_note_only():
    f = finding(Kind.AGENT_CONFIG, caps=("code-exec",), metadata={"approval_gate": {"scope": "every-action"}})
    apply_autonomy(f, entry(4))
    autonomy = f.metadata["autonomy"]
    assert autonomy["ceiling"] == 2 and UNDERSTATED_TAG not in f.tags
    assert rules(autonomy, "ceiling") == {"per-action-approval": 2, "declared-above-ceiling": 4}
    assert valid_autonomy(autonomy)


@pytest.mark.parametrize("matched", [None, entry(None)])
def test_no_declared_level_records_no_comparison(matched):
    f = finding(Kind.AGENT, caps=("tool-use",))
    apply_autonomy(f, matched)
    assert "declared" not in f.metadata["autonomy"] and "declared_source" not in f.metadata["autonomy"]


def test_apply_autonomy_is_idempotent_and_replaces_derived_output():
    f = finding(Kind.AGENT, caps=("tool-use", "code-exec"), tags=(UNDERSTATED_TAG, "custom"))
    # A plugin, cache entry or earlier pass cannot plant the block or the tag.
    f.metadata["autonomy"] = {"schema": SCHEMA, "floor": 0, "ceiling": 0}
    apply_autonomy(f, entry(5))
    first = (copy.deepcopy(f.metadata["autonomy"]), list(f.tags))
    assert first[0]["floor"] == 3 and UNDERSTATED_TAG not in f.tags and "custom" in f.tags
    apply_autonomy(f, entry(5))
    assert (f.metadata["autonomy"], f.tags) == first
    apply_autonomy(f, entry(0))
    apply_autonomy(f, entry(0))
    assert f.tags.count(UNDERSTATED_TAG) == 1
    apply_autonomy(f, None)
    assert UNDERSTATED_TAG not in f.tags and "declared" not in f.metadata["autonomy"]


# --------------------------------------------------------------- validation


def _valid() -> dict[str, Any]:
    autonomy = classify(finding(Kind.AGENT, caps=("tool-use",)))
    assert autonomy is not None
    return {**autonomy, "declared": 3, "declared_source": "ops-agent"}


@pytest.mark.parametrize(
    "change",
    [
        lambda a: a.update(schema="shadowscan.autonomy/v2"),
        lambda a: a.update(floor=True),
        lambda a: a.update(floor=6, floor_label="L6"),
        lambda a: a.update(
            floor=5, floor_label="L5 Fully Autonomous", ceiling=4, ceiling_label="L4 High Autonomy"
        ),
        lambda a: a.update(floor_label="L3 Agentic"),
        lambda a: a.update(oversight="maybe"),
        lambda a: a.update(initiation="cron"),
        lambda a: a.update(extra=1),
        lambda a: a.pop("basis"),
        lambda a: a.pop("declared_source"),
        lambda a: a.update(declared=True),
        lambda a: a.update(declared_source=" "),
        lambda a: a.update(basis="ai-system"),
        lambda a: a.update(basis=[{"bound": "floor", "rule": "invented", "value": 1}]),
        lambda a: a.update(basis=[{"bound": "ceiling", "rule": "ai-system", "value": 0}]),
        lambda a: a.update(basis=[{"bound": "floor", "rule": "ai-system", "value": True}]),
        lambda a: a.update(basis=[{"bound": "floor", "rule": "ai-system", "value": [0]}]),
        lambda a: a.update(basis=[{"bound": "floor", "rule": "ai-system", "value": 0, "evidence": "x"}]),
        lambda a: a.update(basis=["ai-system"]),
        # Regression: an unhashable rule raised TypeError, so `shadowscan merge` crashed.
        lambda a: a.update(basis=[{"bound": "floor", "rule": ["ai-system"], "value": 0}]),
        lambda a: a.update(basis=[{"bound": "floor", "rule": {"ai-system": 1}, "value": 0}]),
        lambda a: a.update(basis=[{"bound": ["floor"], "rule": "ai-system", "value": 0}]),
        # Each value stays in its bound's vocabulary; basis never carries free text.
        lambda a: a.update(basis=[{"bound": "floor", "rule": "ai-system", "value": "anything"}]),
        lambda a: a.update(basis=[{"bound": "ceiling", "rule": "per-action-approval", "value": 6}]),
        lambda a: a.update(basis=[{"bound": "oversight", "rule": "approval-gated", "value": "<b>x</b>"}]),
        lambda a: a.update(basis=[{"bound": "initiation", "rule": "event-trigger", "value": 2}]),
        lambda a: a.update(basis=[{"bound": "floor", "rule": "ai-system", "value": 0}] * (MAX_BASIS + 1)),
    ],
)
def test_valid_autonomy_rejects_malformed_blocks(change):
    autonomy = _valid()
    assert valid_autonomy(autonomy)
    change(autonomy)
    assert not valid_autonomy(autonomy)


@pytest.mark.parametrize("value", [None, [], "x", 3])
def test_valid_autonomy_rejects_non_objects(value):
    assert not valid_autonomy(value)
