"""Property tests for the autonomy interval: invariants over arbitrary evidence combinations."""

from __future__ import annotations

import copy
from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan import autonomy as autonomy_module  # noqa: E402
from shadowscan.models import Evidence, Finding, Kind, Surface  # noqa: E402
from shadowscan.registry import InventoryEntry  # noqa: E402
from shadowscan.signatures.schema import CAPABILITIES  # noqa: E402

APPLICABLE_KINDS = autonomy_module.APPLICABLE_KINDS
RULES = autonomy_module.RULES
UNDERSTATED_TAG = autonomy_module.UNDERSTATED_TAG
apply_autonomy = autonomy_module.apply_autonomy
classify = autonomy_module.classify
valid_autonomy = autonomy_module.valid_autonomy

TAGS = [
    "scheduled",
    "event-triggered",
    "always-on",
    "asks-user",
    "posture-permissions-bypassed",
    "posture-unrestricted-shell",
    "posture-unsandboxed",
    "mcp-auto-approve",
    "write-access",
    "disabled",
    "inactive",
    "suspended",
    UNDERSTATED_TAG,
    "custom-tag",
]
METADATA = st.fixed_dictionaries(
    {},
    optional={
        "approval_gate": st.one_of(
            st.fixed_dictionaries({"scope": st.sampled_from(["every-action", "some-actions", "other"])}),
            st.integers(),
        ),
        "trigger_type": st.sampled_from(["Scheduled", "RecordAfterSave", "Screen", ""]),
        "trigger_types": st.lists(
            st.sampled_from(["Recurrence", "ApiConnectionWebhook", "Request"]), max_size=3
        ),
        "trigger": st.one_of(st.none(), st.sampled_from(["", "https", "google.cloud.pubsub.v1"])),
        "servers": st.lists(
            st.fixed_dictionaries(
                {"auto_approve": st.one_of(st.booleans(), st.lists(st.just("t"), max_size=2))},
                optional={"disabled": st.booleans()},
            ),
            max_size=2,
        ),
        "posture": st.lists(
            st.fixed_dictionaries(
                {
                    "id": st.sampled_from(["posture-unrestricted-shell", "posture-permissions-bypassed"]),
                    "setting": st.sampled_from(["permissions.allow", "capabilities.shell_access"]),
                }
            ),
            max_size=2,
        ),
        "autonomy": st.just({"schema": "forged", "floor": 9}),
    },
)
FINDINGS = st.builds(
    lambda kind, caps, tags, metadata, signatures, surface, resource_type: _finding(
        kind, caps, tags, metadata, signatures, surface, resource_type
    ),
    st.sampled_from(sorted(Kind, key=lambda kind: kind.value)),
    st.lists(st.sampled_from(sorted(CAPABILITIES)), unique=True),
    st.lists(st.sampled_from(TAGS), unique=True),
    METADATA,
    st.lists(st.sampled_from(["heuristic.autonomy", "heuristic.scheduled-agent", "framework.x"]), max_size=2),
    st.sampled_from([Surface.ENDPOINT, Surface.CODE, Surface.CLOUD]),
    st.sampled_from(["ide-extension", "agent-config", "project"]),
)


def _finding(
    kind: Kind,
    caps: list[str],
    tags: list[str],
    metadata: dict[str, Any],
    signatures: list[str],
    surface: Surface,
    resource_type: str,
) -> Finding:
    f = Finding(
        surface=surface,
        connector="test.connector",
        kind=kind,
        title="AI thing",
        resource="res-1",
        resource_type=resource_type,
        capabilities=caps,
        tags=tags,
        metadata=copy.deepcopy(metadata),
    )
    for signature in signatures:
        f.add_evidence(Evidence(signal=f"code:{signature}", description="matched", signature=signature))
    return f


@given(f=FINDINGS)
@settings(max_examples=400, deadline=5000)
def test_interval_invariants(f: Finding) -> None:
    autonomy = classify(f)
    if f.kind not in APPLICABLE_KINDS:
        assert autonomy is None
        return
    assert autonomy is not None and valid_autonomy(autonomy)
    assert 0 <= autonomy["floor"] <= autonomy["ceiling"] <= 5
    ceiling_rules = {item["rule"] for item in autonomy["basis"] if item["bound"] == "ceiling"}
    assert ceiling_rules and ceiling_rules <= {r for r, bound in RULES.items() if bound == "ceiling"}
    if autonomy["ceiling"] < 5:
        # Only recorded restriction evidence lowers the ceiling.
        assert "per-action-approval" in ceiling_rules
        assert f.metadata["approval_gate"]["scope"] == "every-action"
    else:
        assert ceiling_rules & {"no-restriction-evidence", "conflicting-evidence"}
    floor_values = [item["value"] for item in autonomy["basis"] if item["bound"] == "floor"]
    assert max(floor_values) == autonomy["floor"]
    # Lifecycle and derived tags never move a bound.
    quiet = copy.deepcopy(f)
    quiet.tags = [tag for tag in f.tags if tag not in {"disabled", "inactive", "suspended", UNDERSTATED_TAG}]
    assert classify(quiet) == autonomy


@given(f=FINDINGS, level=st.one_of(st.none(), st.integers(min_value=0, max_value=5)))
@settings(max_examples=300, deadline=5000)
def test_apply_autonomy_is_idempotent(f: Finding, level: int | None) -> None:
    entry = InventoryEntry(agent_id="declared-agent", autonomy_level=level)
    apply_autonomy(f, entry)
    once = (copy.deepcopy(f.metadata.get("autonomy")), list(f.tags))
    apply_autonomy(f, entry)
    assert (f.metadata.get("autonomy"), f.tags) == once
    autonomy = once[0]
    if autonomy is None:
        assert f.kind not in APPLICABLE_KINDS and UNDERSTATED_TAG not in f.tags
        return
    assert valid_autonomy(autonomy)
    assert (UNDERSTATED_TAG in f.tags) is (level is not None and level < autonomy["floor"])
    assert ("declared" in autonomy) is (level is not None)
