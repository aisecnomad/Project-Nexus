"""Autonomy tiers: how much an AI system can do without a person, as an evidence interval.

Each applicable finding gets ``metadata.autonomy`` (schema ``shadowscan.autonomy/v1``) on the
L0 Chatbot to L5 Fully Autonomous scale:

* ``floor``: the lowest level the finding's evidence proves;
* ``ceiling``: the highest level positive evidence has not ruled out (5 without such evidence);
* ``oversight``: ``bypassed``, ``gated`` or ``unknown``;
* ``initiation``: ``schedule``, ``event``, ``human`` or ``unknown``;
* ``basis``: the rules that set each of them, from the closed set in :data:`RULES`.

A scanner can prove that a capability exists but rarely that one is absent, so the floor rises
only on evidence and the ceiling falls only on positive restriction evidence. Unknown never
counts as low. :func:`classify` is a pure function of the finding; :func:`apply_autonomy` adds the
level a matched inventory entry declares, and :func:`merge_autonomy` classifies a finding merged
from several reports. The rules and the evidence behind them are documented in
``docs/concepts/autonomy.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from shadowscan.models import Finding, Kind, Surface

if TYPE_CHECKING:
    from collections.abc import Sequence

    from shadowscan.registry import InventoryEntry

SCHEMA = "shadowscan.autonomy/v1"
UNDERSTATED_TAG = "autonomy-understated"
MAX_BASIS = 32


@dataclass(frozen=True, slots=True)
class Level:
    """One step of the autonomy scale."""

    number: int
    name: str  # stable machine name
    label: str

    @property
    def title(self) -> str:
        return f"L{self.number} {self.label}"


LEVELS = (
    Level(0, "chatbot", "Chatbot"),
    Level(1, "copilot", "Copilot"),
    Level(2, "supervised", "Supervised"),
    Level(3, "semi-autonomous", "Semi-Autonomous / Agentic Workflow"),
    Level(4, "high-autonomy", "High Autonomy"),
    Level(5, "fully-autonomous", "Fully Autonomous"),
)
MIN_LEVEL = LEVELS[0].number
MAX_LEVEL = LEVELS[-1].number

# Autonomy describes something that acts. Credentials, grants, identities, infrastructure, stored
# models and network contacts enable an agent; the correlated agent finding carries its autonomy.
APPLICABLE_KINDS = frozenset(
    {
        Kind.AGENT,
        Kind.FRAMEWORK_USAGE,
        Kind.AGENT_CONFIG,
        Kind.MCP_SERVER,
        Kind.WORKFLOW,
        Kind.BOT_APP,
        Kind.GATEWAY_CALLER,
        Kind.AI_APP,
        Kind.RUNTIME_PROCESS,
        Kind.CLOUD_RESOURCE,
    }
)

OVERSIGHT_VALUES = ("bypassed", "gated", "unknown")
INITIATION_VALUES = ("schedule", "event", "human", "unknown")
BOUNDS = ("floor", "ceiling", "oversight", "initiation")
# How much autonomy each oversight and initiation value admits, for widening merged intervals:
# an unknown gate admits more than a recorded one, and a trigger more than a person starting it.
_OVERSIGHT_RANK = {"gated": 0, "unknown": 1, "bypassed": 2}
_INITIATION_RANK = {"human": 0, "unknown": 1, "event": 2, "schedule": 3}
# The basis rule behind each initiation value.
_INITIATION_RULES = {
    "schedule": "schedule-trigger",
    "event": "event-trigger",
    "human": "interactive-client",
    "unknown": "no-initiation-evidence",
}

# Every rule id that can appear in ``basis``, in report order, with the bound it explains.
RULES: dict[str, str] = {
    "ai-system": "floor",
    "tool-access": "floor",
    "side-effect-tools": "floor",
    "agentic-execution": "floor",
    "unapproved-side-effects": "floor",
    "self-initiated": "floor",
    "no-restriction-evidence": "ceiling",
    "per-action-approval": "ceiling",
    "conflicting-evidence": "ceiling",
    "declared-above-ceiling": "ceiling",
    "approval-bypassed": "oversight",
    "approval-gated": "oversight",
    "no-oversight-evidence": "oversight",
    "schedule-trigger": "initiation",
    "event-trigger": "initiation",
    "interactive-client": "initiation",
    "no-initiation-evidence": "initiation",
}
_RULE_ORDER = {rule: number for number, rule in enumerate(RULES)}

# Read-type access: the system retrieves or calls tools on a person's behalf.
_TOOL_ACCESS = frozenset({"tool-use", "rag", "browsing", "data-access", "memory"})
# Tools with side effects outside the conversation.
_SIDE_EFFECTS = frozenset({"saas-actions", "code-exec", "delegated-identity"})
_SIDE_EFFECT_TAGS = frozenset({"write-access"})
# Side effects that count once approval is bypassed: direct data access can write as well as read.
_UNAPPROVED_SIDE_EFFECTS = _SIDE_EFFECTS | {"data-access"}

# Tags that record a run without per-action approval: Claude Code bypassPermissions, Codex
# approval_policy "never" and Goose GOOSE_MODE auto (posture); MCP autoApprove / alwaysAllow.
_BYPASS_TAGS = frozenset({"posture-permissions-bypassed", "mcp-auto-approve"})
# Signature evidence whose matched pattern disables an approval gate in code
# (human_in_the_loop=False, --dangerously-skip-permissions, autoApprove and similar).
_BYPASS_SIGNATURES = frozenset({"heuristic.autonomy"})
# Signature evidence for code wired to a scheduler, queue or webhook.
_TRIGGER_SIGNATURES = frozenset({"heuristic.scheduled-agent"})

_SCHEDULE_TAGS = frozenset({"scheduled", "always-on"})
_EVENT_TAGS = frozenset({"event-triggered"})
# Workflow definition language trigger types (Power Automate and Logic Apps ``trigger_types``).
_SCHEDULE_TRIGGER_TYPES = frozenset({"recurrence", "slidingwindow"})
_EVENT_TRIGGER_TYPES = frozenset(
    {"apiconnection", "apiconnectionwebhook", "openapiconnection", "openapiconnectionwebhook", "httpwebhook"}
)
# Salesforce flow ``trigger_type``.
_SCHEDULE_FLOW_TRIGGERS = frozenset({"scheduled"})
_EVENT_FLOW_TRIGGERS = frozenset(
    {"recordaftersave", "recordbeforesave", "recordbeforedelete", "platformevent"}
)
# An event function's ``trigger`` names the event type; these values name no event.
_NOT_EVENTS = frozenset({"", "manual", "none", "http", "https", "request"})
# Endpoint observations of something a person runs interactively: an editor extension, a browser
# extension, or a command found in shell history.
_INTERACTIVE_RESOURCE_TYPES = frozenset({"ide-extension", "browser-extension", "cli-usage"})
_LABEL = re.compile(r"[a-z0-9]+")


def level_title(number: int) -> str:
    """``"L3 Semi-Autonomous / Agentic Workflow"`` for 3."""
    return LEVELS[number].title


def applicable(finding: Finding) -> bool:
    return finding.kind in APPLICABLE_KINDS


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _records(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _folded(value: str) -> str:
    return "".join(_LABEL.findall(value.lower()))


def _approval_scope(finding: Finding) -> str | None:
    """``every-action`` or ``some-actions`` when a connector recorded positive approval gating."""
    gate = finding.metadata.get("approval_gate")
    scope = gate.get("scope") if isinstance(gate, dict) else None
    return scope if scope in {"every-action", "some-actions"} else None


def _trigger_initiation(finding: Finding) -> str | None:
    """``schedule`` or ``event`` from trigger tags or connector trigger metadata, else None."""
    tags = set(_strings(finding.tags))
    metadata = finding.metadata
    flow = metadata.get("trigger_type")
    flow_trigger = _folded(flow) if isinstance(flow, str) else ""
    types = {_folded(value) for value in _strings(metadata.get("trigger_types"))}
    if tags & _SCHEDULE_TAGS or flow_trigger in _SCHEDULE_FLOW_TRIGGERS or types & _SCHEDULE_TRIGGER_TYPES:
        return "schedule"
    event = metadata.get("trigger")
    if (
        tags & _EVENT_TAGS
        or flow_trigger in _EVENT_FLOW_TRIGGERS
        or types & _EVENT_TRIGGER_TYPES
        or (isinstance(event, str) and event.strip().lower() not in _NOT_EVENTS)
    ):
        return "event"
    return None


def _evidence_signatures(finding: Finding) -> set[str]:
    return {ev.signature for ev in finding.evidence if isinstance(ev.signature, str)}


def _autonomous_is_bypass(finding: Finding, triggered: bool) -> bool:
    """Whether the ``autonomous`` capability records a run without per-action approval.

    Connectors set it for different reasons. Agent settings and code that disable approval,
    an agent flagged autonomous, and model-selected tool loops mean no person approves each
    step. Low-code and cloud triggers, an unattended workflow definition and a gateway caller's
    around-the-clock cadence mean only that no person starts the run; they are initiation
    evidence and do not show that the flow lacks an approval step.
    """
    if "autonomous" not in _strings(finding.capabilities):
        return False
    signatures = _evidence_signatures(finding)
    if signatures & _BYPASS_SIGNATURES:
        return True
    return not (finding.kind == Kind.WORKFLOW or triggered or signatures & _TRIGGER_SIGNATURES)


def _bypass_evidence(finding: Finding, triggered: bool) -> bool:
    tags = set(_strings(finding.tags))
    if tags & _BYPASS_TAGS:
        return True
    metadata = finding.metadata
    for server in _records(metadata.get("servers")):
        approve = server.get("auto_approve")
        if not server.get("disabled") and (approve is True or (isinstance(approve, list) and approve)):
            return True
    # A Claude Code allow rule for every shell command runs commands without asking. OpenClaw's
    # shell_access grants a capability and says nothing about approval.
    for issue in _records(metadata.get("posture")):
        if issue.get("id") == "posture-unrestricted-shell" and issue.get("setting") == "permissions.allow":
            return True
    return _autonomous_is_bypass(finding, triggered)


def _initiation(finding: Finding, trigger: str | None) -> str:
    if trigger is not None:
        return trigger
    if finding.surface == Surface.ENDPOINT and finding.resource_type in _INTERACTIVE_RESOURCE_TYPES:
        return "human"
    return "unknown"


def classify(finding: Finding) -> dict[str, Any] | None:
    """The observed autonomy interval of ``finding``, or None for a kind autonomy does not describe.

    Total over loaded reports and plugin output: a metadata value of an unexpected shape is
    ignored rather than trusted or allowed to raise.
    """
    return _classify(finding)


def _classify(
    finding: Finding, *, bypassed: bool = False, initiation: str | None = None
) -> dict[str, Any] | None:
    """:func:`classify`, with oversight and initiation evidence another report recorded added.

    ``bypassed`` adds approval-bypass evidence and ``initiation`` raises the initiation to at
    least that value, so the combination rules (a model loop without per-action approval,
    unapproved side effects, a self-initiated run) apply as they would to one observation.
    """
    if not applicable(finding):
        return None
    capabilities = set(_strings(finding.capabilities))
    tags = set(_strings(finding.tags))
    trigger = _trigger_initiation(finding)
    bypassed = bypassed or _bypass_evidence(finding, trigger is not None)
    scope = _approval_scope(finding)
    # Positive gating cannot rule a level out while other evidence says approval is bypassed.
    every_action = scope == "every-action" and not bypassed
    observed = _initiation(finding, trigger)
    if initiation is None or _INITIATION_RANK[observed] >= _INITIATION_RANK[initiation]:
        initiation = observed
    initiation_rule = _INITIATION_RULES[initiation]

    basis: list[dict[str, Any]] = [{"bound": "floor", "rule": "ai-system", "value": 0}]
    floor = 0

    def rise(rule: str, level: int) -> None:
        nonlocal floor
        basis.append({"bound": "floor", "rule": rule, "value": level})
        floor = max(floor, level)

    if capabilities & _TOOL_ACCESS:
        rise("tool-access", 1)
    if capabilities & _SIDE_EFFECTS or tags & _SIDE_EFFECT_TAGS:
        rise("side-effect-tools", 2)
    # A model choosing its tools in a loop is semi-autonomous unless a person approves every
    # side-effecting action, which by definition makes it Supervised (L2).
    model_loop = finding.kind == Kind.AGENT and "tool-use" in capabilities and not every_action
    if finding.kind == Kind.WORKFLOW or "multi-agent" in capabilities or model_loop:
        rise("agentic-execution", 3)
    if bypassed and capabilities & _UNAPPROVED_SIDE_EFFECTS:
        rise("unapproved-side-effects", 4)
        if initiation in {"schedule", "event"}:
            rise("self-initiated", 5)

    if every_action:
        ceiling, ceiling_rule = 2, "per-action-approval"
    elif scope == "every-action":
        ceiling, ceiling_rule = MAX_LEVEL, "conflicting-evidence"
    else:
        ceiling, ceiling_rule = MAX_LEVEL, "no-restriction-evidence"
    basis.append({"bound": "ceiling", "rule": ceiling_rule, "value": ceiling})
    if floor > ceiling:
        ceiling = floor
        basis.append({"bound": "ceiling", "rule": "conflicting-evidence", "value": ceiling})

    if bypassed:
        oversight, oversight_rule = "bypassed", "approval-bypassed"
    elif scope is not None or "asks-user" in tags:
        oversight, oversight_rule = "gated", "approval-gated"
    else:
        oversight, oversight_rule = "unknown", "no-oversight-evidence"
    basis.append({"bound": "oversight", "rule": oversight_rule, "value": oversight})
    basis.append({"bound": "initiation", "rule": initiation_rule, "value": initiation})
    return {
        "schema": SCHEMA,
        "floor": floor,
        "floor_label": level_title(floor),
        "ceiling": ceiling,
        "ceiling_label": level_title(ceiling),
        "oversight": oversight,
        "initiation": initiation,
        "basis": _ordered(basis),
    }


def _ordered(basis: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {(item["bound"], item["rule"]): item for item in basis}
    ordered = sorted(
        unique.values(), key=lambda item: (BOUNDS.index(item["bound"]), _RULE_ORDER[item["rule"]])
    )
    return ordered[:MAX_BASIS]


def observed_floor(finding: Finding) -> int | None:
    autonomy = classify(finding)
    return None if autonomy is None else int(autonomy["floor"])


def apply_autonomy(finding: Finding, entry: InventoryEntry | None = None) -> None:
    """Record the autonomy interval on ``finding`` and compare it with the level ``entry`` declares.

    The block and the ``autonomy-understated`` tag are derived output: any earlier value (from a
    plugin, a cache entry or a previous pass) is replaced, so repeated application is idempotent.
    """
    finding.metadata.pop("autonomy", None)
    if UNDERSTATED_TAG in finding.tags:
        finding.tags = [tag for tag in finding.tags if tag != UNDERSTATED_TAG]
    autonomy = classify(finding)
    if autonomy is None:
        return
    if entry is not None and entry.autonomy_level is not None:
        declared = entry.autonomy_level
        autonomy["declared"] = declared
        autonomy["declared_source"] = entry.agent_id
        if declared < autonomy["floor"]:
            finding.add_tag(UNDERSTATED_TAG)
        elif declared > autonomy["ceiling"]:
            autonomy["basis"] = _ordered(
                [
                    *autonomy["basis"],
                    {"bound": "ceiling", "rule": "declared-above-ceiling", "value": declared},
                ]
            )
    finding.update_metadata(autonomy=autonomy)


def _rank(bound: str, value: Any) -> int:
    if bound == "oversight":
        return _OVERSIGHT_RANK[value]
    if bound == "initiation":
        return _INITIATION_RANK[value]
    return int(value)


def merge_autonomy(finding: Finding, sources: Sequence[Any]) -> None:
    """Record the autonomy interval of a finding merged from several reports.

    ``sources`` are the finding's ``metadata.autonomy`` blocks in its source reports; malformed
    ones are ignored. The interval is classified from the merged finding together with the
    widest oversight and initiation any block records, so the combination rules apply across
    reports (approval bypassed in one and a schedule trigger in another reach L5). It is then
    widened so it admits at least what any source's block admits: the highest floor and
    ceiling, oversight ``bypassed`` over ``unknown`` over ``gated`` and initiation ``schedule``
    over ``event`` over ``unknown`` over ``human``. A widened bound keeps the basis of the block
    that set it. While the merged finding is registered, the lowest level any block declares
    for the agent it is registered to is kept, whatever the order of the reports, and compared
    with the merged interval as :func:`apply_autonomy` compares it.
    """
    finding.metadata.pop("autonomy", None)
    if UNDERSTATED_TAG in finding.tags:
        finding.tags = [tag for tag in finding.tags if tag != UNDERSTATED_TAG]
    blocks = [block for block in sources if valid_autonomy(block)]
    autonomy = _classify(
        finding,
        bypassed=any(block["oversight"] == "bypassed" for block in blocks),
        initiation=max(
            (block["initiation"] for block in blocks), key=_INITIATION_RANK.__getitem__, default=None
        ),
    )
    if autonomy is None:
        return
    basis = {bound: [item for item in autonomy["basis"] if item["bound"] == bound] for bound in BOUNDS}
    for bound in BOUNDS:
        # max() keeps the first of equal blocks, so the classified interval wins ties.
        widest = max([autonomy, *blocks], key=lambda block: _rank(bound, block[bound]))
        if _rank(bound, widest[bound]) > _rank(bound, autonomy[bound]):
            autonomy[bound] = widest[bound]
            basis[bound] = [item for item in widest["basis"] if item["bound"] == bound]
    # Every interval here has floor <= ceiling, so the highest floor never exceeds the highest
    # ceiling.
    autonomy["floor_label"] = level_title(autonomy["floor"])
    autonomy["ceiling_label"] = level_title(autonomy["ceiling"])
    notes = [item for bound in BOUNDS for item in basis[bound] if item["rule"] != "declared-above-ceiling"]
    declared = [
        block
        for block in blocks
        if "declared" in block and block["declared_source"] == finding.registry_match
    ]
    if declared and finding.shadow is False:
        lowest = min(declared, key=lambda block: block["declared"])
        autonomy["declared"] = lowest["declared"]
        autonomy["declared_source"] = lowest["declared_source"]
        if lowest["declared"] < autonomy["floor"]:
            finding.add_tag(UNDERSTATED_TAG)
        elif lowest["declared"] > autonomy["ceiling"]:
            notes.append({"bound": "ceiling", "rule": "declared-above-ceiling", "value": lowest["declared"]})
    autonomy["basis"] = _ordered(notes)
    finding.update_metadata(autonomy=autonomy)


def _level(value: Any) -> bool:
    return type(value) is int and MIN_LEVEL <= value <= MAX_LEVEL


def valid_autonomy(value: Any) -> bool:
    """Whether ``value`` is a well-formed ``shadowscan.autonomy/v1`` block, as read from a report."""
    required = {
        "schema",
        "floor",
        "floor_label",
        "ceiling",
        "ceiling_label",
        "oversight",
        "initiation",
        "basis",
    }
    if not isinstance(value, dict) or not required <= set(value):
        return False
    declared = {"declared", "declared_source"} & set(value)
    if set(value) - required - {"declared", "declared_source"} or declared not in (
        set(),
        {"declared", "declared_source"},
    ):
        return False
    floor, ceiling = value["floor"], value["ceiling"]
    if (
        value["schema"] != SCHEMA
        or not _level(floor)
        or not _level(ceiling)
        or floor > ceiling
        or value["floor_label"] != level_title(floor)
        or value["ceiling_label"] != level_title(ceiling)
        or value["oversight"] not in OVERSIGHT_VALUES
        or value["initiation"] not in INITIATION_VALUES
    ):
        return False
    if declared and (
        not _level(value["declared"])
        or not isinstance(value["declared_source"], str)
        or not value["declared_source"].strip()
    ):
        return False
    basis = value["basis"]
    if not isinstance(basis, list) or len(basis) > MAX_BASIS:
        return False
    for item in basis:
        if (
            not isinstance(item, dict)
            or set(item) != {"bound", "rule", "value"}
            or RULES.get(item["rule"]) != item["bound"]
            or isinstance(item["value"], bool)
            or not isinstance(item["value"], (int, str))
        ):
            return False
    return True
