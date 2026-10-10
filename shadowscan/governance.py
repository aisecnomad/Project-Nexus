"""Governance facts an operator declares in an Agent Capability Card.

A ``schema_version: 2`` card may carry a ``governance:`` block for facts the
scanner cannot observe: the EU AI Act risk class the operator assigned, the
intended purpose, the oversight measures in place, an AIUC-1 certificate
reference and whether the system is inside an ISO/IEC 42001 management system
scope. A finding matched to that card records the block as
``metadata.declared_governance``, with the card's agent id as ``source``, and
reports label it "declared". ShadowScan never infers, checks or scores these
facts; a declared risk class only selects which control references apply.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shadowscan.models import Finding

if TYPE_CHECKING:  # registry imports this module
    from shadowscan.registry import InventoryEntry

DECLARED_GOVERNANCE_KEY = "declared_governance"
EU_AI_ACT_RISK_CLASSES = ("prohibited", "high", "limited", "minimal", "gpai", "gpai-systemic", "unknown")
GOVERNANCE_FIELDS = (
    "eu_ai_act_risk_class",
    "intended_purpose",
    "oversight_measures",
    "aiuc1_certificate",
    "iso42001_scope",
)
MAX_INTENDED_PURPOSE = 500
MAX_OVERSIGHT_MEASURES = 20
MAX_OVERSIGHT_MEASURE = 200
MAX_AIUC1_CERTIFICATE = 200


class GovernanceError(ValueError):
    """A malformed ``governance`` block: ``field`` names where, the message says why, never the value."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(field, "expected a nonempty string")
    text = value.strip()
    if len(text) > limit:
        raise GovernanceError(field, f"expected at most {limit} characters")
    return text


def parse_governance(value: Any) -> dict[str, Any] | None:
    """A validated copy of a card's ``governance`` block, or None when it declares nothing.

    Unknown keys, a risk class outside :data:`EU_AI_ACT_RISK_CLASSES`, blank or
    over-long strings, more than 20 oversight measures and a non-boolean
    ``iso42001_scope`` raise :class:`GovernanceError`. A key set to null is
    undeclared, like an omitted one.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise GovernanceError("governance", "expected a mapping")
    if any(not isinstance(key, str) or key not in GOVERNANCE_FIELDS for key in value):
        # Unknown keys are not echoed: a misplaced value can be a credential.
        raise GovernanceError(
            "governance", "unsupported field; allowed fields: " + ", ".join(GOVERNANCE_FIELDS)
        )
    out: dict[str, Any] = {}
    risk_class = value.get("eu_ai_act_risk_class")
    if risk_class is not None:
        if not isinstance(risk_class, str) or risk_class not in EU_AI_ACT_RISK_CLASSES:
            raise GovernanceError(
                "governance.eu_ai_act_risk_class", "expected one of " + ", ".join(EU_AI_ACT_RISK_CLASSES)
            )
        out["eu_ai_act_risk_class"] = risk_class
    if value.get("intended_purpose") is not None:
        out["intended_purpose"] = _text(
            value["intended_purpose"], "governance.intended_purpose", MAX_INTENDED_PURPOSE
        )
    measures = value.get("oversight_measures")
    if measures is not None:
        field = "governance.oversight_measures"
        if not isinstance(measures, list):
            raise GovernanceError(field, "expected a list of nonempty strings")
        if len(measures) > MAX_OVERSIGHT_MEASURES:
            raise GovernanceError(field, f"expected at most {MAX_OVERSIGHT_MEASURES} measures")
        out["oversight_measures"] = [_text(item, field, MAX_OVERSIGHT_MEASURE) for item in measures]
    if value.get("aiuc1_certificate") is not None:
        out["aiuc1_certificate"] = _text(
            value["aiuc1_certificate"], "governance.aiuc1_certificate", MAX_AIUC1_CERTIFICATE
        )
    scope = value.get("iso42001_scope")
    if scope is not None:
        if type(scope) is not bool:
            raise GovernanceError("governance.iso42001_scope", "expected true or false")
        out["iso42001_scope"] = scope
    return out or None


def valid_declared_governance(value: Any) -> bool:
    """Whether ``value`` is a well-formed ``metadata.declared_governance`` block, as read from a report."""
    if not isinstance(value, dict):
        return False
    source = value.get("source")
    if not isinstance(source, str) or not source.strip():
        return False
    try:
        parsed = parse_governance({key: item for key, item in value.items() if key != "source"})
    except GovernanceError:
        return False
    return parsed is not None


def declared_risk_class(finding: Finding) -> str | None:
    """The EU AI Act risk class a registered finding's card declares; None when it declares none.

    Declared facts describe a sanctioned agent, so a finding that is not registered
    (``shadow`` true or unknown) or carries a malformed block declares nothing.
    """
    if finding.shadow is not False:
        return None
    block = finding.metadata.get(DECLARED_GOVERNANCE_KEY) if isinstance(finding.metadata, dict) else None
    if not isinstance(block, dict) or not valid_declared_governance(block):
        return None
    risk_class = block.get("eu_ai_act_risk_class")
    return risk_class if isinstance(risk_class, str) else None


FIELD_LABELS = {
    "eu_ai_act_risk_class": "EU AI Act risk class",
    "intended_purpose": "intended purpose",
    "oversight_measures": "oversight measures",
    "aiuc1_certificate": "AIUC-1 certificate",
    "iso42001_scope": "ISO/IEC 42001 scope",
}


def declared_facts(finding: Finding) -> tuple[str, list[tuple[str, str]]] | None:
    """``(card agent id, [(label, value)])`` for a report to show as declared; None when there are none.

    Only a registered finding with a well-formed block has declared facts.
    """
    block = finding.metadata.get(DECLARED_GOVERNANCE_KEY) if isinstance(finding.metadata, dict) else None
    if finding.shadow is not False or not isinstance(block, dict) or not valid_declared_governance(block):
        return None
    facts: list[tuple[str, str]] = []
    for key in GOVERNANCE_FIELDS:
        value = block.get(key)
        if isinstance(value, bool):
            facts.append((FIELD_LABELS[key], "yes" if value else "no"))
        elif isinstance(value, list):
            facts.append((FIELD_LABELS[key], "; ".join(value)))
        elif isinstance(value, str):
            facts.append((FIELD_LABELS[key], value))
    return block["source"], facts


def apply_declared_governance(finding: Finding, entry: InventoryEntry | None) -> None:
    """Record what the matched ``entry`` declares, replacing any earlier value.

    The block is derived on every reconciliation pass: a value a connector, a
    plugin, a cache entry or a previous pass wrote is removed first, so only the
    card that approved this finding in this run can declare its governance facts.
    """
    finding.metadata.pop(DECLARED_GOVERNANCE_KEY, None)
    if entry is not None and entry.governance:
        finding.update_metadata(**{DECLARED_GOVERNANCE_KEY: {**entry.governance, "source": entry.agent_id}})
