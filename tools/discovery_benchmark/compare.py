"""Compare a new ``metrics.json`` with a committed baseline and fail on regressions.

A regression is a drop in a tool's in-scope value-level F1 beyond the allowed
tolerance, a drop in repository-level recall, or a control or near-miss
repository that the baseline left clean and the new run flags. Improvements are
reported but never fail the gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Comparison:
    tool: str
    baseline_f1: float | None
    current_f1: float | None
    baseline_recall: float | None
    current_recall: float | None
    newly_flagged: list[str] = field(default_factory=list)
    newly_clean: list[str] = field(default_factory=list)
    regressions: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.regressions

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "baseline_f1": self.baseline_f1,
            "current_f1": self.current_f1,
            "baseline_repo_recall": self.baseline_recall,
            "current_repo_recall": self.current_recall,
            "newly_flagged_negatives": self.newly_flagged,
            "newly_clean_negatives": self.newly_clean,
            "regressions": self.regressions,
            "ok": self.ok,
        }


def _flagged_negatives(tool: dict[str, Any], corpus_classes: dict[str, str]) -> set[str]:
    flagged: set[str] = set()
    for repo_id, per in (tool.get("per_repo") or {}).items():
        if corpus_classes.get(repo_id, "positive") != "positive" and per.get("flagged"):
            flagged.add(repo_id)
    return flagged


def compare_tool(
    tool_id: str,
    baseline: dict[str, Any],
    current: dict[str, Any],
    corpus_classes: dict[str, str],
    *,
    f1_tolerance: float = 0.01,
    recall_tolerance: float = 0.0,
) -> Comparison:
    base = (baseline.get("tools") or {}).get(tool_id) or {}
    cur = (current.get("tools") or {}).get(tool_id) or {}
    b_f1 = ((base.get("value_level") or {}).get("in_scope") or {}).get("f1")
    c_f1 = ((cur.get("value_level") or {}).get("in_scope") or {}).get("f1")
    b_rec = (base.get("repo_level") or {}).get("recall")
    c_rec = (cur.get("repo_level") or {}).get("recall")
    result = Comparison(tool_id, b_f1, c_f1, b_rec, c_rec)
    if not cur:
        result.regressions.append("tool missing from the current metrics")
        return result
    # A null F1 means the tool found nothing, which scores as zero rather than "unknown".
    if b_f1 is not None and (c_f1 or 0.0) < b_f1 - f1_tolerance:
        result.regressions.append(f"in-scope F1 fell from {b_f1:.4f} to {c_f1 or 0.0:.4f}")
    if b_rec is not None and (c_rec or 0.0) < b_rec - recall_tolerance:
        result.regressions.append(f"repository-level recall fell from {b_rec:.4f} to {c_rec or 0.0:.4f}")
    before = _flagged_negatives(base, corpus_classes)
    after = _flagged_negatives(cur, corpus_classes)
    result.newly_flagged = sorted(after - before)
    result.newly_clean = sorted(before - after)
    if result.newly_flagged:
        result.regressions.append("newly flagged negatives: " + ", ".join(result.newly_flagged))
    return result


def compare(
    baseline: dict[str, Any],
    current: dict[str, Any],
    corpus_classes: dict[str, str],
    *,
    tools: list[str] | None = None,
    f1_tolerance: float = 0.01,
) -> list[Comparison]:
    ids = tools or sorted(baseline.get("tools") or {})
    return [compare_tool(t, baseline, current, corpus_classes, f1_tolerance=f1_tolerance) for t in ids]
