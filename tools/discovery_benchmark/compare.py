"""Compare a new ``metrics.json`` with a committed baseline and fail on regressions.

A regression is a drop in a tool's in-scope value-level F1 beyond the allowed
tolerance, a drop in repository-level recall, a control or near-miss
repository that the baseline left clean and the new run flags, or a repository
whose run was complete in the baseline and is incomplete now (an incomplete
scan's facts are a lower bound, so its clean result proves nothing).
Improvements are reported but never fail the gate. With ``repos`` (a partial
run), both sides are recomputed over those repositories only.
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from typing import Any

from tools.discovery_benchmark.score import Counts
from tools.discovery_benchmark.taxonomy import category


@dataclass
class Comparison:
    tool: str
    baseline_f1: float | None
    current_f1: float | None
    baseline_recall: float | None
    current_recall: float | None
    newly_flagged: list[str] = field(default_factory=list)
    newly_clean: list[str] = field(default_factory=list)
    baseline_incomplete: int | None = None  # None: the baseline predates incompleteness tracking
    current_incomplete: int | None = None
    newly_incomplete: list[str] = field(default_factory=list)
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
            "baseline_incomplete": self.baseline_incomplete,
            "current_incomplete": self.current_incomplete,
            "newly_incomplete": self.newly_incomplete,
            "regressions": self.regressions,
            "ok": self.ok,
        }


def _flagged_negatives(tool: dict[str, Any], corpus_classes: dict[str, str]) -> set[str]:
    flagged: set[str] = set()
    for repo_id, per in (tool.get("per_repo") or {}).items():
        if corpus_classes.get(repo_id, "positive") != "positive" and per.get("flagged"):
            flagged.add(repo_id)
    return flagged


def _incomplete(tool: dict[str, Any]) -> set[str] | None:
    """Repositories whose run was incomplete, or None when the metrics do not record it."""
    per_repo = tool.get("per_repo") or {}
    if any("incomplete" not in per for per in per_repo.values()):
        return None
    return {repo_id for repo_id, per in per_repo.items() if per["incomplete"]}


def with_run_incompleteness(metrics: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Fill the per-repository ``incomplete`` flag of metrics scored before it was recorded.

    ``manifest`` is the ``runs.json`` the metrics were scored from; a repository
    without a run there was not run, so it is not incomplete.
    """
    flags = {
        (str(r.get("tool")), str(r.get("repo"))): bool((r.get("detail") or {}).get("incomplete"))
        for r in manifest.get("results") or []
    }
    for tool_id, tool in (metrics.get("tools") or {}).items():
        for repo_id, per in (tool.get("per_repo") or {}).items():
            per.setdefault("incomplete", flags.get((tool_id, repo_id), False))
    return metrics


def subset(tool: dict[str, Any], repos: AbstractSet[str], corpus_classes: dict[str, str]) -> dict[str, Any]:
    """``tool``'s metrics recomputed over ``repos`` from its per-repository results.

    Value matching is per category, so the in-scope counts are the per-repository
    true positives, false positives and misses in the tool's declared categories;
    a positive repository is detected when the tool reported any in-scope fact.
    """
    scope = frozenset(tool.get("categories") or ())
    per_repo = {repo_id: per for repo_id, per in (tool.get("per_repo") or {}).items() if repo_id in repos}
    value = Counts()
    detection = Counts()
    for repo_id, per in per_repo.items():
        tp, fp, fn = ([f for f in per.get(key) or [] if category(f) in scope] for key in ("tp", "fp", "fn"))
        value.add(Counts(len(tp), len(fp), len(fn)))
        flagged = bool(tp or fp)
        if corpus_classes.get(repo_id, "positive") == "positive":
            detection.add(Counts(tp=int(flagged), fn=int(not flagged)))
        else:
            detection.add(Counts(fp=int(flagged)))
    return {
        **tool,
        "per_repo": per_repo,
        "value_level": {"in_scope": value.to_dict()},
        "repo_level": detection.to_dict(),
    }


def compare_tool(
    tool_id: str,
    baseline: dict[str, Any],
    current: dict[str, Any],
    corpus_classes: dict[str, str],
    *,
    f1_tolerance: float = 0.01,
    recall_tolerance: float = 0.0,
    repos: AbstractSet[str] | None = None,
) -> Comparison:
    base = (baseline.get("tools") or {}).get(tool_id) or {}
    cur = (current.get("tools") or {}).get(tool_id) or {}
    if repos is not None:
        base = subset(base, repos, corpus_classes) if base else base
        cur = subset(cur, repos, corpus_classes) if cur else cur
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
    was_incomplete = _incomplete(base)
    now_incomplete = _incomplete(cur)
    result.baseline_incomplete = None if was_incomplete is None else len(was_incomplete)
    result.current_incomplete = None if now_incomplete is None else len(now_incomplete)
    if now_incomplete is None:
        result.regressions.append("the current metrics do not record incomplete runs; re-score them")
    elif was_incomplete is None:
        if now_incomplete:
            result.regressions.append(
                f"{len(now_incomplete)} incomplete run(s), but the baseline records no incompleteness "
                "to compare with; pass its runs.json as --baseline-runs or re-score it"
            )
    else:
        result.newly_incomplete = sorted(now_incomplete - was_incomplete)
        if result.newly_incomplete:
            result.regressions.append(
                f"newly incomplete runs ({len(was_incomplete)} -> {len(now_incomplete)} incomplete): "
                + ", ".join(result.newly_incomplete)
            )
    return result


def compare(
    baseline: dict[str, Any],
    current: dict[str, Any],
    corpus_classes: dict[str, str],
    *,
    tools: list[str] | None = None,
    f1_tolerance: float = 0.01,
    repos: AbstractSet[str] | None = None,
) -> list[Comparison]:
    ids = tools or sorted(baseline.get("tools") or {})
    return [
        compare_tool(t, baseline, current, corpus_classes, f1_tolerance=f1_tolerance, repos=repos)
        for t in ids
    ]
