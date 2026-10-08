"""Scoring: compare normalized tool facts with the labeled corpus.

Three views are reported for every tool:

* repository level - did the tool surface *anything* in the taxonomy for a
  positive repository, and did it stay silent on controls and near-misses;
* category level - facts collapsed to their category (a tool that reports
  ``mcp-client-config:generic`` where the corpus says ``:cursor`` is right at
  this level);
* value level - exact facts. ``<category>:generic`` is a wildcard that
  matches one expected fact of that category.

Predicted facts listed as *tolerated* for a repository (lock-file-only
dependencies) are dropped before scoring. Facts outside a tool's declared
categories are ignored in the *in-scope* view and counted in the *all* view.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from tools.discovery_benchmark.corpus import Corpus, Repo
from tools.discovery_benchmark.taxonomy import CATEGORIES, category


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, other: Counts) -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": _round(self.precision),
            "recall": _round(self.recall),
            "f1": _round(self.f1),
        }


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


@dataclass
class RepoScore:
    status: str
    seconds: float
    predicted: list[str]
    tp: list[str] = field(default_factory=list)
    fp: list[str] = field(default_factory=list)
    fn: list[str] = field(default_factory=list)
    tolerated_hits: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    flagged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "seconds": self.seconds,
            "flagged": self.flagged,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tolerated_hits": self.tolerated_hits,
            "out_of_scope": self.out_of_scope,
        }


def match_values(predicted: set[str], expected: set[str]) -> tuple[list[str], list[str], list[str]]:
    """Exact matching with ``<category>:generic`` wildcards. Returns (tp, fp, fn)."""
    tp: list[str] = []
    remaining = set(expected)
    unmatched: list[str] = []
    for fact in sorted(predicted):
        if fact in remaining:
            tp.append(fact)
            remaining.discard(fact)
        else:
            unmatched.append(fact)
    fp: list[str] = []
    for fact in unmatched:
        cat, _, value = fact.partition(":")
        if value == "generic":
            candidates = sorted(f for f in remaining if category(f) == cat)
            if candidates:
                tp.append(fact)
                remaining.discard(candidates[0])
                continue
            if any(category(f) == cat for f in expected):
                tp.append(fact)  # the category is present; the specific value was already matched
                continue
        fp.append(fact)
    return tp, fp, sorted(remaining)


def match_categories(predicted: set[str], expected: set[str]) -> Counts:
    pred = {category(f) for f in predicted}
    exp = {category(f) for f in expected}
    return Counts(tp=len(pred & exp), fp=len(pred - exp), fn=len(exp - pred))


def score_repo(
    repo: Repo, predicted_facts: list[str], scope: frozenset[str], *, status: str, seconds: float
) -> RepoScore:
    predicted = set(predicted_facts)
    tolerated = {f for f in predicted if f in set(repo.tolerated)}
    predicted -= tolerated
    out_of_scope = sorted(f for f in predicted if category(f) not in scope)
    score = RepoScore(status=status, seconds=seconds, predicted=sorted(predicted))
    score.tolerated_hits = sorted(tolerated)
    score.out_of_scope = out_of_scope
    score.flagged = bool(predicted)
    expected = set(repo.expected_facts)
    tp, fp, fn = match_values(predicted, expected)
    score.tp, score.fp, score.fn = tp, fp, fn
    return score


def _quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))
    return round(ordered[index], 2)


def score_tool(
    corpus: Corpus, tool_id: str, scope: frozenset[str], runs: list[dict[str, Any]]
) -> dict[str, Any]:
    by_repo = {r["repo"]: r for r in runs if r["tool"] == tool_id}
    per_repo: dict[str, RepoScore] = {}
    value_all = Counts()
    value_scope = Counts()
    cat_all = Counts()
    cat_scope = Counts()
    by_category: dict[str, Counts] = {c: Counts() for c in CATEGORIES}
    detection = {"positive": [0, 0], "control": [0, 0], "nearmiss": [0, 0]}
    statuses = {"ok": 0, "failed": 0, "timeout": 0, "skipped": 0, "error": 0, "missing": 0}
    seconds: list[float] = []
    for repo in corpus.repos:
        run = by_repo.get(repo.id)
        if run is None:
            statuses["missing"] += 1
            score = score_repo(repo, [], scope, status="missing", seconds=0.0)
        else:
            statuses[str(run.get("status", "error"))] = statuses.get(str(run.get("status", "error")), 0) + 1
            score = score_repo(
                repo,
                list(run.get("facts") or []),
                scope,
                status=str(run.get("status")),
                seconds=float(run.get("seconds") or 0.0),
            )
            if run.get("status") in {"ok", "failed"}:
                seconds.append(float(run.get("seconds") or 0.0))
        per_repo[repo.id] = score
        expected = set(repo.expected_facts)
        predicted = set(score.predicted)
        value_all.add(Counts(len(score.tp), len(score.fp), len(score.fn)))
        in_scope_pred = {f for f in predicted if category(f) in scope}
        in_scope_exp = {f for f in expected if category(f) in scope}
        tp_s, fp_s, fn_s = match_values(in_scope_pred, in_scope_exp)
        value_scope.add(Counts(len(tp_s), len(fp_s), len(fn_s)))
        cat_all.add(match_categories(predicted, expected))
        cat_scope.add(match_categories(in_scope_pred, in_scope_exp))
        for cat in CATEGORIES:
            pred_c = {f for f in predicted if category(f) == cat}
            exp_c = {f for f in expected if category(f) == cat}
            tp_c, fp_c, fn_c = match_values(pred_c, exp_c)
            by_category[cat].add(Counts(len(tp_c), len(fp_c), len(fn_c)))
        totals = detection[repo.klass]
        totals[1] += 1
        if bool(in_scope_pred):
            totals[0] += 1
    pos_hit, pos_n = detection["positive"]
    neg_hit = detection["control"][0] + detection["nearmiss"][0]
    repo_level = Counts(tp=pos_hit, fp=neg_hit, fn=pos_n - pos_hit)
    return {
        "categories": sorted(scope),
        "runs": statuses,
        "seconds": {
            "median": _quantile(seconds, 0.5),
            "p90": _quantile(seconds, 0.9),
            "max": _quantile(seconds, 1.0),
            "total": round(sum(seconds), 1),
            "mean": round(statistics.fmean(seconds), 2) if seconds else None,
        },
        "repo_level": {
            **repo_level.to_dict(),
            "positives_detected": pos_hit,
            "positives": pos_n,
            "controls_flagged": detection["control"][0],
            "controls": detection["control"][1],
            "nearmiss_flagged": detection["nearmiss"][0],
            "nearmiss": detection["nearmiss"][1],
        },
        "value_level": {
            "all": value_all.to_dict(),
            "in_scope": value_scope.to_dict(),
            "by_category": {c: by_category[c].to_dict() for c in CATEGORIES},
        },
        "category_level": {"all": cat_all.to_dict(), "in_scope": cat_scope.to_dict()},
        "per_repo": {rid: s.to_dict() for rid, s in per_repo.items()},
    }


def score_all(
    corpus: Corpus, manifest: dict[str, Any], scopes: dict[str, frozenset[str]], names: dict[str, str]
) -> dict[str, Any]:
    runs = list(manifest.get("results") or [])
    tool_ids = sorted({str(r["tool"]) for r in runs} | set(manifest.get("tool_versions") or {}))
    tools: dict[str, Any] = {}
    for tool_id in tool_ids:
        scope = scopes.get(tool_id, frozenset(CATEGORIES))
        tools[tool_id] = {
            "name": names.get(tool_id, tool_id),
            "version": (manifest.get("tool_versions") or {}).get(tool_id),
            **score_tool(corpus, tool_id, scope, runs),
        }
    expected_total = sum(len(r.expected) for r in corpus.repos)
    return {
        "corpus": {
            "repos": len(corpus.repos),
            "positive": len(corpus.by_class("positive")),
            "control": len(corpus.by_class("control")),
            "nearmiss": len(corpus.by_class("nearmiss")),
            "expected_facts": expected_total,
            "expected_by_category": {
                c: sum(1 for r in corpus.repos for e in r.expected if category(e.fact) == c)
                for c in CATEGORIES
            },
        },
        "run": {
            k: manifest.get(k) for k in ("started", "finished", "host", "policy", "workers", "tools_skipped")
        },
        "tools": tools,
    }
