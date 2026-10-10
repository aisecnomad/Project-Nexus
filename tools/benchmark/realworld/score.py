"""Score the real-world benchmark against the oracle (and, optionally, adjudicated labels).

``python -m tools.benchmark.realworld.score --manifest manifest.jsonl --labels labels.jsonl \\
    --results OUT [--adjudication adjudication.jsonl] --output summary.json``

Implements section 7 of PROTOCOL.md. Nothing here ranks tools: every number is a proportion with a 95%
interval for a named stratum, and pooled figures say what they pool. Frames fall into four classes
(``probability``, ``search``, ``list``, ``challenge``); the headline scope is the probability class
only. Pooled "all" figures are descriptive of the sampled mix, not estimates for any population.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
Z95 = 1.959963984540054
BOOTSTRAP_REPS = 5000
BOOTSTRAP_SEED = 20261008
PROBABILITY = frozenset({"pypi-ai", "pypi-other", "go-ai", "go-random", "gitlab-random"})
SEARCH = frozenset({"npm-ai", "npm-other", "gitlab-ai"})
LISTED = frozenset({"list-mcp", "list-claude-code", "list-agents", "list-ordinary"})
CHALLENGE = frozenset({"hard-negative", "classical-ml", "prose-only"})
CLASS_ORDER = ("probability", "search", "list", "challenge")
SCOPES = ("probability", "all")
BASELINES = frozenset({"grep-any", "grep-code"})
CONFIG_VARIANTS = {"shadowscan-bigfiles": "shadowscan", "shadowscan-conf03": "shadowscan"}
VARIANTS = ("strict", "app-only", "core", "loose", "no-dep-only", "shared-vocab", "with-libraries")
PREVALENCES = (0.01, 0.05, 0.20)
STRICT_CTX = frozenset({"src", "config", "example", "notebook"})
AI_TIER_CLASSES = {
    "agent_framework": "agent", "agent_runtime": "agent", "mcp": "agent", "a2a": "agent",
    "coding_agent": "agent", "llm_sdk": "llm", "llm_local": "llm", "llm_gateway": "llm",
}  # fmt: skip
FAMILIES = {
    "dep": "declared dependency",
    "import": "import in code",
    "path": "coding-agent or MCP configuration file",
    "content": "workflow or infrastructure marker",
}


def frame_class(frame: str) -> str:
    if frame in PROBABILITY:
        return "probability"
    if frame in SEARCH:
        return "search"
    if frame in LISTED:
        return "list"
    return "challenge"


def wilson(k: int, n: int) -> tuple[float, float, float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + Z95**2 / n
    centre = (p + Z95**2 / (2 * n)) / denom
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95**2 / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / float(2**n)
    return min(1.0, 2 * tail)


def holm(p_values: dict[Any, float]) -> dict[Any, float]:
    """Holm step-down adjustment over a family of tests."""
    ordered = sorted(p_values.items(), key=lambda kv: kv[1])
    m = len(ordered)
    adjusted: dict[Any, float] = {}
    running = 0.0
    for rank, (key, p) in enumerate(ordered):
        running = max(running, min(1.0, (m - rank) * p))
        adjusted[key] = running
    return adjusted


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    err_pos: int = 0  # included in fn
    err_neg: int = 0  # excluded from specificity

    def add(self, other: Counts) -> None:
        for name in ("tp", "fp", "fn", "tn", "err_pos", "err_neg"):
            setattr(self, name, getattr(self, name) + getattr(other, name))


def derived(c: Counts) -> dict[str, float | None]:
    pos, neg = c.tp + c.fn, c.tn + c.fp
    recall = c.tp / pos if pos else None
    spec = c.tn / neg if neg else None
    f1 = 2 * c.tp / (2 * c.tp + c.fp + c.fn) if (2 * c.tp + c.fp + c.fn) else None
    denom = math.sqrt((c.tp + c.fp) * (c.tp + c.fn) * (c.tn + c.fp) * (c.tn + c.fn))
    mcc = (c.tp * c.tn - c.fp * c.fn) / denom if denom else 0.0
    bal = (recall + spec) / 2 if recall is not None and spec is not None else None
    return {"f1": f1, "mcc": mcc, "balanced_accuracy": bal}


def summarize(c: Counts) -> dict[str, Any]:
    out: dict[str, Any] = {
        "tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn, "errors_on_positives": c.err_pos,
        "errors_on_negatives": c.err_neg, "recall": wilson(c.tp, c.tp + c.fn),
        "specificity": wilson(c.tn, c.tn + c.fp), "precision": wilson(c.tp, c.tp + c.fp),
    }  # fmt: skip
    out.update(derived(c))
    return out


def percentile(sorted_values: list[float], q: float) -> float:
    return sorted_values[min(len(sorted_values) - 1, max(0, int(q * len(sorted_values))))]


def cluster_bootstrap(
    per_owner: dict[str, Counts], reps: int = BOOTSTRAP_REPS, seed: int = BOOTSTRAP_SEED
) -> dict[str, tuple[float, float] | None]:
    """95% percentile intervals for F1, MCC and balanced accuracy, resampling owners with replacement."""
    owners = sorted(per_owner)
    if len(owners) < 2:
        return {"f1": None, "mcc": None, "balanced_accuracy": None}
    rng = random.Random(seed)
    draws: dict[str, list[float]] = {"f1": [], "mcc": [], "balanced_accuracy": []}
    for _ in range(reps):
        total = Counts()
        for owner in rng.choices(owners, k=len(owners)):
            total.add(per_owner[owner])
        for key, value in derived(total).items():
            if value is not None:
                draws[key].append(value)
    return {
        key: (percentile(sorted(vals), 0.025), percentile(sorted(vals), 0.975)) if vals else None
        for key, vals in draws.items()
    }


def prevalence_ppv(
    sens: tuple[float, float, float] | None, spec: tuple[float, float, float] | None
) -> dict[str, Any]:
    """PPV at assumed prevalences from sensitivity and specificity (point, and interval corners)."""
    out: dict[str, Any] = {}
    if sens is None or spec is None:
        return out

    def ppv(s: float, f: float, prev: float) -> float | None:
        denom = s * prev + (1 - f) * (1 - prev)
        return s * prev / denom if denom else None

    for prev in PREVALENCES:
        out[f"{prev:.0%}"] = [
            ppv(sens[0], spec[0], prev),
            ppv(sens[1], spec[1], prev),
            ppv(sens[2], spec[2], prev),
        ]
    return out


# ---------------------------------------------------------------------------
# Truth and decisions


def truth(
    label: dict[str, Any],
    variant: str,
    override: dict[str, Any] | None = None,
    shared: frozenset[str] | None = None,
) -> bool | None:
    """True/False for a repository under a label variant, None when it is excluded.

    ``override`` is an adjudication row: ``ai`` (bool, or None when the adjudicators found the evidence
    undecided, which excludes the repository) and ``app`` (application-level integration, used by the
    ``app-only`` variant). ``shared`` is the set of technology ids that a tool other than ShadowScan
    mentions (``registry/vocab-overlap.json``), for the ``shared-vocab`` variant.
    """
    lab = label["labels"]
    if lab["role"] != "consumer" and variant != "with-libraries":
        return None
    if override is not None:
        ai = override.get("ai")
        if ai is None:
            return None
        if not ai:
            return False
        if variant == "app-only":
            app = override.get("app")
            if app is None:
                return True if lab["app_strict"] else None
            return True if app else None
        return True
    negative = lab["state"] == "negative"
    if variant in {"strict", "no-dep-only", "with-libraries"}:
        if lab["ai_strict"]:
            return None if variant == "no-dep-only" and lab["dep_only"] else True
        return False if negative else None
    if variant == "app-only":
        if lab["app_strict"]:
            return True
        return False if negative else None
    if variant == "core":
        if lab["ai_core"]:
            return True
        return False if negative else None
    if variant == "loose":
        if lab["ai_loose"]:
            return True
        return False if negative else None
    if variant == "shared-vocab":
        if lab["ai_strict"]:
            return True if shared is not None and shared & set(label.get("techs", [])) else None
        return False if negative else None
    raise ValueError(variant)


def decide(
    result: dict[str, Any] | None,
    is_positive: bool,
    errors: str = "primary",
    rule: str = "headline",
    partial: str = "error",
) -> str:
    """One of TP FP FN TN ERR_POS ERR_NEG MISSING for a (tool, repository) pair.

    ``partial="error"`` (headline) treats a scan the tool itself called incomplete as an error, whatever it
    found; ``partial="detected"`` keeps its findings (sensitivity analysis). ``errors="primary"`` excludes an
    error on a negative repository from specificity; ``errors="clean"`` counts it as a correct clean result.
    """
    if result is None:
        return "MISSING"
    if result["status"] != "ok" or (partial == "error" and result.get("partial")):
        if is_positive:
            return "ERR_POS"
        return "ERR_NEG" if errors == "primary" else "TN"
    detected = (
        result["detected"] if rule == "headline" else result.get("variants", {}).get(rule, result["detected"])
    )
    if is_positive:
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def tally(codes: list[tuple[str, str]]) -> tuple[Counts, dict[str, Counts]]:
    """Counts overall and per owner from (owner, code) pairs."""
    total = Counts()
    per_owner: dict[str, Counts] = defaultdict(Counts)
    for owner, code in codes:
        for bucket in (total, per_owner[owner]):
            if code == "TP":
                bucket.tp += 1
            elif code == "FP":
                bucket.fp += 1
            elif code in {"FN", "ERR_POS"}:
                bucket.fn += 1
                bucket.err_pos += code == "ERR_POS"
            elif code == "TN":
                bucket.tn += 1
            elif code == "ERR_NEG":
                bucket.err_neg += 1
    return total, dict(per_owner)


# ---------------------------------------------------------------------------
# Loading


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_results(directory: Path) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(directory.glob("*.jsonl")):
        out[path.stem] = {row["id"]: row for row in read_jsonl(path)}
    return out


def size_bucket(nbytes: int) -> str:
    mb = nbytes / 1e6
    return "<1MB" if mb < 1 else "1-10MB" if mb < 10 else "10-50MB" if mb < 50 else ">=50MB"


def runtime_stats(rows: list[dict[str, Any]]) -> dict[str, float | None]:
    times = sorted(float(r["seconds"]) for r in rows if r["status"] == "ok")
    return {
        "median": percentile(times, 0.5) if times else None,
        "p95": percentile(times, 0.95) if times else None,
    }


def evidence_families(label: dict[str, Any]) -> set[str]:
    """Evidence kinds behind a positive label: strong (agent or LLM) evidence in a strict context."""
    return {
        e["kind"]
        for e in label.get("evidence", [])
        if e["ctx"] in STRICT_CTX and e["kind"] in FAMILIES and e["tier"] in AI_TIER_CLASSES
    }


class Scorer:
    """Everything derived from one (manifest, labels, results, overrides) combination."""

    def __init__(
        self,
        manifest: list[dict[str, Any]],
        labels: dict[str, dict[str, Any]],
        results: dict[str, dict[str, dict[str, Any]]],
        overrides: dict[str, dict[str, Any]] | None = None,
        shared: frozenset[str] | None = None,
        excluded: frozenset[str] = frozenset(),
        reps: int = BOOTSTRAP_REPS,
    ) -> None:
        self.labels = labels
        self.results = results
        self.overrides = overrides or {}
        self.shared = shared
        self.reps = reps
        self.excluded = excluded
        self.repos = {
            r["id"]: r
            for r in manifest
            if r["id"] in labels and "labels" in labels[r["id"]] and r["id"] not in excluded
        }
        self.owner = {i: f"{r['host']}/{r['owner'].lower()}" for i, r in self.repos.items()}
        self.language = {i: labels[i]["inventory"]["primary_language"] for i in self.repos}
        self.cls = {i: frame_class(r["frame"]) for i, r in self.repos.items()}

    def truth(self, rid: str, variant: str) -> bool | None:
        return truth(self.labels[rid], variant, self.overrides.get(rid), self.shared)

    def in_scope(self, rid: str, scope: str) -> bool:
        return scope == "all" or self.cls[rid] == scope

    def codes(
        self,
        tool: str,
        scope: str = "all",
        variant: str = "strict",
        errors: str = "primary",
        rule: str = "headline",
        partial: str = "error",
        subset: set[str] | None = None,
    ) -> dict[str, str]:
        out: dict[str, str] = {}
        for rid in self.repos:
            if not self.in_scope(rid, scope) or (subset is not None and rid not in subset):
                continue
            t = self.truth(rid, variant)
            if t is not None:
                out[rid] = decide(self.results[tool].get(rid), t, errors, rule, partial)
        return out

    def summary_of(self, codes: dict[str, str]) -> dict[str, Any]:
        return summarize(tally([(self.owner[rid], c) for rid, c in codes.items()])[0])

    def block(self, tool: str, scope: str) -> dict[str, Any]:
        """One tool in one scope: the primary summary with intervals, policy and label sensitivity."""
        codes = self.codes(tool, scope)
        total, per_owner = tally([(self.owner[rid], c) for rid, c in codes.items()])
        primary = summarize(total)
        primary["bootstrap_95"] = cluster_bootstrap(per_owner, self.reps)
        primary["prevalence_ppv"] = prevalence_ppv(primary["recall"], primary["specificity"])
        by_id = self.results[tool]
        rules = sorted({k for r in by_id.values() for k in r.get("variants", {})})
        return {
            "primary": primary,
            "partial_as_detection": self.summary_of(self.codes(tool, scope, partial="detected")),
            "errors_as_clean": self.summary_of(self.codes(tool, scope, errors="clean")),
            "label_variants": {v: self.summary_of(self.codes(tool, scope, variant=v)) for v in VARIANTS},
            "detection_rules": {r: self.summary_of(self.codes(tool, scope, rule=r)) for r in rules},
        }

    def grouped(self, tool: str, key: Any) -> dict[str, dict[str, Any]]:
        groups: defaultdict[str, dict[str, str]] = defaultdict(dict)
        for rid, code in self.codes(tool).items():
            groups[key(rid)][rid] = code
        return {g: self.summary_of(c) for g, c in sorted(groups.items())}

    def families(self, tool: str) -> dict[str, Any]:
        """Recall on primary positives that have each kind of evidence (groups overlap)."""
        codes = self.codes(tool)
        out: dict[str, Any] = {}
        for kind in FAMILIES:
            sub = {
                rid: c
                for rid, c in codes.items()
                if c in {"TP", "FN", "ERR_POS"} and kind in evidence_families(self.labels[rid])
            }
            out[kind] = self.summary_of(sub)["recall"]
        positives = {r: c for r, c in codes.items() if c in {"TP", "FN", "ERR_POS"}}
        agent = {r: c for r, c in positives.items() if self.labels[r]["labels"]["agent_strict"]}
        llm_only = {
            r: c
            for r, c in positives.items()
            if self.labels[r]["labels"]["llm_strict"] and not self.labels[r]["labels"]["agent_strict"]
        }
        out["agent-type"] = self.summary_of(agent)["recall"]
        out["llm-only"] = self.summary_of(llm_only)["recall"]
        return out

    def vocabulary_split(self) -> dict[str, list[str]]:
        """Primary positives split by whether a tool other than ShadowScan mentions their technologies."""
        split: dict[str, list[str]] = {"shared": [], "shadowscan-only-or-unmentioned": []}
        if self.shared is None:
            return split
        for rid in self.repos:
            if self.truth(rid, "strict") is not True:
                continue
            techs = set(self.labels[rid].get("techs", []))
            split["shared" if techs & self.shared else "shadowscan-only-or-unmentioned"].append(rid)
        return split


def score(
    manifest: list[dict[str, Any]],
    labels: dict[str, dict[str, Any]],
    results: dict[str, dict[str, dict[str, Any]]],
    overrides: dict[str, dict[str, Any]] | None = None,
    reps: int = BOOTSTRAP_REPS,
    shared: frozenset[str] | None = None,
    excluded: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    sc = Scorer(manifest, labels, results, overrides, shared, excluded, reps)
    repos = sc.repos
    summary: dict[str, Any] = {"tools": {}, "sets": {}, "pairwise": {}, "unique_finds": {}}
    primary_truth = {rid: sc.truth(rid, "strict") for rid in repos}
    included = {rid for rid, t in primary_truth.items() if t is not None}
    states: defaultdict[str, int] = defaultdict(int)
    by_class: dict[str, defaultdict[str, int]] = {c: defaultdict(int) for c in CLASS_ORDER}
    for rid in repos:
        lab = labels[rid]["labels"]
        key = "ai-library" if lab["role"] != "consumer" else lab["state"]
        states[key] += 1
        by_class[sc.cls[rid]][key] += 1
    positives = {rid for rid in included if primary_truth[rid]}
    summary["sets"] = {
        "repositories": len(repos),
        "excluded": sorted(excluded),
        "primary": {
            "repositories": len(included),
            "positives": len(positives),
            "negatives": len(included) - len(positives),
        },  # fmt: skip
        "oracle_states": dict(sorted(states.items())),
        "by_class": {c: dict(sorted(v.items())) for c, v in by_class.items()},
        "frames": {
            f: sum(1 for r in repos.values() if r["frame"] == f)
            for f in sorted({r["frame"] for r in repos.values()})
        },
        "composition": {
            "positives": len(positives),
            "agent_type": sum(1 for r in positives if labels[r]["labels"]["agent_strict"]),
            "llm_only": sum(
                1
                for r in positives
                if labels[r]["labels"]["llm_strict"] and not labels[r]["labels"]["agent_strict"]
            ),
            "dependency_only": sum(1 for r in positives if labels[r]["labels"]["dep_only"]),
            "developer_config_only": sum(
                1 for r in positives if labels[r]["labels"].get("devcfg_only", False)
            ),
            "application_level": sum(1 for r in positives if labels[r]["labels"]["app_strict"]),
        },
    }
    devcfg = {rid for rid in positives if labels[rid]["labels"].get("devcfg_only", False)}
    split = sc.vocabulary_split()
    summary["sets"]["vocabulary_split"] = {k: len(v) for k, v in split.items()}

    for tool, by_id in results.items():
        entry: dict[str, Any] = {
            "baseline": tool in BASELINES,
            "variant_of": CONFIG_VARIANTS.get(tool),
            "scopes": {scope: sc.block(tool, scope) for scope in SCOPES},
            "by_class": sc.grouped(tool, lambda rid: sc.cls[rid]),
            "by_frame": sc.grouped(tool, lambda rid: repos[rid]["frame"]),
            "by_language": sc.grouped(tool, lambda rid: sc.language[rid]),
            "by_evidence": sc.families(tool),
            "devcfg_only_recall": sc.summary_of(sc.codes(tool, subset=devcfg))["recall"],
            "recall_by_vocabulary": {
                k: sc.summary_of(sc.codes(tool, subset=set(v)))["recall"] for k, v in split.items()
            },
        }
        strict_codes = sc.codes(tool)
        entry["decisions"] = {
            "false_alarms": sorted(rid for rid, c in strict_codes.items() if c == "FP"),
            "misses": sorted(rid for rid, c in strict_codes.items() if c == "FN"),
            "errors": sorted(rid for rid, c in strict_codes.items() if c in {"ERR_POS", "ERR_NEG"}),
        }
        rows = [by_id[rid] for rid in repos if rid in by_id]
        entry["partial_scans"] = sum(1 for r in rows if r.get("partial"))
        entry["runtime_seconds"] = runtime_stats(rows)
        entry["error_rate"] = wilson(sum(1 for r in rows if r["status"] != "ok"), len(rows))
        entry["error_rate_by_size"] = {
            b: [sum(1 for r in rows if size_bucket(repos[r["id"]]["bytes"]) == b and r["status"] != "ok"),
                sum(1 for r in rows if size_bucket(repos[r["id"]]["bytes"]) == b)]
            for b in ("<1MB", "1-10MB", "10-50MB", ">=50MB")
        }  # fmt: skip
        agent_pos = [
            rid
            for rid in included
            if primary_truth[rid]
            and labels[rid]["labels"]["agent_strict"]
            and by_id.get(rid, {}).get("status") == "ok"
        ]
        others = [
            rid
            for rid in included
            if rid in by_id
            and by_id[rid]["status"] == "ok"
            and rid not in set(agent_pos)
            and by_id[rid].get("agentic") is not None
        ]
        agent_flag = [rid for rid in agent_pos if by_id[rid].get("agentic")]
        entry["agent_tier"] = (
            {
                "agent_recall": wilson(len(agent_flag), len(agent_pos)),
                "agentic_flag_on_non_agent": wilson(
                    sum(1 for rid in others if by_id[rid]["agentic"]), len(others)
                ),
            }
            if tool not in BASELINES
            else None
        )
        summary["tools"][tool] = entry

    compared = [t for t in results if t not in CONFIG_VARIANTS]
    real = [t for t in compared if t not in BASELINES]
    for scope in SCOPES:
        correct = {
            t: {
                rid: c in {"TP", "TN"}
                for rid, c in sc.codes(t, scope).items()
                if c not in {"ERR_NEG", "MISSING"}
            }
            for t in compared
        }
        raw_p: dict[tuple[str, str], float] = {}
        counts: dict[tuple[str, str], tuple[int, int, int]] = {}
        for i, a in enumerate(sorted(compared)):
            for b in sorted(compared)[i + 1 :]:
                shared_ids = set(correct[a]) & set(correct[b])
                only_a = sum(1 for rid in shared_ids if correct[a][rid] and not correct[b][rid])
                only_b = sum(1 for rid in shared_ids if correct[b][rid] and not correct[a][rid])
                raw_p[(a, b)] = mcnemar_exact(only_a, only_b)
                counts[(a, b)] = (len(shared_ids), only_a, only_b)
        adjusted = holm(raw_p)
        summary["pairwise"][scope] = {
            f"{a}|{b}": {
                "n": counts[(a, b)][0],
                "a_right_b_wrong": counts[(a, b)][1],
                "b_right_a_wrong": counts[(a, b)][2],
                "p": raw_p[(a, b)],
                "p_holm": adjusted[(a, b)],
            }  # fmt: skip
            for (a, b) in raw_p
        }
    detections = {t: {rid for rid, c in sc.codes(t).items() if c == "TP"} for t in real}
    summary["unique_finds"] = {
        t: sorted(rid for rid in detections[t] if not any(rid in detections[o] for o in real if o != t))
        for t in real
    }
    union = set().union(*detections.values()) if detections else set()
    summary["union_recall"] = wilson(len(union), len(positives))
    summary["positives_missed_by_every_tool"] = sorted(positives - union)
    summary["ambiguous"] = {
        rid: {
            "frame": repos[rid]["frame"],
            "kind": (
                "weak-only" if labels[rid]["labels"]["weak_only"]
                else "adjacent-only" if labels[rid]["labels"]["adjacent_only"]
                else "tests-or-docs-only"
            ),
            "tools": {
                t: ("E" if (r := results[t].get(rid)) is None or r["status"] != "ok" or r.get("partial")
                    else "D" if r["detected"] else "-")
                for t in sorted(compared)
            },
        }
        for rid in repos
        if labels[rid]["labels"]["role"] == "consumer" and labels[rid]["labels"]["state"] == "ambiguous"
    }  # fmt: skip
    summary["bootstrap"] = {"reps": reps, "seed": BOOTSTRAP_SEED, "cluster": "host/owner"}
    summary["policies"] = {
        "headline_partial_scan": "error",
        "headline_errors": "positive: miss; negative: outside the specificity denominator",
        "scopes": {"probability": sorted(PROBABILITY), "all": "every frame"},
    }
    return summary


def load_shared(path: Path) -> frozenset[str] | None:
    if not path.exists():
        return None
    return frozenset(json.loads(path.read_text(encoding="utf-8"))["shared"])


def load_excluded(path: Path) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    return frozenset(json.loads(path.read_text(encoding="utf-8"))["excluded"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--vocab", type=Path, default=HERE / "registry" / "vocab-overlap.json")
    parser.add_argument("--exclusions", type=Path, default=HERE / "exclusions.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reps", type=int, default=BOOTSTRAP_REPS)
    args = parser.parse_args(argv)
    manifest = read_jsonl(args.manifest)
    labels = {row["id"]: row for row in read_jsonl(args.labels)}
    results = load_results(args.results)
    shared, excluded = load_shared(args.vocab), load_excluded(args.exclusions)
    summary = score(manifest, labels, results, None, args.reps, shared, excluded)
    if args.adjudication:
        overrides = {row["id"]: row for row in read_jsonl(args.adjudication)}
        summary["adjudicated"] = score(manifest, labels, results, overrides, args.reps, shared, excluded)
        summary["adjudicated"]["overridden"] = len(overrides)
    text = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
