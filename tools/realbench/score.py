"""Score tool results against the frozen labels (PROTOCOL.md §8 and §9).

``python -m tools.realbench.score --labels L.json --manifest corpus.json --results DIR --output OUT.json``
(optional: ``--adjudicated adjudicated.json`` for the post-run labels)

Verdicts follow the pre-registered rule (``strict``): a completed scan gives a
positive verdict when its report holds an item for the task and a negative
one otherwise; a crash, a timeout or a scan the tool itself reports as
incomplete gives *no verdict*. No verdict is a wrong answer in the primary
analysis (a miss on a positive, a false alarm on a negative), because a failed
scan cannot certify a repository clean. Two secondary analyses relax this:
``completed_only`` drops rows without a verdict, and the ``evidence`` rule
(added at the run freeze, see PROTOCOL.md §12) also accepts an item found by
an incomplete scan as a positive verdict.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tools.benchmark.score import mcnemar_exact, wilson

BOOTSTRAP = 2000
BOOTSTRAP_SEED = 20261008
PREVALENCES = (0.01, 0.05, 0.20)
REFERENCES = ("shadowscan", "baseline-grep")
Row = dict[str, Any]


def load_results(results: Path) -> dict[str, dict[str, Row]]:
    out: dict[str, dict[str, Row]] = {}
    for path in sorted(results.glob("*.jsonl")):
        if path.name.endswith(".repeat.jsonl"):
            continue
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        out[path.stem] = {r["id"]: r for r in rows}
    return out


def load_repeats(results: Path) -> dict[str, dict[str, Row]]:
    out: dict[str, dict[str, Row]] = {}
    for path in sorted(results.glob("*.repeat.jsonl")):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        out[path.name.removesuffix(".repeat.jsonl")] = {r["id"]: r for r in rows}
    return out


def verdict(row: Row, task: str, rule: str = "strict") -> bool | None:
    """True/False for a positive/negative verdict, None for no verdict."""
    flag = bool(row["detected"] if task == "t1" else row["agentic"])
    if row["status"] == "ok":
        return flag
    if rule == "evidence" and row["status"] == "partial" and flag:
        return True
    return None


def truth(label: Row, task: str) -> bool:
    return bool(label["label"] != "none") if task == "t1" else bool(label["label"] == "agent")


def populations(labels: dict[str, Row]) -> dict[str, Callable[[Row, str], bool | None]]:
    """name -> function(label, task) returning the truth value, or None when excluded."""

    def primary(lab: Row, task: str) -> bool | None:
        if lab["label"] == "none" and lab["assistant_artifacts"]:
            return None
        return truth(lab, task)

    def footprint(lab: Row, task: str) -> bool | None:
        if task == "t1":
            return lab["label"] != "none" or bool(lab["assistant_artifacts"])
        return truth(lab, task)

    def no_ml(lab: Row, task: str) -> bool | None:
        return None if lab.get("ml_only") else primary(lab, task)

    def t2_no_assistant_negatives(lab: Row, task: str) -> bool | None:
        value = primary(lab, task)
        if task == "t2" and value is False and lab["assistant_artifacts"]:
            return None
        return value

    return {
        "primary": primary,
        "footprint": footprint,
        "no_ml": no_ml,
        "t2_without_assistant_negatives": t2_no_assistant_negatives,
    }


def confusion(pairs: list[tuple[bool, bool | None]], completed_only: bool = False) -> dict[str, Any]:
    tp = fp = fn = tn = no_verdict = 0
    for actual, predicted in pairs:
        if predicted is None:
            no_verdict += 1
            if completed_only:
                continue
            predicted = not actual  # no verdict is a wrong answer
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return metrics(tp, fp, fn, tn) | {"no_verdict": no_verdict}


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    recall = wilson(tp, tp + fn)
    spec = wilson(tn, tn + fp)
    prec = wilson(tp, tp + fp)
    f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else 0.0
    bal = (recall[0] + spec[0]) / 2 if recall[0] is not None and spec[0] is not None else None
    return {
        "n": tp + fp + fn + tn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "recall": recall,
        "specificity": spec,
        "precision": prec,
        "f1": f1,
        "mcc": mcc,
        "balanced_accuracy": bal,
    }


def bootstrap(pairs: list[tuple[bool, bool | None]], reps: int = BOOTSTRAP) -> dict[str, tuple[float, float]]:
    rng = random.Random(BOOTSTRAP_SEED)
    f1s, mccs = [], []
    n = len(pairs)
    for _ in range(reps):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        m = confusion(sample)
        f1s.append(m["f1"])
        mccs.append(m["mcc"])
    f1s.sort()
    mccs.sort()
    lo, hi = int(0.025 * reps), int(0.975 * reps) - 1
    return {"f1": (f1s[lo], f1s[hi]), "mcc": (mccs[lo], mccs[hi])}


def ppv(recall: float | None, specificity: float | None, prevalence: float) -> float | None:
    if recall is None or specificity is None:
        return None
    denom = recall * prevalence + (1 - specificity) * (1 - prevalence)
    return recall * prevalence / denom if denom else None


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (monotone)."""
    order = sorted(pvalues, key=lambda k: pvalues[k])
    m = len(order)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, key in enumerate(order):
        running = max(running, min(1.0, (m - i) * pvalues[key]))
        adjusted[key] = running
    return adjusted


def _applies(rows: dict[str, Row], task: str) -> bool:
    return task == "t1" or any(r["agentic"] is not None for r in rows.values())


def score(
    labels: dict[str, Row], manifest: dict[str, Row], results: dict[str, dict[str, Row]]
) -> dict[str, Any]:
    pops = populations(labels)
    out: dict[str, Any] = {
        "tools": {},
        "paired": {},
        "label_counts": dict(Counter(lab["label"] for lab in labels.values())),
    }
    out["assistant_only"] = sorted(
        i for i, lab in labels.items() if lab["label"] == "none" and lab["assistant_artifacts"]
    )
    for tool, rows in results.items():
        missing = set(labels) - set(rows)
        if missing:
            raise ValueError(f"{tool}: no result for {sorted(missing)[:5]}")
        entry: dict[str, Any] = {}
        for task in ("t1", "t2"):
            if not _applies(rows, task):
                continue
            for pop_name, pop in pops.items():
                if task == "t1" and pop_name == "t2_without_assistant_negatives":
                    continue
                pairs = []
                evidence_pairs = []
                for rid, lab in labels.items():
                    actual = pop(lab, task)
                    if actual is not None:
                        pairs.append((actual, verdict(rows[rid], task)))
                        evidence_pairs.append((actual, verdict(rows[rid], task, "evidence")))
                block = confusion(pairs)
                if pop_name == "primary":
                    block["ci"] = bootstrap(pairs)
                    block["completed_only"] = confusion(pairs, completed_only=True)
                    block["evidence_rule"] = confusion(evidence_pairs)
                    rec, spec = block["recall"][0], block["specificity"][0]
                    block["ppv_at_prevalence"] = {str(p): ppv(rec, spec, p) for p in PREVALENCES}
                entry[f"{task}:{pop_name}"] = block
        seconds = sorted(r["seconds"] for r in rows.values() if r["status"] != "error")
        entry["runtime"] = {
            "median": seconds[len(seconds) // 2] if seconds else None,
            "p90": seconds[min(len(seconds) - 1, int(0.9 * len(seconds)))] if seconds else None,
            "status": dict(Counter(r["status"] for r in rows.values())),
        }
        entry["breakdowns"] = breakdowns(labels, manifest, rows)
        entry["evidence_overlap"] = evidence_overlap(labels, rows)
        assistant_only = [
            rid for rid, lab in labels.items() if lab["label"] == "none" and lab["assistant_artifacts"]
        ]
        flagged = sum(verdict(rows[rid], "t1") is True for rid in assistant_only)
        entry["assistant_only_detection"] = wilson(flagged, len(assistant_only))
        out["tools"][tool] = entry
    for reference in REFERENCES:
        if reference not in results:
            continue
        for task in ("t1", "t2"):
            if not _applies(results[reference], task):
                continue
            raw: dict[str, float] = {}
            detail: dict[str, Any] = {}
            for tool, rows in results.items():
                if tool == reference or not _applies(rows, task):
                    continue
                b = c = n = 0
                for rid, lab in labels.items():
                    actual = pops["primary"](lab, task)
                    if actual is None:
                        continue
                    ref_ok = verdict(results[reference][rid], task) == actual
                    other_ok = verdict(rows[rid], task) == actual
                    n += 1
                    b += ref_ok and not other_ok
                    c += other_ok and not ref_ok
                raw[tool] = mcnemar_exact(b, c)
                detail[tool] = {"n": n, "reference_right_other_wrong": b, "other_right_reference_wrong": c}
            adjusted = holm(raw)
            for tool in detail:
                detail[tool]["p"] = raw[tool]
                detail[tool]["p_holm"] = adjusted[tool]
            out["paired"][f"{reference}:{task}"] = detail
    return out


def _dominant_language(repo: Row) -> str:
    names = {
        ".py": "Python", ".ipynb": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".jsx": "JavaScript",
        ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".java": "Java", ".kt": "Kotlin",
        ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".c": "C/C++", ".h": "C/C++",
        ".cpp": "C/C++", ".cc": "C/C++", ".swift": "Swift", ".tf": "Terraform", ".sh": "Shell",
    }  # fmt: skip
    counts: Counter[str] = Counter()
    for ext, n in (repo.get("top_ext") or {}).items():
        if ext in names:
            counts[names[ext]] += n
    return counts.most_common(1)[0][0] if counts else "other"


def breakdowns(labels: dict[str, Row], manifest: dict[str, Row], rows: dict[str, Row]) -> dict[str, Any]:
    """Detection rates (T1 verdict positive) by stratum, subtype, trait, host, language and size tercile."""
    sizes = sorted(manifest[i]["files"] for i in labels)
    cut1, cut2 = sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3]
    groups: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))

    def add(dimension: str, key: str, hit: bool) -> None:
        cell = groups[dimension][key]
        cell[0] += hit
        cell[1] += 1

    for rid, lab in labels.items():
        repo = manifest[rid]
        hit = verdict(rows[rid], "t1") is True
        agent_hit = verdict(rows[rid], "t2") is True if rows[rid]["agentic"] is not None else None
        tag = "assistant-only" if lab["label"] == "none" and lab["assistant_artifacts"] else lab["label"]
        add("stratum", f"{repo['stratum']}|{tag}", hit)
        add("host", f"{repo['host']}|{tag}", hit)
        add("language", f"{_dominant_language(repo)}|{tag}", hit)
        size = "small" if repo["files"] <= cut1 else ("medium" if repo["files"] <= cut2 else "large")
        add("size", f"{size}|{tag}", hit)
        for sub in lab.get("subtypes") or []:
            add("subtype", sub, hit)
            if agent_hit is not None and sub.startswith("A"):
                add("subtype_agentic", sub, agent_hit)
        if lab["label"] == "none":
            for trait in lab.get("traits") or []:
                add("trait_false_alarm", trait, hit)
            if lab.get("ml_only"):
                add("trait_false_alarm", "ml_only", hit)
    return {
        dim: {k: {"hits": v[0], "n": v[1]} for k, v in sorted(cells.items())} for dim, cells in groups.items()
    }


def evidence_overlap(labels: dict[str, Row], rows: dict[str, Row]) -> dict[str, Any]:
    """Among T1 true positives, the share where a cited file is one of the annotators' evidence files."""
    hit = total = without_paths = 0
    for rid, lab in labels.items():
        if lab["label"] == "none" or verdict(rows[rid], "t1") is not True:
            continue
        total += 1
        cited = set(rows[rid].get("paths") or [])
        if not cited:
            without_paths += 1
        gold = {e["path"] for e in lab.get("evidence") or [] if e.get("criterion") not in ("none-note",)}
        hit += bool(cited & gold)
    return {"true_positives": total, "overlap": wilson(hit, total), "without_paths": without_paths}


def determinism(results: dict[str, dict[str, Row]], repeats: dict[str, dict[str, Row]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for tool, again in repeats.items():
        first = results.get(tool, {})
        flips = [rid for rid, row in again.items() if rid in first and (
            verdict(row, "t1") != verdict(first[rid], "t1")
            or (row["agentic"] is not None and verdict(row, "t2") != verdict(first[rid], "t2"))
        )]  # fmt: skip
        out[tool] = {"n": len(again), "flips": flips}
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--adjudicated", type=Path, help="post-run adjudicated labels (same schema)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    labels = {r["id"]: r for r in json.loads(args.labels.read_text(encoding="utf-8"))["labels"]}
    manifest = {r["id"]: r for r in json.loads(args.manifest.read_text(encoding="utf-8"))["repos"]}
    results = load_results(args.results)
    summary: dict[str, Any] = {"frozen": score(labels, manifest, results)}
    summary["determinism"] = determinism(results, load_repeats(args.results))
    if args.adjudicated:
        adjudicated = {r["id"]: r for r in json.loads(args.adjudicated.read_text(encoding="utf-8"))["labels"]}
        summary["adjudicated"] = score(adjudicated, manifest, results)
        summary["label_changes"] = [
            {"id": i, "frozen": labels[i]["label"], "adjudicated": adjudicated[i]["label"]}
            for i in sorted(labels)
            if labels[i]["label"] != adjudicated[i]["label"]
            or labels[i]["assistant_artifacts"] != adjudicated[i]["assistant_artifacts"]
        ]
    args.output.write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
