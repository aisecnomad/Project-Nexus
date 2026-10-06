"""Score benchmark results: confusion matrices, Wilson intervals and paired tests.

``python -m tools.benchmark.score --results OUT [--reference shadowscan]``

Positive means the case label is ``agent`` or ``llm``. An ``error`` outcome
counts as "not detected" in the confusion matrix and is also reported on its
own. Cases a tool does not support (``n/a``) are excluded from that tool's
per-surface metrics but count as misses in estate-wide recall.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

Z95 = 1.959963984540054
SURFACES = ("repo", "endpoint", "network")


def wilson(k: int, n: int) -> tuple[float | None, float | None, float | None]:
    if n == 0:
        return None, None, None
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
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / float(2**n)
    return min(1.0, 2 * tail)


def confusion(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = err = 0
    by_label: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        hit = r["status"] == "ok" and r["detected"]
        err += r["status"] == "error"
        pos = r["label"] != "none"
        by_label[r["label"]][0] += hit
        by_label[r["label"]][1] += 1
        if pos and hit:
            tp += 1
        elif pos:
            fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1
    recall = wilson(tp, tp + fn)
    spec = wilson(tn, tn + fp)
    prec = wilson(tp, tp + fp)
    f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    bal = (recall[0] + spec[0]) / 2 if recall[0] is not None and spec[0] is not None else None
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else 0.0
    return {
        "n": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "errors": err,
        "recall": recall,
        "specificity": spec,
        "precision": prec,
        "f1": f1,
        "balanced_accuracy": bal,
        "mcc": mcc,
        "rate_by_label": {k: (v[0] / v[1] if v[1] else None, v[1]) for k, v in sorted(by_label.items())},
    }


def bootstrap_f1(rows: list[dict[str, Any]], reps: int = 2000, seed: int = 7) -> tuple[float, float]:
    rng = random.Random(seed)
    vals = []
    for _ in range(reps):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        vals.append(confusion(sample)["f1"])
    vals.sort()
    return vals[int(0.025 * reps)], vals[int(0.975 * reps) - 1]


def load(results: Path) -> dict[str, list[dict[str, Any]]]:
    out = {}
    for path in sorted(results.glob("*.jsonl")):
        out[path.stem] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return out


def score(results: Path, reference: str) -> dict[str, Any]:
    data = load(results)
    manifest = json.loads((results / "run-manifest.json").read_text(encoding="utf-8"))
    summary: dict[str, Any] = {"manifest": manifest, "tools": {}, "paired": {}, "families": {}}
    for tool, rows in data.items():
        entry: dict[str, Any] = {"surfaces": {}}
        supported = [r for r in rows if r["status"] != "n/a"]
        for surface in SURFACES:
            srows = [r for r in rows if r["surface"] == surface and r["status"] != "n/a"]
            if srows:
                metrics = confusion(srows)
                metrics["f1_ci"] = bootstrap_f1(srows)
                times = sorted(r["seconds"] for r in srows if r["status"] == "ok")
                metrics["median_seconds"] = times[len(times) // 2] if times else None
                agent_rows = [r for r in srows if r["agentic"] is not None]
                if agent_rows:
                    pos = [r for r in agent_rows if r["label"] == "agent"]
                    non = [r for r in agent_rows if r["label"] != "agent"]
                    flagged_pos = sum(bool(r["agentic"]) for r in pos)
                    flagged_non = sum(bool(r["agentic"]) for r in non)
                    metrics["agent_tier"] = {
                        "agent_recall": wilson(flagged_pos, len(pos)),
                        "agent_false_alarm_on_non_agent": wilson(flagged_non, len(non)),
                    }
                entry["surfaces"][surface] = metrics
        if supported:
            entry["supported_cases"] = len(supported)
            entry["supported_overall"] = confusion(supported)
        estate = confusion(
            [r if r["status"] != "n/a" else {**r, "status": "ok", "detected": False} for r in rows]
        )
        entry["estate"] = {"recall": estate["recall"], "specificity": estate["specificity"], "n": estate["n"]}
        summary["tools"][tool] = entry
        fam: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in rows:
            if r["status"] != "n/a":
                fam[f"{r['surface']}|{r['family']}|{r['label']}"][0] += r["status"] == "ok" and r["detected"]
                fam[f"{r['surface']}|{r['family']}|{r['label']}"][1] += 1
        summary["families"][tool] = dict(sorted(fam.items()))
    if reference in data:
        ref = {r["case"]: r for r in data[reference]}
        for tool, rows in data.items():
            if tool == reference:
                continue
            for surface in SURFACES:
                b = c = n = 0
                for r in rows:
                    if r["surface"] != surface or r["status"] == "n/a":
                        continue
                    o = ref[r["case"]]
                    truth = r["label"] != "none"
                    other_ok = (r["status"] == "ok" and r["detected"]) == truth
                    ref_ok = (o["status"] == "ok" and o["detected"]) == truth
                    n += 1
                    b += ref_ok and not other_ok
                    c += other_ok and not ref_ok
                if n:
                    summary["paired"].setdefault(tool, {})[surface] = {
                        "n": n,
                        f"{reference}_right_other_wrong": b,
                        f"other_right_{reference}_wrong": c,
                        "mcnemar_p": mcnemar_exact(b, c),
                    }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--reference", default="shadowscan")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    summary = score(args.results, args.reference)
    text = json.dumps(summary, indent=1) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
