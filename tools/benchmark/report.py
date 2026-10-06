"""Render a Markdown report from scored benchmark results.

``python -m tools.benchmark.report --results DIR --output REPORT.md``
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Any

from tools.benchmark.adapters import ADAPTERS
from tools.benchmark.score import SURFACES, confusion, score

DISPLAY = {a.name: a.display for a in ADAPTERS}
ORDER = [a.name for a in ADAPTERS]


def _ci(triple: Any) -> str:
    if not triple or triple[0] is None:
        return "–"
    p, lo, hi = triple
    return f"{p:.2f} ({lo:.2f}–{hi:.2f})"


def _pct(x: float | None) -> str:
    return "–" if x is None else f"{100 * x:.0f}%"


def agentsonar_sweep(results: Path, thresholds: tuple[float, ...]) -> list[tuple[float, dict[str, Any]]]:
    """Post-hoc: re-apply AgentSonar's scores at other cut-offs (from the stored raw output)."""
    raw_path = results / "raw" / "agentsonar.jsonl.gz"
    rows = {
        r["case"]: r
        for r in map(json.loads, (results / "agentsonar.jsonl").read_text(encoding="utf-8").splitlines())
    }
    best: dict[str, float] = {}
    with gzip.open(raw_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            item = json.loads(line)
            top = 0.0
            for out in item["raw"]["classify.jsonl"].splitlines():
                row = json.loads(out)
                if row.get("is_noise"):
                    continue
                score_ = 1.0 if row.get("agent") else max([float(v) for v in row["scores"].values()] or [0.0])
                top = max(top, score_)
            best[item["case"]] = top
    sweep = []
    for t in thresholds:
        scored = [{**r, "detected": best.get(c, 0.0) > t} for c, r in rows.items() if r["status"] == "ok"]
        sweep.append((t, confusion(scored)))
    return sweep


def render(results: Path) -> str:
    s = score(results, "shadowscan")
    tools = [t for t in ORDER if t in s["tools"]]
    m = s["manifest"]
    out: list[str] = []
    w = out.append
    w("# Shadow-AI discovery head-to-head: results\n")
    w(
        f"Corpus: {m['cases_run']} synthetic cases, SHA-256 `{m['corpus_sha256']}` "
        f"(seed {m['corpus_metadata']['seed']}). Python {m['python']} on {m['platform']}.\n"
    )
    w(
        "**These are results on author-written synthetic cases, not field accuracy.** "
        "The corpus was written in the ShadowScan repository; see the README for the "
        "conflict of interest, the per-tool run modes and the limits. Intervals are 95% "
        "Wilson (proportions) or bootstrap (F1).\n"
    )
    w("## Coverage: which surfaces each tool can be scored on\n")
    w("| Tool | " + " | ".join(SURFACES) + " | Estate recall (unsupported = miss) |")
    w("|---|" + "---|" * (len(SURFACES) + 1))
    for t in tools:
        cells = ["✓" if sur in s["tools"][t]["surfaces"] else "—" for sur in SURFACES]
        w(f"| {DISPLAY[t]} | " + " | ".join(cells) + f" | {_ci(s['tools'][t]['estate']['recall'])} |")
    w("")
    for sur in SURFACES:
        w(f"## Surface: {sur}\n")
        w(
            "| Tool | n | TP | FP | FN | TN | Errors | Recall | Specificity | Precision | F1 | MCC "
            "| Agent recall | Median s |"
        )
        w("|---|" + "---|" * 13)
        ranked = [t for t in tools if sur in s["tools"][t]["surfaces"]]
        ranked.sort(key=lambda t: -s["tools"][t]["surfaces"][sur]["mcc"])
        for t in ranked:
            x = s["tools"][t]["surfaces"][sur]
            lo, hi = x["f1_ci"]
            tier = x.get("agent_tier", {}).get("agent_recall")
            secs = x["median_seconds"]
            w(
                f"| {DISPLAY[t]} | {x['n']} | {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} | {x['errors']} "
                f"| {_ci(x['recall'])} | {_ci(x['specificity'])} | {_ci(x['precision'])} "
                f"| {x['f1']:.2f} ({lo:.2f}–{hi:.2f}) | {x['mcc']:.2f} | {_ci(tier)} "
                f"| {'–' if secs is None else f'{secs:.1f}'} |"
            )
        w("")
        w("Detection rate by family (positives: higher is better; `none` rows: lower is better).\n")
        fams = sorted(
            {k for t in ranked for k in s["families"][t] if k.startswith(sur + "|")},
            key=lambda k: ({"agent": 0, "llm": 1, "none": 2}[k.split("|")[2]], k),
        )
        w("| Family | Label | " + " | ".join(DISPLAY[t] for t in ranked) + " |")
        w("|---|---|" + "---|" * len(ranked))
        for k in fams:
            _, fam, lab = k.split("|")
            cells = []
            for t in ranked:
                hit, n = s["families"][t].get(k, (0, 0))
                cells.append(f"{hit}/{n}" if n else "–")
            w(f"| {fam} | {lab} | " + " | ".join(cells) + " |")
        w("")
    if s["paired"]:
        w("## Paired comparison with ShadowScan (exact McNemar on correct/incorrect)\n")
        w("| Tool | Surface | n | ShadowScan right, other wrong | Other right, ShadowScan wrong | p |")
        w("|---|---|---|---|---|---|")
        for t in tools:
            for sur, x in s["paired"].get(t, {}).items():
                w(
                    f"| {DISPLAY[t]} | {sur} | {x['n']} | {x['shadowscan_right_other_wrong']} "
                    f"| {x['other_right_shadowscan_wrong']} | {x['mcnemar_p']:.2g} |"
                )
        w("")
    if (results / "raw" / "agentsonar.jsonl.gz").exists():
        w("## Supplementary (post hoc): AgentSonar at other cut-offs\n")
        w(
            "The pre-registered cut-off is 0.3, the value in the project's examples. These rows "
            "re-apply its stored scores at other cut-offs after the scored run. They were not "
            "pre-registered and are shown only to separate threshold choice from ranking quality.\n"
        )
        w("| Cut-off | Recall | Specificity | F1 |")
        w("|---|---|---|---|")
        for cut, x in agentsonar_sweep(results, (0.3, 0.5, 0.6, 0.7, 0.8, 0.9)):
            w(f"| > {cut:.1f} | {_ci(x['recall'])} | {_ci(x['specificity'])} | {x['f1']:.2f} |")
        w("")
    w("## Errors\n")
    for t in tools:
        rows = [json.loads(line) for line in (results / f"{t}.jsonl").read_text().splitlines()]
        errs = [r for r in rows if r["status"] == "error"]
        if errs:
            w(f"- {DISPLAY[t]}: {len(errs)} errors, e.g. `{errs[0]['note'][:160]}`")
    if not any(
        r["status"] == "error"
        for t in tools
        for r in map(json.loads, (results / f"{t}.jsonl").read_text().splitlines())
    ):
        w("- None: every supported case completed for every tool.")
    w("")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    text = render(args.results)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
