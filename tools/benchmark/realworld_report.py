"""Render a Markdown report from scored real-world benchmark results.

``python -m tools.benchmark.realworld_report --results DIR --output REPORT.md``
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from tools.benchmark.realworld_adapters import rw_adapters
from tools.benchmark.score import confusion, load, score

_DISPLAY = {a.name: a.display for a in rw_adapters({})}
_ORDER = [a.name for a in rw_adapters({})]


def _ci(triple: Any) -> str:
    if not triple or triple[0] is None:
        return "–"
    p, lo, hi = triple
    return f"{p:.2f} ({lo:.2f}–{hi:.2f})"


def _ordered(names: list[str]) -> list[str]:
    return [n for n in _ORDER if n in names] + sorted(set(names) - set(_ORDER))


def _mark(row: dict[str, Any]) -> str:
    if row["status"] == "error":
        return "E"
    if row["status"] != "ok":
        return "–"
    if not row["detected"]:
        return "·"
    return "**A**" if row.get("agentic") else "✓"


def render(results: Path) -> str:
    summary = score(results, reference="shadowscan")
    data = load(results)
    tools = _ordered(list(data))
    manifest = summary["manifest"]
    lines: list[str] = []
    out = lines.append

    out("# Real-world repository benchmark results")
    out("")
    out(
        "Repo surface only; every case is a public repository pinned by commit "
        "(see `benchmarks/realworld/corpus.json`). Positive means the label is "
        "`agent` or `llm`. Errors count as misses and are also shown. Read the "
        "caveats in `benchmarks/realworld/README.md` before quoting numbers."
    )
    out("")
    out(
        f"- Corpus: `{manifest['corpus']}` sha256 `{manifest['corpus_sha256'][:16]}…`, "
        f"{manifest['cases_run']} repositories"
    )
    out(
        f"- Runtime: Python {manifest['python']}, {manifest['platform']}, "
        f"{manifest.get('timeout_seconds', '?')}s timeout per tool per repository"
    )
    dirty = manifest.get("checkouts_dirtied_by_tool") or {}
    if dirty:
        pairs = "; ".join(f"{tool}: {', '.join(repos)}" for tool, repos in sorted(dirty.items()))
        out(f"- Checkouts written to by a tool and restored afterwards: {pairs}")
    out("")

    out("## Detection (any AI/agent evidence vs the repository label)")
    out("")
    out("| Tool | n | Err | Recall | Specificity | Precision | F1 (95% CI) | Bal. acc | MCC | Median s |")
    out("|---|---|---|---|---|---|---|---|---|---|")
    for tool in tools:
        m = summary["tools"][tool]["surfaces"].get("repo")
        if not m:
            continue
        f1lo, f1hi = m.get("f1_ci", (0.0, 0.0))
        bal = "–" if m["balanced_accuracy"] is None else format(m["balanced_accuracy"], ".2f")
        med = "–" if m["median_seconds"] is None else m["median_seconds"]
        out(
            f"| {_DISPLAY.get(tool, tool)} | {m['n']} | {m['errors']} | {_ci(m['recall'])} "
            f"| {_ci(m['specificity'])} | {_ci(m['precision'])} "
            f"| {m['f1']:.2f} ({f1lo:.2f}–{f1hi:.2f}) "
            f"| {bal} | {m['mcc']:.2f} | {med} |"
        )
    out("")

    out("## Agent tier (tools whose output separates agent evidence from plain usage)")
    out("")
    out("| Tool | Agent recall | False alarm on non-agent repos |")
    out("|---|---|---|")
    for tool in tools:
        m = summary["tools"][tool]["surfaces"].get("repo", {})
        tier = m.get("agent_tier")
        if tier:
            out(
                f"| {_DISPLAY.get(tool, tool)} | {_ci(tier['agent_recall'])} "
                f"| {_ci(tier['agent_false_alarm_on_non_agent'])} |"
            )
    out("")

    out("## Per-family detection (detected/total)")
    out("")
    families: dict[str, tuple[str, int]] = {}
    for rows in data.values():
        for row in rows:
            families[f"{row['family']}|{row['label']}"] = (row["label"], 0)
    header = "| Family (label) | " + " | ".join(_DISPLAY.get(t, t) for t in tools) + " |"
    out(header)
    out("|---" * (len(tools) + 1) + "|")
    for fam_key in sorted(families, key=lambda k: (families[k][0], k)):
        family, label = fam_key.split("|")
        cells = []
        for tool in tools:
            rows = [r for r in data[tool] if r["family"] == family and r["label"] == label]
            hits = sum(r["status"] == "ok" and r["detected"] for r in rows)
            cells.append(f"{hits}/{len(rows)}")
        out(f"| {family} ({label}) | " + " | ".join(cells) + " |")
    out("")

    out("## Per-repository outcomes")
    out("")
    out("`**A**` detected with agent-tier evidence, `✓` detected, `·` nothing reported, `E` error.")
    out("")
    out("| Repository | Label | " + " | ".join(_DISPLAY.get(t, t) for t in tools) + " |")
    out("|---" * (len(tools) + 2) + "|")
    by_case: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    labels: dict[str, str] = {}
    for tool, rows in data.items():
        for row in rows:
            by_case[row["case"]][tool] = row
            labels[row["case"]] = row["label"]
    order = sorted(by_case, key=lambda c: ({"agent": 0, "llm": 1, "none": 2}[labels[c]], c))
    for case in order:
        cells = [_mark(by_case[case][tool]) if tool in by_case[case] else "–" for tool in tools]
        out(f"| {case} | {labels[case]} | " + " | ".join(cells) + " |")
    out("")

    paired = summary.get("paired", {})
    if paired:
        out("## Paired against ShadowScan (exact McNemar, repo surface)")
        out("")
        out("| Tool | n | ShadowScan right, tool wrong | Tool right, ShadowScan wrong | p |")
        out("|---|---|---|---|---|")
        for tool in tools:
            entry = paired.get(tool, {}).get("repo")
            if entry:
                out(
                    f"| {_DISPLAY.get(tool, tool)} | {entry['n']} "
                    f"| {entry['shadowscan_right_other_wrong']} "
                    f"| {entry['other_right_shadowscan_wrong']} | {entry['mcnemar_p']:.4f} |"
                )
        out("")

    errors = [
        (tool, row["case"], row["note"]) for tool in tools for row in data[tool] if row["status"] == "error"
    ]
    if errors:
        out("## Errors (counted as misses above)")
        out("")
        for tool, case, note in errors:
            out(f"- {_DISPLAY.get(tool, tool)} on `{case}`: {note[:200]}")
        out("")

    out("## Noise on repositories with no AI (`none` label)")
    out("")
    out("| Tool | Repos flagged | Median items reported on flagged `none` repos |")
    out("|---|---|---|")
    for tool in tools:
        none_rows = [r for r in data[tool] if r["label"] == "none" and r["status"] == "ok"]
        flagged = [r for r in none_rows if r["detected"]]
        items = sorted(r["items"] for r in flagged)
        median = items[len(items) // 2] if items else 0
        out(f"| {_DISPLAY.get(tool, tool)} | {len(flagged)}/{len(none_rows)} | {median} |")
    out("")
    overall = {tool: confusion([r for r in data[tool] if r["status"] != "n/a"]) for tool in tools}
    best = max(overall, key=lambda t: overall[t]["f1"])
    out(
        f"Highest F1 on this corpus: {_DISPLAY.get(best, best)} ({overall[best]['f1']:.2f}). "
        "See the caveats before treating that as a ranking."
    )
    out("")
    return "\n".join(lines)


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
