"""Before/after comparison of ShadowScan runs on the same corpus.

``python -m tools.benchmark.compare --before RESULTS --after RESULTS [--output FILE]``

``--before`` is the published run (``tools/benchmark/results``); ``--after``
holds ``shadowscan.jsonl`` (the same configuration on newer code) and,
optionally, ``shadowscan-dedicated.jsonl``. The baseline is also re-scored
from its stored raw reports with the after-run's agent rule (a caller or
contact whose ``metadata.agent_indicators`` is positive counts as agentic), so
a change in the agent rule is not credited to a change in code.

Both runs use the corpus written in this repository, and the changes were
made after reading the first run's misses: this is a regression check, not
independent or field evidence.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from tools.benchmark.adapters import AGENTIC_KINDS
from tools.benchmark.score import SURFACES, confusion, wilson


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def rescore_agentic(rows: list[dict[str, Any]], raw: Path) -> list[dict[str, Any]]:
    """Baseline rows with ``agentic`` recomputed from the stored reports by the metadata rule."""
    reports: dict[str, dict[str, Any]] = {}
    with gzip.open(raw, "rt", encoding="utf-8") as fh:
        for line in fh:
            entry = json.loads(line)
            text = entry.get("raw", {}).get("report.json")
            if text:
                reports[entry["case"]] = json.loads(text)
    out = []
    for row in rows:
        report = reports.get(row["case"])
        findings = report.get("findings", []) if report else []
        kinds = {f.get("kind") for f in findings}
        indicated = any((f.get("metadata") or {}).get("agent_indicators", 0) > 0 for f in findings)
        out.append({**row, "agentic": bool(kinds & AGENTIC_KINDS) or indicated} if report else row)
    return out


def _agentic_rate(rows: list[dict[str, Any]], label: str) -> tuple[int, int]:
    subset = [r for r in rows if r["label"] == label and r["status"] == "ok" and r["detected"]]
    total = sum(1 for r in rows if r["label"] == label)
    return sum(1 for r in subset if r["agentic"]), total


def _fmt(triple: tuple[float | None, float | None, float | None]) -> str:
    p, lo, hi = triple
    return "–" if p is None else f"{p:.2f} ({lo:.2f}–{hi:.2f})"


def render(variants: dict[str, list[dict[str, Any]]]) -> str:
    lines = [
        "| Variant | Surface | Recall | Specificity | F1 | Agent recall | LLM-only called agentic "
        "| Negatives called agentic | Errors |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, rows in variants.items():
        for surface in SURFACES:
            subset = [r for r in rows if r["surface"] == surface]
            if not subset:
                continue
            c = confusion(subset)
            agent_k, agent_n = _agentic_rate(subset, "agent")
            llm_k, llm_n = _agentic_rate(subset, "llm")
            none_k, none_n = _agentic_rate(subset, "none")
            lines.append(
                f"| {name} | {surface} | {_fmt(c['recall'])} | {_fmt(c['specificity'])} | {c['f1']:.2f} | "
                f"{_fmt(wilson(agent_k, agent_n))} | {llm_k}/{llm_n} | {none_k}/{none_n} | {c['errors']} |"
            )
    families: dict[str, dict[str, str]] = defaultdict(dict)
    labels: dict[str, str] = {}
    for name, rows in variants.items():
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            grouped[f"{r['surface']}:{r['family']}"].append(r)
            labels[f"{r['surface']}:{r['family']}"] = r["label"]
        for family, members in grouped.items():
            hits = sum(1 for r in members if r["status"] == "ok" and r["detected"])
            families[family][name] = f"{hits}/{len(members)}"
    changed = sorted(f for f, cells in families.items() if len(set(cells.values())) > 1)
    if changed:
        names = list(variants)
        lines += ["", "Families whose detection count differs between variants:", ""]
        lines.append("| Family | Label | " + " | ".join(names) + " |")
        lines.append("|---|---|" + "---|" * len(names))
        for family in changed:
            cells = " | ".join(families[family].get(n, "–") for n in names)
            lines.append(f"| {family} | {labels[family]} | {cells} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument(
        "--before-raw",
        type=Path,
        help="raw reports of the before run (default: BEFORE/raw/shadowscan.jsonl.gz)",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    baseline = _rows(args.before / "shadowscan.jsonl")
    after = _rows(args.after / "shadowscan.jsonl")
    before_raw = args.before_raw or args.before / "raw" / "shadowscan.jsonl.gz"
    after_raw = args.after / "raw" / "shadowscan.jsonl.gz"
    # Re-scoring needs the stored reports; a variant whose reports are absent is left out.
    variants = {"before (published)": baseline}
    if before_raw.exists():
        variants["before, agent rule re-scored"] = rescore_agentic(baseline, before_raw)
    variants["after, same configuration"] = after
    if after_raw.exists():
        variants["after, agent rule re-scored"] = rescore_agentic(after, after_raw)
    dedicated = args.after / "shadowscan-dedicated.jsonl"
    if dedicated.exists():
        variants["after, dedicated connectors"] = _rows(dedicated)
    text = render(variants)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
