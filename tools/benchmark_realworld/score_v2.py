"""Score the v2 real-world benchmark and write its report.

``python -m tools.benchmark_realworld.score_v2 --results tools/benchmark_realworld/results-v2
  --manifest tools/benchmark_realworld/corpus_v2.json --out tools/benchmark_realworld/REPORT-v2.md
  --json tools/benchmark_realworld/summary-v2.json``

Surfaces: ``repo`` (source tree) and ``endpoint`` (repository root read as $HOME).
Network, identity and cloud are not measured: no public real-world data exists.

A positive is a label of ``agent``, ``llm`` or ``client``. Ambiguous and ``n/a``
rows are left out.

An error is not a clean answer. It counts as wrong on both classes: a miss on a
positive, and a false alarm on a clean case, because an incomplete scan must never
clear a case (AGENTS.md: fail closed). Errors are also reported by category, and the
completed-scan view leaves them out, so both readings are visible.

Per surface: balanced accuracy and MCC, each with a stratified bootstrap interval
(positives and clean cases are resampled separately). Composite: mean balanced
accuracy over the surfaces a tool supports, undefined if any of them is undefined.
Estate: mean over both measured surfaces, where an unsupported surface counts as
chance (0.5).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import sys
import zlib
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tools.benchmark.score import mcnemar_exact, wilson
from tools.benchmark_realworld.adapters import ADAPTERS_V2
from tools.benchmark_realworld.cases import surfaces_of, validate_manifest
from tools.benchmark_realworld.run import ROOT, code_sha256
from tools.benchmark_realworld.score import load_rows, scored

SURFACES = ("repo", "endpoint")
SURFACE_TITLE = {
    "repo": "Repo surface (the source tree)",
    "endpoint": "Endpoint surface (repository root read as $HOME)",
}
STRATA = ("ai-app", "hard-negative", "ordinary", "dotfiles")
CHANCE = 0.5
BOOT = 2000
SEED = 20260901
# Commit 7e523ba (9fdaf85 after its sign-off rewrite) tuned the Rust and JSX lexer on the
# repositories added in v2. The frozen v2 run was recorded at fc3e998 (887142c after that rewrite,
# the same tree), before it. A run at any other commit, including every run of the merged code, does
# not treat those entries as held out.
PRE_LEXER_TUNING_COMMITS = frozenset(
    {"fc3e998cc4c37ba9b61a408b5e62571a303d8a36", "887142c651cc39c9fc8b971f7cbb72f14d5d33a7"}
)
ERROR_CATEGORIES = (
    ("incomplete", "incomplete"),
    ("not complete", "incomplete"),
    ("timeout", "timeout"),
    ("adapter exception", "exception"),
    ("not installed", "not installed"),
    ("exit ", "tool exit"),
    ("baseline", "baseline"),
)


def _truth(row: dict[str, Any]) -> bool:
    return bool(row["label"] != "none")


def predicted_positive(row: dict[str, Any]) -> bool:
    """Whether the tool reports AI for this case. An error counts as wrong on both classes."""
    if row["status"] == "error":
        return not _truth(row)
    return row["status"] == "ok" and bool(row["detected"])


def counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    c = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in rows:
        truth = _truth(row)
        predicted = predicted_positive(row)
        if truth:
            c["tp" if predicted else "fn"] += 1
        else:
            c["fp" if predicted else "tn"] += 1
    return c


def balanced_accuracy(c: dict[str, int]) -> float | None:
    pos = c["tp"] + c["fn"]
    neg = c["fp"] + c["tn"]
    if not pos or not neg:
        return None
    return (c["tp"] / pos + c["tn"] / neg) / 2


def mcc(c: dict[str, int]) -> float | None:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return None if denom == 0 else (tp * tn - fp * fn) / denom


def bootstrap(
    rows: list[dict[str, Any]], stat: Callable[[dict[str, int]], float | None], seed: int
) -> tuple[float | None, float | None]:
    """Stratified percentile interval: every resample holds both classes.

    A resample in which a statistic is undefined (for example MCC when a tool flags
    nothing) is skipped; if more than half are skipped the interval is undefined.
    """
    positives = [r for r in rows if _truth(r)]
    negatives = [r for r in rows if not _truth(r)]
    if not positives or not negatives:
        return None, None
    rng = random.Random(seed)
    values = []
    for _ in range(BOOT):
        sample = [positives[rng.randrange(len(positives))] for _ in positives]
        sample += [negatives[rng.randrange(len(negatives))] for _ in negatives]
        value = stat(counts(sample))
        if value is not None:
            values.append(value)
    if len(values) < BOOT // 2:
        return None, None
    values.sort()
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]


def _seed(tool: str, surface: str) -> int:
    return SEED + zlib.crc32(f"{tool}|{surface}".encode())


def cell(rows: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    """All metrics for one tool on one surface. ``rows`` are the scored rows."""
    c = counts(rows)
    pos = c["tp"] + c["fn"]
    neg = c["fp"] + c["tn"]
    flagged = c["tp"] + c["fp"]
    f1_den = 2 * c["tp"] + c["fp"] + c["fn"]
    completed = [r for r in rows if r["status"] == "ok"]
    return {
        "n": len(rows),
        **c,
        "positives": pos,
        "negatives": neg,
        "errors": sum(r["status"] == "error" for r in rows),
        "recall": wilson(c["tp"], pos),
        "specificity": wilson(c["tn"], neg),
        "precision": c["tp"] / flagged if flagged else None,
        "f1": 2 * c["tp"] / f1_den if f1_den else None,
        "balanced_accuracy": balanced_accuracy(c),
        "balanced_accuracy_ci": bootstrap(rows, balanced_accuracy, seed),
        "mcc": mcc(c),
        "mcc_ci": bootstrap(rows, mcc, seed + 1),
        # Sensitivities: errors left out of both classes, and no hard-negative stratum.
        "balanced_accuracy_completed": balanced_accuracy(counts(completed)),
        "balanced_accuracy_no_hard_negatives": balanced_accuracy(
            counts([r for r in rows if r["family"] != "hard-negative"])
        ),
    }


def error_categories(rows: list[dict[str, Any]]) -> dict[str, int]:
    found: Counter[str] = Counter()
    for row in rows:
        if row["status"] != "error":
            continue
        note = row.get("note", "")
        label = next((cat for needle, cat in ERROR_CATEGORIES if needle in note), "other")
        found[label] += 1
    return dict(found)


def paired_v2(
    rows_by_tool: dict[str, list[dict[str, Any]]], surface: str, reference: str = "shadowscan"
) -> dict[str, Any]:
    """Exact McNemar tests against the reference, on the cases both tools support."""
    ref = {r["case"]: r for r in scored(rows_by_tool.get(reference, []), surface)}
    out: dict[str, Any] = {}
    for tool, rows in rows_by_tool.items():
        if tool == reference:
            continue
        ref_only = tool_only = n = 0
        for r in scored(rows, surface):
            o = ref.get(r["case"])
            if o is None:
                continue
            truth = _truth(r)
            tool_right = predicted_positive(r) == truth
            ref_right = predicted_positive(o) == truth
            n += 1
            ref_only += ref_right and not tool_right
            tool_only += tool_right and not ref_right
        if n:
            out[tool] = {
                "n": n,
                "reference_only_right": ref_only,
                "tool_only_right": tool_only,
                "mcnemar_p": mcnemar_exact(ref_only, tool_only),
            }
    return out


def summarize(rows_by_tool: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"surfaces": {}, "composite": {}, "estate": {}, "paired": {}}
    for surface in SURFACES:
        summary["surfaces"][surface] = {}
        summary["paired"][surface] = paired_v2(rows_by_tool, surface)
        for tool, rows in rows_by_tool.items():
            supported = any(r["surface"] == surface and r["status"] != "n/a" for r in rows)
            entry: dict[str, Any] = {"supported": supported}
            if supported:
                mine = scored(rows, surface)
                entry["cell"] = cell(mine, _seed(tool, surface))
                entry["errors_by_category"] = error_categories(mine)
                entry["strata"] = {
                    stratum: {
                        "positives": sum(r["family"] == stratum and _truth(r) for r in mine),
                        "detected_positives": sum(
                            r["family"] == stratum and _truth(r) and predicted_positive(r) for r in mine
                        ),
                        "negatives": sum(r["family"] == stratum and not _truth(r) for r in mine),
                        "false_positives": sum(
                            r["family"] == stratum and not _truth(r) and predicted_positive(r) for r in mine
                        ),
                    }
                    for stratum in STRATA
                }
            summary["surfaces"][surface][tool] = entry
    for tool in rows_by_tool:
        measured = [s for s in SURFACES if summary["surfaces"][s][tool]["supported"]]
        values = [summary["surfaces"][s][tool]["cell"]["balanced_accuracy"] for s in measured]
        undefined = [s for s, v in zip(measured, values, strict=True) if v is None]
        summary["composite"][tool] = {
            "surfaces": measured,
            "undefined_on": undefined,
            "value": None if undefined or not values else sum(values) / len(values),
        }
        estate_values: list[float | None] = []
        for s in SURFACES:
            entry = summary["surfaces"][s][tool]
            estate_values.append(entry["cell"]["balanced_accuracy"] if entry["supported"] else CHANCE)
        known = [v for v in estate_values if v is not None]
        summary["estate"][tool] = sum(known) / len(known) if len(known) == len(estate_values) else None
    return summary


def coverage_problems(rows_by_tool: dict[str, list[dict[str, Any]]], doc: dict[str, Any]) -> list[str]:
    """Every configuration needs one row per manifest case on each surface it is run on."""
    expected_metadata: dict[str, dict[str, Any]] = {}
    for entry in validate_manifest(doc):
        for surface in surfaces_of(entry):
            case_id = f"{entry['id']}:{'repo' if surface == 'repo' else 'home'}"
            metadata = {
                "surface": "repo" if surface == "repo" else "endpoint",
                "family": entry["stratum"],
            }
            if surface == "repo":
                metadata["label"] = entry["label"]
            expected_metadata[case_id] = metadata
    expected = set(expected_metadata)
    endpoint_labels: dict[str, str] = {}
    problems = []
    names = {adapter.name for adapter in ADAPTERS_V2}
    for adapter in ADAPTERS_V2:
        rows = rows_by_tool.get(adapter.name)
        if rows is None:
            problems.append(f"no results file for {adapter.name}")
            continue
        seen = {r["case"] for r in rows}
        if expected - seen:
            problems.append(f"{adapter.name}: {len(expected - seen)} cases missing")
        if seen - expected:
            problems.append(f"{adapter.name}: {len(seen - expected)} rows match no manifest case")
        repeated = [case for case, n in Counter(r["case"] for r in rows).items() if n > 1]
        if repeated:
            problems.append(f"{adapter.name}: {len(repeated)} cases have more than one row")
        for row in rows:
            case_id = row["case"]
            row_metadata = expected_metadata.get(case_id)
            if row_metadata is None:
                continue
            for key, value in row_metadata.items():
                if row.get(key) != value:
                    problems.append(f"{adapter.name}: {case_id} {key} differs from the manifest")
            if row_metadata["surface"] == "endpoint":
                label = row.get("label")
                if label not in ("client", "none"):
                    problems.append(f"{adapter.name}: {case_id} has an invalid endpoint label")
                elif case_id in endpoint_labels and endpoint_labels[case_id] != label:
                    problems.append(f"{adapter.name}: {case_id} endpoint label differs between tools")
                else:
                    endpoint_labels[case_id] = label
            if row.get("status") not in ("ok", "error", "n/a"):
                problems.append(f"{adapter.name}: {case_id} has an invalid status")
            if not isinstance(row.get("detected"), bool):
                problems.append(f"{adapter.name}: {case_id} detected must be a boolean")
        supported = set(adapter.surfaces)
        if any(r["status"] == "n/a" and r["surface"] in supported for r in rows):
            problems.append(f"{adapter.name}: a row is n/a on a surface the configuration runs")
        if any(r["status"] != "n/a" and r["surface"] not in supported for r in rows):
            problems.append(f"{adapter.name}: a row on an unsupported surface is not n/a")
    for name in rows_by_tool:
        if name not in names:
            problems.append(f"results file {name} matches no configuration of this protocol")
    return problems


# A serial re-run (section 8) covers every timeout and every incomplete scan. Notes come from the
# adapters: a timeout is "exit 124", an incomplete scan says "incomplete" or "not complete".
RERUN_NOTE = re.compile(r"timeout|incomplete|not complete|exit 124")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_file(path: Path) -> dict[str, Any] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _provenance_problems(run: dict[str, Any] | None, manifest: Path, protocol: Path) -> list[str]:
    """A run must have used the manifest, protocol and code that are on disk now."""
    if run is None:
        return ["no run manifest in the results directory"]
    current = {
        "manifest_version": 2,
        "manifest_sha256": _sha256(manifest),
        "protocol_sha256": _sha256(protocol),
        "code_sha256": code_sha256(ROOT),
    }
    return [
        f"run manifest {key} does not match the file on disk"
        for key, value in current.items()
        if run.get(key) != value
    ]


def provenance_problems(
    run: dict[str, Any] | None, rows_by_tool: dict[str, list[dict[str, Any]]], manifest: Path, protocol: Path
) -> list[str]:
    """The run manifest must match the files on disk, and each tool's summary its own rows."""
    problems = _provenance_problems(run, manifest, protocol)
    if run is None:
        return problems
    summaries = {r["tool"]: r for r in run.get("runs", [])}
    for adapter in ADAPTERS_V2:
        summary = summaries.get(adapter.name)
        if summary is None:
            problems.append(f"{adapter.name}: no run summary")
            continue
        counts = Counter(r["status"] for r in rows_by_tool.get(adapter.name, []))
        for status in ("ok", "error", "n/a"):
            if summary.get(status) != counts.get(status, 0):
                problems.append(f"{adapter.name}: summary {status} count differs from its rows")
    return problems


def rerun_plan(rows_by_tool: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    """Per configuration, the cases to re-run serially: its timeouts and its incomplete scans."""
    return {
        tool: sorted(r["case"] for r in rows if r["status"] == "error" and RERUN_NOTE.search(r["note"]))
        for tool, rows in rows_by_tool.items()
    }


def write_rerun(plan: dict[str, list[str]], directory: Path) -> None:
    """One case file per configuration with a non-empty plan, and the plan itself."""
    directory.mkdir(parents=True, exist_ok=True)
    for tool, cases in plan.items():
        if cases:
            (directory / f"cases-{tool}.txt").write_text("\n".join(cases) + "\n", encoding="utf-8")
    (directory / "rerun-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")


def rerun_problems(
    rerun: Path,
    plan: dict[str, list[str]],
    run: dict[str, Any] | None,
    manifest: Path,
    protocol: Path,
) -> list[str]:
    """The serial re-run must use exactly the planned cases, with the manifest, protocol and code on disk."""
    problems = _provenance_problems(run, manifest, protocol)
    if run is None:
        return problems
    redo = load_rows(rerun)
    summaries = {r["tool"]: r for r in run.get("runs", [])}
    for tool, cases in plan.items():
        if not cases:
            continue
        case_file = rerun / f"cases-{tool}.txt"
        if not case_file.exists() or sorted(case_file.read_text(encoding="utf-8").split()) != cases:
            problems.append(f"{tool}: its case file does not match the plan")
            continue
        if {r["case"] for r in redo.get(tool, [])} != set(cases):
            problems.append(f"{tool}: the re-run rows do not match the plan")
        summary = summaries.get(tool)
        if summary is None or summary.get("only_cases_sha256") != _sha256(case_file):
            problems.append(f"{tool}: the re-run summary does not record its case file")
    return problems


def corpus_counts(rows_by_tool: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Case counts per surface, taken from the first tool's rows (every tool sees the same cases)."""
    first = next(iter(rows_by_tool.values()))
    out: dict[str, Any] = {}
    for surface in SURFACES:
        mine = [r for r in first if r["surface"] == surface]
        out[surface] = {
            "cases": len(mine),
            "labels": dict(Counter(r["label"] for r in mine)),
            "strata": dict(Counter(r["family"] for r in mine)),
            "scored": len(scored(first, surface)),
        }
    return out


def tree_diagnostic(v1_results: Path | None) -> dict[str, Any] | None:
    """v1 whole-tree home rows of the three path-scanning tools: a diagnostic, not endpoint evidence."""
    if v1_results is None or not (v1_results / "shadowscan.jsonl").exists():
        return None
    v1 = load_rows(v1_results)
    out: dict[str, Any] = {}
    for tool in ("shadowscan", "cisco-aibom", "agentdiscover"):
        rows = scored(v1.get(tool, []), "endpoint")
        out[tool] = cell(rows, _seed(tool, "tree-diagnostic")) if rows else None
    return out


def determinism_check(v1_results: Path | None) -> dict[str, Any] | None:
    """v1 repo rows of ShadowScan published vs dedicated: same code path, so they should match."""
    if v1_results is None or not (v1_results / "shadowscan.jsonl").exists():
        return None
    v1 = load_rows(v1_results)
    a = {r["case"]: r for r in v1["shadowscan"] if r["surface"] == "repo"}
    b = {r["case"]: r for r in v1["shadowscan-dedicated"] if r["surface"] == "repo"}
    differences = []
    for case in sorted(a):
        ra, rb = a[case], b[case]
        if (ra["status"], ra["detected"], ra["items"]) != (rb["status"], rb["detected"], rb["items"]):
            differences.append(
                {
                    "case": case,
                    "published": f"{ra['status']}/{ra['detected']}/{ra['items']}",
                    "dedicated": f"{rb['status']}/{rb['detected']}/{rb['items']}",
                    "published_note": ra["note"],
                    "dedicated_note": rb["note"],
                }
            )
    return {"repo_cases": len(a), "differences": differences}


def sensitivity_rerun(
    rows_by_tool: dict[str, list[dict[str, Any]]], rerun: Path | None
) -> dict[str, Any] | None:
    """Serial re-run of the load-sensitive cases of every configuration, merged over the primary rows."""
    if rerun is None or not rerun.exists():
        return None
    redo_by_tool = load_rows(rerun)
    out: dict[str, Any] = {"tools": {}}
    total = 0
    for tool, primary in rows_by_tool.items():
        redo = {r["case"]: r for r in redo_by_tool.get(tool, [])}
        if not redo:
            continue
        total += len(redo)
        merged = [redo.get(r["case"], r) for r in primary]
        flips = [
            {
                "case": r["case"],
                "before": r["status"] + " " + r["note"][:60],
                "after": redo[r["case"]]["status"],
            }
            for r in primary
            if r["case"] in redo and r["status"] != redo[r["case"]]["status"]
        ]
        cells = {}
        for surface in SURFACES:
            mine = scored(merged, surface)
            if mine:
                cells[surface] = cell(mine, _seed(tool, f"serial-{surface}"))
        out["tools"][tool] = {"status_changed": flips, "cells": cells}
    out["cases_rerun"] = total
    return out


def _f(x: float | None, digits: int = 2) -> str:
    return "n/a" if x is None else f"{x:.{digits}f}"


def _ci(pair: tuple[float | None, float | None] | list[float | None] | None) -> str:
    if not pair or pair[0] is None or pair[1] is None:
        return "n/a"
    return f"[{pair[0]:.2f}–{pair[1]:.2f}]"


def _val(value: float | None, pair: tuple[float | None, float | None] | list[float | None] | None) -> str:
    interval = _ci(pair)
    return _f(value) if interval == "n/a" else f"{_f(value)} {interval}"


def _wilson(t: tuple[float | None, float | None, float | None]) -> str:
    p, lo, hi = t
    return "n/a" if p is None or lo is None or hi is None else f"{p:.2f} [{lo:.2f}–{hi:.2f}]"


def render(summary: dict[str, Any], corpus: dict[str, Any], extras: dict[str, Any]) -> str:
    out: list[str] = [
        "# Real-world shadow-AI discovery benchmark, v2",
        "",
        "Generated by `tools/benchmark_realworld/score_v2.py`. Results describe these repositories at "
        "these pinned commits. They are not production precision or recall, and the labels are from "
        "model-based labelers, not from human review.",
        "",
        "## Corpus",
        "",
        "| Surface | Cases | Labels | Strata | Scored |",
        "|---|---:|---|---|---:|",
    ]
    for surface in SURFACES:
        c = corpus[surface]
        labels = ", ".join(f"{k} {v}" for k, v in sorted(c["labels"].items()))
        strata = ", ".join(f"{k} {v}" for k, v in sorted(c["strata"].items()))
        out.append(f"| {SURFACE_TITLE[surface]} | {c['cases']} | {labels} | {strata} | {c['scored']} |")

    out += [
        "",
        "## Composite and estate",
        "",
        "Composite: mean balanced accuracy over the surfaces a tool supports; undefined if any of them is "
        "undefined. Estate: mean over both measured surfaces, with an unsupported surface at chance (0.5).",
        "",
        "| Tool | Supported surfaces | Composite | Estate |",
        "|---|---|---:|---:|",
    ]
    for tool, comp in summary["composite"].items():
        supported = ", ".join(comp["surfaces"]) or "none"
        out.append(f"| {tool} | {supported} | {_f(comp['value'])} | {_f(summary['estate'][tool])} |")

    for surface in SURFACES:
        out += [
            "",
            f"## {SURFACE_TITLE[surface]}",
            "",
            "| Tool | Scored | Pos | Neg | TP | FP | FN | TN | Errors | Recall (95% CI) | "
            "Specificity (95% CI) | Balanced acc. [95% CI] | MCC [95% CI] | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|---:|",
        ]
        for tool, entry in summary["surfaces"][surface].items():
            if not entry["supported"]:
                out.append(f"| {tool} | not run on this surface | | | | | | | | | | | | |")
                continue
            c = entry["cell"]
            out.append(
                f"| {tool} | {c['n']} | {c['positives']} | {c['negatives']} | {c['tp']} | {c['fp']} | "
                f"{c['fn']} | {c['tn']} | {c['errors']} | {_wilson(c['recall'])} | "
                f"{_wilson(c['specificity'])} | {_val(c['balanced_accuracy'], c['balanced_accuracy_ci'])} | "
                f"{_val(c['mcc'], c['mcc_ci'])} | {_f(c['f1'])} |"
            )

    out += ["", "## Paired comparison with ShadowScan (published), McNemar", ""]
    for surface in SURFACES:
        out += [
            f"**{SURFACE_TITLE[surface]}**",
            "",
            "| Tool | n | Only ShadowScan right | Only tool right | Exact p |",
            "|---|---:|---:|---:|---:|",
        ]
        for tool, p in summary["paired"][surface].items():
            out.append(
                f"| {tool} | {p['n']} | {p['reference_only_right']} | {p['tool_only_right']} | "
                f"{_f(p['mcnemar_p'], 3)} |"
            )
        out.append("")

    out += [
        "## Sensitivity: completed scans only, without hard negatives, and error categories",
        "",
        "| Surface | Tool | BA, completed scans only | BA without hard negatives | Errors by category |",
        "|---|---|---:|---:|---|",
    ]
    for surface in SURFACES:
        for tool, entry in summary["surfaces"][surface].items():
            if not entry["supported"]:
                continue
            c = entry["cell"]
            cats = ", ".join(f"{k} {v}" for k, v in sorted(entry["errors_by_category"].items())) or "none"
            out.append(
                f"| {surface} | {tool} | {_f(c['balanced_accuracy_completed'])} | "
                f"{_f(c['balanced_accuracy_no_hard_negatives'])} | {cats} |"
            )

    out += ["", "## Strata (detected positives; false alarms)", ""]
    for surface in SURFACES:
        out += [
            f"**{SURFACE_TITLE[surface]}**",
            "",
            "| Tool | ai-app | hard-negative | ordinary | dotfiles |",
            "|---|---|---|---|---|",
        ]
        for tool, entry in summary["surfaces"][surface].items():
            if not entry["supported"]:
                continue
            s = entry["strata"]
            cells = []
            for k in ("ai-app", "hard-negative", "ordinary", "dotfiles"):
                hit = s[k]
                found = f"{hit['detected_positives']}/{hit['positives']}"
                wrong = f"{hit['false_positives']}/{hit['negatives']}"
                cells.append(f"{found}; {wrong}")
            out.append(f"| {tool} | " + " | ".join(cells) + " |")
        out.append("")

    held = summary.get("held_out")
    if held:
        if held.get("predates_lexer_tuning"):
            out += [
                "",
                "## Held-out view (no connector or rule was designed on these entries)",
                "",
                "The 43 repositories and 40 dotfiles repositories added in v2. Both groups were fixed before "
                "they were attached, and neither was used to design a connector or a rule.",
                "",
            ]
        else:
            out += [
                "",
                "## Entries added in v2 (not held out for runs after the lexer was tuned on them)",
                "",
                "The 43 repositories and 40 dotfiles repositories added in v2. The Rust and JSX lexer was "
                "tuned on these repositories (commit 7e523ba, 9fdaf85 after its sign-off rewrite). This run "
                "was not recorded at the commit of the frozen v2 run, which predates that tuning, so these "
                "entries are not held-out evidence for this run.",
                "",
            ]
        for surface, label in (
            ("repo", "New repositories (repo surface)"),
            ("endpoint", "New dotfiles (endpoint surface)"),
        ):
            out += [
                f"**{label}**",
                "",
                "| Tool | Scored | Pos | Neg | Errors | Balanced acc. [95% CI] | MCC [95% CI] |",
                "|---|---:|---:|---:|---:|---|---|",
            ]
            for tool, c in held[surface].items():
                if c is None:
                    continue
                out.append(
                    f"| {tool} | {c['n']} | {c['positives']} | {c['negatives']} | {c['errors']} | "
                    f"{_val(c['balanced_accuracy'], c['balanced_accuracy_ci'])} | "
                    f"{_val(c['mcc'], c['mcc_ci'])} |"
                )
            out.append("")

    tree = extras.get("tree_diagnostic")
    if tree is not None:
        out += [
            "## Diagnostic: whole-tree home rows of v1 (not endpoint evidence)",
            "",
            "These three configurations scan the copied tree as a path. Their v1 home rows measure "
            "repository files, so they are reported here and not in the endpoint surface.",
            "",
        ]
        for tool, c in tree.items():
            if c is not None:
                out.append(
                    f"- {tool}: {c['n']} rows, BA {_f(c['balanced_accuracy'])}, FP {c['fp']}, "
                    f"errors {c['errors']} (counted as wrong answers, section 7)"
                )
        out.append("")

    det = extras.get("determinism")
    if det is not None:
        out += [
            "## Determinism check: ShadowScan published vs dedicated, v1 repo rows",
            "",
            f"{det['repo_cases']} repository cases. Both configurations run the same code path on the repo "
            f"surface, so any difference is run-to-run variation. Differences: {len(det['differences'])}.",
            "",
        ]
        for d in det["differences"]:
            out.append(
                f"- `{d['case']}`: published {d['published']} ({d['published_note'][:80]}); "
                f"dedicated {d['dedicated']} ({d['dedicated_note'][:80]})"
            )
        out.append("")

    sens = extras.get("sensitivity")
    if sens is not None:
        out += [
            "## Serial re-run of load-sensitive cases (every configuration)",
            "",
            f"{sens['cases_rerun']} cases were re-run with one worker and no other tool running. "
            "The cases are the v2 errors whose category is timeout or incomplete scan.",
            "",
        ]
        for tool, t in sens["tools"].items():
            out.append(f"- {tool}: status changed on {len(t['status_changed'])} case(s)")
            for flip in t["status_changed"][:20]:
                out.append(f"  - `{flip['case']}`: {flip['before']} -> {flip['after']}")
        out.append("")

    label_block = extras.get("labels")
    if label_block is not None:
        out += ["## Labelling", "", label_block["text"], ""]

    out += [
        "## Limits",
        "",
        "- Two surfaces are measured. Network, identity, SaaS and cloud are not (no public real-world data).",
        "- Labels are model-based and blinded, not human. Agreement is reported above. This is not "
        "independent human review.",
        "- The conflict-of-interest audit and its residual risk are in `PROTOCOL-v2.md`, section 10.",
        "- Endpoint positives are few. Intervals on balanced accuracy and MCC are wide.",
        "",
    ]
    return "\n".join(out) + "\n"


def held_out(
    rows_by_tool: dict[str, list[dict[str, Any]]], doc: dict[str, Any], run: dict[str, Any] | None
) -> dict[str, Any]:
    """The view on the 43 repositories and the 40 dotfiles repositories added in v2. Both groups were
    fixed before they were attached. They are held out only for a run recorded before the lexer was
    tuned on them (``PRE_LEXER_TUNING_COMMITS``); an unknown commit is not held out."""
    added_repo = {e["id"] for e in doc["repos"] if "category" in e}
    added_endpoint = {e["id"] for e in doc["repos"] if "design" in e}
    commit = run.get("shadowscan_commit") if run is not None else None
    out: dict[str, Any] = {
        "repo": {},
        "endpoint": {},
        "predates_lexer_tuning": commit in PRE_LEXER_TUNING_COMMITS,
    }
    for surface, ids in (("repo", added_repo), ("endpoint", added_endpoint)):
        for tool, rows in rows_by_tool.items():
            mine = [r for r in scored(rows, surface) if r["case"].split(":")[0] in ids]
            out[surface][tool] = cell(mine, _seed(tool, f"held-{surface}")) if mine else None
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--v1-results", type=Path, default=None)
    parser.add_argument("--sensitivity", type=Path, default=None)
    parser.add_argument("--labels-report", type=Path, default=None, help="text block from build_manifest_v2")
    parser.add_argument("--protocol", type=Path, required=True, help="PROTOCOL-v2.md, hashed against the run")
    parser.add_argument(
        "--write-rerun", type=Path, default=None, help="write the serial re-run case lists here"
    )
    args = parser.parse_args(argv)

    doc = json.loads(args.manifest.read_text(encoding="utf-8"))
    rows_by_tool = load_rows(args.results)
    problems = coverage_problems(rows_by_tool, doc) if rows_by_tool else ["no results"]
    run = _json_file(args.results / "run-manifest.json")
    problems += provenance_problems(run, rows_by_tool, args.manifest, args.protocol)
    plan = rerun_plan(rows_by_tool)
    if args.sensitivity is not None:
        redo = _json_file(args.sensitivity / "run-subset-manifest.json")
        problems += rerun_problems(args.sensitivity, plan, redo, args.manifest, args.protocol)
    if problems:
        print("scoring stopped (fail closed):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    if args.write_rerun is not None:
        write_rerun(plan, args.write_rerun)

    summary = summarize(rows_by_tool)
    summary["held_out"] = held_out(rows_by_tool, doc, run)
    corpus = corpus_counts(rows_by_tool)
    extras: dict[str, Any] = {
        "tree_diagnostic": tree_diagnostic(args.v1_results),
        "determinism": determinism_check(args.v1_results),
        "sensitivity": sensitivity_rerun(rows_by_tool, args.sensitivity),
        "labels": {"text": args.labels_report.read_text(encoding="utf-8")} if args.labels_report else None,
        "rerun_plan": {tool: len(cases) for tool, cases in plan.items()},
    }
    summary["extras"] = extras
    summary["manifest"] = {"entries": len(doc.get("repos", [])), "version": doc.get("version")}
    args.json.write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    args.out.write_text(render(summary, corpus, extras), encoding="utf-8")
    print(f"wrote {args.out} and {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
