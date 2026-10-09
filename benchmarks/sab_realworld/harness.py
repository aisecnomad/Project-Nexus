"""Run ShadowScan against the real-world corpus and produce scored results.

Usage:
    python -m benchmarks.sab_realworld [--output DIR]

Materializes each case to a temporary directory, runs the FilesystemConnector,
and compares findings against expected labels. Produces JSONL results and a
Markdown report.

Surface-balanced scoring:
    Many discovery tools only support a subset of scanning surfaces (repo,
    endpoint, network). The harness reports per-surface metrics so that tools
    are scored on the surfaces they actually cover, not penalized for surfaces
    they never claimed to support. The "best-surface F1" metric reports the
    highest F1 across supported surfaces, and the "surface-normalized score"
    is a weighted average across all surfaces, each weighted by number of
    cases.

This harness is author-written and cannot establish independent precision or
recall.  It complements the synthetic benchmark with structurally realistic
patterns but shares the same conflict of interest.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import random
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import Kind
from shadowscan.signatures import get_index

from benchmarks.sab_realworld.corpus import CASES, CORPUS_METADATA, RealWorldCase

Z95 = 1.959963984540054


def wilson(k: int, n: int) -> tuple[float | None, float | None, float | None]:
    if n == 0:
        return None, None, None
    p = k / n
    denom = 1 + Z95**2 / n
    centre = (p + Z95**2 / (2 * n)) / denom
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95**2 / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def bootstrap_f1(
    rows: list[dict[str, Any]], reps: int = 2000, seed: int = 42
) -> tuple[float, float]:
    rng = random.Random(seed)
    vals = []
    for _ in range(reps):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        c = confusion(sample)
        vals.append(c["f1"])
    vals.sort()
    return vals[int(0.025 * reps)], vals[int(0.975 * reps) - 1]


def confusion(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for r in rows:
        pos = r["label"] != "none"
        hit = r["detected"]
        if pos and hit:
            tp += 1
        elif pos and not hit:
            fn += 1
        elif not pos and hit:
            fp += 1
        else:
            tn += 1
    recall = wilson(tp, tp + fn)
    specificity = wilson(tn, tn + fp)
    precision = wilson(tp, tp + fp)
    f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else 0.0
    return {
        "n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": recall, "specificity": specificity, "precision": precision,
        "f1": round(f1, 4), "mcc": round(mcc, 4),
    }


def _materialize(case: RealWorldCase, root: Path) -> None:
    for rel_path, content in case.files.items():
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _scan(case: RealWorldCase, root: Path, index: Any) -> dict[str, Any]:
    ctx = ConnectorContext(
        config={
            "path": str(root),
            "label": f"rw-bench:{case.id}",
            "use_git": False,
            "scan_secrets": True,
            "default_excludes": False,
        },
        index=index,
    )
    started = time.perf_counter()
    findings = FilesystemConnector(ctx).run()
    elapsed = time.perf_counter() - started
    detected = len(findings) > 0
    agentic = any(
        f.kind.value in {"agent", "mcp-server", "agent-config", "bot-app", "workflow"}
        for f in findings
    )
    items = [
        {
            "kind": f.kind.value,
            "signatures": sorted(set(f.frameworks + f.model_providers)),
            "capabilities": sorted(set(f.capabilities)),
            "confidence": f.confidence,
        }
        for f in findings
    ]
    return {
        "detected": detected,
        "agentic": agentic,
        "items": items,
        "seconds": round(elapsed, 4),
        "finding_count": len(findings),
    }


# Corpus labels name packages or products ("crewai", "langchain-openai") while
# findings carry signature IDs ("framework.crewai", "provider.openai"). These
# labels name a product that no signature ID or dependency name spells out.
_LABEL_ALIASES: dict[str, tuple[str, ...]] = {
    "bedrock": ("provider.aws-bedrock",),
    "bedrock-agents": ("cloud.aws-bedrock-agents",),
    "codeium": ("coding-agent.windsurf",),
    "coderabbit": ("coding-agent.pr-review-bots",),
    "cody": ("coding-agent.sourcegraph-cody",),
    "go-openai": ("provider.openai",),
    "jetbrains-ai": ("coding-agent.jetbrains-junie",),
    "openai-kotlin": ("provider.openai",),
    "openai-php": ("provider.openai",),
    "vertex-ai": ("provider.google-vertex-ai",),
}


def label_signatures(label: str, index: Any) -> frozenset[str]:
    """Signature IDs that satisfy an expected label.

    A signature satisfies a label when its ID names it (``crewai`` and
    ``framework.crewai``), when one of its dependency signals declares that
    package (``langchain-openai`` and ``provider.openai``), or through
    ``_LABEL_ALIASES``. A label nothing satisfies always counts as missed.
    """
    ids = set(_LABEL_ALIASES.get(label, ()))
    for sig in index.signatures.values():
        if sig.id.split(".", 1)[-1] == label or any(
            signal.type == "dependency" and label in signal.names for signal in sig.signals
        ):
            ids.add(sig.id)
    return frozenset(ids)


def _check_expectations(
    case: RealWorldCase, scan_result: dict[str, Any], index: Any
) -> dict[str, Any]:
    all_sigs = set()
    for item in scan_result["items"]:
        all_sigs.update(item["signatures"])
    expected_hit = set(case.expected_signatures)
    found_expected = {label for label in expected_hit if label_signatures(label, index) & all_sigs}
    missed_expected = expected_hit - found_expected

    correct_detection = (
        (case.label != "none" and scan_result["detected"])
        or (case.label == "none" and not scan_result["detected"])
    )
    correct_agent_tier = True
    if case.label == "agent" and scan_result["detected"]:
        correct_agent_tier = scan_result["agentic"]
    elif case.label == "llm" and scan_result["detected"]:
        correct_agent_tier = not scan_result["agentic"]

    return {
        "correct_detection": correct_detection,
        "correct_agent_tier": correct_agent_tier,
        "found_expected_signatures": sorted(found_expected),
        "missed_expected_signatures": sorted(missed_expected),
        "signature_recall": (
            len(found_expected) / len(expected_hit) if expected_hit else None
        ),
    }


def run_benchmark(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    index = get_index()
    results: list[dict[str, Any]] = []
    errors: list[str] = []

    for case in CASES:
        work_dir = Path(tempfile.mkdtemp(prefix=f"rw-{case.id}-"))
        try:
            _materialize(case, work_dir)
            scan_result = _scan(case, work_dir, index)
            checks = _check_expectations(case, scan_result, index)
            row = {
                "case_id": case.id,
                "category": case.category,
                "family": case.family,
                "label": case.label,
                "difficulty": case.difficulty,
                "surface": case.surface,
                "detected": scan_result["detected"],
                "agentic": scan_result["agentic"],
                "finding_count": scan_result["finding_count"],
                "seconds": scan_result["seconds"],
                "items": scan_result["items"],
                "correct_detection": checks["correct_detection"],
                "correct_agent_tier": checks["correct_agent_tier"],
                "found_expected_signatures": checks["found_expected_signatures"],
                "missed_expected_signatures": checks["missed_expected_signatures"],
                "signature_recall": checks["signature_recall"],
                "status": "ok",
            }
            results.append(row)
        except Exception as exc:
            errors.append(f"{case.id}: {type(exc).__name__}: {exc}")
            results.append({
                "case_id": case.id,
                "category": case.category,
                "family": case.family,
                "label": case.label,
                "difficulty": case.difficulty,
                "surface": case.surface,
                "detected": False,
                "agentic": False,
                "finding_count": 0,
                "seconds": 0.0,
                "items": [],
                "correct_detection": False,
                "correct_agent_tier": False,
                "found_expected_signatures": [],
                "missed_expected_signatures": case.expected_signatures,
                "signature_recall": 0.0,
                "status": "error",
                "error": str(exc)[:300],
            })
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    jsonl_path = output_dir / "results.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as fh:
        for row in results:
            fh.write(json.dumps(row) + "\n")

    manifest = {
        "benchmark": "sab-realworld",
        "version": CORPUS_METADATA["version"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "shadowscan",
        "tool_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "corpus_metadata": CORPUS_METADATA,
        "case_count": len(CASES),
        "errors": errors,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    summary = _build_summary(results)
    report = render_report(summary, manifest)
    (output_dir / "REPORT.md").write_text(report, encoding="utf-8")

    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def _build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    ok_rows = [r for r in results if r["status"] == "ok"]

    overall = confusion(ok_rows)
    overall["f1_ci"] = bootstrap_f1(ok_rows)

    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in ok_rows:
        by_category[r["category"]].append(r)
    category_metrics = {
        cat: confusion(rows) for cat, rows in sorted(by_category.items())
    }

    by_label: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in ok_rows:
        by_label[r["label"]]["total"] += 1
        if r["correct_detection"]:
            by_label[r["label"]]["correct"] += 1

    by_difficulty: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in ok_rows:
        by_difficulty[r["difficulty"]]["total"] += 1
        if r["correct_detection"]:
            by_difficulty[r["difficulty"]]["correct"] += 1

    # --- Surface-balanced metrics ---
    by_surface: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in ok_rows:
        by_surface[r["surface"]].append(r)
    surface_metrics = {
        s: confusion(rows) for s, rows in sorted(by_surface.items())
    }

    best_surface_f1 = max(
        (m["f1"] for m in surface_metrics.values()), default=0.0
    )
    best_surface_name = max(
        surface_metrics, key=lambda s: surface_metrics[s]["f1"], default=""
    )

    total_surface_cases = sum(m["n"] for m in surface_metrics.values())
    surface_normalized = (
        sum(m["f1"] * m["n"] for m in surface_metrics.values()) / total_surface_cases
        if total_surface_cases else 0.0
    )

    by_family: dict[str, dict[str, Any]] = {}
    for r in ok_rows:
        key = f"{r['category']}|{r['family']}"
        if key not in by_family:
            by_family[key] = {
                "label": r["label"],
                "surface": r["surface"],
                "detected": r["detected"],
                "correct": r["correct_detection"],
                "agent_tier_correct": r["correct_agent_tier"],
                "signature_recall": r["signature_recall"],
            }

    agent_tier_rows = [r for r in ok_rows if r["label"] == "agent" and r["detected"]]
    agent_tier_accuracy = (
        sum(r["correct_agent_tier"] for r in agent_tier_rows) / len(agent_tier_rows)
        if agent_tier_rows else None
    )

    sig_recalls = [r["signature_recall"] for r in ok_rows if r["signature_recall"] is not None]
    mean_sig_recall = sum(sig_recalls) / len(sig_recalls) if sig_recalls else None

    false_positives = [r for r in ok_rows if r["label"] == "none" and r["detected"]]
    false_negatives = [r for r in ok_rows if r["label"] != "none" and not r["detected"]]

    # --- Adversarial breakdown ---
    adversarial_rows = [r for r in ok_rows if r["category"] == "adversarial"]
    adversarial_metrics = confusion(adversarial_rows) if adversarial_rows else None

    return {
        "overall": overall,
        "by_category": category_metrics,
        "by_label": dict(by_label),
        "by_difficulty": dict(by_difficulty),
        "by_surface": surface_metrics,
        "best_surface_f1": round(best_surface_f1, 4),
        "best_surface_name": best_surface_name,
        "surface_normalized_f1": round(surface_normalized, 4),
        "adversarial_metrics": adversarial_metrics,
        "by_family": by_family,
        "agent_tier_accuracy": agent_tier_accuracy,
        "mean_signature_recall": mean_sig_recall,
        "false_positives": [{"case_id": r["case_id"], "family": r["family"]} for r in false_positives],
        "false_negatives": [{"case_id": r["case_id"], "family": r["family"]} for r in false_negatives],
        "error_count": sum(1 for r in results if r["status"] == "error"),
    }


def _fmt(val: float | None, decimals: int = 2) -> str:
    if val is None:
        return "-"
    return f"{val:.{decimals}f}"


def _fmt_wilson(w: tuple[float | None, float | None, float | None]) -> str:
    if w[0] is None:
        return "-"
    return f"{w[0]:.2f} [{w[1]:.2f}, {w[2]:.2f}]"


def render_report(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    lines: list[str] = []

    lines.append("# SAB Real-World Benchmark Report")
    lines.append("")
    lines.append("> **Shadow AI Agent Discovery — Real-World Pattern Corpus v2**")
    lines.append(">")
    lines.append("> This benchmark uses file patterns modeled on actual public GitHub")
    lines.append("> repositories. It is author-written and cannot establish independent")
    lines.append("> precision or recall. An adversarial category explicitly targets")
    lines.append("> known ShadowScan blind spots to surface author bias rather than")
    lines.append("> hide it. See [Limitations](#limitations).")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append(f"- **Tool**: ShadowScan v{manifest['tool_version']}")
    lines.append(f"- **Corpus version**: {manifest['version']}")
    lines.append(f"- **Cases**: {manifest['case_count']}")
    lines.append(f"- **Surfaces**: {', '.join(sorted(summary['by_surface'].keys()))}")
    lines.append(f"- **Categories**: {len(summary['by_category'])}")
    lines.append(f"- **Families**: {len(summary['by_family'])}")
    lines.append(f"- **Timestamp**: {manifest['timestamp']}")
    lines.append(f"- **Python**: {manifest['python']}")
    lines.append(f"- **Errors**: {summary['error_count']}")
    lines.append("")

    o = summary["overall"]
    lines.append("## Overall Results")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Cases | {o['n']} |")
    lines.append(f"| TP / FP / FN / TN | {o['tp']} / {o['fp']} / {o['fn']} / {o['tn']} |")
    lines.append(f"| Recall | {_fmt_wilson(o['recall'])} |")
    lines.append(f"| Specificity | {_fmt_wilson(o['specificity'])} |")
    lines.append(f"| Precision | {_fmt_wilson(o['precision'])} |")
    lines.append(f"| F1 | {_fmt(o['f1'])} |")
    lines.append(f"| F1 95% CI (bootstrap) | [{_fmt(o['f1_ci'][0])}, {_fmt(o['f1_ci'][1])}] |")
    lines.append(f"| MCC | {_fmt(o['mcc'])} |")
    if summary["agent_tier_accuracy"] is not None:
        lines.append(f"| Agent-tier accuracy | {_fmt(summary['agent_tier_accuracy'])} |")
    if summary["mean_signature_recall"] is not None:
        lines.append(f"| Mean signature recall | {_fmt(summary['mean_signature_recall'])} |")
    lines.append("")

    # --- Surface-balanced scoring ---
    lines.append("## Surface-Balanced Scoring")
    lines.append("")
    lines.append("Tools differ in which scanning surfaces they support. These metrics")
    lines.append("allow fair comparison by reporting per-surface performance.")
    lines.append("")
    lines.append("| Surface | N | TP | FP | FN | TN | Recall | Precision | F1 | MCC |")
    lines.append("|---------|---|----|----|----|----|--------|-----------|----|-----|")
    for surface, m in sorted(summary["by_surface"].items()):
        lines.append(
            f"| {surface} | {m['n']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} "
            f"| {_fmt(m['recall'][0])} | {_fmt(m['precision'][0])} "
            f"| {_fmt(m['f1'])} | {_fmt(m['mcc'])} |"
        )
    lines.append("")
    lines.append("| Aggregate Metric | Value |")
    lines.append("|------------------|-------|")
    lines.append(f"| Best-surface F1 | {_fmt(summary['best_surface_f1'])} ({summary['best_surface_name']}) |")
    lines.append(f"| Surface-normalized F1 | {_fmt(summary['surface_normalized_f1'])} |")
    lines.append("")
    lines.append("*Best-surface F1*: highest F1 among supported surfaces. Use when")
    lines.append("comparing tools that claim different surface coverage.")
    lines.append("")
    lines.append("*Surface-normalized F1*: weighted average of per-surface F1 scores,")
    lines.append("each weighted by case count. Penalizes tools that skip surfaces.")
    lines.append("")

    lines.append("## Results by Category")
    lines.append("")
    lines.append("| Category | N | TP | FP | FN | TN | Recall | Precision | F1 | MCC |")
    lines.append("|----------|---|----|----|----|----|--------|-----------|----|-----|")
    for cat, m in sorted(summary["by_category"].items()):
        lines.append(
            f"| {cat} | {m['n']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} "
            f"| {_fmt(m['recall'][0])} | {_fmt(m['precision'][0])} "
            f"| {_fmt(m['f1'])} | {_fmt(m['mcc'])} |"
        )
    lines.append("")

    # --- Adversarial breakdown ---
    if summary.get("adversarial_metrics"):
        am = summary["adversarial_metrics"]
        lines.append("### Adversarial Category Detail")
        lines.append("")
        lines.append("These 15 cases target known ShadowScan blind spots (sparse")
        lines.append("Go/Rust patterns, custom HTTP-only LLM clients, C/C++ unsupported")
        lines.append("extensions, dynamic imports, gated heuristics). An honest benchmark")
        lines.append("should expose, not hide, the tool author's weaknesses.")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Cases | {am['n']} |")
        lines.append(f"| TP / FP / FN / TN | {am['tp']} / {am['fp']} / {am['fn']} / {am['tn']} |")
        lines.append(f"| F1 | {_fmt(am['f1'])} |")
        lines.append(f"| MCC | {_fmt(am['mcc'])} |")
        lines.append("")

    lines.append("## Results by Difficulty")
    lines.append("")
    lines.append("| Difficulty | Correct | Total | Accuracy |")
    lines.append("|------------|---------|-------|----------|")
    for diff in ("easy", "medium", "hard"):
        d = summary["by_difficulty"].get(diff, {"correct": 0, "total": 0})
        acc = d["correct"] / d["total"] if d["total"] else 0
        lines.append(f"| {diff} | {d['correct']} | {d['total']} | {_fmt(acc)} |")
    lines.append("")

    lines.append("## Results by Label")
    lines.append("")
    lines.append("| Label | Correct | Total | Accuracy |")
    lines.append("|-------|---------|-------|----------|")
    for label in ("agent", "llm", "none"):
        d = summary["by_label"].get(label, {"correct": 0, "total": 0})
        acc = d["correct"] / d["total"] if d["total"] else 0
        lines.append(f"| {label} | {d['correct']} | {d['total']} | {_fmt(acc)} |")
    lines.append("")

    lines.append("## Per-Family Results")
    lines.append("")
    lines.append("| Family | Surface | Label | Detected | Correct | Agent Tier | Sig Recall |")
    lines.append("|--------|---------|-------|----------|---------|------------|------------|")
    for key, fam in sorted(summary["by_family"].items()):
        cat_fam = key.split("|", 1)[1]
        check = "Y" if fam["correct"] else "**N**"
        at = "Y" if fam["agent_tier_correct"] else "**N**"
        sr = _fmt(fam["signature_recall"]) if fam["signature_recall"] is not None else "-"
        lines.append(
            f"| {cat_fam} | {fam.get('surface', 'repo')} | {fam['label']} "
            f"| {fam['detected']} | {check} | {at} | {sr} |"
        )
    lines.append("")

    if summary["false_positives"]:
        lines.append("## False Positives")
        lines.append("")
        for fp in summary["false_positives"]:
            lines.append(f"- `{fp['case_id']}` ({fp['family']})")
        lines.append("")

    if summary["false_negatives"]:
        lines.append("## False Negatives")
        lines.append("")
        for fn_ in summary["false_negatives"]:
            lines.append(f"- `{fn_['case_id']}` ({fn_['family']})")
        lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append("1. **Author-written corpus**: This benchmark is written by the ShadowScan")
    lines.append("   maintainer. It cannot serve as independent validation. See AGENTS.md.")
    lines.append("2. **Adversarial cases surface but do not eliminate bias**: The adversarial")
    lines.append("   category targets known blind spots (Go/Rust sparse patterns, C/C++ no")
    lines.append("   source extension support, custom HTTP LLM clients, gated heuristics).")
    lines.append("   This makes weaknesses visible but the author chose which weaknesses to")
    lines.append("   test, which is itself a form of bias.")
    lines.append("3. **Single tool**: Only ShadowScan is tested against this corpus. The")
    lines.append("   cross-tool comparison uses the separate synthetic benchmark.")
    lines.append("4. **Structural patterns only**: Cases reproduce file structure and import")
    lines.append("   patterns, not full repositories with git history, CI, or runtime signals.")
    lines.append("5. **Surface coverage**: This corpus covers repo and endpoint surfaces.")
    lines.append("   Network surface (egress traffic, DNS) needs a separate corpus with")
    lines.append("   packet captures. The FilesystemConnector scans both repo and endpoint")
    lines.append("   cases identically; a tool that distinguishes surfaces would need")
    lines.append("   separate harness paths.")
    lines.append("6. **39 hard negatives**: While substantially expanded from 12, 39 families")
    lines.append("   still cannot cover the full space of false-positive triggers in")
    lines.append("   production environments.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).parent / "results",
    )
    args = parser.parse_args()
    summary = run_benchmark(args.output)
    o = summary["overall"]
    print(f"Cases: {o['n']}  F1: {o['f1']}  MCC: {o['mcc']}  "
          f"TP: {o['tp']} FP: {o['fp']} FN: {o['fn']} TN: {o['tn']}")
    if summary["error_count"]:
        print(f"Errors: {summary['error_count']}")

    for surface, m in sorted(summary["by_surface"].items()):
        print(f"  [{surface}] F1: {m['f1']}  N: {m['n']}")
    print(f"  Best-surface F1: {summary['best_surface_f1']} ({summary['best_surface_name']})")
    print(f"  Surface-normalized F1: {summary['surface_normalized_f1']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
