"""Score the real-world benchmark and write its report.

``python -m tools.benchmark_realworld.score --results tools/benchmark_realworld/results
  --manifest tools/benchmark_realworld/corpus.json``

Positive means the label is ``agent``, ``llm`` or ``client`` (home view). A case
labeled ``ambiguous`` is left out of every primary metric. An ``error`` counts as
not detected and is also reported on its own. ``n/a`` cases are excluded from
the tool's metrics on that surface.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from tools.benchmark.score import bootstrap_f1, confusion, mcnemar_exact, wilson
from tools.benchmark_realworld.cases import validate_manifest

STRATA = ("ai-app", "hard-negative", "ordinary")
SURFACE_TITLE = {
    "repo": "Repo surface (the source tree)",
    "endpoint": "Home-view surface (root read as $HOME)",
}


def load_rows(results: Path) -> dict[str, list[dict[str, Any]]]:
    return {
        path.stem: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        for path in sorted(results.glob("*.jsonl"))
    }


def scored(
    rows: list[dict[str, Any]], surface: str, *, exclude_families: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    """Rows the primary metrics use: this surface, supported, not ambiguous, not excluded."""
    return [
        r
        for r in rows
        if r["surface"] == surface
        and r["status"] != "n/a"
        and r["label"] != "ambiguous"
        and r["family"] not in exclude_families
    ]


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    m = confusion(rows)
    m["f1_ci"] = bootstrap_f1(rows) if rows else (None, None)
    times = sorted(r["seconds"] for r in rows if r["status"] == "ok")
    m["median_seconds"] = times[len(times) // 2] if times else None
    return m


def agent_tier(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Flagged as agent-capable: recall on ``agent`` repos, false alarms on the rest."""
    if not rows or any(r["agentic"] is None for r in rows):
        return None
    pos = [r for r in rows if r["label"] == "agent"]
    non = [r for r in rows if r["label"] != "agent"]
    return {
        "agent_recall": wilson(sum(bool(r["agentic"]) for r in pos), len(pos)),
        "false_alarm_on_non_agent": wilson(sum(bool(r["agentic"]) for r in non), len(non)),
    }


def by_stratum(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for stratum in STRATA:
        mine = [r for r in rows if r["family"] == stratum]
        pos = [r for r in mine if r["label"] != "none"]
        neg = [r for r in mine if r["label"] == "none"]
        out[stratum] = {
            "positives": len(pos),
            "detected_positives": sum(r["status"] == "ok" and r["detected"] for r in pos),
            "negatives": len(neg),
            "false_positives": sum(r["status"] == "ok" and r["detected"] for r in neg),
        }
    return out


def paired(
    rows_by_tool: dict[str, list[dict[str, Any]]], surface: str, reference: str = "shadowscan"
) -> dict[str, Any]:
    """Exact McNemar tests against the reference tool on the cases both tools support."""
    ref = {r["case"]: r for r in scored(rows_by_tool.get(reference, []), surface)}
    out: dict[str, Any] = {}
    for tool, rows in rows_by_tool.items():
        if tool == reference:
            continue
        b = c = n = 0
        for r in scored(rows, surface):
            o = ref.get(r["case"])
            if o is None:
                continue
            truth = r["label"] != "none"
            other_ok = (r["status"] == "ok" and r["detected"]) == truth
            ref_ok = (o["status"] == "ok" and o["detected"]) == truth
            n += 1
            b += ref_ok and not other_ok
            c += other_ok and not ref_ok
        if n:
            out[tool] = {
                "n": n,
                "reference_only_right": b,
                "tool_only_right": c,
                "mcnemar_p": mcnemar_exact(b, c),
            }
    return out


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    n = len(pairs)
    if n == 0:
        return None
    cats = sorted({x for p in pairs for x in p})
    observed = sum(a == b for a, b in pairs) / n
    expected = sum((sum(a == c for a, _ in pairs) / n) * (sum(b == c for _, b in pairs) / n) for c in cats)
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


def agreement(repos: list[dict[str, Any]]) -> dict[str, Any]:
    three = [(r["labels"]["A"], r["labels"]["B"]) for r in repos]
    binary = [
        ("pos" if a in ("agent", "llm") else a, "pos" if b in ("agent", "llm") else b) for a, b in three
    ]
    return {
        "repos": len(repos),
        "exact_agreement": sum(a == b for a, b in three) / len(three) if three else None,
        "kappa_three_way": cohen_kappa(three),
        "kappa_positive_vs_none": cohen_kappa(binary),
        "disagreements": [r["id"] for r in repos if r["labels"]["A"] != r["labels"]["B"]],
    }


def fmt_p(p: float | None, lo: float | None = None, hi: float | None = None) -> str:
    if p is None:
        return "—"
    if lo is None or hi is None:
        return f"{p:.2f}"
    return f"{p:.2f} [{lo:.2f}–{hi:.2f}]"


def tool_table(rows_by_tool: dict[str, list[dict[str, Any]]], surface: str) -> list[str]:
    lines = [
        "| Tool | Supported | TP | FP | FN | TN | Errors | Recall [95% CI] | Specificity "
        "| Precision | F1 [95% CI] | Median s |",
        "|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---|---:|",
    ]
    for tool, rows in rows_by_tool.items():
        sup = [r for r in rows if r["surface"] == surface and r["status"] != "n/a"]
        if not sup:
            continue
        m = metrics(scored(rows, surface))
        lo, hi = m["f1_ci"]
        lines.append(
            f"| {tool} | {len(sup)} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['errors']} | "
            f"{fmt_p(*m['recall'])} | {fmt_p(m['specificity'][0])} | {fmt_p(m['precision'][0])} | "
            f"{fmt_p(m['f1'], lo, hi)} | "
            f"{m['median_seconds'] if m['median_seconds'] is not None else '—'} |"
        )
    return lines


def render(
    rows_by_tool: dict[str, list[dict[str, Any]]],
    repos: list[dict[str, Any]],
    manifest_sha: str,
    self_check: dict[str, Any] | None,
) -> str:
    lines: list[str] = []
    label_counts = Counter(r["label"] for r in repos)
    stratum_counts = Counter(r["stratum"] for r in repos)
    agree = agreement(repos)
    lines += [
        "# Real-world shadow-AI discovery benchmark: results",
        "",
        "> **Read this first.** These are results on public repositories at pinned commits, labeled by two "
        "model-based labelers (no human labeled the corpus) under `PROTOCOL.md`. They are not field "
        "precision or recall, not an independent review, and not production accuracy. Intervals are "
        "95% Wilson (proportions) or a 2,000-sample bootstrap (F1). Small strata give wide intervals.",
        "",
        f"Manifest SHA-256 `{manifest_sha}`. Protocol v1 (`PROTOCOL.md`).",
        "",
        "## Corpus",
        "",
        f"- Repositories: {len(repos)} (pinned commits). Labels after adjudication: "
        + ", ".join(f"{k} {v}" for k, v in sorted(label_counts.items()))
        + ".",
        "- Strata: " + ", ".join(f"{k} {stratum_counts.get(k, 0)}" for k in STRATA) + ".",
        f"- Labeler agreement before adjudication: exact {agree['exact_agreement']:.2f}, "
        f"Cohen's kappa {agree['kappa_three_way']:.2f} (agent / llm / none / ambiguous), "
        f"kappa {agree['kappa_positive_vs_none']:.2f} (positive versus none)."
        if agree["kappa_three_way"] is not None
        else "- Labeler agreement: not available.",
        "- Disagreements, adjudicated from the cited evidence: "
        + (", ".join(agree["disagreements"]) or "none")
        + ".",
        "",
    ]
    for surface in ("repo", "endpoint"):
        lines += [f"## {SURFACE_TITLE[surface]}", ""]
        lines += tool_table(rows_by_tool, surface)
        lines.append("")
    lines += ["## False positives by stratum (repo surface)", ""]
    lines += [
        "| Tool | AI apps detected | Hard negatives flagged | Ordinary repos flagged |",
        "|---|---|---|---|",
    ]
    for tool, rows in rows_by_tool.items():
        strata = by_stratum(
            [r for r in rows if r["surface"] == "repo" and r["status"] != "n/a" and r["label"] != "ambiguous"]
        )
        if not any(v["positives"] + v["negatives"] for v in strata.values()):
            continue
        a, h, o = strata["ai-app"], strata["hard-negative"], strata["ordinary"]
        lines.append(
            f"| {tool} | {a['detected_positives']}/{a['positives']} | "
            f"{h['false_positives']}/{h['negatives']} | "
            f"{o['false_positives']}/{o['negatives']} |"
        )
    lines.append("")
    lines += ["## Sensitivity: hard negatives excluded (repo surface)", ""]
    lines += [
        "| Tool | F1 (all scored) | F1 (hard negatives excluded) | Specificity (all) |",
        "|---|---|---|---|",
    ]
    for tool, rows in rows_by_tool.items():
        if not any(r["surface"] == "repo" and r["status"] != "n/a" for r in rows):
            continue
        all_m = metrics(scored(rows, "repo"))
        ex_m = metrics(scored(rows, "repo", exclude_families=("hard-negative",)))
        lines.append(
            f"| {tool} | {fmt_p(all_m['f1'])} | {fmt_p(ex_m['f1'])} | {fmt_p(all_m['specificity'][0])} |"
        )
    lines.append("")
    lines += ["## Agent tier (repo surface)", ""]
    lines += ["| Tool | Recall on agent repos | False alarms on llm and none repos |", "|---|---|---|"]
    for tool, rows in rows_by_tool.items():
        tier = agent_tier(scored(rows, "repo"))
        if tier:
            lines.append(
                f"| {tool} | {fmt_p(*tier['agent_recall'])} | {fmt_p(*tier['false_alarm_on_non_agent'])} |"
            )
    lines.append("")
    for surface in ("repo", "endpoint"):
        pairs = paired(rows_by_tool, surface)
        if not pairs:
            continue
        lines += [f"## Paired comparison with ShadowScan (exact McNemar), {surface} surface", ""]
        lines += ["| Tool | n | ShadowScan only right | Tool only right | p |", "|---|---:|---:|---:|---:|"]
        for tool, v in pairs.items():
            lines.append(
                f"| {tool} | {v['n']} | {v['reference_only_right']} | "
                f"{v['tool_only_right']} | {v['mcnemar_p']:.2g} |"
            )
        lines.append("")
    lines += ["## Errors (crash, timeout, incomplete scan, unreadable output)", ""]
    lines += ["| Tool | Surface | Errors | Example note (sanitized) |", "|---|---|---:|---|"]
    for tool, rows in rows_by_tool.items():
        for surface in ("repo", "endpoint"):
            errs = [r for r in rows if r["surface"] == surface and r["status"] == "error"]
            if errs:
                lines.append(f"| {tool} | {surface} | {len(errs)} | {errs[0]['note'][:120]} |")
    lines.append("")
    if self_check:
        lines += [
            "## Self-check: ShadowScan on this repository (descriptive, not scored)",
            "",
            f"Status `{self_check['status']}`, detected `{self_check['detected']}`, "
            f"items {self_check['items']}. "
            "This repository is not a corpus member, and it contains the signatures it searches for.",
            "",
        ]
    lines += [
        "## Limits",
        "",
        "- The corpus is small. Strata of 1 to 4 repositories cannot support rates; read them as examples.",
        "- Labels come from model-based labelers following the protocol. No human labeled them, and "
        "adjudication is by the same pipeline. Treat labels as a reproducible reading of public code, "
        "not as ground truth.",
        "- Repositories are at pinned commits. Results do not transfer to other commits or to private code.",
        "- Network, identity, SaaS and cloud surfaces are not measured here (no public real-world data).",
        "- Several tools were run in a reduced mode: Cisco AI BOM without its LLM classifier, "
        "AgentDiscover without "
        "layers 2 to 5, Snyk Agent Scan with no analysis upload (no network in the sandbox).",
        "",
        "## Reproduce",
        "",
        "```bash",
        "bash tools/benchmark_realworld/install_tools.sh /opt/rwbench/tools",
        "python -m tools.benchmark_realworld.run --manifest tools/benchmark_realworld/corpus.json "
        "--checkout-root /home/user --tool-root /opt/rwbench/tools "
        "--results tools/benchmark_realworld/results --raw /opt/rwbench/raw --self-check",
        "python -m tools.benchmark_realworld.score --results tools/benchmark_realworld/results "
        "--manifest tools/benchmark_realworld/corpus.json",
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)

    manifest_bytes = args.manifest.read_bytes()
    repos = validate_manifest(json.loads(manifest_bytes))
    rows_by_tool = load_rows(args.results)
    run_manifest = json.loads((args.results / "run-manifest.json").read_text(encoding="utf-8"))
    self_path = args.results / "self-check.json"
    self_check = json.loads(self_path.read_text(encoding="utf-8")) if self_path.exists() else None

    summary = {
        "tools": {
            tool: {"repo": metrics(scored(rows, "repo")), "endpoint": metrics(scored(rows, "endpoint"))}
            for tool, rows in rows_by_tool.items()
        },
        "paired_repo": paired(rows_by_tool, "repo"),
        "paired_endpoint": paired(rows_by_tool, "endpoint"),
        "agreement": agreement(repos),
        "run_manifest_sha256": run_manifest.get("manifest_sha256"),
    }
    (args.results / "summary.json").write_text(
        json.dumps(summary, indent=1, default=str) + "\n", encoding="utf-8"
    )
    report = render(rows_by_tool, repos, run_manifest.get("manifest_sha256", "unknown"), self_check)
    (args.results / "REPORT.md").write_text(report, encoding="utf-8")
    print(f"wrote {args.results / 'REPORT.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
