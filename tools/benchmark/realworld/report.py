"""Render REPORT.md from the scored summary: tables only, plus an optional hand-written findings section.

``python -m tools.benchmark.realworld.report --summary results/summary.json --run-manifest results/run-manifest.json
--manifest manifest.jsonl --labels labels.jsonl --results results [--findings findings.md] [--freeze freeze.json]
[--adjudication-report adjudication-report.json] --output REPORT.md``

Every figure comes from ``summary.json`` (written by ``score.py``). The report does not rank tools: rows are
ordered by name, and each proportion carries a 95% Wilson interval. The findings section is written by a
person (or an agent) after reading the tables and is included verbatim, so the numbers and the reading of
them stay separate.
"""

# ruff: noqa: E501  (long prose strings in the generated report)
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.benchmark.realworld import freeze as freeze_module
from tools.benchmark.realworld.score import (
    BASELINES,
    CLASS_ORDER,
    CONFIG_VARIANTS,
    FAMILIES,
    Scorer,
    frame_class,
    load_excluded,
    load_shared,
    read_jsonl,
)

HERE = Path(__file__).resolve().parent
UNFROZEN = (
    "adjudicate.py", "report.py", "rerun_errors.py", "record_environment.py", "corpus_summary.py", "README.md",
    "CORPUS.md",
)  # fmt: skip

NOT_SCORED = (
    ("Snyk Agent Scan (formerly Invariant mcp-scan)", "scans a machine's MCP and agent configuration, not a repository"),
    ("Cisco AI Defense MCP Scanner", "analyses a running or remote MCP server, not a repository"),
    ("Open Shadow AI, AgentSonar", "network and endpoint surface (traffic, DNS, processes)"),
    ("k8s-aibom and similar", "Kubernetes cluster surface"),
    ("Claw-Hunter and similar", "endpoint inventory of one agent product"),
)  # fmt: skip


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def ci(interval: Any) -> str:
    """``62% [48-74]`` from a (point, low, high) triple."""
    if not interval:
        return "n/a"
    return f"{pct(interval[0])} [{pct(interval[1])}-{pct(interval[2])}]"


def cell(k: int, n: int, interval: Any) -> str:
    return f"{k}/{n} = {ci(interval)}" if n else "n/a"


def recall_cell(s: dict[str, Any]) -> str:
    return cell(s["tp"], s["tp"] + s["fn"], s["recall"])


def spec_cell(s: dict[str, Any]) -> str:
    return cell(s["tn"], s["tn"] + s["fp"], s["specificity"])


def table(header: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


class Names:
    """Display names from the run manifest, with the tool id as fallback."""

    def __init__(self, run_manifest: dict[str, Any]) -> None:
        self.info: dict[str, dict[str, str]] = {}
        for run in run_manifest.get("runs", []):
            self.info.update(run.get("tool_info", {}))

    def display(self, tool: str) -> str:
        return self.info.get(tool, {}).get("display", tool)


def ordered(summary: dict[str, Any], names: Names) -> tuple[list[str], list[str], list[str]]:
    tools = list(summary["tools"])
    real = sorted(
        (t for t in tools if t not in BASELINES and t not in CONFIG_VARIANTS),
        key=lambda t: names.display(t).lower(),
    )
    return real, sorted(t for t in tools if t in BASELINES), sorted(t for t in tools if t in CONFIG_VARIANTS)


def label_of(tool: str, names: Names) -> str:
    suffix = (
        " *(baseline)*" if tool in BASELINES else " *(sensitivity row)*" if tool in CONFIG_VARIANTS else ""
    )
    return names.display(tool) + suffix


def headline(summary: dict[str, Any], names: Names) -> str:
    rows = []
    for tool in [t for group in ordered(summary, names) for t in group]:
        entry = summary["tools"][tool]
        s = entry["scopes"]["probability"]["primary"]
        err = entry["error_rate"]
        median = entry["runtime_seconds"]["median"]
        rows.append([
            label_of(tool, names), recall_cell(s), spec_cell(s), pct(err[0]) if err else "n/a",
            entry["partial_scans"], f"{median:.0f} s" if median is not None else "n/a",
        ])  # fmt: skip
    head = [
        "Tool",
        "Recall on positives",
        "Specificity on negatives",
        "Errors (all repos)",
        "Incomplete scans",
        "Median time",
    ]
    return table(head, rows)


def forest_svg(summary: dict[str, Any], names: Names) -> str:
    """Two-panel interval plot (recall, specificity) for the headline scope; rows are alphabetical, not ranked."""
    tools = [t for group in ordered(summary, names) for t in group]
    row_h, left, panel_w, gap, top = 22, 250, 260, 40, 44
    width = left + 2 * panel_w + gap + 60
    height = top + row_h * len(tools) + 30
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        'font-family="sans-serif" font-size="12">',
        '<rect width="100%" height="100%" fill="white"/>',
    ]
    for panel, (title, key) in enumerate(
        (("Recall on positives", "recall"), ("Specificity on negatives", "specificity"))
    ):
        x0 = left + panel * (panel_w + gap)
        out.append(f'<text x="{x0}" y="18" font-weight="bold">{title} (95% Wilson interval)</text>')
        for tick in (0, 25, 50, 75, 100):
            x = x0 + panel_w * tick / 100
            out.append(f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{height - 22}" stroke="#ddd"/>')
            out.append(f'<text x="{x:.1f}" y="{height - 8}" text-anchor="middle" fill="#555">{tick}</text>')
        for i, tool in enumerate(tools):
            block = summary["tools"][tool]["scopes"]["probability"]["primary"]
            y = top + i * row_h + row_h / 2
            if panel == 0:
                out.append(
                    f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{label_plain(tool, names)}</text>'
                )
            interval = block[key]
            n = block["tp"] + block["fn"] if key == "recall" else block["tn"] + block["fp"]
            if not interval:
                out.append(f'<text x="{x0}" y="{y + 4:.1f}" fill="#888">no data</text>')
                continue
            point, low, high = (x0 + panel_w * v for v in interval)
            out.append(
                f'<line x1="{low:.1f}" y1="{y:.1f}" x2="{high:.1f}" y2="{y:.1f}" stroke="#2a6" stroke-width="2"/>'
            )
            out.append(f'<circle cx="{point:.1f}" cy="{y:.1f}" r="4" fill="#064"/>')
            out.append(
                f'<text x="{x0 + panel_w + 4}" y="{y + 4:.1f}" font-size="10" fill="#555">n={n}</text>'
            )
    out.append("</svg>")
    return "\n".join(out) + "\n"


def label_plain(tool: str, names: Names) -> str:
    suffix = " (baseline)" if tool in BASELINES else " (sensitivity)" if tool in CONFIG_VARIANTS else ""
    return (names.display(tool) + suffix).replace("&", "&amp;").replace("<", "&lt;")


def per_class(summary: dict[str, Any], names: Names, kind: str) -> str:
    rows = []
    for tool in [t for group in ordered(summary, names) for t in group]:
        by_class = summary["tools"][tool]["by_class"]
        row = [label_of(tool, names)]
        for cls in CLASS_ORDER:
            s = by_class.get(cls)
            row.append("n/a" if s is None else recall_cell(s) if kind == "recall" else spec_cell(s))
        rows.append(row)
    return table(["Tool", *CLASS_ORDER], rows)


def per_frame(summary: dict[str, Any], names: Names, kind: str) -> str:
    real, baselines, _ = ordered(summary, names)
    frames = sorted(summary["sets"]["frames"], key=lambda f: (CLASS_ORDER.index(frame_class(f)), f))
    rows = []
    for tool in [*real, *baselines]:
        by_frame = summary["tools"][tool]["by_frame"]
        row = [names.display(tool)]
        for frame in frames:
            s = by_frame.get(frame)
            if s is None:
                row.append("-")
                continue
            k, n = (s["tp"], s["tp"] + s["fn"]) if kind == "recall" else (s["tn"], s["tn"] + s["fp"])
            row.append(f"{k}/{n}" if n else "-")
        rows.append(row)
    return table(["Tool", *frames], rows)


def sensitivity(summary: dict[str, Any], names: Names) -> str:
    rows = []
    for tool in [t for group in ordered(summary, names) for t in group]:
        block = summary["tools"][tool]["scopes"]["probability"]
        head, lenient, clean = block["primary"], block["partial_as_detection"], block["errors_as_clean"]
        rows.append([
            label_of(tool, names), recall_cell(head), recall_cell(lenient), spec_cell(head), spec_cell(lenient),
            spec_cell(clean),
        ])  # fmt: skip
    return table(
        ["Tool", "Recall (headline)", "Recall, partial scans kept", "Specificity (headline)",
         "Specificity, partial scans kept", "Specificity, errors as clean"],
        rows,
    )  # fmt: skip


def detection_rules(summary: dict[str, Any], names: Names) -> str:
    real, _, _ = ordered(summary, names)
    rows = []
    for tool in real:
        block = summary["tools"][tool]["scopes"]["probability"]
        if not block["detection_rules"]:
            continue
        rows.append(
            [
                names.display(tool),
                "*headline rule*",
                recall_cell(block["primary"]),
                spec_cell(block["primary"]),
            ]
        )
        for rule, s in sorted(block["detection_rules"].items()):
            rows.append([names.display(tool), f"`{rule}`", recall_cell(s), spec_cell(s)])
    return table(["Tool", "Detection rule", "Recall", "Specificity"], rows) if rows else "(none)"


def label_variants(summary: dict[str, Any], names: Names, scope: str) -> str:
    real, baselines, _ = ordered(summary, names)
    variants = list(summary["tools"][real[0]]["scopes"][scope]["label_variants"])
    rows = []
    for tool in [*real, *baselines]:
        row = [names.display(tool)]
        for v in variants:
            s = summary["tools"][tool]["scopes"][scope]["label_variants"][v]
            row.append(f"{recall_cell(s)}<br>{spec_cell(s)}")
        rows.append(row)
    return table(["Tool (recall<br>specificity)", *variants], rows)


def evidence(summary: dict[str, Any], names: Names) -> str:
    real, baselines, _ = ordered(summary, names)
    kinds = [*FAMILIES, "agent-type", "llm-only"]
    rows = []
    for tool in [*real, *baselines]:
        entry = summary["tools"][tool]
        rows.append([
            names.display(tool), *[ci(entry["by_evidence"].get(k)) for k in kinds],
            ci(entry["devcfg_only_recall"]),
        ])  # fmt: skip
    return table(["Tool", *[FAMILIES.get(k, k) for k in kinds], "developer-config-only"], rows)


def vocabulary(summary: dict[str, Any], names: Names) -> str:
    real, baselines, _ = ordered(summary, names)
    split = summary["sets"].get("vocabulary_split", {})
    rows = []
    for tool in [*real, *baselines]:
        by = summary["tools"][tool]["recall_by_vocabulary"]
        rows.append([names.display(tool), ci(by.get("shared")), ci(by.get("shadowscan-only-or-unmentioned"))])
    head = [
        "Tool",
        f"Recall, positives resting on technologies other tools mention (n={split.get('shared', 0)})",
        "Recall, positives resting only on ShadowScan-mentioned or unmentioned technologies "
        f"(n={split.get('shadowscan-only-or-unmentioned', 0)})",
    ]
    return table(head, rows)


def pairwise(summary: dict[str, Any], names: Names, scope: str) -> str:
    rows = []
    for key, v in sorted(summary["pairwise"][scope].items(), key=lambda kv: kv[1]["p_holm"]):
        if v["p_holm"] >= 0.05:
            continue
        a, b = key.split("|")
        rows.append([names.display(a), names.display(b), v["n"], v["a_right_b_wrong"], v["b_right_a_wrong"],
                     f"{v['p_holm']:.3g}"])  # fmt: skip
    if not rows:
        return "No pair differs at Holm-adjusted p < 0.05."
    return table(
        ["Tool A", "Tool B", "Repositories", "A right, B wrong", "B right, A wrong", "p (Holm)"], rows
    )


def prevalence(summary: dict[str, Any], names: Names) -> str:
    rows = []
    for tool in [t for group in ordered(summary, names) for t in group]:
        ppv = summary["tools"][tool]["scopes"]["probability"]["primary"].get("prevalence_ppv", {})
        rows.append([label_of(tool, names), *[ci(ppv.get(p)) if ppv else "n/a" for p in ("1%", "5%", "20%")]])
    return table(["Tool", "PPV at 1% prevalence", "at 5%", "at 20%"], rows)


def unique(summary: dict[str, Any], names: Names) -> str:
    real, _, _ = ordered(summary, names)
    rows = [[names.display(t), len(summary["unique_finds"].get(t, []))] for t in real]
    return table(["Tool", "Positives detected by this tool alone"], rows)


def listing(ids: list[str], manifest: dict[str, dict[str, Any]], labels: dict[str, Any]) -> str:
    rows = []
    for rid in ids:
        lab = labels.get(rid, {})
        rows.append(
            [rid, manifest[rid]["url"], manifest[rid]["frame"], ", ".join(lab.get("techs", [])[:6]) or "-"]
        )
    return table(["Id", "Repository", "Frame", "Oracle technologies"], rows) if rows else "None."


def ambiguous(summary: dict[str, Any], manifest: dict[str, dict[str, Any]], names: Names) -> str:
    real, baselines, _ = ordered(summary, names)
    tools = [*real, *baselines]
    rows = [
        [rid, manifest[rid]["url"], info["kind"], *[info["tools"].get(t, "-") for t in tools]]
        for rid, info in sorted(summary["ambiguous"].items())
    ]
    head = ["Id", "Repository", "Why ambiguous", *[names.display(t) for t in tools]]
    return table(head, rows) if rows else "None sampled."


def shadowscan_notes(
    summary: dict[str, Any],
    manifest: dict[str, dict[str, Any]],
    results: dict[str, dict[str, Any]],
    causes: dict[str, Any] | None = None,
) -> str:
    out: list[str] = []
    for tool in ("shadowscan", "shadowscan-bigfiles", "shadowscan-conf03"):
        entry = summary["tools"].get(tool)
        if entry is None:
            continue
        dec = entry["decisions"]
        out.append(
            f"* `{tool}`: {len(dec['false_alarms'])} false alarm(s), {len(dec['misses'])} miss(es) and "
            f"{len(dec['errors'])} error(s) among the primary repositories; {entry['partial_scans']} scan(s) "
            "flagged incomplete in total."
        )
    entry = summary["tools"].get("shadowscan")
    if entry:
        rows = [
            [
                rid,
                manifest[rid]["url"],
                manifest[rid]["frame"],
                results.get("shadowscan", {}).get(rid, {}).get("note", ""),
            ]
            for rid in entry["decisions"]["false_alarms"]
        ]
        out += ["", "False alarms of ShadowScan under defaults (the finding kinds it reported):", "",
                table(["Id", "Repository", "Frame", "Finding kinds"], rows) if rows else "None."]  # fmt: skip
    if causes:
        by_cause = sorted(causes["repositories_by_cause"].items(), key=lambda kv: (-kv[1], kv[0]))
        out += [
            "",
            f"Why ShadowScan scans end incomplete: the {causes['scans_repeated']} incomplete or failed scans "
            "were repeated outside the scored run and their stderr messages were classified into fixed causes "
            "(one scan can have several; no raw output is stored):",
            "",
            table(["Cause", "Repositories"], [[c, n] for c, n in by_cause]),
        ]
    return "\n".join(out)


def corpus(summary: dict[str, Any], manifest: dict[str, dict[str, Any]]) -> str:
    sets = summary["sets"]
    sets = {**sets, "excluded": [rid for rid in sets["excluded"] if rid in manifest]}
    rows = []
    for cls in CLASS_ORDER:
        c = sets["by_class"].get(cls, {})
        rows.append(
            [cls, c.get("positive", 0), c.get("negative", 0), c.get("ambiguous", 0), c.get("ai-library", 0)]
        )
    comp = sets["composition"]
    lines = [
        table(["Class", "Positive", "Negative", "Ambiguous", "AI library"], rows),
        "",
        f"Primary set: {sets['primary']['repositories']} repositories ({sets['primary']['positives']} positive, "
        f"{sets['primary']['negatives']} negative). Removed because the ShadowScan repository names them: "
        f"{', '.join(sets['excluded']) or 'none'}.",
        "",
        f"Among the {comp['positives']} positives: {comp['agent_type']} involve an agent-type artifact (framework, "
        f"MCP, coding-agent configuration), {comp['llm_only']} are LLM-SDK use only, {comp['application_level']} have "
        f"application-level evidence, {comp['developer_config_only']} have only developer-tooling configuration "
        f"(AGENTS.md, CLAUDE.md, .mcp.json and similar), {comp['dependency_only']} rest on a declared dependency "
        "alone.",
    ]
    return "\n".join(lines)


def versions(run_manifest: dict[str, Any]) -> str:
    runs = run_manifest.get("runs", [])
    if not runs:
        return "(no run manifest)"
    last = runs[-1]
    rows = [
        [k, f"`{json.dumps(v) if isinstance(v, (list, dict)) else v}`"]
        for k, v in sorted(last.get("versions", {}).items())
        if k != "safedep_vet_version"
    ]
    if "safedep_vet_version" in last.get("versions", {}):
        rows.append(
            [
                "safedep_vet_version",
                "not captured (the recorded value was a telemetry warning from the offline sandbox); "
                "the installed binary reports `v0.0.0-20261007080544-948d9bafaf80`, matching `safedep_vet` above",
            ]
        )
    meta = (
        f"Finished {last.get('finished')}, {last.get('wall_seconds')} s wall clock, {last.get('workers')} workers, "
        f"{last.get('timeout_s')} s per-run cap, Python {last.get('python')}, {last.get('platform')}."
    )
    return meta + "\n\n" + table(["Component", "Version or commit"], rows)


def tools_table(summary: dict[str, Any], names: Names, run_manifest: dict[str, Any]) -> str:
    """Which tool, which pinned version, and exactly what was run (the adapter's scope line)."""
    runs = run_manifest.get("runs", [])
    versions = runs[-1].get("versions", {}) if runs else {}
    real, baselines, variants = ordered(summary, names)
    rows = []
    for tool in [*real, *baselines, *variants]:
        info = names.info.get(tool, {})
        source = info.get("source", "")
        key = source.replace("/", "_")
        pinned = versions.get(key) or (
            versions.get("shadowscan_commit") if tool.startswith("shadowscan") else ""
        )
        if tool == "cdxgen-aibom":
            pinned = f"npm {versions.get('cdxgen', '')}"
        rows.append(
            [
                label_of(tool, names),
                source or "-",
                f"`{str(pinned)[:12]}`" if pinned else "-",
                info.get("scope", ""),
            ]
        )
    return table(["Tool", "Source", "Pinned commit or version", "What was run (offline, no LLM)"], rows)


def adjudication(summary: dict[str, Any], names: Names, report: dict[str, Any] | None) -> str:
    post = summary.get("adjudicated")
    if not post:
        return "Adjudication was not run for this report."
    real, baselines, _ = ordered(summary, names)
    rows = []
    for tool in [*real, *baselines]:
        pre = summary["tools"][tool]["scopes"]["probability"]["primary"]
        aft = post["tools"][tool]["scopes"]["probability"]["primary"]
        rows.append([names.display(tool), recall_cell(pre), recall_cell(aft), spec_cell(pre), spec_cell(aft)])
    lines = []
    if report:
        lines += [
            f"{post.get('overridden', 0)} repositories were adjudicated; Cohen's kappa between the two adjudicators "
            f"on the `ai` question is {report.get('kappa_ai')} over {report.get('pairs')} cards "
            f"(basis: {report.get('basis')}). The adjudicators are language models of the same family as the "
            "benchmark author, so this is a consistency check, not independent agreement.",
            "",
        ]
    lines.append(
        table(["Tool", "Recall before", "Recall after", "Specificity before", "Specificity after"], rows)
    )
    return "\n".join(lines)


def freeze_section(record: dict[str, Any] | None, run_manifest: dict[str, Any]) -> str:
    if not record:
        return "(no freeze record supplied)"
    runs = run_manifest.get("runs", [])
    used = runs[-1].get("frozen_files_sha256", {}) if runs else {}
    rows = [
        [name, f"`{digest[:16]}`", "yes" if used.get(name) == digest else "NO"]
        for name, digest in sorted(record["files"].items())
    ]
    return (
        f"Freeze record written {record.get('created')} ({record.get('note')}). "
        "`run.py --freeze` refuses to start unless every file matches.\n\n"
        + table(["File", "SHA-256 (first 16)", "Same in the scored run"], rows)
    )


POLICY_CAPTION = (
    "**Incomplete scans.** Only ShadowScan, Cisco AI BOM and agent-bom say, in a form the harness can read, that a "
    "scan was incomplete. For the other tools an incomplete scan cannot be told from a complete one, so the strict "
    "headline policy can only penalise the three that disclose it. Read the headline beside the "
    '"partial scans kept" columns of the error-policy table below, and do not read a higher strict number as a '
    "more complete scan."
)


def composition_note(summary: dict[str, Any], names: Names) -> str:
    """How much of the headline scope's recall is recall on AI-enriched strata."""
    real, _, _ = ordered(summary, names)
    frames = summary["tools"][real[0]]["by_frame"]
    per_frame = {f: s["tp"] + s["fn"] for f, s in frames.items() if frame_class(f) == "probability"}
    total = sum(per_frame.values())
    enriched = per_frame.get("pypi-ai", 0) + per_frame.get("go-ai", 0)
    return (
        f"Of the {total} positives in this scope, {enriched} come from `pypi-ai` and `go-ai`, strata chosen because "
        "the project declares an AI package or has an AI-like name. Recall here is therefore mostly recall on "
        "AI-enriched strata; the untargeted frames (`pypi-other`, `go-random`, `gitlab-random`) hold "
        f"{total - enriched} positives."
    )


def modified_scorer(
    manifest: list[dict[str, Any]],
    labels: dict[str, Any],
    results: dict[str, dict[str, dict[str, Any]]],
    excluded: frozenset[str],
    shared: frozenset[str] | None,
) -> Scorer:
    return Scorer(manifest, labels, results, None, shared, excluded, reps=0)


def radar_sensitivity(
    manifest: list[dict[str, Any]],
    labels: dict[str, Any],
    results: dict[str, dict[str, dict[str, Any]]],
    excluded: frozenset[str],
    shared: frozenset[str] | None,
) -> str:
    """Agentic Radar tries five framework scanners; a crash in one while another finds something is reported as ok."""
    rows = results.get("agentic-radar")
    if not rows:
        return ""
    crashed = {
        rid
        for rid, r in rows.items()
        if r["status"] == "ok" and str(r.get("note", "")).startswith("crashed:")
    }
    changed = {rid: {**r, "partial": True} if rid in crashed else r for rid, r in rows.items()}
    base = modified_scorer(manifest, labels, results, excluded, shared)
    alt = modified_scorer(manifest, labels, {**results, "agentic-radar": changed}, excluded, shared)
    a = base.summary_of(base.codes("agentic-radar", "probability"))
    b = alt.summary_of(alt.codes("agentic-radar", "probability"))
    return (
        f"Agentic Radar scans five framework scanners and reports a repository as ok when one of them finds "
        f"something even if another crashed ({len(crashed)} such repositories). Counting those as incomplete:\n\n"
        + table(
            ["Agentic Radar reading", "Recall", "Specificity"],
            [
                [
                    "headline (a crash elsewhere is ignored once something is found)",
                    recall_cell(a),
                    spec_cell(a),
                ],
                ["a crashed framework scanner makes the scan an error", recall_cell(b), spec_cell(b)],
            ],
        )  # fmt: skip
    )


def vocabulary_detail(
    manifest: list[dict[str, Any]],
    labels: dict[str, Any],
    results: dict[str, dict[str, dict[str, Any]]],
    excluded: frozenset[str],
    vocab: dict[str, Any] | None,
    names: Names,
) -> str:
    """Three groups instead of two: separate the ShadowScan-only technologies from the unmeasured ones."""
    if not vocab:
        return ""
    shared = frozenset(vocab["shared"])
    only = frozenset(vocab["shadowscan_only"])
    sc = modified_scorer(manifest, labels, results, excluded, shared)
    groups: dict[str, set[str]] = {
        "shared": set(),
        "ShadowScan-only": set(),
        "not measured or mentioned by nobody": set(),
    }
    for rid in sc.repos:
        if sc.truth(rid, "strict") is not True:
            continue
        techs = set(labels[rid].get("techs", []))
        key = (
            "shared"
            if techs & shared
            else "ShadowScan-only"
            if techs & only
            else "not measured or mentioned by nobody"
        )
        groups[key].add(rid)
    tools = [t for t in results if t not in CONFIG_VARIANTS]
    rows = []
    for tool in sorted(tools, key=lambda t: names.display(t).lower()):
        row = [label_of(tool, names)]
        for ids in groups.values():
            codes = sc.codes(tool, subset=ids)
            row.append(recall_cell(sc.summary_of(codes)) if ids else "n/a")
        rows.append(row)
    head = ["Tool", *[f"{g} (n={len(ids)})" for g, ids in groups.items()]]
    unmeasured = sorted(set(vocab.get("mentioned_by_nobody", [])))
    return (
        table(head, rows)
        + "\n\n"
        + "Recall on primary positives (all frames), by what supports each positive. The vocabulary script measures "
        "whether a tool's own source *mentions* a technology's names, not whether the tool detects it; a technology "
        "counts as shared if any one of its names (a bundle can list dozens) appears in any other tool. Content "
        "markers and path rules the script does not cover (n8n, Flowise, Langflow, Dify, Bedrock, raw MCP protocol "
        "literals, MCP directory manifests, agent cards, Modelfiles and ChatGPT plugins) fall in the last group "
        f"although nobody was measured; technologies mentioned by nobody: {', '.join(unmeasured) or 'none'}. "
        "**A null result in this table cannot show that the registry is independent of ShadowScan**; a large gap "
        "for ShadowScan alone would be evidence of a favourable registry."
    )


def rerun_section(
    summary: dict[str, Any], merged: dict[str, Any] | None, rerun_dir: Path | None, names: Names
) -> str:
    if not merged or not rerun_dir or not rerun_dir.exists():
        return "No pair was re-run."
    redone: dict[str, list[dict[str, Any]]] = {
        p.stem: read_jsonl(p) for p in sorted(rerun_dir.glob("*.jsonl"))
    }
    rows = []
    for tool in [t for group in ordered(summary, names) for t in group]:
        re_rows = redone.get(tool, [])
        a = summary["tools"][tool]["scopes"]["probability"]["primary"]
        b = merged["tools"][tool]["scopes"]["probability"]["primary"]
        rows.append([
            label_of(tool, names), len(re_rows), sum(1 for r in re_rows if r["status"] == "ok"),
            recall_cell(a), recall_cell(b), spec_cell(a), spec_cell(b),
        ])  # fmt: skip
    return table(
        ["Tool", "Pairs re-run alone", "Fine on re-run", "Recall (first run)", "Recall (re-run rows used)",
         "Specificity (first run)", "Specificity (re-run rows used)"],
        rows,
    )  # fmt: skip


def row_counts(results: dict[str, dict[str, dict[str, Any]]], manifest: list[dict[str, Any]]) -> str:
    expected = {r["id"] for r in manifest}
    rows = [
        [tool, len(by_id), len(expected - set(by_id)), len(set(by_id) - expected)]
        for tool, by_id in sorted(results.items())
    ]
    return table(["Tool", "Rows", "Repositories without a row", "Rows for unknown repositories"], rows)


def unfrozen_hashes() -> str:
    rows = [
        [name, f"`{freeze_module.sha256(HERE / name)[:16]}`"] for name in UNFROZEN if (HERE / name).exists()
    ]
    return table(["File (not in the freeze)", "SHA-256 (first 16) when this report was generated"], rows)


LIMITATIONS = """\
* **Declared after the run started, before any result was read** (on an independent reviewer's advice): the re-run
  of timeouts and harness failures alone (section above), the Agentic Radar reading, the three-group vocabulary
  table and the incomplete-scan caption. None changes the headline, which is the first run.
* **Machine load.** The scored run used 8 workers on 4 CPUs with a load average of about 9, so some timeouts,
  and ShadowScan's own 120 s per-connector deadline, are partly load artefacts. ShadowScan's headline row passes
  no `--connector-timeout-seconds`; the `shadowscan-bigfiles` row uses 540 s.
* **Statements in PROTOCOL.md that are slightly wider than the code.** PROTOCOL.md says a non-zero exit that a tool
  does not document as a verdict is an error; Cisco AI BOM, the AgentDiscover scan step and vet's discovery step
  accept a non-zero exit when they have written a report. "Every tool alike" holds for the incompleteness policy
  and the decision function, but the classical-ML reading rule has a variant for four tools only (not for
  ShadowScan's weak-confidence findings or Trusera). Go modules are sampled by *publication events* in random
  index windows, so a module with many versions is more likely to be drawn. The symlink neutraliser removes
  absolute, dangling and escaping links and most cycles, but simple cycles (`a -> a`, two links pointing at each
  other) can survive; this is harmless for confinement and was not changed after the freeze.
* **Sandbox residue.** Inside the jail the host `/usr`, `/opt/node22` and the tool root are visible, read-only
  and root-owned (a failed read-only remount is tolerated, and the self-test checks that host paths are absent,
  not that mounts are read-only), as are `passwd`, `group`, `hosts` and the mount table in `/proc/self/mountinfo`.
  No escape was found; kernel or user-namespace bugs are the residual risk.
* **Not frozen, by design:** adjudication, report, re-run, corpus-summary and documentation files and the tests
  do not affect any result; their hashes are listed below. The stored corpus after the 19-link audit is hashed in
  `results/environment.json`.
* **Adjudication cards and one hand correction.** The evidence cards showed the adjudicators matches from a
  fixed keyword list. It lacked some vendors (Groq among them), so `rw-168`, a Streamlit app that imports
  `groq`, was ruled "no" on a thin card although five tools flagged it. I changed that row by hand after
  reading the file (the row carries a `correction` note), which is an edit by the benchmark's author and not
  an adjudicator ruling. The cards were not re-run, and other keyword gaps may exist.
* **Tool versions.** vet's version string was not captured in the run manifest (the recorded value is a
  telemetry warning); the pinned commit is recorded, and the installed binary reports the same commit.
* **Not independent, not human-reviewed, offline, one sample.** See the first paragraph and PROTOCOL.md.
"""


def load(path: Path | None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def render(args: argparse.Namespace) -> str:
    summary = load(args.summary)
    run_manifest = load(args.run_manifest) or {}
    manifest = {r["id"]: r for r in read_jsonl(args.manifest)}
    labels = {r["id"]: r for r in read_jsonl(args.labels)}
    results = {p.stem: {r["id"]: r for r in read_jsonl(p)} for p in sorted(args.results.glob("*.jsonl"))}
    names = Names(run_manifest)
    findings = args.findings.read_text(encoding="utf-8") if args.findings else "(no findings text supplied)\n"
    missed = summary["positives_missed_by_every_tool"]
    manifest_rows = read_jsonl(args.manifest)
    excluded = load_excluded(args.exclusions)
    shared = load_shared(args.vocab)
    vocab = load(args.vocab) if args.vocab.exists() else None
    causes_path = args.results / "shadowscan-incomplete-causes.json"
    parts = [
        "# Real-world Shadow-AI discovery benchmark: results",
        "",
        "> **Read this first.** The benchmark was designed and run by an AI agent working in the ShadowScan "
        "repository, and ShadowScan is one of the tools scored: it is **not independent**. The ground truth is a "
        "deterministic oracle plus language-model adjudication of disagreements, **not human review**. Tools ran "
        "**offline** at pinned versions on one dated sample of public GitHub and GitLab repositories, so these "
        "numbers are not field precision or recall, and nothing here ranks the tools. Nothing was committed to "
        "version control while the benchmark ran, so the order in which things were written is evidenced only by the hash freeze at the "
        "end of this report. [PROTOCOL.md](PROTOCOL.md) gives the design, its limits and its changes.",
        "",
        "## Findings",
        "",
        findings.rstrip(),
        "",
        "## Corpus",
        "",
        corpus(summary, manifest),
        "",
        "## Tools and how they were run",
        "",
        tools_table(summary, names, run_manifest),
        "",
        "## Headline: random-draw frames only",
        "",
        "The `probability` class (`pypi-ai`, `pypi-other`, `go-ai`, `go-random`, `gitlab-random`) is the only "
        "scope that is a random draw from a defined frame. Recall is measured on that frame's positives (many "
        "from `pypi-ai`, whose positives are Python projects declaring a known AI package) and specificity on "
        "its negatives. A scan the tool itself calls incomplete counts as an error: a miss on a positive, outside "
        "the denominator on a negative. Rows are in alphabetical order; no row is better than another by position.",
        "",
        headline(summary, names),
        "",
        "![Recall and specificity with 95% intervals, random-draw frames](results/headline.svg)",
        "",
        composition_note(summary, names),
        "",
        POLICY_CAPTION,
        "",
        "## Recall and specificity by class and frame",
        "",
        "`search`, `list` and `challenge` frames are not random draws and are shown separately, never pooled "
        "into the headline.",
        "",
        "Recall:",
        "",
        per_class(summary, names, "recall"),
        "",
        "Specificity:",
        "",
        per_class(summary, names, "specificity"),
        "",
        "Recall by frame (positives found / positives):",
        "",
        per_frame(summary, names, "recall"),
        "",
        "Specificity by frame (negatives cleared / negatives):",
        "",
        per_frame(summary, names, "specificity"),
        "",
        "## Sensitivity to the error policy (random-draw frames)",
        "",
        sensitivity(summary, names),
        "",
        radar_sensitivity(manifest_rows, labels, results, excluded, shared),
        "",
        "## Sensitivity to the detection rule (random-draw frames)",
        "",
        "Each tool's headline rule leaves out what its own taxonomy files under classical ML or says is not an "
        "independent signal; the variants count everything.",
        "",
        detection_rules(summary, names),
        "",
        "## Sensitivity to the label definition (all frames pooled, descriptive)",
        "",
        label_variants(summary, names, "all"),
        "",
        "## What kind of evidence each tool finds",
        "",
        "Recall on primary positives (all frames) that have each kind of evidence; the groups overlap.",
        "",
        evidence(summary, names),
        "",
        "### Does the oracle favour ShadowScan?",
        "",
        "The registry that labels repositories overlaps with ShadowScan's vocabulary more than with other tools'. "
        "This splits the positives by whether a tool other than ShadowScan mentions their supporting technologies "
        "(`registry/vocab-overlap.json`). A tool whose recall collapses on the second group lacks the vocabulary; "
        "if ShadowScan alone does well there, the registry may favour it.",
        "",
        vocabulary(summary, names),
        "",
        vocabulary_detail(manifest_rows, labels, results, excluded, vocab, names),
        "",
        "## Pairwise comparisons (exact McNemar, Holm-corrected)",
        "",
        "Only pairs with adjusted p < 0.05 are listed. Pooled sample, descriptive.",
        "",
        "Random-draw frames:",
        "",
        pairwise(summary, names, "probability"),
        "",
        "All frames:",
        "",
        pairwise(summary, names, "all"),
        "",
        "## Unique finds and coverage",
        "",
        unique(summary, names),
        "",
        f"Union recall of the real tools: {ci(summary['union_recall'])}. {len(missed)} primary positive(s) were "
        "missed by every real tool:",
        "",
        listing(missed, manifest, labels),
        "",
        "## Ambiguous repositories",
        "",
        "Repositories the oracle could not call (evidence only in tests or documentation, weak-only, or AI-adjacent "
        "only). Not in the primary set. `D` detected, `-` clean, `E` error or incomplete scan.",
        "",
        ambiguous(summary, manifest, names),
        "",
        "## Positive predictive value at assumed prevalences (random-draw frames)",
        "",
        "From each tool's sensitivity and specificity above; a scenario, not a measurement. Flagging 1 in 20 clean "
        "repositories matters when scanning thousands.",
        "",
        prevalence(summary, names),
        "",
        "## ShadowScan",
        "",
        shadowscan_notes(summary, manifest, results, load(causes_path if causes_path.exists() else None)),
        "",
        "## Timeouts and harness failures re-run alone",
        "",
        "The first run used many workers on few CPUs. Every pair that ended in a timeout, a kill or an adapter "
        "exception was re-run once with two workers (`rerun_errors.py`); the headline above stays the first run, "
        "and this table shows what changes if the re-run rows are used instead.",
        "",
        rerun_section(summary, load(args.rerun_summary), args.rerun_dir, names),
        "",
        "## Adjudication",
        "",
        adjudication(summary, names, load(args.adjudication_report)),
        "",
        "## Tools considered but not scored",
        "",
        table(["Tool", "Why not"], [list(x) for x in NOT_SCORED]),
        "",
        "## Deviations and limitations",
        "",
        LIMITATIONS,
        "## Reproducibility",
        "",
        versions(run_manifest),
        "",
        freeze_section(load(args.freeze), run_manifest),
        "",
        "Rows per tool (the scored manifest has "
        + str(len(manifest_rows))
        + " repositories; every tool should have one row each):",
        "",
        row_counts(results, manifest_rows),
        "",
        unfrozen_hashes(),
        "",
    ]
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--run-manifest", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--freeze", type=Path)
    parser.add_argument("--adjudication-report", type=Path)
    parser.add_argument("--rerun-summary", type=Path, help="summary.json scored on the merged re-run results")
    parser.add_argument("--rerun-dir", type=Path, help="directory written by rerun_errors.py --out")
    parser.add_argument("--vocab", type=Path, default=HERE / "registry" / "vocab-overlap.json")
    parser.add_argument("--exclusions", type=Path, default=HERE / "exclusions.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    text = render(args)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        summary = load(args.summary)
        names = Names(load(args.run_manifest) or {})
        (args.output.parent / "results").mkdir(exist_ok=True)
        (args.output.parent / "results" / "headline.svg").write_text(
            forest_svg(summary, names), encoding="utf-8"
        )
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
