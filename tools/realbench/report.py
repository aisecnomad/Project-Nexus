"""Render the Markdown results report from the scorer's summary.

``python -m tools.realbench.report --summary summary.json --results DIR --labels labels.json
--manifest corpus.json [--localisation localisation.json] --output REPORT.md``
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from tools.realbench.adapters import ADAPTERS

DISPLAY = {a.name: a.display for a in ADAPTERS}
ORDER = [a.name for a in ADAPTERS]
TASKS = {"t1": "T1: generative-AI use (agent or llm vs none)", "t2": "T2: AI agents (agent vs llm or none)"}


def ci(triple: Any) -> str:
    if not triple or triple[0] is None:
        return "–"
    p, lo, hi = triple
    return f"{p:.2f} ({lo:.2f}–{hi:.2f})"


def num(x: float | None, digits: int = 2) -> str:
    return "–" if x is None else f"{x:.{digits}f}"


def interval(value: float, bounds: Any) -> str:
    return f"{value:.2f} ({bounds[0]:.2f}–{bounds[1]:.2f})" if bounds else f"{value:.2f}"


def _tools(scored: dict[str, Any]) -> list[str]:
    return [t for t in ORDER if t in scored["tools"]]


def headline(scored: dict[str, Any], task: str, out: list[str], compare: dict[str, Any] | None) -> None:
    w = out.append
    tools = [t for t in _tools(scored) if f"{task}:primary" in scored["tools"][t]]
    extra = " | MCC, adjudicated labels" if compare else ""
    w(f"| Tool | n | TP | FP | FN | TN | No verdict | Recall | Specificity | Precision | F1 | MCC{extra} |")
    w("|---|---|---|---|---|---|---|---|---|---|---|---|" + ("---|" if compare else ""))
    rows = sorted(tools, key=lambda t: -scored["tools"][t][f"{task}:primary"]["mcc"])
    for t in rows:
        m = scored["tools"][t][f"{task}:primary"]
        cells = [
            DISPLAY.get(t, t), str(m["n"]), str(m["tp"]), str(m["fp"]), str(m["fn"]), str(m["tn"]),
            str(m["no_verdict"]), ci(m["recall"]), ci(m["specificity"]), ci(m["precision"]),
            interval(m["f1"], m["ci"]["f1"]), interval(m["mcc"], m["ci"]["mcc"]),
        ]  # fmt: skip
        if compare:
            other = compare["tools"].get(t, {}).get(f"{task}:primary")
            cells.append(interval(other["mcc"], other["ci"]["mcc"]) if other else "–")
        w("| " + " | ".join(cells) + " |")
    w("")


def secondary(scored: dict[str, Any], task: str, out: list[str]) -> None:
    w = out.append
    pops = ["primary"] + [
        p
        for p in ("footprint", "no_ml", "t2_without_assistant_negatives")
        if task == "t2" or p != "t2_without_assistant_negatives"
    ]
    head = [
        "Tool",
        "Primary (strict)",
        "Completed scans only",
        "Evidence rule",
        "Footprint",
        "Without ML-only",
    ]
    if task == "t2":
        head.append("T2 without assistant-file negatives")
    w("| " + " | ".join(head) + " |")
    w("|" + "---|" * len(head))
    for t in _tools(scored):
        entry = scored["tools"][t]
        if f"{task}:primary" not in entry:
            continue
        prim = entry[f"{task}:primary"]
        cells = [
            DISPLAY.get(t, t),
            num(prim["mcc"]),
            num(prim["completed_only"]["mcc"]),
            num(prim["evidence_rule"]["mcc"]),
        ]
        for pop in pops[1:]:
            block = entry.get(f"{task}:{pop}")
            cells.append(num(block["mcc"]) if block else "–")
        w("| " + " | ".join(cells) + " |")
    w("")


def _source_tree(commit: str | None) -> str | None:
    """The git tree id of ``shadowscan/`` at ``commit``: identical ids mean identical scanner source."""
    if not commit:
        return None
    try:
        return subprocess.run(
            ["git", "rev-parse", f"{commit}:shadowscan"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def render(summary: dict[str, Any], run_manifest: dict[str, Any], labels: list[dict[str, Any]],
           manifest: dict[str, Any], localisation: dict[str, Any] | None) -> str:  # fmt: skip
    frozen = summary["frozen"]
    adjudicated = summary.get("adjudicated")
    primary = adjudicated or frozen
    out: list[str] = []
    w = out.append
    repos = manifest["repos"]
    by_id = {r["id"]: r for r in repos}
    counts = Counter(lab["label"] for lab in labels)
    assistant_only = sum(1 for lab in labels if lab["label"] == "none" and lab["assistant_artifacts"])
    w("# Real-world shadow-AI discovery benchmark: results\n")
    tree = _source_tree(run_manifest.get("shadowscan_commit"))
    w(
        f"{len(repos)} public repositories ({Counter(r['host'] for r in repos)['github']} GitHub, "
        f"{Counter(r['host'] for r in repos)['gitlab']} GitLab), each pinned to a commit, drawn by the "
        "pre-registered procedure in [PROTOCOL.md](PROTOCOL.md). Every tool ran offline on a read-only "
        f"checkout. ShadowScan commit `{run_manifest.get('shadowscan_commit')}`"
        + (f" (source tree `{tree}`)" if tree else "")
        + f"; Python {run_manifest.get('python')} on {run_manifest.get('platform')}.\n"
    )
    w(
        "**Read this first.** Labels come from two independent AI annotators and an AI adjudicator, not from "
        "human reviewers. The corpus over-represents AI projects, so precision depends on prevalence (see "
        "below). The harness lives in the ShadowScan repository; see the protocol's conflict-of-interest "
        "section. Intervals are 95% Wilson (proportions) or 2,000-sample bootstrap (F1, MCC).\n"
    )
    w("## Tools\n")
    w("| Tool | Upstream | How it ran | Counted as an agent |")
    w("|---|---|---|---|")
    for run in sorted(
        run_manifest.get("runs", []), key=lambda x: ORDER.index(x["tool"]) if x["tool"] in ORDER else 99
    ):
        w(f"| {run['display']} | `{run['source']}` | {run['mode']} | {run['agentic_rule']} |")
    w("")
    w("## Corpus and labels\n")
    w(f"- Labels: {counts['agent']} `agent`, {counts['llm']} `llm`, {counts['none']} `none` "
      f"({assistant_only} of them assistant-only, excluded from the primary population).")  # fmt: skip
    agree = summary.get("agreement") or {}
    if agree:
        assist = agree["assistant_artifacts"]
        w(
            f"- Annotator agreement before adjudication (n={agree['n']}): three-class label "
            f"{agree['label']['agreement']:.2f} (κ {num(agree['label']['kappa'])}); T1 "
            f"{agree['t1_genai']['agreement']:.2f} (κ {num(agree['t1_genai']['kappa'])}); T2 "
            f"{agree['t2_agent']['agreement']:.2f} (κ {num(agree['t2_agent']['kappa'])}); assistant files "
            f"{assist['agreement']:.2f} (κ {num(assist['kappa'])})."
        )
    changes = summary.get("label_changes") or []
    if adjudicated is not None:
        w(f"- Post-run blind adjudication changed {len(changes)} label(s); both result sets are shown.")
    w("")
    for task, title in TASKS.items():
        w(f"## {title}\n")
        w(
            "Primary population, pre-registered strict verdict rule, "
            + (
                "adjudicated labels; the last column repeats MCC on the frozen labels.\n"
                if adjudicated
                else "frozen labels.\n"
            )
        )
        headline(primary, task, out, frozen if adjudicated else None)
        w("### Secondary analyses (MCC)\n")
        secondary(primary, task, out)
    w("## Assistant-only repositories\n")
    w(
        f"{assistant_only} repositories carry only AI coding-assistant files, with no generative-AI use in "
        "code or configuration. They are outside the primary population: flagging them is a policy choice, "
        "not an error.\n"
    )
    w("| Tool | Flagged |")
    w("|---|---|")
    for t in _tools(primary):
        w(f"| {DISPLAY.get(t, t)} | {ci(primary['tools'][t].get('assistant_only_detection'))} |")
    w("")
    w("## Precision at other prevalences (T1, from recall and specificity)\n")
    w("| Tool | 1% | 5% | 20% |")
    w("|---|---|---|---|")
    for t in _tools(primary):
        p = primary["tools"][t]["t1:primary"]["ppv_at_prevalence"]
        w(f"| {DISPLAY.get(t, t)} | {num(p['0.01'])} | {num(p['0.05'])} | {num(p['0.2'])} |")
    w("")
    w("## Paired comparisons (exact McNemar, Holm-adjusted within each family)\n")
    for family, detail in primary["paired"].items():
        reference, task = family.split(":")
        w(f"**{TASKS[task]} — against {DISPLAY.get(reference, reference)}**\n")
        w("| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |")
        w("|---|---|---|---|---|---|")
        for t, d in sorted(detail.items(), key=lambda kv: kv[1]["p_holm"]):
            w(f"| {DISPLAY.get(t, t)} | {d['n']} | {d['reference_right_other_wrong']} | "
              f"{d['other_right_reference_wrong']} | {d['p']:.2g} | {d['p_holm']:.2g} |")  # fmt: skip
        w("")
    w("## Where tools find and miss AI (T1 detection rate, adjudicated labels)\n")
    for dimension, title in (
        ("stratum", "By stratum and label"),
        ("subtype", "Positives by evidence type"),
        ("trait_false_alarm", "False alarms on hard negatives by trait"),
        ("language", "By dominant language and label"),
        ("size", "By size tercile and label"),
        ("host", "By host and label"),
    ):
        keys = sorted(
            {k for t in _tools(primary) for k in primary["tools"][t]["breakdowns"].get(dimension, {})}
        )
        if not keys:
            continue
        tools = _tools(primary)
        w(f"### {title}\n")
        w("| Group | n | " + " | ".join(DISPLAY.get(t, t) for t in tools) + " |")
        w("|---|---|" + "---|" * len(tools))
        for k in keys:
            cells = []
            n = 0
            for t in tools:
                cell = primary["tools"][t]["breakdowns"][dimension].get(k)
                n = cell["n"] if cell else n
                cells.append(f"{cell['hits']}" if cell else "–")
            w(f"| {k} | {n} | " + " | ".join(cells) + " |")
        w("")
    w("## Localisation\n")
    w("| Tool | True positives | Cites an evidence file | TPs citing no file | Cited-file precision |")
    w("|---|---|---|---|---|")
    for t in _tools(primary):
        ev = primary["tools"][t]["evidence_overlap"]
        audit = (localisation or {}).get(t)
        audit_cell = ci(audit["precision"]) + f" of {audit['n']}" if audit else "–"
        cells = [
            DISPLAY.get(t, t),
            str(ev["true_positives"]),
            ci(ev["overlap"]),
            str(ev["without_paths"]),
            audit_cell,
        ]
        w("| " + " | ".join(cells) + " |")
    w("")
    w("## Run status, time and determinism\n")
    w("| Tool | ok | partial | error | Median s | p90 s | Repeat runs | Verdict flips |")
    w("|---|---|---|---|---|---|---|---|")
    for t in _tools(primary):
        rt = primary["tools"][t]["runtime"]
        st = rt["status"]
        det = summary.get("determinism", {}).get(t, {"n": 0, "flips": []})
        w(f"| {DISPLAY.get(t, t)} | {st.get('ok', 0)} | {st.get('partial', 0)} | {st.get('error', 0)} | "
          f"{num(rt['median'], 1)} | {num(rt['p90'], 1)} | {det['n']} | {len(det['flips'])} |")  # fmt: skip
    w("")
    if changes:
        w("## Labels changed by post-run adjudication\n")
        w("| Repository | Commit | Frozen | Adjudicated |")
        w("|---|---|---|---|")
        for c in changes:
            r = by_id[c["id"]]
            w(f"| [{c['id']}]({r['url']}) | `{r['sha'][:12]}` | {c['frozen']} | {c['adjudicated']} |")
        w("")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--localisation", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    run_manifest = json.loads((args.results / "run-manifest.json").read_text(encoding="utf-8"))
    label_doc = json.loads(args.labels.read_text(encoding="utf-8"))
    summary.setdefault("agreement", label_doc.get("agreement"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    localisation = json.loads(args.localisation.read_text(encoding="utf-8")) if args.localisation else None
    text = render(summary, run_manifest, label_doc["labels"], manifest, localisation)
    args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
