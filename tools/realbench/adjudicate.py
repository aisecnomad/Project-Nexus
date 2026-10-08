"""Build blind adjudication packets and fold the decisions back in (PROTOCOL.md §5 and §9).

``python -m tools.realbench.adjudicate prerun --a A.jsonl --b B.jsonl --manifest corpus.json --output DIR``
    One packet per repository where the annotators disagree. The two
    annotations appear as "Annotation 1" and "Annotation 2" in a seeded random
    order, so the adjudicator cannot tell which strategy or model wrote which.

``python -m tools.realbench.adjudicate postrun --labels L.json --results R --manifest M.json --output DIR``
    One packet per repository where any tool's verdict disagrees with the
    frozen label. The packet lists the frozen label with its evidence and the
    union of files the tools cited, each with the number of tools citing it,
    and never a tool name.

``python -m tools.realbench.adjudicate localisation --results DIR --output sample.json``
    A seeded sample of up to ``PER_TOOL`` cited files per tool, pooled and
    shuffled, for a blind file-level audit.

``python -m tools.realbench.adjudicate apply --labels L.json --decisions D.jsonl --output adjudicated.json``
``python -m tools.realbench.adjudicate audit --sample S.json --decisions D.jsonl --output localisation.json``
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from tools.benchmark.score import wilson
from tools.realbench.labels import _by_id, disagreements, load, redact
from tools.realbench.score import load_results, truth, verdict

SEED = 20261008
PER_TOOL = 25
MAX_POOLED = 40
VALID_FILE_VERDICTS = frozenset({"ai-evidence", "assistant-artifact"})


def _annotation_block(row: dict[str, Any]) -> list[str]:
    lines = [
        f"- label: `{row['label']}`; assistant_artifacts: {row['assistant_artifacts']}; "
        f"subtypes: {row.get('subtypes') or []}; confidence: {row.get('confidence')}",
    ]
    for e in row.get("evidence") or []:
        excerpt = redact(str(e.get("excerpt", "")))
        lines.append(f"  - {e.get('path')}:{e.get('line')} [{e.get('criterion')}] `{excerpt}`")
    if row.get("notes"):
        lines.append(f"- notes: {redact(str(row['notes']))[:300]}")
    return lines


def prerun(
    a_rows: list[dict[str, Any]], b_rows: list[dict[str, Any]], repos: dict[str, Any], out: Path
) -> list[str]:
    a, b = _by_id(a_rows), _by_id(b_rows)
    ids = disagreements(a_rows, b_rows)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(f"{SEED}:prerun")
    order = {}
    for i in ids:
        first, second = (a[i], b[i]) if rng.random() < 0.5 else (b[i], a[i])
        order[i] = [first["annotator"], second["annotator"]]
        repo = repos[i]
        text = [
            f"# Adjudication packet {i}",
            f"Checkout: /home/user/rwbench/corpus/{i}/  (url {repo['url']}, commit {repo['sha']})",
            "",
            "## Annotation 1",
            *_annotation_block(first),
            "",
            "## Annotation 2",
            *_annotation_block(second),
            "",
        ]
        (out / f"{i}.md").write_text("\n".join(text), encoding="utf-8")
    (out / "order.json").write_text(json.dumps(order, indent=1) + "\n", encoding="utf-8")
    return ids


def postrun(
    labels: dict[str, dict[str, Any]], results: dict[str, dict[str, Any]], repos: dict[str, Any], out: Path
) -> list[str]:
    """Packets for repositories where any tool's verdict (strict or evidence rule) contradicts the label."""
    out.mkdir(parents=True, exist_ok=True)
    queued = []
    for rid, lab in sorted(labels.items()):
        contrary: set[str] = set()
        cited: dict[str, int] = defaultdict(int)
        for rows in results.values():
            row = rows[rid]
            for path in row.get("paths") or []:
                cited[path] += 1
            for task in ("t1", "t2"):
                if task == "t2" and row["agentic"] is None:
                    continue
                said = verdict(row, task, "evidence")
                if said is not None and said != truth(lab, task):
                    contrary.add(task)
        if not contrary:
            continue
        queued.append(rid)
        repo = repos[rid]
        pooled = sorted(cited.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_POOLED]
        text = [
            f"# Post-run adjudication packet {rid}",
            f"Checkout: /home/user/rwbench/corpus/{rid}/  (url {repo['url']}, commit {repo['sha']})",
            f"At least one tool disagreed with the frozen label on: {', '.join(sorted(contrary))}"
            " (t1 = generative-AI use, t2 = agent).",
            "",
            "## Frozen label",
            *_annotation_block({**lab, "confidence": "frozen"}),
            "",
            "## Files cited as AI evidence by the tools (number of tools citing each; tool names withheld)",
            *(f"- {path} ({n})" for path, n in pooled),
            *(["- (no file cited)"] if not pooled else []),
            "",
        ]
        (out / f"{rid}.md").write_text("\n".join(text), encoding="utf-8")
    return queued


def localisation_sample(results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Seeded sample of cited files per tool; each (repository, file) is judged once."""
    rng = random.Random(f"{SEED}:localisation")
    picks: dict[tuple[str, str], set[str]] = defaultdict(set)
    for tool in sorted(results):
        cited = sorted(
            {
                (rid, path)
                for rid, row in results[tool].items()
                if verdict(row, "t1", "evidence")
                for path in row["paths"]
            }
        )
        for pick in rng.sample(cited, min(PER_TOOL, len(cited))):
            picks[pick].add(tool)
    items: list[dict[str, Any]] = [
        {"key": f"{rid}::{path}", "id": rid, "path": path, "tools": sorted(t)}
        for (rid, path), t in sorted(picks.items())
    ]
    rng.shuffle(items)
    for number, entry in enumerate(items, start=1):
        entry["item"] = number
    return items


def apply(labels_doc: dict[str, Any], decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a copy of the frozen labels with post-run decisions applied, each change recorded."""
    by_id = _by_id(decisions)
    out = []
    for lab in labels_doc["labels"]:
        d = by_id.get(lab["id"])
        if d is None or (
            d["label"] == lab["label"] and d["assistant_artifacts"] == lab["assistant_artifacts"]
        ):
            out.append({**lab, "postrun": {"reviewed": d is not None, "changed": False}})
            continue
        subtypes = sorted(set(d.get("subtypes") or []))
        new_evidence = [
            {**e, "excerpt": redact(str(e.get("excerpt", "")))} for e in (d.get("evidence") or [])[:5]
        ]
        out.append(
            {
                **lab,
                "evidence": new_evidence + [e for e in lab.get("evidence") or [] if e not in new_evidence],
                "label": d["label"],
                "assistant_artifacts": d["assistant_artifacts"],
                "subtypes": subtypes if d["label"] != "none" else [],
                "ml_only": d["label"] == "none" and bool(lab.get("ml_only")),
                "postrun": {
                    "reviewed": True,
                    "changed": True,
                    "from": lab["label"],
                    "from_assistant": lab["assistant_artifacts"],
                    "reason": redact(str(d.get("reason", "")))[:400],
                },
            }
        )
    return {"labels": out, "agreement": labels_doc.get("agreement")}


def audit(sample: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> dict[str, Any]:
    judged = {d["item"]: d for d in decisions}
    per_tool: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for item in sample:
        d = judged.get(item["item"])
        if d is None:
            continue
        valid = d.get("verdict") in VALID_FILE_VERDICTS
        for tool in item["tools"]:
            per_tool[tool][0] += valid
            per_tool[tool][1] += 1
    return {
        tool: {"n": n, "valid": k, "precision": wilson(k, n)} for tool, (k, n) in sorted(per_tool.items())
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prerun")
    p.add_argument("--a", type=Path, required=True)
    p.add_argument("--b", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    q = sub.add_parser("postrun")
    q.add_argument("--labels", type=Path, required=True)
    q.add_argument("--results", type=Path, required=True)
    q.add_argument("--manifest", type=Path, required=True)
    q.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("localisation")
    s.add_argument("--results", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    ap = sub.add_parser("apply")
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--decisions", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    au = sub.add_parser("audit")
    au.add_argument("--sample", type=Path, required=True)
    au.add_argument("--decisions", type=Path, required=True)
    au.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command in ("prerun", "postrun"):
        repos = {r["id"]: r for r in json.loads(args.manifest.read_text(encoding="utf-8"))["repos"]}
    if args.command == "prerun":
        ids = prerun(load(args.a), load(args.b), repos, args.output)
        print(f"{len(ids)} packet(s): {','.join(ids)}")
    elif args.command == "postrun":
        labels = {r["id"]: r for r in json.loads(args.labels.read_text(encoding="utf-8"))["labels"]}
        ids = postrun(labels, load_results(args.results), repos, args.output)
        print(f"{len(ids)} packet(s): {','.join(ids)}")
    elif args.command == "localisation":
        sample = localisation_sample(load_results(args.results))
        args.output.write_text(json.dumps(sample, indent=1) + "\n", encoding="utf-8")
        print(f"{len(sample)} file(s) to judge")
    elif args.command == "apply":
        doc = apply(json.loads(args.labels.read_text(encoding="utf-8")), load(args.decisions))
        args.output.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        print(f"{sum(1 for r in doc['labels'] if r['postrun']['changed'])} label(s) changed")
    else:
        sample = json.loads(args.sample.read_text(encoding="utf-8"))
        result = audit(sample, load(args.decisions))
        args.output.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        print(json.dumps({t: v["precision"][0] for t, v in result.items()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
