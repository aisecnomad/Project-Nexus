"""Describe the scored corpus: ``python -m tools.benchmark.realworld.corpus_summary > CORPUS.md``.

Generated from ``manifest.jsonl`` and ``labels.jsonl`` only, so it can be checked by anyone with the
two files. It reports what is in the sample before any tool result exists.
"""

# ruff: noqa: E501  (long prose strings in the generated document)
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from tools.benchmark.realworld.score import CLASS_ORDER, frame_class, load_excluded, read_jsonl

HERE = Path(__file__).resolve().parent


def state(label: dict[str, Any]) -> str:
    lab = label["labels"]
    return "ai-library" if lab["role"] != "consumer" else str(lab["state"])


def table(header: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def main() -> int:
    manifest = read_jsonl(HERE / "manifest.jsonl")
    labels = {r["id"]: r for r in read_jsonl(HERE / "labels.jsonl")}
    by_frame: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for row in manifest:
        by_frame[row["frame"]][state(labels[row["id"]])] += 1
    out = [
        "# Corpus summary (generated)",
        "",
        f"{len(manifest)} scored repositories; oracle version "
        f"{next(iter(labels.values()))['oracle_version']}.",
        "",
        "## Frames and oracle states",
        "",
    ]
    rows = []
    for frame, counts in sorted(by_frame.items(), key=lambda kv: (frame_class(kv[0]), kv[0])):
        rows.append([frame, frame_class(frame), sum(counts.values()), counts["positive"], counts["negative"],
                     counts["ambiguous"], counts["ai-library"]])  # fmt: skip
    totals = Counter[str]()
    for counts in by_frame.values():
        totals.update(counts)
    rows.append(
        [
            "**all**",
            "",
            len(manifest),
            totals["positive"],
            totals["negative"],
            totals["ambiguous"],
            totals["ai-library"],
        ]
    )
    out += [table(["frame", "class", "repos", "positive", "negative", "ambiguous", "ai-library"], rows), ""]
    excluded = load_excluded(HERE / "exclusions.json")
    primary = [
        r for r in manifest if r["id"] not in excluded and state(labels[r["id"]]) in {"positive", "negative"}
    ]
    positives = [r for r in primary if state(labels[r["id"]]) == "positive"]
    app = sum(1 for r in primary if labels[r["id"]]["labels"]["app_strict"])
    cfg = sum(1 for r in primary if labels[r["id"]]["labels"]["devcfg_only"])
    agent = sum(1 for r in primary if labels[r["id"]]["labels"]["agent_strict"])
    llm_only = sum(
        1
        for r in positives
        if labels[r["id"]]["labels"]["llm_strict"] and not labels[r["id"]]["labels"]["agent_strict"]
    )
    by_class = Counter(frame_class(r["frame"]) for r in primary)
    pos_by_class = Counter(frame_class(r["frame"]) for r in positives)
    owners = {(r["host"], r["owner"].lower()) for r in manifest}
    cap = json.loads((HERE / "sampling-summary.json").read_text())["max_per_owner"]
    named = sorted(excluded & {r["id"] for r in manifest})
    active = [rid for rid in named if state(labels[rid]) in {"positive", "negative"}]
    libraries = [rid for rid in named if rid not in active]
    out += [
        "## Primary analysis set",
        "",
        f"{len(primary)} repositories: the {len(manifest)} scored, less {totals['ambiguous']} ambiguous and "
        f"{totals['ai-library']} AI-library repositories, and less {len(active)} repository "
        f"({', '.join(active) or 'none'}) that a file of the ShadowScan repository names. "
        f"A second named repository ({', '.join(libraries) or 'none'}) is an AI library and was already out.",
        "",
        table(
            ["class", "primary repositories", "of which positive"],
            [[c, by_class[c], pos_by_class[c]] for c in CLASS_ORDER],
        ),
        "",
        f"Among the {len(positives)} positives: {agent} involve an agent-type artifact (agent framework, MCP, "
        f"coding-agent configuration), {llm_only} are LLM-SDK use only, {app} have application-level evidence "
        f"(dependency, import, workflow, IaC), and {cfg} are developer-tooling configuration only (for example "
        "AGENTS.md, CLAUDE.md, .mcp.json).",
        "",
        "This benchmark therefore measures mostly agent-type integrations; plain LLM-SDK use is a small share.",
        "",
    ]
    langs = Counter(labels[r["id"]]["inventory"]["primary_language"] for r in primary)
    hosts = Counter(r["host"] for r in manifest)
    sizes = sorted(r["bytes"] for r in manifest)
    links = sum(r["symlinks"] for r in manifest)
    neutralised = sum(r["symlinks_neutralized"] for r in manifest)
    out += [
        "## Languages (primary set, by most common source extension)",
        "",
        table(["language", "repos"], [[k, v] for k, v in langs.most_common()]),
        "",
        "## Hosts and size",
        "",
        table(["host", "repos"], [[k, v] for k, v in hosts.most_common()]),
        "",
        f"Snapshot size: median {sizes[len(sizes) // 2] / 1e6:.1f} MB, max {sizes[-1] / 1e6:.1f} MB. At sampling "
        f"time {links} symlinks were recorded and {neutralised} neutralised by the first (lexical) check; a later "
        "physical-resolution audit of the stored corpus neutralised 19 more (PROTOCOL.md section 3.2).",
        "",
        "## Owners",
        "",
        f"{len(owners)} distinct owners (cap {cap} per owner).",
        "",
    ]
    sys.stdout.write("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
