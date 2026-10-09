"""Build ``corpus.json`` from the labeler sheets and the pinned checkouts.

``python -m tools.benchmark_realworld.build_manifest --checkout-root /home/user``

Inputs (all committed under ``labels/``):
- ``labeler-a.tsv``: id, checkout dir, repository slug, stratum, label, confidence, evidence.
- ``labeler-b.json``: the second labeler's label and confidence per id.
- ``adjudication.json``: a decision, its evidence and its reason for every disagreement
  and every ambiguous label. A disagreement without a decision stops the build.

SHAs and licenses are read from the checkouts, not typed in. The result is
validated before it is written.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.benchmark_realworld.cases import checkout_head, detect_license, validate_manifest

HERE = Path(__file__).resolve().parent


def build(checkout_root: Path, labels_dir: Path) -> dict[str, Any]:
    labeler_b = json.loads((labels_dir / "labeler-b.json").read_text(encoding="utf-8"))["labels"]
    adjudication = json.loads((labels_dir / "adjudication.json").read_text(encoding="utf-8"))["decisions"]
    repos: list[dict[str, Any]] = []
    for line in (labels_dir / "labeler-a.tsv").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rid, dirname, slug, stratum, label_a, conf_a, evidence = line.split("\t")
        root = checkout_root / dirname
        b = labeler_b[rid]
        entry: dict[str, Any] = {
            "id": rid,
            "repo": slug,
            "url": f"https://github.com/{slug}",
            "dir": dirname,
            "sha": checkout_head(root),
            "license": detect_license(root),
            "stratum": stratum,
            "labels": {"A": label_a, "B": b["label"]},
        }
        if label_a == b["label"] and rid not in adjudication:
            entry["label"] = label_a
            entry["confidence"] = "high" if conf_a == "high" and b["confidence"] == "high" else "medium"
            entry["evidence"] = [part.strip() for part in evidence.split(";") if part.strip()]
            if label_a == "ambiguous":
                raise SystemExit(f"{rid}: both labelers say ambiguous; add an adjudication decision")
        else:
            if rid not in adjudication:
                raise SystemExit(f"{rid}: labelers disagree ({label_a} vs {b['label']}); no adjudication")
            decision = adjudication[rid]
            entry["label"] = decision["label"]
            entry["confidence"] = decision["confidence"]
            entry["evidence"] = decision["evidence"]
            entry["adjudication"] = decision["reason"]
            if "candidates" in decision:
                entry["candidates"] = decision["candidates"]
        if entry["label"] == "ambiguous" and "candidates" not in entry:
            entry["candidates"] = b.get("candidates", ["llm", "agent"])
        repos.append(entry)
    doc = {"version": 1, "repos": sorted(repos, key=lambda e: e["id"])}
    validate_manifest(doc)
    return doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--checkout-root", type=Path, required=True)
    parser.add_argument("--labels", type=Path, default=HERE / "labels")
    parser.add_argument("--output", type=Path, default=HERE / "corpus.json")
    args = parser.parse_args(argv)
    doc = build(args.checkout_root, args.labels)
    args.output.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for entry in doc["repos"]:
        counts[entry["label"]] = counts.get(entry["label"], 0) + 1
    print(f"wrote {len(doc['repos'])} repositories to {args.output}: {dict(sorted(counts.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
