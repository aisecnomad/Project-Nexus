"""Verify a frozen public corpus against two independent annotation records.

This checks the recorded labeling process and content integrity. Reviewer names
are declarations, not authenticated identities or external certification.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from shadowscan.utils.files import read_policy_text
from tools.evaluation.evaluate import CorpusError, _keys, _unique_pairs, load_corpus

MAX_ANNOTATION_BYTES = 1_000_000


def validate_annotations(corpus: Path, annotations: Path) -> dict[str, Any]:
    metadata, cases, digest = load_corpus(corpus)
    if annotations.is_symlink() or not annotations.is_file() or annotations.stat().st_size > MAX_ANNOTATION_BYTES:
        raise CorpusError("annotations must be a regular, nonsymlink file of at most 1 MB")
    try:
        ledger = json.loads(read_policy_text(annotations, max_bytes=MAX_ANNOTATION_BYTES), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CorpusError("invalid annotation JSON") from exc
    _keys(ledger, {"schema", "corpus_sha256", "method", "selection", "reviewers", "adjudications"}, set(), "annotations")
    if type(ledger["schema"]) is not int or ledger["schema"] != 1 or ledger["corpus_sha256"] != digest:
        raise CorpusError("annotation schema or frozen corpus digest mismatch")
    if not isinstance(ledger["method"], str) or ledger["method"] not in {
        "independent-ai-double-label-before-scan", "independent-human-double-label-before-scan",
    }:
        raise CorpusError("unsupported annotation method; record the actual labeling process")
    if not isinstance(ledger["selection"], str) or not 1 <= len(ledger["selection"]) <= 2000:
        raise CorpusError("selection must describe the sampling limitations")
    if metadata["type"] not in {"public-pinned", "adjudicated"} or any(case.source is None for case in cases):
        raise CorpusError("independent public evaluation requires attributed source for every case")
    positives = sum(case.present for case in cases)
    negatives = len(cases) - positives
    if len(cases) < 20 or not positives or negatives < 2 * positives:
        raise CorpusError("corpus requires at least 20 cases, positives, and at least two negatives per positive")
    repositories = sorted({case.source["repo"] for case in cases if case.source})
    if len(repositories) < 3:
        raise CorpusError("corpus requires at least three independent source repositories")
    reviewers = ledger["reviewers"]
    if not isinstance(reviewers, list) or len(reviewers) != 2:
        raise CorpusError("exactly two independently recorded reviewers are required")
    expected = {case.id: case.present for case in cases}
    identities: set[str] = set()
    ballots: list[dict[str, bool]] = []
    for reviewer in reviewers:
        _keys(reviewer, {"id", "labels"}, set(), "reviewer")
        identity = reviewer["id"]
        if not isinstance(identity, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,79}", identity) or identity in identities:
            raise CorpusError("reviewer IDs must be distinct nonempty identifiers")
        identities.add(identity)
        if not isinstance(reviewer["labels"], list) or len(reviewer["labels"]) != len(cases):
            raise CorpusError("each reviewer must label every frozen case")
        ballot = {}
        for label in reviewer["labels"]:
            _keys(label, {"case_id", "present", "reason"}, set(), "label")
            case_id = label["case_id"]
            if not isinstance(case_id, str) or case_id not in expected or case_id in ballot:
                raise CorpusError("unknown or duplicate annotation case")
            if type(label["present"]) is not bool or not isinstance(label["reason"], str) or not 1 <= len(label["reason"]) <= 2000:
                raise CorpusError("annotations require boolean labels and source-based reasons")
            ballot[case_id] = label["present"]
        ballots.append(ballot)
    resolutions = ledger["adjudications"]
    if not isinstance(resolutions, list):
        raise CorpusError("adjudications must be a list")
    resolved = {}
    for resolution in resolutions:
        _keys(resolution, {"case_id", "present", "reason"}, set(), "adjudication")
        case_id = resolution["case_id"]
        if not isinstance(case_id, str) or case_id not in expected or case_id in resolved:
            raise CorpusError("unknown or duplicate adjudication")
        if type(resolution["present"]) is not bool or not isinstance(resolution["reason"], str) or not 1 <= len(resolution["reason"]) <= 2000:
            raise CorpusError("adjudications require boolean labels and source-based reasons")
        if ballots[0][case_id] == ballots[1][case_id]:
            raise CorpusError("adjudication may only resolve a recorded disagreement")
        resolved[case_id] = resolution["present"]
    disagreements = 0
    for case_id, expected_label in expected.items():
        first, second = ballots[0][case_id], ballots[1][case_id]
        if first != second:
            disagreements += 1
            if case_id not in resolved:
                raise CorpusError(f"unresolved annotation disagreement: {case_id}")
            label = resolved[case_id]
        else:
            label = first
        if label != expected_label:
            raise CorpusError(f"frozen label disagrees with recorded annotations: {case_id}")
    return {
        "corpus_sha256": digest,
        "cases": len(cases),
        "positive_cases": positives,
        "negative_cases": negatives,
        "source_repositories": repositories,
        "reviewers": sorted(identities),
        "initial_agreement": (len(cases) - disagreements) / len(cases),
        "adjudicated_disagreements": disagreements,
        "method": ledger["method"],
        "selection": ledger["selection"],
        "assurance": (
            "Recorded independent AI annotation, not human validation or representative field accuracy."
            if ledger["method"] == "independent-ai-double-label-before-scan"
            else "Declared independent human annotation; identities are not authenticated and field representativeness is not established."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--annotations", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(validate_annotations(args.corpus, args.annotations), indent=2, sort_keys=True))
        return 0
    except (CorpusError, OSError, ValueError, RecursionError) as exc:
        print(f"annotation validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
