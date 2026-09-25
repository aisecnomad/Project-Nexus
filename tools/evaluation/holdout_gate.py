"""Run a fresh human-labeled code holdout against an explicit acceptance policy.

This verifies declared labeling and sample integrity; it cannot authenticate
reviewer identities, prove blindness, or measure deployment-wide accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from shadowscan.models import Kind
from shadowscan.utils.files import read_policy_text
from tools.evaluation.annotations import MAX_ANNOTATION_BYTES, validate_annotations
from tools.evaluation.evaluate import (
    DEFAULT_CORPUS,
    CorpusError,
    _keys,
    _unique_pairs,
    evaluate,
    load_corpus,
    summarize,
)

_KNOWN_CORPORA = (
    DEFAULT_CORPUS,
    DEFAULT_CORPUS.with_name("public_corpus.json"),
    DEFAULT_CORPUS.with_name("independent_corpus.json"),
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CorpusError(f"policy {name} must be an integer in [{minimum}, {maximum}]")
    return value


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    """Parse a strict, bounded policy whose digest is retained with the result."""
    raw = read_policy_text(path, max_bytes=16_384).encode("utf-8")
    try:
        policy = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError) as exc:
        raise CorpusError("policy must be unambiguous UTF-8 JSON") from exc
    _keys(
        policy,
        {"schema", "corpus_sha256", "annotations_sha256", "target_kinds", "minimums", "max_errors", "per_kind"},
        set(),
        "policy",
    )
    if type(policy["schema"]) is not int or policy["schema"] != 1:
        raise CorpusError("unsupported holdout policy schema")
    if not isinstance(policy["corpus_sha256"], str) or not _DIGEST.fullmatch(policy["corpus_sha256"]):
        raise CorpusError("policy corpus_sha256 must be a SHA-256 digest")
    if not isinstance(policy["annotations_sha256"], str) or not _DIGEST.fullmatch(policy["annotations_sha256"]):
        raise CorpusError("policy annotations_sha256 must be a SHA-256 digest")
    kinds = policy["target_kinds"]
    if (
        not isinstance(kinds, list)
        or not kinds
        or len(kinds) != len({kind for kind in kinds if isinstance(kind, str)})
        or any(not isinstance(kind, str) or kind not in {item.value for item in Kind} for kind in kinds)
    ):
        raise CorpusError("policy target_kinds must be distinct known finding kinds")
    minimums = _keys(policy["minimums"], {"positive", "negative", "repositories"}, set(), "minimums")
    _integer(minimums["positive"], "minimums.positive", 1, 500)
    _integer(minimums["negative"], "minimums.negative", 2, 500)
    _integer(minimums["repositories"], "minimums.repositories", 3, 500)
    limits = _keys(policy["max_errors"], {"false_positive", "false_negative"}, set(), "max_errors")
    _integer(limits["false_positive"], "max_errors.false_positive", 0, 500)
    _integer(limits["false_negative"], "max_errors.false_negative", 0, 500)
    per_kind = _keys(policy["per_kind"], set(kinds), set(), "per_kind")
    for kind, criteria in per_kind.items():
        _keys(criteria, {"minimums", "max_errors"}, set(), f"per_kind.{kind}")
        samples = _keys(criteria["minimums"], {"positive", "negative"}, set(), f"per_kind.{kind}.minimums")
        errors = _keys(
            criteria["max_errors"], {"false_positive", "false_negative"}, set(), f"per_kind.{kind}.max_errors"
        )
        for label in ("positive", "negative"):
            _integer(samples[label], f"per_kind.{kind}.minimums.{label}", 1, 500)
        for label in ("false_positive", "false_negative"):
            _integer(errors[label], f"per_kind.{kind}.max_errors.{label}", 0, 500)
    return policy, hashlib.sha256(raw).hexdigest()


def _annotations_sha256(path: Path) -> str:
    return hashlib.sha256(read_policy_text(path, max_bytes=MAX_ANNOTATION_BYTES).encode("utf-8")).hexdigest()


def _reject_reused_cases(cases: list[Any], corpus_digest: str, excluded: list[Path]) -> list[dict[str, str]]:
    prior_digests: set[str] = set()
    prior_files: set[str] = set()
    prior_sources: set[tuple[str, str, str]] = set()
    history: list[dict[str, str]] = []
    for path in [*_KNOWN_CORPORA, *excluded]:
        _, known, digest = load_corpus(path)
        history.append({"corpus": str(path), "sha256": digest})
        prior_digests.add(digest)
        for case in known:
            prior_files.update(hashlib.sha256(content.encode("utf-8")).hexdigest() for content in case.files.values())
            if case.source:
                prior_sources.add((case.source["repo"], case.source["commit"], case.source["path"]))
    if corpus_digest in prior_digests:
        raise CorpusError("holdout corpus is a previously evaluated corpus")
    holdout_files: set[str] = set()
    holdout_sources: set[tuple[str, str, str]] = set()
    for case in cases:
        for content in case.files.values():
            file_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if file_digest in prior_files:
                raise CorpusError(f"{case.id}: holdout reuses a previously evaluated source file")
            if file_digest in holdout_files:
                raise CorpusError(f"{case.id}: duplicate source file within the holdout")
            holdout_files.add(file_digest)
        if case.source:
            location = (case.source["repo"], case.source["commit"], case.source["path"])
            if location in prior_sources:
                raise CorpusError(f"{case.id}: holdout reuses a previously evaluated source location")
            if location in holdout_sources:
                raise CorpusError(f"{case.id}: duplicate source location within the holdout")
            holdout_sources.add(location)
    return history


def assess(
    corpus: Path, annotations: Path, policy_path: Path, *, excluded: list[Path] | None = None,
) -> dict[str, Any]:
    """Produce a process and detection gate for the declared, selected code cases."""
    policy, policy_digest = load_policy(policy_path)
    metadata, cases, corpus_digest = load_corpus(corpus)
    if corpus_digest != policy["corpus_sha256"]:
        raise CorpusError("holdout corpus digest does not match the frozen policy")
    if metadata["type"] != "adjudicated":
        raise CorpusError("human holdout requires adjudicated corpus metadata")
    annotation_digest = _annotations_sha256(annotations)
    if annotation_digest != policy["annotations_sha256"]:
        raise CorpusError("holdout annotation ledger digest does not match the frozen policy")
    annotation = validate_annotations(corpus, annotations)
    if annotation["method"] != "independent-human-double-label-before-scan":
        raise CorpusError("human holdout requires declared independent human double labeling before scanning")
    if _annotations_sha256(annotations) != annotation_digest:
        raise CorpusError("holdout annotation ledger changed during preflight")
    actual_kinds = {case.kind.value for case in cases}
    if actual_kinds != set(policy["target_kinds"]):
        raise CorpusError("policy target_kinds must exactly match the holdout targets")
    history = _reject_reused_cases(cases, corpus_digest, excluded or [])

    reasons: list[str] = []
    for key, observed in (
        ("positive", annotation["positive_cases"]),
        ("negative", annotation["negative_cases"]),
        ("repositories", len(annotation["source_repositories"])),
    ):
        if observed < policy["minimums"][key]:
            reasons.append(f"{key}: {observed} < minimum {policy['minimums'][key]}")

    result = evaluate(corpus, annotations=annotations)
    if result["corpus"]["sha256"] != corpus_digest or result["annotation_validation"] != annotation:
        raise CorpusError("holdout corpus or annotations changed during the acceptance run")
    if _annotations_sha256(annotations) != annotation_digest:
        raise CorpusError("holdout annotation ledger changed during the acceptance run")
    matrix = result["metrics"]["all"]
    for key, count in (("false_positive", matrix["fp"]), ("false_negative", matrix["fn"])):
        if count > policy["max_errors"][key]:
            reasons.append(f"{key}: {count} > limit {policy['max_errors'][key]}")
    if any(case["assertion_failures"] for case in result["cases"]):
        reasons.append("one or more structural assertions failed")
    by_kind = {
        kind: summarize([{**row, "family": kind} for row in result["cases"] if row["target"]["kind"] == kind])[kind]
        for kind in sorted(actual_kinds)
    }
    for kind, counts in by_kind.items():
        criteria = policy["per_kind"][kind]
        for label, observed in (("positive", counts["positive_cases"]), ("negative", counts["negative_cases"])):
            minimum = criteria["minimums"][label]
            if observed < minimum:
                reasons.append(f"{kind} {label}: {observed} < minimum {minimum}")
        for label, observed in (("false_positive", counts["fp"]), ("false_negative", counts["fn"])):
            maximum = criteria["max_errors"][label]
            if observed > maximum:
                reasons.append(f"{kind} {label}: {observed} > limit {maximum}")
    return {
        "schema": 1,
        "passed": not reasons,
        "reasons": reasons,
        "scope": "selected, independently labeled code.filesystem cases only",
        "limitations": "Reviewer identities and blindness are declarations; results do not establish field accuracy or live tenant acceptance.",
        "policy": policy,
        "policy_sha256": policy_digest,
        "annotation_validation": annotation,
        "annotations_sha256": annotation_digest,
        "excluded_corpora": history,
        "by_kind": by_kind,
        "evaluation": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--annotations", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--exclude-corpus", action="append", type=Path, default=[],
                        help="additional previously evaluated corpus (repeatable)")
    parser.add_argument("--output", required=True, type=Path, help="create a private JSON receipt; never overwrite")
    args = parser.parse_args(argv)
    try:
        report = assess(args.corpus, args.annotations, args.policy, excluded=args.exclude_corpus)
        encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
        print(f"Human holdout gate: {'PASS' if report['passed'] else 'FAIL'} | report: {args.output}")
        return 0 if report["passed"] else 1
    except (CorpusError, OSError, RuntimeError, ValueError) as exc:
        print(f"holdout gate invalid: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
