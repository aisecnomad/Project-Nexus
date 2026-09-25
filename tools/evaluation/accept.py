"""Gate a frozen, independently labeled corpus against predeclared detection targets.

The operator supplies a private human-adjudicated corpus and an independently
reviewed policy. A corpus type label, a passing score, or the bundled public
sample does not prove sampling independence or field accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any

from tools.evaluation.evaluate import CorpusError, _unique_pairs, evaluate, load_corpus

MAX_POLICY_BYTES = 128_000
_DIGEST = re.compile(r"[0-9a-f]{64}\\Z")
_BOUNDS = ("precision", "recall", "specificity")
_Z_95 = 1.959963984540054
_HUMAN_METHOD = "independent-human-double-label-before-scan"
_BUNDLED_NAMES = frozenset({"corpus.json", "public_corpus.json", "independent_corpus.json"})
_EVALUATION_DIR = Path(__file__).resolve().parent


def _is_bundled_release_corpus(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return resolved.parent == _EVALUATION_DIR and resolved.name in _BUNDLED_NAMES


def _policy(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_POLICY_BYTES:
        raise CorpusError("policy must be a regular, nonsymlink file of at most 128 KB")
    raw = path.read_bytes()
    try:
        policy = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise CorpusError("policy is not valid, unambiguous UTF-8 JSON") from exc
    if (
        not isinstance(policy, dict)
        or set(policy) != {"schema", "corpus_sha256", "groups"}
        or type(policy["schema"]) is not int
        or policy["schema"] != 1
        or not isinstance(policy["corpus_sha256"], str)
        or not _DIGEST.fullmatch(policy["corpus_sha256"])
    ):
        raise CorpusError("policy needs schema 1, corpus_sha256 and groups")
    groups = policy["groups"]
    if not isinstance(groups, dict) or not 1 <= len(groups) <= 100 or "all" not in groups:
        raise CorpusError("policy groups must include all and each labeled family")
    expected = {
        "min_positive_cases",
        "min_negative_cases",
        "min_precision_lower95",
        "min_recall_lower95",
        "min_specificity_lower95",
    }
    for name, requirements in groups.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,79}", name):
            raise CorpusError("policy group names must be family slugs")
        if not isinstance(requirements, dict) or set(requirements) != expected:
            raise CorpusError(f"policy group {name}: expected two case floors and three lower-bound targets")
        for key in ("min_positive_cases", "min_negative_cases"):
            value = requirements[key]
            if type(value) is not int or not 1 <= value <= 500:
                raise CorpusError(f"policy group {name}: {key} must be an integer from 1 to 500")
        for metric in _BOUNDS:
            key = f"min_{metric}_lower95"
            value = requirements[key]
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 1:
                raise CorpusError(f"policy group {name}: {key} must be a finite target in (0, 1]")
    return policy, hashlib.sha256(raw).hexdigest()


def wilson_lower95(successes: int, attempts: int) -> float | None:
    """Conservative two-sided 95% Wilson lower endpoint for a binomial rate."""
    if attempts == 0:
        return None
    if successes < 0 or attempts < 0 or successes > attempts:
        raise CorpusError("Wilson interval requires 0 <= successes <= attempts")
    proportion = successes / attempts
    z2 = _Z_95 * _Z_95
    return (
        proportion + z2 / (2 * attempts)
        - _Z_95 * math.sqrt((proportion * (1 - proportion) + z2 / (4 * attempts)) / attempts)
    ) / (1 + z2 / attempts)


def _annotation_method(annotations: Path) -> str:
    if annotations.is_symlink() or not annotations.is_file():
        raise CorpusError("annotations must be a regular, nonsymlink file")
    try:
        ledger = json.loads(annotations.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise CorpusError("annotations are not valid, unambiguous UTF-8 JSON") from exc
    if not isinstance(ledger, dict) or not isinstance(ledger.get("method"), str):
        raise CorpusError("annotations must declare a labeling method")
    return ledger["method"]


def accept(corpus: Path, policy_path: Path, annotations: Path) -> dict[str, Any]:
    """Execute the scanner on a private holdout and compare it to a frozen policy."""
    if _is_bundled_release_corpus(corpus):
        raise CorpusError(
            "bundled synthetic, public-pinned and independent corpora are regression "
            "suites; acceptance requires a private human-adjudicated holdout"
        )
    policy, policy_digest = _policy(policy_path)
    metadata, cases, digest = load_corpus(corpus)
    if metadata["type"] != "adjudicated":
        raise CorpusError("acceptance requires an independently adjudicated corpus")
    if digest != policy["corpus_sha256"]:
        raise CorpusError("corpus SHA-256 differs from the frozen acceptance policy")
    if any(case.family == "all" for case in cases):
        raise CorpusError("all is a reserved metrics group; use another case family")
    method = _annotation_method(annotations)
    if method != _HUMAN_METHOD:
        raise CorpusError(
            "acceptance requires independent-human-double-label-before-scan; "
            "AI-labeled public samples remain regression evidence only"
        )
    result = evaluate(corpus, repeats=2, annotations=annotations)
    if result["corpus"]["sha256"] != policy["corpus_sha256"]:
        raise CorpusError("corpus SHA-256 differs from the frozen acceptance policy")
    metrics = result["metrics"]
    if set(policy["groups"]) != set(metrics):
        raise CorpusError("policy must declare exactly all observed families and the all group")
    assertions_passed = all(not case["assertion_failures"] for case in result["cases"])
    groups: dict[str, dict[str, Any]] = {}
    for name, counts in sorted(metrics.items()):
        requirements = policy["groups"][name]
        failures: list[str] = []
        for sign in ("positive", "negative"):
            key = f"{sign}_cases"
            minimum = requirements[f"min_{key}"]
            if counts[key] < minimum:
                failures.append(f"{key}: observed {counts[key]} below required {minimum}")
        endpoints = {
            "precision": wilson_lower95(counts["tp"], counts["tp"] + counts["fp"]),
            "recall": wilson_lower95(counts["tp"], counts["tp"] + counts["fn"]),
            "specificity": wilson_lower95(counts["tn"], counts["tn"] + counts["fp"]),
        }
        for metric, lower in endpoints.items():
            threshold = requirements[f"min_{metric}_lower95"]
            if lower is None or lower < threshold:
                observed = "undefined" if lower is None else f"{lower:.6f}"
                failures.append(f"{metric} lower95: observed {observed} below required {threshold}")
        groups[name] = {
            "counts": counts,
            "lower95": endpoints,
            "requirements": requirements,
            "passed": not failures,
            "failures": failures,
        }
    return {
        "schema": 1,
        "corpus_sha256": result["corpus"]["sha256"],
        "policy_sha256": policy_digest,
        "annotation_validation": result["annotation_validation"],
        "annotation_method": method,
        "case_assertions_passed": assertions_passed,
        "all_labels_matched": result["passed"],
        "groups": groups,
        "passed": assertions_passed and all(group["passed"] for group in groups.values()),
        "note": (
            "Human review must verify independent sampling, labels, and tenant "
            "applicability. A passing gate is not live tenant acceptance."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="private adjudicated corpus JSON")
    parser.add_argument("--policy", type=Path, required=True, help="reviewed, SHA-256-bound policy JSON")
    parser.add_argument(
        "--annotations",
        type=Path,
        required=True,
        help="frozen two-reviewer human label ledger bound to the corpus",
    )
    parser.add_argument("--output", type=Path, help="create a private summary JSON file, mode 0600")
    args = parser.parse_args(argv)
    try:
        report = accept(args.corpus, args.policy, args.annotations)
        payload = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            print(f"Acceptance: {'passed' if report['passed'] else 'failed'} | report: {args.output}")
        else:
            sys.stdout.write(payload)
        return 0 if report["passed"] else 1
    except (CorpusError, OSError, RuntimeError, ValueError) as exc:
        print(f"acceptance failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
