"""Evaluate filesystem detection on isolated, labeled repository examples.

Run from the checkout with ``python -m tools.evaluation.evaluate``. This module
never clones a repository, executes sample content, or uses live credentials.
The bundled corpus is synthetic and cannot establish field precision or recall.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from shadowscan import __version__
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import Kind
from shadowscan.signatures import get_index

DEFAULT_CORPUS = Path(__file__).with_name("corpus.json")
MAX_CORPUS_BYTES = 2_000_000
MAX_CASES = 500
MAX_FILES_PER_CASE = 20
MAX_FILE_BYTES = 32_000
MAX_TOTAL_FILE_BYTES = 1_000_000
_ID = re.compile(r"[a-z][a-z0-9_-]{1,79}\Z")
_SIGNATURE = re.compile(r"[a-z0-9][a-z0-9._-]{0,100}\Z")


class CorpusError(ValueError):
    """A corpus is malformed or exceeds the reviewable resource limits."""


@dataclass(frozen=True)
class Case:
    id: str
    family: str
    description: str
    files: dict[str, str]
    kind: Kind
    signature: str | None
    present: bool
    assertions: dict[str, Any]
    source: dict[str, str] | None = None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _keys(value: Any, required: set[str], optional: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - required - optional or required - set(value):
        raise CorpusError(f"{where}: expected keys {sorted(required)} and optional {sorted(optional)}")
    return value


def _safe_name(name: Any) -> bool:
    if not isinstance(name, str) or not name or len(name) > 240 or "\\" in name or "\x00" in name:
        return False
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and path.as_posix() == name
        and all(part not in {"", ".", ".."} for part in name.split("/"))
    )


def load_corpus(path: Path) -> tuple[dict[str, str], list[Case], str]:
    """Parse a bounded, declarative corpus. Case files are text and never run."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CORPUS_BYTES:
        raise CorpusError("corpus must be a regular, nonsymlink file of at most 2 MB")
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise CorpusError("corpus is not valid, unambiguous UTF-8 JSON") from exc
    data = _keys(data, {"schema", "metadata", "cases"}, set(), "corpus")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise CorpusError("unsupported corpus schema; expected 1")
    meta = _keys(data["metadata"], {"name", "type", "provenance"}, set(), "metadata")
    if not all(isinstance(value, str) and 0 < len(value) <= 500 for value in meta.values()) or meta[
        "type"
    ] not in {"synthetic", "public-pinned", "adjudicated"}:
        raise CorpusError("metadata requires a name, type and provenance")
    items = data["cases"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_CASES:
        raise CorpusError("corpus must contain 1 to 500 cases")
    cases: list[Case] = []
    ids: set[str] = set()
    total_bytes = 0
    for i, item in enumerate(items):
        where = f"case {i}"
        obj = _keys(
            item,
            {"id", "family", "description", "files", "target", "present"},
            {"assertions", "source"},
            where,
        )
        case_id, family, desc = obj["id"], obj["family"], obj["description"]
        if not isinstance(case_id, str) or not _ID.fullmatch(case_id) or case_id in ids:
            raise CorpusError(f"{where}: case IDs must be unique slugs")
        ids.add(case_id)
        if not isinstance(family, str) or not _ID.fullmatch(family):
            raise CorpusError(f"{where}: family must be a slug")
        if not isinstance(desc, str) or not 1 <= len(desc) <= 500:
            raise CorpusError(f"{where}: description must be 1 to 500 characters")
        if type(obj["present"]) is not bool:
            raise CorpusError(f"{where}: present must be boolean")
        target = _keys(obj["target"], {"kind"}, {"signature"}, f"{where} target")
        try:
            kind = Kind(target["kind"])
        except (ValueError, TypeError) as exc:
            raise CorpusError(f"{where}: unknown finding kind") from exc
        sig = target.get("signature")
        if sig is not None and (not isinstance(sig, str) or not _SIGNATURE.fullmatch(sig)):
            raise CorpusError(f"{where}: signature must be a signature ID")
        assertions = _keys(
            obj.get("assertions", {}),
            set(),
            {"max_agent_findings", "server_count", "server_names"},
            f"{where} assertions",
        )
        for key in ("max_agent_findings", "server_count"):
            if key in assertions and (type(assertions[key]) is not int or not 0 <= assertions[key] <= 20):
                raise CorpusError(f"{where}: {key} must be an integer from 0 to 20")
        if "server_names" in assertions and (
            not isinstance(assertions["server_names"], list)
            or len(assertions["server_names"]) > 20
            or any(
                not isinstance(name, str) or not name or len(name) > 100
                for name in assertions["server_names"]
            )
            or len(set(assertions["server_names"])) != len(assertions["server_names"])
        ):
            raise CorpusError(f"{where}: server_names must contain up to 20 unique names")
        files = obj["files"]
        if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES_PER_CASE:
            raise CorpusError(f"{where}: files must contain 1 to 20 entries")
        for name, contents in files.items():
            if not _safe_name(name) or not isinstance(contents, str):
                raise CorpusError(f"{where}: invalid text file or unsafe relative path")
            size = len(contents.encode("utf-8"))
            if size > MAX_FILE_BYTES:
                raise CorpusError(f"{where}: file exceeds 32 KB")
            total_bytes += size
            if total_bytes > MAX_TOTAL_FILE_BYTES:
                raise CorpusError("case files exceed 1 MB combined")
        source = obj.get("source")
        if source is not None:
            source = _keys(
                source,
                {"repo", "url", "commit", "path", "sha256", "license", "label_evidence"},
                set(),
                f"{where} source",
            )
            if (
                len(files) != 1
                or source["path"] not in files
                or not all(isinstance(v, str) and v and len(v) <= 500 for v in source.values())
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source["repo"])
                or not re.fullmatch(r"[0-9a-f]{40}", source["commit"])
                or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
            ):
                raise CorpusError(f"{where}: invalid source attribution")
            expected_url = f"https://github.com/{source['repo']}/blob/{source['commit']}/{source['path']}"
            if source["url"] != expected_url:
                raise CorpusError(f"{where}: source URL does not match repository commit and path")
            if hashlib.sha256(files[source["path"]].encode("utf-8")).hexdigest() != source["sha256"]:
                raise CorpusError(f"{where}: source snapshot digest mismatch")
        if meta["type"] == "public-pinned" and source is None:
            raise CorpusError(f"{where}: public pinned cases require source attribution")
        cases.append(Case(case_id, family, desc, files, kind, sig, obj["present"], assertions, source))
    return meta, cases, hashlib.sha256(raw).hexdigest()


def _scan_case(case: Case, root: Path, index: Any) -> tuple[float, list[dict[str, Any]]]:
    ctx = ConnectorContext(
        config={"path": str(root), "label": f"eval:{case.id}", "use_git": False, "scan_secrets": False},
        index=index,
    )
    started = time.perf_counter()
    findings = FilesystemConnector(ctx).run()
    elapsed = time.perf_counter() - started
    if (
        ctx.stats is None
        or ctx.stats.incomplete
        or ctx.stats.skipped
        or ctx.stats.errors
        or ctx.stats.warnings
    ):
        raise RuntimeError(
            f"{case.id}: scan incomplete: "
            + "; ".join((ctx.stats.errors + ctx.stats.warnings) if ctx.stats else ["no status"])
        )
    return elapsed, [
        {
            "kind": f.kind.value,
            "resource_type": f.resource_type,
            "signatures": sorted(set(f.frameworks + f.model_providers)),
            "confidence": f.confidence,
            **(
                {
                    "server_count": f.metadata.get("server_count"),
                    "server_names": sorted(str(server["name"]) for server in f.metadata.get("servers", [])),
                }
                if f.kind == Kind.MCP_SERVER
                else {}
            ),
        }
        for f in findings
    ]


def _assertions(case: Case, findings: list[dict[str, Any]]) -> list[str]:
    failures = []
    mcp = [f for f in findings if f["kind"] == Kind.MCP_SERVER.value]
    if "max_agent_findings" in case.assertions:
        observed = sum(f["kind"] == Kind.AGENT.value for f in findings)
        if observed > case.assertions["max_agent_findings"]:
            failures.append(
                f"agent findings: expected at most {case.assertions['max_agent_findings']}; got {observed}"
            )
    if "server_count" in case.assertions:
        observed = sum(f["server_count"] for f in mcp)
        if observed != case.assertions["server_count"]:
            failures.append(
                f"active MCP server count: expected {case.assertions['server_count']}; got {observed}"
            )
    if "server_names" in case.assertions:
        observed_names = sorted(name for f in mcp for name in f["server_names"])
        if observed_names != sorted(case.assertions["server_names"]):
            failures.append(
                f"active MCP server names: expected {sorted(case.assertions['server_names'])}; got {observed_names}"
            )
    return failures


def _percentile(values: list[float], pct: float) -> float:
    # Nearest rank is stable for even and small sample sizes.
    return sorted(values)[max(0, math.ceil(len(values) * pct) - 1)]


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Binary detection scores per labeled case; no assertion of field validity."""
    groups: dict[str, list[dict[str, Any]]] = {"all": rows}
    for row in rows:
        groups.setdefault(row["family"], []).append(row)
    return _scores(groups)


_EXTENSION_LANGUAGES = {
    ".py": "python", ".ipynb": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust",
    ".java": "java", ".kt": "java", ".cs": "dotnet", ".rb": "ruby", ".php": "php",
    ".json": "config", ".jsonc": "config", ".yaml": "config", ".yml": "config", ".toml": "config",
    ".md": "docs", ".mdc": "docs", ".txt": "docs",
}


def _languages(row: dict[str, Any]) -> list[str]:
    found = {_EXTENSION_LANGUAGES.get(Path(name).suffix.lower(), "other") for name in row.get("files", [])}
    return sorted(found) or ["other"]


def breakdowns(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Scores per source language and per target signature.

    A case counts once in every language it contains. Small groups say little;
    report sample sizes with any rate taken from here.
    """
    by_language: dict[str, list[dict[str, Any]]] = {}
    by_signature: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        for language in _languages(row):
            by_language.setdefault(language, []).append(row)
        by_signature.setdefault(row["target"].get("signature") or "any", []).append(row)
    return {"language": _scores(by_language), "signature": _scores(by_signature)}


def _scores(groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for family, group in sorted(groups.items()):
        tp = sum(row["present"] and row["predicted"] for row in group)
        fp = sum(not row["present"] and row["predicted"] for row in group)
        fn = sum(row["present"] and not row["predicted"] for row in group)
        tn = sum(not row["present"] and not row["predicted"] for row in group)
        summary[family] = {
            "cases": len(group),
            "positive_cases": tp + fn,
            "negative_cases": tn + fp,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "specificity": tn / (tn + fp) if tn + fp else None,
        }
    return summary


def calibration(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Descriptive reliability bins; a scanner score is not a probability."""
    bounds = [(0.0, 0.5), (0.5, 0.7), (0.7, 0.85), (0.85, 1.0)]
    bins = []
    total = len(rows)
    for lower, upper in bounds:
        subset = [row for row in rows if lower <= row["score"] < upper or upper == 1 and row["score"] == 1]
        mean = statistics.mean(row["score"] for row in subset) if subset else None
        rate = statistics.mean(float(row["present"]) for row in subset) if subset else None
        bins.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(subset),
                "mean_score": mean,
                "observed_fraction": rate,
            }
        )
    ece = 0.0
    for bucket in bins:
        if bucket["count"]:
            mean_score, observed_fraction = bucket["mean_score"], bucket["observed_fraction"]
            assert mean_score is not None and observed_fraction is not None
            ece += bucket["count"] / total * abs(mean_score - observed_fraction)
    return {
        "note": "Descriptive selected-case score reliability only; confidence is not a calibrated probability.",
        "brier_proxy": statistics.mean((row["score"] - int(row["present"])) ** 2 for row in rows),
        "ece_proxy": ece,
        "bins": bins,
    }


def _source_fingerprint(root: Path | None = None) -> str:
    """Identify the actual scanner sources, including an uncommitted candidate."""
    root = root or Path(__file__).resolve().parents[2] / "shadowscan"
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        name = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def evaluate(path: Path, *, repeats: int = 1, annotations: Path | None = None) -> dict[str, Any]:
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError("repeats must be between 1 and 20")
    metadata, cases, corpus_digest = load_corpus(path)
    annotation_report = None
    if metadata["type"] == "adjudicated" and annotations is None:
        raise CorpusError("adjudicated corpora require a frozen annotation ledger via --annotations")
    if annotations is not None:
        from tools.evaluation.annotations import validate_annotations

        annotation_report = validate_annotations(path, annotations)
    index = get_index()
    rows: list[dict[str, Any]] = []
    durations: list[float] = []
    file_bytes = 0
    with tempfile.TemporaryDirectory(prefix="shadowscan-eval-") as temp:
        for case in cases:
            root = Path(temp) / case.id
            root.mkdir(mode=0o700)
            for name, contents in case.files.items():
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(contents, encoding="utf-8")
                file_bytes += len(contents.encode("utf-8"))
            iterations = [_scan_case(case, root, index) for _ in range(repeats)]
            durations.extend(duration for duration, _ in iterations)
            if any(observations != iterations[0][1] for _, observations in iterations[1:]):
                raise RuntimeError(f"{case.id}: nondeterministic observations across repeated scans")
            # Match IDs by kind and signature; no finding means a score of 0.
            matching = [
                f
                for f in iterations[0][1]
                if f["kind"] == case.kind.value
                and (case.signature is None or case.signature in f["signatures"])
            ]
            score = max((f["confidence"] for f in matching), default=0.0)
            assertion_failures = _assertions(case, iterations[0][1])
            rows.append(
                {
                    "id": case.id,
                    "family": case.family,
                    "description": case.description,
                    "source": case.source,
                    "target": {"kind": case.kind.value, "signature": case.signature},
                    "files": sorted(case.files),
                    "present": case.present,
                    "predicted": bool(matching),
                    "score": score,
                    "correct": case.present == bool(matching) and not assertion_failures,
                    "assertion_failures": assertion_failures,
                    "findings": iterations[0][1],
                    "median_ms": round(statistics.median(duration for duration, _ in iterations) * 1000, 3),
                }
            )
    return {
        "schema": 1,
        "corpus": {**metadata, "sha256": corpus_digest},
        "annotation_validation": annotation_report,
        "implementation": {
            "scanner_version": __version__,
            "scanner_source_sha256": _source_fingerprint(),
            # The metric computation is part of what a report asserts.
            "evaluator_source_sha256": _source_fingerprint(Path(__file__).resolve().parent),
            "signature_sha256": index.fingerprint(),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "cases": rows,
        "metrics": summarize(rows),
        "breakdowns": breakdowns(rows),
        "calibration": calibration(rows),
        "performance": {
            "repeats": repeats,
            "scans": len(durations),
            "files_per_pass": sum(len(c.files) for c in cases),
            "bytes_per_pass": file_bytes,
            "median_scan_ms": round(statistics.median(durations) * 1000, 3),
            "p95_scan_ms": round(_percentile(durations, 0.95) * 1000, 3),
            "total_scan_s": round(sum(durations), 3),
        },
        "passed": all(row["correct"] for row in rows),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
        help="bounded, labeled corpus JSON; default is the bundled synthetic corpus",
    )
    parser.add_argument("--repeats", type=int, default=1, help="repeat each scan for timing (1-20)")
    parser.add_argument("--annotations", type=Path, help="verify independent labels and corpus digest before scanning")
    parser.add_argument("--output", type=Path, help="write JSON report to a local file, mode 0600")
    args = parser.parse_args(argv)
    try:
        report = evaluate(args.corpus, repeats=args.repeats, annotations=args.annotations)
        output = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            # No automatic parent creation, and no accidental overwrite of a
            # report outside the analyst-selected location.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(output)
            print(f"Evaluation: {report['metrics']['all']} | report: {args.output}")
        else:
            sys.stdout.write(output)
        return 0 if report["passed"] else 1
    except (CorpusError, OSError, RuntimeError, ValueError) as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
