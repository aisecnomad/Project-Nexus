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
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

from shadowscan import __version__
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import Kind
from shadowscan.signatures import get_index
from shadowscan.utils.files import read_policy_text

DEFAULT_CORPUS = Path(__file__).with_name("corpus.json")
MAX_CORPUS_BYTES = 2_000_000
MAX_CASES = 500
MAX_FILES_PER_CASE = 20
MAX_FILE_BYTES = 32_000
MAX_TOTAL_FILE_BYTES = 1_000_000
_ID = re.compile(r"[a-z][a-z0-9_-]{1,79}\Z")
_SIGNATURE = re.compile(r"[a-z0-9][a-z0-9._-]{0,100}\Z")
_FINDING_SELECTORS = ("expected_findings", "forbidden_findings")


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
    # A documented scanner miss or false positive. The case still runs and is
    # counted in the metrics, but it does not fail the run; a known gap that
    # passes is reported so the flag can be removed.
    known_gap: bool = False


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


def _validate_finding_selectors(assertions: dict[str, Any], where: str) -> None:
    """Constrain explicit labels to scanner fields, with one bounded selector per rule."""
    for relation in _FINDING_SELECTORS:
        selectors = assertions.get(relation, [])
        if not isinstance(selectors, list) or len(selectors) > 20:
            raise CorpusError(f"{where}: {relation} must contain at most 20 finding selectors")
        seen: set[tuple[str, str | None, str | None]] = set()
        for selector in selectors:
            _keys(
                selector,
                {"kind"},
                {"product_signature", "provider_signature"},
                f"{where} {relation} selector",
            )
            try:
                kind = Kind(selector["kind"])
            except (ValueError, TypeError) as exc:
                raise CorpusError(f"{where}: unknown {relation} finding kind") from exc
            for field in ("product_signature", "provider_signature"):
                signature = selector.get(field)
                if field in selector and (
                    not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature)
                ):
                    raise CorpusError(f"{where}: invalid {relation} {field}")
            product = selector.get("product_signature")
            provider = selector.get("provider_signature")
            if product is not None and product.startswith("provider."):
                raise CorpusError(f"{where}: product_signature must not be a provider ID")
            if provider is not None and not provider.startswith("provider."):
                raise CorpusError(f"{where}: provider_signature must be a provider ID")
            key = (kind.value, product, provider)
            if key in seen:
                raise CorpusError(f"{where}: duplicate {relation} selector")
            seen.add(key)
    expected = {
        (selector["kind"], selector.get("product_signature"), selector.get("provider_signature"))
        for selector in assertions.get("expected_findings", [])
    }
    forbidden = {
        (selector["kind"], selector.get("product_signature"), selector.get("provider_signature"))
        for selector in assertions.get("forbidden_findings", [])
    }
    if expected & forbidden:
        raise CorpusError(f"{where}: a finding selector cannot be both expected and forbidden")
    for required_kind, required_product, required_provider in expected:
        for excluded_kind, excluded_product, excluded_provider in forbidden:
            if (
                required_kind == excluded_kind
                and (excluded_product is None or excluded_product == required_product)
                and (excluded_provider is None or excluded_provider == required_provider)
            ):
                raise CorpusError(f"{where}: forbidden selector covers an expected finding")


def _validate_exact_findings(assertions: dict[str, Any], where: str) -> None:
    if "exact_findings" not in assertions:
        return
    entries = assertions["exact_findings"]
    if not isinstance(entries, list) or len(entries) > 20:
        raise CorpusError(f"{where}: exact_findings must contain at most 20 finding labels")
    for entry in entries:
        _keys(
            entry,
            {"kind", "product_signatures", "provider_signatures"},
            set(),
            f"{where} exact_findings entry",
        )
        try:
            Kind(entry["kind"])
        except (ValueError, TypeError) as exc:
            raise CorpusError(f"{where}: unknown exact_findings kind") from exc
        for field, expected_prefix in (("product_signatures", False), ("provider_signatures", True)):
            signatures = entry[field]
            if (
                not isinstance(signatures, list)
                or len(signatures) > 20
                or any(
                    not isinstance(sig, str)
                    or not _SIGNATURE.fullmatch(sig)
                    or sig.startswith("provider.") != expected_prefix
                    for sig in signatures
                )
                or len(set(signatures)) != len(signatures)
            ):
                raise CorpusError(f"{where}: {field} must contain up to 20 unique signature IDs")


def load_corpus(path: Path) -> tuple[dict[str, Any], list[Case], str]:
    """Parse a bounded, declarative corpus. Case files are text and never run."""
    try:
        # Use the same descriptor-based read as other policy inputs: checking a
        # path before an unbounded read leaves symlink/replacement races open.
        raw = read_policy_text(path, max_bytes=MAX_CORPUS_BYTES).encode("utf-8")
        data = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise CorpusError("corpus is not valid, unambiguous UTF-8 JSON") from exc
    data = _keys(data, {"schema", "metadata", "cases"}, set(), "corpus")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise CorpusError("unsupported corpus schema; expected 1")
    meta = _keys(
        data["metadata"],
        {"name", "type", "provenance"},
        {"known_gap_policy"},
        "metadata",
    )
    if not all(
        isinstance(meta[key], str) and 0 < len(meta[key]) <= 500 for key in ("name", "type", "provenance")
    ) or meta["type"] not in {"synthetic", "public-pinned", "adjudicated"}:
        raise CorpusError("metadata requires a name, type and provenance")
    gap_policy = meta.get("known_gap_policy")
    if gap_policy is not None:
        gap_policy = _keys(
            gap_policy,
            {"max_count", "expires_on"},
            set(),
            "metadata known_gap_policy",
        )
        if type(gap_policy["max_count"]) is not int or not 0 <= gap_policy["max_count"] <= 20:
            raise CorpusError("metadata known_gap_policy max_count must be an integer from 0 to 20")
        try:
            expiry = date.fromisoformat(gap_policy["expires_on"])
        except (TypeError, ValueError) as exc:
            raise CorpusError("metadata known_gap_policy expires_on must be an ISO date") from exc
        if expiry.isoformat() != gap_policy["expires_on"]:
            raise CorpusError("metadata known_gap_policy expires_on must be an ISO date")
        if expiry < date.today():
            raise CorpusError("metadata known_gap_policy has expired; review or remove every known gap")
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
            {"assertions", "source", "known_gap"},
            where,
        )
        case_id, family, desc = obj["id"], obj["family"], obj["description"]
        if not isinstance(case_id, str) or not _ID.fullmatch(case_id) or case_id in ids:
            raise CorpusError(f"{where}: case IDs must be unique slugs")
        ids.add(case_id)
        if not isinstance(family, str) or not _ID.fullmatch(family):
            raise CorpusError(f"{where}: family must be a slug")
        if family == "all":
            raise CorpusError(f"{where}: family 'all' is reserved for aggregate metrics")
        if not isinstance(desc, str) or not 1 <= len(desc) <= 500:
            raise CorpusError(f"{where}: description must be 1 to 500 characters")
        if type(obj["present"]) is not bool:
            raise CorpusError(f"{where}: present must be boolean")
        known_gap = obj.get("known_gap", False)
        if type(known_gap) is not bool:
            raise CorpusError(f"{where}: known_gap must be boolean")
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
            {
                "forbidden_signatures",
                "max_agent_findings",
                "max_secret_findings",
                "server_count",
                "server_names",
                "exact_findings",
                *_FINDING_SELECTORS,
            },
            f"{where} assertions",
        )
        for key in ("max_agent_findings", "max_secret_findings", "server_count"):
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
        if "forbidden_signatures" in assertions and (
            not isinstance(assertions["forbidden_signatures"], list)
            or len(assertions["forbidden_signatures"]) > 20
            or any(
                not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature)
                for signature in assertions["forbidden_signatures"]
            )
            or len(set(assertions["forbidden_signatures"])) != len(assertions["forbidden_signatures"])
        ):
            raise CorpusError(f"{where}: forbidden_signatures must contain up to 20 unique signature IDs")
        _validate_finding_selectors(assertions, where)
        _validate_exact_findings(assertions, where)
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
                or not all(isinstance(v, str) and v and len(v) <= 500 for v in source.values())
                or source["path"] not in files
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
        cases.append(
            Case(case_id, family, desc, files, kind, sig, obj["present"], assertions, source, known_gap)
        )
    gap_count = sum(case.known_gap for case in cases)
    if gap_count and gap_policy is None:
        raise CorpusError("known_gap cases require a bounded metadata known_gap_policy")
    if gap_policy is not None and gap_count > gap_policy["max_count"]:
        raise CorpusError(
            f"known_gap count {gap_count} exceeds the declared maximum {gap_policy['max_count']}"
        )
    return meta, cases, hashlib.sha256(raw).hexdigest()


def _scan_case(case: Case, root: Path, index: Any) -> tuple[float, list[dict[str, Any]]]:
    ctx = ConnectorContext(
        config={"path": str(root), "label": f"eval:{case.id}", "use_git": False, "scan_secrets": True},
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
            "frameworks": sorted(set(f.frameworks)),
            "model_providers": sorted(set(f.model_providers)),
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


def _finding_checks(case: Case, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks = []
    for relation in _FINDING_SELECTORS:
        for selector in case.assertions.get(relation, []):
            observed = any(
                finding["kind"] == selector["kind"]
                and (
                    "product_signature" not in selector
                    or selector["product_signature"] in finding["frameworks"]
                )
                and (
                    "provider_signature" not in selector
                    or selector["provider_signature"] in finding["model_providers"]
                )
                for finding in findings
            )
            checks.append(
                {
                    "relation": relation,
                    "selector": selector,
                    "observed": observed,
                    "passed": observed if relation == "expected_findings" else not observed,
                }
            )
    return checks


def _exact_finding_set(case: Case, findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Compare all emitted findings, including duplicate kinds and full attribution."""
    if "exact_findings" not in case.assertions:
        return None
    expected = sorted(
        (
            entry["kind"],
            tuple(sorted(entry["product_signatures"])),
            tuple(sorted(entry["provider_signatures"])),
        )
        for entry in case.assertions["exact_findings"]
    )
    observed = sorted(
        (finding["kind"], tuple(finding["frameworks"]), tuple(finding["model_providers"]))
        for finding in findings
    )
    return {
        "expected": [[kind, list(products), list(providers)] for kind, products, providers in expected],
        "observed": [[kind, list(products), list(providers)] for kind, products, providers in observed],
        "passed": expected == observed,
    }


def _assertions(
    case: Case,
    findings: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    exact_set: dict[str, Any] | None,
) -> list[str]:
    failures = []
    for check in checks:
        if not check["passed"]:
            action = (
                "expected finding missing"
                if check["relation"] == "expected_findings"
                else "forbidden finding observed"
            )
            failures.append(f"{action}: {json.dumps(check['selector'], sort_keys=True)}")
    if exact_set is not None and not exact_set["passed"]:
        failures.append(
            f"exact findings differ: expected {exact_set['expected']}; observed {exact_set['observed']}"
        )
    mcp = [f for f in findings if f["kind"] == Kind.MCP_SERVER.value]
    if "max_agent_findings" in case.assertions:
        observed = sum(f["kind"] == Kind.AGENT.value for f in findings)
        if observed > case.assertions["max_agent_findings"]:
            failures.append(
                f"agent findings: expected at most {case.assertions['max_agent_findings']}; got {observed}"
            )
    if "max_secret_findings" in case.assertions:
        observed = sum(f["kind"] == Kind.SECRET.value for f in findings)
        if observed > case.assertions["max_secret_findings"]:
            failures.append(
                f"secret findings: expected at most {case.assertions['max_secret_findings']}; got {observed}"
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
    forbidden = set(case.assertions.get("forbidden_signatures", []))
    if forbidden:
        observed = sorted(forbidden & {signature for f in findings for signature in f["signatures"]})
        if observed:
            failures.append(f"forbidden signature attributions observed: {observed}")
    return failures


def _percentile(values: list[float], pct: float) -> float:
    # Nearest rank is stable for even and small sample sizes.
    return sorted(values)[max(0, math.ceil(len(values) * pct) - 1)]


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Binary detection scores per labeled case; no assertion of field validity."""
    groups: dict[str, list[dict[str, Any]]] = {"all": rows}
    for row in rows:
        # Defend direct callers as well as the corpus parser. Appending an
        # 'all' family into this aggregate would mutate the list being iterated.
        if row["family"] == "all":
            raise CorpusError("family 'all' is reserved for aggregate metrics")
        groups.setdefault(row["family"], []).append(row)
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


def finding_assertion_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts of explicitly labeled selectors, never inferred from the binary target."""
    groups = {
        name: {"checks": 0, "passed": 0, "failed": 0}
        for name in (*_FINDING_SELECTORS, "kind_only", "product_signature", "provider_signature")
    }
    for row in rows:
        for check in row["finding_checks"]:
            selector = check["selector"]
            fields = [check["relation"]]
            fields.extend(field for field in ("product_signature", "provider_signature") if field in selector)
            if len(fields) == 1:
                fields.append("kind_only")
            for field in fields:
                groups[field]["checks"] += 1
                groups[field]["passed" if check["passed"] else "failed"] += 1
    return {
        "note": "Explicit checks on selected cases; selectors are partial unless exact_findings is set. Overlapping categories are not independent observations or field accuracy.",
        "cases_with_checks": sum(bool(row["finding_checks"]) for row in rows),
        "exact_finding_sets": {
            "checks": sum(row["exact_finding_set"] is not None for row in rows),
            "passed": sum(
                row["exact_finding_set"] is not None and row["exact_finding_set"]["passed"] for row in rows
            ),
            "failed": sum(
                row["exact_finding_set"] is not None and not row["exact_finding_set"]["passed"]
                for row in rows
            ),
        },
        **groups,
    }


def known_gaps(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Separate documented misses and false positives from regressions.

    Flagged cases stay in the metrics so the scores stay honest. ``failing``
    lists the gaps still open; ``passing`` lists flagged cases that now pass
    and whose ``known_gap`` flag should be removed so they guard against
    regression.
    """
    flagged = [row for row in rows if row["known_gap"]]
    return {
        "count": len(flagged),
        "failing": [row["id"] for row in flagged if not row["correct"]],
        "passing": [row["id"] for row in flagged if row["correct"]],
        "regressions": [row["id"] for row in rows if not row["known_gap"] and not row["correct"]],
    }


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


def _source_fingerprint() -> str:
    """Identify the actual scanner sources, including an uncommitted candidate."""
    root = Path(__file__).resolve().parents[2] / "shadowscan"
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
        if annotation_report["corpus_sha256"] != corpus_digest:
            raise CorpusError("corpus changed between evaluation and annotation validation")
    index = get_index()
    rows: list[dict[str, Any]] = []
    durations: list[float] = []
    file_bytes = 0
    with tempfile.TemporaryDirectory(prefix="shadowscan-eval-") as temp:
        # The scanner refuses a scan root that traverses a symbolic link. The
        # platform temporary directory itself can be one (macOS resolves /var
        # and /tmp through /private), so scan the resolved private directory.
        base = Path(temp).resolve()
        for case in cases:
            root = base / case.id
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
            finding_checks = _finding_checks(case, iterations[0][1])
            exact_set = _exact_finding_set(case, iterations[0][1])
            assertion_failures = _assertions(case, iterations[0][1], finding_checks, exact_set)
            rows.append(
                {
                    "id": case.id,
                    "family": case.family,
                    "description": case.description,
                    "source": case.source,
                    "target": {"kind": case.kind.value, "signature": case.signature},
                    "present": case.present,
                    "predicted": bool(matching),
                    "score": score,
                    "correct": case.present == bool(matching) and not assertion_failures,
                    "known_gap": case.known_gap,
                    "assertion_failures": assertion_failures,
                    "finding_checks": finding_checks,
                    "exact_finding_set": exact_set,
                    "findings": iterations[0][1],
                    "median_ms": round(statistics.median(duration for duration, _ in iterations) * 1000, 3),
                }
            )
    gap_report = known_gaps(rows)
    return {
        "schema": 1,
        "corpus": {**metadata, "sha256": corpus_digest},
        "annotation_validation": annotation_report,
        "implementation": {
            "scanner_version": __version__,
            "scanner_source_sha256": _source_fingerprint(),
            "signature_sha256": index.fingerprint(),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "cases": rows,
        "metrics": summarize(rows),
        "finding_assertions": finding_assertion_metrics(rows),
        "known_gaps": gap_report,
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
        # Open gaps are temporarily waived only inside the bounded, unexpired
        # corpus policy validated above. A passing flagged case fails the gate
        # until its obsolete waiver is removed, preventing permanent bypasses.
        "passed": all(row["correct"] or row["known_gap"] for row in rows) and not gap_report["passing"],
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
    parser.add_argument(
        "--annotations", type=Path, help="verify independent labels and corpus digest before scanning"
    )
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
        gaps = report["known_gaps"]
        if gaps["count"]:
            print(
                f"Known gaps: {gaps['count']} flagged; still failing: {gaps['failing']}; "
                f"now passing (remove known_gap): {gaps['passing']}",
                file=sys.stderr,
            )
        if gaps["regressions"]:
            print(f"Regressions: {gaps['regressions']}", file=sys.stderr)
        return 0 if report["passed"] else 1
    except (CorpusError, OSError, RuntimeError, ValueError) as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
