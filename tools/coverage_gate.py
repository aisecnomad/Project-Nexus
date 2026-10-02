"""Fail CI when aggregate coverage hides an untested built-in connector module."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from shadowscan.utils.safe_json import strict_json_loads

MIN_CONNECTOR_COVERAGE = 75.0
CONNECTOR_PACKAGE = ("shadowscan", "connectors")
ROOT = Path(__file__).resolve().parents[1]
_COUNTS = ("num_statements", "covered_lines", "num_branches", "covered_branches")


def connector_modules(root: Path | None = None) -> set[str]:
    """Every Python module under ``shadowscan/connectors/`` in the checkout, at any depth."""
    root = ROOT if root is None else root
    package = root.joinpath(*CONNECTOR_PACKAGE)
    return {path.relative_to(root).as_posix() for path in package.rglob("*.py") if path.is_file()}


def _is_connector_module(path: str) -> bool:
    return Path(path).parts[: len(CONNECTOR_PACKAGE)] == CONNECTOR_PACKAGE and path.endswith(".py")


def _counts(path: str, details: Any) -> dict[str, int]:
    """The four counts of one file entry, each a nonnegative integer with covered <= total."""
    if not isinstance(details, dict) or not isinstance(details.get("summary"), dict):
        raise ValueError(f"{path}: coverage entry must contain a summary object")
    summary = details["summary"]
    counts: dict[str, int] = {}
    for name in _COUNTS:
        value = summary.get(name)
        if type(value) is not int or value < 0:
            raise ValueError(f"{path}: {name} must be a nonnegative integer")
        counts[name] = value
    if (
        counts["covered_lines"] > counts["num_statements"]
        or counts["covered_branches"] > counts["num_branches"]
    ):
        raise ValueError(f"{path}: covered counts exceed the totals")
    return counts


def reported_connector_modules(report: Any) -> set[str]:
    """The connector modules a ``coverage json`` report has an entry for."""
    if not isinstance(report, dict) or not isinstance(report.get("files"), dict):
        raise ValueError("coverage report must contain a files object")
    return {Path(path).as_posix() for path in report["files"] if _is_connector_module(path)}


def connector_coverage(report: Any) -> dict[str, float]:
    """Return the coverage percentage of every connector module in a ``coverage json`` report.

    Every module under ``shadowscan/connectors/`` counts at any depth: the
    family modules and their helpers, and also the shared ``base``, ``common``,
    ``offline`` and registry modules that every connector runs through. Modules
    without statements (empty package markers) have nothing to measure.

    The percentage combines statements and branches, as the aggregate
    ``fail_under`` floor does, so a module cannot pass on lines alone while
    leaving half of its conditions untested. Every count is validated: a
    missing, negative, boolean or fractional count is an invalid report, never
    zero or full coverage.
    """
    measured: dict[str, float] = {}
    for path in sorted(reported_connector_modules(report)):
        counts = _counts(path, report["files"][path])
        total = counts["num_statements"] + counts["num_branches"]
        if not total:
            continue
        covered = counts["covered_lines"] + counts["covered_branches"]
        measured[path] = 100.0 * covered / total
    return measured


def _read_report(path: Path) -> dict[str, float]:
    """Measurements of a report that covers the whole connector inventory of this checkout."""
    report = strict_json_loads(path.read_text(encoding="utf-8"))
    # Statement-only data would let every module pass on lines alone.
    meta = report.get("meta") if isinstance(report, dict) else None
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        raise ValueError("no branch data; run the suite with branch coverage")
    reported = reported_connector_modules(report)
    expected = connector_modules()
    if not expected:
        raise ValueError("checkout contains no built-in connector modules")
    if reported != expected:
        # A report of a selected test run or of another checkout cannot vouch
        # for the modules it never measured.
        missing = ", ".join(sorted(expected - reported)) or "none"
        unexpected = ", ".join(sorted(reported - expected)) or "none"
        raise ValueError(f"connector module inventory mismatch; missing: {missing}; unexpected: {unexpected}")
    return connector_coverage(report)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m tools.coverage_gate COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        measured = _read_report(Path(args[0]))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(f"invalid coverage report: {exc}", file=sys.stderr)
        return 2
    if not measured:
        print("invalid coverage report: no built-in connector module has statements", file=sys.stderr)
        return 2
    failures = [
        f"{path}: {percent:.2f}% < {MIN_CONNECTOR_COVERAGE:.0f}%"
        for path, percent in sorted(measured.items())
        if percent < MIN_CONNECTOR_COVERAGE
    ]
    if failures:
        print("Built-in connector coverage below the CI floor:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    lowest = min(measured, key=lambda path: (measured[path], path))
    print(
        f"Checked {len(measured)} built-in connector modules, statements and branches "
        f"(at least {MIN_CONNECTOR_COVERAGE:.0f}% each; lowest {lowest} at {measured[lowest]:.2f}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
