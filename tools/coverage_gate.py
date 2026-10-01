"""Fail CI when aggregate coverage hides an untested built-in connector module."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

MIN_CONNECTOR_COVERAGE = 75.0
CONNECTOR_PACKAGE = ("shadowscan", "connectors")


def connector_coverage(report: dict[str, Any]) -> dict[str, float]:
    """Return the coverage percentage of every connector module in a ``coverage json`` report.

    Every module under ``shadowscan/connectors/`` counts at any depth: the
    family modules and their helpers, and also the shared ``base``, ``common``,
    ``offline`` and registry modules that every connector runs through. Modules
    without statements (empty package markers) have nothing to measure.
    """
    measured: dict[str, float] = {}
    for path, details in report["files"].items():
        parts = Path(path).parts
        if parts[: len(CONNECTOR_PACKAGE)] != CONNECTOR_PACKAGE or not path.endswith(".py"):
            continue
        summary = details["summary"]
        total = summary["num_statements"]
        if not total:
            continue
        measured[Path(*parts).as_posix()] = 100.0 * summary["covered_lines"] / total
    return measured


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m tools.coverage_gate COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        report = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        measured = connector_coverage(report)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"unreadable coverage report: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if not measured:
        print("coverage report contains no built-in connector modules", file=sys.stderr)
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
        f"Checked {len(measured)} built-in connector modules "
        f"(at least {MIN_CONNECTOR_COVERAGE:.0f}% each; lowest {lowest} at {measured[lowest]:.2f}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
