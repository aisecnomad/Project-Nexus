"""Fail CI when aggregate coverage hides an untested built-in connector."""

from __future__ import annotations

import math
import sys
from pathlib import Path

from shadowscan.utils.safe_json import strict_json_loads

MIN_CONNECTOR_COVERAGE = 75.0
CONNECTOR_FAMILIES = {"cloud", "code", "gateway", "identity", "lowcode", "saas"}
ROOT = Path(__file__).resolve().parents[1]


def _is_connector_module(path: str) -> bool:
    parts = Path(path).parts
    return (
        len(parts) == 4
        and parts[:2] == ("shadowscan", "connectors")
        and parts[2] in CONNECTOR_FAMILIES
        and parts[3].endswith(".py")
        and parts[3] != "__init__.py"
    )


def _connector_coverage(report_path: Path) -> dict[str, float]:
    """Require valid measurements for the entire existing connector scope."""
    report = strict_json_loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or not isinstance(report.get("files"), dict):
        raise ValueError("coverage report must contain a files object")
    files = report["files"]
    expected = {
        path.relative_to(ROOT).as_posix()
        for family in CONNECTOR_FAMILIES
        for path in (ROOT / "shadowscan" / "connectors" / family).glob("*.py")
        if path.name != "__init__.py" and path.is_file()
    }
    reported = {path for path in files if _is_connector_module(path)}
    if not expected:
        raise ValueError("checkout contains no built-in connector modules")
    if reported != expected:
        missing = ", ".join(sorted(expected - reported)) or "none"
        unexpected = ", ".join(sorted(reported - expected)) or "none"
        raise ValueError(
            f"connector coverage inventory mismatch; missing: {missing}; unexpected: {unexpected}"
        )
    measured: dict[str, float] = {}
    for path in sorted(expected):
        details = files[path]
        if not isinstance(details, dict) or not isinstance(details.get("summary"), dict):
            raise ValueError(f"{path}: coverage entry must contain a summary object")
        summary = details["summary"]
        statements = summary.get("num_statements")
        percentage = summary.get("percent_statements_covered")
        if type(statements) is not int or statements < 0:
            raise ValueError(f"{path}: num_statements must be a nonnegative integer")
        if (
            type(percentage) not in (int, float)
            or not 0 <= percentage <= 100
            or not math.isfinite(percentage)
        ):
            raise ValueError(f"{path}: percent_statements_covered must be a finite number from 0 to 100")
        if statements:
            measured[path] = float(percentage)
    return measured


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m tools.coverage_gate COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        measured = _connector_coverage(Path(sys.argv[1]))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(f"invalid coverage report: {exc}", file=sys.stderr)
        return 2
    if not measured:
        print("coverage report contains no built-in connector modules", file=sys.stderr)
        return 2
    failures = [
        f"{path}: {percentage:.1f}% < {MIN_CONNECTOR_COVERAGE:.0f}%"
        for path, percentage in measured.items()
        if percentage < MIN_CONNECTOR_COVERAGE
    ]
    if failures:
        print("Built-in connector coverage below the CI floor:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print(f"Checked {len(measured)} built-in connector modules (at least {MIN_CONNECTOR_COVERAGE:.0f}% each)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
