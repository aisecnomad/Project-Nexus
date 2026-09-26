"""Fail CI when aggregate coverage hides an untested built-in connector."""

from __future__ import annotations

import json
import sys
from pathlib import Path

MIN_CONNECTOR_COVERAGE = 75.0
CONNECTOR_FAMILIES = {"cloud", "code", "gateway", "identity", "lowcode", "saas"}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m tools.coverage_gate COVERAGE_JSON", file=sys.stderr)
        return 2
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    files = report["files"]
    failures: list[str] = []
    examined = 0
    for path, details in sorted(files.items()):
        parts = Path(path).parts
        # Include modules in any subpackage of a connector family, so a new
        # nested package cannot silently escape the floor.
        if (
            len(parts) < 4
            or parts[:2] != ("shadowscan", "connectors")
            or parts[2] not in CONNECTOR_FAMILIES
            or not parts[-1].endswith(".py")
            or parts[-1] == "__init__.py"
        ):
            continue
        summary = details["summary"]
        if not summary["num_statements"]:
            continue
        examined += 1
        measured = summary["percent_statements_covered"]
        if measured < MIN_CONNECTOR_COVERAGE:
            failures.append(f"{path}: {measured:.1f}% < {MIN_CONNECTOR_COVERAGE:.0f}%")
    if not examined:
        print("coverage report contains no built-in connector modules", file=sys.stderr)
        return 2
    if failures:
        print("Built-in connector coverage below the CI floor:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print(f"Checked {examined} built-in connector modules (at least {MIN_CONNECTOR_COVERAGE:.0f}% each)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
