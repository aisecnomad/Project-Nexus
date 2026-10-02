"""Fail CI when aggregate coverage hides an untested built-in connector.

Every module under ``shadowscan/connectors/`` must be covered by the rule: a
connector module ``shadowscan/connectors/<family>/<module>.py`` of a listed
family meets the per-connector floor, and only the package ``__init__`` files
and the shared helpers directly under ``connectors/`` are exempt. A module in
an unlisted family directory or a nested package fails the gate instead of
being skipped. Modules without statements have nothing to measure.

Exit status: 0 when every connector module meets the floor, 1 when a module is
below it or outside the rule, 2 for a usage error, an unreadable report or a
report without connector modules.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

MIN_CONNECTOR_COVERAGE = 75.0
CONNECTOR_FAMILIES = {"cloud", "code", "gateway", "identity", "lowcode", "saas"}
# Shared helpers directly under shadowscan/connectors/; the aggregate floor
# measures them.
SHARED_MODULES = {"base.py", "common.py", "offline.py"}


def _outside_rule(parts: tuple[str, ...]) -> str | None:
    """Why a connector-package module is not a checked connector or an exempt helper."""
    if len(parts) == 3:
        return None if parts[2] in SHARED_MODULES else "not a listed shared helper under connectors/"
    if len(parts) == 4:
        return None if parts[2] in CONNECTOR_FAMILIES else f"connector family {parts[2]!r} is not listed"
    return "nested package below a connector family"


def main(argv: Sequence[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 1:
        print("usage: python -m tools.coverage_gate COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        files = json.loads(Path(args[0]).read_text(encoding="utf-8"))["files"]
        summaries = {
            path: (
                int(details["summary"]["num_statements"]),
                float(details["summary"]["percent_statements_covered"]),
            )
            for path, details in files.items()
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"cannot read coverage report {args[0]}: {exc!r}", file=sys.stderr)
        return 2
    failures: list[str] = []
    outside: list[str] = []
    examined = 0
    for path, (statements, measured) in sorted(summaries.items()):
        parts = Path(path).parts
        if parts[:2] != ("shadowscan", "connectors") or len(parts) < 3 or parts[-1] == "__init__.py":
            continue
        if not parts[-1].endswith(".py") or not statements:
            continue
        reason = _outside_rule(parts)
        if reason is not None:
            outside.append(f"{path}: {reason}")
            continue
        if len(parts) == 3:
            continue
        examined += 1
        if measured < MIN_CONNECTOR_COVERAGE:
            failures.append(f"{path}: {measured:.2f}% < {MIN_CONNECTOR_COVERAGE:.0f}%")
    if outside:
        print(
            "Connector modules outside the per-connector coverage rule; add the family to "
            "CONNECTOR_FAMILIES in tools/coverage_gate.py or flatten the package:\n" + "\n".join(outside),
            file=sys.stderr,
        )
    if not examined and not outside:
        print("coverage report contains no built-in connector modules", file=sys.stderr)
        return 2
    if failures:
        print("Built-in connector coverage below the CI floor:\n" + "\n".join(failures), file=sys.stderr)
    if failures or outside:
        return 1
    print(f"Checked {examined} built-in connector modules (at least {MIN_CONNECTOR_COVERAGE:.0f}% each)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
