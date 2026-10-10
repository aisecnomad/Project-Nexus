"""Re-score the v1 results under the v2 error rule, for the v1 erratum (read-only diagnostic).

``python -m tools.benchmark_realworld.erratum_v1 --results tools/benchmark_realworld/results``

v1 counted an error on a clean case as a true negative. v2 counts it as a false alarm,
because an error is never a clean answer. This prints both readings side by side, per
tool and surface, with the number of errors on clean cases that the change moves.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.benchmark_realworld.score import load_rows, scored
from tools.benchmark_realworld.score_v2 import balanced_accuracy, counts


def v1_counts(rows: list[dict]) -> dict[str, int]:
    """The v1 rule: only an ok, detected row is a detection, so an error is not detected."""
    c = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in rows:
        truth = row["label"] != "none"
        flagged = row["status"] == "ok" and bool(row["detected"])
        if truth:
            c["tp" if flagged else "fn"] += 1
        else:
            c["fp" if flagged else "tn"] += 1
    return c


def _rate(num: int, den: int) -> str:
    return f"{num / den:.2f}" if den else "n/a"


def _ba(c: dict[str, int]) -> str:
    value = balanced_accuracy(c)
    return "n/a" if value is None else f"{value:.2f}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(argv)
    rows_by_tool = load_rows(args.results)
    header = (
        "| Tool | Scored | Errors on clean cases | Errors on positives | Specificity v1 | "
        "Specificity v2 | Recall v1 | Recall v2 | BA v1 | BA v2 |"
    )
    for surface in ("repo", "endpoint"):
        print(f"\n## v1 {surface} surface: v1 rule and v2 error rule")
        print(header)
        print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for tool, rows in rows_by_tool.items():
            mine = scored(rows, surface)
            if not mine or all(r["status"] == "n/a" for r in mine):
                continue
            c1, c2 = v1_counts(mine), counts(mine)
            clean_errors = sum(1 for r in mine if r["status"] == "error" and r["label"] == "none")
            positive_errors = sum(1 for r in mine if r["status"] == "error" and r["label"] != "none")
            cells = [
                tool,
                str(len(mine)),
                str(clean_errors),
                str(positive_errors),
                _rate(c1["tn"], c1["tn"] + c1["fp"]),
                _rate(c2["tn"], c2["tn"] + c2["fp"]),
                _rate(c1["tp"], c1["tp"] + c1["fn"]),
                _rate(c2["tp"], c2["tp"] + c2["fn"]),
                _ba(c1),
                _ba(c2),
            ]
            print("| " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
