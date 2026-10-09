"""CSV output (one row per finding; evidence summarised)."""

from __future__ import annotations

import csv
import io
import re

from shadowscan.models import ScanResult
from shadowscan.reporters._publication import publication_stats, visible_controls

COLUMNS = [
    "id",
    "risk_level",
    "risk_score",
    "shadow",
    "registry_match",
    "surface",
    "kind",
    "title",
    "resource",
    "resource_type",
    "provider",
    "account",
    "region",
    "owner",
    "confidence",
    "likelihood",
    "frameworks",
    "model_providers",
    "models",
    "capabilities",
    "tags",
    "permissions",
    "first_seen",
    "last_seen",
    "risk_factors",
    "evidence_count",
    "top_evidence",
    "connector",
]

# A spreadsheet cell must not begin with a formula trigger (OWASP CSV injection).
# A value can start several cells: a report opened with another delimiter (for
# example a semicolon locale), or a joined list split on "|", starts a new cell
# after each delimiter or line break. Leading whitespace, including a no-break
# space, and quotes may be trimmed, so they do not hide a trigger. A value that
# starts with a tab or line break, or a later cell that does, is also neutralised.
#
# The marks are found in one backwards pass. Reading ahead from every cell start
# (a lookahead over the whitespace that may precede a trigger) rescans a long
# run of line breaks once per break, which is quadratic in the length of the run.
_CELL_DELIMITERS = frozenset(",;\t|\r\n")
_CELL_TRIMMED = frozenset(' \t\r\n\v\f\ufeff\u00a0"')
_FORMULA_TRIGGERS = frozenset("=+-@")
# Nothing to mark without a trigger or a tab, carriage return or line feed.
_FORMULA_HINT = re.compile(r"[=+\-@\t\r\n]")


def _formula_marks(value: str) -> list[int]:
    """Offsets where a cell of ``value`` starts with a formula trigger, a tab or a carriage return.

    Also offset 0 when the value starts with a line feed. In descending order.
    """
    marks: list[int] = []
    trigger_ahead = False  # the first character after any trimmed ones is a trigger
    for index in range(len(value) - 1, -1, -1):
        char = value[index]
        if char in _FORMULA_TRIGGERS:
            trigger_ahead = True
        elif char not in _CELL_TRIMMED:
            trigger_ahead = False
        if index == 0:
            if char in "\t\r\n" or trigger_ahead:
                marks.append(0)
        elif (char in "\t\r" or trigger_ahead) and value[index - 1] in _CELL_DELIMITERS:
            marks.append(index)
    return marks


def _safe_cell(value: object) -> object:
    """Force every formula-like cell in an untrusted string to spreadsheet text and show terminal controls."""
    if not isinstance(value, str):
        return value
    # Tab, CR and LF stay: they are cell data, and the formula guard below needs them.
    value = visible_controls(value, keep="\t\r\n")
    if _FORMULA_HINT.search(value) is None:
        return value
    pieces: list[str] = []
    cursor = 0
    for mark in reversed(_formula_marks(value)):
        pieces.append(value[cursor:mark])
        pieces.append("'")
        cursor = mark
    pieces.append(value[cursor:])
    return "".join(pieces)


def _status_row(result: ScanResult) -> dict[str, object]:
    """First record of an incomplete scan, so a partial file cannot pass for an empty one.

    The header stays the first line, so ``csv.DictReader`` consumers keep their
    column names. The row carries no finding data and no diagnostic text; the
    JSON report has the connector errors.
    """
    unfinished = [
        st["connector"]
        for st in publication_stats(result)
        if st["errors"] or st["skipped"] or st["incomplete"]
    ]
    return {
        "id": "SCAN-INCOMPLETE",
        "kind": "scan-status",
        "resource_type": "scan-status",
        "title": "INCOMPLETE SCAN: some required inputs could not be assessed; "
        "missing rows are not evidence of absence (exit code 3)",
        "connector": "|".join(unfinished),
    }


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    w.writeheader()
    if not result.complete:
        w.writerow({key: _safe_cell(value) for key, value in _status_row(result).items()})
    for f in result.findings:
        f.sanitize()
        top_evidence = sorted(f.evidence, key=lambda e: -e.weight)[:3]
        row = {
            "id": f.id,
            "risk_level": f.risk.level.value,
            "risk_score": f.risk.score,
            "shadow": "" if f.shadow is None else ("yes" if f.shadow else "no"),
            "registry_match": f.registry_match or "",
            "surface": f.surface.value,
            "kind": f.kind.value,
            "title": f.title,
            "resource": f.resource,
            "resource_type": f.resource_type,
            "provider": f.provider or "",
            "account": f.account or "",
            "region": f.region or "",
            "owner": f.owner or "",
            "confidence": f.confidence,
            "likelihood": f.likelihood.value,
            "frameworks": "|".join(f.frameworks),
            "model_providers": "|".join(f.model_providers),
            "models": "|".join(f.models),
            "capabilities": "|".join(f.capabilities),
            "tags": "|".join(f.tags),
            "permissions": "|".join(f.permissions),
            "first_seen": f.first_seen or "",
            "last_seen": f.last_seen or "",
            "risk_factors": "; ".join(x.description for x in f.risk.factors if x.weight > 0),
            "evidence_count": len(f.evidence),
            "top_evidence": " | ".join(e.description for e in top_evidence),
            "connector": f.connector,
        }
        w.writerow({key: _safe_cell(value) for key, value in row.items()})
    return buf.getvalue()
