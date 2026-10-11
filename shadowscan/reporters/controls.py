"""Control evidence report output: Markdown tables, CSV for GRC tools and JSON.

Renders the ``shadowscan.control-evidence/v1`` document of
:func:`shadowscan.controls.build_control_evidence`. Every format carries the
notice that these are evidence references, not compliance determinations, and
an incomplete input is marked before any control row. Untrusted text (finding
titles, report names) uses the Markdown reporter's escaping and the CSV
reporter's spreadsheet-injection protection; a code span in a Markdown table
cell also escapes ``|``, which would otherwise end the cell.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from shadowscan.controls import UNKNOWN_INCOMPLETE
from shadowscan.governance import FIELD_LABELS, GOVERNANCE_FIELDS
from shadowscan.reporters.csv_ import _safe_cell
from shadowscan.reporters.markdown import _code, _text

CONTROL_FORMATS = ("markdown", "csv", "json")
CSV_COLUMNS = [
    "framework",
    "edition",
    "control_id",
    "title",
    "findings",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "examples",
    "scan_complete",
    "inventory",
    "evidence",
    "declared_findings",
    "ref",
    "verification",
    "mapping_review",
]
_LEVELS = ("critical", "high", "medium", "low", "info")
_REVIEW_LABELS = {"author": "author mapping, not independently reviewed"}
_MAX_DECLARED_ROWS = 200
_MAX_REPORT_ROWS = 50
_INCOMPLETE = (
    "INCOMPLETE SCAN: some required inputs could not be assessed. A control that no finding"
    " references is unknown, not absent, and counts are lower bounds (exit code 3)."
)


def _cell_code(value: object) -> str:
    """A code span for a table cell: GFM splits cells at ``|`` before reading code spans, unless escaped."""
    return _code(value).replace("|", "\\|")


def _review(framework: dict[str, Any]) -> str:
    """A short review label for a table cell; the full statement when there is none."""
    return str(_REVIEW_LABELS.get(framework["review"], framework["review_statement"]))


def _example_text(example: dict[str, Any]) -> str:
    declared = " [declared]" if example["basis"] == "declared" else ""
    return f"{example['id']}: {example['title']} ({example['risk_level']} {example['risk_score']}){declared}"


def _governance_value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return str(value)


def render_controls_json(evidence: dict[str, Any]) -> str:
    return json.dumps(evidence, indent=2, allow_nan=False) + "\n"


def render_controls_csv(evidence: dict[str, Any]) -> str:
    """One row per control; an incomplete input adds a status row first, after the header."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    complete = evidence["evidence_scope"]["complete"]
    inventory = evidence["evidence_scope"]["inventory"]
    if not complete:
        row = {
            "framework": "SCAN-INCOMPLETE",
            "control_id": "SCAN-INCOMPLETE",
            "title": _INCOMPLETE,
            "scan_complete": "no",
            "inventory": inventory,
            "evidence": UNKNOWN_INCOMPLETE,
        }
        writer.writerow({key: _safe_cell(value) for key, value in row.items()})
    for framework in evidence["frameworks"]:
        for control in framework["controls"]:
            row = {
                "framework": framework["framework"],
                "edition": framework["edition"],
                "control_id": control["control_id"],
                "title": control["title"],
                "findings": control["findings"],
                **{level: control["by_risk_level"].get(level, 0) for level in _LEVELS},
                "examples": " | ".join(_example_text(example) for example in control["examples"]),
                "scan_complete": "yes" if complete else "no",
                "inventory": inventory,
                "evidence": control["evidence"],
                "declared_findings": control["declared_findings"],
                "ref": control["ref"],
                "verification": framework["verification"],
                "mapping_review": _review(framework),
            }
            writer.writerow({key: _safe_cell(value) for key, value in row.items()})
    return buf.getvalue()


def _report_lines(reports: list[dict[str, Any]]) -> list[str]:
    """One summary line, then each report: incomplete ones first, then those without an inventory."""
    incomplete = sum(1 for report in reports if not report["complete"])
    uninventoried = sum(1 for report in reports if not report["inventory"])
    lines = [f"- **Reports:** {len(reports)} ({incomplete} incomplete, {uninventoried} without an inventory)"]
    ordered = sorted(reports, key=lambda report: (report["complete"], report["inventory"]))
    for report in ordered[:_MAX_REPORT_ROWS]:
        lines.append(
            f"  - {_code(report['name'])}: {'complete' if report['complete'] else 'incomplete'}, "
            f"{'inventory supplied' if report['inventory'] else 'no inventory'}"
        )
    if len(reports) > _MAX_REPORT_ROWS:
        lines.append(f"  - … {len(reports) - _MAX_REPORT_ROWS} more in the JSON format")
    return lines


def _scope_lines(evidence: dict[str, Any]) -> list[str]:
    scope = evidence["evidence_scope"]
    unfinished = ", ".join(_code(name) for name in scope["incomplete_connectors"]) or "none"
    statement = next(item["statement"] for item in evidence["scan_evidence"] if item["fact"] == "inventory")
    return [
        "## Evidence scope",
        "",
        *_report_lines(scope["reports"]),
        f"- **Scan status:** {scope['status']}",
        f"- **Incomplete connectors:** {unfinished}",
        f"- **Inventory:** {_text(statement)}",
        f"- **Findings considered:** {scope['findings']}",
        f"- **Reports finished:** {_text(evidence['report_finished_at'] or 'unknown')}",
        "",
    ]


def _framework_lines(framework: dict[str, Any]) -> list[str]:
    lines = [
        f"## {_text(framework['name'])}, edition {_text(framework['edition'])}",
        "",
        f"Prefix {_code(framework['prefix'])} · verification: {_text(framework['verification'])}"
        f" · review: {_text(_review(framework))} · source: {_code(framework['source_url'])}",
        "",
        "| Control | Title | Evidence | Findings | Critical | High | Medium | Low | Info |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for control in framework["controls"]:
        counts = " | ".join(str(control["by_risk_level"].get(level, 0)) for level in _LEVELS)
        lines.append(
            f"| {_cell_code(control['control_id'])} | {_text(control['title'])}"
            f" | {_text(control['evidence'])} | {control['findings']} | {counts} |"
        )
    lines.append("")
    referenced = [control for control in framework["controls"] if control["examples"]]
    if referenced:
        lines += ["### Highest-risk findings per control", ""]
        for control in referenced:
            lines.append(f"- {_code(control['control_id'])} {_text(control['title'])}")
            for example in control["examples"]:
                declared = " (declared)" if example["basis"] == "declared" else ""
                lines.append(
                    f"  - {_code(example['id'])} {_text(example['title'])}"
                    f" — {_text(example['risk_level'])} {_text(example['risk_score'])}{declared}"
                )
            more = control["findings"] - len(control["examples"])
            if more > 0:
                lines.append(f"  - … {more} more")
        lines.append("")
    notes = sorted({note for control in framework["controls"] for note in control["scan_evidence"]})
    for note in notes:
        refs = [
            control["control_id"] for control in framework["controls"] if note in control["scan_evidence"]
        ]
        lines += [f"_Scan evidence for {', '.join(_code(ref) for ref in refs)}: {_text(note)}_", ""]
    return lines


def _declared_lines(declared: list[dict[str, Any]]) -> list[str]:
    if not declared:
        return []
    lines = [
        "## Declared governance facts",
        "",
        "_Declared by the inventory card that registered each finding. ShadowScan does not verify them._",
        "",
        "| Finding | Card | "
        + " | ".join(
            f"{FIELD_LABELS[key][:1].upper()}{FIELD_LABELS[key][1:]} (declared)" for key in GOVERNANCE_FIELDS
        )
        + " |",
        "|---|---|" + "---|" * len(GOVERNANCE_FIELDS),
    ]
    for item in declared[:_MAX_DECLARED_ROWS]:
        values = " | ".join(
            _text(_governance_value(item[key])) if key in item else "" for key in GOVERNANCE_FIELDS
        )
        lines.append(f"| {_cell_code(item['finding'])} | {_cell_code(item['source'])} | {values} |")
    if len(declared) > _MAX_DECLARED_ROWS:
        lines.append("")
        lines.append(f"… {len(declared) - _MAX_DECLARED_ROWS} more in the JSON format.")
    lines.append("")
    return lines


def render_controls_markdown(evidence: dict[str, Any]) -> str:
    notice = f"_{_text(evidence['notice'])}_"
    lines = ["# ShadowScan control evidence", "", notice, ""]
    if not evidence["evidence_scope"]["complete"]:
        lines += [f"**{_text(_INCOMPLETE)}**", ""]
    lines += _scope_lines(evidence)
    for framework in evidence["frameworks"]:
        lines += _framework_lines(framework)
    lines += _declared_lines(evidence["declared_governance"])
    lines += ["---", "", notice, ""]
    return "\n".join(lines)


def render_controls(evidence: dict[str, Any], fmt: str) -> str:
    """``evidence`` in one of :data:`CONTROL_FORMATS`; any other format raises ``ValueError``."""
    if fmt == "markdown":
        return render_controls_markdown(evidence)
    if fmt == "csv":
        return render_controls_csv(evidence)
    if fmt == "json":
        return render_controls_json(evidence)
    raise ValueError(f"unknown control evidence format: {fmt}")
