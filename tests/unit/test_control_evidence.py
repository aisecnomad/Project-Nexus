"""``shadowscan controls``: the control evidence report in Markdown, CSV and JSON.

Evidence references, not compliance determinations. These tests pin the
per-control counts and examples, the completeness of the evidence behind each
control (an incomplete input, or a finding whose shadow status or declared risk
class is unknown, is never shown as "not observed"), framework selection,
declared facts, output safety and determinism.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from markdown_it import MarkdownIt

from shadowscan.cli import main
from shadowscan.controls import (
    EVIDENCE_STATUSES,
    INVENTORY_REFS,
    MAX_EXAMPLES,
    NOT_MAPPED,
    NOT_OBSERVED,
    REFERENCED,
    REFERENCED_INCOMPLETE,
    SCHEMA,
    UNKNOWN_INCOMPLETE,
    UNKNOWN_NO_INVENTORY,
    UNKNOWN_NOT_DECLARED,
    ControlSelectionError,
    control_catalogs,
    control_evidence,
)
from shadowscan.fleet import merge_reports
from shadowscan.governance import DECLARED_GOVERNANCE_KEY
from shadowscan.mappings import load_mappings
from shadowscan.mappings.schema import CONTROL_KINDS
from shadowscan.models import Finding, Kind, Risk, RiskLevel, ScanResult, ScanStats, Surface
from shadowscan.reporters.controls import CONTROL_FORMATS, CSV_COLUMNS, render_controls

NOTICE = (
    "Evidence references, not compliance determinations. "
    "Mappings are author mappings and have not been independently reviewed."
)
FORBIDDEN = re.compile(r"\b(compliant|certified|pass|fail)\b", re.IGNORECASE)
SPEC_CSV_COLUMNS = [
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
]
# The controls whose rules read shadow status (shadow-ai-system).
SHADOW_REFS = ("nist-ai-rmf-1.0:GOVERN-1.6", "iso-iec-42001-2023:A.4.2", "aiuc-1-2026q2:E")


def _finding(name: str, score: int = 50, **overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "surface": Surface.CLOUD,
        "connector": "cloud.aws",
        "kind": Kind.AGENT,
        "title": f"Agent {name}",
        "resource": f"arn:aws:bedrock:us-east-1:111111111111:agent/{name}",
        "resource_type": "bedrock-agent",
        "provider": "aws",
        "account": "111111111111",
        "region": "us-east-1",
        "owner": "team",
        "shadow": False,
        "registry_match": "card",
        "risk": Risk(score=score, level=RiskLevel.from_score(score), danger_score=score),
    }
    fields.update(overrides)
    return Finding(**fields)


def _report(*findings: Finding, complete: bool = True, inventory: bool = True) -> dict[str, Any]:
    result = ScanResult(
        findings=list(findings),
        stats=[
            ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00", incomplete=not complete)
        ],
        inventory_present=inventory,
        inventory_size=3 if inventory else 0,
    )
    result.started_at = "2026-01-01T00:00:00+00:00"
    result.finished_at = "2026-01-01T00:05:00+00:00"
    return json.loads(result.to_json())


def _write(tmp_path: Path, report: dict[str, Any], name: str = "report.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _controls(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        control["ref"]: control for framework in evidence["frameworks"] for control in framework["controls"]
    }


def _invoke(*args: str) -> Any:
    return CliRunner().invoke(main, ["controls", *args])


def _standard_report(**options: Any) -> dict[str, Any]:
    return _report(
        _finding("exposed", 90, tags=["hardcoded-credential"]),
        _finding("shadow", 70, shadow=True, registry_match=None),
        _finding("unowned", 30, owner=None),
        **options,
    )


# ------------------------------------------------------------------- document


def test_document_counts_findings_per_control_by_risk_level():
    evidence = control_evidence([("report.json", _standard_report())])
    assert evidence["schema"] == SCHEMA and evidence["notice"] == NOTICE
    assert [f["prefix"] for f in evidence["frameworks"]] == [c.prefix for c in control_catalogs()]
    controls = _controls(evidence)
    # Every entry of every control catalog is listed, referenced or not.
    expected = {e.ref for c in load_mappings().catalogs if c.kind in CONTROL_KINDS for e in c.entries}
    assert set(controls) == expected
    security = controls["nist-ai-rmf-1.0:MEASURE-2.7"]
    assert security["evidence"] == REFERENCED and security["findings"] == 1
    assert security["by_risk_level"] == {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    inventory = controls["nist-ai-rmf-1.0:GOVERN-1.6"]
    assert inventory["findings"] == 1 and inventory["examples"][0]["title"] == "Agent shadow"
    assert inventory["scan_evidence"] == ["Sanctioned inventory supplied (3 registered agents)."]
    owner = controls["iso-iec-42001-2023:A.3.2"]
    assert owner["findings"] == 1 and owner["by_risk_level"]["medium"] == 1
    assert controls["aiuc-1-2026q2:E"]["findings"] == 2
    assert controls["nist-ai-rmf-1.0:GOVERN-1.7"]["evidence"] == NOT_OBSERVED
    # No card declares a risk class, so a high-risk declaration is not ruled out.
    assert controls["eu-ai-act-2024:Art.26"]["evidence"] == UNKNOWN_NOT_DECLARED
    assert controls["aiuc-1-2026q2:A"]["evidence"] == NOT_MAPPED
    assert {control["evidence"] for control in controls.values()} <= set(EVIDENCE_STATUSES)
    scope = evidence["evidence_scope"]
    assert scope["complete"] is True and scope["status"] == "complete" and scope["findings"] == 3
    assert scope["reports"] == [{"name": "report.json", "complete": True, "inventory": True}]
    assert scope["incomplete_connectors"] == [] and scope["inventory"] == "supplied"
    assert evidence["report_finished_at"] == "2026-01-01T00:05:00+00:00"


def test_examples_are_the_ten_highest_risk_findings():
    findings = [_finding(f"a{n:02d}", 40 + n, tags=["wildcard-permissions"]) for n in range(12)]
    evidence = control_evidence([("report.json", _report(*findings))])
    control = _controls(evidence)["eu-ai-act-2024:Art.15"]
    assert control["findings"] == 12 and len(control["examples"]) == MAX_EXAMPLES
    assert [e["risk_score"] for e in control["examples"]] == list(range(51, 41, -1))
    assert control["examples"][0] == {
        "id": findings[11].id,
        "title": "Agent a11",
        "risk_level": "high",
        "risk_score": 51,
        "basis": "observed",
    }
    markdown = render_controls(evidence, "markdown")
    assert "  - … 2 more" in markdown


def test_equal_scores_are_ordered_by_identity():
    findings = [_finding(name, 60, tags=["wildcard-permissions"]) for name in ("b", "a", "c")]
    evidence = control_evidence([("report.json", _report(*findings))])
    ids = [e["id"] for e in _controls(evidence)["eu-ai-act-2024:Art.15"]["examples"]]
    assert ids == sorted(f.id for f in findings)


def test_inventory_refs_are_catalog_entries():
    entries = load_mappings().entries
    assert all(ref in entries and entries[ref].kind == "control" for ref in INVENTORY_REFS)


# ---------------------------------------------------------------- completeness


def test_incomplete_input_never_reads_as_not_observed():
    evidence = control_evidence([("report.json", _standard_report(complete=False))])
    scope = evidence["evidence_scope"]
    assert scope["complete"] is False and scope["status"] == "incomplete"
    assert scope["incomplete_connectors"] == ["cloud.aws", "engine.fleet"]
    statuses = {control["evidence"] for control in _controls(evidence).values()}
    assert NOT_OBSERVED not in statuses
    controls = _controls(evidence)
    assert controls["eu-ai-act-2024:Art.26"]["evidence"] == UNKNOWN_INCOMPLETE
    assert controls["nist-ai-rmf-1.0:MEASURE-2.7"]["evidence"] == REFERENCED_INCOMPLETE
    # A control no rule maps is a property of the catalogs, not of the scan.
    assert controls["aiuc-1-2026q2:A"]["evidence"] == NOT_MAPPED


def test_a_truncated_findings_array_is_incomplete():
    report = _standard_report()
    report["findings"] = report["findings"][:1]
    evidence = control_evidence([("report.json", report)])
    assert evidence["evidence_scope"]["complete"] is False
    assert evidence["evidence_scope"]["reports"][0]["complete"] is False


def test_controls_that_need_an_inventory_are_unknown_without_one():
    report = _report(_finding("a", 50, shadow=None, registry_match=None), inventory=False)
    evidence = control_evidence([("report.json", report)])
    controls = _controls(evidence)
    # The finding could be shadow AI, or declared high-risk or limited-risk: without an inventory
    # neither is known, although other rules for these controls (registry-gap, logging-gap,
    # missing-owner) need no inventory.
    for ref in (*SHADOW_REFS, "eu-ai-act-2024:Art.12", "eu-ai-act-2024:Art.26", "eu-ai-act-2024:Art.50"):
        assert controls[ref]["evidence"] == UNKNOWN_NO_INVENTORY, ref
    # A control whose rules all read observed facts is not affected.
    assert controls["nist-ai-rmf-1.0:GOVERN-2.1"]["evidence"] == NOT_OBSERVED
    assert controls["eu-ai-act-2024:Art.15"]["evidence"] == NOT_OBSERVED
    assert evidence["scan_evidence"] == [
        {
            "fact": "inventory",
            "value": "not supplied",
            "statement": "No sanctioned inventory supplied; shadow status is unknown.",
            "refs": list(INVENTORY_REFS),
        }
    ]


def test_a_scan_without_inventory_never_reads_as_no_shadow_ai(tmp_path):
    report = _report(
        _finding("a", 50, shadow=None, registry_match=None),
        _finding("b", 40, shadow=None, registry_match=None),
        inventory=False,
    )
    result = _invoke(str(_write(tmp_path, report)), "-f", "csv")
    assert result.exit_code == 0, result.output
    rows = {row["ref"]: row for row in csv.DictReader(io.StringIO(result.output))}
    for ref in SHADOW_REFS:
        assert (rows[ref]["findings"], rows[ref]["scan_complete"]) == ("0", "yes")
        assert rows[ref]["evidence"] == UNKNOWN_NO_INVENTORY and rows[ref]["inventory"] == "not supplied"
    assert {row["inventory"] for row in rows.values()} == {"not supplied"}


def test_a_scan_without_findings_has_nothing_unknown():
    evidence = control_evidence([("report.json", _report(inventory=False))])
    controls = _controls(evidence)
    # No finding could reference a control, whatever an inventory would have said about it.
    assert controls["nist-ai-rmf-1.0:GOVERN-1.6"]["evidence"] == NOT_OBSERVED
    assert controls["eu-ai-act-2024:Art.26"]["evidence"] == NOT_OBSERVED
    assert evidence["evidence_scope"]["inventory"] == "not supplied"


def test_a_finding_seen_only_without_an_inventory_leaves_shadow_controls_unknown():
    inventoried = _report(_finding("kept", 40))
    uninventoried = _report(_finding("loose", 55, shadow=None, registry_match=None), inventory=False)
    evidence = control_evidence([("a/report.json", inventoried), ("b/report.json", uninventoried)])
    assert evidence["evidence_scope"]["inventory"] == "partial"
    controls = _controls(evidence)
    for ref in SHADOW_REFS:
        assert controls[ref]["findings"] == 0 and controls[ref]["evidence"] == UNKNOWN_NO_INVENTORY
    rows = list(csv.DictReader(io.StringIO(render_controls(evidence, "csv"))))
    assert {row["inventory"] for row in rows} == {"partial"}
    # With the same finding registered by the inventoried report, nothing is unknown.
    registered = _report(_finding("kept", 40), _finding("loose", 55))
    controls = _controls(control_evidence([("report.json", registered)]))
    assert {controls[ref]["evidence"] for ref in SHADOW_REFS} == {NOT_OBSERVED}


def _declaring(name: str, risk_class: str, **overrides: Any) -> Finding:
    block = {"eu_ai_act_risk_class": risk_class, "source": f"{name}-card"}
    return _finding(name, 50, metadata={DECLARED_GOVERNANCE_KEY: block}, **overrides)


def test_declared_controls_are_not_observed_only_when_every_finding_declares_a_class():
    controls = _controls(control_evidence([("report.json", _report(_declaring("a", "minimal")))]))
    for article in ("Art.12", "Art.14", "Art.26", "Art.50"):
        assert controls[f"eu-ai-act-2024:{article}"]["evidence"] == NOT_OBSERVED, article
    for undeclared in (
        _finding("b", 50),
        _declaring("b", "unknown"),
        _finding("b", 50, shadow=True, registry_match=None),
    ):
        report = _report(_declaring("a", "minimal"), undeclared)
        controls = _controls(control_evidence([("report.json", report)]))
        for article in ("Art.12", "Art.14", "Art.26", "Art.50"):
            assert controls[f"eu-ai-act-2024:{article}"]["evidence"] == UNKNOWN_NOT_DECLARED, article


def test_a_rule_that_cannot_match_a_finding_leaves_no_unknown():
    # Art.50's declared rule needs a user-facing kind; a framework-usage finding never matches it.
    framework = _finding("lib", 30, kind=Kind.FRAMEWORK_USAGE, resource_type="repository")
    controls = _controls(control_evidence([("report.json", _report(_declaring("a", "minimal"), framework))]))
    assert controls["eu-ai-act-2024:Art.50"]["evidence"] == NOT_OBSERVED
    assert controls["eu-ai-act-2024:Art.26"]["evidence"] == UNKNOWN_NOT_DECLARED


# ------------------------------------------------------------- several reports


def test_several_reports_merge_and_never_infer_shadow_from_a_source_without_inventory():
    shared = _finding("shared", 60, shadow=True, registry_match=None)
    only_uninventoried = _finding("loose", 55, shadow=None, registry_match=None)
    with_inventory = _report(shared, _finding("kept", 40))
    without = _report(
        _finding("shared", 60, shadow=None, registry_match=None), only_uninventoried, inventory=False
    )
    evidence = control_evidence([("a/report.json", with_inventory), ("b/report.json", without)])
    scope = evidence["evidence_scope"]
    assert scope["inventory"] == "partial" and scope["findings"] == 3
    assert [report["inventory"] for report in scope["reports"]] == [True, False]
    govern = _controls(evidence)["nist-ai-rmf-1.0:GOVERN-1.6"]
    # Shadow where a source with an inventory said so; unknown, not shadow, for the other.
    assert [e["id"] for e in govern["examples"]] == [shared.id]
    assert evidence["scan_evidence"][0]["value"] == "partial"
    assert "1 of 2 reports" in evidence["scan_evidence"][0]["statement"]


def test_one_incomplete_report_makes_the_merged_evidence_incomplete(tmp_path):
    first = _write(tmp_path, _standard_report(), "first.json")
    second = _write(tmp_path, _standard_report(complete=False), "second.json")
    out = tmp_path / "controls.json"
    result = _invoke(str(first), str(second), "-f", "json", "-o", str(out))
    assert result.exit_code == 3, result.output
    scope = json.loads(out.read_text())["evidence_scope"]
    assert [r["complete"] for r in scope["reports"]] == [True, False] and scope["complete"] is False


def test_an_already_merged_report_is_refused(tmp_path):
    source = _report(_finding("a", 50, shadow=None, registry_match=None), inventory=False)
    merged = json.loads(merge_reports([("noinv.json", source)]).to_json())
    # The merge records the finding seen without an inventory as unassessed (null), and a merged
    # report is refused whatever it records: its sources' scopes are not checked again.
    assert [record["shadow"] for record in merged["findings"]] == [None]
    with pytest.raises(ValueError, match="an already merged report; pass the source reports"):
        control_evidence([("merged.json", merged)])
    result = _invoke(str(_write(tmp_path, merged, "merged.json")))
    assert result.exit_code == 1 and "merged.json: an already merged report" in result.output
    assert "Sanctioned inventory supplied" not in result.output


def test_a_report_without_inventory_never_supplies_shadow_status():
    # A report that says no inventory was supplied is believed, whatever its findings say.
    report = _report(_finding("a", 50, shadow=True, registry_match=None), inventory=False)
    evidence = control_evidence([("report.json", report)])
    assert evidence["evidence_scope"]["reports"][0]["inventory"] is False
    controls = _controls(evidence)
    for ref in SHADOW_REFS:
        assert controls[ref]["findings"] == 0 and controls[ref]["evidence"] == UNKNOWN_NO_INVENTORY
    # A report from before inventory_present existed falls back to its shadow values.
    del report["inventory_present"]
    evidence = control_evidence([("report.json", report)])
    assert evidence["evidence_scope"]["reports"][0]["inventory"] is True
    assert _controls(evidence)["nist-ai-rmf-1.0:GOVERN-1.6"]["evidence"] == REFERENCED


# ------------------------------------------------------------- declared facts


def test_declared_facts_are_labelled_declared():
    block = {
        "eu_ai_act_risk_class": "high",
        "intended_purpose": "Refunds",
        "oversight_measures": ["second approver", "weekly review"],
        "iso42001_scope": True,
        "source": "refunds-card",
    }
    declared = _finding("declared", 65, metadata={DECLARED_GOVERNANCE_KEY: block})
    evidence = control_evidence([("report.json", _report(declared))])
    art26 = _controls(evidence)["eu-ai-act-2024:Art.26"]
    assert art26["findings"] == art26["declared_findings"] == 1
    assert art26["examples"][0]["basis"] == "declared"
    assert evidence["declared_governance"] == [
        {
            "finding": declared.id,
            "title": "Agent declared",
            "source": "refunds-card",
            "eu_ai_act_risk_class": "high",
            "intended_purpose": "Refunds",
            "oversight_measures": ["second approver", "weekly review"],
            "iso42001_scope": True,
        }
    ]
    markdown = render_controls(evidence, "markdown")
    assert "## Declared governance facts" in markdown and "(declared)" in markdown
    assert "| `refunds-card` | high | Refunds | second approver; weekly review |  | yes |" in markdown
    rows = list(csv.DictReader(io.StringIO(render_controls(evidence, "csv"))))
    row = next(r for r in rows if r["ref"] == "eu-ai-act-2024:Art.26")
    assert row["examples"].endswith("[declared]") and row["declared_findings"] == "1"


def test_declared_facts_of_an_unregistered_finding_are_ignored():
    block = {"eu_ai_act_risk_class": "high", "source": "refunds-card"}
    shadow = _finding("x", 65, shadow=True, registry_match=None, metadata={DECLARED_GOVERNANCE_KEY: block})
    evidence = control_evidence([("report.json", _report(shadow))])
    assert _controls(evidence)["eu-ai-act-2024:Art.26"]["findings"] == 0
    assert evidence["declared_governance"] == []


def test_both_bases_count_as_observed():
    block = {"eu_ai_act_risk_class": "high", "source": "card"}
    finding = _finding("both", 70, tags=["no-invocation-logging"], metadata={DECLARED_GOVERNANCE_KEY: block})
    evidence = control_evidence([("report.json", _report(finding))])
    art12 = _controls(evidence)["eu-ai-act-2024:Art.12"]
    assert art12["examples"][0]["basis"] == "observed" and art12["declared_findings"] == 0


# ------------------------------------------------------------------ selection


@pytest.mark.parametrize(
    ("names", "prefixes"),
    [
        ((), ["aiuc-1-2026q2", "eu-ai-act-2024", "iso-iec-42001-2023", "nist-ai-rmf-1.0"]),
        (("eu-ai-act",), ["eu-ai-act-2024"]),
        (("nist-ai-rmf-1.0", "aiuc-1"), ["aiuc-1-2026q2", "nist-ai-rmf-1.0"]),
    ],
)
def test_framework_selection(names, prefixes):
    assert [catalog.prefix for catalog in control_catalogs(names)] == prefixes


@pytest.mark.parametrize("name", ["owasp-llm-2026", "mitre-atlas", "nist", "eu-ai-act-2023"])
def test_unknown_or_threat_frameworks_are_refused(name):
    with pytest.raises(ControlSelectionError, match="must name a control catalog"):
        control_catalogs([name])


def test_cli_framework_selection_limits_rows(tmp_path):
    path = _write(tmp_path, _standard_report())
    result = _invoke(str(path), "-f", "csv", "--framework", "eu-ai-act")
    assert result.exit_code == 0, result.output
    rows = list(csv.DictReader(io.StringIO(result.output)))
    assert [row["control_id"] for row in rows] == ["Art.12", "Art.14", "Art.15", "Art.26", "Art.50"]
    refused = _invoke(str(path), "--framework", "owasp-llm")
    assert refused.exit_code == 1 and "must name a control catalog" in refused.output


# --------------------------------------------------------------------- formats


def test_markdown_output(tmp_path):
    result = _invoke(str(_write(tmp_path, _standard_report())))
    assert result.exit_code == 0, result.output
    text = result.output
    assert text.startswith(
        "# ShadowScan control evidence\n\n_Evidence references, not compliance determinations."
    )
    assert text.count("Mappings are author mappings and have not been independently reviewed.") == 2
    assert "## NIST AI Risk Management Framework (AI 100-1), edition 1.0" in text
    assert "verification: secondary · review: author mapping, not independently reviewed" in text
    assert "| Control | Title | Evidence | Findings | Critical | High | Medium | Low | Info |" in text
    assert (
        "| `MEASURE-2.7` | AI system security and resilience are evaluated | referenced | 1 | 1 | 0 | 0 | 0 | 0 |"
        in text
    )
    assert (
        "| `Art.26` | Obligations of deployers of high-risk AI systems | unknown (risk class not declared) | 0 |"
        in text
    )
    assert "| `GOVERN-1.7` | AI systems are decommissioned and phased out safely | not observed | 0 |" in text
    assert "| `A` | Data and Privacy | not mapped | 0 |" in text
    assert "_Scan evidence for `GOVERN-1.6`: Sanctioned inventory supplied (3 registered agents)._" in text
    assert "INCOMPLETE" not in text


def test_markdown_lists_problem_reports_first_and_caps_long_lists():
    evidence = control_evidence([("report.json", _standard_report())])
    evidence["evidence_scope"]["reports"] = [
        {"name": f"r{n:02d}.json", "complete": n != 59, "inventory": n % 2 == 1} for n in range(60)
    ]
    evidence["declared_governance"] = [
        {"finding": f"ss-{n:03d}", "title": "t", "source": "card", "eu_ai_act_risk_class": "high"}
        for n in range(205)
    ]
    text = render_controls(evidence, "markdown")
    assert "- **Reports:** 60 (1 incomplete, 30 without an inventory)\n  - `r59.json`: incomplete" in text
    # Then the 30 reports without an inventory, then complete ones until 50 are shown.
    assert (
        "  - `r00.json`: complete, no inventory" in text and "  - `r58.json`: complete, no inventory" in text
    )
    assert "  - `r37.json`: complete, inventory supplied" in text and "`r39.json`" not in text
    assert "  - … 10 more in the JSON format" in text
    assert text.count("| `card` | high |") == 200 and "… 5 more in the JSON format." in text


def test_csv_output(tmp_path):
    result = _invoke(str(_write(tmp_path, _standard_report())), "--format", "csv")
    assert result.exit_code == 0, result.output
    rows = list(csv.reader(io.StringIO(result.output)))
    assert rows[0] == CSV_COLUMNS and rows[0][: len(SPEC_CSV_COLUMNS)] == SPEC_CSV_COLUMNS
    records = list(csv.DictReader(io.StringIO(result.output)))
    total = sum(len(c.entries) for c in control_catalogs())
    assert len(records) == total
    row = next(r for r in records if r["ref"] == "nist-ai-rmf-1.0:MEASURE-2.7")
    assert (
        row["framework"] == "nist-ai-rmf" and row["edition"] == "1.0" and row["control_id"] == "MEASURE-2.7"
    )
    assert (row["findings"], row["critical"], row["high"], row["scan_complete"]) == ("1", "1", "0", "yes")
    assert row["examples"].endswith(": Agent exposed (critical 90)")
    assert row["mapping_review"] == "author mapping, not independently reviewed"
    assert row["evidence"] == REFERENCED and row["verification"] == "secondary"
    assert {record["inventory"] for record in records} == {"supplied"}


def test_json_output(tmp_path):
    out = tmp_path / "controls.json"
    result = _invoke(str(_write(tmp_path, _standard_report())), "-f", "json", "-o", str(out))
    assert result.exit_code == 0, result.output
    assert "wrote json control evidence to" in result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA and document["notice"] == NOTICE
    assert document == control_evidence([("report.json", _standard_report())])


@pytest.mark.parametrize("fmt", CONTROL_FORMATS)
def test_incomplete_input_writes_the_banner_and_exits_3(tmp_path, fmt):
    out = tmp_path / f"controls.{fmt}"
    result = _invoke(str(_write(tmp_path, _standard_report(complete=False))), "-f", fmt, "-o", str(out))
    assert result.exit_code == 3, result.output
    text = out.read_text(encoding="utf-8")
    if fmt == "markdown":
        banner = text.index("**INCOMPLETE SCAN: some required inputs could not be assessed.")
        assert banner < text.index("## Evidence scope") and "unknown (scan incomplete)" in text
        assert "| not observed |" not in text
    elif fmt == "csv":
        rows = list(csv.DictReader(io.StringIO(text)))
        assert rows[0]["framework"] == "SCAN-INCOMPLETE" and rows[0]["scan_complete"] == "no"
        assert rows[0]["title"].startswith("INCOMPLETE SCAN:")
        assert {row["scan_complete"] for row in rows} == {"no"}
        assert NOT_OBSERVED not in {row["evidence"] for row in rows}
    else:
        document = json.loads(text)
        assert document["evidence_scope"]["status"] == "incomplete"


def test_an_unknown_format_is_refused():
    evidence = control_evidence([("report.json", _standard_report())])
    with pytest.raises(ValueError, match="unknown control evidence format"):
        render_controls(evidence, "html")


def test_stdout_exit_code_is_3_for_an_incomplete_input(tmp_path):
    result = _invoke(str(_write(tmp_path, _standard_report(complete=False))))
    assert result.exit_code == 3 and "INCOMPLETE SCAN" in result.output


@pytest.mark.parametrize("complete", [True, False])
def test_generated_text_never_reads_as_a_compliance_determination(tmp_path, complete):
    block = {"eu_ai_act_risk_class": "high", "source": "card"}
    report = _report(
        _finding("one", 90, tags=["hardcoded-credential"], metadata={DECLARED_GOVERNANCE_KEY: block}),
        _finding("two", 70, shadow=True, registry_match=None),
        complete=complete,
    )
    evidence = control_evidence([("report.json", report)])
    titles = {e["title"] for f in evidence["frameworks"] for c in f["controls"] for e in c["examples"]}
    for fmt in CONTROL_FORMATS:
        text = render_controls(evidence, fmt)
        for title in titles:
            text = text.replace(title, "")
        assert FORBIDDEN.search(text) is None, (fmt, FORBIDDEN.search(text))
    assert not any(key in json.dumps(evidence) for key in ('"score"', "compliance_score"))


# --------------------------------------------------------------------- safety


def test_csv_cells_are_protected_against_spreadsheet_injection(tmp_path):
    report = _report(
        _finding("x", 90, title='a|=HYPERLINK("https://evil.test")', tags=["wildcard-permissions"]),
        _finding("y", 80, title="b; +cmd", tags=["wildcard-permissions"]),
        _finding("z", 70, title="c,@SUM(1)", tags=["wildcard-permissions"]),
    )
    result = _invoke(str(_write(tmp_path, report)), "-f", "csv", "--framework", "eu-ai-act")
    assert result.exit_code == 0, result.output
    row = next(r for r in csv.DictReader(io.StringIO(result.output)) if r["control_id"] == "Art.15")
    examples = row["examples"]
    # A cell that a spreadsheet could start at a formula trigger (after any delimiter) is text.
    assert "|'=HYPERLINK" in examples and ";' +cmd" in examples and ",'@SUM" in examples
    assert re.search(r"(?:^|[,;\t|\r\n])[\s\"]*[=+\-@]", examples) is None


def test_untrusted_text_is_escaped_in_markdown_and_terminal_csv(tmp_path):
    report = _report(
        _finding("x", 90, title="<script>@admin https://evil.test \x1b[31m", tags=["public-ingress"])
    )
    path = _write(tmp_path, report, "<b>name.json")
    markdown = _invoke(str(path)).output
    assert "<script>" not in markdown and "&lt;script&gt;" in markdown
    assert "hxxps://evil.test" in markdown and "\\[@\\]admin" in markdown and "\x1b" not in markdown
    csv_out = _invoke(str(path), "-f", "csv").output
    assert "\x1b" not in csv_out and "\\u001b" in csv_out


def test_a_pipe_in_a_table_code_span_never_shifts_columns():
    block = {"eu_ai_act_risk_class": "high", "intended_purpose": "Refunds", "source": "card`|x"}
    finding = _finding("y", 60, metadata={DECLARED_GOVERNANCE_KEY: block})
    evidence = control_evidence([("report.json", _report(finding))])
    evidence["declared_governance"][0]["finding"] = "=cmd|' /C calc'!A0"
    text = render_controls(evidence, "markdown")
    markdown = MarkdownIt("default").enable("table")
    rows: list[list[str]] = []
    for token in markdown.parse(text):
        if token.type == "tr_open":
            rows.append([])
        elif token.type == "inline" and token.level == 4:  # a table cell
            rows[-1].append(token.content)
    header = next(row for row in rows if row[:2] == ["Finding", "Card"])
    [row] = [row for row in rows if "calc" in row[0]]
    cells = dict(zip(header, row, strict=True))
    assert len(row) == len(header) == 7
    assert cells["Finding"] == "`=cmd|' /C calc'!A0`" and cells["Card"] == "``card`|x``"
    assert cells["EU AI Act risk class (declared)"] == "high"
    assert cells["Intended purpose (declared)"] == "Refunds"
    page = markdown.render(text)
    assert "<td><code>=cmd|' /C calc'!A0</code></td>" in page and "<td><code>card`|x</code></td>" in page


def test_lone_surrogates_are_written_visibly(tmp_path):
    report = _report(_finding("x", 90, title="agent\ud800name", tags=["public-ingress"]))
    path = _write(tmp_path, report)
    for fmt in CONTROL_FORMATS:
        out = tmp_path / f"out.{fmt}"
        result = _invoke(str(path), "-f", fmt, "-o", str(out))
        assert result.exit_code == 0, result.output
        assert "ud800" in out.read_text(encoding="utf-8")
        stdout = _invoke(str(path), "-f", fmt)
        assert stdout.exit_code == 0 and "ud800" in stdout.output


def test_output_is_private_and_never_written_through_a_symlink(tmp_path):
    path = _write(tmp_path, _standard_report())
    out = tmp_path / "controls.md"
    assert _invoke(str(path), "-o", str(out)).exit_code == 0
    assert os.stat(out).st_mode & 0o777 == 0o600
    target = tmp_path / "target.md"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.md"
    link.symlink_to(target)
    result = _invoke(str(path), "-o", str(link))
    assert result.exit_code == 1 and "could not write control evidence" in result.output
    assert target.read_text(encoding="utf-8") == "keep"


def test_invalid_reports_exit_1(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    result = _invoke(str(broken))
    assert result.exit_code == 1 and "could not read a ShadowScan JSON report" in result.output
    report = _standard_report()
    report["findings"][0]["metadata"][DECLARED_GOVERNANCE_KEY] = {"eu_ai_act_risk_class": "critical"}
    result = _invoke(str(_write(tmp_path, report)))
    assert result.exit_code == 1 and "malformed declared governance" in result.output


def test_output_is_deterministic(tmp_path):
    first, second = (
        _write(tmp_path, _standard_report(), "a.json"),
        _write(tmp_path, _standard_report(), "b.json"),
    )
    for fmt in CONTROL_FORMATS:
        outputs = [_invoke(str(first), str(second), "-f", fmt).output for _ in range(2)]
        assert outputs[0] == outputs[1]
