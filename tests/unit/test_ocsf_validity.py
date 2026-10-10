"""OCSF output must stay a valid Detection Finding stream and never hide an incomplete scan.

Severity carries the heuristic risk level, not CVSS (docs/severity.md), and
``status_id`` never invents a triage state.
"""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from typing import Any

import pytest

from shadowscan import __version__
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, RiskLevel, ScanResult, ScanStats, Surface
from shadowscan.reporters import render
from shadowscan.reporters.ocsf import render_ocsf

UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
STARTED = "2026-01-01T00:00:00+00:00"
FINISHED = "2026-01-01T00:00:09+00:00"
SEVERITIES = {
    RiskLevel.INFO: (1, "Informational"),
    RiskLevel.LOW: (2, "Low"),
    RiskLevel.MEDIUM: (3, "Medium"),
    RiskLevel.HIGH: (4, "High"),
    RiskLevel.CRITICAL: (5, "Critical"),
}


def _stats(**overrides: Any) -> ScanStats:
    return ScanStats(connector="code.filesystem", started_at=STARTED, **overrides)


def _finding(*evidence: Evidence, **overrides: Any) -> Finding:
    fields: dict[str, Any] = dict(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="Agent project",
        resource="/repo/app",
        resource_type="project",
        frameworks=["framework.langchain"],
    )
    fields.update(overrides)
    finding = Finding(**fields)
    for item in evidence:
        finding.add_evidence(item)
    return finding


def _render(*findings: Finding, stats: list[ScanStats] | None = None, **result_fields: Any) -> dict[str, Any]:
    result_fields.setdefault("started_at", STARTED)
    result_fields.setdefault("finished_at", FINISHED)
    result = ScanResult(
        findings=list(findings), stats=stats if stats is not None else [_stats()], **result_fields
    )
    return json.loads(render_ocsf(result))


def _nulls(node: Any, path: str = "$") -> list[str]:
    """Paths of every key whose value is null."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if value is None:
                found.append(f"{path}.{key}")
            found.extend(_nulls(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found.extend(_nulls(value, f"{path}[{i}]"))
    return found


def _timestamp_strings(node: Any) -> list[tuple[str, str]]:
    """Every (key, value) whose key names a timestamp the document publishes as a string."""
    pairs: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and (key.endswith("_dt") or key in {"started_at", "finished_at"}):
                pairs.append((key, value))
            pairs.extend(_timestamp_strings(value))
    elif isinstance(node, list):
        for value in node:
            pairs.extend(_timestamp_strings(value))
    return pairs


def _assert_event_shape(event: dict[str, Any]) -> None:
    assert event["activity_id"] == 1 and event["activity_name"] == "Create"
    assert event["category_uid"] == 2 and event["category_name"] == "Findings"
    assert event["class_uid"] == 2004 and event["class_name"] == "Detection Finding"
    assert event["type_uid"] == 200401
    assert event["severity_id"] in {1, 2, 3, 4, 5}
    assert event["status_id"] == 1 and event["status"] == "New"
    assert event["metadata"]["version"] == "1.1.0"
    assert event["metadata"]["product"] == {
        "name": "ShadowScan",
        "version": __version__,
        "vendor_name": "Project Nexus",
    }
    # ``time_dt`` and the ``*_dt`` twins are attributes of the datetime profile.
    assert event["metadata"]["profiles"] == ["datetime"]
    info = event["finding_info"]
    assert info["uid"] and info["title"] and info["types"]
    assert event["resources"] and event["resources"][0]["uid"]
    assert isinstance(event["confidence_score"], int) and 0 <= event["confidence_score"] <= 100


# ------------------------------------------------------------- sample scan


def test_sample_scan_renders_one_conformant_event_per_finding(fixtures, index):
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec(
                name="code.filesystem", config={"path": str(fixtures / "sample_repo"), "label": "repo"}
            )
        ]
    )
    result = Engine(cfg, index).run()
    assert result.complete and result.findings
    document = json.loads(render_ocsf(result))
    assert _nulls(document) == []
    assert document["ocsf_version"] == "1.1.0"
    assert len(document["events"]) == len(result.findings)
    for event, finding in zip(document["events"], result.findings, strict=True):
        _assert_event_shape(event)
        assert event["finding_info"]["uid"] == finding.id
        assert event["finding_info"]["types"] == [finding.kind.value]
        assert event["severity_id"] == SEVERITIES[finding.risk.level][0]
        assert event["unmapped"]["connector"] == finding.connector
    scan = document["scan"]
    assert scan["status"] == "complete" and scan["complete"] is True
    assert scan["summary"]["total"] == len(result.findings)
    assert [st["connector"] for st in scan["connectors"]] == [st.connector for st in result.stats]
    assert render(result, "ocsf") == render_ocsf(result)


# -------------------------------------------------------- severity mapping


@pytest.mark.parametrize("level", list(RiskLevel))
def test_severity_id_carries_the_heuristic_risk_level(level):
    finding = _finding()
    finding.risk.level = level
    (event,) = _render(finding)["events"]
    severity_id, severity = SEVERITIES[level]
    assert event["severity_id"] == severity_id and event["severity"] == severity
    # risk_level_id is the same heuristic level on the 0..4 scale, never CVSS.
    assert event["risk_level_id"] == severity_id - 1
    assert event["unmapped"]["score_basis"] == "heuristic-not-cvss"
    assert event["status_id"] == 1 and event["status"] == "New"


# --------------------------------------------------------- incomplete scan


def test_incomplete_scan_is_unmistakably_marked():
    stats = [
        _stats(finished_at="2026-01-01T00:00:03+00:00"),
        ScanStats(
            connector="cloud.aws",
            started_at=STARTED,
            errors=["cannot enumerate scope"],
            warnings=["partial listing"],
            skipped=True,
            skip_reason="denied",
        ),
    ]
    document = _render(_finding(), stats=stats)
    scan = document["scan"]
    assert scan["status"] == "incomplete" and scan["complete"] is False
    assert scan["summary"]["status"] == "incomplete"
    denied = next(st for st in scan["connectors"] if st["connector"] == "cloud.aws")
    assert denied["errors"] == ["cannot enumerate scope"]
    assert denied["warnings"] == ["partial listing"]
    assert denied["skipped"] is True and denied["skip_reason"] == "denied"
    assert _nulls(document) == []


def test_incomplete_scan_with_no_findings_never_looks_empty():
    document = _render(stats=[_stats(errors=["export rejected"])])
    assert document["events"] == []
    assert document["scan"]["status"] == "incomplete" and document["scan"]["complete"] is False
    assert document["scan"]["connectors"][0]["errors"] == ["export rejected"]


# ------------------------------------------------------------- null fields


def test_null_valued_keys_are_omitted():
    finding = _finding(
        provider=None,
        account=None,
        region=None,
        owner=None,
        shadow=None,
        registry_match=None,
        first_seen=None,
        last_seen=None,
    )
    document = _render(finding, finished_at=None)
    assert _nulls(document) == []
    (event,) = document["events"]
    assert set(event["resources"][0]) == {"uid", "type"}
    for key in ("shadow", "registry_match", "models", "capabilities"):
        assert key not in event["unmapped"], key
    for key in ("first_seen_time", "first_seen_time_dt", "last_seen_time", "last_seen_time_dt"):
        assert key not in event["finding_info"], key
    assert "finished_at" not in document["scan"]


def test_unparseable_timestamps_are_omitted_not_invented():
    document = _render(_finding(), started_at="not a timestamp", finished_at="")
    (event,) = document["events"]
    assert "time" not in event and "time_dt" not in event
    assert "started_at" not in document["scan"] and "finished_at" not in document["scan"]
    assert _nulls(document) == []


# ---------------------------------------------------------- non-finite data


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_nonfinite_confidence_fails_publication(value):
    finding = _finding()
    result = ScanResult(findings=[finding], stats=[_stats()])
    finding.confidence = value
    with pytest.raises(ValueError, match="Out of range float values"):
        render_ocsf(result)


# ------------------------------------------------------------- timestamps


def test_timestamps_are_epoch_millis_plus_z_suffixed_utc():
    finding = _finding(first_seen="2026-01-02T03:04:05+02:00", last_seen="2026-01-02T03:04:05.250000Z")
    document = _render(finding)
    pairs = _timestamp_strings(document)
    assert pairs and all(UTC_TIMESTAMP.match(value) for _, value in pairs), pairs
    (event,) = document["events"]
    finished = datetime.fromisoformat(FINISHED).astimezone(UTC)
    assert event["time"] == round(finished.timestamp() * 1000)
    assert event["time_dt"] == "2026-01-01T00:00:09Z"
    info = event["finding_info"]
    assert info["first_seen_time_dt"] == "2026-01-02T01:04:05Z"
    first_seen = datetime.fromisoformat("2026-01-02T03:04:05+02:00")
    assert info["first_seen_time"] == round(first_seen.timestamp() * 1000)
    assert info["last_seen_time_dt"] == "2026-01-02T03:04:05.250000Z"
    assert document["scan"]["started_at"] == "2026-01-01T00:00:00Z"
    assert document["scan"]["finished_at"] == "2026-01-01T00:00:09Z"


def test_naive_timestamps_are_taken_as_utc():
    # The engine only records aware UTC timestamps; a naive value from an
    # imported report is taken as UTC rather than the renderer's local zone.
    (event,) = _render(_finding(first_seen="2026-01-02T03:04:05"))["events"]
    assert event["finding_info"]["first_seen_time_dt"] == "2026-01-02T03:04:05Z"
    expected = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert event["finding_info"]["first_seen_time"] == round(expected.timestamp() * 1000)


# ---------------------------------------------------------- field mapping


def test_resources_evidence_and_unmapped_carry_the_finding_context():
    evidence = Evidence(
        signal="import",
        description="import of langchain",
        location="/repo/app.py:3",
        snippet="x" * 300,
        weight=0.9,
        signature="framework.langchain",
    )
    finding = _finding(
        evidence,
        provider="aws",
        account="123456789012",
        region="eu-west-1",
        owner="ml-team",
        shadow=True,
        registry_match="agent-001",
        tags=["a", "a", "b"],
        model_providers=["provider.openai"],
        confidence=0.42,
    )
    (event,) = _render(finding)["events"]
    assert event["resources"] == [
        {
            "uid": "/repo/app",
            "type": "project",
            "region": "eu-west-1",
            "owner": {"name": "ml-team"},
            "data": {"provider": "aws", "account": "123456789012"},
        }
    ]
    (evidence_entry,) = event["evidences"]
    assert evidence_entry["data"]["signal"] == "import"
    assert evidence_entry["data"]["location"] == "/repo/app.py:3"
    assert evidence_entry["data"]["snippet"] == "x" * 200
    assert evidence_entry["data"]["signature"] == "framework.langchain"
    assert event["confidence_score"] == 42
    unmapped = event["unmapped"]
    assert unmapped["shadow"] is True and unmapped["registry_match"] == "agent-001"
    assert unmapped["tags"] == ["a", "b"]
    assert unmapped["frameworks"] == ["framework.langchain"]
    assert unmapped["model_providers"] == ["provider.openai"]
    assert unmapped["confidence"] == 0.42 and unmapped["likelihood"] == "possible"


# -------------------------------------------------------- untrusted titles


def test_untrusted_title_round_trips_as_a_plain_json_string():
    title = "[bold red]Agent[/bold red] \x1b]0;owned\x07 ‮ run"
    finding = _finding(title=title)
    output = render_ocsf(ScanResult(findings=[finding], stats=[_stats()]))
    # JSON escapes every control and non-ASCII character; none reaches a terminal raw.
    assert all(raw not in output for raw in ("\x1b", "\x07", "‮"))
    (event,) = json.loads(output)["events"]
    assert event["message"] == title
    assert event["finding_info"]["title"] == title
