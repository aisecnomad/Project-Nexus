"""Baseline pinning (`--baseline-sha256`) and expiry (`--max-baseline-age-days`) for `shadowscan diff`.

A pinned baseline is refused unless its file has exactly the reviewed digest;
an expired or undatable baseline makes the comparison incomplete, so missing
findings stay unknown rather than resolved.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import (
    MAX_BASELINE_AGE_DAYS,
    ReportDigestMismatch,
    baseline_age_days,
    baseline_lifecycle_reasons,
    compare_reports,
    load_report,
    load_report_with_digest,
)
from shadowscan.fleet import merge_reports
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.utils.files import read_policy_bytes

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
EXPIRED = "baseline is older than --max-baseline-age-days"


def _finding(resource: str) -> dict[str, Any]:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=f"Agent {resource}",
        resource=resource,
        resource_type="repository",
    ).to_dict()


def _report(*findings: dict[str, Any], started: datetime | str | None = NOW) -> dict[str, Any]:
    report = ScanResult(
        stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01")],
        collection_scope={
            "schema": "shadowscan.collection-scope/v1",
            "comparable": True,
            "fingerprint": "a" * 64,
        },
    ).to_dict()
    report["findings"] = list(findings)
    report["summary"].update(
        total=len(findings),
        by_surface=dict(Counter(finding["surface"] for finding in findings)),
        by_kind=dict(Counter(finding["kind"] for finding in findings)),
    )
    if started is None:
        report.pop("started_at")
    else:
        report["started_at"] = started.isoformat() if isinstance(started, datetime) else started
    return report


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr("shadowscan.comparison._utcnow", lambda: NOW)


def _write(path: Path, report: dict[str, Any]) -> Path:
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _diff(tmp_path: Path, baseline: dict[str, Any], current: dict[str, Any], *extra: str):
    before = _write(tmp_path / "baseline.json", baseline)
    after = _write(tmp_path / "current.json", current)
    return CliRunner().invoke(main, ["diff", str(before), str(after), *extra])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------------- pinning
def test_matching_pin_compares_and_reports_the_digest(tmp_path):
    before = _write(tmp_path / "baseline.json", _report(_finding("gone")))
    after = _write(tmp_path / "current.json", _report())
    digest = _sha256(before)
    result = CliRunner().invoke(
        main, ["diff", str(before), str(after), "--json", "--baseline-sha256", digest]
    )
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["baseline"] == {"sha256": digest, "pinned": True, "age_days": 0}
    assert len(document["resolved"]) == 1


def test_unpinned_comparison_still_reports_the_digest(tmp_path):
    result = _diff(tmp_path, _report(), _report(), "--json")
    assert result.exit_code == 0, result.output
    baseline = json.loads(result.output)["baseline"]
    assert baseline == {"sha256": _sha256(tmp_path / "baseline.json"), "pinned": False, "age_days": 0}


def test_uppercase_pin_is_accepted(tmp_path):
    before = _write(tmp_path / "baseline.json", _report())
    after = _write(tmp_path / "current.json", _report())
    result = CliRunner().invoke(
        main, ["diff", str(before), str(after), "--baseline-sha256", _sha256(before).upper()]
    )
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("edit", ["whitespace", "reindented", "other"])
def test_mismatched_pin_refuses_before_any_output(tmp_path, edit):
    reviewed = _report(_finding("reviewed-secret-agent"))
    before = _write(tmp_path / "baseline.json", reviewed)
    digest = _sha256(before)
    if edit == "whitespace":
        before.write_text(before.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    elif edit == "reindented":
        # The same JSON document in other bytes is not the reviewed file.
        before.write_text(json.dumps(reviewed, indent=1), encoding="utf-8")
    else:
        _write(before, _report(_finding("unreviewed-agent")))
    after = _write(tmp_path / "current.json", _report())
    for extra in ([], ["--json"]):
        result = CliRunner().invoke(
            main, ["diff", str(before), str(after), "--baseline-sha256", digest, *extra]
        )
        assert result.exit_code == 1, result.output
        assert "baseline digest does not match --baseline-sha256" in result.output
        assert "agent" not in result.output.replace("baseline digest", "")
        assert "{" not in result.output


def test_pin_is_checked_before_the_baseline_is_parsed(tmp_path):
    before = tmp_path / "baseline.json"
    before.write_text('{"findings": [', encoding="utf-8")
    after = _write(tmp_path / "current.json", _report())
    result = CliRunner().invoke(main, ["diff", str(before), str(after), "--baseline-sha256", "0" * 64])
    assert result.exit_code == 1
    assert "baseline digest does not match" in result.output


@pytest.mark.parametrize("value", ["0" * 63, "0" * 65, "g" * 64, " " + "0" * 63, "", "sha256:" + "0" * 57])
def test_malformed_pin_is_a_usage_error(tmp_path, value):
    result = _diff(tmp_path, _report(), _report(), "--baseline-sha256", value)
    assert result.exit_code == 1, result.output
    assert "64 hexadecimal characters" in " ".join(result.output.split())


def test_digest_covers_the_raw_bytes_including_a_byte_order_mark(tmp_path):
    before = tmp_path / "baseline.json"
    before.write_bytes(b"\xef\xbb\xbf" + json.dumps(_report()).encode())
    report, digest = load_report_with_digest(before)
    assert digest == hashlib.sha256(before.read_bytes()).hexdigest()
    assert report["findings"] == []
    assert read_policy_bytes(before).startswith(b"\xef\xbb\xbf")


def test_load_report_with_digest_raises_on_mismatch(tmp_path):
    before = _write(tmp_path / "baseline.json", _report())
    with pytest.raises(ReportDigestMismatch):
        load_report_with_digest(before, expected_sha256="0" * 64)
    assert load_report_with_digest(before, expected_sha256=_sha256(before))[1] == _sha256(before)
    assert load_report(before)["findings"] == []


@pytest.mark.parametrize(
    ("content", "message"),
    [("[]", "JSON object"), ("[" * 100_000 + "]" * 100_000, "nesting limit")],
)
def test_a_pinned_baseline_must_still_be_a_valid_report(tmp_path, content, message):
    # Matching the pin proves the file is the reviewed one, not that it is a report.
    before = tmp_path / "baseline.json"
    before.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_report_with_digest(before, expected_sha256=_sha256(before))
    after = _write(tmp_path / "current.json", _report())
    result = CliRunner().invoke(main, ["diff", str(before), str(after), "--baseline-sha256", _sha256(before)])
    assert result.exit_code == 1 and "invalid comparison input" in result.output


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
@pytest.mark.parametrize("pinned", [False, True])
def test_symlinked_baseline_is_still_refused(tmp_path, pinned):
    target = _write(tmp_path / "real.json", _report())
    link = tmp_path / "baseline.json"
    link.symlink_to(target)
    after = _write(tmp_path / "current.json", _report())
    extra = ["--baseline-sha256", _sha256(target)] if pinned else []
    result = CliRunner().invoke(main, ["diff", str(link), str(after), *extra])
    assert result.exit_code == 1, result.output
    assert "invalid comparison input" in result.output


# -------------------------------------------------------------------- expiry
@pytest.mark.parametrize(
    ("age", "expected"), [(timedelta(days=34, hours=23), 0), (timedelta(days=35, seconds=1), 3)]
)
def test_baseline_expires_after_the_configured_age(tmp_path, age, expected):
    baseline = _report(_finding("gone"), started=NOW - age)
    result = _diff(tmp_path, baseline, _report(), "--max-baseline-age-days", "35", "--json")
    assert result.exit_code == expected, result.output
    document = json.loads(result.output)
    if expected:
        assert EXPIRED in document["reasons"]
        assert document["resolved"] == [] and len(document["unknown"]) == 1
        assert document["adverse"]["coverage"] is True
    else:
        assert len(document["resolved"]) == 1 and document["unknown"] == []
    assert document["baseline"]["age_days"] == age.days


def test_expired_baseline_text_output_names_the_reason(tmp_path):
    baseline = _report(_finding("gone"), started=NOW - timedelta(days=60))
    result = _diff(tmp_path, baseline, _report(), "--max-baseline-age-days", "35")
    assert result.exit_code == 3, result.output
    assert f"Comparison incomplete: {EXPIRED}" in result.output
    assert "0 resolved" in result.output and "1 unknown" in result.output


def test_age_is_not_enforced_without_the_option(tmp_path):
    baseline = _report(_finding("gone"), started=NOW - timedelta(days=400))
    result = _diff(tmp_path, baseline, _report(), "--json")
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert len(document["resolved"]) == 1 and document["baseline"]["age_days"] == 400


MISSING = "baseline start time is missing or invalid"


@pytest.mark.parametrize(
    ("started", "reason"),
    [
        (None, MISSING),
        ("last tuesday", MISSING),
        ("2026-10-01T00:00:00", MISSING),  # no timezone
        (12345, MISSING),
        ((NOW + timedelta(days=2)).isoformat(), "baseline start time is in the future"),
    ],
)
def test_undatable_baseline_makes_the_comparison_incomplete(tmp_path, started, reason):
    baseline = _report(_finding("gone"))
    baseline["started_at"] = started
    result = _diff(tmp_path, baseline, _report(started=NOW), "--max-baseline-age-days", "35", "--json")
    assert result.exit_code == 3, result.output
    document = json.loads(result.output)
    assert any(item.startswith(reason) for item in document["reasons"]), document["reasons"]
    assert document["resolved"] == [] and len(document["unknown"]) == 1


def test_small_clock_skew_is_not_a_future_baseline(tmp_path):
    baseline = _report(started=NOW + timedelta(minutes=2))
    result = _diff(
        tmp_path, baseline, _report(started=NOW + timedelta(minutes=3)), "--max-baseline-age-days", "1"
    )
    assert result.exit_code == 0, result.output


def test_baseline_newer_than_the_current_report_is_incomplete(tmp_path):
    baseline = _report(_finding("gone"), started=NOW - timedelta(days=1))
    current = _report(started=NOW - timedelta(days=2))
    result = _diff(tmp_path, baseline, current, "--max-baseline-age-days", "35", "--json")
    assert result.exit_code == 3, result.output
    assert "baseline started after the current scan" in json.loads(result.output)["reasons"]


def test_current_report_without_a_start_time_is_incomplete(tmp_path):
    result = _diff(tmp_path, _report(), _report(started=None), "--max-baseline-age-days", "35", "--json")
    assert result.exit_code == 3, result.output
    assert any(reason.startswith("current start time") for reason in json.loads(result.output)["reasons"])


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "soon", "36501", "1000000000"])
def test_invalid_age_limit_is_a_usage_error(tmp_path, value):
    result = _diff(tmp_path, _report(), _report(), "--max-baseline-age-days", value)
    assert result.exit_code == 1, result.output
    # A usage error, never an unhandled exception such as an overflowing timedelta.
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output


def test_largest_age_limit_is_accepted(tmp_path):
    result = _diff(tmp_path, _report(), _report(), "--max-baseline-age-days", str(MAX_BASELINE_AGE_DAYS))
    assert result.exit_code == 0, result.output


def test_expiry_combines_with_a_pin_and_the_drift_gate(tmp_path):
    before = _write(tmp_path / "baseline.json", _report(started=NOW - timedelta(days=90)))
    after = _write(tmp_path / "current.json", _report(_finding("new")))
    args = [
        "diff",
        str(before),
        str(after),
        "--baseline-sha256",
        _sha256(before),
        "--max-baseline-age-days",
        "35",
    ]
    result = CliRunner().invoke(main, [*args, "--fail-on-drift", "inventory"])
    # Expiry is a coverage reason, so the new finding cannot downgrade exit 3 to 2.
    assert result.exit_code == 3, result.output


# ------------------------------------------------------------------- library
def test_lifecycle_reasons_use_the_injected_clock():
    baseline, current = _report(started=NOW - timedelta(days=10)), _report(started=NOW)
    assert baseline_lifecycle_reasons(baseline, current, max_age_days=10, now=NOW) == []
    later = NOW + timedelta(days=1)
    assert baseline_lifecycle_reasons(baseline, current, max_age_days=10, now=later) == [EXPIRED]
    assert baseline_lifecycle_reasons(baseline, current, max_age_days=None, now=later) == []
    assert baseline_age_days(baseline, now=later) == 11
    assert baseline_age_days(_report(started=None), now=later) is None


@pytest.mark.parametrize("value", [0, -3, True, 1.5, MAX_BASELINE_AGE_DAYS + 1, 10**9])
def test_lifecycle_rejects_invalid_age_limits(value):
    with pytest.raises(ValueError, match="positive number of days"):
        baseline_lifecycle_reasons(_report(), _report(), max_age_days=value, now=NOW)


def test_compare_reports_takes_the_age_limit_and_clock():
    baseline = _report(_finding("gone"), started=NOW - timedelta(days=40))
    comparison = compare_reports(baseline, _report(), max_baseline_age_days=35, now=NOW)
    assert not comparison["comparable"] and EXPIRED in comparison["reasons"]
    assert comparison["baseline"] == {"age_days": 40}
    snapshot = copy.deepcopy(baseline)
    assert compare_reports(baseline, _report(), now=NOW)["comparable"]
    assert baseline == snapshot


def test_zulu_suffix_and_timezone_offsets_are_honoured():
    zulu = (NOW - timedelta(days=35, hours=1)).isoformat().replace("+00:00", "Z")
    pacific = (NOW - timedelta(days=34)).astimezone(timezone(timedelta(hours=-7))).isoformat()
    assert baseline_lifecycle_reasons(_report(started=zulu), _report(), max_age_days=35, now=NOW) == [EXPIRED]
    assert baseline_lifecycle_reasons(_report(started=pacific), _report(), max_age_days=35, now=NOW) == []


# --------------------------------------------------------------------- fleet
def _source(name: str, started: datetime) -> tuple[str, dict[str, Any]]:
    finding = _finding(f"{name}/agent")
    finding["risk"] = {"level": "low", "score": 15, "factors": []}
    return name, _report(finding, started=started)


def test_fleet_baseline_age_is_the_age_of_its_oldest_source(tmp_path):
    fleet = merge_reports(
        [_source("host-a.json", NOW - timedelta(days=40)), _source("host-b.json", NOW - timedelta(days=1))]
    ).to_dict()
    assert fleet["started_at"] == (NOW - timedelta(days=40)).isoformat()
    current = merge_reports(
        [_source("host-a.json", NOW - timedelta(hours=1)), _source("host-b.json", NOW - timedelta(hours=1))]
    ).to_dict()
    result = _diff(tmp_path, fleet, current, "--max-baseline-age-days", "35", "--json")
    assert result.exit_code == 3, result.output
    document = json.loads(result.output)
    assert EXPIRED in document["reasons"] and document["baseline"]["age_days"] == 40
    fresh = _diff(tmp_path, fleet, current, "--max-baseline-age-days", "45")
    assert fresh.exit_code == 0, fresh.output


def test_fleet_with_an_undated_source_is_undated(tmp_path):
    """Dating an undated fleet by its merge time would let an old baseline pass any age limit."""
    old = _source("host-a.json", NOW - timedelta(days=400))
    undated = _source("host-b.json", NOW - timedelta(days=1))
    undated[1].pop("started_at")
    fleet = merge_reports([old, undated]).to_dict()
    assert fleet["started_at"] is None and fleet["summary"]["complete"] is True
    assert baseline_age_days(fleet, now=NOW) is None
    current = merge_reports([_source("host-a.json", NOW), _source("host-b.json", NOW)]).to_dict()
    result = _diff(tmp_path, fleet, current, "--max-baseline-age-days", "35", "--json")
    assert result.exit_code == 3, result.output
    assert any(reason.startswith(MISSING) for reason in json.loads(result.output)["reasons"])
    # Without an age limit the undated fleet still compares as before.
    unlimited = _diff(tmp_path, fleet, current)
    assert unlimited.exit_code == 0, unlimited.output


@pytest.mark.parametrize("started", ["last tuesday", "2026-10-01T00:00:00", 12345])
def test_fleet_with_an_unparseable_source_start_is_undated(started):
    source = _source("host-b.json", NOW)
    source[1]["started_at"] = started
    fleet = merge_reports([_source("host-a.json", NOW - timedelta(days=2)), source]).to_dict()
    assert fleet["started_at"] is None


def test_fleet_start_is_the_earliest_instant_across_timezone_offsets():
    tokyo = datetime(2026, 10, 1, 10, 0, tzinfo=timezone(timedelta(hours=9)))  # 01:00Z
    london = datetime(2026, 10, 1, 5, 0, tzinfo=UTC)
    fleet = merge_reports([_source("host-a.json", london), _source("host-b.json", tokyo)]).to_dict()
    # The earliest instant, not the lexically smallest string; its offset is kept.
    assert fleet["started_at"] == tokyo.isoformat()
    assert baseline_age_days(fleet, now=NOW) == (NOW - tokyo).days


def test_fleet_of_fleets_stays_undated():
    undated = _source("host-b.json", NOW)
    undated[1].pop("started_at")
    inner = merge_reports([_source("host-a.json", NOW), undated]).to_dict()
    outer = merge_reports([("fleet-1.json", inner), _source("host-c.json", NOW)]).to_dict()
    assert outer["started_at"] is None
