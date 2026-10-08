"""Execute the scoped scheduled audit against complete, partial and failed reads."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULESET_IDS = (23892853, 23913372)


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "disabled",
        "missing_gate",
        "missing_bypass",
        "missing_bypass_and_disabled",
        "missing_rules",
        "wrong_repository",
        "denied",
        "denied_with_valid_stdout",
        "malformed",
    ],
)
def test_scheduled_audit_reports_scoped_assurance_without_admin_writes(tmp_path: Path, change: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/audit.yml").read_text())
    job = workflow["jobs"]["merge-policy"]
    assert workflow["permissions"] == {"contents": "read"}
    assert job["if"] == "github.repository == 'aisecnomad/Project-Nexus' && github.ref == 'refs/heads/main'"
    assert "permissions" not in job
    steps = [step for step in job["steps"] if step.get("env", {}).get("GH_TOKEN")]
    assert len(steps) == 1
    assert steps[0]["env"] == {"GH_TOKEN": "${{ github.token }}"}
    snapshots = {}
    for ruleset_id in RULESET_IDS:
        payload = json.loads((ROOT / ".github/rulesets" / f"{ruleset_id}.update.json").read_text())
        snapshots[str(ruleset_id)] = {
            **payload,
            "id": ruleset_id,
            "source_type": "Repository",
            "source": "aisecnomad/Project-Nexus",
        }
    ruleset = snapshots["23913372"]
    if change in {"disabled", "missing_bypass_and_disabled"}:
        ruleset["enforcement"] = "disabled"
    if change in {"missing_bypass", "missing_bypass_and_disabled"}:
        del ruleset["bypass_actors"]
    elif change == "missing_rules":
        del ruleset["rules"]
    elif change == "wrong_repository":
        ruleset["source"] = "different/repository"
    elif change == "missing_gate":
        checks = next(
            row["parameters"] for row in ruleset["rules"] if row["type"] == "required_status_checks"
        )
        checks["required_status_checks"] = [
            row for row in checks["required_status_checks"] if row["context"] != "CI gate"
        ]
    inputs = tmp_path / "responses.json"
    inputs.write_text(json.dumps(snapshots))
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    cli = fake_bin / "gh"
    cli.write_text(
        "#!/usr/bin/env python\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "allowed = {'repos/aisecnomad/Project-Nexus/rulesets/23892853', "
        "'repos/aisecnomad/Project-Nexus/rulesets/23913372'}\n"
        "if len(args) != 2 or args[0] != 'api' or args[1] not in allowed:\n"
        "    raise SystemExit('Only the two read-only ruleset requests are allowed')\n"
        "with Path(os.environ['AUDIT_REQUEST_LOG']).open('a') as log:\n"
        "    log.write(args[1] + '\\n')\n"
        "if os.environ['AUDIT_CHANGE'] == 'denied':\n"
        "    raise SystemExit(1)\n"
        "if os.environ['AUDIT_CHANGE'] == 'malformed':\n"
        "    print('{invalid-json')\n"
        "else:\n"
        "    data = json.loads(Path(os.environ['AUDIT_RESPONSES']).read_text())\n"
        "    print(json.dumps(data[args[1].rsplit('/', 1)[1]]))\n"
        "if os.environ['AUDIT_CHANGE'] == 'denied_with_valid_stdout':\n"
        "    raise SystemExit(1)\n"
    )
    cli.chmod(0o700)
    requests = tmp_path / "requests.log"
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    env = dict(os.environ)
    env.update(
        PATH=os.pathsep.join((str(fake_bin), str(Path(sys.executable).parent), env.get("PATH", ""))),
        GITHUB_REPOSITORY="aisecnomad/Project-Nexus",
        RUNNER_TEMP=str(runner_temp),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary.md"),
        AUDIT_RESPONSES=str(inputs),
        AUDIT_REQUEST_LOG=str(requests),
        AUDIT_CHANGE=change,
    )
    result = subprocess.run(
        ["bash", "-c", steps[0]["run"]], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30
    )
    assert (result.returncode == 0) is (change in {"none", "missing_bypass"}), result.stdout + result.stderr
    observed = requests.read_text().splitlines()
    assert observed[0].endswith("/23892853")
    assert set(observed).issubset(
        {f"repos/aisecnomad/Project-Nexus/rulesets/{number}" for number in RULESET_IDS}
    )
    assert len(observed) == 2  # One bad ruleset must not hide the other's status.
    reports = {
        number: json.loads(
            (runner_temp / "governance-observations" / f"observation-{number}.json").read_text()
        )
        for number in RULESET_IDS
    }
    report = reports[23913372]
    summary = (tmp_path / "summary.md").read_text()
    if change == "missing_bypass":
        assert report["status"] == "partial"
        assert report["visible_controls_match"] is True
        assert report["complete_readback_verified"] is False
        assert report["administrator_readback_required"] is True
        assert report["unknown_fields"] == ["bypass_actors"]
        assert "Bypass actors are UNKNOWN; administrator readback REQUIRED" in summary
    elif change == "none":
        assert report["status"] == "complete" and report["complete_readback_verified"] is True
        assert report["unknown_fields"] == []
    else:
        assert report["status"] == "failed"
        assert report["complete_readback_verified"] is False and report["verified_fields"] == []
        assert "Verification FAILED" in summary
    retention = [step for step in job["steps"] if step.get("name") == "Retain scoped governance observations"]
    assert len(retention) == 1 and retention[0]["if"] == "always()"
    assert retention[0]["with"]["if-no-files-found"] == "error"
