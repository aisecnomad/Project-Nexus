"""Release acceptance gates and integrity evidence must fail closed."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools.release.evidence import verify_ci_run, verify_codeql_run, write_manifest
from tools.release.rules import MAIN_RULESET_ID, verify_against_live, verify_ruleset

SHA = "a" * 40
REPOSITORY = "aisecnomad/Project-Nexus"


def _merge_rules() -> dict[str, Any]:
    return verify_ruleset(
        {
            "id": MAIN_RULESET_ID,
            "name": "Require CI and CodeQL",
            "target": "branch",
            "source_type": "Repository",
            "source": REPOSITORY,
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 1,
                        "dismiss_stale_reviews_on_push": True,
                        "require_code_owner_review": False,
                        "require_last_push_approval": True,
                        "required_review_thread_resolution": True,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {"context": "CI gate", "integration_id": 15368},
                            {"context": "analyze", "integration_id": 15368},
                            {"context": "test (3.11)", "integration_id": 15368},
                            {"context": "test (3.12)", "integration_id": 15368},
                        ],
                    },
                },
                {
                    "type": "code_scanning",
                    "parameters": {
                        "code_scanning_tools": [
                            {
                                "tool": "CodeQL",
                                "security_alerts_threshold": "medium_or_higher",
                                "alerts_threshold": "errors",
                            }
                        ]
                    },
                },
                {"type": "non_fast_forward"},
                {"type": "required_signatures"},
                {"type": "deletion"},
            ],
        },
        repository=REPOSITORY,
        default_branch="main",
    )


def _run(workflow: str = "ci") -> dict[str, Any]:
    return {
        "id": 123,
        "head_sha": SHA,
        "head_branch": "main",
        # A real workflow-run REST response uses this bare path; GitHub's
        # published example also shows the @main form.
        "path": f".github/workflows/{workflow}.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "display_title": "An untrusted message need not be retained",
    }


def _verify(run: Any, **overrides: Any) -> dict[str, Any]:
    arguments = {"repository": REPOSITORY, "expected_sha": SHA, "current_sha": SHA, "run_id": "123"}
    return verify_ci_run(run, **(arguments | overrides))


def _verify_codeql(run: Any, **overrides: Any) -> dict[str, Any]:
    arguments = {"repository": REPOSITORY, "expected_sha": SHA, "current_sha": SHA, "run_id": "456"}
    return verify_codeql_run(run, **(arguments | overrides))


@pytest.mark.parametrize(
    "workflow,verify,run_id",
    [
        ("ci", _verify, 123),
        ("codeql", _verify_codeql, 456),
    ],
)
@pytest.mark.parametrize("suffix", ["", "@main"])
def test_accepts_exact_successful_push_run_for_main(
    workflow: str,
    verify: Any,
    run_id: int,
    suffix: str,
) -> None:
    verified = verify(_run(workflow) | {"id": run_id, "path": f".github/workflows/{workflow}.yml{suffix}"})
    assert verified["path"] == f".github/workflows/{workflow}.yml{suffix}"
    assert verified["url"] == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 124),
        ("id", 123.0),
        ("id", True),
        ("head_sha", "b" * 40),
        ("head_branch", "feature"),
        ("path", ".github/workflows/spoof-ci.yml@main"),
        ("path", ".github/workflows/ci.yml@feature"),
        ("event", "pull_request"),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("conclusion", "skipped"),
        ("repository", {"full_name": "someone/fork"}),
        ("head_repository", {"full_name": "someone/fork"}),
        ("head_repository", None),
    ],
)
def test_ci_gate_rejects_wrong_or_incomplete_run(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="CI gate failed"):
        _verify(_run() | {field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 457),
        ("head_sha", "b" * 40),
        ("head_branch", "feature"),
        ("path", ".github/workflows/ci.yml"),
        ("path", ".github/workflows/codeql.yml@feature"),
        ("event", "pull_request"),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("repository", {"full_name": "someone/fork"}),
        ("head_repository", {"full_name": "someone/fork"}),
    ],
)
def test_codeql_gate_rejects_wrong_or_incomplete_run(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="CodeQL gate failed"):
        _verify_codeql(_run("codeql") | {"id": 456, field: value})


@pytest.mark.parametrize(
    "overrides",
    [
        {"expected_sha": "a" * 7},
        {"expected_sha": "A" * 40},
        {"current_sha": "b" * 40},
        {"run_id": "123/../../another"},
        {"run_id": "0"},
        {"repository": "bad\n/repository"},
    ],
)
def test_ci_gate_rejects_invalid_dispatch_identity(overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        _verify(_run(), **overrides)


def test_ci_gate_retains_only_verified_fields() -> None:
    verified = _verify(_run())
    assert verified["url"] == f"https://github.com/{REPOSITORY}/actions/runs/123"
    assert "display_title" not in verified
    with pytest.raises(ValueError, match="object"):
        _verify([])


@pytest.mark.parametrize("workflow,run_id", [("ci", "123"), ("codeql", "456")])
def test_release_cli_writes_only_verified_run_and_refuses_failed_run(
    tmp_path: Path,
    workflow: str,
    run_id: str,
) -> None:
    source = tmp_path / "api-response.json"
    output = tmp_path / "verified.json"
    run = _run(workflow) | {"id": int(run_id)}
    source.write_text(json.dumps(run), encoding="utf-8")
    command = [
        sys.executable,
        "-m",
        "tools.release.evidence",
        f"verify-{workflow}",
        "--input",
        str(source),
        "--output",
        str(output),
        "--repository",
        REPOSITORY,
        "--expected-sha",
        SHA,
        "--current-sha",
        SHA,
        "--run-id",
        run_id,
    ]
    assert subprocess.run(command, capture_output=True, text=True, check=False).returncode == 0
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["id"] == int(run_id)
    assert "display_title" not in saved
    output.unlink()
    source.write_text(json.dumps(run | {"conclusion": "failure"}), encoding="utf-8")
    assert subprocess.run(command, capture_output=True, text=True, check=False).returncode != 0
    assert not output.exists()


@pytest.mark.parametrize(
    "body",
    [
        '{"id":123,"id":124}',
        '{"id":123,"diagnostic":NaN}',
        '{"id":123,"diagnostic":1e999}',
    ],
)
def test_release_cli_rejects_ambiguous_or_nonfinite_api_json(tmp_path: Path, body: str) -> None:
    source = tmp_path / "api-response.json"
    output = tmp_path / "verified.json"
    source.write_text(body, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.release.evidence",
            "verify-ci",
            "--input",
            str(source),
            "--output",
            str(output),
            "--repository",
            REPOSITORY,
            "--expected-sha",
            SHA,
            "--current-sha",
            SHA,
            "--run-id",
            "123",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "bounded, unambiguous JSON with finite numbers" in result.stderr
    assert not output.exists()


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    (tmp_path / "nexusshadowscan-0.1.1-py3-none-any.whl").write_bytes(b"wheel bytes")
    (tmp_path / "requirements.lock").write_text("click==8.1\n", encoding="utf-8")
    (tmp_path / "requirements-build.lock").write_text("setuptools==84.0.0\n", encoding="utf-8")
    (tmp_path / "requirements-ci.lock").write_text(
        "pip-audit==2.10.1 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8"
    )
    (tmp_path / "requirements-ci-constraints.txt").write_text("pip-audit==2.10.1\n", encoding="utf-8")
    (tmp_path / "ci-verification.json").write_text(json.dumps(_verify(_run())), encoding="utf-8")
    (tmp_path / "codeql-verification.json").write_text(
        json.dumps(_verify_codeql(_run("codeql") | {"id": 456})), encoding="utf-8"
    )
    (tmp_path / "merge-rule-verification.json").write_text(json.dumps(_merge_rules()), encoding="utf-8")
    (tmp_path / "runtime-sbom.cdx.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "click", "version": "8.1"}]}),
        encoding="utf-8",
    )
    return tmp_path


def _manifest(candidate: Path) -> None:
    write_manifest(candidate, repository=REPOSITORY, commit=SHA, workflow_run="456")


def test_release_manifest_covers_every_artifact_and_detects_changed_bytes(candidate: Path) -> None:
    _manifest(candidate)
    manifest = json.loads((candidate / "build-evidence.json").read_text())
    assert manifest["source"] == {"repository": REPOSITORY, "commit": SHA}
    assert "requirements-build.lock" in {item["name"] for item in manifest["files"]}
    assert "requirements-ci.lock" in {item["name"] for item in manifest["files"]}
    assert manifest["ci"]["id"] == 123
    assert manifest["codeql"]["id"] == 456
    assert manifest["merge_rules"]["ruleset_id"] == MAIN_RULESET_ID
    assert "merge-rule-verification.json" in {item["name"] for item in manifest["files"]}
    assert "not a claim" in manifest["scope"]["assurance"]
    checksums = (candidate / "SHA256SUMS").read_text().splitlines()
    checksummed = {}
    for line in checksums:
        digest, filename = line.split("  ", 1)
        assert hashlib.sha256((candidate / filename).read_bytes()).hexdigest() == digest
        checksummed[filename] = digest
    assert set(checksummed) == {path.name for path in candidate.iterdir()} - {"SHA256SUMS"}
    wheel = next(candidate.glob("*.whl"))
    wheel.write_bytes(b"tampered")
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() != checksummed[wheel.name]


@pytest.mark.parametrize(
    ("filename", "body", "message"),
    [
        (
            "ci-verification.json",
            '{"repository":"wrong/repo","repository":"aisecnomad/Project-Nexus"}',
            "saved ci evidence",
        ),
        (
            "codeql-verification.json",
            '{"repository":"aisecnomad/Project-Nexus","diagnostic":Infinity}',
            "saved codeql evidence",
        ),
        (
            "runtime-sbom.cdx.json",
            '{"bomFormat":"CycloneDX","components":[],"components":[{}]}',
            "runtime SBOM",
        ),
        (
            "merge-rule-verification.json",
            '{"ruleset_id":23913372,"ruleset_id":23913373}',
            "saved merge-rule evidence",
        ),
    ],
)
def test_release_manifest_rejects_ambiguous_or_nonfinite_json(
    candidate: Path, filename: str, body: str, message: str
) -> None:
    (candidate / filename).write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        _manifest(candidate)


def test_release_evidence_refuses_mismatched_ci(candidate: Path) -> None:
    (candidate / "ci-verification.json").write_text(
        json.dumps(_verify(_run()) | {"head_sha": "b" * 40}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="release source"):
        _manifest(candidate)


def test_release_evidence_refuses_failed_saved_ci(candidate: Path) -> None:
    (candidate / "ci-verification.json").write_text(
        json.dumps(_verify(_run()) | {"conclusion": "failure"}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="CI gate failed"):
        _manifest(candidate)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("head_sha", "b" * 40, "release source"),
        ("conclusion", "failure", "CodeQL gate failed"),
        ("path", ".github/workflows/ci.yml", "CodeQL gate failed"),
        ("head_branch", "feature", "CodeQL gate failed"),
    ],
)
def test_release_evidence_refuses_mismatched_codeql(
    candidate: Path,
    field: str,
    value: Any,
    error: str,
) -> None:
    saved_path = candidate / "codeql-verification.json"
    saved_path.write_text(json.dumps(json.loads(saved_path.read_text()) | {field: value}), encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        _manifest(candidate)
    assert not (candidate / "SHA256SUMS").exists()


@pytest.mark.parametrize(
    "field,value",
    [("repository", "attacker/fork"), ("ruleset_id", MAIN_RULESET_ID + 1), ("default_branch", "other")],
)
def test_release_evidence_refuses_mismatched_merge_rule_receipt(
    candidate: Path, field: str, value: Any
) -> None:
    saved_path = candidate / "merge-rule-verification.json"
    receipt = json.loads(saved_path.read_text())
    saved_path.write_text(json.dumps(receipt | {field: value}), encoding="utf-8")
    with pytest.raises(ValueError, match="release source or ruleset"):
        _manifest(candidate)
    assert not (candidate / "SHA256SUMS").exists()


def test_release_manifest_keeps_merge_rule_provenance(candidate: Path) -> None:
    saved_path = candidate / "merge-rule-verification.json"
    readback = _merge_rules()["ruleset"] | {"updated_at": "2026-10-07T06:09:59.254+01:00"}
    live = {key: value for key, value in readback.items() if key != "bypass_actors"}
    receipt = verify_against_live(readback, live, repository=REPOSITORY, default_branch="main")
    saved_path.write_text(json.dumps(receipt), encoding="utf-8")
    _manifest(candidate)
    merge_rules = json.loads((candidate / "build-evidence.json").read_text())["merge_rules"]
    assert merge_rules["bypass_actors_source"].startswith("an administrator readback supplied at dispatch")
    assert merge_rules["observed_updated_at"] == "2026-10-07T06:09:59.254+01:00"


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("id", MAIN_RULESET_ID + 1, "ID does not match"),
        ("source", "attacker/fork", "source does not match"),
        ("enforcement", "disabled", "active"),
    ],
)
def test_release_evidence_rechecks_saved_merge_rule_snapshot(
    candidate: Path, field: str, value: Any, error: str
) -> None:
    saved_path = candidate / "merge-rule-verification.json"
    receipt = json.loads(saved_path.read_text())
    receipt["ruleset"][field] = value
    saved_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        _manifest(candidate)
    assert not (candidate / "SHA256SUMS").exists()


@pytest.mark.parametrize(
    "case",
    [
        "missing-sbom",
        "missing-codeql",
        "missing-merge-rules",
        "missing-build-lock",
        "missing-ci-lock",
        "empty-sbom",
        "no-wheel",
        "two-wheels",
        "symlink",
        "bad-name",
    ],
)
def test_release_evidence_refuses_incomplete_or_unsafe_bundle(candidate: Path, case: str) -> None:
    if case == "missing-sbom":
        (candidate / "runtime-sbom.cdx.json").unlink()
    elif case == "missing-codeql":
        (candidate / "codeql-verification.json").unlink()
    elif case == "missing-merge-rules":
        (candidate / "merge-rule-verification.json").unlink()
    elif case == "missing-build-lock":
        (candidate / "requirements-build.lock").unlink()
    elif case == "missing-ci-lock":
        (candidate / "requirements-ci.lock").unlink()
    elif case == "empty-sbom":
        (candidate / "runtime-sbom.cdx.json").write_text(
            '{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8"
        )
    elif case == "no-wheel":
        next(candidate.glob("*.whl")).unlink()
    elif case == "two-wheels":
        (candidate / "other.whl").write_bytes(b"other")
    elif case == "symlink":
        (candidate / "linked.txt").symlink_to(candidate / "requirements.lock")
    else:
        (candidate / "multiline\nname.txt").write_text("unsafe checksum name", encoding="utf-8")
    with pytest.raises(ValueError):
        _manifest(candidate)
    assert not (candidate / "SHA256SUMS").exists()


def test_release_evidence_is_not_silently_overwritten(candidate: Path) -> None:
    _manifest(candidate)
    with pytest.raises(ValueError, match="overwrite"):
        _manifest(candidate)


def test_release_workflow_limits_signing_to_artifacts_without_executing_source() -> None:
    workflow = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
    )
    # PyYAML follows YAML 1.1, where GitHub's YAML 1.2 'on' key parses as True.
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch"}
    assert triggers["workflow_dispatch"]["inputs"]["codeql_run_id"]["required"] is True
    assert triggers["workflow_dispatch"]["inputs"]["ruleset_readback"]["required"] is True
    assert workflow["permissions"] == {}
    build = workflow["jobs"]["build"]
    attest = workflow["jobs"]["attest"]
    assert build["if"] == "github.ref == 'refs/heads/main'"
    assert all(value == "read" for value in build["permissions"].values())
    assert build["env"] == {"PYTHONDONTWRITEBYTECODE": "1"}
    initialize = next(step for step in build["steps"] if step.get("name", "").startswith("Initialize"))
    assert 'candidate_dir="${RUNNER_TEMP:?}/release-candidate"' in initialize["run"]
    assert '>> "$GITHUB_ENV"' in initialize["run"]
    gate = next(step for step in build["steps"] if step.get("name", "").startswith("Verify exact commit"))
    assert 'gh api "repos/$GITHUB_REPOSITORY/actions/runs/$CODEQL_RUN_ID"' in gate["run"]
    assert "verify-codeql" in gate["run"]
    assert '"$CANDIDATE_DIR/codeql-verification.json"' in gate["run"]
    rules_gate = next(step for step in build["steps"] if step.get("name", "").startswith("Verify current"))
    assert 'gh api "repos/$GITHUB_REPOSITORY/rulesets/23913372"' in rules_gate["run"]
    assert "gh api \"repos/$GITHUB_REPOSITORY\" --jq '.default_branch'" in rules_gate["run"]
    assert "python -m tools.release.rules verify" in rules_gate["run"]
    assert '"$CANDIDATE_DIR/merge-rule-verification.json"' in rules_gate["run"]
    # The read-only token's own read binds the administrator readback.
    assert '--input "$RUNNER_TEMP/merge-rules-readback.json"' in rules_gate["run"]
    assert '--live "$RUNNER_TEMP/merge-rules.json"' in rules_gate["run"]
    assert rules_gate["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "RULESET_READBACK": "${{ inputs.ruleset_readback }}",
    }
    assert attest["needs"] == "build"
    assert attest["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}
    assert not any("checkout" in step.get("uses", "") for step in attest["steps"])
    publication = workflow["jobs"]["publication-input"]
    assert set(publication["needs"]) == {"build", "attest"}
    assert publication["permissions"] == {}
    assert not any("checkout" in step.get("uses", "") for step in publication["steps"])
    publication_text = yaml.safe_dump(publication)
    assert "nexusshadowscan-*.whl" in publication_text
    assert "sha256sum --check SHA256SUMS" in publication_text
    build_text = "\n".join(step.get("run", "") for step in build["steps"])
    assert "--untracked-files=all --ignored=matching" in build_text
    assert "git archive --format=tar HEAD" in build_text
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert len(step["uses"].split("@")[-1]) == 40
