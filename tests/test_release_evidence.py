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

SHA = "a" * 40
REPOSITORY = "aisecnomad/Project-Nexus"


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


@pytest.mark.parametrize("workflow,verify,run_id", [
    ("ci", _verify, 123), ("codeql", _verify_codeql, 456),
])
@pytest.mark.parametrize("suffix", ["", "@main"])
def test_accepts_exact_successful_push_run_for_main(
    workflow: str, verify: Any, run_id: int, suffix: str,
) -> None:
    verified = verify(_run(workflow) | {"id": run_id, "path": f".github/workflows/{workflow}.yml{suffix}"})
    assert verified["path"] == f".github/workflows/{workflow}.yml{suffix}"
    assert verified["url"] == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 124), ("id", 123.0), ("id", True),
        ("head_sha", "b" * 40), ("head_branch", "feature"),
        ("path", ".github/workflows/spoof-ci.yml@main"),
        ("path", ".github/workflows/ci.yml@feature"), ("event", "pull_request"),
        ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "skipped"),
        ("repository", {"full_name": "someone/fork"}),
        ("head_repository", {"full_name": "someone/fork"}), ("head_repository", None),
    ],
)
def test_ci_gate_rejects_wrong_or_incomplete_run(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="CI gate failed"):
        _verify(_run() | {field: value})


@pytest.mark.parametrize("field,value", [
    ("id", 457), ("head_sha", "b" * 40), ("head_branch", "feature"),
    ("path", ".github/workflows/ci.yml"), ("path", ".github/workflows/codeql.yml@feature"),
    ("event", "pull_request"), ("status", "in_progress"), ("conclusion", "failure"),
    ("repository", {"full_name": "someone/fork"}),
    ("head_repository", {"full_name": "someone/fork"}),
])
def test_codeql_gate_rejects_wrong_or_incomplete_run(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="CodeQL gate failed"):
        _verify_codeql(_run("codeql") | {"id": 456, field: value})


@pytest.mark.parametrize(
    "overrides", [
        {"expected_sha": "a" * 7}, {"expected_sha": "A" * 40}, {"current_sha": "b" * 40},
        {"run_id": "123/../../another"}, {"run_id": "0"}, {"repository": "bad\n/repository"},
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
    tmp_path: Path, workflow: str, run_id: str,
) -> None:
    source = tmp_path / "api-response.json"
    output = tmp_path / "verified.json"
    run = _run(workflow) | {"id": int(run_id)}
    source.write_text(json.dumps(run), encoding="utf-8")
    command = [
        sys.executable, "-m", "tools.release.evidence", f"verify-{workflow}",
        "--input", str(source), "--output", str(output), "--repository", REPOSITORY,
        "--expected-sha", SHA, "--current-sha", SHA, "--run-id", run_id,
    ]
    assert subprocess.run(command, capture_output=True, text=True, check=False).returncode == 0
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["id"] == int(run_id)
    assert "display_title" not in saved
    output.unlink()
    source.write_text(json.dumps(run | {"conclusion": "failure"}), encoding="utf-8")
    assert subprocess.run(command, capture_output=True, text=True, check=False).returncode != 0
    assert not output.exists()


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    (tmp_path / "shadowscan-0.1.1-py3-none-any.whl").write_bytes(b"wheel bytes")
    (tmp_path / "requirements.lock").write_text("click==8.1\n", encoding="utf-8")
    (tmp_path / "requirements-build.lock").write_text("setuptools==84.0.0\n", encoding="utf-8")
    (tmp_path / "requirements-ci-constraints.txt").write_text("pip-audit==2.10.1\n", encoding="utf-8")
    (tmp_path / "ci-verification.json").write_text(json.dumps(_verify(_run())), encoding="utf-8")
    (tmp_path / "codeql-verification.json").write_text(
        json.dumps(_verify_codeql(_run("codeql") | {"id": 456})), encoding="utf-8"
    )
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
    assert manifest["ci"]["id"] == 123
    assert manifest["codeql"]["id"] == 456
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


@pytest.mark.parametrize("field,value,error", [
    ("head_sha", "b" * 40, "release source"),
    ("conclusion", "failure", "CodeQL gate failed"),
    ("path", ".github/workflows/ci.yml", "CodeQL gate failed"),
    ("head_branch", "feature", "CodeQL gate failed"),
])
def test_release_evidence_refuses_mismatched_codeql(
    candidate: Path, field: str, value: Any, error: str,
) -> None:
    saved_path = candidate / "codeql-verification.json"
    saved_path.write_text(json.dumps(json.loads(saved_path.read_text()) | {field: value}), encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        _manifest(candidate)
    assert not (candidate / "SHA256SUMS").exists()


@pytest.mark.parametrize("case", ["missing-sbom", "missing-codeql", "missing-build-lock", "empty-sbom", "no-wheel",
                                 "two-wheels", "symlink", "bad-name"])
def test_release_evidence_refuses_incomplete_or_unsafe_bundle(candidate: Path, case: str) -> None:
    if case == "missing-sbom":
        (candidate / "runtime-sbom.cdx.json").unlink()
    elif case == "missing-codeql":
        (candidate / "codeql-verification.json").unlink()
    elif case == "missing-build-lock":
        (candidate / "requirements-build.lock").unlink()
    elif case == "empty-sbom":
        (candidate / "runtime-sbom.cdx.json").write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
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
    workflow = yaml.safe_load(Path(".github/workflows/release.yml").read_text())
    # PyYAML follows YAML 1.1, where GitHub's YAML 1.2 'on' key parses as True.
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch"}
    assert triggers["workflow_dispatch"]["inputs"]["codeql_run_id"]["required"] is True
    assert workflow["permissions"] == {}
    build = workflow["jobs"]["build"]
    attest = workflow["jobs"]["attest"]
    assert build["if"] == "github.ref == 'refs/heads/main'"
    assert all(value == "read" for value in build["permissions"].values())
    gate = next(step for step in build["steps"] if step.get("name", "").startswith("Verify exact commit"))
    assert "gh api \"repos/$GITHUB_REPOSITORY/actions/runs/$CODEQL_RUN_ID\"" in gate["run"]
    assert "verify-codeql" in gate["run"]
    assert "candidate/codeql-verification.json" in gate["run"]
    assert attest["needs"] == "build"
    assert attest["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}
    assert not any("checkout" in step.get("uses", "") for step in attest["steps"])
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert len(step["uses"].split("@")[-1]) == 40
