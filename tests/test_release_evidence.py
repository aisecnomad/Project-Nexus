"""Release acceptance gates and integrity evidence must fail closed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools.release.evidence import verify_ci_run, write_manifest

SHA = "a" * 40
REPOSITORY = "aisecnomad/Project-Nexus"


def _run() -> dict[str, Any]:
    return {
        "id": 123,
        "head_sha": SHA,
        "head_branch": "main",
        "path": ".github/workflows/ci.yml@main",
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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 124), ("head_sha", "b" * 40), ("head_branch", "feature"),
        ("path", ".github/workflows/spoof-ci.yml@main"),
        ("path", ".github/workflows/ci.yml"),
        ("path", ".github/workflows/ci.yml@feature"), ("event", "pull_request"),
        ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "skipped"),
        ("repository", {"full_name": "someone/fork"}),
        ("head_repository", {"full_name": "someone/fork"}), ("head_repository", None),
    ],
)
def test_ci_gate_rejects_wrong_or_incomplete_run(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="CI gate failed"):
        _verify(_run() | {field: value})


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


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    (tmp_path / "shadowscan-0.1.1-py3-none-any.whl").write_bytes(b"wheel bytes")
    (tmp_path / "requirements.lock").write_text("click==8.1\n", encoding="utf-8")
    (tmp_path / "requirements-build.lock").write_text("setuptools==84.0.0\n", encoding="utf-8")
    (tmp_path / "requirements-ci-constraints.txt").write_text("pip-audit==2.10.1\n", encoding="utf-8")
    (tmp_path / "ci-verification.json").write_text(json.dumps(_verify(_run())), encoding="utf-8")
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


@pytest.mark.parametrize("case", ["missing-sbom", "missing-build-lock", "empty-sbom", "no-wheel",
                                 "two-wheels", "symlink", "bad-name"])
def test_release_evidence_refuses_incomplete_or_unsafe_bundle(candidate: Path, case: str) -> None:
    if case == "missing-sbom":
        (candidate / "runtime-sbom.cdx.json").unlink()
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
    assert workflow["permissions"] == {}
    build = workflow["jobs"]["build"]
    attest = workflow["jobs"]["attest"]
    assert build["if"] == "github.ref == 'refs/heads/main'"
    assert all(value == "read" for value in build["permissions"].values())
    assert attest["needs"] == "build"
    assert attest["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}
    assert not any("checkout" in step.get("uses", "") for step in attest["steps"])
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert len(step["uses"].split("@")[-1]) == 40
