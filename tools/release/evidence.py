"""Bind release candidates to successful CI and retain verifiable file hashes.

GitHub's API response must be fetched by the workflow with its scoped token.
This module is offline: it never requests credentials, calls an API, or publishes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from importlib.metadata import version
from pathlib import Path
from typing import Any

_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def verify_ci_run(
    run: Any, *, repository: str, expected_sha: str, current_sha: str, run_id: str
) -> dict[str, Any]:
    """Require successful push CI for the exact dispatched main commit.

    A successful PR run, another workflow, a fork, and a different commit do not
    establish the acceptance gate, even when they share a display name.
    """
    if not _REPOSITORY.fullmatch(repository):
        raise ValueError("invalid repository")
    if not _SHA.fullmatch(expected_sha) or expected_sha != current_sha:
        raise ValueError("expected commit must be the full lowercase SHA of this workflow run")
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("CI run ID must be a positive integer")
    if not isinstance(run, dict):
        raise ValueError("CI run response must be an object")
    expected = {
        "id": int(run_id),
        "head_sha": expected_sha,
        "head_branch": "main",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }
    for key, value in expected.items():
        if run.get(key) != value:
            raise ValueError(f"CI gate failed: {key} does not match")
    for key in ("repository", "head_repository"):
        candidate = run.get(key)
        if not isinstance(candidate, dict) or candidate.get("full_name") != repository:
            raise ValueError(f"CI gate failed: {key} does not match")
    return {
        **expected,
        "repository": repository,
        "url": f"https://github.com/{repository}/actions/runs/{run_id}",
    }


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_manifest(directory: Path, *, repository: str, commit: str, workflow_run: str) -> None:
    """Hash the review bundle with stable ordering; no reproducible-build claim."""
    if not _REPOSITORY.fullmatch(repository) or not _SHA.fullmatch(commit):
        raise ValueError("invalid source identity")
    if not re.fullmatch(r"[1-9][0-9]*", workflow_run):
        raise ValueError("workflow run ID must be a positive integer")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("release directory must be a real directory")
    files = sorted(directory.iterdir())
    required = {"ci-verification.json", "runtime-sbom.cdx.json", "requirements.lock", "requirements-ci-constraints.txt"}
    if not required.issubset({path.name for path in files}):
        raise ValueError("release evidence is missing required files")
    if len([path for path in files if path.suffix == ".whl"]) != 1:
        raise ValueError("release evidence requires exactly one wheel")
    for path in files:
        if path.is_symlink() or not path.is_file() or not _FILENAME.fullmatch(path.name):
            raise ValueError("release files must be regular files with portable names")
    if {"build-evidence.json", "SHA256SUMS"}.intersection(path.name for path in files):
        raise ValueError("refusing to overwrite existing release evidence")
    ci = json.loads((directory / "ci-verification.json").read_text(encoding="utf-8"))
    # Recheck the saved CI identity rather than just copying an arbitrary JSON file.
    if not isinstance(ci, dict) or ci.get("repository") != repository or ci.get("head_sha") != commit:
        raise ValueError("saved CI evidence does not match the release source")
    verified = verify_ci_run(
        {**ci, "repository": {"full_name": repository}, "head_repository": {"full_name": repository}},
        repository=repository, expected_sha=commit, current_sha=commit, run_id=str(ci.get("id", "")),
    )
    sbom = json.loads((directory / "runtime-sbom.cdx.json").read_text(encoding="utf-8"))
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
        raise ValueError("runtime SBOM must contain CycloneDX components")
    manifest = {
        "schema_version": 1,
        "source": {"repository": repository, "commit": commit},
        "workflow_run": f"https://github.com/{repository}/actions/runs/{workflow_run}",
        "ci": verified,
        "build_environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "tools": {name: version(name) for name in ("pip", "setuptools", "wheel", "pip-audit")},
        },
        "scope": {
            "sbom": "dependencies in requirements.lock (core and cloud extras); not a container/OS SBOM",
            "artifact": "wheel candidate; publication requires a separate maintainer action",
            "assurance": "CI and artifact identity only; not a claim of live tenant validation or reproducible builds",
        },
        "files": [{"name": path.name, "sha256": _digest(path), "bytes": path.stat().st_size} for path in files],
    }
    manifest_path = directory / "build-evidence.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(manifest_path)
    (directory / "SHA256SUMS").write_text(
        "".join(f"{_digest(path)}  {path.name}\n" for path in sorted(files)), encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gate = commands.add_parser("verify-ci")
    gate.add_argument("--input", type=Path, required=True)
    gate.add_argument("--output", type=Path, required=True)
    gate.add_argument("--repository", required=True)
    gate.add_argument("--expected-sha", required=True)
    gate.add_argument("--current-sha", required=True)
    gate.add_argument("--run-id", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--directory", type=Path, required=True)
    manifest.add_argument("--repository", required=True)
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--workflow-run", required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify-ci":
            result = verify_ci_run(
                json.loads(args.input.read_text(encoding="utf-8")), repository=args.repository,
                expected_sha=args.expected_sha, current_sha=args.current_sha, run_id=args.run_id,
            )
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            write_manifest(
                args.directory, repository=args.repository, commit=args.commit, workflow_run=args.workflow_run
            )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
