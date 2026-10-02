"""The repository secret gate must fail without disclosing matched credentials."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "check_secrets.py"
SECRET = "ghp_" + "A" * 36


def _run(cwd: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=cwd,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    "secret",
    [
        "sk-" + "A" * 24,
        "sk-proj-" + "A" * 40,
        "sk-svcacct-" + "A" * 40,
        "sk-admin-" + "A" * 40,
        "sk-ant-api03-" + "A" * 24,
        "sk-ant-admin01-" + "A" * 24,
        "AKIA" + "A" * 16,
        SECRET,
        "glpat-" + "A" * 24,
        "xoxb-123456789012-" + "A" * 24,
    ],
)
def test_matches_report_locations_without_credential_fragments(tmp_path: Path, secret: str) -> None:
    source = tmp_path / "app.py"
    source.write_text(f"# Settings\nTOKEN = {secret!r}\n", encoding="utf-8")
    result = _run(tmp_path, str(source))
    assert result.returncode == 1
    assert ":2: possible hardcoded secret [REDACTED]" in result.stdout
    assert secret not in result.stdout + result.stderr
    assert secret[:12] not in result.stdout + result.stderr


def test_filenames_cannot_inject_log_lines_or_disclose_credentials(tmp_path: Path) -> None:
    source = tmp_path / f"bad\n::error::{SECRET}.py"
    source.write_text(f"TOKEN = {SECRET!r}\n", encoding="utf-8")
    result = _run(tmp_path, str(source))
    assert result.returncode == 1
    assert len(result.stdout.splitlines()) == 1
    assert "\\n::error::[REDACTED].py" in result.stdout
    assert SECRET not in result.stdout + result.stderr


def test_multiple_matches_preserve_same_line_and_later_line_locations(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        f"TOKENS = [{SECRET!r}, {SECRET!r}]\n# A comment\n\nTOKEN = {SECRET!r}\n\nTOKEN = {SECRET!r}\n",
        encoding="utf-8",
    )
    result = _run(tmp_path, str(source))
    assert result.returncode == 1
    diagnostics = result.stdout.splitlines()
    assert [line.rsplit(": possible", 1)[0].rsplit(":", 1)[1] for line in diagnostics] == [
        "1",
        "1",
        "4",
        "6",
    ]
    assert SECRET not in result.stdout + result.stderr


def test_argument_errors_escape_controls_and_mask_credentials(tmp_path: Path) -> None:
    result = _run(tmp_path, f"--bad\n::error::{SECRET}")
    assert result.returncode == 2
    assert SECRET not in result.stdout + result.stderr
    assert "\\n::error::[REDACTED]" in result.stderr
    assert not any(line.startswith("::error::") for line in result.stderr.splitlines())


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "fifo"])
def test_unreadable_and_nonregular_inputs_fail_closed(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "app.py"
    if kind == "directory":
        source.mkdir()
    elif kind == "symlink":
        outside = tmp_path / "outside"
        outside.write_text("# Innocuous target\n", encoding="utf-8")
        source.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(source)
    result = _run(tmp_path, str(source))
    assert result.returncode == 1
    assert "cannot read a regular source file" in result.stderr


def test_missing_input_and_git_enumeration_failures_never_pass(tmp_path: Path) -> None:
    assert _run(tmp_path).returncode == 2
    result = _run(tmp_path, "--tracked", env={"PATH": ""})
    assert result.returncode == 2
    assert result.stderr == "cannot enumerate tracked source files\n"


def test_non_utf8_source_still_checks_ascii_credentials(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_bytes(b"# encoding: latin-1\n# \xff\nTOKEN = '" + SECRET.encode() + b"'\n")
    result = _run(tmp_path, str(source))
    assert result.returncode == 1
    assert ":3: possible hardcoded secret [REDACTED]" in result.stdout


def test_tracked_mode_keeps_synthetic_exemptions_and_handles_unusual_names(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)
    for name in ("app.py", "tests/fixture.py", "shadowscan/signatures/data/provider.yaml", "untracked.py"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Clean\n" if name == "app.py" else f"TOKEN = {SECRET!r}\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py", "tests", "shadowscan"], cwd=tmp_path, check=True, timeout=10)
    assert _run(tmp_path, "--tracked").returncode == 0

    source = tmp_path / "workflow with\nnewline.yml"
    source.write_text(f"token: {SECRET}\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", source.name], cwd=tmp_path, check=True, timeout=10)
    result = _run(tmp_path, "--tracked")
    assert result.returncode == 1
    assert "workflow with\\nnewline.yml" in result.stdout
    assert len(result.stdout.splitlines()) == 1
    assert SECRET not in result.stdout + result.stderr

    source.unlink()
    result = _run(tmp_path, "--tracked")
    assert result.returncode == 1
    assert "cannot read a regular source file" in result.stderr
