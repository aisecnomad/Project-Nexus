from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.models import Finding, Kind, ScanResult, Surface
from shadowscan.reporters.html import render_html
from shadowscan.utils.output import write_private_text


def test_sensitive_report_replaces_permissive_file_with_private_mode(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("old")
    path.chmod(0o644)
    old_umask = os.umask(0o022)
    try:
        write_private_text(path, "new")
    finally:
        os.umask(old_umask)
    assert path.read_text() == "new"
    assert path.stat().st_mode & 0o777 == 0o600


def test_sensitive_report_refuses_symlink_without_touching_target(tmp_path):
    original = tmp_path / "original"
    original.write_text("retain")
    link = tmp_path / "report"
    link.symlink_to(original)
    with pytest.raises(ValueError, match="symlink"):
        write_private_text(link, "replacement")
    assert original.read_text() == "retain"


def test_output_failure_preserves_previous_report(tmp_path, monkeypatch):
    target = tmp_path / "report"
    target.write_text("previous")

    def failed_replace(*args):
        raise OSError("synthetic failure")

    monkeypatch.setattr("shadowscan.utils.output.os.replace", failed_replace)
    with pytest.raises(OSError):
        write_private_text(target, "replacement")
    assert target.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [target]


def test_html_escapes_external_finding_identifier():
    finding = Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                      title="Agent", resource="repo", resource_type="repository", id="<b>external-id</b>")
    html = render_html(ScanResult(findings=[finding]))
    assert "<b>external-id</b>" not in html
    assert "&lt;b&gt;external-id&lt;/b&gt;" in html


def test_listing_plugins_does_not_import_plugin_code(monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.entry_points", lambda **kwargs: [
        SimpleNamespace(name="custom.unloaded", value="must_never_import:Connector"),
    ])
    result = CliRunner().invoke(main, ["connectors", "--json"])
    assert result.exit_code == 0, result.output
    entry = next(row for row in json.loads(result.output) if row["name"] == "custom.unloaded")
    assert entry["enabled"] is False
    assert "error" not in entry


def test_cli_security_options_and_private_report(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\n")
    output = tmp_path / "scan.json"
    result = CliRunner().invoke(main, [
        "code", str(repo), "--deny-private-origin", "--deny-signature-override",
        "--format", "json", "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(output.read_text())["summary"]["complete"] is True


@pytest.mark.parametrize("option,value", [("--expected-issuer", "https://issuer.example"), ("--jwt-algorithm", "RS256")])
def test_cli_verification_policy_requires_jwks(option, value):
    result = CliRunner().invoke(main, ["jwt", "synthetic", option, value])
    assert result.exit_code == 2
    assert "require --jwks-url" in result.output


def test_inventory_stubs_do_not_change_shared_directory_permissions(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": []}))
    output = tmp_path / "shared"
    output.mkdir()
    output.chmod(0o755)
    result = CliRunner().invoke(main, ["inventory", "stubs", str(report), "--out", str(output)])
    assert result.exit_code == 1 and "0700" in result.output
    assert output.stat().st_mode & 0o777 == 0o755
    assert not list(output.iterdir())


def test_inventory_stubs_reject_symlinked_parent_directories(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": []}))
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    result = CliRunner().invoke(main, ["inventory", "stubs", str(report), "--out", str(link / "stubs")])
    assert result.exit_code == 1 and "symlinks" in result.output
    assert not (outside / "stubs").exists()
