"""Regression checks for CLI security gate inputs and diagnostic output."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from shadowscan.cli import main


@pytest.mark.parametrize("value", ["-0.01", "1.01", "nan", "inf", "-inf"])
def test_min_confidence_cli_rejects_invalid_threshold_before_scan(tmp_path, value):
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--min-confidence", value, "--fail-on", "high"])
    assert result.exit_code == 2, result.output
    assert "min_confidence must be a finite number between 0 and 1" in result.output


@pytest.mark.parametrize("value", ["-0.01", "1.01", ".nan", ".inf", "unparseable"])
def test_min_confidence_yaml_rejects_invalid_threshold_before_scan(tmp_path, value):
    config = tmp_path / "scan.yaml"
    config.write_text(f"options:\n  min_confidence: {value}\nconnectors: []\n")
    result = CliRunner().invoke(main, ["scan", "-c", str(config), "--fail-on", "high"])
    assert result.exit_code == 2, result.output
    assert "min_confidence must be a finite number between 0 and 1" in result.output


@pytest.mark.parametrize("kind", ["secret", "auto"])
def test_signature_test_never_prints_matched_credential(kind):
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
    result = CliRunner().invoke(main, ["signatures", "test", key, "--kind", kind])
    assert result.exit_code == 0, result.output
    assert "provider.openai" in result.output
    assert key not in result.output
    assert "[REDACTED]" in result.output
