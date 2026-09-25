"""Deprecated timeout spellings preserve finite completion deadlines."""

from __future__ import annotations

from dataclasses import asdict, replace

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ScanConfig


@pytest.mark.parametrize("value,expected", [(2.5, 2.5), (600, 600.0), (None, 120.0)])
def test_legacy_yaml_timeout_maps_to_canonical_value(tmp_path, value, expected):
    path = tmp_path / "scan.yaml"
    serialized = "null" if value is None else str(value)
    path.write_text(f"options:\n  connector_timeout: {serialized}\n")
    config = ScanConfig.from_yaml(path)
    assert config.connector_timeout_seconds == expected
    assert "connector_timeout" not in asdict(config)


@pytest.mark.parametrize("legacy,canonical", [(2, 3), (2, 2), (None, 120), (None, None)])
def test_both_yaml_timeout_keys_are_rejected(legacy, canonical):
    with pytest.raises(ConfigValidationError, match="not both"):
        ScanConfig.from_dict({"options": {"connector_timeout": legacy, "connector_timeout_seconds": canonical}})


@pytest.mark.parametrize("value", [0, -1, True, False, float("nan"), float("inf"), "infinity", "opaque-secret-value"])
def test_legacy_timeout_alias_cannot_disable_completion_deadlines(value):
    with pytest.raises(ConfigValidationError) as failure:
        ScanConfig.from_dict({"options": {"connector_timeout": value}})
    assert "opaque-secret-value" not in str(failure.value)


def test_canonical_null_remains_invalid():
    with pytest.raises(ConfigValidationError):
        ScanConfig.from_dict({"options": {"connector_timeout_seconds": None}})


@pytest.mark.parametrize("value,expected", [(2.5, 2.5), (None, 120.0)])
def test_legacy_constructor_alias_is_applied_only_once(value, expected):
    config = ScanConfig(connector_timeout=value)
    assert config.connector_timeout_seconds == expected
    config.connector_timeout_seconds = 15
    config.validate_security_options()
    assert config.connector_timeout_seconds == 15
    assert replace(config, connector_timeout_seconds=30).connector_timeout_seconds == 30
    assert "connector_timeout" not in asdict(config)


def test_constructor_conflicting_timeout_values_are_rejected():
    with pytest.raises(ConfigValidationError, match="not both"):
        ScanConfig(connector_timeout=5, connector_timeout_seconds=10)


@pytest.mark.parametrize("flag", ["--connector-timeout", "--connector-timeout-seconds"])
def test_cli_alias_sets_canonical_setting(monkeypatch, flag):
    received = []
    monkeypatch.setattr("shadowscan.cli._run_and_emit", lambda config, *args, **kwargs: received.append(config))
    result = CliRunner().invoke(main, ["run", "gateway.logs", flag, "2.5"])
    assert result.exit_code == 0, result.output
    assert received[0].connector_timeout_seconds == 2.5


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_cli_alias_rejects_disabled_or_nonfinite_deadlines(value):
    result = CliRunner().invoke(main, ["run", "gateway.logs", "--connector-timeout", value])
    assert result.exit_code == 2
    assert "positive finite" in result.output


@pytest.mark.parametrize("flag", ["--connector-timeout", "--connector-timeout-seconds"])
@pytest.mark.parametrize("yaml_value", ["600", "null"])
def test_cli_override_wins_over_legacy_yaml_after_revalidation(monkeypatch, tmp_path, flag, yaml_value):
    received = []

    def capture(config, *args, **kwargs):
        config.validate_security_options()
        received.append(config)

    monkeypatch.setattr("shadowscan.cli._run_and_emit", capture)
    path = tmp_path / "scan.yaml"
    path.write_text(f"options:\n  connector_timeout: {yaml_value}\nconnectors: [gateway.logs]\n")
    result = CliRunner().invoke(main, ["scan", "--config", str(path), flag, "3.5"])
    assert result.exit_code == 0, result.output
    assert received[0].connector_timeout_seconds == 3.5
