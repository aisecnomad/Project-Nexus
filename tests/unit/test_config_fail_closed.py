"""Configuration must reject ambiguous or unsafe input before a scan starts."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ScanConfig


@pytest.mark.parametrize("present_value", [None, ""])
@pytest.mark.parametrize("template", ["${SHADOWSCAN_REQUIRED_TEST}", "prefix-${SHADOWSCAN_REQUIRED_TEST}-suffix"])
def test_missing_or_empty_required_environment_reference_fails_closed(monkeypatch, present_value, template):
    if present_value is None:
        monkeypatch.delenv("SHADOWSCAN_REQUIRED_TEST", raising=False)
    else:
        monkeypatch.setenv("SHADOWSCAN_REQUIRED_TEST", present_value)

    with pytest.raises(ValueError):
        ScanConfig.from_dict({"connectors": [{"name": "code.github", "token": template}]})


@pytest.mark.parametrize("present_value", [None, ""])
def test_explicit_environment_default_is_used_for_missing_or_empty_variable(monkeypatch, present_value):
    if present_value is None:
        monkeypatch.delenv("SHADOWSCAN_OPTIONAL_TEST", raising=False)
    else:
        monkeypatch.setenv("SHADOWSCAN_OPTIONAL_TEST", present_value)

    cfg = ScanConfig.from_dict({
        "connectors": [{
            "name": "code.github",
            "token": "${SHADOWSCAN_OPTIONAL_TEST:-fallback}",
            "api_url": "${SHADOWSCAN_OPTIONAL_TEST:-}",
        }],
    })
    assert cfg.connectors[0].config["token"] == "fallback"
    assert cfg.connectors[0].config["api_url"] == ""


def test_present_environment_reference_expands_without_coercing_connector_secret(monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_REQUIRED_TEST", "opaque value")
    cfg = ScanConfig.from_dict({"connectors": [{"name": "code.github", "token": "${SHADOWSCAN_REQUIRED_TEST}"}]})
    assert cfg.connectors[0].config["token"] == "opaque value"


@pytest.mark.parametrize("document", [
    "options:\n  parallel: 1\n  parallel: 2\n",
    "options:\n  fail_on: high\n  fail_on: critical\n",
    "connectors:\n  - name: code.github\n    name: code.filesystem\n",
    "connectors:\n  - name: code.github\n    config:\n      token: first\n      token: second\n",
    "inventory: []\ninventory: []\n",
])
def test_duplicate_authored_yaml_keys_are_rejected(tmp_path, document):
    path = tmp_path / "scan.yaml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        ScanConfig.from_yaml(path)


def test_explicit_yaml_merge_overrides_remain_valid(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text(
        "options:\n"
        "  <<: &defaults {fail_on: high, parallel: 1}\n"
        "  fail_on: critical\n"
        "  parallel: 3\n"
        "connectors:\n"
        "  - name: code.github\n"
        "    config:\n"
        "      <<: &connector_defaults {org: acme, token: default}\n"
        "      token: overridden\n",
        encoding="utf-8",
    )

    cfg = ScanConfig.from_yaml(path)
    assert cfg.fail_on == "critical"
    assert cfg.parallel == 3
    assert cfg.connectors[0].config == {"org": "acme", "token": "overridden"}


@pytest.mark.parametrize("value", ["", "HIGH", "warning", 0, False, [], {}])
def test_invalid_fail_on_is_rejected_in_file_and_direct_configuration(value):
    with pytest.raises(ValueError, match="fail_on"):
        ScanConfig.from_dict({"options": {"fail_on": value}})
    with pytest.raises(ValueError, match="fail_on"):
        ScanConfig(fail_on=value)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "not-a-number", None, [], {}])
def test_invalid_parallel_is_rejected_in_file_and_direct_configuration(value):
    with pytest.raises(ValueError, match="parallel"):
        ScanConfig.from_dict({"options": {"parallel": value}})
    with pytest.raises(ValueError, match="parallel"):
        ScanConfig(parallel=value)


@pytest.mark.parametrize("value", [None, "critical", "high", "medium", "low", "info"])
def test_supported_fail_on_levels_are_accepted(value):
    assert ScanConfig.from_dict({"options": {"fail_on": value}}).fail_on == value


@pytest.mark.parametrize("data", [
    {"option": {"parallel": 1}},
    {"options": {"paralell": 1}},
    {"options": []},
    {"options": "parallel: 1"},
    {"inventory": "./inventory"},
    {"inventory": ["./inventory", 2]},
    {"signatures": "./signatures"},
    {"signatures": [None]},
    {"connectors": "code.github"},
    {"connectors": {"name": "code.github"}},
    {"connectors": [{"name": "code.github", "config": []}]},
    {"connectors": [{"name": "code.github", "config": "token=value"}]},
    {"connectors": [{"name": 42}]},
    {"connectors": [{"name": "code.github", "label": False}]},
    {"options": {"workdir": []}},
])
def test_unknown_fields_and_invalid_container_types_are_rejected(data):
    with pytest.raises(ValueError):
        ScanConfig.from_dict(data)


def test_connector_options_stay_open_for_external_plugins():
    cfg = ScanConfig.from_dict({"connectors": [{"name": "custom.example", "new_plugin_parameter": "value"}]})
    assert cfg.connectors[0].config["new_plugin_parameter"] == "value"


@pytest.mark.parametrize("data", [
    {"options": {"parallel": "private-value-do-not-echo"}},
    {"options": {"incremental": "private-value-do-not-echo"}},
    {"options": {"fail_on": "private-value-do-not-echo"}},
    {"options": {"unexpected": "private-value-do-not-echo"}},
])
def test_config_validation_errors_never_echo_values(data):
    with pytest.raises(ValueError) as error:
        ScanConfig.from_dict(data)
    assert "private-value-do-not-echo" not in str(error.value)


def test_yaml_parse_error_and_cli_diagnostic_do_not_echo_config_values(tmp_path):
    secret = "private-value-do-not-echo"
    path = tmp_path / "scan.yaml"
    path.write_text(f"options:\n  parallel: 2\n  fail_on: [{secret}\n", encoding="utf-8")

    with pytest.raises(ValueError) as error:
        ScanConfig.from_yaml(path)
    assert secret not in str(error.value)

    result = CliRunner().invoke(main, ["scan", "--config", str(path)])
    assert result.exit_code != 0
    assert secret not in result.output


def test_cli_diagnostic_does_not_echo_expanded_environment_value(tmp_path, monkeypatch):
    secret = "private-value-do-not-echo"
    monkeypatch.setenv("SHADOWSCAN_SECRET_TEST", secret)
    path = tmp_path / "scan.yaml"
    path.write_text("options:\n  fail_on: ${SHADOWSCAN_SECRET_TEST}\n", encoding="utf-8")

    with pytest.raises(ValueError) as error:
        ScanConfig.from_yaml(path)
    assert secret not in str(error.value)

    result = CliRunner().invoke(main, ["scan", "--config", str(path)])
    assert result.exit_code != 0
    assert secret not in result.output
