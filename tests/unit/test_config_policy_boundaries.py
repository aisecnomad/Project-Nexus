"""Configuration mistakes must not silently disable a requested security policy."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ScanConfig, expand_env


@pytest.mark.parametrize("value", [None, ""])
@pytest.mark.parametrize("field", ["expected_issuer", "input", "tenant_id"])
def test_required_environment_binding_cannot_disappear(monkeypatch, value, field):
    if value is None:
        monkeypatch.delenv("NEXUS_REQUIRED_POLICY", raising=False)
    else:
        monkeypatch.setenv("NEXUS_REQUIRED_POLICY", value)
    with pytest.raises(ConfigValidationError, match="NEXUS_REQUIRED_POLICY is missing or empty"):
        ScanConfig.from_dict({"connectors": [{"name": "identity.jwt", field: "${NEXUS_REQUIRED_POLICY}"}]})


@pytest.mark.parametrize("value", [None, ""])
def test_explicit_environment_defaults_work_for_unset_and_empty(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("NEXUS_OPTIONAL_POLICY", raising=False)
    else:
        monkeypatch.setenv("NEXUS_OPTIONAL_POLICY", value)
    assert expand_env("${NEXUS_OPTIONAL_POLICY:-https://identity.example/}") == "https://identity.example/"
    assert expand_env("${NEXUS_OPTIONAL_POLICY:-}") == ""


def test_environment_values_are_not_reexpanded(monkeypatch):
    monkeypatch.setenv("NEXUS_TOKEN", "opaque-${LITERAL}-value")
    assert expand_env({"token": ["${NEXUS_TOKEN}"]}) == {"token": ["opaque-${LITERAL}-value"]}


def test_config_missing_environment_fails_before_collection_and_preserves_secrets(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_REQUIRED_ISSUER", raising=False)
    path = tmp_path / "scan.yaml"
    path.write_text("connectors:\n  - name: identity.jwt\n    token: arbitrary-private-value\n"
                    "    expected_issuer: ${NEXUS_REQUIRED_ISSUER}\n")
    collected = []
    monkeypatch.setattr("shadowscan.cli.Engine", lambda *args, **kwargs: collected.append(True))
    result = CliRunner().invoke(main, ["scan", "-c", str(path)])
    assert result.exit_code == 1
    assert "NEXUS_REQUIRED_ISSUER is missing or empty" in result.output
    assert "arbitrary-private-value" not in result.output
    assert not collected


@pytest.mark.parametrize("content", [
    "options:\n  fail_on: high\n  fail_on: null\n",
    "connectors: []\nconnectors: [cloud.aws]\n",
    "connectors:\n  - name: cloud.aws\n    config:\n      account: one\n      account: two\n",
])
def test_duplicate_yaml_cannot_replace_security_configuration(tmp_path, content):
    path = tmp_path / "scan.yaml"
    path.write_text(content)
    with pytest.raises(ConfigValidationError, match="duplicate configuration mapping key"):
        ScanConfig.from_yaml(path)


def test_ordinary_yaml_merge_override_remains_supported(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text("connectors:\n  - name: cloud.aws\n    config: &defaults\n      regions: [us-east-1]\n"
                    "  - name: cloud.aws\n    config:\n      <<: *defaults\n      regions: [eu-west-1]\n")
    config = ScanConfig.from_yaml(path)
    assert config.connectors[0].config["regions"] == ["us-east-1"]
    assert config.connectors[1].config["regions"] == ["eu-west-1"]


def test_nested_reused_yaml_merge_overrides_remain_supported(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text("connectors:\n  - name: cloud.aws\n    config:\n      <<: &defaults\n"
                    "        <<: {regions: [us-east-1]}\n        regions: [eu-west-1]\n"
                    "  - name: cloud.aws\n    config: *defaults\n")
    assert all(spec.config["regions"] == ["eu-west-1"] for spec in ScanConfig.from_yaml(path).connectors)


@pytest.mark.parametrize("payload,field", [
    ({"option": {"fail_on": "high"}}, "scan configuration"),
    ({"options": {"fail_onn": "high"}}, "options"),
    ({"options": []}, "options"),
    ({"connectors": "cloud.aws"}, "connectors"),
    ({"connectors": {"cloud.aws": {}}}, "connectors"),
    ({"connectors": [{"name": "cloud.aws", "config": "expected_issuer=required"}]}, "connector config"),
    ({"connectors": [{"name": 42}]}, "connector name"),
    ({"connectors": [""]}, "connector name"),
    ({"connectors": [{"name": "cloud.aws", "label": []}]}, "connector label"),
    ({"inventory": "inventory/"}, "inventory"),
    ({"inventory": [""]}, "inventory"),
    ({"signatures": "signatures/"}, "signatures"),
    ({"options": {"dump_records": 123}}, "options.dump_records"),
    ({"options": {"state_dir": True}}, "options.state_dir"),
])
def test_config_schema_rejects_ignored_or_misinterpreted_fields(payload, field):
    with pytest.raises(ConfigValidationError, match=field):
        ScanConfig.from_dict(payload)


@pytest.mark.parametrize("value", ["HIGH", "", "urgent", True, [], 5])
def test_risk_gate_is_validated_before_scan(value):
    with pytest.raises(ConfigValidationError, match="options.fail_on"):
        ScanConfig.from_dict({"options": {"fail_on": value}})


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "2.0", None])
def test_parallel_requires_positive_integer(value):
    with pytest.raises(ConfigValidationError, match="options.parallel"):
        ScanConfig.from_dict({"options": {"parallel": value}})


@pytest.mark.parametrize("content", [
    "options:\n  secret-as-key: arbitrary-private-value\n",
    "connectors:\n  - name: cloud.aws\n    123: arbitrary-private-value\n",
    "connectors: [arbitrary-private-value\n",
])
def test_schema_diagnostics_never_echo_unknown_keys_or_values(tmp_path, content):
    path = tmp_path / "scan.yaml"
    path.write_text(content)
    result = CliRunner().invoke(main, ["scan", "-c", str(path)])
    assert result.exit_code == 1 and "invalid scan configuration" in result.output
    assert "arbitrary-private-value" not in result.output and "secret-as-key" not in result.output
    assert "Traceback" not in result.output


def test_connector_specific_fields_and_nested_overrides_remain_supported(monkeypatch):
    monkeypatch.setenv("NEXUS_PARALLEL", "2")
    config = ScanConfig.from_dict({
        "options": {"parallel": "${NEXUS_PARALLEL}"},
        "connectors": [{"name": "cloud.aws", "regions": ["us-east-1"],
                        "config": {"regions": ["eu-west-1"], "custom_plugin_setting": True}}],
    })
    assert config.parallel == 2
    assert config.connectors[0].config == {"regions": ["eu-west-1"], "custom_plugin_setting": True}
