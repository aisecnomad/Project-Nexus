from __future__ import annotations

import ast
import inspect
import logging
import math
import textwrap

import pytest

import shadowscan.config as config_module
from shadowscan.config import (
    SHARED_CONNECTOR_KEYS,
    ConfigValidationError,
    MinConfidenceError,
    ScanConfig,
    accepted_connector_keys,
)
from shadowscan.connectors import builtin_connector_names, get_connector_class
from shadowscan.connectors.base import BaseConnector
from shadowscan.errors import SetupError


@pytest.mark.parametrize("value", [1.01, -0.01, math.nan, math.inf, -math.inf, True, None, "invalid"])
def test_min_confidence_rejects_values_outside_finite_unit_interval(value):
    with pytest.raises(ValueError, match="min_confidence"):
        ScanConfig.from_dict({"options": {"min_confidence": value}})


@pytest.mark.parametrize("value", [0, 1, 0.25, "0.75"])
def test_min_confidence_accepts_finite_unit_interval_values(value):
    cfg = ScanConfig.from_dict({"options": {"min_confidence": value}})
    assert cfg.min_confidence == float(value)


def test_min_confidence_error_is_a_typed_printable_setup_error():
    with pytest.raises(MinConfidenceError) as failure:
        ScanConfig.from_dict({"options": {"min_confidence": "private-value-do-not-echo"}})
    assert isinstance(failure.value, ConfigValidationError)
    assert isinstance(failure.value, SetupError)
    assert "private-value-do-not-echo" not in str(failure.value)
    assert failure.value.__cause__ is None


# ---------------------------------------------------------- connector keys
@pytest.mark.parametrize("entry", [
    {"name": "identity.okta", "fetch_tokenz": True},
    {"name": "identity.okta", "config": {"fetch_tokenz": True}},
])
def test_unknown_connector_key_names_connector_key_and_closest_option(entry):
    expected = r"connector 'identity\.okta' does not accept 'fetch_tokenz' \(did you mean 'fetch_tokens'\?\)"
    with pytest.raises(ConfigValidationError, match=expected):
        ScanConfig.from_dict({"connectors": [entry]})


def test_unknown_connector_key_never_echoes_its_value():
    with pytest.raises(ConfigValidationError, match="does not accept 'unexpected'") as failure:
        ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "unexpected": "private-value-do-not-echo"}]})
    assert "private-value-do-not-echo" not in str(failure.value)


def test_non_identifier_connector_key_is_described_not_echoed():
    with pytest.raises(ConfigValidationError, match="does not accept an unsupported key") as failure:
        ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "sk-live private key": True}]})
    assert "sk-live" not in str(failure.value)


@pytest.mark.parametrize("name", ["identity.okta", "custom.plugin"])
def test_reserved_underscore_keys_are_rejected_for_every_connector(name):
    with pytest.raises(ConfigValidationError, match="underscore") as failure:
        ScanConfig.from_dict({"connectors": [{"name": name, "_dump_path": "/private/anywhere"}]})
    assert "/private/anywhere" not in str(failure.value)


def test_shared_limits_labels_and_read_aliases_are_accepted():
    cfg = ScanConfig.from_dict({"connectors": [
        {"name": "identity.okta", "bearer": "token-value", "max_input_files": 5, "input": "export.json"},
        {"name": "code.github", "repos": ["acme/app"], "github_token": "token-value"},
        {"name": "gateway.logs", "input": "log.jsonl", "gateway_name": "edge", "label": "edge-1"},
        {"name": "code.filesystem", "paths": ["."], "owner": "platform-team"},
    ]})
    assert cfg.connectors[0].config["bearer"] == "token-value"
    assert cfg.connectors[1].config["repos"] == ["acme/app"]
    assert cfg.connectors[2].label == "edge-1"
    assert cfg.connectors[3].config["owner"] == "platform-team"


def test_plugin_connector_keys_are_not_checked_at_parse_time():
    assert accepted_connector_keys("custom.plugin") is None
    cfg = ScanConfig.from_dict({"connectors": [{"name": "custom.plugin", "anything": 1}]})
    assert cfg.connectors[0].config == {"anything": 1}


def _keys_read_by(cls: type[BaseConnector]) -> set[str]:
    """Keys the connector class and its shadowscan bases read through ctx.get / ctx.require."""
    keys: set[str] = set()
    for klass in cls.__mro__:
        if klass is BaseConnector or not klass.__module__.startswith("shadowscan.connectors"):
            continue
        tree = ast.parse(textwrap.dedent(inspect.getsource(klass)))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "require"}):
                continue
            receiver = node.func.value
            reads_ctx = (isinstance(receiver, ast.Name) and receiver.id == "ctx") or (
                isinstance(receiver, ast.Attribute) and receiver.attr == "ctx"
            )
            if reads_ctx and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                keys.add(node.args[0].value)
    return keys


@pytest.mark.parametrize("name", sorted(builtin_connector_names()))
def test_every_key_a_built_in_connector_reads_is_accepted(name):
    """Guard against drift: a key a connector reads must not be rejected by the parser."""
    accepted = accepted_connector_keys(name)
    assert accepted is not None
    assert accepted >= SHARED_CONNECTOR_KEYS
    read = {key for key in _keys_read_by(get_connector_class(name)) if not key.startswith("_")}
    assert accepted >= read, f"{name} reads keys the configuration would reject: {sorted(read - accepted)}"


# ------------------------------------------------------------ YAML positions
def test_yaml_syntax_error_reports_position_only(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text("options:\n  parallel: 2\n  fail_on: [private-value-do-not-echo\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError) as failure:
        ScanConfig.from_yaml(path)
    message = str(failure.value)
    assert message.startswith("invalid YAML syntax or structural limits exceeded (line ")
    assert "context started at line 3, column 12" in message
    assert "private-value-do-not-echo" not in message


def test_duplicate_key_error_reports_position(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text("options:\n  parallel: 1\n  parallel: 2\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError, match=r"duplicate configuration mapping key \(line 3, column 3\)"):
        ScanConfig.from_yaml(path)


# --------------------------------------------------------- deprecation alias
def test_deprecated_timeout_alias_warns_once_per_process(caplog, monkeypatch):
    monkeypatch.setattr(config_module, "_deprecations_warned", set())
    with caplog.at_level(logging.WARNING, logger="shadowscan.config"):
        assert ScanConfig.from_dict({"options": {"connector_timeout": 5}}).connector_timeout_seconds == 5
        ScanConfig.from_dict({"options": {"connector_timeout": 7}})
        ScanConfig(connector_timeout=3)
    messages = [record.getMessage() for record in caplog.records if "connector_timeout" in record.getMessage()]
    assert messages == ["options.connector_timeout is deprecated; use options.connector_timeout_seconds"]


def test_canonical_timeout_key_does_not_warn(caplog, monkeypatch):
    monkeypatch.setattr(config_module, "_deprecations_warned", set())
    with caplog.at_level(logging.WARNING, logger="shadowscan.config"):
        ScanConfig.from_dict({"options": {"connector_timeout_seconds": 5}})
    assert not [record for record in caplog.records if "deprecated" in record.getMessage()]
