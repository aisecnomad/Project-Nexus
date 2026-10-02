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
    ConnectorSpec,
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
@pytest.mark.parametrize(
    "entry",
    [
        {"name": "identity.okta", "fetch_tokenz": True},
        {"name": "identity.okta", "config": {"fetch_tokenz": True}},
    ],
)
def test_unknown_connector_key_names_connector_key_and_closest_option(entry):
    expected = r"connector 'identity\.okta' does not accept 'fetch_tokenz' \(did you mean 'fetch_tokens'\?\)"
    with pytest.raises(ConfigValidationError, match=expected):
        ScanConfig.from_dict({"connectors": [entry]})


def test_unknown_connector_key_never_echoes_its_value():
    with pytest.raises(ConfigValidationError, match="does not accept 'unexpected'") as failure:
        ScanConfig.from_dict(
            {"connectors": [{"name": "cloud.aws", "unexpected": "private-value-do-not-echo"}]}
        )
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
    cfg = ScanConfig.from_dict(
        {
            "connectors": [
                {
                    "name": "identity.okta",
                    "bearer": "token-value",
                    "max_input_files": 5,
                    "input": "export.json",
                },
                {"name": "code.github", "repos": ["acme/app"], "github_token": "token-value"},
                {"name": "gateway.logs", "input": "log.jsonl", "gateway_name": "edge", "label": "edge-1"},
                {"name": "code.filesystem", "paths": ["."], "owner": "platform-team"},
            ]
        }
    )
    assert cfg.connectors[0].config["bearer"] == "token-value"
    assert cfg.connectors[1].config["repos"] == ["acme/app"]
    assert cfg.connectors[2].label == "edge-1"
    assert cfg.connectors[3].config["owner"] == "platform-team"


def test_plugin_connector_keys_are_not_checked_at_parse_time():
    assert accepted_connector_keys("custom.plugin") is None
    cfg = ScanConfig.from_dict({"connectors": [{"name": "custom.plugin", "anything": 1}]})
    assert cfg.connectors[0].config == {"anything": 1}


@pytest.mark.parametrize("name", ["code.filesystem", "custom.plugin"])
def test_inline_and_nested_connector_options_cannot_overlap(name):
    with pytest.raises(
        ConfigValidationError, match="inline options and nested config both define 'path'"
    ) as failure:
        ScanConfig.from_dict(
            {
                "connectors": [
                    {
                        "name": name,
                        "path": "inline-private-path",
                        "config": {"path": "nested-private-path"},
                    }
                ]
            }
        )
    assert "inline-private-path" not in str(failure.value)
    assert "nested-private-path" not in str(failure.value)


def test_nonoverlapping_inline_and_nested_connector_options_are_merged():
    cfg = ScanConfig.from_dict(
        {
            "connectors": [
                {
                    "name": "code.filesystem",
                    "path": ".",
                    "config": {"scan_secrets": False},
                }
            ]
        }
    )
    assert cfg.connectors[0].config["path"].endswith(".")
    assert cfg.connectors[0].config["scan_secrets"] is False


def test_yaml_filesystem_path_and_paths_are_mutually_exclusive(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text(
        "connectors:\n  - name: code.filesystem\n    path: one\n    paths: [two]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="specify path or paths, not both"):
        ScanConfig.from_yaml(path)


def test_programmatic_filesystem_path_and_paths_are_mutually_exclusive():
    with pytest.raises(ConfigValidationError, match="specify path or paths, not both"):
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": "one", "paths": ["two"]})])


def test_reused_engine_rejects_path_alias_added_after_a_run(tmp_path, index):
    from shadowscan.engine import Engine

    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path)})])
    engine = Engine(cfg, index)
    engine.run()

    cfg.connectors[0].config["paths"] = [str(tmp_path)]
    with pytest.raises(ConfigValidationError, match="specify path or paths, not both"):
        engine.run()


@pytest.mark.parametrize(
    "name,key",
    [
        ("cloud.aws", "allow_instance_credentials"),
        ("cloud.azure", "include_app_settings"),
        ("cloud.gcp", "allow_instance_credentials"),
        ("cloud.oci", "allow_instance_credentials"),
        ("code.filesystem", "scan_secrets"),
        ("code.github", "include_archived"),
        ("code.gitlab", "include_archived"),
        ("gateway.logs", "llm_hosts_only"),
        ("identity.entra", "include_first_party"),
        ("identity.okta", "fetch_tokens"),
        ("lowcode.power-platform", "include_bots"),
        ("saas.generic", "keep_all"),
        ("saas.github-apps", "include_unrecognized_apps"),
        ("saas.microsoft-teams", "include_store"),
    ],
)
def test_environment_expanded_false_never_inverts_connector_booleans(monkeypatch, name, key):
    monkeypatch.setenv("NEXUS_CONNECTOR_BOOLEAN", "false")
    cfg = ScanConfig.from_dict({"connectors": [{"name": name, key: "${NEXUS_CONNECTOR_BOOLEAN}"}]})
    assert cfg.connectors[0].config[key] is False


def test_environment_expanded_true_is_a_native_connector_boolean(monkeypatch):
    monkeypatch.setenv("NEXUS_CONNECTOR_BOOLEAN", "TrUe")
    cfg = ScanConfig.from_dict(
        {"connectors": [{"name": "code.github", "include_archived": "${NEXUS_CONNECTOR_BOOLEAN}"}]}
    )
    assert cfg.connectors[0].config["include_archived"] is True


@pytest.mark.parametrize("value", ["yes", "0", "perhaps", 0, 1, None, [], {}])
def test_invalid_connector_boolean_fails_closed_without_echoing_value(value):
    with pytest.raises(ConfigValidationError, match="connector option llm_hosts_only") as failure:
        ScanConfig.from_dict({"connectors": [{"name": "gateway.logs", "llm_hosts_only": value}]})
    assert repr(value) not in str(failure.value)


def test_programmatic_scan_config_rejects_misspelled_built_in_option():
    with pytest.raises(
        ConfigValidationError,
        match=r"connector 'identity\.okta' does not accept 'fetch_tokenz'",
    ):
        ScanConfig(connectors=[ConnectorSpec("identity.okta", {"fetch_tokenz": True})])


def test_engine_boundary_rejects_a_built_in_option_added_after_construction(index):
    from shadowscan.engine import Engine

    cfg = ScanConfig(connectors=[ConnectorSpec("identity.okta")])
    cfg.connectors[0].config["fetch_tokenz"] = True
    with pytest.raises(ConfigValidationError, match="fetch_tokenz"):
        Engine(cfg, index)


def test_valid_programmatic_scan_config_normalises_connector_booleans():
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec(
                "code.github",
                {"include_archived": "false", "include_forks": "true", "max_repos": 25},
                enabled="false",  # type: ignore[arg-type] - embedding input is runtime-validated
            )
        ]
    )
    assert cfg.connectors[0].config == {
        "include_archived": False,
        "include_forks": True,
        "max_repos": 25,
    }
    assert cfg.connectors[0].enabled is False


@pytest.mark.parametrize(
    "value,expected",
    [("yes", True), ("on", True), ("1", True), ("no", False), ("off", False), ("0", False)],
)
def test_programmatic_connector_enabled_preserves_compatibility_aliases(value, expected):
    spec = ConnectorSpec("custom.plugin", enabled=value)  # type: ignore[arg-type]
    assert spec.enabled is expected


def test_programmatic_plugin_config_values_remain_opaque():
    cfg = ScanConfig(
        connectors=[ConnectorSpec("custom.plugin", {"plugin_switch": "false"})],
        plugins=["custom.plugin"],
    )
    assert cfg.connectors[0].config == {"plugin_switch": "false"}


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_nonfinite_numbers_are_rejected_inside_opaque_plugin_config(value):
    with pytest.raises(ConfigValidationError, match="numbers must be finite") as failure:
        ScanConfig.from_dict(
            {"connectors": [{"name": "custom.plugin", "config": {"opaque": [{"number": value}]}}]}
        )
    assert str(value) not in str(failure.value)


def test_nonfinite_yaml_is_rejected_inside_opaque_plugin_config(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text(
        "connectors:\n  - name: custom.plugin\n    config:\n      opaque: [.nan, .inf]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="numbers must be finite"):
        ScanConfig.from_yaml(path)


def test_programmatic_plugin_config_rejects_nonfinite_numbers():
    with pytest.raises(ConfigValidationError, match="numbers must be finite"):
        ScanConfig(connectors=[ConnectorSpec("custom.plugin", {"opaque": {"number": math.nan}})])


def test_recursive_config_validation_is_depth_bounded_without_interpreting_plugin_keys():
    opaque: object = "leaf"
    for _ in range(70):
        opaque = {"plugin-owned-key": opaque}
    with pytest.raises(ConfigValidationError, match="validation limit exceeded"):
        ScanConfig.from_dict({"connectors": [{"name": "custom.plugin", "config": {"opaque": opaque}}]})


def _is_ctx(node: ast.expr) -> bool:
    return (isinstance(node, ast.Name) and node.id == "ctx") or (
        isinstance(node, ast.Attribute) and node.attr == "ctx"
    )


def _string_constants(node: ast.expr) -> set[str]:
    if not isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        return set()
    return {
        item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def _keys_read_by(cls: type[BaseConnector]) -> set[str]:
    """Keys the connector class and its shadowscan bases read or forward from their configuration.

    Keys are read through ctx.get / ctx.require, or forwarded by a comprehension
    over ctx.config.items() that keeps listed names (code.github and code.gitlab
    pass scanner options to their nested filesystem scans).
    """
    keys: set[str] = set()
    for klass in cls.__mro__:
        if klass is BaseConnector or not klass.__module__.startswith("shadowscan.connectors"):
            continue
        tree = ast.parse(textwrap.dedent(inspect.getsource(klass)))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"get", "require"}
                and _is_ctx(node.func.value)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.add(node.args[0].value)
            elif (
                isinstance(node, ast.comprehension)
                and isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Attribute)
                and node.iter.func.attr == "items"
                and isinstance(node.iter.func.value, ast.Attribute)
                and node.iter.func.value.attr == "config"
                and _is_ctx(node.iter.func.value.value)
            ):
                for condition in node.ifs:
                    if isinstance(condition, ast.Compare) and isinstance(condition.ops[0], ast.In):
                        keys.update(*(_string_constants(container) for container in condition.comparators))
    return keys


@pytest.mark.parametrize("name", sorted(builtin_connector_names()))
def test_every_key_a_built_in_connector_reads_is_accepted(name):
    """Guard against drift: a key a connector reads must not be rejected by the parser."""
    accepted = accepted_connector_keys(name)
    assert accepted is not None
    assert accepted >= SHARED_CONNECTOR_KEYS
    read = {key for key in _keys_read_by(get_connector_class(name)) if not key.startswith("_")}
    assert accepted >= read, f"{name} reads keys the configuration would reject: {sorted(read - accepted)}"


@pytest.mark.parametrize("name", sorted(builtin_connector_names()))
def test_every_key_a_built_in_connector_accepts_is_read(name):
    """The reverse drift guard: an accepted key the connector never reads would be ignored silently."""
    accepted = accepted_connector_keys(name)
    assert accepted is not None
    unread = accepted - SHARED_CONNECTOR_KEYS - _keys_read_by(get_connector_class(name))
    assert not unread, f"{name} accepts keys it never reads: {sorted(unread)}"


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
    with pytest.raises(
        ConfigValidationError, match=r"duplicate configuration mapping key \(line 3, column 3\)"
    ):
        ScanConfig.from_yaml(path)


# --------------------------------------------------------- deprecation alias
def test_deprecated_timeout_alias_warns_once_per_process(caplog, monkeypatch):
    monkeypatch.setattr(config_module, "_deprecations_warned", set())
    with caplog.at_level(logging.WARNING, logger="shadowscan.config"):
        assert ScanConfig.from_dict({"options": {"connector_timeout": 5}}).connector_timeout_seconds == 5
        ScanConfig.from_dict({"options": {"connector_timeout": 7}})
        ScanConfig(connector_timeout=3)
    messages = [
        record.getMessage() for record in caplog.records if "connector_timeout" in record.getMessage()
    ]
    assert messages == ["options.connector_timeout is deprecated; use options.connector_timeout_seconds"]


def test_canonical_timeout_key_does_not_warn(caplog, monkeypatch):
    monkeypatch.setattr(config_module, "_deprecations_warned", set())
    with caplog.at_level(logging.WARNING, logger="shadowscan.config"):
        ScanConfig.from_dict({"options": {"connector_timeout_seconds": 5}})
    assert not [record for record in caplog.records if "deprecated" in record.getMessage()]


def test_config_relative_globs_and_workdir_use_configuration_directory(tmp_path):
    directory = tmp_path / "deployment"
    directory.mkdir()
    config = directory / "scan.yaml"
    config.write_text("inventory: [inventory/*.yaml]\noptions:\n  workdir: working\n")
    loaded = ScanConfig.from_yaml(config)
    assert loaded.inventory == [str(directory / "inventory" / "*.yaml")]
    assert loaded.workdir == str(directory / "working")
