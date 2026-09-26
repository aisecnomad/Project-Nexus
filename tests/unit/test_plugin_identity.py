"""A plugin reports under the exact entry-point name the operator approved, or not at all."""

from __future__ import annotations

import sys
import types
from importlib.metadata import EntryPoint
from typing import Any

import pytest

import shadowscan.connectors as registry
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import PluginDiagnostic, PluginRegistryError
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface
from shadowscan.utils.redaction import REDACTED

# Never installed anywhere; each test injects it into sys.modules.
MODULE = "acme_shadowscan_plugin"
ENTRY = "saas.acme-hub"
INHERIT = object()  # leave the attribute to BaseConnector's default


def _collect(self: BaseConnector) -> Any:
    yield {"id": "agent-1", "name": "Acme agent"}


def _analyze(self: BaseConnector, records: Any) -> Any:
    for record in records:
        yield Finding(surface=self.surface, connector=self.name, kind=Kind.AGENT, title=f"Hub agent: {record['name']}",
                      resource=f"acme-hub:agent:{record['id']}", resource_type="hub-agent",
                      provider=self.provider, confidence=0.9)


def _connector(**overrides: Any) -> type:
    """Build a plugin class that satisfies every identity rule unless ``overrides`` says otherwise."""
    attributes: dict[str, Any] = {
        "name": ENTRY, "surface": Surface.SAAS, "provider": "acme-hub",
        "description": "Agents registered in Acme's hub.", "config_keys": {"input": "offline export"},
        "collect": _collect, "analyze": _analyze,
    }
    for key, value in overrides.items():
        if value is INHERIT:
            del attributes[key]
        else:
            attributes[key] = value
    return type("AcmeHubConnector", (BaseConnector,), attributes)


def _publish(monkeypatch: pytest.MonkeyPatch, *plugins: tuple[str, object], extra: tuple[EntryPoint, ...] = ()) -> None:
    """Expose ``plugins`` as (entry-point name, target) pairs of a fake installed distribution."""
    module = types.ModuleType(MODULE)
    entries = []
    attributes: dict[int, str] = {}  # one module attribute per distinct target object
    for name, target in plugins:
        attribute = attributes.setdefault(id(target), f"Target{len(attributes)}")
        setattr(module, attribute, target)
        entries.append(EntryPoint(name=name, value=f"{MODULE}:{attribute}", group="shadowscan.connectors"))
    monkeypatch.setitem(sys.modules, MODULE, module)
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [*entries, *extra])


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])


def _refusal(name: str) -> PluginRegistryError:
    with pytest.raises(PluginRegistryError) as info:
        registry.get_connector_class(name, allowed_plugins=[name])
    assert name not in registry._cache
    return info.value


def test_mismatched_name_is_refused_and_reported(monkeypatch):
    _publish(monkeypatch, ("saas.acme-alias", _connector(name="saas.other")))
    error = _refusal("saas.acme-alias")
    assert error.diagnostic == PluginDiagnostic("saas.acme-alias", "identity-mismatch", str(error))
    assert str(error).startswith(f"plugin 'saas.acme-alias' ('{MODULE}:Target0') declares name 'saas.other'")
    assert "equal to its entry-point name" in str(error)
    # Refusal is not cached as success and the diagnostic is not duplicated.
    assert _refusal("saas.acme-alias").diagnostic == error.diagnostic
    assert registry.plugin_registry_errors() == (error.diagnostic,)


def test_builtin_name_cannot_be_claimed_by_a_plugin_class(monkeypatch):
    _publish(monkeypatch, ("saas.acme-alias", _connector(name="saas.slack")))
    error = _refusal("saas.acme-alias")
    assert error.diagnostic.rule == "reserved-name"
    assert "declares name 'saas.slack', which is a built-in connector name" in str(error)
    # The built-in itself is untouched and still resolves to first-party code.
    assert registry.get_connector_class("saas.slack").name == "saas.slack"
    assert registry.get_connector_class("saas.slack").__module__ == "shadowscan.connectors.saas.slack"


@pytest.mark.parametrize("name", ["saas.slack", "SaaS.Slack", "cloud", "Cloud", "code.filesystem"])
def test_builtin_name_or_namespace_entry_point_is_never_listed(monkeypatch, name):
    _publish(monkeypatch, (name, _connector(name=name)))
    listed = registry.available_connectors()
    assert listed.get(name) == registry._BUILTIN.get(name)
    assert all(value.startswith("shadowscan.") for value in listed.values())
    (diagnostic,) = registry.plugin_registry_errors()
    assert diagnostic.rule == "reserved-name" and diagnostic.entry == name
    assert repr(name) in diagnostic.message
    if name in registry._BUILTIN:
        assert registry.get_connector_class(name).__module__.startswith("shadowscan.connectors.")
    else:
        with pytest.raises(KeyError, match="unknown connector"):
            registry.get_connector_class(name, allowed_plugins=[name])


def test_duplicate_entry_points_are_reported_once_and_never_loaded(monkeypatch):
    first, second, twice = _connector(), _connector(), _connector(name="saas.acme-twice")
    _publish(monkeypatch, (ENTRY, first), (ENTRY, second), (ENTRY, first),
             ("saas.acme-twice", twice), ("saas.acme-twice", twice))
    listed = registry.available_connectors()
    assert ENTRY not in listed
    assert listed["saas.acme-twice"] == f"{MODULE}:Target2"  # the same target twice is not ambiguous
    with pytest.raises(KeyError, match="unknown connector"):
        registry.get_connector_class(ENTRY, allowed_plugins=[ENTRY])
    assert registry.plugin_registry_errors() == (PluginDiagnostic(
        ENTRY, "duplicate-name",
        f"plugin '{ENTRY}' is registered by 3 entry points with different targets; none of them is loaded",
    ),)
    assert registry.get_connector_class("saas.acme-twice", allowed_plugins=["saas.acme-twice"]) is twice


def test_valid_plugin_loads_once_and_is_attributed_to_its_own_name(monkeypatch, index):
    plugin = _connector()
    _publish(monkeypatch, (ENTRY, plugin))
    assert registry.get_connector_class(ENTRY, allowed_plugins=[ENTRY]) is plugin
    assert registry._cache[ENTRY] is plugin
    assert registry.plugin_registry_errors() == ()
    with pytest.raises(ValueError, match="not approved"):
        registry.get_connector_class(ENTRY)

    config = ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY])
    result = Engine(config, index).run()
    assert result.complete
    (finding,) = result.findings
    (stats,) = result.stats
    assert finding.connector == stats.connector == ENTRY
    assert finding.provider == "acme-hub" and finding.surface is Surface.SAAS
    assert finding.id == finding.compute_id()
    impostor = Finding.from_dict({**finding.to_dict(), "connector": "saas.slack", "id": ""})
    assert impostor.id != finding.id
    assert result.collection_scope["comparable"] is False


def test_mismatched_plugin_yields_no_findings_and_an_incomplete_scan(monkeypatch, index):
    _publish(monkeypatch, ("saas.acme-alias", _connector(name="saas.slack")))
    config = ScanConfig(connectors=[ConnectorSpec("saas.acme-alias")], plugins=["saas.acme-alias"])
    result = Engine(config, index).run()
    assert not result.complete and result.findings == []
    (stats,) = result.stats
    assert stats.connector == "saas.acme-alias" and stats.skipped and stats.incomplete
    (error,) = stats.errors
    assert "PluginRegistryError" in error and "declares name 'saas.slack'" in error
    (diagnostic,) = registry.plugin_registry_errors()
    assert diagnostic.rule == "reserved-name" and diagnostic.entry == "saas.acme-alias"


def test_listing_and_diagnostics_never_import_plugin_code(monkeypatch):
    entry = EntryPoint(name="custom.unloaded", value="must_never_import:Connector", group="shadowscan.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [entry])
    monkeypatch.delitem(sys.modules, "must_never_import", raising=False)
    assert registry.available_connectors()["custom.unloaded"] == "must_never_import:Connector"
    assert registry.connectors_for_surface("custom") == ["custom.unloaded"]
    assert registry.plugin_registry_errors() == ()
    with pytest.raises(ValueError, match="not approved"):
        registry.get_connector_class("custom.unloaded")
    assert "must_never_import" not in sys.modules
    assert "custom.unloaded" not in registry._cache


@pytest.mark.parametrize("rule,overrides", [
    ("identity-mismatch", {"name": 42}),
    ("reserved-name", {"name": "Saas.Slack"}),
    ("reserved-name", {"name": "saas"}),
    ("missing-attribute", {"name": INHERIT}),
    ("missing-attribute", {"surface": INHERIT}),
    ("missing-attribute", {"description": INHERIT}),
    ("missing-attribute", {"config_keys": INHERIT}),
    ("invalid-attribute", {"description": "   "}),
    ("invalid-attribute", {"surface": "saas"}),
    ("invalid-attribute", {"config_keys": ["input"]}),
    ("invalid-attribute", {"config_keys": {"input": None}}),
    ("invalid-attribute", {"provider": 3}),
    ("invalid-attribute", {"requires": "requests"}),
    ("surface-mismatch", {"surface": Surface.CLOUD}),
    ("abstract-class", {"analyze": INHERIT}),
])
def test_incomplete_or_inconsistent_plugin_class_is_refused(monkeypatch, rule, overrides):
    _publish(monkeypatch, (ENTRY, _connector(**overrides)))
    error = _refusal(ENTRY)
    assert error.diagnostic.rule == rule and error.diagnostic.entry == ENTRY
    assert str(error).startswith(f"plugin '{ENTRY}' ('{MODULE}:Target0') ")
    assert registry.plugin_registry_errors() == (error.diagnostic,)


def test_new_namespace_plugin_may_use_any_surface(monkeypatch):
    plugin = _connector(name="platform.acme-hub", surface=Surface.LOWCODE)
    _publish(monkeypatch, ("platform.acme-hub", plugin))
    assert registry.get_connector_class("platform.acme-hub", allowed_plugins=["platform.acme-hub"]) is plugin
    assert registry.plugin_registry_errors() == ()


def test_code_surface_plugin_is_isolated_from_live_credentials_like_a_builtin(monkeypatch):
    # A plugin's namespace need not start with "code." to declare surface
    # CODE (test_new_namespace_plugin_may_use_any_surface); the credential
    # isolation guard must classify it by that declared surface, not by name.
    plugin = _connector(name="acme.reponaut", surface=Surface.CODE)
    _publish(monkeypatch, ("acme.reponaut", plugin))
    cfg = ScanConfig(connectors=[
        ConnectorSpec("acme.reponaut"), ConnectorSpec("identity.okta"),
    ], plugins=["acme.reponaut"])
    with pytest.raises(ValueError, match="allow_credential_mixing"):
        cfg.validate_connector_isolation(cfg.connectors)
    cfg.allow_credential_mixing = True
    assert cfg.validate_connector_isolation(cfg.connectors) is None


def test_non_code_surface_plugin_is_not_isolated_as_code(monkeypatch):
    plugin = _connector(name="acme.reponaut", surface=Surface.SAAS)
    _publish(monkeypatch, ("acme.reponaut", plugin))
    cfg = ScanConfig(connectors=[
        ConnectorSpec("acme.reponaut"), ConnectorSpec("identity.okta"),
    ], plugins=["acme.reponaut"])
    assert cfg.validate_connector_isolation(cfg.connectors) is None


@pytest.mark.parametrize("target,rule,detail", [
    (object(), "not-a-connector", "is not a BaseConnector subclass"),
    (type("Loose", (), {"name": ENTRY}), "not-a-connector", "is not a BaseConnector subclass"),
])
def test_target_that_is_not_a_connector_is_refused(monkeypatch, target, rule, detail):
    _publish(monkeypatch, (ENTRY, target))
    error = _refusal(ENTRY)
    assert error.diagnostic.rule == rule and detail in str(error)


def test_import_failures_are_refused_with_a_bounded_diagnostic(monkeypatch):
    _publish(monkeypatch, extra=(
        EntryPoint(name="saas.missing-attribute", value=f"{MODULE}:Missing", group="shadowscan.connectors"),
        EntryPoint(name="saas.missing-module", value="no_such_shadowscan_module:Connector", group="shadowscan.connectors"),
    ))
    for name in ("saas.missing-attribute", "saas.missing-module"):
        error = _refusal(name)
        assert error.diagnostic.rule == "load-failed" and error.diagnostic.entry == name
        assert "could not be imported" in str(error)
    assert {diagnostic.entry for diagnostic in registry.plugin_registry_errors()} == {
        "saas.missing-attribute", "saas.missing-module",
    }


def test_diagnostics_are_credential_free_and_bounded(monkeypatch):
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123"
    _publish(monkeypatch, ("saas.leaky", _connector(name=f"saas.leaky?token={token}")),
             ("saas.verbose", _connector(name="saas.verbose-" + "x" * 500)))
    leaky = _refusal("saas.leaky")
    assert token not in str(leaky) and REDACTED in str(leaky)
    verbose = _refusal("saas.verbose")
    assert "xxxx" not in str(verbose) and "omitted" in str(verbose)
    for diagnostic in registry.plugin_registry_errors():
        assert token not in diagnostic.message and "xxxx" not in diagnostic.message


@pytest.mark.parametrize("name,rule", [
    (" saas.acme-hub", "invalid-name"), ("saas.acme hub", "invalid-name"), ("saas.acme\thub", "invalid-name"),
])
def test_malformed_entry_point_names_are_not_listed(monkeypatch, name, rule):
    _publish(monkeypatch, (name, _connector(name=name)))
    assert name not in registry.available_connectors()
    (diagnostic,) = registry.plugin_registry_errors()
    assert diagnostic.rule == rule and diagnostic.entry == name
    assert "\t" not in diagnostic.message


def test_every_builtin_connector_satisfies_the_plugin_identity_rules():
    for name, path in registry._BUILTIN.items():
        cls = registry.get_connector_class(name)
        assert registry._verify_connector_class(name, path, cls) is cls
    assert registry.plugin_registry_errors() == ()
