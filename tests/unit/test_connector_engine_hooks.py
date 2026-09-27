"""Engine behaviour a connector declares through BaseConnector hooks.

The engine holds no connector names. Per-root incremental caching, the
scan-wide instance-credential approval and the per-run identity key are
capabilities a connector class declares; BaseConnector supplies defaults.
The engine looks each job's class up once, before it reads those hooks.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, ClassVar

import pytest

import shadowscan.engine as engine_module
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import builtin_connector_names, get_connector_class
from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import Engine
from shadowscan.models import Finding, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.utils import http


def _recording_connector(**hooks: Any) -> tuple[type[BaseConnector], list[ConnectorContext]]:
    """A plugin-like connector class that records the context the engine builds for it."""
    contexts: list[ConnectorContext] = []

    class Recorder(BaseConnector):
        name: ClassVar[str] = "platform.recorder"
        surface: ClassVar[Surface] = Surface.LOWCODE
        description: ClassVar[str] = "records its connector context"

        def __init__(self, ctx: ConnectorContext) -> None:
            super().__init__(ctx)
            contexts.append(ctx)

        def collect(self) -> list[dict[str, Any]]:
            return []

        def analyze(self, records: Any) -> list[Finding]:
            return []

    for attribute, value in hooks.items():
        setattr(Recorder, attribute, value)
    return Recorder, contexts


def _run(monkeypatch: pytest.MonkeyPatch, connector: type[BaseConnector], specs: list[ConnectorSpec],
         **options: Any) -> Engine:
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: connector)
    engine = Engine(ScanConfig(connectors=specs, **options), SignatureIndex([]))
    assert engine.run().complete
    return engine


def test_engine_source_names_no_connector_and_imports_no_connector_module():
    tree = ast.parse(Path(engine_module.__file__).read_text(encoding="utf-8"))
    namespaces = {name.partition(".")[0] for name in builtin_connector_names()}
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    connector_modules = {module for module in imported if module.startswith("shadowscan.connectors.")}
    assert connector_modules <= {"shadowscan.connectors.base", "shadowscan.connectors.common"}
    strings = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not {value for value in strings if value.partition(".")[0] in namespaces and "." in value}


def test_base_connector_hooks_describe_an_ordinary_connector():
    assert BaseConnector.uses_run_identity_key is False
    assert BaseConnector.inherits_instance_credentials_approval() is False
    assert BaseConnector.cache_roots_separately(["a", "b"], None, labelled=False) is False


def test_builtin_connectors_declare_exactly_the_hooks_the_engine_used_to_hard_code():
    classes = {name: get_connector_class(name) for name in builtin_connector_names()}
    assert {name for name, cls in classes.items() if cls.uses_run_identity_key} == {"gateway.logs"}
    assert {name for name, cls in classes.items() if cls.inherits_instance_credentials_approval()} == {
        "cloud.aws", "cloud.azure", "cloud.gcp", "cloud.oci",
    }
    # The cloud surface covers every name the engine used to match by prefix.
    assert {name for name, cls in classes.items() if cls.surface == Surface.CLOUD} == {
        name for name in classes if name.partition(".")[0] == Surface.CLOUD.value
    }
    splitting = {
        name for name, cls in classes.items()
        if any("cache_roots_separately" in vars(klass) for klass in cls.__mro__ if klass is not BaseConnector)
    }
    assert splitting == {"code.filesystem"}


def test_filesystem_root_split_hook_validates_labelled_roots_and_ids(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    roots = [str(first), str(second)]
    assert FilesystemConnector.cache_roots_separately(roots, None, labelled=False) is True
    assert FilesystemConnector.cache_roots_separately(roots, ["repo-a", "repo-b"], labelled=True) is True
    with pytest.raises(ConnectorError, match="distinct scan roots"):
        FilesystemConnector.cache_roots_separately([str(first), str(first)], None, labelled=True)
    with pytest.raises(ConnectorError, match="root_ids"):
        FilesystemConnector.cache_roots_separately(roots, ["only-one"], labelled=False)


def test_declared_run_identity_key_is_shared_within_a_run_and_rotated_between_runs(monkeypatch):
    connector, contexts = _recording_connector(uses_run_identity_key=True)
    specs = [ConnectorSpec("platform.recorder", label="one"), ConnectorSpec("platform.recorder", label="two")]
    engine = _run(monkeypatch, connector, specs, parallel=2)
    first_run = {ctx.gateway_identity_key for ctx in contexts}
    assert len(first_run) == 1 and None not in first_run
    contexts.clear()
    assert engine.run().complete
    second_run = {ctx.gateway_identity_key for ctx in contexts}
    assert len(second_run) == 1 and second_run != first_run


def test_undeclared_connector_receives_no_run_identity_key(monkeypatch):
    connector, contexts = _recording_connector()
    _run(monkeypatch, connector, [ConnectorSpec("platform.recorder")])
    assert [ctx.gateway_identity_key for ctx in contexts] == [None]


@pytest.mark.parametrize("approved", [False, True])
def test_documented_instance_credentials_key_inherits_the_scan_wide_approval(monkeypatch, approved):
    documented = {"allow_instance_credentials": "inherited from options"}
    connector, contexts = _recording_connector(config_keys=documented)
    _run(monkeypatch, connector, [ConnectorSpec("platform.recorder")], allow_instance_credentials=approved)
    assert contexts[0].config["allow_instance_credentials"] is approved


@pytest.mark.parametrize("approved", [False, True])
def test_cloud_connector_inherits_the_scan_wide_approval_without_documenting_the_key(monkeypatch, approved):
    # Every cloud.* entry received the scan-wide value before the hook. A
    # cloud plugin that reads the key without documenting it must not fall
    # back to its own default and acquire credentials the scan denied.
    connector, contexts = _recording_connector(name="cloud.acme", surface=Surface.CLOUD)
    _run(monkeypatch, connector, [ConnectorSpec("cloud.acme")], allow_instance_credentials=approved)
    assert "allow_instance_credentials" not in connector.config_keys
    assert contexts[0].config["allow_instance_credentials"] is approved
    assert contexts[0].get("allow_instance_credentials", True) is approved


def test_undocumented_instance_credentials_key_is_not_injected(monkeypatch):
    connector, contexts = _recording_connector()
    _run(monkeypatch, connector, [ConnectorSpec("platform.recorder")], allow_instance_credentials=True)
    assert "allow_instance_credentials" not in contexts[0].config


def test_connector_level_instance_credentials_approval_never_takes_effect(monkeypatch):
    # Before the hook, only names starting with "cloud." were overridden, so
    # an entry of any other connector passed its own approval through.
    connector, contexts = _recording_connector()
    spec = ConnectorSpec("platform.recorder", {"allow_instance_credentials": True})
    _run(monkeypatch, connector, [spec], allow_instance_credentials=False)
    assert contexts[0].config["allow_instance_credentials"] is False


def _recording_lookup(monkeypatch: pytest.MonkeyPatch, connector: type[BaseConnector]) -> list[bool]:
    """Replace the class lookup; record the private-origin policy each lookup runs under."""
    policies: list[bool] = []

    def lookup(name: str) -> type[BaseConnector]:
        policies.append(http._allow_private_origin.get())
        return connector

    monkeypatch.setattr(engine_module, "get_connector_class", lookup)
    return policies


def test_connector_lookup_runs_under_the_scan_private_origin_policy(monkeypatch):
    # Looking up a plugin imports it. As in collection, that code runs under
    # the scan's policy, which is restored afterwards.
    connector, contexts = _recording_connector()
    policies = _recording_lookup(monkeypatch, connector)
    config = ScanConfig(connectors=[ConnectorSpec("platform.recorder")], allow_private_origin=True)
    assert Engine(config, SignatureIndex([])).run().complete
    assert policies == [True] and len(contexts) == 1
    assert http._allow_private_origin.get() is False


def test_job_out_of_time_does_not_look_up_its_connector(monkeypatch):
    # A job whose deadline has already passed reports it without importing
    # the plugin, as collection did before the lookup moved ahead of it.
    connector, contexts = _recording_connector()
    policies = _recording_lookup(monkeypatch, connector)
    config = ScanConfig(connectors=[ConnectorSpec("platform.recorder")], connector_timeout_seconds=1e-9)
    result = Engine(config, SignatureIndex([])).run()
    assert not result.complete and result.stats[0].incomplete
    assert policies == [] and contexts == []
