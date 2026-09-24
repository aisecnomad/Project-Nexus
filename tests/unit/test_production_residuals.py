"""Regressions for the 2026-09-24 production residual review."""

from __future__ import annotations

from importlib.metadata import EntryPoint

import shadowscan.connectors as registry
from shadowscan.models import Finding, Kind, Surface


def test_duplicate_plugin_names_are_omitted(monkeypatch):
    entries = [
        EntryPoint(name="code.extension", value="plugin_a:A", group="shadowscan.connectors"),
        EntryPoint(name="code.extension", value="plugin_b:B", group="shadowscan.connectors"),
    ]
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: entries)
    connectors = registry.available_connectors()
    assert "code.extension" not in connectors
    assert connectors["code.filesystem"] == registry._BUILTIN["code.filesystem"]


def test_plugin_discovery_failure_keeps_builtins(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("broken metadata")

    monkeypatch.setattr(registry, "entry_points", boom)
    connectors = registry.available_connectors()
    assert connectors["code.filesystem"] == registry._BUILTIN["code.filesystem"]
    assert connectors["cloud.aws"] == registry._BUILTIN["cloud.aws"]


def test_finding_from_dict_ignores_unknown_keys():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="t",
        resource="r",
        resource_type="repository",
    )
    payload = finding.to_dict()
    payload["future_reporter_field"] = {"not": "a finding attribute"}
    restored = Finding.from_dict(payload)
    assert restored.resource == "r"
    assert restored.title == "t"
    assert restored.identity_schema == finding.identity_schema
