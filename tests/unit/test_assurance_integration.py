"""Cross-layer checks for retained trust boundaries and failed cloud records."""
from __future__ import annotations

import json
from importlib.metadata import EntryPoint

import pytest

import shadowscan.connectors as registry
from shadowscan.cli import _exit_code
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import Engine
from shadowscan.reporters.sarif import render_sarif


def test_plugin_entrypoint_cannot_replace_builtin(monkeypatch):
    entries = [
        EntryPoint(name="code.filesystem", value="untrusted_plugin:Replacement", group="shadowscan.connectors"),
        EntryPoint(name="code.extension", value="custom_plugin:Extension", group="shadowscan.connectors"),
    ]
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: entries)
    monkeypatch.setattr(registry, "_cache", {})
    connectors = registry.available_connectors()
    assert connectors["code.filesystem"] == registry._BUILTIN["code.filesystem"]
    assert connectors["code.extension"] == "custom_plugin:Extension"
    assert registry.get_connector_class("code.filesystem") is FilesystemConnector


@pytest.mark.parametrize("connector,record", [
    ("cloud.aws", {"_kind": "bedrock-agent"}),
    ("cloud.gcp", {"_kind": "reasoning-engine"}),
    ("cloud.azure", {"_kind": "resource", "type": "Microsoft.CognitiveServices/accounts", "kind": "OpenAI"}),
    ("cloud.oci", {"_kind": "genai-agent"}),
])
def test_missing_cloud_resource_cannot_pass_or_enter_cache(tmp_path, index, connector, record):
    source = tmp_path / "records.json"
    source.write_text(json.dumps([record]))
    config = ScanConfig(
        connectors=[ConnectorSpec(connector, {"input": str(source)})],
        incremental=True, state_dir=str(tmp_path / "state"),
    )
    for _ in range(2):
        result = Engine(config, index=index).run()
        assert not result.complete
        assert result.stats[0].errors or result.stats[0].warnings
        assert not result.stats[0].cached
        assert not result.findings
        assert _exit_code(result, "high") == 3
        invocation = json.loads(render_sarif(result))["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
    assert not list((tmp_path / "state").glob("*.json"))
