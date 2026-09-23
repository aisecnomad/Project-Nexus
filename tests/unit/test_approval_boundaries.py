"""Regression coverage for approval, extension and audit-export boundaries."""

from __future__ import annotations

import json
import stat
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest
import yaml

import shadowscan.connectors as registry
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, card_stub_for
from shadowscan.signatures import get_index
from shadowscan.signatures.loader import load_signature_file, load_signatures


def _finding(resource: str) -> Finding:
    return Finding(Surface.CLOUD, "cloud.aws", Kind.AGENT, "Agent", resource, "agent", provider="aws")


@pytest.mark.parametrize("resource,other", [
    ("agent[12]", "agent1"), ("agent*", "agent-anything"),
    ("agent?", "agent1"), ("agent[*?]", "agent*"),
])
def test_generated_card_approves_only_literal_resource(tmp_path, resource, other):
    path = tmp_path / "card.yaml"
    path.write_text(yaml.safe_dump(card_stub_for(_finding(resource))))
    inventory = Inventory.load([path])
    assert inventory.match(_finding(resource)) is not None
    assert inventory.match(_finding(other)) is None


def test_authored_inventory_still_supports_explicit_wildcards(tmp_path):
    path = tmp_path / "agents.yaml"
    path.write_text("id: approved\nresources: ['agent-*']\n")
    assert Inventory.load([path]).match(_finding("agent-one")) is not None


def test_plugin_requires_approval_even_after_cached_import(monkeypatch):
    entry = EntryPoint(name="code.extension", value="custom_plugin:Extension", group="shadowscan.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [entry])
    monkeypatch.setattr(registry, "_cache", {})
    imports = []

    def load(path):
        imports.append(path)
        return BaseConnector

    monkeypatch.setattr(registry, "_load", load)
    with pytest.raises(ValueError, match="not approved"):
        registry.get_connector_class("code.extension")
    assert imports == []
    assert registry.get_connector_class("code.extension", allowed_plugins=["code.extension"]) is BaseConnector
    assert len(imports) == 1
    with pytest.raises(ValueError, match="not approved"):
        registry.get_connector_class("code.extension")
    with pytest.raises(ValueError, match="not approved"):
        registry.get_connector_class("code.extension", allowed_plugins="code.extension")


@pytest.mark.parametrize("name,value", [
    ("plugins", "code.plugin"), ("plugins", [1]), ("plugins", [""]),
    ("allow_signature_override", "false"), ("allow_private_origin", 1),
])
def test_security_options_require_explicit_types(name, value):
    with pytest.raises(ValueError, match=name):
        ScanConfig.from_dict({"options": {name: value}})
    with pytest.raises(ValueError, match=name):
        ScanConfig(**{name: value})


def test_index_override_authorization_does_not_leak_across_calls(tmp_path):
    path = tmp_path / "override.yaml"
    path.write_text("id: framework.langchain\nname: Override\ncategory: framework\n"
                    "signals:\n  - type: dependency\n    names: [custom]\n")
    assert get_index([str(tmp_path)], allow_override=True).signatures["framework.langchain"].name == "Override"
    with pytest.raises(ValueError, match="reserved by a built-in"):
        get_index([str(tmp_path)])


def test_explicit_policy_symlinks_cannot_approve_or_override(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    inventory = outside / "inventory.yaml"
    inventory.write_text("id: all\nresources: ['*']\n")
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic links"):
        Inventory.load([link])
    with pytest.raises(ValueError, match="symbolic links"):
        load_signatures([link], include_builtin=False)
    with pytest.raises((OSError, ValueError)):
        load_signature_file(link / "inventory.yaml")


def test_recursive_inventory_glob_cannot_follow_links_or_loops(tmp_path):
    root = tmp_path / "inventory"
    root.mkdir()
    (root / "agents.yaml").write_text("id: approved\nresources: ['agent-one']\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hostile.yaml").write_text("id: hostile\nresources: ['*']\n")
    (root / "outside").symlink_to(outside, target_is_directory=True)
    (root / "cycle").symlink_to(root, target_is_directory=True)
    assert [entry.agent_id for entry in Inventory.load([root / "**" / "*.yaml"]).entries] == ["approved"]


def _export_config(tmp_path: Path, *, parallel: int = 2) -> ScanConfig:
    specs = []
    for agent_id in ("FIRST", "SECOND"):
        source = tmp_path / f"{agent_id}.json"
        source.write_text(json.dumps([{
            "_kind": "bedrock-agent", "agentId": agent_id, "agentName": agent_id,
            "agentArn": f"arn:aws:bedrock:us-east-1:123456789012:agent/{agent_id}",
        }]))
        specs.append(ConnectorSpec("cloud.aws", {"input": str(source)}, label="same/label"))
    return ScanConfig(connectors=specs, dump_records=str(tmp_path / "exports"), parallel=parallel)


@pytest.mark.parametrize("parallel", [1, 2])
def test_repeated_connector_exports_are_distinct_and_private(tmp_path, index, parallel):
    config = _export_config(tmp_path, parallel=parallel)
    result = Engine(config, index).run()
    assert result.complete and len(result.findings) == 2
    destination = Path(config.dump_records)
    dumps = sorted(destination.glob("*.jsonl"))
    assert len(dumps) == 2
    assert {json.loads(path.read_text())["agentId"] for path in dumps} == {"FIRST", "SECOND"}
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in dumps)
    manifest = json.loads((destination / "manifest.json").read_text())
    assert manifest["complete"] is True
    assert [entry["config_ordinal"] for entry in manifest["exports"]] == [1, 2]
    assert {entry["filename"] for entry in manifest["exports"]} == {path.name for path in dumps}


def test_manifest_does_not_claim_stale_export_after_failure(tmp_path, index):
    config = _export_config(tmp_path, parallel=1)
    assert Engine(config, index).run().complete
    config.connectors[0].config["max_input_bytes"] = 0  # constructor fails before replacing its previous export
    assert not Engine(config, index).run().complete
    manifest = json.loads((Path(config.dump_records) / "manifest.json").read_text())
    failed = manifest["exports"][0]
    assert not manifest["complete"] and not failed["complete"]
    assert failed["filename"] is None and not failed["exported"]


def test_dump_shared_directory_is_rejected_without_permission_changes(tmp_path, index):
    config = _export_config(tmp_path)
    destination = Path(config.dump_records)
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    with pytest.raises(ValueError, match="0700"):
        Engine(config, index).run()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755


def test_manifest_write_failure_marks_scan_incomplete(tmp_path, index, monkeypatch):
    config = _export_config(tmp_path)

    def failed(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("shadowscan.engine.write_private_text", failed)
    result = Engine(config, index).run()
    assert not result.complete
    assert any("manifest could not be saved" in error for stats in result.stats for error in stats.errors)


def test_no_dump_connector_manifest_never_claims_an_export(tmp_path, index):
    import jwt

    token = jwt.encode({"sub": "agent", "agent_id": "agent-one"}, "synthetic-signing-key-only-32-bytes", algorithm="HS256")
    config = ScanConfig(connectors=[ConnectorSpec("identity.jwt", {"tokens": [token]})],
                        dump_records=str(tmp_path / "exports"))
    assert Engine(config, index).run().complete
    manifest = json.loads((Path(config.dump_records) / "manifest.json").read_text())
    assert manifest["exports"][0]["filename"] is None
    assert not manifest["exports"][0]["exported"]
    assert not list(Path(config.dump_records).glob("*.jsonl"))


@pytest.mark.parametrize("parallel", [1, 2])
def test_engine_propagates_and_restores_private_origin_policy(index, monkeypatch, parallel):
    from shadowscan.utils import http

    observed = []

    class Probe(BaseConnector):
        def collect(self):
            observed.append(http._allow_private_origin.get())
            raise RuntimeError("simulated failure")

        def analyze(self, records):
            yield from ()

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda *args, **kwargs: Probe)
    config = ScanConfig(connectors=[ConnectorSpec("probe.one"), ConnectorSpec("probe.two")],
                        allow_private_origin=True, parallel=parallel)
    result = Engine(config, index).run()
    assert not result.complete and observed == [True, True]
    assert http._allow_private_origin.get() is False
