from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import Engine
from shadowscan.incremental import IncrementalCache, Snapshot, _json
from shadowscan.models import Finding, Kind, ScanStats, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.utils import digest as digest_module
from shadowscan.utils.git import MetadataOutputLimitError, MetadataTimeoutError, git_argv_prefix, safe_git_env


def config(tmp_path: Path, **overrides) -> ScanConfig:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "requirements.txt").write_text("langchain\n")
    values = dict(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False})],
        incremental=True,
        state_dir=str(tmp_path / "state"),
        parallel=1,
    )
    values.update(overrides)
    return ScanConfig(**values)


def count_runs(monkeypatch):
    calls = []
    original = FilesystemConnector.run

    def run(self):
        calls.append(self.ctx.config.get("path"))
        return original(self)

    monkeypatch.setattr(FilesystemConnector, "run", run)
    return calls


@pytest.mark.parametrize("ancestor", [False, True])
def test_symlink_root_paths_are_never_cached(tmp_path, index, monkeypatch, ancestor):
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    if ancestor:
        link = tmp_path / "parent-link"
        link.symlink_to(tmp_path, target_is_directory=True)
        root = link / "repo"
    else:
        root = tmp_path / "repo-link"
        root.symlink_to(tmp_path / "repo", target_is_directory=True)
    cfg.connectors[0].config["path"] = str(root)
    for _ in range(2):
        result = Engine(cfg, index).run()
        assert not result.stats[0].cached
    assert len(calls) == 2


def test_symlink_static_export_is_never_cached(tmp_path, index):
    source = tmp_path / "empty.json"
    source.write_text("[]")
    link = tmp_path / "export.json"
    link.symlink_to(source)
    cfg = config(tmp_path, connectors=[ConnectorSpec("cloud.aws", {"input": str(link)})])
    for _ in range(2):
        result = Engine(cfg, index).run()
        assert not result.stats[0].cached


def test_legacy_identity_cache_format_requires_full_rescan(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    Engine(cfg, index).run()
    cache_file = next((tmp_path / "state").glob("*.json"))
    cached = json.loads(cache_file.read_text())
    cached["format"] = 2
    cache_file.write_text(json.dumps(cached))
    result = Engine(cfg, index).run()
    assert result.complete and not result.stats[0].cached and len(calls) == 2


def test_unchanged_code_reuses_findings_without_leaking_mutations(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    first = Engine(cfg, index).run()
    pristine_ids = [f.id for f in first.findings]
    assert pristine_ids and first.complete and not first.stats[0].cached
    first.findings[0].metadata["injected_after_scan"] = True
    second = Engine(cfg, index).run()
    assert calls == [str(tmp_path / "repo")]
    assert [f.id for f in second.findings] == pristine_ids
    assert second.stats[0].cached and second.stats[0].objects_examined == 0 and second.complete
    assert "injected_after_scan" not in second.findings[0].metadata
    assert first.findings[0].risk.score == second.findings[0].risk.score


def test_signature_fingerprint_is_reused_within_one_cache_lifecycle(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    signature = signature_from_dict(
        {
            "id": "framework.example",
            "name": "Example",
            "category": "framework",
            "signals": [{"type": "dependency", "ecosystem": "pypi", "names": ["example"]}],
        }
    )
    index = SignatureIndex([signature])
    original = index.fingerprint
    calls = 0

    def counted() -> str:
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(index, "fingerprint", counted)
    first_cache = IncrementalCache(cfg, index)
    first = first_cache.snapshot(cfg.connectors[0])
    assert first is not None
    assert first_cache.snapshot(cfg.connectors[0]) == first
    assert calls == 1

    # A new run observes changed detection semantics, while repeated input
    # snapshots within the previous run still compare the actual input bytes.
    signature.name = "Updated Example"
    second_cache = IncrementalCache(cfg, index)
    second = second_cache.snapshot(cfg.connectors[0])
    assert second is not None and second.fingerprint != first.fingerprint
    assert calls == 2


def test_config_credential_cache_fingerprint_stays_private_on_miss_and_hit(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    # Use a supported filesystem option so strict programmatic configuration
    # validation remains in force while exercising a nested sensitive value.
    cfg.connectors[0].config["metadata"] = {"token": "t1"}
    calls = count_runs(monkeypatch)
    cache = IncrementalCache(cfg, index)
    snapshot = cache.snapshot(cfg.connectors[0])
    assert snapshot is not None

    first = Engine(cfg, index).run()
    second = Engine(cfg, index).run()
    assert first.complete and second.complete
    assert not first.stats[0].cached and second.stats[0].cached
    assert calls == [str(tmp_path / "repo")]
    for result in (first, second):
        report = result.to_dict()
        assert "cache_key" not in report["stats"][0]
        assert report["collection_scope"]["comparable"] is False
        assert "fingerprint" not in report["collection_scope"]
        assert snapshot.fingerprint not in json.dumps(report)


def test_content_change_ignores_preserved_size_and_mtime_then_deletion(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    file = tmp_path / "repo" / "requirements.txt"
    Engine(cfg, index).run()
    before = file.stat()
    file.write_text("unrelated\n")  # same byte count as langchain\n
    os.utime(file, ns=(before.st_atime_ns, before.st_mtime_ns))
    changed = Engine(cfg, index).run()
    assert not changed.stats[0].cached and not changed.findings
    file.unlink()
    deleted = Engine(cfg, index).run()
    assert not deleted.stats[0].cached and deleted.complete
    assert len(calls) == 3


def test_independent_repository_roots_do_not_rescan_unchanged_repo(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    second_repo = tmp_path / "second"
    second_repo.mkdir()
    (second_repo / "requirements.txt").write_text("crewai\n")
    cfg.connectors[0].config = {"paths": [str(tmp_path / "repo"), str(second_repo)], "use_git": False}
    calls = count_runs(monkeypatch)
    first = Engine(cfg, index).run()
    (second_repo / "requirements.txt").write_text("langgraph\n")
    second = Engine(cfg, index).run()
    assert first.complete and second.complete
    assert len({f.resource for f in second.findings}) == 2
    assert calls.count(str(tmp_path / "repo")) == 1
    assert calls.count(str(second_repo)) == 2
    assert any("reused 1/2" in warning for warning in second.stats[0].warnings)
    assert any("framework.langchain" in f.frameworks for f in second.findings)
    assert any("framework.langgraph" in f.frameworks for f in second.findings)


def test_configuration_and_signature_changes_invalidate(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    Engine(cfg, index).run()
    cfg.connectors[0].config["scan_secrets"] = False
    assert not Engine(cfg, index).run().stats[0].cached
    replacement = signature_from_dict(
        {
            "id": "framework.test",
            "name": "Test",
            "category": "framework",
            "signals": [{"type": "dependency", "ecosystem": "pypi", "names": ["langchain"]}],
        }
    )
    changed = Engine(cfg, SignatureIndex([replacement])).run()
    assert not changed.stats[0].cached
    assert any("framework.test" in f.frameworks for f in changed.findings)
    assert len(calls) == 3


def test_inventory_and_confidence_are_reapplied_even_with_same_engine(tmp_path, index):
    cfg = config(tmp_path)
    first = Engine(cfg, index).run()
    resource = first.findings[0].resource
    inventory = tmp_path / "agents.json"
    inventory.write_text(
        json.dumps({"agents": [{"id": "approved", "resources": [resource], "owner": "first-owner"}]})
    )
    cfg.inventory = [str(inventory)]
    engine = Engine(cfg, index)
    approved = engine.run()
    assert approved.stats[0].cached and approved.findings[0].registry_match == "approved"
    assert approved.findings[0].owner == "first-owner"
    inventory.write_text('{"agents": []}')
    revoked = engine.run()
    assert revoked.stats[0].cached and revoked.findings[0].shadow is True
    assert revoked.findings[0].registry_match is None and revoked.findings[0].owner is None
    assert revoked.findings[0].risk.score > approved.findings[0].risk.score
    cfg.min_confidence = 1.0
    filtered = engine.run()
    assert filtered.stats[0].cached and not filtered.findings


@pytest.mark.parametrize(
    "damage",
    [
        "garbage",
        "missing",
        "unsafe_permissions",
        "payload_modified",
        "deep_json",
        "duplicate_json",
        "nonfinite_json",
    ],
)
def test_unusable_cache_falls_back_to_scan(tmp_path, index, monkeypatch, damage):
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    Engine(cfg, index).run()
    entry = next((tmp_path / "state").glob("*.json"))
    if damage == "missing":
        entry.unlink()
    elif damage == "unsafe_permissions":
        entry.chmod(0o644)
    elif damage == "payload_modified":
        data = json.loads(entry.read_text())
        data["payload"]["findings"] = []
        entry.write_text(json.dumps(data))
    elif damage == "deep_json":
        entry.write_text("[" * 2000 + "0" + "]" * 2000)
    elif damage == "duplicate_json":
        encoded = entry.read_text()
        entry.write_text('{"format":3,' + encoded[1:])
    elif damage == "nonfinite_json":
        encoded = entry.read_text()
        entry.write_text('{"nonfinite":1e999,' + encoded[1:])
    else:
        entry.write_text("invalid json")
    result = Engine(cfg, index).run()
    assert result.findings and result.complete and not result.stats[0].cached
    assert len(calls) == 2


@pytest.mark.parametrize("field, value", [("location", ["agent.py:1"]), ("attributes", [])])
def test_malformed_cached_evidence_falls_back_before_postprocessing(
    tmp_path, index, monkeypatch, field, value
):
    from shadowscan.incremental import _json

    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    Engine(cfg, index).run()
    entry = next((tmp_path / "state").glob("*.json"))
    data = json.loads(entry.read_text())
    data["payload"]["findings"][0]["evidence"][0][field] = value
    # A checksum covers byte integrity, not the model contract. A stale or
    # external cache producer can persist malformed data with a valid digest.
    data["payload_sha256"] = hashlib.sha256(_json(data["payload"])).hexdigest()
    entry.write_text(json.dumps(data))
    result = Engine(cfg, index).run()
    assert result.complete and result.findings and not result.stats[0].cached
    assert len(calls) == 2


@pytest.mark.parametrize("weight", [7.5, -1, True, "0.9"])
def test_cache_entry_with_an_invalid_evidence_weight_is_a_miss(tmp_path, index, monkeypatch, weight):
    # The payload digest is recomputed, so only the weight makes the entry unusable. A corrupt
    # weight must send the connector back to a full scan, not load as a confident finding.
    cfg = config(tmp_path)
    calls = count_runs(monkeypatch)
    Engine(cfg, index).run()
    entry = next((tmp_path / "state").glob("*.json"))
    data = json.loads(entry.read_text())
    data["payload"]["findings"][0]["evidence"][0]["weight"] = weight
    data["payload_sha256"] = hashlib.sha256(_json(data["payload"])).hexdigest()
    entry.write_text(json.dumps(data))
    result = Engine(cfg, index).run()
    assert result.findings and result.complete and not result.stats[0].cached
    assert len(calls) == 2
    assert all(0 <= item.weight <= 1 for finding in result.findings for item in finding.evidence)


def test_keyed_cache_rejects_an_entry_rewritten_without_the_key(tmp_path, index):
    # An unkeyed checksum can be recomputed by anyone who can write the state
    # directory; with an identity key the entry must carry a keyed MAC.
    from shadowscan.incremental import _json

    cfg = config(tmp_path)
    cache = IncrementalCache(cfg, index, identity_key=b"k" * 32)
    snapshot = cache.snapshot(cfg.connectors[0])
    assert snapshot is not None
    cache.save(snapshot, [], ScanStats(connector=cfg.connectors[0].id, started_at="", finished_at=""))
    entry = next((tmp_path / "state").glob("*.json"))
    data = json.loads(entry.read_text())
    assert "payload_hmac_sha256" in data and "payload_sha256" not in data
    assert cache.load(cfg.connectors[0], snapshot) is not None
    data["payload"]["warnings"] = ["forged"]
    data["payload_hmac_sha256"] = hashlib.sha256(_json(data["payload"])).hexdigest()
    entry.write_text(json.dumps(data))
    assert cache.load(cfg.connectors[0], snapshot) is None
    assert IncrementalCache(cfg, index, identity_key=b"j" * 32).load(cfg.connectors[0], snapshot) is None


def test_concurrent_cache_writers_publish_only_complete_matching_entries(tmp_path, index):
    cfg = config(tmp_path)
    cache = IncrementalCache(cfg, index)
    assert cache.enabled

    def write_and_read(writer):
        snapshot = Snapshot(slot="a" * 64, fingerprint=f"writer-{writer}")
        item = Finding(
            Surface.CODE, "code.filesystem", Kind.AGENT, f"Writer {writer}", f"repo:{writer}", "repository"
        )
        stats = ScanStats(connector="code.filesystem", started_at="now", warnings=[f"writer-{writer}"])
        for _ in range(20):
            cache.save(snapshot, [item], stats)
            loaded = cache.load(cfg.connectors[0], snapshot)
            if loaded is not None:
                findings, saved_stats = loaded
                assert len(findings) == 1 and findings[0].resource == f"repo:{writer}"
                assert saved_stats.warnings == [f"writer-{writer}"]
        return snapshot

    with ThreadPoolExecutor(max_workers=6) as pool:
        snapshots = list(pool.map(write_and_read, range(6)))
    # The last complete replace wins; all other fingerprints must miss safely.
    assert sum(cache.load(cfg.connectors[0], snapshot) is not None for snapshot in snapshots) == 1
    assert not list(cache.directory.glob(".pending-*"))


def test_cache_is_private_sanitized_and_never_written_inside_repository(tmp_path, index, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_IDENTITY_KEY", "hex:" + (b"a" * 32).hex())
    cfg = config(tmp_path)
    secret = "sk-proj-" + "a" * 48
    (tmp_path / "repo" / "main.py").write_text(f'import langchain\napi_key = "{secret}"\n')
    first = Engine(cfg, index).run()
    assert first.complete
    entry = next((tmp_path / "state").glob("*.json"))
    assert secret not in entry.read_text()
    assert entry.stat().st_mode & 0o777 == 0o600
    assert entry.parent.stat().st_mode & 0o777 == 0o700
    cfg.state_dir = str(tmp_path / "repo" / "state")
    assert Engine(cfg, index).run().complete
    assert not Path(cfg.state_dir).exists()


def test_incremental_is_opt_in_and_dumping_disables_reuse(tmp_path, index, monkeypatch):
    cfg = config(tmp_path, incremental=False)
    calls = count_runs(monkeypatch)
    Engine(cfg, index).run()
    Engine(cfg, index).run()
    assert len(calls) == 2 and not (tmp_path / "state").exists()
    cfg.incremental = True
    cfg.dump_records = str(tmp_path / "dumps")
    Engine(cfg, index).run()
    assert len(calls) == 3 and not (tmp_path / "state").exists()


def test_live_cloud_and_temporal_connectors_are_never_cached(tmp_path, index):
    cfg = config(tmp_path)
    export = tmp_path / "export.json"
    export.write_text("[]")
    cache = IncrementalCache(cfg, index)
    for name in ["cloud.aws", "cloud.azure", "cloud.gcp", "cloud.oci", "code.github", "code.gitlab"]:
        assert cache.snapshot(ConnectorSpec(name, {"regions": ["us-east-1"]})) is None
    for name in ["identity.jwt", "gateway.logs"]:
        assert cache.snapshot(ConnectorSpec(name, {"input": str(export)})) is None
    assert cache.snapshot(ConnectorSpec("cloud.aws", {"input": str(export)})) is not None


def test_static_cloud_exports_reused_and_updated(tmp_path, index, fixtures, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_IDENTITY_KEY", "hex:" + (b"a" * 32).hex())
    export = tmp_path / "aws.jsonl"
    export.write_bytes((fixtures / "cloud" / "aws_records.jsonl").read_bytes())
    cfg = config(tmp_path, connectors=[ConnectorSpec("cloud.aws", {"input": str(export)})])
    first = Engine(cfg, index).run()
    second = Engine(cfg, index).run()
    assert first.complete and first.findings and second.stats[0].cached
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]
    export.write_text('{"records": []}\n')  # explicit, valid empty inventory
    deleted = Engine(cfg, index).run()
    assert deleted.complete and not deleted.stats[0].cached and not deleted.findings


def test_offline_github_checkout_content_is_in_fingerprint(tmp_path, index, fixtures):
    cfg = config(tmp_path)
    clones = tmp_path / "clones"
    repo = clones / "acme__repo"
    repo.mkdir(parents=True)
    source = repo / "requirements.txt"
    source.write_text("langchain\n")
    cfg.connectors = [ConnectorSpec("code.github", {"input": str(clones), "use_git": False})]
    first = Engine(cfg, index).run()
    assert first.complete and first.findings
    assert Engine(cfg, index).run().stats[0].cached
    source.write_text("unrelated\n")
    assert not Engine(cfg, index).run().stats[0].cached


def test_incomplete_runs_never_cached_and_constructor_errors_isolated(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    calls = []

    class Partial(BaseConnector):
        def collect(self):
            yield {}

        def analyze(self, records):
            calls.append(1)
            yield Finding(Surface.CODE, "code.filesystem", Kind.AGENT, "Agent", "repo:1", "repository")
            self.ctx.error("failed one input")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: Partial)
    assert not Engine(cfg, index).run().complete
    assert not Engine(cfg, index).run().complete
    assert len(calls) == 2 and not list((tmp_path / "state").glob("*.json"))

    class Broken(Partial):
        def __init__(self, ctx):
            raise ValueError("invalid connector option")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: Broken)
    broken = Engine(cfg, index).run()
    assert not broken.complete and "invalid connector option" in broken.stats[0].errors[0]
    assert not Engine(ScanConfig(), index).run().complete


def test_input_mutation_during_scan_prevents_snapshot_save(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    original = FilesystemConnector.run

    def run(self):
        findings = original(self)
        (tmp_path / "repo" / "added.txt").write_text("changed")
        return findings

    monkeypatch.setattr(FilesystemConnector, "run", run)
    result = Engine(cfg, index).run()
    assert result.findings and not result.complete
    assert "changed during the scan" in result.stats[0].errors[0]
    assert not list((tmp_path / "state").glob("*.json"))


def test_input_restored_to_original_bytes_during_scan_cannot_be_cached(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    dependency = tmp_path / "repo" / "requirements.txt"
    original_run = FilesystemConnector.run

    def run(self):
        before = dependency.stat()
        dependency.write_text("langgraph\n")
        findings = original_run(self)
        dependency.write_text("langchain\n")
        os.utime(dependency, ns=(before.st_atime_ns, before.st_mtime_ns))
        return findings

    monkeypatch.setattr(FilesystemConnector, "run", run)
    result = Engine(cfg, index).run()
    assert any("framework.langgraph" in f.frameworks for f in result.findings)
    assert not result.complete and "changed during the scan" in result.stats[0].errors[0]
    assert not list((tmp_path / "state").glob("*.json"))


def test_multi_root_connector_lookup_error_is_reported_as_incomplete(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    another = tmp_path / "another"
    another.mkdir()
    cfg.connectors[0].config = {"paths": [str(tmp_path / "repo"), str(another)]}

    def missing_connector(_name):
        raise ImportError("missing plugin dependency")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", missing_connector)
    result = Engine(cfg, index).run()
    assert not result.complete and not result.findings
    assert result.stats[0].incomplete and "missing plugin dependency" in result.stats[0].errors[0]


def test_reused_engine_reloads_signature_pack_between_runs(tmp_path):
    cfg = config(tmp_path)
    cfg.allow_signature_override = True
    extra = tmp_path / "signatures"
    extra.mkdir()
    override = extra / "langchain.yaml"
    cfg.signature_dirs = [str(extra)]
    override.write_text(
        "id: framework.langchain\nname: LangChain\ncategory: framework\nsignals:\n  - type: dependency\n    ecosystem: pypi\n    names: [langchain]\n"
    )
    engine = Engine(cfg)
    first = engine.run()
    assert first.complete and any("framework.langchain" in f.frameworks for f in first.findings)
    override.write_text(
        "id: framework.langchain\nname: LangChain\ncategory: framework\nsignals:\n  - type: dependency\n    ecosystem: pypi\n    names: [unrelated]\n"
    )
    second = engine.run()
    assert second.complete and not second.stats[0].cached
    assert not any("framework.langchain" in f.frameworks for f in second.findings)


def test_cache_never_serializes_post_scan_correlation(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)

    def correlate(findings):
        findings[0].metadata["runtime_marker"] = "changed per run"

    monkeypatch.setattr("shadowscan.engine.correlate_runtime", correlate)
    first = Engine(cfg, index).run()
    assert first.findings[0].metadata["runtime_marker"]
    entry = next((tmp_path / "state").glob("*.json"))
    assert "runtime_marker" not in entry.read_text()
    monkeypatch.setattr("shadowscan.engine.correlate_runtime", lambda _: None)
    second = Engine(cfg, index).run()
    assert second.stats[0].cached and "runtime_marker" not in second.findings[0].metadata


def test_incremental_config_paths_and_boolean_validation(tmp_path):
    cfg = ScanConfig.from_dict(
        {"options": {"incremental": True, "state_dir": "state"}}, source=str(tmp_path / "config.yaml")
    )
    assert cfg.incremental and cfg.state_dir == str(tmp_path / "state")
    with pytest.raises(ValueError, match="YAML boolean"):
        ScanConfig.from_dict({"options": {"incremental": "false"}})


@pytest.mark.parametrize("through_directory", [False, True])
def test_new_codeowners_symlink_cannot_hide_incomplete_scan(tmp_path, index, through_directory):
    cfg = config(tmp_path)
    first = Engine(cfg, index).run()
    assert first.complete
    external = tmp_path / "external"
    external.mkdir()
    (external / "CODEOWNERS").write_text("* @external-team\n")
    if through_directory:
        (tmp_path / "repo" / ".github").symlink_to(external, target_is_directory=True)
    else:
        (tmp_path / "repo" / "CODEOWNERS").symlink_to(external / "CODEOWNERS")
    result = Engine(cfg, index).run()
    assert not result.stats[0].cached and not result.complete
    assert any("CODEOWNERS" in error for error in result.stats[0].errors)
    # Changing a symlink target's contents also must never revive an old result.
    (external / "CODEOWNERS").write_text("* @different-team\n")
    assert not Engine(cfg, index).run().stats[0].cached


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
@pytest.mark.parametrize("repo_name", ["dist", "vendor", ".venv"])
def test_offline_checkout_container_never_excludes_repository_names(tmp_path, index, connector, repo_name):
    cfg = config(tmp_path)
    clones = tmp_path / "clones"
    repo = clones / repo_name
    repo.mkdir(parents=True)
    dependency = repo / "requirements.txt"
    dependency.write_text("unrelated\n")
    cfg.connectors = [ConnectorSpec(connector, {"input": str(clones), "use_git": False})]
    first = Engine(cfg, index).run()
    assert first.complete and not first.findings
    assert Engine(cfg, index).run().stats[0].cached
    dependency.write_text("langgraph\n")
    changed = Engine(cfg, index).run()
    assert changed.complete and not changed.stats[0].cached
    assert any("framework.langgraph" in f.frameworks for f in changed.findings)


def test_irrelevant_oversized_file_is_cached_without_hashing_entire_file(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    # This file is ignored by the code analyzer. Hashing it must not make the
    # incremental optimization perform arbitrarily more I/O than the analyzer:
    # with a hash budget far below its size, only metadata tracking can cache.
    monkeypatch.setattr("shadowscan.incremental._MAX_HASH_BYTES", 16 * 1024 * 1024)
    with (tmp_path / "repo" / "large.bin").open("wb") as stream:
        stream.truncate(1024 * 1024 * 1024)
    result = Engine(cfg, index).run()
    assert result.complete and result.findings and not result.stats[0].cached
    assert list((tmp_path / "state").glob("*.json"))
    assert Engine(cfg, index).run().stats[0].cached


@pytest.mark.parametrize("root_key", ["path", "paths", "input"])
def test_include_scan_never_fingerprints_its_root(tmp_path, index, monkeypatch, root_key):
    # `input` names the root as `path` does: an include walk always runs in
    # full, and the files it does not select are never opened for a digest.
    from shadowscan import incremental

    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text('{"mcpServers": {"fs": {"command": "npx"}}}\n')
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("not a real key\n")
    root = [str(home)] if root_key == "paths" else str(home)
    spec = ConnectorSpec(
        "code.filesystem", {root_key: root, "include": [".cursor/mcp.json"], "use_git": False}
    )
    opened: list[Path] = []
    original = incremental._file_digest

    def recorded(path, *args, **kwargs):
        opened.append(Path(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(incremental, "_file_digest", recorded)
    for _ in range(2):
        result = Engine(config(tmp_path, connectors=[spec]), index).run()
        assert result.complete and not result.stats[0].cached
    assert opened == []


def test_literal_excluded_directory_reuses_cache_but_direct_codeowners_remains_tracked(tmp_path, index):
    cfg = config(tmp_path)
    cfg.connectors[0].config["exclude"] = ["assets", "docs"]
    root = tmp_path / "repo"
    assets = root / "assets"
    assets.mkdir()
    ignored = assets / "agent.py"
    ignored.write_text("import crewai\n")
    docs = root / "docs"
    docs.mkdir()
    owners = docs / "CODEOWNERS"
    owners.write_text("* @first-team\n")

    first = Engine(cfg, index).run()
    cached = Engine(cfg, index).run()
    assert first.complete and cached.complete and cached.stats[0].cached
    assert first.findings[0].owner == "@first-team"

    ignored.write_text("import langgraph\n")
    unchanged = Engine(cfg, index).run()
    assert unchanged.complete and unchanged.stats[0].cached
    assert [f.to_dict() for f in unchanged.findings] == [f.to_dict() for f in cached.findings]

    owners.write_text("* @second-team\n")
    updated = Engine(cfg, index).run()
    assert updated.complete and not updated.stats[0].cached
    assert updated.findings[0].owner == "@second-team"


def test_default_excludes_option_decides_whether_built_in_directories_are_fingerprinted(tmp_path, index):
    cfg = config(tmp_path)
    cfg.connectors[0].config["default_excludes"] = False
    (tmp_path / "skipped").mkdir()
    skipped = config(tmp_path / "skipped")
    agent = tmp_path / "repo" / "bin" / "agent.py"
    agent.parent.mkdir()
    agent.write_text("import crewai\n")
    ignored = tmp_path / "skipped" / "repo" / "bin" / "agent.py"
    ignored.parent.mkdir()
    ignored.write_text("import crewai\n")

    # Scanned directory: a change inside it must miss the cache and be reported.
    assert Engine(cfg, index).run().stats[0].cached is False
    assert Engine(cfg, index).run().stats[0].cached
    agent.write_text("import langgraph\n")
    updated = Engine(cfg, index).run()
    assert not updated.stats[0].cached
    assert any("framework.langgraph" in f.frameworks for f in updated.findings)

    # Skipped (default) directory: it is outside the scan, so a change there reuses the cache.
    assert Engine(skipped, index).run().stats[0].cached is False
    ignored.write_text("import langgraph\n")
    assert Engine(skipped, index).run().stats[0].cached


@pytest.mark.parametrize("limit", ["_MAX_HASH_BYTES", "_MAX_HASH_ENTRIES", "_MAX_HASH_SECONDS"])
def test_fingerprint_work_limits_fall_back_to_full_scan(tmp_path, index, monkeypatch, limit):
    cfg = config(tmp_path)
    monkeypatch.setattr(f"shadowscan.incremental.{limit}", 0)
    result = Engine(cfg, index).run()
    assert result.complete and result.findings and not result.stats[0].cached
    assert not list((tmp_path / "state").glob("*.json"))


def test_fingerprint_depth_limit_precedes_recursive_descent(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    directory = tmp_path / "repo"
    for number in range(4):
        directory = directory / f"level-{number}"
        directory.mkdir()
    monkeypatch.setattr("shadowscan.incremental._MAX_HASH_DEPTH", 2)
    assert IncrementalCache(cfg, index).snapshot(cfg.connectors[0]) is None


def test_runtime_semantics_are_part_of_shared_scanner_digest(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    (package / "scanner.py").write_text("value = 1\n")
    first = digest_module.scanner_source_digest(package)
    monkeypatch.setattr(digest_module, "runtime_semantics", lambda: {"python": "different"})
    assert digest_module.scanner_source_digest(package) != first


def test_gitfile_checkout_is_not_eligible_for_git_aware_reuse(tmp_path, index):
    cfg = config(tmp_path)
    cfg.connectors[0].config["use_git"] = True
    external = tmp_path / "external.git"
    external.mkdir()
    (tmp_path / "repo" / ".git").write_text(f"gitdir: {external}\n")
    cache = IncrementalCache(cfg, index)
    assert cache.snapshot(cfg.connectors[0]) is None


@pytest.mark.parametrize("layout", ["config-include", "common-directory", "internal-link"])
def test_git_fingerprint_refuses_unconfined_metadata_before_git(tmp_path, index, monkeypatch, layout):
    cfg = config(tmp_path)
    cfg.connectors[0].config["use_git"] = True
    marker = tmp_path / "repo" / ".git"
    marker.mkdir()
    external = tmp_path / "outside"
    external.mkdir()
    if layout == "config-include":
        (marker / "config").write_text(f'[include]\n path = "{external / "config"}"\n')
    elif layout == "common-directory":
        (marker / "commondir").write_text(f"{external}\n")
    else:
        (marker / "objects").symlink_to(external, target_is_directory=True)
    cache = IncrementalCache(cfg, index)

    def unexpected_git(*args, **kwargs):
        pytest.fail("unconfined metadata reached Git during fingerprinting")

    monkeypatch.setattr("shadowscan.incremental.run_bounded_metadata", unexpected_git)
    assert cache.snapshot(cfg.connectors[0]) is None


@pytest.mark.requires_git_2_45
def test_unsafe_metadata_change_cannot_reuse_complete_scan(tmp_path, index):
    cfg = config(tmp_path)
    cfg.connectors[0].config["use_git"] = True
    repo = tmp_path / "repo"

    def git(*args):
        subprocess.run(
            [*git_argv_prefix(), "-c", "commit.gpgsign=false", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            env=safe_git_env(),
        )

    git("init")
    git("config", "user.name", "Synthetic")
    git("config", "user.email", "synthetic@example.invalid")
    git("add", "requirements.txt")
    git("-c", "maintenance.auto=false", "commit", "-m", "initial")
    assert Engine(cfg, index).run().complete
    assert Engine(cfg, index).run().stats[0].cached

    external = tmp_path / "outside.config"
    external.write_text("[core]\n bare = false\n")
    with (repo / ".git" / "config").open("a") as stream:
        stream.write(f'\n[include]\n path = "{external}"\n')
    result = Engine(cfg, index).run()
    assert not result.complete and not result.stats[0].cached
    assert result.findings
    assert any("metadata" in warning or "gitlinks" in warning for warning in result.stats[0].warnings)


def test_git_preflight_obeys_deadline_and_rechecks_cancellation(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    cfg.connectors[0].config["use_git"] = True
    (tmp_path / "repo" / ".git").mkdir()
    cache = IncrementalCache(cfg, index)
    cancelled = False
    timeouts = []

    def preflight(root, *, timeout):
        nonlocal cancelled
        timeouts.append(timeout)
        cancelled = True

    def check_deadline():
        if cancelled:
            raise ConnectorError("connector completion deadline exceeded")

    def unexpected_git(*args, **kwargs):
        pytest.fail("cancelled fingerprint reached Git after metadata preflight")

    monkeypatch.setattr("shadowscan.incremental.require_local_git_metadata", preflight)
    monkeypatch.setattr("shadowscan.incremental.run_bounded_metadata", unexpected_git)
    with pytest.raises(ConnectorError, match="deadline"):
        cache.snapshot(cfg.connectors[0], check_deadline=check_deadline, deadline=time.monotonic() + 5)
    assert len(timeouts) == 1 and 0 < timeouts[0] <= 5


def test_fingerprinting_propagates_connector_cancellation(tmp_path, index):
    cfg = config(tmp_path)
    cache = IncrementalCache(cfg, index)
    checks = 0

    def check_deadline():
        nonlocal checks
        checks += 1
        if checks == 3:
            raise ConnectorError("connector completion deadline exceeded")

    with pytest.raises(ConnectorError, match="deadline"):
        cache.snapshot(cfg.connectors[0], check_deadline=check_deadline, deadline=time.monotonic() + 30)
    assert checks == 3


def test_git_fingerprint_command_is_bounded_by_connector_deadline(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    cfg.connectors[0].config["use_git"] = True
    (tmp_path / "repo" / ".git").mkdir()
    cache = IncrementalCache(cfg, index)
    timeouts = []

    def timeout(*args, **kwargs):
        timeouts.append(kwargs["timeout"])
        raise MetadataTimeoutError("git metadata completion deadline exceeded")

    monkeypatch.setattr("shadowscan.incremental.run_bounded_metadata", timeout)
    connector_deadline = time.monotonic() + 0.5
    assert cache.snapshot(cfg.connectors[0], deadline=connector_deadline) is None
    assert len(timeouts) == 1 and 0 < timeouts[0] <= 0.5


def test_git_fingerprint_output_is_byte_bounded(tmp_path, index, monkeypatch):
    # Repository-controlled refs must not stream unbounded output into memory.
    cfg = config(tmp_path)
    cfg.connectors[0].config["use_git"] = True
    (tmp_path / "repo" / ".git").mkdir()
    monkeypatch.setattr("shadowscan.incremental.require_local_git_metadata", lambda root, *, timeout: None)
    calls = []

    def bounded(cmd, env, ctx, **kwargs):
        calls.append(kwargs)
        raise MetadataOutputLimitError("git metadata output limit exceeded")

    monkeypatch.setattr("shadowscan.incremental.run_bounded_metadata", bounded)
    assert IncrementalCache(cfg, index).snapshot(cfg.connectors[0]) is None
    assert len(calls) == 1 and calls[0]["strict_utf8"]


def test_engine_passes_connector_deadline_to_all_fingerprint_work(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    observed = []
    original = IncrementalCache.snapshot

    def snapshot(self, spec, **kwargs):
        observed.append(kwargs)
        return original(self, spec, **kwargs)

    monkeypatch.setattr(IncrementalCache, "snapshot", snapshot)
    assert Engine(cfg, index).run().complete
    assert observed
    assert all(callable(item.get("check_deadline")) for item in observed)
    assert all(isinstance(item.get("deadline"), float) for item in observed)


def test_startup_maintenance_deadline_disables_cache_and_runs_full_scan(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    monkeypatch.setattr("shadowscan.incremental._MAX_CACHE_MAINTENANCE_SECONDS", 0.0)

    assert not IncrementalCache(cfg, index).enabled
    result = Engine(cfg, index).run()

    assert result.complete and result.findings
    assert not result.stats[0].cached
    assert not list((tmp_path / "state").glob("*.json"))


@pytest.mark.parametrize(
    "flags",
    [{"incomplete": True}, {"errors": ["connector failed"]}, {"skipped": True}],
    ids=["incomplete", "errors", "skipped"],
)
def test_a_result_that_is_not_a_clean_complete_scan_is_never_cached(tmp_path, index, flags):
    cfg = config(tmp_path)
    cache = IncrementalCache(cfg, index)
    snapshot = Snapshot("a" * 64, "b" * 64)
    cache.save(snapshot, [], ScanStats(connector="test", started_at="2026-09-27T00:00:00Z", **flags))
    assert not (cache.directory / f"{snapshot.slot}.json").exists()
    assert cache.load(cfg.connectors[0], snapshot) is None
    # The same snapshot is stored when the scan was clean, so the refusal above is the flags' doing.
    cache.save(snapshot, [], ScanStats(connector="test", started_at="2026-09-27T00:00:00Z"))
    assert (cache.directory / f"{snapshot.slot}.json").exists()


def test_cache_load_propagates_connector_cancellation(tmp_path, index):
    cfg = config(tmp_path)
    cache = IncrementalCache(cfg, index)
    snapshot = Snapshot("a" * 64, "b" * 64)
    cache.save(snapshot, [], ScanStats(connector="test", started_at="2026-09-27T00:00:00Z"))

    checks = 0

    def cancelled():
        nonlocal checks
        checks += 1
        if checks == 3:
            raise ConnectorError("connector completion deadline exceeded")

    with pytest.raises(ConnectorError, match="deadline"):
        cache.load(cfg.connectors[0], snapshot, check_deadline=cancelled)
    assert checks == 3


def test_cache_enforces_lru_entry_cap_and_refreshes_successful_reads(tmp_path, index, monkeypatch):
    monkeypatch.setattr("shadowscan.incremental._MAX_CACHE_ENTRIES", 2)
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, index)
    stats = ScanStats(connector="test", started_at="2026-09-27T00:00:00Z")
    first = Snapshot("1" * 64, "a" * 64)
    second = Snapshot("2" * 64, "b" * 64)
    third = Snapshot("3" * 64, "c" * 64)
    cache.save(first, [], stats)
    cache.save(second, [], stats)
    now = time.time_ns()
    os.utime(cache.directory / f"{first.slot}.json", ns=(now - 3_000_000_000, now - 3_000_000_000))
    os.utime(cache.directory / f"{second.slot}.json", ns=(now - 2_000_000_000, now - 2_000_000_000))
    assert cache.load(ConnectorSpec("code.filesystem"), first) is not None
    cache.save(third, [], stats)
    assert (cache.directory / f"{first.slot}.json").exists()
    assert not (cache.directory / f"{second.slot}.json").exists()
    assert (cache.directory / f"{third.slot}.json").exists()
    assert (cache.directory / f"{second.slot}.lock").exists()
    assert IncrementalCache(cfg, index).enabled
    assert not (cache.directory / f"{second.slot}.lock").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_orphan_slot_locks_are_reclaimed_before_directory_ceiling(tmp_path, index, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    for number in range(5):
        lock = state / f"{number:064x}.lock"
        lock.write_text("")
        lock.chmod(0o600)
    monkeypatch.setattr("shadowscan.incremental._MAX_CACHE_DIRECTORY_ENTRIES", 1)
    cache = IncrementalCache(ScanConfig(incremental=True, state_dir=str(state)), index)
    assert cache.enabled
    assert not list(state.glob("*.lock"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_startup_budget_check_reaches_orphan_lock_cleanup(tmp_path, index, monkeypatch):
    state = tmp_path / "state"
    cfg = ScanConfig(incremental=True, state_dir=str(state))
    cache = IncrementalCache(cfg, index)
    lock = state / f"{'a' * 64}.lock"
    lock.touch(mode=0o600)
    cleanup_started = False
    original = IncrementalCache._remove_orphan_lock

    def tracked_cleanup(self, slot, *, check_deadline=None):
        nonlocal cleanup_started
        cleanup_started = True
        return original(self, slot, check_deadline=check_deadline)

    def expired():
        if cleanup_started:
            raise RuntimeError("maintenance deadline exceeded")

    monkeypatch.setattr(IncrementalCache, "_remove_orphan_lock", tracked_cleanup)
    with pytest.raises(RuntimeError, match="maintenance deadline exceeded"):
        cache._cache_inventory(check_deadline=expired)
    assert lock.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_active_orphan_slot_lock_is_preserved_until_released(tmp_path, index):
    import fcntl

    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, index)
    lock = cache.directory / f"{'a' * 64}.lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert IncrementalCache(cfg, index).enabled
        assert lock.exists()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    assert IncrementalCache(cfg, index).enabled
    assert not lock.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_slot_lock_rejects_inode_unlinked_between_open_and_flock(tmp_path, index, monkeypatch):
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, index)
    snapshot = Snapshot("b" * 64, "c" * 64)
    lock = cache.directory / f"{snapshot.slot}.lock"
    original_open = os.open
    stale_fd = original_open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    lock.unlink()
    lock.touch(mode=0o600)
    lock.chmod(0o600)

    def open_stale(path, *args, **kwargs):
        if Path(path) == lock:
            return os.dup(stale_fd)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("shadowscan.incremental.os.open", open_stale)
    try:
        with pytest.raises(ValueError, match="pathname changed"), cache._slot_lock(snapshot, exclusive=True):
            pytest.fail("stale lock inode entered the critical section")
    finally:
        os.close(stale_fd)


def test_cache_cleans_expired_entries_and_abandoned_pending_files(tmp_path, index, monkeypatch):
    monkeypatch.setattr("shadowscan.incremental._CACHE_TTL_SECONDS", 1)
    monkeypatch.setattr("shadowscan.incremental._PENDING_TTL_SECONDS", 1)
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, index)
    snapshot = Snapshot("4" * 64, "d" * 64)
    cache.save(snapshot, [], ScanStats(connector="test", started_at="2026-09-27T00:00:00Z"))
    entry = cache.directory / f"{snapshot.slot}.json"
    pending = cache.directory / ".pending-abandoned"
    pending.write_text("partial")
    old = time.time_ns() - 2_000_000_000
    os.utime(entry, ns=(old, old))
    os.utime(pending, ns=(old, old))

    assert IncrementalCache(cfg, index).enabled
    assert not entry.exists()
    assert not pending.exists()


def test_startup_budget_check_reaches_expired_entry_cleanup(tmp_path, index, monkeypatch):
    monkeypatch.setattr("shadowscan.incremental._CACHE_TTL_SECONDS", 1)
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, index)
    snapshot = Snapshot("6" * 64, "f" * 64)
    cache.save(snapshot, [], ScanStats(connector="test", started_at="2026-09-27T00:00:00Z"))
    entry = cache.directory / f"{snapshot.slot}.json"
    old = time.time_ns() - 2_000_000_000
    os.utime(entry, ns=(old, old))
    cleanup_started = False
    original = IncrementalCache._remove_entry

    def tracked_cleanup(self, candidate, *, check_deadline=None):
        nonlocal cleanup_started
        cleanup_started = True
        return original(self, candidate, check_deadline=check_deadline)

    def expired():
        if cleanup_started:
            raise RuntimeError("maintenance deadline exceeded")

    monkeypatch.setattr(IncrementalCache, "_remove_entry", tracked_cleanup)
    with pytest.raises(RuntimeError, match="maintenance deadline exceeded"):
        cache._maintain_cache(check_deadline=expired)
    assert entry.exists()


def test_new_entry_is_discarded_when_aggregate_byte_quota_cannot_hold_it(tmp_path, index, monkeypatch):
    monkeypatch.setattr("shadowscan.incremental._MAX_CACHE_TOTAL_BYTES", 1)
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, index)
    snapshot = Snapshot("5" * 64, "e" * 64)
    cache.save(snapshot, [], ScanStats(connector="test", started_at="2026-09-27T00:00:00Z"))
    assert not (cache.directory / f"{snapshot.slot}.json").exists()


def test_plugin_overriding_builtin_name_is_not_cached(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    runs = []

    class Plugin(BaseConnector):
        def collect(self):
            yield {}

        def analyze(self, records):
            runs.append(1)
            yield Finding(
                Surface.CODE, "code.filesystem", Kind.AGENT, "Plugin", f"run:{len(runs)}", "repository"
            )

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: Plugin)
    assert Engine(cfg, index).run().findings[0].resource == "run:1"
    second = Engine(cfg, index).run()
    assert second.findings[0].resource == "run:2" and not second.stats[0].cached


@pytest.mark.requires_git_2_45
def test_git_replacement_cannot_reuse_stale_owner(tmp_path, index):
    cfg = config(tmp_path)
    repo = tmp_path / "repo"
    cfg.connectors[0].config["use_git"] = True

    def git(*args, env=None):
        return subprocess.run(
            ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
        ).stdout.strip()

    git("init")
    git("config", "user.name", "Alice")
    git("config", "user.email", "alice@example.com")
    git("add", "requirements.txt")
    git("-c", "maintenance.auto=false", "commit", "-m", "initial")
    first = Engine(cfg, index).run()
    assert first.complete and first.findings[0].owner == "alice@example.com"
    assert Engine(cfg, index).run().stats[0].cached
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    replacement = git(
        "commit-tree",
        tree,
        "-m",
        "replacement",
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Bob",
            "GIT_AUTHOR_EMAIL": "bob@example.com",
        },
    )
    git("replace", head, replacement)
    changed = Engine(cfg, index).run()
    assert changed.complete and not changed.stats[0].cached
    assert changed.findings[0].owner == "bob@example.com"


@pytest.mark.parametrize("value", [None, "", "relative/state", "."])
def test_default_state_directory_ignores_empty_or_relative_xdg_state_home(
    tmp_path, monkeypatch, index, value
):
    from shadowscan.incremental import IncrementalCache

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    if value is None:
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    else:
        monkeypatch.setenv("XDG_STATE_HOME", value)
    cache = IncrementalCache(ScanConfig(), index)
    assert cache.directory == tmp_path / "home" / ".local" / "state" / "shadowscan"


@pytest.mark.parametrize("incremental", [True, False])
def test_record_exports_disabling_the_cache_is_announced(tmp_path, caplog, index, incremental):
    from shadowscan.incremental import IncrementalCache

    config = ScanConfig(
        incremental=incremental, dump_records=str(tmp_path / "exports"), state_dir=str(tmp_path)
    )
    with caplog.at_level("WARNING", logger="shadowscan.incremental"):
        assert not IncrementalCache(config, index).enabled
    expected = ["incremental cache not used: record exports (--dump-records) need a full scan"]
    assert [record.getMessage() for record in caplog.records] == (expected if incremental else [])


def test_absolute_xdg_state_home_is_used(tmp_path, monkeypatch, index):
    from shadowscan.incremental import IncrementalCache

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert IncrementalCache(ScanConfig(), index).directory == tmp_path / "state" / "shadowscan"


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_offline_checkout_fingerprint_follows_the_default_excludes_option(tmp_path, index, connector):
    # With default_excludes false the provider scans vendor/, so a change there
    # must miss the cache instead of replaying a complete result without it.
    cfg = config(tmp_path)
    clones = tmp_path / "clones"
    vendored = clones / "acme__repo" / "vendor" / "helper.py"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("print('unrelated')\n")
    options = {"input": str(clones), "use_git": False, "default_excludes": False}
    cfg.connectors = [ConnectorSpec(connector, options)]
    first = Engine(cfg, index).run()
    assert first.complete and not first.findings
    assert Engine(cfg, index).run().stats[0].cached
    vendored.write_text("import langgraph\n")
    changed = Engine(cfg, index).run()
    assert changed.complete and not changed.stats[0].cached
    assert any("framework.langgraph" in f.frameworks for f in changed.findings)


def test_default_excluded_directory_that_gains_a_file_is_disclosed_despite_the_cache(tmp_path, index):
    # The scan warns about a skipped vendor/ that holds files; whether it does
    # is part of the fingerprint, so the warning cannot be lost to a stale entry.
    cfg = config(tmp_path)
    vendored = tmp_path / "repo" / "vendor"
    vendored.mkdir()
    first = Engine(cfg, index).run()
    assert not any("default-excluded" in w for w in first.stats[0].warnings)
    assert Engine(cfg, index).run().stats[0].cached
    (vendored / "agent.py").write_text("import crewai\n")
    changed = Engine(cfg, index).run()
    assert not changed.stats[0].cached
    assert any("default-excluded directories not scanned: vendor" in w for w in changed.stats[0].warnings)
    replayed = Engine(cfg, index).run()
    assert replayed.stats[0].cached
    assert replayed.stats[0].warnings == changed.stats[0].warnings


def test_deeper_default_excluded_probe_cannot_reuse_complete_entry_limited_scan(tmp_path, index):
    cfg = config(tmp_path)
    cfg.connectors[0].config["max_entries"] = 4
    vendored = tmp_path / "repo" / "vendor"
    vendored.mkdir()
    source = vendored / "file.txt"
    source.write_text("ignored source\n")
    first = Engine(cfg, index).run()
    assert first.complete
    assert Engine(cfg, index).run().stats[0].cached

    # Only descendants of the excluded directory change. Its non-empty
    # status stays the same, but finding a file now exceeds max_entries.
    nested = vendored / "a" / "b" / "c"
    nested.mkdir(parents=True)
    source.rename(nested / source.name)
    changed = Engine(cfg, index).run()
    assert not changed.stats[0].cached and not changed.complete
    assert any("max_entries (4)" in issue for issue in changed.stats[0].errors)

    cfg.incremental = False
    full_scan = Engine(cfg, index).run()
    assert full_scan.complete == changed.complete
    assert full_scan.stats[0].errors == changed.stats[0].errors


def test_default_excluded_probe_consumes_the_fingerprint_entry_budget(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    nested = tmp_path / "repo" / "vendor" / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (nested / "file.txt").write_text("ignored source\n")
    monkeypatch.setattr("shadowscan.incremental._MAX_HASH_ENTRIES", 5)
    cache = IncrementalCache(cfg, index)
    assert cache.snapshot(cfg.connectors[0]) is None
