from __future__ import annotations

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import Engine
from shadowscan.incremental import IncrementalCache, Snapshot
from shadowscan.models import Finding, Kind, ScanStats, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict


def config(tmp_path: Path, **overrides) -> ScanConfig:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "requirements.txt").write_text("langchain\n")
    values = dict(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False})],
        incremental=True, state_dir=str(tmp_path / "state"), parallel=1,
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
    signature = signature_from_dict({
        "id": "framework.example", "name": "Example", "category": "framework",
        "signals": [{"type": "dependency", "ecosystem": "pypi", "names": ["example"]}],
    })
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
    cfg.connectors[0].config["token"] = "t1"
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
    replacement = signature_from_dict({
        "id": "framework.test", "name": "Test", "category": "framework",
        "signals": [{"type": "dependency", "ecosystem": "pypi", "names": ["langchain"]}],
    })
    changed = Engine(cfg, SignatureIndex([replacement])).run()
    assert not changed.stats[0].cached
    assert any("framework.test" in f.frameworks for f in changed.findings)
    assert len(calls) == 3


def test_inventory_and_confidence_are_reapplied_even_with_same_engine(tmp_path, index):
    cfg = config(tmp_path)
    first = Engine(cfg, index).run()
    resource = first.findings[0].resource
    inventory = tmp_path / "agents.json"
    inventory.write_text(json.dumps({"agents": [{"id": "approved", "resources": [resource], "owner": "first-owner"}]}))
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


@pytest.mark.parametrize("damage", ["garbage", "missing", "unsafe_permissions", "payload_modified", "deep_json"])
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
    else:
        entry.write_text("invalid json")
    result = Engine(cfg, index).run()
    assert result.findings and result.complete and not result.stats[0].cached
    assert len(calls) == 2


def test_concurrent_cache_writers_publish_only_complete_matching_entries(tmp_path, index):
    cfg = config(tmp_path)
    cache = IncrementalCache(cfg, index)
    assert cache.enabled

    def write_and_read(writer):
        snapshot = Snapshot(slot="a" * 64, fingerprint=f"writer-{writer}")
        item = Finding(Surface.CODE, "code.filesystem", Kind.AGENT,
                       f"Writer {writer}", f"repo:{writer}", "repository")
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


def test_cache_is_private_sanitized_and_never_written_inside_repository(tmp_path, index):
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


def test_static_cloud_exports_reused_and_updated(tmp_path, index, fixtures):
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
    override.write_text("id: framework.langchain\nname: LangChain\ncategory: framework\nsignals:\n  - type: dependency\n    ecosystem: pypi\n    names: [langchain]\n")
    engine = Engine(cfg)
    first = engine.run()
    assert first.complete and any("framework.langchain" in f.frameworks for f in first.findings)
    override.write_text("id: framework.langchain\nname: LangChain\ncategory: framework\nsignals:\n  - type: dependency\n    ecosystem: pypi\n    names: [unrelated]\n")
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
    cfg = ScanConfig.from_dict({"options": {"incremental": True, "state_dir": "state"}}, source=str(tmp_path / "config.yaml"))
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


@pytest.mark.parametrize("limit", ["_MAX_HASH_BYTES", "_MAX_HASH_ENTRIES", "_MAX_HASH_SECONDS"])
def test_fingerprint_work_limits_fall_back_to_full_scan(tmp_path, index, monkeypatch, limit):
    cfg = config(tmp_path)
    monkeypatch.setattr(f"shadowscan.incremental.{limit}", 0)
    result = Engine(cfg, index).run()
    assert result.complete and result.findings and not result.stats[0].cached
    assert not list((tmp_path / "state").glob("*.json"))


def test_plugin_overriding_builtin_name_is_not_cached(tmp_path, index, monkeypatch):
    cfg = config(tmp_path)
    runs = []

    class Plugin(BaseConnector):
        def collect(self):
            yield {}

        def analyze(self, records):
            runs.append(1)
            yield Finding(Surface.CODE, "code.filesystem", Kind.AGENT, "Plugin", f"run:{len(runs)}", "repository")

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
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

    git("init")
    git("config", "user.name", "Alice")
    git("config", "user.email", "alice@example.com")
    git("add", "requirements.txt")
    git("commit", "-m", "initial")
    first = Engine(cfg, index).run()
    assert first.complete and first.findings[0].owner == "alice@example.com"
    assert Engine(cfg, index).run().stats[0].cached
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    replacement = git("commit-tree", tree, "-m", "replacement", env={
        **os.environ, "GIT_AUTHOR_NAME": "Bob", "GIT_AUTHOR_EMAIL": "bob@example.com",
    })
    git("replace", head, replacement)
    changed = Engine(cfg, index).run()
    assert changed.complete and not changed.stats[0].cached
    assert changed.findings[0].owner == "bob@example.com"
