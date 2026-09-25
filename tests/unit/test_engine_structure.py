"""Engine decomposition seams, single-load preparation and verified-clean sanitization."""

from __future__ import annotations

import inspect
import os
import re
import shutil
from copy import deepcopy
from dataclasses import fields
from threading import Event

import pytest
import regex

import shadowscan.engine as engine_module
import shadowscan.models as models
import shadowscan.utils.redaction as redaction
from shadowscan.comparison import _scanner_digest
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine, _ExportLedger, _JobState, _retain_sanitizable
from shadowscan.incremental import IncrementalCache
from shadowscan.models import (
    Evidence,
    Finding,
    Kind,
    Risk,
    RiskFactor,
    ScanResult,
    ScanStats,
    Surface,
    now_iso,
)
from shadowscan.registry import Inventory, InventoryValidationError
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import Signal, signature_from_dict, signature_source_digest
from shadowscan.utils.digest import scanner_source_digest
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError

SECRET = "sk-proj-" + "a" * 40
PACK = "id: org.example\nname: Example\ncategory: framework\nsignals:\n  - type: dependency\n    ecosystem: pypi\n    names: [{name}]\n"


def _finding(**kwargs) -> Finding:
    base = dict(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT, title="Agent",
                resource="repo/agent", resource_type="repository",
                evidence=[Evidence("signal", "clean", snippet="ordinary", attributes={"label": "x"})],
                metadata={"nested": {"key": "value"}, "names": ["a"]})
    base.update(kwargs)
    return Finding(**base)


@pytest.fixture
def sanitizer_calls(monkeypatch):
    """Count full passes through the redaction sanitizer made by Finding and Evidence."""
    calls = []
    original = models.sanitize

    def counting(value, **kwargs):
        if inspect.currentframe().f_back.f_code.co_name == "sanitize":
            calls.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(models, "sanitize", counting)
    return calls


class _Connector:
    """A connector stub returning one finding per configured label."""

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        self.ctx.stats = ScanStats(connector="stub", started_at=now_iso(), finished_at=now_iso())
        label = self.ctx.config.get("label", "stub")
        return [Finding(Surface.CODE, "code.filesystem", Kind.AGENT, label, label, "agent")]


# ----------------------------------------------------------- clean state


def test_unmutated_finding_is_not_reprocessed(sanitizer_calls):
    finding = _finding()
    assert finding._clean_digest is not None
    baseline = len(sanitizer_calls)
    for _ in range(3):
        finding.sanitize()
    report = ScanResult(findings=[finding])
    report.summary()
    serialized = report.to_json()
    assert len(sanitizer_calls) == baseline
    assert "_clean_digest" not in serialized and REDACTED not in serialized


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda f: setattr(f, "title", f"leaked {SECRET}"), id="attribute"),
    pytest.param(lambda f: f.metadata.__setitem__("note", f"Authorization: Bearer {SECRET}"), id="metadata-in-place"),
    pytest.param(lambda f: f.metadata["nested"].__setitem__("api_key", SECRET), id="nested-metadata"),
    pytest.param(lambda f: f.metadata["names"].append(SECRET), id="metadata-list-append"),
    pytest.param(lambda f: f.update_metadata(password=SECRET), id="update_metadata"),
    pytest.param(lambda f: setattr(f.evidence[0], "snippet", f"key = '{SECRET}'"), id="evidence-attribute"),
    pytest.param(lambda f: f.evidence[0].attributes.__setitem__("token", SECRET), id="evidence-attributes"),
    pytest.param(lambda f: f.tags.append(SECRET), id="tags-in-place"),
    pytest.param(lambda f: f.add_tag(SECRET), id="add_tag"),
    pytest.param(lambda f: setattr(f, "risk", Risk(factors=[RiskFactor("factor", SECRET, 1)])), id="risk"),
    pytest.param(lambda f: f.permissions.append(f"Bearer {SECRET}"), id="permissions-in-place"),
])
def test_every_mutation_path_is_resanitized(sanitizer_calls, mutate):
    finding = _finding()
    finding.sanitize()
    baseline = len(sanitizer_calls)
    mutate(finding)
    finding.sanitize()
    assert len(sanitizer_calls) == baseline + 1
    assert SECRET not in ScanResult(findings=[finding]).to_json()
    # The marker is restored, so the next pass is a no-op again.
    after = len(sanitizer_calls)
    finding.sanitize()
    assert len(sanitizer_calls) == after


def test_add_evidence_sanitizes_only_new_evidence_and_dirties_the_finding(sanitizer_calls):
    finding = _finding()
    baseline = len(sanitizer_calls)
    evidence = Evidence("signal", f"copied {SECRET}")  # constructor pass
    assert len(sanitizer_calls) == baseline + 1 and SECRET not in evidence.description
    finding.add_evidence(evidence)
    assert len(sanitizer_calls) == baseline + 1  # verified clean: no second pass
    assert finding._clean_digest is None
    finding.sanitize()
    assert len(sanitizer_calls) == baseline + 2


def test_reassigning_the_same_object_keeps_the_finding_clean(sanitizer_calls):
    finding = _finding()
    baseline = len(sanitizer_calls)
    finding.connector = finding.connector
    finding.metadata = finding.metadata
    assert finding._clean_digest is not None
    finding.sanitize()
    assert len(sanitizer_calls) == baseline


def test_redaction_policy_change_invalidates_verified_clean_state(sanitizer_calls, monkeypatch):
    finding = _finding(metadata={"new_secret_format": "opaque-secret-value"})
    finding.sanitize()
    baseline = len(sanitizer_calls)
    before = redaction.policy_token()
    monkeypatch.setattr(redaction, "_SENSITIVE_NAMES", redaction._SENSITIVE_NAMES | {"newsecretformat"})
    assert redaction.policy_token() != before
    finding.sanitize()
    assert len(sanitizer_calls) == baseline + 1
    assert finding.metadata["new_secret_format"] == REDACTED


def test_clean_marker_is_private_process_state():
    finding = _finding()
    data = finding.to_dict()
    assert "_clean_digest" not in data and "_clean_digest" not in data["evidence"][0]
    assert "_clean_digest" not in {attr.name for attr in fields(Finding) if attr.init}
    with pytest.raises(TypeError):
        Evidence("signal", "description", _clean_digest="forged")  # type: ignore[call-arg]
    restored = Finding.from_dict({**data, "_clean_digest": "forged",
                                  "evidence": [{**data["evidence"][0], "_clean_digest": "forged"}]})
    assert restored.id == finding.id and restored == finding
    copied = deepcopy(finding)
    assert copied == finding and copied._clean_digest == finding._clean_digest


def test_clean_check_bounds_alias_graphs_before_digesting():
    finding = _finding()
    value = {"label": "ordinary"}
    for _ in range(12):
        value = {"children": [value] * 10}
    finding.metadata["graph"] = value
    with pytest.raises(SanitizationLimitError, match="expanded output"):
        finding.sanitize()
    assert finding._clean_digest is None


def test_failed_sanitization_never_leaves_a_clean_marker():
    finding = _finding()
    finding.resource = f"repo/{SECRET}"
    with pytest.raises(SanitizationLimitError, match="identity"):
        finding.sanitize()
    assert finding._clean_digest is None


def test_undigestable_state_falls_back_to_full_passes(sanitizer_calls, monkeypatch):
    assert models._clean_state([{(1, 2): "tuple keys have no JSON form"}], bounded=True) is None
    finding = _finding()
    monkeypatch.setattr(models, "_clean_state", lambda state, *, bounded: None)
    finding.sanitize()
    assert finding._clean_digest is None
    baseline = len(sanitizer_calls)
    finding.sanitize()
    assert len(sanitizer_calls) == baseline + 1


# ------------------------------------------------------------ preparation


def test_signature_index_and_inventory_load_once_per_lifecycle(monkeypatch, tmp_path):
    index_loads = []
    inventory_loads = []
    monkeypatch.setattr(engine_module, "get_index", lambda **kwargs: index_loads.append(kwargs) or SignatureIndex([]))

    class CountingInventory(Inventory):
        @classmethod
        def load(cls, paths):
            inventory_loads.append(list(paths))
            return Inventory.load(paths)

    monkeypatch.setattr(engine_module, "Inventory", CountingInventory)
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _Connector)
    inventory = tmp_path / "agents.yaml"
    inventory.write_text("agents:\n  - id: agent\n    owner: team\n    resources: ['repo/agent']\n")
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem")], inventory=[str(inventory)])
    engine = Engine(cfg)
    assert len(index_loads) == 1 and len(inventory_loads) == 1
    first = engine.run()
    assert first.complete and first.inventory_size == 1
    assert len(index_loads) == 1 and len(inventory_loads) == 1
    # Approval can change independently of the Engine; a reused Engine reads it again.
    second = engine.run()
    assert second.complete and len(index_loads) == 1 and len(inventory_loads) == 2


def test_reused_engine_reloads_index_only_when_pack_sources_change(monkeypatch, tmp_path):
    loads = []
    monkeypatch.setattr(engine_module, "get_index", lambda **kwargs: loads.append(kwargs) or SignatureIndex([]))
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _Connector)
    extra = tmp_path / "signatures"
    extra.mkdir()
    pack = extra / "org.yaml"
    pack.write_text(PACK.format(name="one"))
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem")], signature_dirs=[str(extra)])
    engine = Engine(cfg)
    engine.run()
    assert len(loads) == 1
    pack.write_text(PACK.format(name="two"))
    engine.run()
    assert len(loads) == 2 and loads[-1]["extra_dirs"] == [str(extra)]
    engine.run()
    assert len(loads) == 2
    # Turning override approval on changes what the loader would accept.
    cfg.allow_signature_override = True
    engine.run()
    assert len(loads) == 3 and loads[-1]["allow_override"] is True
    engine.run()
    assert len(loads) == 3
    # A pack that can no longer be digested is reloaded, so the loader reports it.
    shutil.rmtree(extra)
    engine.run()
    assert len(loads) == 4


def test_supplied_index_is_never_reloaded(monkeypatch):
    monkeypatch.setattr(engine_module, "get_index", lambda **kwargs: pytest.fail("supplied index must be kept"))
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _Connector)
    index = SignatureIndex([])
    engine = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem")]), index)
    engine.run()
    engine.run()
    assert engine.index is index


def test_security_options_validate_once_unless_the_config_changes(monkeypatch):
    calls = []
    original = ScanConfig.validate_security_options

    def counting(self):
        calls.append(self)
        return original(self)

    monkeypatch.setattr(ScanConfig, "validate_security_options", counting)
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _Connector)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem")])
    assert len(calls) == 1  # ScanConfig.__post_init__
    engine = Engine(cfg, SignatureIndex([]))
    assert len(calls) == 2
    assert engine.run().complete and engine.run().complete
    assert len(calls) == 2
    cfg.allow_private_origin = "yes"
    with pytest.raises(ValueError, match="allow_private_origin"):
        engine.run()
    assert len(calls) == 3
    cfg.allow_private_origin = True
    assert engine.run().complete and len(calls) == 4


def test_invalid_inventory_still_fails_at_construction(tmp_path):
    inventory = tmp_path / "agents.yaml"
    inventory.write_text("agents:\n  - id: agent\n    resources: 'not-a-list'\n")
    with pytest.raises(InventoryValidationError, match="resources"):
        Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem")], inventory=[str(inventory)]), SignatureIndex([]))


# ------------------------------------------------------------------ seams


def test_selection_seams(monkeypatch):
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", label="a"), ConnectorSpec("code.filesystem", label="b"),
                                 ConnectorSpec("cloud.aws", enabled=False)])
    engine = Engine(cfg, SignatureIndex([]))
    assert engine._invalid_selectors(None) == []
    assert engine._invalid_selectors(["code.filesystem", "cloud.aws", "typo"]) == ["cloud.aws", "typo"]
    assert [number for number, _ in engine._select_jobs(None)] == [1, 2]
    assert [spec.label for _, spec in engine._select_jobs(["b"])] == ["b"]
    assert [spec.label for _, spec in engine._select_jobs(["code.filesystem"])] == ["a", "b"]
    rejected = Engine._reject_selection(ScanResult(), ["typo"])
    assert rejected.collection_scope == {"schema": "shadowscan.collection-scope/v1", "comparable": False,
                                         "reason": "requested connectors are unknown or disabled"}
    assert not rejected.complete and rejected.stats[0].connector == "engine.selection"
    assert Engine._selection_stats([ConnectorSpec("code.filesystem")]) == []
    empty = Engine._selection_stats([])
    assert len(empty) == 1 and empty[0].incomplete and empty[0].skip_reason == "no connectors selected"


def test_export_ledger_drops_cancelled_and_timed_out_entries():
    ledger = _ExportLedger()
    live, cancelled = _JobState(), _JobState(cancelled=Event())
    cancelled.cancelled.set()
    jobs = [(1, ConnectorSpec("cloud.aws", label="one")), (2, ConnectorSpec("cloud.aws", label="two"))]
    ledger.record(live, {"config_ordinal": 1, "part": "0001", "connector": "cloud.aws", "label": "one",
                         "filename": "0001-cloud_aws.jsonl", "complete": True, "exported": True})
    ledger.record(cancelled, {"config_ordinal": 2, "part": "0002", "connector": "cloud.aws", "label": "two",
                              "filename": "0002-cloud_aws.jsonl", "complete": True, "exported": True})
    ledger.record(live, {"config_ordinal": 2, "part": "0002", "connector": "cloud.aws", "label": "two",
                         "filename": "stale.jsonl", "complete": True, "exported": True})
    entries = ledger.entries(jobs, timed_out={2})
    assert [entry["part"] for entry in entries] == ["0001", "0002"]
    assert entries[0]["exported"] is True
    assert entries[1] == {"config_ordinal": 2, "part": "0002", "connector": "cloud.aws", "label": "two",
                          "filename": None, "complete": False, "exported": False}


def test_retain_sanitizable_counts_omissions_without_losing_neighbors():
    safe, unsafe = _finding(resource="safe"), _finding(resource="unsafe")
    unsafe.metadata["big"] = [0] * 100_001
    retained, omitted = _retain_sanitizable([safe, unsafe])
    assert retained == [safe] and omitted == 1


def test_postprocess_reports_runtime_and_omission_errors_in_order(monkeypatch, index):
    def over_budget(findings):
        raise SanitizationLimitError("bounded failure")

    monkeypatch.setattr(engine_module, "correlate_runtime", over_budget)
    engine = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem")]), index)
    unsafe = _finding(resource="unsafe")
    unsafe.metadata["big"] = [0] * 100_001
    findings, errors = engine._postprocess([_finding(resource="safe"), unsafe])
    assert [finding.resource for finding in findings] == ["safe"]
    assert findings[0].risk.score > 0 and findings[0].shadow is None
    assert errors == ["runtime correlation incomplete: sanitization safety limit exceeded",
                      "1 finding(s) omitted after aggregation: sanitization safety limit exceeded"]


def test_run_keeps_configured_order_and_finishes_incomplete_results(monkeypatch):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _Connector)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", label=label) for label in ("z", "a")], parallel=2)
    result = Engine(cfg, SignatureIndex([])).run()
    assert result.complete and result.finished_at is not None
    assert [stat.connector for stat in result.stats] == ["a", "z"]
    assert {finding.resource for finding in result.findings} == {"a", "z"}


# ---------------------------------------------------------------- digests


def test_scanner_digest_is_shared_by_comparison_and_incremental_cache(tmp_path):
    digest = scanner_source_digest()
    assert re.fullmatch(r"[0-9a-f]{64}", digest) and digest == scanner_source_digest() == _scanner_digest()
    if os.name != "posix":
        pytest.skip("incremental state requires POSIX flock")
    cache = IncrementalCache(ScanConfig(incremental=True, state_dir=str(tmp_path / "state")), SignatureIndex([]))
    assert cache.enabled and cache.scanner_digest == digest


def test_scanner_digest_covers_python_sources_by_content_and_path(tmp_path):
    package = tmp_path / "pkg"
    (package / "sub").mkdir(parents=True)
    (package / "a.py").write_text("x = 1\n")
    (package / "sub" / "b.py").write_text("y = 2\n")
    (package / "notes.txt").write_text("ignored\n")
    first = scanner_source_digest(package)
    assert first == scanner_source_digest(package)
    (package / "notes.txt").write_text("still ignored\n")
    assert scanner_source_digest(package) == first
    (package / "sub" / "b.py").write_text("y = 3\n")
    second = scanner_source_digest(package)
    assert second != first
    (package / "c.py").write_text("")
    assert scanner_source_digest(package) not in {first, second}


def test_signature_source_digest_tracks_pack_content_and_approval(tmp_path):
    extra = tmp_path / "signatures"
    extra.mkdir()
    pack = extra / "org.yaml"
    pack.write_text(PACK.format(name="one"))
    digest = signature_source_digest([extra], include_builtin=False)
    assert digest == signature_source_digest([str(extra)], include_builtin=False)
    assert digest != signature_source_digest([extra], include_builtin=False, allow_override=True)
    assert digest != signature_source_digest([extra])
    pack.write_text(PACK.format(name="two"))
    assert digest != signature_source_digest([extra], include_builtin=False)
    (extra / "second.yaml").write_text(PACK.format(name="one").replace("org.example", "org.second"))
    assert signature_source_digest([extra], include_builtin=False) != digest
    assert signature_source_digest() == signature_source_digest()
    with pytest.raises(FileNotFoundError):
        signature_source_digest([tmp_path / "missing"], include_builtin=False)
    with pytest.raises(ValueError, match="boolean"):
        signature_source_digest([extra], include_builtin=False, allow_override="yes")  # type: ignore[arg-type]


def test_signal_compiled_view_is_lazy_and_outside_the_fingerprint():
    signature = signature_from_dict({"id": "org.example", "category": "framework",
                                     "signals": [{"type": "import", "patterns": [r"^import example\b"]}]})
    signal = signature.signals[0]
    assert "compiled" not in {attr.name for attr in fields(Signal)}
    fingerprint = SignatureIndex([signature]).fingerprint()
    assert len(signal.bounded_compiled) == 1 and isinstance(signal.bounded_compiled[0], regex.Pattern)
    assert all(isinstance(rx, re.Pattern) for rx in signal.compiled) and len(signal.compiled) == 1
    assert SignatureIndex([signature]).fingerprint() == fingerprint
    with pytest.raises(ValueError, match="invalid regex"):
        signature_from_dict({"id": "org.broken", "category": "framework",
                             "signals": [{"type": "import", "patterns": ["("]}]})
    with pytest.raises(ValueError, match="invalid domain regex"):
        signature_from_dict({"id": "org.broken", "category": "provider",
                             "signals": [{"type": "domain", "values": ["re:("]}]})
