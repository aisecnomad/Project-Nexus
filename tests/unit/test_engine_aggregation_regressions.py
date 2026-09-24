"""Aggregation must be deterministic, idempotent and safe for large exports."""

from __future__ import annotations

from concurrent.futures import wait
from copy import deepcopy

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine, merge
from shadowscan.models import Evidence, Finding, Kind, Surface


def finding(**values):
    return Finding(
        surface=values.pop("surface", Surface.CODE), connector="test.aggregate",
        kind=Kind.AGENT, title="Same workload", resource="repo:shared",
        resource_type="repository", **values,
    )


def test_duplicate_evidence_in_merged_input_does_not_inflate_confidence():
    first = finding(evidence=[Evidence("first", "first signal", weight=0.5)])
    duplicate = Evidence("second", "same observation", location="main.py:1", weight=0.5)
    second = finding(evidence=[duplicate, deepcopy(duplicate)])
    result = merge([first, second])[0]
    assert len(result.evidence) == 2
    assert result.confidence == 0.75


def test_parallel_completion_order_does_not_select_owner_or_metadata(monkeypatch, index):
    class Probe(BaseConnector):
        name = "test.aggregate"

        def collect(self):
            yield {}

        def analyze(self, records):
            yield finding(owner=self.ctx.config["owner"], metadata={"source": self.ctx.config["owner"]})

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: Probe)
    # Force completion iteration opposite to configured precedence, independent
    # of machine timing. All submitted futures still execute normally.
    class ReversedCompleted(set):
        def __iter__(self):
            return iter(sorted(super().__iter__(), key=lambda future: future.result()[0].config["owner"], reverse=True))

    def reverse_completed(futures, **kwargs):
        completed, pending = wait(futures)
        return ReversedCompleted(completed), pending

    monkeypatch.setattr("shadowscan.engine.wait", reverse_completed)
    specs = [ConnectorSpec("test.aggregate", {"owner": owner}) for owner in ("first", "second")]
    serial = Engine(ScanConfig(connectors=specs, parallel=1), index).run()
    parallel = Engine(ScanConfig(connectors=specs, parallel=2), index).run()
    assert serial.complete and parallel.complete
    assert serial.findings[0].owner == parallel.findings[0].owner == "first"
    assert serial.findings[0].to_dict() == parallel.findings[0].to_dict()


def test_large_gateway_observation_merge_is_idempotent_and_preserves_sources():
    observations = [{"scope": {"tenant": str(i)}, "timestamped_events": 1} for i in range(1500)]
    first = finding(surface=Surface.GATEWAY, metadata={
        "runtime_source": {"input": "a.jsonl"}, "runtime_observations": observations,
    })
    same = deepcopy(first)
    other = deepcopy(first)
    other.metadata["runtime_source"] = {"input": "b.jsonl"}
    # Numeric JSON values compare equally even if exporters vary number syntax.
    for observation in same.metadata["runtime_observations"]:
        observation["timestamped_events"] = 1.0
    result = merge([first, same, other])[0]
    merged = result.metadata["runtime_observations"]
    assert len(merged) == 3000
    assert sum(item["source"]["input"] == "a.jsonl" for item in merged) == 1500
    assert sum(item["source"]["input"] == "b.jsonl" for item in merged) == 1500

