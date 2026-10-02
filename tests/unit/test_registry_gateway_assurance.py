"""A registry match on a log-supplied gateway caller name is flagged, never silently trusted."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry

TAG = "registry-identity-unverified"


def _gateway_finding(assurance: Any, resource: str = "principal:svc-ops") -> Finding:
    observations = [] if assurance is None else [{"identity_assurance": assurance, "events": 1}]
    return Finding(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        title="Agentic caller: svc-ops",
        resource=resource,
        resource_type="caller/principal",
        metadata={"runtime_observations": observations},
    )


def _inventory(resource: str = "principal:svc-ops") -> Inventory:
    return Inventory([InventoryEntry(agent_id="svc-ops-approved", owner="platform", resources=[resource])])


@pytest.mark.parametrize("assurance", ["operator-asserted", "unverified"])
def test_unauthenticated_gateway_caller_match_is_flagged(assurance):
    finding = _gateway_finding(assurance)

    entry = _inventory().match(finding)

    # The documented match semantics are unchanged: the entry still matches ...
    assert entry is not None and entry.agent_id == "svc-ops-approved"
    # ... but the report says the caller name behind it was never authenticated.
    assert finding.metadata["registry_match_assurance"] == assurance
    assert TAG in finding.tags


def test_weakest_observation_assurance_is_reported():
    finding = _gateway_finding("provider-authenticated-field")
    finding.metadata["runtime_observations"].append({"identity_assurance": "operator-asserted"})

    assert _inventory().match(finding) is not None
    assert finding.metadata["registry_match_assurance"] == "operator-asserted"


@pytest.mark.parametrize("observations", [None, [], "garbage", [{"events": 1}], [{"identity_assurance": 7}]])
def test_missing_or_malformed_assurance_counts_as_unverified(observations):
    finding = _gateway_finding(None)
    finding.metadata["runtime_observations"] = observations

    assert _inventory().match(finding) is not None
    assert finding.metadata["registry_match_assurance"] == "unverified"


def test_provider_authenticated_caller_is_not_flagged():
    finding = _gateway_finding("provider-authenticated-field")

    assert _inventory().match(finding) is not None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_non_gateway_findings_are_not_flagged():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="Agent",
        resource="github:acme/ops",
        resource_type="repository",
    )

    assert _inventory("github:acme/ops").match(finding) is not None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_marker_is_cleared_when_a_later_match_no_longer_qualifies():
    finding = _gateway_finding("operator-asserted")
    assert _inventory().match(finding) is not None and TAG in finding.tags

    # Reconciling the same object again must not keep a stale marker.
    assert _inventory("principal:other").match(finding) is None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_unmatched_gateway_finding_stays_shadow_and_unmarked():
    finding = _gateway_finding("operator-asserted", resource="principal:rogue")

    assert _inventory().match(finding) is None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_cli_gateway_scan_flags_the_spoofed_caller_name(tmp_path: Path):
    log = tmp_path / "gateway.jsonl"
    log.write_text(
        json.dumps(
            {
                "service": "svc-ops",
                "user_agent": "autogen/0.4",
                "model": "gpt-4o",
                "timestamp": "2026-09-22T10:00:00Z",
                "tools": [{"name": "shell"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "agents:\n  - id: svc-ops-approved\n    owner: platform\n    resources: ['principal:svc-ops']\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    result = CliRunner().invoke(
        main, ["gateway", str(log), "-i", str(inventory), "-f", "json", "-o", str(out)]
    )

    assert result.exit_code == 0, result.output
    finding = json.loads(out.read_text(encoding="utf-8"))["findings"][0]
    assert finding["resource"] == "principal:svc-ops"
    assert finding["registry_match"] == "svc-ops-approved" and finding["shadow"] is False
    assert finding["metadata"]["registry_match_assurance"] == "operator-asserted"
    assert TAG in finding["tags"]
