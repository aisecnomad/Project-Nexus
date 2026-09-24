"""An inventory approval must bind to a complete, unambiguous resource ID."""

from __future__ import annotations

import json

import pytest
import yaml

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import (
    Inventory,
    InventoryEntry,
    InventoryValidationError,
    _strip_cite_markers,
    card_stub_for,
)
from shadowscan.utils.identity import has_aws_account_scope
from shadowscan.utils.redaction import REDACTED


def _finding(resource: str, **kwargs: object) -> Finding:
    return Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Agent", resource=resource, resource_type="repository", **kwargs,
    )


def test_distinct_redacted_repository_ids_cannot_approve_each_other_via_generated_card(tmp_path):
    first = _finding("github:org/ghp_AAAAAAAAAAAAAAAA")
    second = _finding("github:org/ghp_BBBBBBBBBBBBBBBB")
    assert first.id != second.id
    assert first.resource == second.resource == f"github:org/{REDACTED}"

    stub = card_stub_for(first)
    assert stub["discovery"]["resources"] == []
    path = tmp_path / "generated.yaml"
    path.write_text(yaml.safe_dump(stub))
    registry = Inventory.load([path])
    for finding in (first, second, Finding.from_dict(second.to_dict())):
        assert registry.match(finding) is None
        assert finding.metadata["registry_match_reason"] == "redacted-or-missing-resource-identity"


def test_exact_or_wildcard_approval_cannot_register_redacted_resource():
    finding = _finding("github:org/ghp_AAAAAAAAAAAAAAAA")
    # The escaped pattern is what older generated cards used to write; it
    # matches the placeholder byte-for-byte under fnmatchcase.
    for pattern in ("github:org/[[]REDACTED]", finding.resource, "github:org/*", "*"):
        registry = Inventory([InventoryEntry(agent_id="approved", resources=[pattern])])
        assert registry.match(finding) is None
        assert finding.metadata["registry_match_reason"] == "redacted-or-missing-resource-identity"

    # Sibling evidence can redact an otherwise unremarkable ID too.
    opaque = "private-opaque-repository-name"
    sibling = _finding(f"github:org/{opaque}", metadata={"token": opaque})
    assert sibling.resource == f"github:org/{REDACTED}"
    assert registry.match(sibling) is None


@pytest.mark.parametrize("field", ["account", "provider", "region"])
def test_redacted_identity_scope_cannot_approve_same_resource_across_distinct_scopes(tmp_path, field):
    first = _finding("github:org/stable-repository", **{field: "ghp_AAAAAAAAAAAAAAAA"})
    second = _finding("github:org/stable-repository", **{field: "ghp_BBBBBBBBBBBBBBBB"})
    assert first.resource == second.resource == "github:org/stable-repository"
    assert getattr(first, field) == getattr(second, field) == REDACTED

    generated = card_stub_for(first)
    assert generated["discovery"]["resources"] == []
    path = tmp_path / "generated.yaml"
    path.write_text(yaml.safe_dump(generated))
    approved = Inventory.load([path])

    # A historical card with the resource filled in and either an explicit
    # placeholder scope or no scope at all must also fail closed.
    scopes = {"accounts": [REDACTED]} if field == "account" else (
        {"providers": [REDACTED]} if field == "provider" else {}
    )
    historical = Inventory([InventoryEntry(agent_id="approved", resources=[first.resource], **scopes)])
    unscoped = Inventory([InventoryEntry(agent_id="unscoped", resources=[first.resource])])
    for finding in (first, second, Finding.from_dict(second.to_dict())):
        for inventory in (approved, historical, unscoped):
            assert inventory.match(finding) is None
            assert finding.metadata["registry_match_reason"] == "redacted-scope-identity"


def test_safe_exact_and_deliberate_wildcard_approvals_still_work(tmp_path):
    safe = _finding("github:org/team-agent")
    path = tmp_path / "generated.yaml"
    path.write_text(yaml.safe_dump(card_stub_for(safe)))
    registered = Inventory.load([path])
    assert registered.match(safe).agent_id
    assert registered.match(_finding("github:org/another-agent")) is None

    broad = Inventory([InventoryEntry(agent_id="approved", resources=["github:org/*"])])
    assert broad.match(safe).agent_id == "approved"
    assert broad.match(_finding("")) is None


def test_bedrock_fallback_agent_id_card_registers_only_its_region(tmp_path, index):
    source = tmp_path / "bedrock.jsonl"
    records = [
        {"_kind": "bedrock-agent", "agentId": "ABC123DEF0", "agentName": "Same fallback ID",
         "_region": region, "agentStatus": "PREPARED"}
        for region in ("us-east-1", "eu-west-1")
    ]
    source.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    connector = ConnectorSpec(name="cloud.aws", config={"input": str(source), "account_id": "123456789012"})
    discovered = Engine(ScanConfig(connectors=[connector]), index).run()
    assert discovered.complete and len(discovered.findings) == 2
    regions = {item.region: item for item in discovered.findings}
    assert set(regions) == {"us-east-1", "eu-west-1"}
    east, west = regions["us-east-1"], regions["eu-west-1"]
    assert east.resource == west.resource == "ABC123DEF0"
    assert east.account == west.account == "123456789012" and east.provider == west.provider == "aws"
    assert east.id != west.id

    card = card_stub_for(east)
    assert card["discovery"]["resources"] == ["ABC123DEF0"]
    assert card["discovery"]["regions"] == ["us-east-1"]
    path = tmp_path / "approved.yaml"
    path.write_text(yaml.safe_dump(card))
    inventory = Inventory.load([path])
    assert inventory.match(east) is not None
    assert inventory.match(west) is None
    missing_region = Finding.from_dict(west.to_dict())
    missing_region.region = None
    assert inventory.match(missing_region) is None

    reconciled = Engine(ScanConfig(connectors=[connector], inventory=[str(path)]), index).run()
    assert reconciled.complete and len(reconciled.findings) == 2
    by_region = {finding.region: finding for finding in reconciled.findings}
    assert by_region["us-east-1"].shadow is False
    assert by_region["eu-west-1"].shadow is True
    assert by_region["eu-west-1"].registry_match is None


def test_short_aws_id_without_account_cannot_approve_or_claim_complete(tmp_path, index):
    specs = []
    for name in ("first", "second"):
        source = tmp_path / f"{name}.json"
        source.write_text(json.dumps([{
            "_kind": "bedrock-agent", "agentId": "ABC123DEF0", "agentName": name,
            "_region": "us-east-1", "agentStatus": "PREPARED",
        }]))
        specs.append(ConnectorSpec("cloud.aws", {"input": str(source)}))

    first, second = (
        Engine(ScanConfig(connectors=[spec]), index).run() for spec in specs
    )
    for result in (first, second):
        assert not result.complete
        assert any("resource lacks account scope" in warning for stat in result.stats for warning in stat.warnings)
        assert len(result.findings) == 1
        assert result.findings[0].account is None
        assert card_stub_for(result.findings[0])["discovery"]["resources"] == []

    candidate = second.findings[0]
    for resource_pattern in ("ABC123DEF0", "*"):
        inventory = Inventory([InventoryEntry(agent_id="approved", resources=[resource_pattern])])
        assert inventory.match(candidate) is None
        assert candidate.metadata["registry_match_reason"] == "missing-aws-account-scope"

    # Both accountless IDs collide, so this aggregation must never be a valid
    # baseline or make an absence claim about either source.
    combined = Engine(ScanConfig(connectors=specs), index).run()
    assert not combined.complete
    assert all(stat.incomplete for stat in combined.stats)

    scoped = Engine(ScanConfig(connectors=[ConnectorSpec(
        "cloud.aws", {**specs[0].config, "account_id": "123456789012"},
    )]), index).run()
    assert scoped.complete
    assert card_stub_for(scoped.findings[0])["discovery"]["accounts"] == ["123456789012"]


@pytest.mark.parametrize("account,resource,expected", [
    (None, "ABC123DEF0", False),
    ("unknown", "ABC123DEF0", False),
    (REDACTED, "ABC123DEF0", False),
    ("123", "ABC123DEF0", False),
    ("123456789012", "ABC123DEF0", True),
    (None, "arn:aws:bedrock:us-east-1:123456789012:agent/ABC123DEF0", True),
    (None, "cloudtrail:arn:aws:sts::123456789012:assumed-role/agent/session", True),
    (None, "evil:arn:aws:bedrock:us-east-1:123456789012:agent/ABC123DEF0", False),
    (None, "arn:aws:bedrock:us-east-1:123:agent/ABC123DEF0", False),
    ("unknown", "arn:aws:bedrock:us-east-1:123456789012:agent/ABC123DEF0", False),
    ("999999999999", "arn:aws:bedrock:us-east-1:123456789012:agent/ABC123DEF0", False),
    ("123456789012", "arn:aws:bedrock:us-east-1:123456789012:agent/ABC123DEF0", True),
])
def test_aws_account_scope_requires_valid_consistent_identity(account, resource, expected):
    assert has_aws_account_scope("aws", account, resource) is expected
    finding = Finding(
        Surface.CLOUD, "cloud.aws", Kind.AGENT, "Bedrock agent", resource,
        "bedrock-agent", provider="aws", account=account,
    )
    inventory = Inventory([InventoryEntry(agent_id="approved", resources=["*"])])
    assert (inventory.match(finding) is not None) is expected
    assert bool(card_stub_for(finding)["discovery"]["resources"]) is expected


@pytest.mark.parametrize("suffix", ["yaml", "json", "csv"])
def test_simple_inventories_enforce_regions_across_formats(tmp_path, suffix):
    item = {"id": "approved", "resources": ["shared-id"], "regions": ["us-east-1", "us-west-2"]}
    path = tmp_path / f"inventory.{suffix}"
    if suffix == "csv":
        path.write_text("id,resources,regions\napproved,shared-id,us-east-1|us-west-2\n")
    else:
        path.write_text(json.dumps(item) if suffix == "json" else yaml.safe_dump(item))
    registry = Inventory.load([path])
    assert registry.entries[0].regions == ["us-east-1", "us-west-2"]
    assert registry.match(_finding("shared-id", region="us-east-1")) is not None
    assert registry.match(_finding("shared-id", region="us-west-2")) is not None
    assert registry.match(_finding("shared-id", region="eu-west-1")) is None
    assert registry.match(_finding("shared-id")) is None


@pytest.mark.parametrize("suffix,text", [
    ("yaml", 'id: approved\nresources: ["agent-[cite_start]*"]\n'),
    ("yaml", 'id: approved\nresources: ["agent-\n[cite_start]\n*"]\n'),
    ("json", json.dumps({"id": "approved", "resources": ["agent-[cite_start]*"]})),
    ("csv", 'agent_id,resources\napproved,agent-[cite_start]*\n'),
])
def test_citation_inside_resource_pattern_is_rejected_in_every_format(tmp_path, suffix, text):
    path = tmp_path / f"inventory.{suffix}"
    path.write_text(text)
    with pytest.raises(InventoryValidationError, match="citation marker in resource pattern"):
        Inventory.load([path])


def test_citation_filter_ignores_standalone_export_markers_only(tmp_path):
    quoted = 'id: approved\nresources: ["agent-[cite_start]*"]\n'
    assert _strip_cite_markers(quoted) == quoted
    assert _strip_cite_markers('  - "agent-[cite: 1]*"\n') == '  - "agent-[cite: 1]*"\n'
    multiline = 'id: approved\nresources: ["agent-\n[cite_start]\n*"]\n'
    assert _strip_cite_markers(multiline) == multiline

    path = tmp_path / "document-export.yaml"
    path.write_text('[cite_start]\n[cite: 2]\nid: approved\nresources: ["agent-one"]\n')
    entry = Inventory.load([path]).entries[0]
    assert entry.resources == ["agent-one"]
    assert Inventory([entry]).match(_finding("agent-one")) is entry
    assert Inventory([entry]).match(_finding("agent-prod")) is None
