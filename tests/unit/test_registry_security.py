from pathlib import Path

from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry, card_stub_for


def finding(**kwargs):
    return Finding(surface=Surface.CLOUD, connector="aws.bedrock", kind=Kind.AGENT,
                   title="Agent: trusted-agent", resource="arn:aws:bedrock:us-east-1:111:agent/OTHER",
                   resource_type="agent", provider="aws", account="111", region="us-east-1", **kwargs)


def test_spoofed_name_and_agent_id_only_suggest_review():
    inv = Inventory([InventoryEntry(agent_id="trusted-agent", owner="Approved Team", resources=["arn:aws:bedrock:*:111:agent/APPROVED"], names=["trusted-agent"])])
    item = finding(metadata={"agent_name": "trusted-agent"})
    assert inv.match(item) is None
    assert item.metadata["registry_suggestions"] == ["trusted-agent"]
    assert item.owner is None
    item.resource = "arn:aws:bedrock:us-east-1:111:agent/trusted-agent"
    assert inv.match(item) is None


def test_explicit_resource_requires_all_scope_constraints():
    entry = InventoryEntry(agent_id="trusted-agent", resources=["arn:aws:bedrock:*:111:agent/*"],
                           surfaces=["cloud"], providers=["aws"], accounts=["111"], regions=["us-east-1"])
    inv = Inventory([entry])
    item = finding()
    assert inv.match(item) is entry
    for attribute, wrong in (("surface", Surface.CODE), ("provider", "other"), ("account", "222"),
                             ("account", None), ("region", "eu-west-1"), ("region", None)):
        saved = getattr(item, attribute)
        setattr(item, attribute, wrong)
        assert inv.match(item) is None
        setattr(item, attribute, saved)


def test_resource_matching_is_case_sensitive_and_ambiguity_fails_closed():
    item = finding()
    entry = InventoryEntry(agent_id="one", resources=[item.resource.lower()])
    assert Inventory([entry]).match(item) is None
    entry.resources = [item.resource]
    other = InventoryEntry(agent_id="two", resources=[item.resource])
    assert Inventory([entry, other]).match(item) is None
    assert item.metadata["registry_match_reason"] == "ambiguous-resource-approval"


def test_inventory_constraints_load_from_card_simple_and_csv(tmp_path):
    values = {"surfaces": ["cloud"], "providers": ["aws"], "accounts": ["111"], "regions": ["us-east-1"]}
    simple = Inventory._entry_from_simple({"id": "x", **values}, Path("inventory.yaml"))
    card = Inventory._entry_from_card({"metadata": {"agent_id": "x"}, "discovery": values}, Path("card.yaml"))
    path = tmp_path / "inventory.csv"
    path.write_text("agent_id,surfaces,providers,accounts,regions\nx,cloud,aws,111,us-east-1\n")
    csv_entry = Inventory.load([path]).entries[0]
    for entry in (simple, card, csv_entry):
        assert entry.surfaces == ["cloud"] and entry.providers == ["aws"] and entry.accounts == ["111"]
        assert entry.regions == ["us-east-1"]
    stub = card_stub_for(finding())
    assert stub["discovery"]["accounts"] == ["111"]
    assert stub["discovery"]["regions"] == ["us-east-1"]


def test_name_only_inventory_never_auto_approves():
    assert Inventory([InventoryEntry(agent_id="trusted-agent")]).match(finding()) is None
