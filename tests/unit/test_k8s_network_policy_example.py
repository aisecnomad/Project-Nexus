"""The shipped Kubernetes egress example keeps its deny-by-default shape.

Regression guard for the fix that added a deny-all policy for every ShadowScan pod (a live Job
without the mode label otherwise fell outside every policy and had unrestricted egress) and
denied Azure's wire server, and for the IPv6 guidance in its comment.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import yaml

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "k8s-network-policy.yaml"
NAME = {"app.kubernetes.io/name": "shadowscan"}


def _policies() -> dict[str, dict]:
    docs = [doc for doc in yaml.safe_load_all(EXAMPLE.read_text(encoding="utf-8")) if doc]
    assert all(doc["kind"] == "NetworkPolicy" for doc in docs)
    return {doc["metadata"]["name"]: doc["spec"] for doc in docs}


def _covered(address: str, cidr: str, excepted: list[str]) -> bool:
    ip = ipaddress.ip_address(address)
    return ip in ipaddress.ip_network(cidr) and not any(ip in ipaddress.ip_network(e) for e in excepted)


def test_every_shadowscan_pod_is_denied_egress_by_default():
    spec = _policies()["shadowscan-default-deny-egress"]
    assert spec["podSelector"] == {"matchLabels": NAME}
    assert spec["policyTypes"] == ["Egress"] and spec["egress"] == []


def test_live_egress_applies_only_to_labelled_shadowscan_pods():
    live = _policies()["shadowscan-live-egress"]
    labels = live["podSelector"]["matchLabels"]
    assert labels.items() >= NAME.items() and labels.get("shadowscan-mode") == "live"
    assert live["policyTypes"] == ["Egress"]


def test_live_https_rule_denies_private_metadata_and_wire_server_addresses():
    rules = _policies()["shadowscan-live-egress"]["egress"]
    blocks = [peer["ipBlock"] for rule in rules for peer in rule.get("to", []) if "ipBlock" in peer]
    assert len(blocks) == 1
    [block] = blocks
    https = next(rule for rule in rules if any("ipBlock" in peer for peer in rule["to"]))
    assert https["ports"] == [{"protocol": "TCP", "port": 443}]
    denied = ["10.1.2.3", "100.64.0.1", "168.63.129.16", "169.254.169.254", "172.16.0.1", "192.168.1.1"]
    for address in denied:
        assert not _covered(address, block["cidr"], block["except"]), address
    assert _covered("8.8.8.8", block["cidr"], block["except"])


def test_documented_ipv6_rule_excepts_internal_and_nat64_prefixes():
    match = re.search(r"^#\s+cidr: (::/0)\n#\s+except: (\[.*\])$", EXAMPLE.read_text(encoding="utf-8"), re.M)
    assert match, "the IPv6 ipBlock guidance is missing"
    cidr, excepted = match.group(1), yaml.safe_load(match.group(2))
    for address in (
        "fd00:ec2::254",  # AWS metadata
        "fe80::1",
        "64:ff9b::a9fe:a9fe",  # NAT64 well-known prefix to 169.254.169.254
        "64:ff9b:1::a9fe:a9fe",  # RFC 8215 local-use NAT64 prefix
        "::ffff:169.254.169.254",
    ):
        assert not _covered(address, cidr, excepted), address
    assert _covered("2001:4860:4860::8888", cidr, excepted)
