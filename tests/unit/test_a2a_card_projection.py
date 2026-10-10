"""The shared A2A Agent Card projection used by code.filesystem and the endpoint.mcp probe.

Cards are synthetic, modeled on the A2A 1.0 and 0.3 specification examples.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.semantic_config import (
    MAX_CARD_SIGNATURES,
    a2a_card_interfaces,
    a2a_card_metadata,
    a2a_card_tags,
    a2a_plaintext_interfaces,
    a2a_signature_state,
    a2a_unsupported_protocol_version,
    bounded_metadata,
    parse_agent_manifest,
    validate_agent_manifest,
)
from shadowscan.connectors.endpoint.runtime import MCPInventoryConnector
from shadowscan.utils.redaction import sanitize

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "a2a"
CARD_V1 = json.loads((FIXTURES / "agent_card_v1.json").read_text(encoding="utf-8"))
CARD_V03 = json.loads((FIXTURES / "agent_card_v03.json").read_text(encoding="utf-8"))
SIGNATURE = {"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2lnbmF0dXJl"}
# Userinfo is assembled at run time so no credential-shaped URL is committed.
USERINFO = ":".join(("user", "pw"))


def test_fixture_cards_are_valid_for_both_protocol_versions() -> None:
    assert validate_agent_manifest(CARD_V1, "a2a").valid
    assert validate_agent_manifest(CARD_V03, "a2a").valid
    assert parse_agent_manifest("agent-card.json", json.dumps(CARD_V1), "a2a").valid
    assert parse_agent_manifest("agent-card.json", "{", "a2a").errors == ["invalid agent manifest syntax"]
    assert validate_agent_manifest(["not", "a", "card"], "a2a").errors == ["agent manifest must be an object"]


def test_1x_interfaces_supply_the_url_and_protocol_version() -> None:
    metadata = a2a_card_metadata(CARD_V1)
    assert metadata["url"] == "https://planner.agents.example.com/a2a/v1"
    assert metadata["protocol_version"] == "1.0"
    assert metadata["interfaces"] == [
        {
            "url": "https://planner.agents.example.com/a2a/v1",
            "protocol_binding": "JSONRPC",
            "protocol_version": "1.0",
        },
        {
            "url": "https://planner.agents.example.com/a2a/json",
            "protocol_binding": "HTTP+JSON",
            "protocol_version": "1.0",
        },
    ]
    assert metadata["skills"] == ["Route Optimizer"]
    assert metadata["security_schemes"] == ["oidc"]
    assert metadata["signature"] == "absent"


def test_0x_cards_keep_the_top_level_url_first_and_deduplicate_interfaces() -> None:
    metadata = a2a_card_metadata(CARD_V03)
    assert metadata["protocol_version"] == "0.3.0"
    assert [(i["url"], i["protocol_binding"]) for i in metadata["interfaces"]] == [
        ("https://travel.agents.example.com/a2a", "JSONRPC"),
        ("http://travel.agents.example.com/a2a/rest", "HTTP+JSON"),
    ]
    assert a2a_card_tags(CARD_V03, metadata["signature"]) == ["no-auth-declared", "a2a-plaintext-interface"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Agents.Example.com:8443/a2a?token=x#frag", "https://agents.example.com:8443/a2a"),
        # User information (redacted in the displayed copy) or a backslash can hide the host a
        # client reaches: http://remote.example\@localhost/ reaches remote.example.
        (f"https://{USERINFO}@Agents.Example.com:8443/a2a", None),
        ("http://agent.attacker.example\\@localhost/a2a", None),
        ("wss://agents.example.com/stream", "wss://agents.example.com/stream"),
        ("https://[2001:db8::1]/a2a", "https://[2001:db8::1]/a2a"),
        ("agents.example.com:443", "agents.example.com:443"),
        (f"{USERINFO}@agents.example.com:443", None),
        ("agents.example.com:443/path", None),
        ("agents.example.com", None),
        ("https://agents.example.com:99999/a2a", None),
        ("ftp://agents.example.com/a2a", None),
        ("https://agents.example.com /a2a", None),
        (42, None),
    ],
)
def test_interface_addresses_keep_only_scheme_host_port_and_path(url: object, expected: str | None) -> None:
    interfaces = a2a_card_interfaces({"supportedInterfaces": [{"url": url, "protocolBinding": "GRPC"}]})
    assert [i["url"] for i in interfaces] == ([] if expected is None else [expected])


def test_interfaces_are_bounded() -> None:
    card = {"supportedInterfaces": [{"url": f"https://a{n}.agents.example.com/"} for n in range(40)]}
    assert len(a2a_card_interfaces(card)) == 20


@pytest.mark.parametrize(
    ("url", "plaintext"),
    [
        ("http://agents.example.com/a2a", True),
        ("ws://agents.example.com/a2a", True),
        ("http://localhost:8080/a2a", False),
        ("http://127.0.0.1:8080/a2a", False),
        ("http://[::1]:8080/a2a", False),
        ("https://agents.example.com/a2a", False),
        ("agents.example.com:50051", False),
    ],
)
def test_plaintext_interfaces_to_remote_hosts_are_tagged(url: str, plaintext: bool) -> None:
    card = {"supportedInterfaces": [{"url": url, "protocolBinding": "JSONRPC"}]}
    assert a2a_plaintext_interfaces(card) is plaintext
    assert ("a2a-plaintext-interface" in a2a_card_tags(card, "absent")) is plaintext


@pytest.mark.parametrize(
    ("url", "plaintext"),
    [
        # An HTTP client reaches agent.attacker.example; urlsplit reads localhost.
        ("http://agent.attacker.example\\@localhost/a2a", True),
        ("ws://agent.attacker.example\\@127.0.0.1/a2a", True),
        (f"http://{USERINFO}@localhost/a2a", True),
        ("https://agent.attacker.example\\@localhost/a2a", False),
    ],
)
def test_an_interface_whose_host_cannot_be_told_is_not_projected_and_still_plaintext(
    url: str, plaintext: bool
) -> None:
    card = copy.deepcopy(CARD_V1)
    card["supportedInterfaces"] = [{"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
    # The probe projects the sanitized card, whose redacted user information hides the backslash.
    for metadata in (a2a_card_metadata(card), a2a_card_metadata(card, sanitize(card))):
        assert metadata["interfaces"] == [] and metadata["url"] is None
    assert ("a2a-plaintext-interface" in a2a_card_tags(card, "absent")) is plaintext


@pytest.mark.parametrize(
    ("signatures", "state"),
    [
        (None, "absent"),
        ([], "absent"),
        ([SIGNATURE], "present-unverified"),
        ([{**SIGNATURE, "header": {"kid": "k1"}}], "present-unverified"),
        ([{**SIGNATURE, "header": "kid"}], "invalid"),
        ([{"protected": SIGNATURE["protected"]}], "invalid"),
        ([{**SIGNATURE, "signature": "has spaces"}], "invalid"),
        ([SIGNATURE] * (MAX_CARD_SIGNATURES + 1), "invalid"),
        ("signed", "invalid"),
    ],
)
def test_signature_state_without_verification(signatures: object, state: str) -> None:
    card = copy.deepcopy(CARD_V1)
    if signatures is not None:
        card["signatures"] = signatures
    assert a2a_signature_state(card)[0] == state
    metadata = a2a_card_metadata(card)
    assert metadata["signature"] == state
    assert ("signature_detail" in metadata) is (state == "invalid")
    assert ("a2a-card-signature-invalid" in a2a_card_tags(card, state)) is (state == "invalid")


def test_a_verifier_result_replaces_the_shape_check() -> None:
    card = {**copy.deepcopy(CARD_V1), "signatures": [SIGNATURE]}
    metadata = a2a_card_metadata(card, signature=("verified", None))
    assert metadata["signature"] == "verified" and "signature_detail" not in metadata


def test_displayed_values_come_from_the_sanitized_card_and_decisions_from_the_parsed_one() -> None:
    secret = "SYNTHETIC_CARD_SECRET_1234567890"
    card = copy.deepcopy(CARD_V03)
    card["api_key"] = secret
    card["description"] = f"Uses {secret}"
    card["url"] = f"https://travel.agents.example.com/{secret}"
    card["securitySchemes"] = {
        "oauth": {
            "oauth2SecurityScheme": {"flows": {"clientCredentials": {"tokenUrl": "https://t.example.com"}}}
        }
    }
    shown = sanitize(card)
    metadata = a2a_card_metadata(card, shown)
    assert secret not in json.dumps(metadata)
    assert metadata["url"] == "https://travel.agents.example.com/[REDACTED]"
    assert metadata["security_schemes"] == ["oauth"]
    # The parsed card decides: the sanitized flow value would read as a string.
    assert "no-auth-declared" not in a2a_card_tags(card, metadata["signature"])


def test_projected_strings_are_bounded() -> None:
    card = {**copy.deepcopy(CARD_V1), "name": "n" * 5000, "version": "v" * 5000}
    metadata = a2a_card_metadata(card)
    assert len(metadata["name"]) <= 200 and len(metadata["version"]) <= 200
    assert bounded_metadata({"k": [[[[["deep"]]]]]}) == {"k": [[[None]]]}


def test_filesystem_and_probe_project_the_same_card(tmp_path: Path, run_connector) -> None:
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent-card.json").write_text(json.dumps(CARD_V1), encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    (code_finding,) = [f for f in findings if "agent_card" in f.metadata]
    probe = MCPInventoryConnector(ConnectorContext())
    record = {
        "record_type": "a2a_card",
        "card_url": "https://planner.agents.example.com/.well-known/agent-card.json",
        "card": CARD_V1,
    }
    (probe_finding,) = probe.analyze([record])
    assert code_finding.metadata["agent_card"] == probe_finding.metadata["agent_card"]
    # The 1.x card's interface now supplies the URL the old projection left empty.
    assert code_finding.metadata["agent_card"]["url"] == "https://planner.agents.example.com/a2a/v1"


def test_filesystem_tags_a_plaintext_0x_card(tmp_path: Path, run_connector) -> None:
    (tmp_path / "agent-card.json").write_text(json.dumps(CARD_V03), encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    (card,) = [f for f in findings if "agent_card" in f.metadata]
    assert {"no-auth-declared", "a2a-plaintext-interface"} <= set(card.tags)
    assert card.metadata["agent_card"]["signature"] == "absent"


@pytest.mark.parametrize(
    ("card", "unsupported"),
    [
        (CARD_V1, False),
        (CARD_V03, False),
        ({"protocolVersion": "0.2.5"}, False),
        ({"protocolVersion": "1.1"}, False),
        ({"protocolVersion": ""}, False),
        ({}, False),
        ({"protocolVersion": "2.0"}, True),
        ({"protocolVersion": "9.9-experimental"}, True),
        ({"protocolVersion": "1.0-rc1"}, True),
        ({"protocolVersion": 1.0}, True),
        ({"protocol_version": "2"}, True),
        ({"supportedInterfaces": [{"url": "https://a.example.com", "protocolVersion": "2.0"}]}, True),
        ({"additionalInterfaces": [{"url": "https://a.example.com", "protocol_version": "3"}]}, True),
    ],
)
def test_protocol_versions_other_than_0x_and_1x_are_unsupported(card: dict, unsupported: bool) -> None:
    assert a2a_unsupported_protocol_version(card) is unsupported


def test_filesystem_card_with_an_unknown_protocol_version_is_kept_and_incomplete(
    tmp_path: Path, run_connector
) -> None:
    card = copy.deepcopy(CARD_V1)
    card["supportedInterfaces"][0]["protocolVersion"] = "2.0"
    (tmp_path / "agent-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    (found,) = [f for f in findings if "agent_card" in f.metadata]
    assert found.metadata["agent_card"]["name"] == "Synthetic Route Planner"
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "code.filesystem: agent-card.json: A2A card declares a protocol version other than 0.x or 1.x; "
        "its fields were read as A2A 0.3 and 1.0 fields"
    ]
