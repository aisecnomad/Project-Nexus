"""endpoint.mcp A2A Agent Card probe: fetch rules, replay and signature verification.

Every card here is synthetic, modeled on the A2A specification's examples and
not validated against a live service. HTTP runs through the real HttpClient
with a scripted transport, so redirect, origin, size and JSON rules are the
production ones; the autouse ``blocked_connections`` fixture fails any test
that reaches the network.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from jwt.api_jws import PyJWS

from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig, normalize_connector_config
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.semantic_config import A2A_SIGNATURE_STATES
from shadowscan.connectors.endpoint import a2a
from shadowscan.connectors.endpoint import runtime as endpoint_runtime
from shadowscan.connectors.endpoint.runtime import MCPInventoryConnector
from shadowscan.engine import Engine
from shadowscan.models import Kind, ScanStats
from shadowscan.utils.http import HttpClient, reset_allow_private_origin, set_allow_private_origin
from shadowscan.utils.jcs import MAX_DEPTH, CanonicalizationError, canonicalize
from shadowscan.utils.redaction import SanitizationLimitError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "a2a"
CARD_V1 = json.loads((FIXTURES / "agent_card_v1.json").read_text(encoding="utf-8"))
CARD_V03 = json.loads((FIXTURES / "agent_card_v03.json").read_text(encoding="utf-8"))
ORIGIN = "https://planner.agents.example.com"
WELL_KNOWN = ORIGIN + "/.well-known/agent-card.json"
LEGACY = ORIGIN + "/.well-known/agent.json"
JWKS_URL = "https://keys.agents.example.com/jwks.json"
# Userinfo is assembled at run time so no credential-shaped URL is committed.
USERINFO = ":".join(("user", "pw"))


# ------------------------------------------------------------------ transport


def _response(status: int, body: Any = None, headers: dict[str, str] | None = None) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp.headers.update(headers or {})
    if isinstance(body, bytes):
        resp._content = body
    else:
        resp._content = b"" if body is None else json.dumps(body).encode()
    resp._content_consumed = True  # type: ignore[attr-defined]
    return resp


class _Routes(requests.Session):
    """Answer by exact URL; record every request URL."""

    def __init__(self, routes: dict[str, requests.Response]):
        super().__init__()
        self.routes = routes
        self.calls: list[str] = []

    def request(self, method, url, **kwargs):  # type: ignore[override]
        self.calls.append(url)
        if url not in self.routes:
            return _response(404, {"error": "not found"})
        return self.routes[url]


@pytest.fixture
def routes(monkeypatch: pytest.MonkeyPatch) -> _Routes:
    session = _Routes({})

    def client(**kwargs: Any) -> HttpClient:
        return HttpClient(session=session, max_retries=0, **kwargs)

    monkeypatch.setattr(a2a, "HttpClient", client)
    return session


def _run(**config: Any) -> tuple[list[Any], ConnectorContext]:
    ctx = ConnectorContext(config=config)
    findings = MCPInventoryConnector(ctx).run()
    return findings, ctx


# ------------------------------------------------------------------- signing


class _Signer:
    """An ES256 key pair; ``jwks`` is the public key set an operator would publish."""

    def __init__(self, kid: str = "card-key-1"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = kid
        public = json.loads(ECAlgorithm.to_jwk(self.key.public_key()))
        self.jwk = {**public, "kid": kid, "use": "sig", "alg": "ES256"}

    def sign(self, card: dict[str, Any], **header: Any) -> dict[str, Any]:
        payload = canonicalize({k: v for k, v in card.items() if k != "signatures"})
        token = PyJWS().encode(payload, self.key, algorithm="ES256", headers={"kid": self.kid, **header})
        protected, _, signature = token.split(".")
        return {"protected": protected, "signature": signature}


@pytest.fixture
def signer() -> _Signer:
    return _Signer()


@pytest.fixture
def trusted_keys(monkeypatch: pytest.MonkeyPatch, signer: _Signer) -> list[tuple[str, Any]]:
    """Serve the signer's public key as the operator's JWKS and record each fetch."""
    fetched: list[tuple[str, Any]] = []

    def fetch(url: str, *, ca_bundle: str | None = None) -> dict[str, Any]:
        fetched.append((url, ca_bundle))
        return {"keys": [signer.jwk]}

    monkeypatch.setattr(endpoint_runtime, "fetch_jwks", fetch)
    return fetched


def _signed(signer: _Signer, card: dict[str, Any] | None = None, **header: Any) -> dict[str, Any]:
    card = copy.deepcopy(CARD_V1 if card is None else card)
    card["signatures"] = [signer.sign(card, **header)]
    return card


def _analyze(card: dict[str, Any], **config: Any) -> tuple[list[Any], ConnectorContext]:
    ctx = ConnectorContext(config=config)
    ctx.stats = ScanStats(connector="endpoint.mcp", started_at="2026-10-10T00:00:00Z")
    record = {"record_type": "a2a_card", "card_url": WELL_KNOWN, "card": card}
    return list(MCPInventoryConnector(ctx).analyze([record])), ctx


# ------------------------------------------------------------------ probing


def test_bare_origin_probes_the_well_known_card(routes: _Routes) -> None:
    routes.routes[WELL_KNOWN] = _response(200, CARD_V1)
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert routes.calls == [WELL_KNOWN]
    (finding,) = findings
    assert finding.connector == "endpoint.mcp"
    assert finding.kind == Kind.AGENT
    assert finding.provider == "a2a"
    assert finding.resource == WELL_KNOWN
    assert finding.resource_type == "a2a-agent-card"
    assert finding.identity_discriminator == "a2a-card"
    assert finding.frameworks == ["protocol.a2a"]
    assert "multi-agent" in finding.capabilities
    assert [e.signal for e in finding.evidence] == ["a2a:card-probe", "a2a:card-signature"]
    card = finding.metadata["agent_card"]
    assert card["name"] == "Synthetic Route Planner"
    assert card["url"] == "https://planner.agents.example.com/a2a/v1"
    assert card["protocol_version"] == "1.0"
    assert card["security_schemes"] == ["oidc"]
    assert card["signature"] == "absent"
    assert [i["protocol_binding"] for i in card["interfaces"]] == ["JSONRPC", "HTTP+JSON"]
    assert finding.metadata["card_path"] == "/.well-known/agent-card.json"
    assert not {"no-auth-declared", "a2a-plaintext-interface", "a2a-card-signature-invalid"} & set(
        finding.tags
    )
    assert ctx.stats.objects_examined == 1


def test_404_falls_back_to_the_legacy_card_path(routes: _Routes) -> None:
    routes.routes[LEGACY] = _response(200, CARD_V03)
    findings, ctx = _run(agent_card_urls=[ORIGIN + "/"])
    assert not ctx.stats.errors
    assert routes.calls == [WELL_KNOWN, LEGACY]
    (finding,) = findings
    assert finding.resource == LEGACY
    assert finding.metadata["card_path"] == "/.well-known/agent.json"
    card = finding.metadata["agent_card"]
    assert card["protocol_version"] == "0.3.0"
    assert card["url"] == "https://travel.agents.example.com/a2a"
    # The plaintext additional interface and the missing security scheme are tagged.
    assert {"no-auth-declared", "a2a-plaintext-interface"} <= set(finding.tags)


def test_only_a_404_falls_back(routes: _Routes) -> None:
    routes.routes[WELL_KNOWN] = _response(403, {"error": "denied"})
    routes.routes[LEGACY] = _response(200, CARD_V1)
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert findings == [] and routes.calls == [WELL_KNOWN]
    assert ctx.stats.incomplete
    assert ctx.stats.errors == [
        "endpoint.mcp: A2A Agent Card fetch from https://planner.agents.example.com failed (HTTP 403)"
    ]


def test_explicit_card_url_is_fetched_as_given_and_its_query_stays_out_of_findings(routes: _Routes) -> None:
    url = ORIGIN + "/cards/planner.json?token=SYNTHETIC-QUERY-VALUE-123#frag"
    routes.routes[ORIGIN + "/cards/planner.json?token=SYNTHETIC-QUERY-VALUE-123"] = _response(200, CARD_V1)
    findings, ctx = _run(agent_card_urls=[url])
    assert not ctx.stats.errors
    (finding,) = findings
    assert finding.resource == ORIGIN + "/cards/planner.json"
    assert "SYNTHETIC-QUERY-VALUE" not in json.dumps(finding.to_dict())


def test_failure_diagnostics_never_echo_a_configured_url_path_or_query(routes: _Routes) -> None:
    url = ORIGIN + "/private-path/card.json?token=SYNTHETIC-QUERY-VALUE-123"
    findings, ctx = _run(agent_card_urls=[url])
    assert findings == [] and ctx.stats.incomplete
    text = json.dumps(ctx.stats.errors)
    assert "private-path" not in text and "SYNTHETIC-QUERY-VALUE" not in text and "HTTP 404" in text


def test_same_origin_redirect_is_followed_and_cross_origin_refused(routes: _Routes) -> None:
    routes.routes[WELL_KNOWN] = _response(302, headers={"Location": "/cards/current.json"})
    routes.routes[ORIGIN + "/cards/current.json"] = _response(200, CARD_V1)
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert len(findings) == 1 and not ctx.stats.errors
    assert findings[0].resource == WELL_KNOWN

    routes.calls.clear()
    routes.routes[WELL_KNOWN] = _response(
        302, headers={"Location": "https://other.agents.example.net/card.json"}
    )
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert findings == [] and ctx.stats.incomplete
    assert routes.calls == [WELL_KNOWN]
    assert ctx.stats.errors == [
        "endpoint.mcp: A2A Agent Card fetch from https://planner.agents.example.com failed (ValueError)"
    ]


def test_private_addresses_are_refused_unless_the_scan_allows_them(routes: _Routes) -> None:
    private = "https://10.0.0.5"
    routes.routes[private + "/.well-known/agent-card.json"] = _response(200, CARD_V1)
    findings, ctx = _run(agent_card_urls=[private])
    assert findings == [] and routes.calls == [] and ctx.stats.incomplete
    token = set_allow_private_origin(True)
    try:
        findings, ctx = _run(agent_card_urls=[private])
    finally:
        reset_allow_private_origin(token)
    assert len(findings) == 1 and not ctx.stats.errors


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b'{"name": "a", "name": "b"}', "ValueError"),
        (b"{" + b" " * (a2a.MAX_CARD_BYTES + 1) + b"}", "ValueError"),
        (b"not json", "ValueError"),
    ],
    ids=["duplicate-keys", "oversized", "malformed"],
)
def test_unparseable_cards_fail_closed(routes: _Routes, body: bytes, reason: str) -> None:
    routes.routes[WELL_KNOWN] = _response(200, body)
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.errors == [
        f"endpoint.mcp: A2A Agent Card fetch from https://planner.agents.example.com failed ({reason})"
    ]


@pytest.mark.parametrize("body", [[CARD_V1], None], ids=["array", "empty-body"])
def test_a_card_that_is_not_an_object_fails_closed(routes: _Routes, body: Any) -> None:
    routes.routes[WELL_KNOWN] = _response(200, body)
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.errors == [
        "endpoint.mcp: A2A Agent Card from https://planner.agents.example.com is not a JSON object"
    ]


def test_one_failed_agent_does_not_stop_the_others(routes: _Routes) -> None:
    other = "https://travel.agents.example.com"
    routes.routes[other + "/.well-known/agent-card.json"] = _response(200, CARD_V03)
    findings, ctx = _run(agent_card_urls=[ORIGIN, other])
    assert [f.resource for f in findings] == [other + "/.well-known/agent-card.json"]
    assert ctx.stats.incomplete and len(ctx.stats.errors) == 1


def test_urls_declared_inside_a_card_are_never_fetched(routes: _Routes, trusted_keys, signer) -> None:
    card = _signed(signer, jku="https://attacker.agents.example.net/jwks.json")
    routes.routes[WELL_KNOWN] = _response(200, card)
    findings, ctx = _run(agent_card_urls=[ORIGIN], agent_card_jwks_url=JWKS_URL)
    assert routes.calls == [WELL_KNOWN]
    assert trusted_keys == [(JWKS_URL, None)]
    assert findings[0].metadata["agent_card"]["signature"] == "verified"


def test_invalid_card_is_an_error_without_a_finding(routes: _Routes) -> None:
    routes.routes[WELL_KNOWN] = _response(200, {"title": "not a card"})
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.errors[0].startswith(
        "endpoint.mcp: invalid A2A Agent Card at https://planner.agents.example.com: A2A card requires"
    )


def test_incomplete_card_is_protocol_evidence_and_incomplete(routes: _Routes) -> None:
    routes.routes[WELL_KNOWN] = _response(
        200, {"name": "Draft", "url": "https://planner.agents.example.com/a2a"}
    )
    findings, ctx = _run(agent_card_urls=[ORIGIN])
    (finding,) = findings
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "incomplete-agent-card" in finding.tags and "multi-agent" not in finding.capabilities
    assert finding.title == "Incomplete A2A Agent Card: Draft"
    assert finding.metadata["card_errors"]
    assert ctx.stats.incomplete and ctx.stats.errors[0].startswith("endpoint.mcp: incomplete A2A Agent Card")


def test_without_urls_the_connector_still_requires_offline_input() -> None:
    findings, ctx = _run()
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.errors == [
        "endpoint.mcp: NotImplementedError: endpoint inventory requires offline input"
    ]


# ------------------------------------------------------------ configuration


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"agent_card_urls": "https://planner.agents.example.com"}, "agent_card_urls must be a list"),
        ({"agent_card_urls": ["http://planner.agents.example.com"]}, "entry 1 must use HTTPS"),
        ({"agent_card_urls": [f"https://{USERINFO}@planner.agents.example.com"]}, "entry 1 must use HTTPS"),
        ({"agent_card_urls": [ORIGIN, "https://planner .example.com"]}, "entry 2 must be an HTTPS URL"),
        ({"agent_card_urls": ["https://planner.agents.example.com:99999"]}, "entry 1 is not a valid URL"),
        ({"agent_card_urls": [ORIGIN, ORIGIN + "/x"], "max_agent_cards": 1}, "more than max_agent_cards (1)"),
        ({"agent_card_urls": [ORIGIN], "max_agent_cards": 0}, "max_agent_cards"),
        ({"agent_card_urls": [ORIGIN], "max_agent_cards": True}, "max_agent_cards"),
        ({"agent_card_jwks_url": "http://keys.agents.example.com/jwks.json"}, "agent_card_jwks_url must use"),
        ({"agent_card_jwks_url": 42}, "agent_card_jwks_url must be an HTTPS URL"),
        ({"input": "cards.jsonl", "agent_card_urls": [ORIGIN]}, "never probes agent_card_urls"),
    ],
)
def test_invalid_probe_configuration_is_refused_at_construction(config: dict[str, Any], message: str) -> None:
    with pytest.raises(ConnectorError) as raised:
        MCPInventoryConnector(ConnectorContext(config=config))
    assert message in str(raised.value)
    assert USERINFO not in str(raised.value)


def test_a_scan_that_replays_input_with_agent_card_urls_is_refused_not_silently_unprobed(
    routes: _Routes,
) -> None:
    spec = ConnectorSpec(
        "endpoint.mcp", {"input": str(FIXTURES / "card_records.jsonl"), "agent_card_urls": [ORIGIN]}
    )
    result = Engine(ScanConfig(connectors=[spec])).run()
    (stats,) = result.stats
    assert stats.skipped and stats.incomplete and not result.complete
    assert result.findings == [] and routes.calls == []
    # Replay with the operator's key set alone stays allowed.
    findings, ctx = _run(input=str(FIXTURES / "card_records.jsonl"), agent_card_jwks_url=JWKS_URL)
    assert len(findings) == 3


def test_url_list_is_deduplicated_and_never_truncated() -> None:
    urls = [f"https://agent{n}.agents.example.com" for n in range(a2a.DEFAULT_MAX_AGENT_CARDS)]
    assert a2a.agent_card_urls(urls, None) == urls
    assert a2a.agent_card_urls([ORIGIN, ORIGIN], 2) == [ORIGIN]
    assert a2a.agent_card_urls(None, None) == []
    # The configured list is counted as written: repeats count toward the limit.
    with pytest.raises(ConnectorError):
        a2a.agent_card_urls([*urls, urls[0]], None)


def test_probe_keys_are_accepted_connector_configuration() -> None:
    config = {
        "agent_card_urls": [ORIGIN],
        "max_agent_cards": 5,
        "agent_card_jwks_url": JWKS_URL,
        "ca_bundle": "/etc/ssl/private-ca.pem",
    }
    assert normalize_connector_config("endpoint.mcp", config) == config
    with pytest.raises(ConfigValidationError):
        normalize_connector_config("endpoint.mcp", {"agent_card_url": [ORIGIN]})


def test_card_resource_drops_userinfo_query_fragment_and_default_port() -> None:
    assert a2a.card_resource("https://u@Planner.Agents.example.com:443/a?b=c#d") == (
        "https://planner.agents.example.com/a"
    )
    assert a2a.card_resource("https://[::1]:8443") == "https://[::1]:8443/"


def test_ca_bundle_reaches_the_card_and_key_fetches(monkeypatch: pytest.MonkeyPatch, signer) -> None:
    seen: list[Any] = []

    def fetch_card(url: str, *, ca_bundle: str | None = None) -> tuple[str, Any]:
        seen.append(("card", ca_bundle))
        return WELL_KNOWN, _signed(signer)

    def fetch_jwks(url: str, *, ca_bundle: str | None = None) -> dict[str, Any]:
        seen.append(("jwks", ca_bundle))
        return {"keys": [signer.jwk]}

    monkeypatch.setattr(a2a, "fetch_card", fetch_card)
    monkeypatch.setattr(endpoint_runtime, "fetch_jwks", fetch_jwks)
    findings, ctx = _run(agent_card_urls=[ORIGIN], agent_card_jwks_url=JWKS_URL, ca_bundle="/pki/ca.pem")
    assert seen == [("card", "/pki/ca.pem"), ("jwks", "/pki/ca.pem")]
    assert findings[0].metadata["agent_card"]["signature"] == "verified"


# ------------------------------------------------------------ replay


def test_dumped_records_replay_to_the_same_findings(routes: _Routes, tmp_path: Path) -> None:
    routes.routes[WELL_KNOWN] = _response(200, CARD_V1)
    dump = tmp_path / "endpoint_mcp.jsonl"
    live, ctx = _run(agent_card_urls=[ORIGIN], _dump_path=str(dump))
    assert ctx.dump_path == str(dump) and not ctx.stats.errors
    replayed, replay_ctx = _run(input=str(dump))
    assert not replay_ctx.stats.errors
    assert [f.id for f in replayed] == [f.id for f in live]
    assert replayed[0].to_dict()["metadata"]["agent_card"] == live[0].to_dict()["metadata"]["agent_card"]


def test_fixture_records_replay_offline() -> None:
    findings, ctx = _run(input=str(FIXTURES / "card_records.jsonl"))
    by_name = {f.metadata["agent_card"]["name"]: f for f in findings}
    assert set(by_name) == {"Synthetic Route Planner", "Synthetic Travel Desk", "Synthetic Unfinished Agent"}
    assert by_name["Synthetic Route Planner"].kind == Kind.AGENT
    assert {"no-auth-declared", "a2a-plaintext-interface"} <= set(by_name["Synthetic Travel Desk"].tags)
    assert by_name["Synthetic Unfinished Agent"].kind == Kind.FRAMEWORK_USAGE
    # The incomplete card is reported and keeps the scan incomplete.
    assert ctx.stats.incomplete and len(ctx.stats.errors) == 1


@pytest.mark.parametrize(
    "record",
    [
        {"record_type": "a2a_card", "card_url": WELL_KNOWN},
        {"record_type": "a2a_card", "card_url": "http://planner.agents.example.com/card", "card": CARD_V1},
        {"record_type": "a2a_card", "card": CARD_V1},
        {
            "record_type": "mcp_tool_list",
            "server": "https://mcp.agents.example.com",
            "tools": [{"name": "x"}],
        },
    ],
    ids=["no-card", "plaintext-url", "no-url", "unknown-type"],
)
def test_malformed_or_unknown_records_are_dropped_and_incomplete(record: dict[str, Any]) -> None:
    ctx = ConnectorContext()
    ctx.stats = ScanStats(connector="endpoint.mcp", started_at="2026-10-10T00:00:00Z")
    assert list(MCPInventoryConnector(ctx).analyze([record])) == []
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1


def test_card_records_do_not_change_tool_list_analysis() -> None:
    ctx = ConnectorContext()
    ctx.stats = ScanStats(connector="endpoint.mcp", started_at="2026-10-10T00:00:00Z")
    records = [
        {"record_type": "a2a_card", "card_url": WELL_KNOWN, "card": CARD_V1},
        {"server": "https://mcp.agents.example.com", "tools": [{"name": "search", "description": "Search"}]},
    ]
    findings = list(MCPInventoryConnector(ctx).analyze(records))
    assert [(f.resource_type, f.provider) for f in findings] == [
        ("a2a-agent-card", "a2a"),
        ("mcp-tool", None),
    ]
    assert findings[1].resource == "https://mcp.agents.example.com/search"
    assert not ctx.stats.incomplete


# ------------------------------------------------------------ signatures


def test_unsigned_card_is_absent_and_signed_card_without_keys_is_unverified(signer) -> None:
    (unsigned,), _ = _analyze(copy.deepcopy(CARD_V1))
    assert unsigned.metadata["agent_card"]["signature"] == "absent"
    (signed,), ctx = _analyze(_signed(signer))
    card = signed.metadata["agent_card"]
    assert card["signature"] == "present-unverified" and "signature_detail" not in card
    assert "a2a-card-signature-invalid" not in signed.tags
    assert not ctx.stats.incomplete
    evidence = next(e for e in signed.evidence if e.signal == "a2a:card-signature")
    assert "NOT verified" in evidence.description and evidence.weight == 0.0


def test_signature_verifies_against_the_operator_key_set_once_per_run(signer, trusted_keys) -> None:
    ctx = ConnectorContext(config={"agent_card_jwks_url": JWKS_URL})
    ctx.stats = ScanStats(connector="endpoint.mcp", started_at="2026-10-10T00:00:00Z")
    records = [
        {"record_type": "a2a_card", "card_url": WELL_KNOWN, "card": _signed(signer)},
        {"record_type": "a2a_card", "card_url": LEGACY, "card": _signed(signer, CARD_V03)},
    ]
    findings = list(MCPInventoryConnector(ctx).analyze(records))
    assert [f.metadata["agent_card"]["signature"] for f in findings] == ["verified", "verified"]
    assert trusted_keys == [(JWKS_URL, None)]
    assert not ctx.stats.incomplete


def test_tampered_card_fails_verification(signer, trusted_keys) -> None:
    card = _signed(signer)
    card["skills"][0]["name"] = "Exfiltrate everything"
    (finding,), ctx = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "invalid"
    assert finding.metadata["agent_card"]["signature_detail"] == (
        "signature matches none of the card's canonical forms"
    )
    assert "a2a-card-signature-invalid" in finding.tags
    assert not ctx.stats.incomplete


def test_signature_by_an_untrusted_key_with_its_own_jku_is_invalid(signer, trusted_keys) -> None:
    attacker = _Signer(kid=signer.kid)
    card = _signed(attacker, jku="https://attacker.agents.example.net/jwks.json")
    (finding,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "invalid"
    assert trusted_keys == [(JWKS_URL, None)]


def test_unknown_key_id_is_invalid_with_a_fixed_reason(signer, trusted_keys) -> None:
    other = _Signer(kid="rotated-away")
    (finding,), _ = _analyze(_signed(other), agent_card_jwks_url=JWKS_URL)
    card = finding.metadata["agent_card"]
    assert card["signature"] == "invalid"
    assert card["signature_detail"] == "JWKS does not contain a matching signature key"


def test_any_verifying_signature_suffices_for_key_rotation(signer, trusted_keys) -> None:
    card = copy.deepcopy(CARD_V1)
    card["signatures"] = [_Signer(kid="old").sign(card), signer.sign(card)]
    (finding,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "verified"


def test_symmetric_or_unlisted_algorithms_are_never_accepted(signer, trusted_keys) -> None:
    card = copy.deepcopy(CARD_V1)
    payload = canonicalize(card)
    token = PyJWS().encode(payload, "shared-secret-for-tests-only-0123456789", algorithm="HS256")
    protected, _, signature = token.split(".")
    card["signatures"] = [{"protected": protected, "signature": signature}]
    (finding,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "invalid"
    assert "allowlist" in finding.metadata["agent_card"]["signature_detail"]


@pytest.mark.parametrize(
    "signatures",
    [{"protected": "x"}, [{"protected": "eyJh", "signature": "not base64url!"}], ["entry"]],
    ids=["not-array", "bad-signature-encoding", "not-object"],
)
def test_malformed_signatures_are_invalid_without_any_key(signatures: Any) -> None:
    card = {**copy.deepcopy(CARD_V1), "signatures": signatures}
    (finding,), _ = _analyze(card)
    assert finding.metadata["agent_card"]["signature"] == "invalid"
    assert "a2a-card-signature-invalid" in finding.tags


def test_card_without_a_canonical_form_is_invalid(signer, trusted_keys) -> None:
    card = {**copy.deepcopy(CARD_V1), "x-serial": 2**60}
    card["signatures"] = [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2lnbmF0dXJl"}]
    (finding,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    card_meta = finding.metadata["agent_card"]
    assert card_meta["signature"] == "invalid"
    assert card_meta["signature_detail"] == "JSON integer is outside the exactly representable range"
    assert trusted_keys == []


def test_unavailable_key_set_leaves_signatures_unverified_and_the_scan_incomplete(
    monkeypatch, signer
) -> None:
    calls: list[str] = []

    def fail(url: str, *, ca_bundle: str | None = None) -> dict[str, Any]:
        calls.append(url)
        raise ValueError("JWKS document is not a key set")

    monkeypatch.setattr(endpoint_runtime, "fetch_jwks", fail)
    ctx = ConnectorContext(config={"agent_card_jwks_url": JWKS_URL})
    ctx.stats = ScanStats(connector="endpoint.mcp", started_at="2026-10-10T00:00:00Z")
    records = [{"record_type": "a2a_card", "card_url": WELL_KNOWN, "card": _signed(signer)}] * 2
    findings = list(MCPInventoryConnector(ctx).analyze(records))
    assert [f.metadata["agent_card"]["signature"] for f in findings] == ["present-unverified"] * 2
    assert calls == [JWKS_URL]
    assert ctx.stats.incomplete
    assert ctx.stats.errors == [
        "endpoint.mcp: agent_card_jwks_url could not be read (ValueError); Agent Card signatures stay unverified"
    ]


def test_replayed_card_redacted_by_the_export_is_not_judged(signer, trusted_keys, tmp_path: Path) -> None:
    card = _signed(signer)
    card["securitySchemes"]["oidc"]["openIdConnectSecurityScheme"]["clientSecret"] = "synthetic-value"
    card["signatures"] = [signer.sign(card)]
    export = tmp_path / "cards.jsonl"
    record = {"record_type": "a2a_card", "card_url": WELL_KNOWN, "card": card}
    export.write_text(json.dumps(record).replace("synthetic-value", "[REDACTED]") + "\n", encoding="utf-8")
    (finding,), ctx = _run(input=str(export), agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "present-unverified"
    assert "redacted" in finding.metadata["agent_card"]["signature_detail"]
    assert trusted_keys == []


def test_signed_fixture_card_replays_as_verified(signer, trusted_keys, tmp_path: Path) -> None:
    export = tmp_path / "cards.jsonl"
    record = {"record_type": "a2a_card", "card_url": WELL_KNOWN, "card": _signed(signer)}
    export.write_text(json.dumps(record) + "\n", encoding="utf-8")
    (finding,), ctx = _run(input=str(export), agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "verified"
    assert not ctx.stats.errors


def test_an_unusable_trusted_key_is_reported_by_type_only(monkeypatch, signer) -> None:
    broken = {"kty": "EC", "crv": "P-256", "kid": signer.kid, "x": "AAAA", "y": "AAAA"}
    monkeypatch.setattr(endpoint_runtime, "fetch_jwks", lambda url, *, ca_bundle=None: {"keys": [broken]})
    (finding,), _ = _analyze(_signed(signer), agent_card_jwks_url=JWKS_URL)
    card = finding.metadata["agent_card"]
    assert card["signature"] == "invalid"
    assert card["signature_detail"] == "signature not verifiable (InvalidKeyError)"


def test_a_card_the_sanitizer_refuses_is_omitted_and_incomplete(monkeypatch) -> None:
    def refuse(value: Any) -> Any:
        raise SanitizationLimitError("synthetic limit")

    monkeypatch.setattr(endpoint_runtime, "sanitize", refuse)
    findings, ctx = _analyze(copy.deepcopy(CARD_V1))
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.errors == [
        "endpoint.mcp: A2A Agent Card at https://planner.agents.example.com omitted: "
        "sanitization safety limit exceeded"
    ]


def test_every_signature_state_has_evidence_text() -> None:
    assert set(endpoint_runtime._SIGNATURE_EVIDENCE) == set(A2A_SIGNATURE_STATES)


# ------------------------------------------------- canonical forms (interop)


def _clean_empty_reference(value: Any) -> Any:
    """The A2A Python SDK's ``_clean_empty``, written out here independently of a2a.py."""
    if isinstance(value, dict):
        members = {k: c for k, v in value.items() if (c := _clean_empty_reference(v)) is not None}
        return members or None
    if isinstance(value, list):
        items = [c for v in value if (c := _clean_empty_reference(v)) is not None]
        return items or None
    if isinstance(value, str) and not value:
        return None
    return value


def _sign_bytes(signer: _Signer, payload: bytes) -> dict[str, str]:
    token = PyJWS().encode(payload, signer.key, algorithm="ES256", headers={"kid": signer.kid, "typ": "JOSE"})
    protected, _, signature = token.split(".")
    return {"protected": protected, "signature": signature}


def _served_with_empty_values() -> dict[str, Any]:
    card = copy.deepcopy(CARD_V1)
    card["description"] = ""
    card["capabilities"]["extensions"] = []
    card["skills"][0]["examples"] = []
    return card


def test_a_card_signed_in_the_sdk_form_verifies_when_served_with_empty_values(signer, trusted_keys) -> None:
    card = _served_with_empty_values()
    card["signatures"] = [_sign_bytes(signer, canonicalize(_clean_empty_reference(copy.deepcopy(card))))]
    (finding,), ctx = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "verified"
    assert "a2a-card-signature-invalid" not in finding.tags and not ctx.stats.incomplete
    # Only empty values are ignored: a nonempty addition still fails.
    card["capabilities"]["extensions"] = [{"uri": "https://ext.agents.example.com/unsigned"}]
    (tampered,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert tampered.metadata["agent_card"]["signature"] == "invalid"


def test_a_card_signed_in_the_specification_form_verifies_when_served_with_empty_values(
    signer, trusted_keys
) -> None:
    card = _served_with_empty_values()
    # Section 8.4.1: empty members are dropped unless REQUIRED (description is kept).
    signed = copy.deepcopy(card)
    del signed["capabilities"]["extensions"], signed["skills"][0]["examples"]
    payload = canonicalize(signed)
    assert payload != canonicalize(card) and payload != canonicalize(_clean_empty_reference(card))
    card["signatures"] = [_sign_bytes(signer, payload)]
    (finding,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert finding.metadata["agent_card"]["signature"] == "verified"


@pytest.mark.parametrize(
    "added",
    [
        {"securitySchemes": {"oauth2": {}}},
        {"authentication": {"schemes": []}},
        {"securitySchemes": {"oauth2": {"oauth2SecurityScheme": {"flows": {}}}}},
    ],
)
def test_a_verified_card_is_read_as_its_signature_covers_it(signer, trusted_keys, added) -> None:
    card = copy.deepcopy(CARD_V1)
    del card["securitySchemes"]
    card.pop("securityRequirements", None)
    signed = copy.deepcopy(card)
    card["signatures"] = [_sign_bytes(signer, canonicalize(_clean_empty_reference(copy.deepcopy(signed))))]
    (genuine,), _ = _analyze(card, agent_card_jwks_url=JWKS_URL)
    assert genuine.metadata["agent_card"]["signature"] == "verified"
    assert "no-auth-declared" in genuine.tags
    # Empty values added after signing keep the signature valid, and they decide nothing.
    (tampered,), ctx = _analyze({**card, **added}, agent_card_jwks_url=JWKS_URL)
    agent_card = tampered.metadata["agent_card"]
    assert agent_card["signature"] == "verified" and agent_card["security_schemes"] is None
    assert "no-auth-declared" in tampered.tags and not ctx.stats.incomplete
    # The forms differ only by empty values, and the one a signature covers is returned with it.
    forms = a2a.signed_forms({**card, **added})
    assert [payload for _, payload in forms] == a2a.signed_payloads({**card, **added})
    assert all(canonicalize(form) == payload for form, payload in forms)


def test_the_specification_default_value_example_is_a_signed_payload() -> None:
    fragment = {
        "name": "Example Agent",
        "description": "",
        "capabilities": {"streaming": False, "pushNotifications": False, "extensions": []},
        "skills": [],
        "signatures": [{"protected": "e30", "signature": "c2ln"}],
    }
    payloads = a2a.signed_payloads(fragment)
    # The canonical output printed in A2A specification section 8.4.1.
    assert (
        b'{"capabilities":{"pushNotifications":false,"streaming":false},'
        b'"description":"","name":"Example Agent","skills":[]}'
    ) in payloads
    assert len(payloads) == 3 and all(b"signatures" not in p for p in payloads)
    assert a2a.signed_payloads({"name": "x", "skills": [{"id": "a"}]}) == [
        b'{"name":"x","skills":[{"id":"a"}]}'
    ]


def test_payload_forms_refuse_nesting_beyond_the_canonicalization_limit() -> None:
    deep: Any = "leaf"
    for _ in range(MAX_DEPTH + 2):
        deep = [deep]
    with pytest.raises(CanonicalizationError):
        a2a.signed_payloads({"name": "x", "deep": deep})
    with pytest.raises(CanonicalizationError):
        a2a._without_empty_optional(deep, a2a._NO_FIELDS, 0)


# ------------------------------------------------------- protocol versions


@pytest.mark.parametrize("version", ["2.0", "9.9-experimental"])
def test_a_card_declaring_an_unknown_protocol_version_is_kept_and_incomplete(version: str) -> None:
    card = copy.deepcopy(CARD_V1)
    card["protocolVersion"] = version
    for interface in card["supportedInterfaces"]:
        interface["protocolVersion"] = version
    (finding,), ctx = _analyze(card)
    assert finding.kind == Kind.AGENT
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert ctx.stats.warnings == [
        "endpoint.mcp: A2A Agent Card at https://planner.agents.example.com declares a protocol version "
        "other than 0.x or 1.x; its fields were read as A2A 0.3 and 1.0 fields"
    ]


def test_known_protocol_versions_keep_the_scan_complete() -> None:
    for card in (CARD_V1, CARD_V03, {**CARD_V03, "protocolVersion": "0.2.5"}):
        _, ctx = _analyze(copy.deepcopy(card))
        assert not ctx.stats.incomplete and not ctx.stats.warnings


# ----------------------------------------------------------- record export


def test_export_withholds_grpc_userinfo_that_live_verification_still_reads(
    routes: _Routes, signer, trusted_keys, tmp_path: Path
) -> None:
    card = copy.deepcopy(CARD_V1)
    card["supportedInterfaces"].append(
        {
            "url": f"{USERINFO}@grpc.agents.example.com:443",
            "protocolBinding": "GRPC",
            "protocolVersion": "1.0",
        }
    )
    routes.routes[WELL_KNOWN] = _response(200, _signed(signer, card))
    dump = tmp_path / "endpoint_mcp.jsonl"
    (live,), ctx = _run(agent_card_urls=[ORIGIN], agent_card_jwks_url=JWKS_URL, _dump_path=str(dump))
    assert live.metadata["agent_card"]["signature"] == "verified" and ctx.dump_path == str(dump)
    exported = dump.read_text(encoding="utf-8")
    assert USERINFO not in exported and "[REDACTED]@grpc.agents.example.com:443" in exported
    (replayed,), _ = _run(input=str(dump), agent_card_jwks_url=JWKS_URL)
    assert replayed.id == live.id
    assert replayed.metadata["agent_card"]["signature"] == "present-unverified"


@pytest.mark.parametrize(
    ("value", "exported"),
    [
        (f"{USERINFO}@grpc.agents.example.com:443", "[REDACTED]@grpc.agents.example.com:443"),
        ("deploy@grpc.agents.example.com:8443", "[REDACTED]@grpc.agents.example.com:8443"),
        (f"{USERINFO}@[2001:db8::1]:443", "[REDACTED]@[2001:db8::1]:443"),
        ("ops@agents.example.com", "ops@agents.example.com"),
        ("grpc.agents.example.com:443", "grpc.agents.example.com:443"),
        ("deploy@grpc.agents.example.com:443/path", "deploy@grpc.agents.example.com:443/path"),
        ("deploy@[2001:db8::1", "deploy@[2001:db8::1"),
        (f"https://{USERINFO}@agents.example.com/a2a", f"https://{USERINFO}@agents.example.com/a2a"),
    ],
)
def test_export_card_withholds_only_scheme_less_address_userinfo(value: str, exported: str) -> None:
    card = {"url": value, "supportedInterfaces": [{"url": value}], "provider": {"url": value}, "n": 1}
    assert a2a.export_card(card) == {
        "url": exported,
        "supportedInterfaces": [{"url": exported}],
        "provider": {"url": exported},
        "n": 1,
    }


def test_export_card_withholds_nesting_beyond_the_canonicalization_limit() -> None:
    deep: Any = "leaf"
    for _ in range(MAX_DEPTH + 2):
        deep = [deep]
    exported = a2a.export_card({"deep": deep})
    assert "leaf" not in json.dumps(exported) and "[REDACTED]" in json.dumps(exported)


def test_tool_list_records_are_exported_unchanged() -> None:
    record = {"server": "https://mcp.agents.example.com", "tools": [{"name": "search"}]}
    assert MCPInventoryConnector(ConnectorContext())._export_record(record) is record
