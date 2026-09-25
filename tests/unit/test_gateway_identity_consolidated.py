"""Security boundaries retained while combining independent hardening work."""

from __future__ import annotations

import json
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import Event, GatewayLogConnector
from shadowscan.connectors.identity.auth0 import Auth0Connector
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.connectors.identity.okta import OktaConnector
from shadowscan.models import ScanStats
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.jwks import verify_against_jwks

JWKS_URL = "https://keys.example/jwks"
ISSUER = "https://issuer.example/tenant"


def context(index, **config):
    ctx = ConnectorContext(index=index, config=config)
    ctx.stats = ScanStats(connector="test", started_at="now")
    return ctx


@pytest.fixture(scope="module")
def signed_token():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({"sub": "agent", "iss": ISSUER}, key, algorithm="RS256", headers={"kid": "one"})
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "one", "alg": "RS256", "use": "sig"})
    return token, {"keys": [jwk]}


def test_jwks_cache_is_per_analysis_and_preserves_issuer_validation(index, monkeypatch, signed_token):
    token, document = signed_token
    fetch = Mock(return_value=document)
    monkeypatch.setattr("shadowscan.connectors.identity.jwt.fetch_jwks", fetch)
    ctx = context(index, jwks_url=JWKS_URL, expected_issuer=ISSUER)
    connector = JwtConnector(ctx)
    for _ in range(2):
        findings = list(connector.analyze([{"token": token}] * 3))
        assert len(findings) == 3
        assert all(f.metadata["issuer_verified"] for f in findings)
    assert fetch.call_count == 2
    ctx.config["expected_issuer"] = "https://different.example"
    assert not next(iter(connector.analyze([{"token": token}]))).metadata["verified"]
    assert ctx.stats.incomplete


def test_direct_token_analysis_can_use_jwks(index, monkeypatch, signed_token):
    token, document = signed_token
    fetch = Mock(return_value=document)
    monkeypatch.setattr("shadowscan.connectors.identity.jwt.fetch_jwks", fetch)
    connector = JwtConnector(context(index, expected_issuer=ISSUER))
    assert connector.analyze_token(token, jwks_url=JWKS_URL).metadata["verified"]
    fetch.assert_called_once_with(JWKS_URL)


def test_failed_jwks_fetch_is_not_retried_for_every_token(index, monkeypatch, signed_token):
    token, _ = signed_token
    fetch = Mock(side_effect=ValueError("unavailable"))
    monkeypatch.setattr("shadowscan.connectors.identity.jwt.fetch_jwks", fetch)
    ctx = context(index, jwks_url=JWKS_URL)
    connector = JwtConnector(ctx)
    findings = list(connector.analyze([{"token": token}] * 3))
    assert len(findings) == 3 and all(not f.metadata["verified"] for f in findings)
    fetch.assert_called_once_with(JWKS_URL)
    assert ctx.stats.incomplete
    # Reusing a failure must not accumulate every previous token's stack.
    list(connector.analyze([{"token": token}] * 100))
    traceback = connector._jwks_cache[JWKS_URL].__traceback__
    depth = 0
    while traceback:
        depth += 1
        traceback = traceback.tb_next
    assert depth < 10


def test_unsigned_tokens_never_fetch_jwks(index, monkeypatch):
    fetch = Mock(side_effect=AssertionError("unsigned tokens must not fetch keys"))
    monkeypatch.setattr("shadowscan.connectors.identity.jwt.fetch_jwks", fetch)
    token = jwt.encode({"sub": "agent", "iss": ISSUER}, key=None, algorithm="none")
    findings = list(JwtConnector(context(index, jwks_url=JWKS_URL)).analyze([{"token": token}]))
    assert len(findings) == 1 and findings[0].metadata["verified"] is False
    fetch.assert_not_called()


@pytest.mark.parametrize("header", [{"alg": "HS256"}, {"alg": "none"}, {"alg": "RS256", "crit": ["custom"]}])
def test_document_loader_cannot_bypass_header_validation(header):
    loader = Mock()
    with pytest.raises(ValueError):
        verify_against_jwks("a.b.c", JWKS_URL, header, document_loader=loader)
    loader.assert_not_called()


def test_gateway_overflow_is_atomic_and_keeps_later_callers(index):
    ctx = context(index, format="litellm")
    records = [
        {"api_key": "a", "model": "gpt-4o", "spend": 1e308},
        {"api_key": "a", "model": "gpt-4o", "spend": 1e308},
        {"api_key": "b", "model": "gpt-4o", "spend": 1},
    ]
    findings = list(GatewayLogConnector(ctx).analyze(records))
    assert len(findings) == 2
    assert sum(f.metadata["events"] for f in findings) == 2
    assert sorted(f.metadata["cost"] for f in findings) == [1, 1e308]
    json.dumps([f.metadata for f in findings], allow_nan=False)
    assert ctx.stats.incomplete


def test_gateway_json_lines_recover_after_corrupt_first_row(index, tmp_path):
    source = tmp_path / "gateway.json"
    source.write_text('{broken\n' + json.dumps({"api_key": "a", "model": "gpt-4o", "spend": 1}) + '\n')
    ctx = context(index, input=str(source), format="litellm")
    findings = GatewayLogConnector(ctx).run()
    assert len(findings) == 1 and findings[0].metadata["events"] == 1
    assert ctx.stats.incomplete


def test_gateway_usage_interval_details_are_bounded_and_totals_preserved(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_DISTINCT_KEYS", 2)
    callers = {}
    event = Event("principal:worker", "principal", "worker", aggregated=True, request_count=10)
    for _ in range(5):
        GatewayLogConnector._accumulate(callers, event)
    caller = next(iter(callers.values()))
    finding = GatewayLogConnector(context(index))._finding(caller)
    assert finding.metadata["events"] == 50
    assert len(finding.metadata["usage_intervals"]) == 2
    assert finding.metadata["usage_intervals_dropped"] == 3


def test_gateway_distribution_limit_reports_lost_classification_and_owner(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_DISTINCT_KEYS", 2)
    ctx = context(index, format="litellm")
    values = [("unknown-a", "a"), ("unknown-b", "b")] + [("gpt-4o", "real-owner")] * 5
    # Previously retained labels must keep accumulating after the limit.
    values.append(("unknown-a", "a"))
    records = [{"api_key": "one", "model": model, "user": user} for model, user in values]
    finding, = list(GatewayLogConnector(ctx).analyze(records))
    assert finding.metadata["events"] == 8
    assert finding.metadata["distribution_events_dropped"] == {"models": 5, "end_users": 5}
    assert finding.metadata["models"] == {"unknown-a": 2, "unknown-b": 1}
    assert finding.metadata["end_users"] == {"a": 2, "b": 1}
    assert finding.metadata["classification_incomplete"] is True
    assert finding.metadata["distribution_limit"] == 2
    assert finding.owner is None
    assert "<other>" not in finding.models and "<other>" not in finding.title
    assert ctx.stats.incomplete
    assert any("distribution limit" in warning for warning in ctx.stats.warnings)


def test_gateway_all_distribution_limits_count_omitted_requests_without_labels(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_DISTINCT_KEYS", 2)
    callers = {}
    for n in range(5):
        event = Event(
            "principal:worker", "principal", "worker", request_count=10,
            model=f"model-{n}", provider=f"provider-{n}", host=f"host-{n}.example",
            user_agent=f"agent-{n}", ip=f"10.0.0.{n}", user=f"user-{n}",
            team=f"team-{n}", path=f"/operation-{n}",
        )
        GatewayLogConnector._accumulate(callers, event)
    caller = next(iter(callers.values()))
    finding = GatewayLogConnector(context(index))._finding(caller)
    dimensions = ("models", "providers", "hosts", "user_agents", "source_ips", "end_users", "teams", "operations")
    assert finding.metadata["distribution_events_dropped"] == dict.fromkeys(dimensions, 30)
    assert finding.metadata["events"] == 50
    assert all(len(getattr(caller, attr)) == 2 for attr in (
        "models", "providers", "hosts", "user_agents", "ips", "users", "teams", "paths",
    ))
    for dimension in dimensions:
        assert sum(finding.metadata[dimension].values()) + finding.metadata["distribution_events_dropped"][dimension] == 50
    assert finding.owner is None
    assert finding.metadata["classification_incomplete"] is True


def test_gateway_final_matching_timeout_preserves_other_callers(index, monkeypatch):
    original = index.match_model

    def match(model):
        if model == "bad-model":
            raise MatchTimeoutError("signature matching timed out (custom.pattern)")
        return original(model)

    monkeypatch.setattr(index, "match_model", match)
    ctx = context(index, format="generic")
    findings = list(GatewayLogConnector(ctx).analyze([
        {"service": "a", "model": "bad-model"},
        {"service": "b", "model": "gpt-4o"},
    ]))
    assert len(findings) == 1 and findings[0].metadata["caller"] == "b"
    assert ctx.stats.incomplete
    assert any("custom.pattern" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("connector_class,method,records", [
    (Auth0Connector, "_client_finding", [{"client_id": "a"}, {"client_id": "b", "app_type": "non_interactive"}]),
    (OktaConnector, "_app_finding", [{"id": "a"}, {"id": "b", "signOnMode": "OPENID_CONNECT", "settings": {"oauthClient": {"application_type": "service"}}}]),
])
def test_identity_match_timeout_is_isolated(index, monkeypatch, connector_class, method, records):
    ctx = context(index)
    connector = connector_class(ctx)
    original = getattr(connector, method)
    calls = 0

    def analyze(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise MatchTimeoutError("signature matching timed out (custom.pattern)")
        return original(*args)

    monkeypatch.setattr(connector, method, analyze)
    findings = list(connector.analyze(records))
    assert len(findings) == 1 and findings[0].resource.endswith(":b")
    assert ctx.stats.incomplete
    assert any("custom.pattern" in warning for warning in ctx.stats.warnings)
