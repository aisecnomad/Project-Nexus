"""Asymmetric verification with operator-supplied trust and bounded fetching."""

from __future__ import annotations

import base64
import json
from unittest.mock import Mock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.identity import jwt as jwt_module
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.models import ScanStats, now_iso
from shadowscan.utils.jwks import (
    ALLOWED_JWT_ALGS,
    MAX_JWKS_BYTES,
    verification_algorithms,
    verify_against_jwks,
)

JWKS_URL = "https://keys.example/jwks"
ISSUER = "https://issuer.example/tenant"


@pytest.fixture(scope="module")
def rsa_private():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def signed(private, algorithm="RS256", claims=None, kid="key-1"):
    header = {"kid": kid} if kid is not None else {}
    token = jwt.encode(
        claims or {"sub": "agent", "iss": ISSUER}, private, algorithm=algorithm, headers=header
    )
    jwk = json.loads(jwt.algorithms.get_default_algorithms()[algorithm].to_jwk(private.public_key()))
    jwk.update({"alg": algorithm, "use": "sig", "key_ops": ["verify"]})
    if kid is not None:
        jwk["kid"] = kid
    return token, jwk, jwt.get_unverified_header(token)


def check(token, jwk, header, **kwargs):
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [jwk]}) as fetch:
        result = verify_against_jwks(token, JWKS_URL, header, **kwargs)
        fetch.assert_called_once_with(JWKS_URL, max_bytes=MAX_JWKS_BYTES)
        return result


def test_allowed_algs_are_asymmetric_only():
    assert ALLOWED_JWT_ALGS == ("RS256", "ES256", "EdDSA", "PS256")
    assert verification_algorithms(["RS256", "RS256"]) == ("RS256",)


@pytest.mark.parametrize("configured", [[], "RS256", ["HS256"], ["none"], [None], ["RS256", "HS256"]])
def test_operator_can_only_narrow_algorithm_allowlist(configured):
    with pytest.raises(ValueError):
        verification_algorithms(configured)


@pytest.mark.parametrize("algorithm", ["HS256", "none", "RS512", None, ["RS256"]])
def test_disallowed_header_is_rejected_before_jwks_fetch(algorithm):
    with patch("shadowscan.utils.http.HttpClient.get_json") as fetch:
        with pytest.raises(ValueError, match="allowlist"):
            verify_against_jwks("a.b.c", JWKS_URL, {"alg": algorithm})
        fetch.assert_not_called()


@pytest.mark.parametrize("algorithm", ALLOWED_JWT_ALGS)
def test_supported_asymmetric_signatures_verify(algorithm, rsa_private):
    private = (
        ec.generate_private_key(ec.SECP256R1())
        if algorithm == "ES256"
        else ed25519.Ed25519PrivateKey.generate()
        if algorithm == "EdDSA"
        else rsa_private
    )
    token, jwk, header = signed(private, algorithm)
    assert check(token, jwk, header, expected_issuer=ISSUER)


def test_operator_algorithm_restriction_is_enforced(rsa_private):
    token, jwk, header = signed(rsa_private)
    with pytest.raises(ValueError, match="allowlist"):
        check(token, jwk, header, allowed_algorithms=["ES256"])


def test_signature_verification_uses_expected_issuer_not_token_host(rsa_private):
    token, jwk, header = signed(rsa_private, claims={"sub": "agent", "iss": "https://attacker.example"})
    # The operator explicitly trusts JWKS_URL; signature-only analysis can
    # inspect any issuer claim, without inferring trust from that claim.
    assert check(token, jwk, header)
    with pytest.raises(jwt.InvalidIssuerError):
        check(token, jwk, header, expected_issuer=ISSUER)


def test_expected_issuer_and_jwks_can_have_different_hosts(rsa_private):
    token, jwk, header = signed(rsa_private)
    assert check(token, jwk, header, expected_issuer=ISSUER)


@pytest.mark.parametrize(
    "alteration",
    [
        {"use": "enc"},
        {"key_ops": ["sign"]},
        {"key_ops": ["verify", "sign"]},
        {"key_ops": "verify"},
        {"alg": "PS256"},
        {"kty": "oct", "k": "c2VjcmV0"},
        {"d": None},
        {"p": "private-material"},
        {"n": "a" * 2000},
        {"e": "a" * 1000},
    ],
)
def test_ineligible_or_private_keys_are_rejected(rsa_private, alteration):
    token, jwk, header = signed(rsa_private)
    jwk.update(alteration)
    with pytest.raises(ValueError, match="matching signature key"):
        check(token, jwk, header)


@pytest.mark.parametrize("kid", ["key-1", None])
def test_ambiguous_key_selection_is_rejected(rsa_private, kid):
    token, jwk, header = signed(rsa_private, kid=kid)
    with (
        patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [jwk, dict(jwk)]}),
        pytest.raises(ValueError, match="ambiguous"),
    ):
        verify_against_jwks(token, JWKS_URL, header)


def test_wrong_signature_is_rejected(rsa_private):
    token, _, header = signed(rsa_private)
    _, other_jwk, _ = signed(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    with pytest.raises(jwt.InvalidSignatureError):
        check(token, other_jwk, header)


def test_jwks_key_count_limit():
    with (
        patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [{}] * 65}),
        pytest.raises(ValueError, match="too many keys"),
    ):
        verify_against_jwks("a.b.c", JWKS_URL, {"alg": "RS256"})


def test_metadata_jwks_url_is_rejected():
    with pytest.raises(ValueError, match="Refusing"):
        verify_against_jwks("a.b.c", "https://169.254.169.254/jwks", {"alg": "RS256"})


def test_analyze_token_records_unverified_for_bad_alg(index):
    connector = JwtConnector(ConnectorContext(index=index, config={"jwks_url": JWKS_URL}))
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlIn0."
    finding = connector.analyze_token(token, jwks_url=JWKS_URL)
    assert finding is not None
    assert finding.metadata["verified"] is False
    assert finding.resource.startswith("jwt:")


def test_output_says_when_the_signature_was_not_checked(index, rsa_private, tmp_path):
    # Without jwks_url there was no "verified" key and no jwt:signature
    # evidence, so an unsigned or tampered token read like a checked one.
    claims = {"iss": "https://sts.windows.net/tenant/", "sub": "agent-runner", "azp": "openai-agent"}
    genuine, _, _ = signed(rsa_private, claims=claims)
    header, _, signature = genuine.split(".")
    forged = {**claims, "sub": "someone-else", "scp": "Mail.ReadWrite"}
    tampered = ".".join(
        [header, base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode(), signature]
    )
    tokens = [genuine, tampered]
    export = tmp_path / "tokens.json"
    export.write_text(json.dumps([{"token": token} for token in tokens]))
    connector = JwtConnector(ConnectorContext(index=index, config={"input": str(export)}))
    findings = connector.run()
    assert len(findings) == 2
    for finding in findings:
        assert finding.metadata["verified"] is False
        assert finding.metadata["verification_scope"] == "none"
        assert finding.metadata["issuer_verified"] is False
        (signature,) = [e for e in finding.evidence if e.signal == "jwt:signature"]
        assert signature.description.startswith("signature not checked")
        assert len(finding.resource) == len("jwt:") + 16  # digest length unchanged
    report = json.dumps([finding.to_dict() for finding in findings])
    assert not any(token.rstrip(".") in report for token in tokens)
    assert not any(token.split(".")[1] in report for token in tokens)


@pytest.mark.parametrize(
    "expected_issuer,scope", [(None, "signature-only"), (ISSUER, "signature-and-issuer")]
)
def test_connector_wires_verifier_and_labels_scope(index, rsa_private, expected_issuer, scope):
    token, jwk, _ = signed(
        rsa_private, claims={"sub": "agent", "iss": ISSUER, "exp": 1, "aud": "unvalidated"}
    )
    config = {"jwks_url": JWKS_URL, "allowed_algorithms": ["RS256"]}
    if expected_issuer:
        config["expected_issuer"] = expected_issuer
    connector = JwtConnector(ConnectorContext(index=index, config=config))
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [jwk]}):
        finding = next(iter(connector.analyze([{"token": token}])))
    assert finding.metadata["verified"] is True
    assert finding.metadata["verification_scope"] == scope
    assert finding.metadata["issuer_verified"] is bool(expected_issuer)
    assert finding.metadata["authorization_validated"] is False
    assert "NOT validated" in next(e.description for e in finding.evidence if e.signal == "jwt:signature")


def test_invalid_verification_configuration_fails_the_connector(index):
    connector = JwtConnector(ConnectorContext(index=index, config={"allowed_algorithms": ["HS256"]}))
    with pytest.raises(ConnectorError, match="allowlist"):
        list(connector.analyze([]))


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


def _ctx(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at=now_iso())
    return ctx


def _unsigned(claims: dict) -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}."


def test_jwt_hostile_numeric_claims_do_not_abort_other_tokens(index, monkeypatch):
    tokens = [
        _unsigned(
            {"sub": "svc-a", "iss": "https://issuer.example", "iat": 1_700_000_000, "exp": 1_700_003_600}
        ),
        _unsigned({"sub": "svc-b", "iss": "https://issuer.example", "iat": 10**400, "exp": "1" * 5000}),
        _unsigned({"sub": "svc-c", "iss": "https://issuer.example"}),
    ]
    ctx = _ctx(index, tokens=tokens)
    assert len(JwtConnector(ctx).run()) == 3  # huge numbers are unparsable timestamps, not crashes
    ctx = _ctx(index, tokens=tokens)
    connector = JwtConnector(ctx)
    original = connector.analyze_token

    def failing(token, **kwargs):
        if token == tokens[1]:
            raise ValueError("synthetic")
        return original(token, **kwargs)

    monkeypatch.setattr(connector, "analyze_token", failing)
    assert len(connector.run()) == 2
    assert any("token analysis failed (ValueError)" in warning for warning in ctx.stats.warnings)


def test_jwks_is_fetched_once_per_run(index, monkeypatch):
    fetches: list[str] = []

    def fake_fetch(url):
        fetches.append(url)
        return {"keys": []}

    monkeypatch.setattr(jwt_module, "fetch_jwks", fake_fetch)

    def encoded(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    tokens = [
        f"{encoded({'alg': 'RS256'})}.{encoded({'sub': f'svc-{i}', 'iss': 'https://issuer.example'})}.AAAA"
        for i in range(3)
    ]
    ctx = _ctx(index, tokens=tokens, jwks_url="https://keys.example/jwks")
    findings = JwtConnector(ctx).run()
    assert len(findings) == 3 and fetches == ["https://keys.example/jwks"]
    assert all(f.metadata.get("verified") is False for f in findings)
