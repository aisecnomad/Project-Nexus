"""Asymmetric verification with operator-supplied trust and bounded fetching."""

from __future__ import annotations

import json
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.identity.jwt import JwtConnector
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
    token = jwt.encode(claims or {"sub": "agent", "iss": ISSUER}, private, algorithm=algorithm, headers=header)
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
    private = ec.generate_private_key(ec.SECP256R1()) if algorithm == "ES256" else ed25519.Ed25519PrivateKey.generate() if algorithm == "EdDSA" else rsa_private
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


@pytest.mark.parametrize("alteration", [{"use": "enc"}, {"key_ops": ["sign"]}, {"key_ops": ["verify", "sign"]}, {"key_ops": "verify"}, {"alg": "PS256"}, {"kty": "oct", "k": "c2VjcmV0"}, {"d": None}, {"p": "private-material"}, {"n": "a" * 2000}, {"e": "a" * 1000}])
def test_ineligible_or_private_keys_are_rejected(rsa_private, alteration):
    token, jwk, header = signed(rsa_private)
    jwk.update(alteration)
    with pytest.raises(ValueError, match="matching signature key"):
        check(token, jwk, header)


@pytest.mark.parametrize("kid", ["key-1", None])
def test_ambiguous_key_selection_is_rejected(rsa_private, kid):
    token, jwk, header = signed(rsa_private, kid=kid)
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [jwk, dict(jwk)]}), pytest.raises(ValueError, match="ambiguous"):
        verify_against_jwks(token, JWKS_URL, header)


def test_wrong_signature_is_rejected(rsa_private):
    token, _, header = signed(rsa_private)
    _, other_jwk, _ = signed(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    with pytest.raises(jwt.InvalidSignatureError):
        check(token, other_jwk, header)


def test_jwks_key_count_limit():
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [{}] * 65}), pytest.raises(ValueError, match="too many keys"):
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


@pytest.mark.parametrize("expected_issuer,scope", [(None, "signature-only"), (ISSUER, "signature-and-issuer")])
def test_connector_wires_verifier_and_labels_scope(index, rsa_private, expected_issuer, scope):
    token, jwk, _ = signed(rsa_private, claims={"sub": "agent", "iss": ISSUER, "exp": 1, "aud": "unvalidated"})
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
