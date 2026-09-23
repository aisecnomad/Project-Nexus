"""JWT verification must never trust header.alg or PyJWKClient."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.utils.jwks import ALLOWED_JWT_ALGS, verify_against_jwks


def test_allowed_algs_are_asymmetric_only():
    assert ALLOWED_JWT_ALGS == ("RS256", "ES256", "EdDSA", "PS256")
    assert "HS256" not in ALLOWED_JWT_ALGS
    assert "none" not in ALLOWED_JWT_ALGS


def test_source_never_passes_header_alg_as_algorithms_list():
    source = Path("shadowscan/connectors/identity/jwt.py").read_text(encoding="utf-8")
    helper = Path("shadowscan/utils/jwks.py").read_text(encoding="utf-8")
    for text in (source, helper):
        assert "algorithms=[header.get(" not in text
        assert "algorithms=[header[" not in text
        assert "PyJWKClient" not in text


def test_hs256_header_is_rejected_before_jwks_fetch():
    with patch("shadowscan.utils.http.HttpClient.get_json") as fetch:
        with pytest.raises(ValueError, match="allowlist"):
            verify_against_jwks("a.b.c", "https://issuer.example/.well-known/jwks.json", {"alg": "HS256", "kid": "k1"})
        fetch.assert_not_called()


def test_none_alg_is_rejected():
    with pytest.raises(ValueError, match="allowlist"):
        verify_against_jwks("a.b.c", "https://issuer.example/jwks", {"alg": "none"})


def test_jwks_fetch_uses_httpclient():
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": []}) as fetch:
        with pytest.raises(ValueError, match="matching signature key"):
            verify_against_jwks("a.b.c", "https://issuer.example/.well-known/jwks.json", {"alg": "RS256", "kid": "k1"})
        fetch.assert_called_once()


def test_metadata_jwks_url_is_rejected():
    with pytest.raises(ValueError, match="Refusing"):
        verify_against_jwks("a.b.c", "https://169.254.169.254/jwks", {"alg": "RS256"})


def test_issuer_host_must_match_jwks_host():
    with pytest.raises(ValueError, match="issuer host"):
        verify_against_jwks(
            "a.b.c",
            "https://evil.example/jwks",
            {"alg": "RS256"},
            issuer="https://login.example.com/",
        )


def test_symmetric_jwk_is_ignored():
    document = {"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "k1", "alg": "HS256", "use": "sig"}]}
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value=document):
        with pytest.raises(ValueError, match="matching signature key"):
            verify_against_jwks("a.b.c", "https://issuer.example/jwks", {"alg": "RS256", "kid": "k1"})


def test_analyze_token_records_unverified_for_bad_alg(index):
    connector = JwtConnector(ConnectorContext(index=index, config={"jwks_url": "https://issuer.example/jwks"}))
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlIn0."
    finding = connector.analyze_token(token, jwks_url="https://issuer.example/jwks")
    assert finding is not None
    assert finding.metadata.get("verified") is False
    assert finding.resource.startswith("jwt:")
