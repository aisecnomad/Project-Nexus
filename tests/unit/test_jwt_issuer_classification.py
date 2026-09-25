"""Issuer labels are hostname hints, never proofs of identity or authorization."""
from __future__ import annotations

import jwt
import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.identity.jwt import JwtConnector, _issuer_family


@pytest.mark.parametrize("issuer,family", [
    ("https://login.microsoftonline.com/tenant/v2.0", "entra"),
    ("https://sts.windows.net/tenant/", "entra"),
    ("https://tenant.okta.com/oauth2/default", "okta"),
    ("https://tenant.eu.auth0.com/", "auth0"),
    ("https://accounts.google.com", "google"),
    ("accounts.google.com", "google"),
    ("https://cognito-idp.eu-west-1.amazonaws.com/pool", "cognito"),
    ("https://token.actions.githubusercontent.com", "github-actions"),
    ("https://gitlab.com", "gitlab"),
    ("https://id.example/realms/production", "keycloak"),
    ("spiffe://example.org/agent", "spiffe"),
])
def test_known_issuer_namespace(issuer, family):
    assert _issuer_family(issuer, {}) == family


@pytest.mark.parametrize("issuer", [
    "https://evilgoogle.example", "https://accounts.google.com.evil.example",
    "https://evil.example/accounts.google.com", "https://evil.example?issuer=login.microsoftonline.com",
    "https://login.microsoftonline.com.evil.example/", "https://notokta.com/",
    "https://tenant.auth0.com.evil.example/", "https://cognito-idp.evil.example/",
    "https://github.com.evil.example", "https://gitlab.attacker.example/",
    "https://evil.example/?issuer=spiffe://example.org/agent",
    "https://accounts.google.com@evil.example", "https://evil@accounts.google.com",
    "https://[invalid/", "not-a-url-google",
])
def test_attacker_controlled_substrings_do_not_impersonate_provider(issuer):
    assert _issuer_family(issuer, {}) == "custom"


def test_generic_grant_or_tenant_claims_do_not_name_a_provider():
    claims = {"gty": "client-credentials", "tid": "tenant", "aud": "api", "appid": "app"}
    assert _issuer_family("https://id.example", claims) == "custom"
    assert _issuer_family("", claims) == "unknown"


def test_kubernetes_claim_namespace_does_not_match_arbitrary_claim_text():
    assert _issuer_family("https://id.example", {"note": "kubernetes.io"}) == "custom"
    assert _issuer_family("https://cluster.example", {"kubernetes.io": {"pod": "agent"}}) == "kubernetes"


def test_kubernetes_claim_namespace_segment_is_exact():
    assert _issuer_family(
        "https://id.example",
        {"kubernetes.io/serviceaccount/namespace": "default"},
    ) == "kubernetes"
    assert _issuer_family(
        "https://id.example",
        {"kubernetes.ioevil/serviceaccount/namespace": "default"},
    ) == "custom"


@pytest.mark.parametrize("claim", [
    "kubernetes.io/serviceaccount/namespace",
    "kubernetes.io/serviceaccount/secret.name",
    "kubernetes.io/serviceaccount/service-account.name",
    "kubernetes.io/serviceaccount/service-account.uid",
])
def test_legacy_kubernetes_claims_use_exact_field_names(claim):
    assert _issuer_family("kubernetes/serviceaccount", {claim: "default"}) == "kubernetes"


@pytest.mark.parametrize("claim", [
    "notkubernetes.io/serviceaccount/namespace",
    "kubernetes.io.evil.example/serviceaccount/namespace",
    "https://kubernetes.io/serviceaccount/namespace",
    "https://evil.example/kubernetes.io/serviceaccount/namespace",
    "kubernetes.io/serviceaccount/namespace/extra",
    "kubernetes.io%2Fserviceaccount%2Fnamespace",
    "kubernetes.io/arbitrary",
    "kubernetes.io/",
])
def test_kubernetes_claim_lookalikes_are_not_service_account_fields(claim):
    assert _issuer_family("https://id.example", {claim: "default"}) == "custom"


@pytest.mark.parametrize("claims", [
    {"kubernetes.io": "https://kubernetes.io"},
    {"kubernetes.io": []},
    {"kubernetes.io": {}},
    {"kubernetes.io/serviceaccount/namespace": {}},
    {"kubernetes.io/serviceaccount/namespace": ""},
    {"kubernetes.io/serviceaccount/namespace": "  "},
    {"note": {"kubernetes.io": {"namespace": "default"}}},
])
def test_kubernetes_claim_hints_require_the_expected_top_level_shape(claims):
    assert _issuer_family("https://id.example", claims) == "custom"


def test_kubernetes_claim_label_does_not_establish_signature_or_issuer_trust(index, monkeypatch):
    def unexpected_fetch(url):
        pytest.fail("an unsigned token must not fetch a trusted key set")

    monkeypatch.setattr("shadowscan.connectors.identity.jwt.fetch_jwks", unexpected_fetch)
    ctx = ConnectorContext(index=index, config={"expected_issuer": "https://trusted.example"})
    token = jwt.encode({
        "iss": "https://untrusted.example", "sub": "system:serviceaccount:default:agent",
        "kubernetes.io": {"namespace": "default", "serviceaccount": {"name": "agent", "uid": "one"}},
    }, key=None, algorithm="none")
    finding = JwtConnector(ctx).analyze_token(token, jwks_url="https://keys.example/jwks")
    assert finding.metadata["issuer_family"] == "kubernetes"
    assert finding.metadata["verified"] is False
    assert finding.metadata["issuer_verified"] is False
    assert finding.metadata["authorization_validated"] is False
