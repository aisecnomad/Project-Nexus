"""Issuer labels are hostname hints, never proofs of identity or authorization."""
from __future__ import annotations

import pytest

from shadowscan.connectors.identity.jwt import _issuer_family


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
