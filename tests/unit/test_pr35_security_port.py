"""Credential diagnostics and issuer labels retained during PR #35 reconciliation."""

from __future__ import annotations

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.identity.jwt import _issuer_family
from shadowscan.utils.redaction import REDACTED, sanitize


@pytest.mark.parametrize("key", ["api_token", "foundry_token", "github_token"])
def test_specific_credential_names_redact_record_and_diagnostic(key):
    secret = "synthetic-opaque-credential-value-0123456789"
    record = sanitize({key: secret, "status": f"provider rejected {secret}"})
    assert record[key] == REDACTED
    assert secret not in record["status"]
    ctx = ConnectorContext(config={key: secret})
    assert secret not in ctx.sanitize_message(f"provider rejected {secret}")


def test_short_credential_still_withholds_diagnostic_by_default():
    record, diagnostic = sanitize(({"api_token": "a"}, "provider rejected a"))
    assert diagnostic == REDACTED
    assert REDACTED in record.values()


def test_usage_metric_names_stay_visible():
    metrics = {"token_count": 12, "input_tokens": 3, "output_tokens": 9}
    assert sanitize(metrics) == metrics


def test_github_fallback_token_is_registered_for_diagnostic_redaction(index, monkeypatch):
    secret = "synthetic-opaque-github-cli-token-0123456789"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", secret)
    ctx = ConnectorContext(config={}, index=index)
    connector = GitHubConnector(ctx)
    assert connector.token == secret
    assert ctx.sanitize_message(f"provider rejected {secret}") == f"provider rejected {REDACTED}"


@pytest.mark.parametrize("claim", [
    "kubernetes.io/serviceaccount/namespace",
    "kubernetes.io/serviceaccount/secret.name",
    "kubernetes.io/serviceaccount/service-account.name",
    "kubernetes.io/serviceaccount/service-account.uid",
])
def test_exact_legacy_kubernetes_claims_identify_the_issuer_family(claim):
    assert _issuer_family("https://issuer.example", {claim: "default"}) == "kubernetes"


@pytest.mark.parametrize("claim", [
    "kubernetes.io/arbitrary",
    "kubernetes.io/serviceaccount/namespace/extra",
    "kubernetes.io.evil/serviceaccount/namespace",
    "kubernetes.io%2Fserviceaccount%2Fnamespace",
])
def test_kubernetes_claim_lookalikes_do_not_identify_the_issuer_family(claim):
    assert _issuer_family("https://issuer.example", {claim: "default"}) == "custom"


@pytest.mark.parametrize("claims", [
    {"kubernetes.io": {"namespace": "default"}},
    {"kubernetes.io/serviceaccount/namespace": "default"},
])
def test_structured_and_legacy_kubernetes_claims_keep_the_display_label(claims):
    assert _issuer_family("https://issuer.example", claims) == "kubernetes"


@pytest.mark.parametrize("claims", [
    {"kubernetes.io": {}},
    {"kubernetes.io": "not a structured claim"},
    {"kubernetes.io/serviceaccount/namespace": "  "},
])
def test_malformed_kubernetes_claims_do_not_set_the_display_label(claims):
    assert _issuer_family("https://issuer.example", claims) == "custom"
