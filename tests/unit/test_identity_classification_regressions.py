"""Identity classification: privileged-scope names, agent claims, workload issuers, unverified tokens."""

from __future__ import annotations

import json
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.signatures import SignatureIndex

JWKS_URL = "https://keys.example/jwks"
OKTA_ISSUER = "https://acme.okta.com/oauth2/default"
PRIVILEGED = "policy.privileged-scopes"


def _token(claims: dict) -> str:
    return jwt.encode(claims, key=None, algorithm="none")


def _analyze(index: SignatureIndex, claims: dict, **config):
    connector = JwtConnector(ConnectorContext(index=index, config=config))
    finding = connector.analyze_token(_token(claims), **({"jwks_url": config["jwks_url"]} if config else {}))
    assert finding is not None
    return finding


# ------------------------------------------------------ privileged scope names
@pytest.mark.parametrize(
    "scope", ["offline_access", "refresh_token", "web", "api", "full", "workflow", "admin", "OFFLINE_ACCESS"]
)
def test_ambiguous_or_standard_scope_names_are_not_privileged(index: SignatureIndex, scope: str):
    assert PRIVILEGED not in {m.signature_id for m in index.match_scope(scope)}


@pytest.mark.parametrize(
    "scope",
    [
        "Directory.ReadWrite.All",
        "Mail.ReadWrite",
        "okta.users.manage",
        "admin:org",
        "admin.users:write",
        "sudo",
        "https://www.googleapis.com/auth/admin.directory.user",
        "iam:PassRole",
    ],
)
def test_distinctly_privileged_scopes_stay_privileged(index: SignatureIndex, scope: str):
    assert PRIVILEGED in {m.signature_id for m in index.match_scope(scope)}


def test_oidc_token_with_offline_access_carries_no_privileged_factor(index: SignatureIndex):
    finding = _analyze(
        index, {"iss": OKTA_ISSUER, "sub": "u1", "scp": "openid profile offline_access User.Read"}
    )
    assert PRIVILEGED not in finding.tags
    assert not [factor for factor in finding.risk.factors if PRIVILEGED in factor.id]


def test_okta_app_with_only_offline_access_is_not_flagged_privileged(run_connector, tmp_path):
    export = tmp_path / "okta.json"
    export.write_text(
        json.dumps(
            [
                {
                    "id": "0oa1wiki",
                    "name": "oidc_client",
                    "label": "Plain Wiki",
                    "status": "ACTIVE",
                    "signOnMode": "OPENID_CONNECT",
                    "settings": {"oauthClient": {"grant_types": ["authorization_code", "refresh_token"]}},
                    "credentials": {"oauthClient": {"client_id": "wiki-client"}},
                    "_grants": [{"scopeId": "offline_access"}],
                    "_tokens": [{"userId": "u1", "scopes": ["openid", "offline_access"]}],
                }
            ]
        )
    )
    findings, ctx = run_connector("identity.okta", input=str(export), org_url="https://acme.okta.com")
    assert not ctx.stats.errors
    assert not [finding for finding in findings if PRIVILEGED in finding.tags]


# --------------------------------------------------------- agent claim values
@pytest.mark.parametrize(
    "claim",
    [
        {"bot": False},
        {"bot": "false"},
        {"purpose": ""},
        {"purpose": "   "},
        {"tools": []},
        {"agent": ""},
        {"actor": None},
        {"workload": {}},
        {"delegation": 0},
        {"tool": "none"},
    ],
)
def test_empty_or_false_agent_claims_do_not_make_an_agent(index: SignatureIndex, claim: dict):
    finding = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1", "email": "u1@acme.example", **claim})
    assert finding.metadata["identity_type"] == "human"
    assert "agent-claims" not in finding.tags
    assert finding.metadata["agent_claims"] == {}


@pytest.mark.parametrize(
    "claim", [{"bot": True}, {"agent_id": "negotiator-7"}, {"tools": ["search"]}, {"workload": "nightly-etl"}]
)
def test_meaningful_agent_claims_still_make_an_agent(index: SignatureIndex, claim: dict):
    finding = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1", "email": "u1@acme.example", **claim})
    assert finding.metadata["identity_type"] == "agent"
    assert "agent-claims" in finding.tags
    assert list(claim) == list(finding.metadata["agent_claims"])


# ------------------------------------------------------------ workload issuers
def test_github_actions_oidc_token_is_a_workload_not_a_human_or_agent(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:acme/app:ref:refs/heads/main",
            "aud": "sts.amazonaws.com",
            # GitHub's `actor` names the user who triggered the run; it is not an agent claim.
            "actor": "octocat",
            "repository": "acme/app",
        },
    )
    assert finding.metadata["issuer_family"] == "github-actions"
    assert finding.metadata["identity_type"] == "workload"
    assert "identity:workload" in finding.tags
    assert "agent-claims" not in finding.tags


def test_kubernetes_service_account_token_is_a_workload(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:payments:worker",
            "kubernetes.io": {"namespace": "payments", "serviceaccount": {"name": "worker", "uid": "u-1"}},
        },
    )
    assert finding.metadata["issuer_family"] == "kubernetes"
    assert finding.metadata["identity_type"] == "workload"


def test_gitlab_ci_job_token_is_a_workload_but_a_gitlab_sign_in_is_not(index: SignatureIndex):
    ci = _analyze(
        index,
        {"iss": "https://gitlab.com", "sub": "project_path:acme/app:ref_type:branch:ref:main", "job_id": "9"},
    )
    assert ci.metadata["identity_type"] == "workload"
    sign_in = _analyze(index, {"iss": "https://gitlab.com", "sub": "42", "email": "dev@acme.example"})
    assert sign_in.metadata["identity_type"] == "human"


def test_workload_issuer_does_not_downgrade_delegation(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:acme/app:ref:refs/heads/main",
            "act": {"sub": "deploy-bot"},
        },
    )
    assert finding.metadata["identity_type"] == "delegated-agent"


# -------------------------------------------------------- signature provenance
def test_token_without_jwks_is_explicitly_marked_unverified(index: SignatureIndex):
    finding = _analyze(
        index,
        {
            "iss": "https://login.microsoftonline.com/tenant/v2.0",
            "sub": "forged",
            "scp": "Mail.ReadWrite Directory.ReadWrite.All",
        },
    )
    assert finding.metadata["signature_verified"] is False
    assert "signature-unverified" in finding.tags
    evidence = next(e for e in finding.evidence if e.signal == "jwt:signature")
    assert "not checked" in evidence.description and "no jwks_url" in evidence.description
    assert evidence.weight == 0.0
    # Only the explicit marker is new: the privileged-claim evidence is not boosted or hidden.
    assert PRIVILEGED in finding.tags


def test_unverified_marker_adds_no_confidence_or_risk(index: SignatureIndex):
    finding = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1", "scp": "okta.users.manage"})
    marker = next(e for e in finding.evidence if e.signal == "jwt:signature")
    assert marker.weight == 0.0
    assert not [factor for factor in finding.risk.factors if "unverified" in factor.id]
    with_marker = finding.confidence
    finding.evidence.remove(marker)
    finding.recompute_confidence()
    assert with_marker == pytest.approx(finding.confidence, abs=0.001)


def test_failed_and_successful_verification_set_the_same_field(index: SignatureIndex):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {"iss": OKTA_ISSUER, "sub": "u1"}, private, algorithm="RS256", headers={"kid": "key-1"}
    )
    jwk = json.loads(jwt.algorithms.get_default_algorithms()["RS256"].to_jwk(private.public_key()))
    jwk.update({"alg": "RS256", "use": "sig", "key_ops": ["verify"], "kid": "key-1"})
    connector = JwtConnector(ConnectorContext(index=index, config={"jwks_url": JWKS_URL}))
    with patch("shadowscan.utils.http.HttpClient.get_json", return_value={"keys": [jwk]}):
        good = connector.analyze_token(token, jwks_url=JWKS_URL)
    assert good is not None
    assert good.metadata["signature_verified"] is True
    assert good.metadata["verified"] is True
    assert "signature-unverified" not in good.tags
    bad = _analyze(index, {"iss": OKTA_ISSUER, "sub": "u1"}, jwks_url=JWKS_URL)
    assert bad.metadata["signature_verified"] is False
    assert bad.metadata["verified"] is False
    assert "signature-unverified" in bad.tags
