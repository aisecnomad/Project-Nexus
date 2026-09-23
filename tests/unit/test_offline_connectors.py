"""Offline smoke tests for low-code, SaaS and cloud connectors against the fixture exports."""

from __future__ import annotations

import pytest

from shadowscan.models import Kind, Surface


def _titles(findings):
    return {f.title for f in findings}


# ------------------------------------------------------------------ lowcode
def test_power_platform(run_connector, fixtures):
    findings, ctx = run_connector("lowcode.power-platform", input=str(fixtures / "lowcode" / "power_platform.json"))
    assert not ctx.stats.errors
    flow = next(f for f in findings if f.kind == Kind.WORKFLOW)
    assert "shared_azureopenai" in flow.metadata["ai_connectors"] and "scheduled" in flow.tags and flow.owner == "dave@acme.com"
    assert "Copy files nightly" not in " ".join(_titles(findings))
    bot = next(f for f in findings if f.kind == Kind.AGENT)
    assert bot.metadata["generative_ai"] is True and bot.metadata["actions"] and "no-authentication" in bot.tags


def test_salesforce(run_connector, fixtures):
    findings, ctx = run_connector("lowcode.salesforce", input=str(fixtures / "lowcode" / "salesforce.json"), instance_url="https://acme.my.salesforce.com")
    assert not ctx.stats.errors
    kinds = {f.kind for f in findings}
    assert {Kind.AGENT, Kind.OAUTH_GRANT, Kind.WORKFLOW, Kind.FRAMEWORK_USAGE} <= kinds
    planner = next(f for f in findings if f.resource_type == "agentforce-planner")
    assert "code-exec" in planner.capabilities and planner.metadata["actions"] == ["Refund Order"]
    gong = next(f for f in findings if "Gong" in f.title)
    assert gong.surface == Surface.SAAS and gong.metadata["users"] == 1 and "self-authorisable" in gong.tags


def test_servicenow(run_connector, fixtures):
    findings, ctx = run_connector("lowcode.servicenow", input=str(fixtures / "lowcode" / "servicenow.json"), instance="acme.service-now.com")
    assert not ctx.stats.errors
    agent = next(f for f in findings if f.resource_type == "now-assist-agent")
    assert "code-exec" in agent.capabilities and "autonomous" in agent.capabilities and len(agent.metadata["tools"]) == 2
    assert any(f.resource_type == "oauth-application-registry" for f in findings)
    assert "Nightly cleanup" not in " ".join(_titles(findings))


@pytest.mark.parametrize(
    "connector,file,expected_kind,needle",
    [
        ("lowcode.n8n", "n8n_workflows.json", Kind.AGENT, "Lead qualifier agent"),
        ("lowcode.make", "make_scenarios.json", Kind.AGENT, "Procurement negotiator"),
        ("lowcode.zapier", "zapier_zaps.csv", Kind.AGENT, "Support agent"),
        ("lowcode.workato", "workato_recipes.json", Kind.WORKFLOW, "Classify tickets"),
    ],
)
def test_automation_platforms(run_connector, fixtures, connector, file, expected_kind, needle):
    findings, ctx = run_connector(connector, input=str(fixtures / "lowcode" / file))
    assert not ctx.stats.errors and findings
    hit = next(f for f in findings if needle in f.title)
    assert hit.kind == expected_kind and hit.frameworks
    if connector == "lowcode.n8n":
        assert "code-exec" in hit.capabilities and hit.models == ["gpt-4o-mini"] and "Backup sheets" not in " ".join(_titles(findings))


# --------------------------------------------------------------------- saas
def test_slack(run_connector, fixtures):
    findings, ctx = run_connector("saas.slack", input=str(fixtures / "saas" / "slack.json"))
    assert not ctx.stats.errors
    claude = next(f for f in findings if f.title == "Slack app (bot): Claude")
    assert "identity-app.anthropic-claude" in claude.frameworks and claude.owner == "peggy" and "policy.data-access-scopes" in claude.tags
    req = next(f for f in findings if "Read.ai" in f.title)
    assert "pending-request" in req.tags and req.owner == "oscar@acme.com"


def test_teams_github_apps_atlassian_notion_zoom_generic(run_connector, fixtures):
    findings, _ = run_connector("saas.microsoft-teams", input=str(fixtures / "saas" / "teams_apps.json"), tenant_id="t")
    assert {f.title for f in findings} == {"Teams app with bot: Contoso Copilot Agent", "Teams app with bot: Otter.ai"}
    findings, _ = run_connector("saas.github-apps", input=str(fixtures / "saas" / "github_installations.json"), org="acme")
    slugs = {f.metadata.get("app_slug") for f in findings}
    assert {"coderabbitai", "claude", "renovate"} <= slugs and "readme-badge" not in slugs
    cr = next(f for f in findings if f.metadata.get("app_slug") == "coderabbitai")
    assert "all-repositories" in cr.tags and "write-access" in cr.tags and "coding-agent.pr-review-bots" in cr.frameworks
    findings, _ = run_connector("saas.atlassian", input=str(fixtures / "saas" / "atlassian_plugins.json"), site="https://acme.atlassian.net")
    assert {f.metadata["key"] for f in findings} == {"com.atlassian.rovo.agents", "ai.glean.confluence"}
    findings, _ = run_connector("saas.notion", input=str(fixtures / "saas" / "notion_users.json"))
    assert len(findings) == 2 and any("user-owned-integration" in f.tags for f in findings)
    findings, _ = run_connector("saas.zoom", input=str(fixtures / "saas" / "zoom_apps.json"))
    assert len(findings) == 1 and "identity-app.meeting-notetakers" in findings[0].frameworks and findings[0].metadata["users"] == 214
    findings, _ = run_connector("saas.generic", input=str(fixtures / "saas" / "generic_apps.csv"), platform="google-marketplace", fields={"name": "App Name", "scopes": "Permissions", "users": "Users", "owner": "Installed By", "url": "Domain"})
    ppx = next(f for f in findings if "Perplexity" in f.title)
    assert "identity-app.perplexity" in ppx.frameworks and ppx.metadata["users"] == 57 and ppx.owner == "tom@acme.com"


# -------------------------------------------------------------------- cloud
def test_aws_offline(run_connector, fixtures):
    findings, ctx = run_connector("cloud.aws", input=str(fixtures / "cloud" / "aws_records.jsonl"))
    assert not ctx.stats.errors
    by_type = {}
    for f in findings:
        by_type.setdefault(f.resource_type, []).append(f)
    ops = next(f for f in by_type["bedrock-agent"] if f.metadata["agent_id"] == "AGENT1")
    assert ops.owner == "platform-eng" and {"code-exec", "rag"} <= set(ops.capabilities) and "no-guardrail" in ops.tags
    rt = by_type["agentcore-runtime"][0]
    assert "plaintext-credential" in rt.tags and "provider.openai" in rt.model_providers
    assert by_type["agentcore-gateway"][0].kind == Kind.MCP_SERVER and "code-exec" in by_type["agentcore-gateway"][0].capabilities
    lam = {f.metadata.get("runtime"): f for f in by_type["lambda-function"]}
    assert "python3.12" in lam and "nodejs20.x" not in lam
    assert "framework.langchain" in lam["python3.12"].frameworks and "provider.anthropic" in lam["python3.12"].model_providers
    assert by_type["ecs-task-definition"][0].frameworks == ["platform.langflow"] or "platform.langflow" in by_type["ecs-task-definition"][0].frameworks
    assert "provider.huggingface" in by_type["sagemaker-endpoint"][0].model_providers
    assert "provider.aws-bedrock" in by_type["state-machine"][0].model_providers
    logging = by_type["bedrock-logging"][0]
    assert "no-invocation-logging" in logging.tags
    roles = {f.metadata["principal_type"]: f for f in findings if f.kind == Kind.IAM_GRANT}
    assert "agent-execution-role" in roles["Role"].tags and "wildcard-permissions" in roles["Role"].tags
    assert roles["User"].surface == Surface.IDENTITY
    callers = [f for f in findings if f.kind == Kind.GATEWAY_CALLER]
    assert len(callers) == 2 and any("framework.aws-strands" in c.frameworks for c in callers)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert "managed-secret" in secret.tags


def test_gcp_azure_oci_offline(run_connector, fixtures):
    findings, ctx = run_connector("cloud.gcp", input=str(fixtures / "cloud" / "gcp_records.jsonl"))
    assert not ctx.stats.errors
    types = {f.resource_type: f for f in findings}
    assert "framework.google-adk" in types["reasoning-engine"].frameworks
    assert "public-ingress" in types["cloud-run-service"].tags and "framework.crewai" in types["cloud-run-service"].frameworks
    assert "unrestricted-api-key" not in types["api-key"].tags and "provider.google-gemini" in types["api-key"].model_providers
    assert any(f.kind == Kind.IAM_GRANT and "service-account" in f.tags for f in findings)
    assert types["caller/principal"].surface == Surface.GATEWAY and "framework.crewai" in types["caller/principal"].frameworks

    findings, ctx = run_connector("cloud.azure", input=str(fixtures / "cloud" / "azure_records.jsonl"))
    assert not ctx.stats.errors
    types = {f.resource_type: f for f in findings}
    acct = types["cognitive-services/OpenAI"]
    assert acct.models == ["gpt-4o"] and {"api-key-auth-enabled", "public-network", "no-diagnostic-logging"} <= set(acct.tags)
    agent = types["foundry-agent"]
    assert {"code-exec", "saas-actions", "rag"} <= set(agent.capabilities)
    assert types["logic-app"].kind == Kind.WORKFLOW and "autonomous" in types["logic-app"].capabilities
    assert "plaintext-credential" in types["web-site/functionapp,linux"].tags
    assert types["role-assignment"].metadata["principal_name"] == "agent-runner-mi"

    findings, ctx = run_connector("cloud.oci", input=str(fixtures / "cloud" / "oci_records.jsonl"))
    assert not ctx.stats.errors
    types = {f.resource_type: f for f in findings}
    agent = types["genai-agent"]
    assert agent.owner == "claims-it" and {"rag", "code-exec"} <= set(agent.capabilities) and "no-content-moderation" in agent.tags
    assert types["iam-policy"].surface == Surface.IDENTITY and "workload-identity" in types["iam-policy"].tags
    assert "provider.oci-generative-ai" in types["function"].model_providers
