"""Regression tests for detection precision, coverage policy and risk explainability.

Cases mirror an externally authored 18-project labeled set and three public
repositories (psf/requests, traceloop/openllmetry, langchain-ai/open_deep_research)
whose earlier results exposed these defects. Credentials are assembled at
runtime so no key-shaped literal appears in this file.
"""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ScanConfig
from shadowscan.connectors.common import looks_like_placeholder
from shadowscan.models import Finding, Kind, Surface
from shadowscan.risk import RiskPolicy, assess

OPENAI_LIKE_KEY = "sk-proj-" + "Xk29fLq8Zr1mNvB4" + "tYc7Hs0pWe3Ja6Ud9GiKo5Rb2Ex"
AZURE_LIKE_KEY = "f3c2a1b0e9d8c7b6" + "a5f4e3d2c1b0a9f8"


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"))
    return path


def scan(run_connector, root: Path, **config):
    findings, ctx = run_connector("code.filesystem", path=str(root), label="repo", **config)
    return findings, ctx.stats


def project(findings):
    matches = [f for f in findings if f.resource_type == "project"]
    assert len(matches) == 1, [f.title for f in findings]
    return matches[0]


# ------------------------------------------------------------------ raw SDK agents
def test_raw_anthropic_tool_loop_is_agent_with_code_execution(run_connector, tmp_path):
    write(tmp_path, "bot.py", '''
        import anthropic, subprocess
        client = anthropic.Anthropic()
        tools = [{"name": "bash", "description": "run bash", "input_schema": {"type": "object"}}]
        messages = [{"role": "user", "content": "clean up disk space"}]
        while True:
            resp = client.messages.create(model="claude-sonnet-4-5", max_tokens=1024, tools=tools, messages=messages)
            if resp.stop_reason != "tool_use":
                break
            for block in resp.content:
                if block.type == "tool_use":
                    out = subprocess.run(block.input["cmd"], shell=True, capture_output=True, text=True).stdout
                    messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": block.id, "content": out}]})
    ''')
    findings, stats = scan(run_connector, tmp_path)
    finding = project(findings)
    assert finding.kind == Kind.AGENT
    assert {"tool-use", "code-exec", "autonomous"} <= set(finding.capabilities)
    assert "provider.anthropic" in finding.model_providers
    assert not stats.incomplete


def test_raw_openai_tool_loop_is_agent(run_connector, tmp_path):
    write(tmp_path, "agent.py", '''
        import json
        from openai import OpenAI
        client = OpenAI()
        tools = [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}]
        messages = [{"role": "user", "content": "find the order"}]
        while True:
            response = client.chat.completions.create(model="gpt-4o", messages=messages, tools=tools)
            message = response.choices[0].message
            if not message.tool_calls:
                break
            messages.append(message)
            for call in message.tool_calls:
                result = lookup(**json.loads(call.function.arguments))
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
    ''')
    findings, _ = scan(run_connector, tmp_path)
    finding = project(findings)
    assert finding.kind == Kind.AGENT
    assert {"tool-use", "autonomous"} <= set(finding.capabilities)
    assert "provider.openai" in finding.model_providers


@pytest.mark.parametrize(("source", "provider"), [
    ('''
        from openai import OpenAI
        client = OpenAI()
        tools = [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}]
        response = client.chat.completions.create(model="gpt-4o", messages=[], tools=tools)
        for call in response.choices[0].message.tool_calls or []:
            print(call.function.name)
    ''', "provider.openai"),
    ('''
        import anthropic
        client = anthropic.Anthropic()
        tools = [{"name": "bash", "description": "run bash", "input_schema": {"type": "object"}}]
        response = client.messages.create(model="claude-sonnet-4-5", max_tokens=1024, tools=tools, messages=[])
        for block in response.content:
            print(block.type, block.input)
    ''', "provider.anthropic"),
])
def test_tool_schema_without_dispatch_is_tool_enabled_usage_not_agent(run_connector, tmp_path, source, provider):
    # Offering tools proves tool-use capability and the provider, not that the
    # program executes what the model selects (see provider_loops).
    write(tmp_path, "app.py", source)
    findings, _ = scan(run_connector, tmp_path)
    finding = project(findings)
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" in finding.capabilities
    assert provider in finding.model_providers


def test_single_completion_without_tools_is_llm_usage_not_agent(run_connector, tmp_path):
    write(tmp_path, "summarize.py", '''
        from openai import OpenAI
        client = OpenAI()
        def summarize(text):
            return client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": text}])
    ''')
    findings, _ = scan(run_connector, tmp_path)
    finding = project(findings)
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "code-exec" not in finding.capabilities


def test_execution_sink_counts_only_beside_model_calls(run_connector, tmp_path):
    write(tmp_path, "summarize.py", '''
        from openai import OpenAI
        client = OpenAI()
        reply = client.chat.completions.create(model="gpt-4o-mini", messages=[])
    ''')
    # Generic sinks in build tooling are not model-driven execution.
    write(tmp_path, "build.py", '''
        import os, subprocess
        subprocess.run(args, shell=True)
        os.system(build_cmd)
    ''')
    findings, _ = scan(run_connector, tmp_path)
    assert "code-exec" not in project(findings).capabilities


# ------------------------------------------------------------ attribution & capabilities
def test_integration_packages_attribute_model_providers(run_connector, tmp_path):
    write(tmp_path, "py/agent.py", '''
        from langchain_openai import ChatOpenAI
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(ChatOpenAI(model="gpt-4o"), tools=[])
    ''')
    write(tmp_path, "ts/package.json", '{"name": "t", "dependencies": {"ai": "^4.0.0", "@ai-sdk/anthropic": "^1.0.0"}}')
    write(tmp_path, "ts/agent.ts", '''
        import { generateText, tool } from 'ai';
        import { anthropic } from '@ai-sdk/anthropic';
        const r = await generateText({ model: anthropic('claude-sonnet-4-5'), tools: { t: tool({}) }, prompt: 'x' });
    ''')
    findings, _ = scan(run_connector, tmp_path)
    providers = {p for f in findings for p in f.model_providers}
    assert {"provider.openai", "provider.anthropic"} <= providers


def test_capabilities_require_specific_evidence(run_connector, tmp_path):
    write(tmp_path, "a/agent.py", '''
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, tools=[])
    ''')
    write(tmp_path, "a/requirements.txt", "langgraph\n")
    write(tmp_path, "b/agent.py", '''
        from langgraph.checkpoint.memory import MemorySaver
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, tools=[], checkpointer=MemorySaver())
    ''')
    write(tmp_path, "b/requirements.txt", "langgraph\n")
    write(tmp_path, "c/main.py", '''
        from agents import Agent, Runner
        support = Agent(name="Support", instructions="Help")
        Runner.run_sync(support, "hi")
    ''')
    write(tmp_path, "c/requirements.txt", "openai-agents\n")
    write(tmp_path, "d/main.py", '''
        from agents import Agent, Runner
        billing = Agent(name="Billing", instructions="Bill")
        triage = Agent(name="Triage", instructions="Route", handoffs=[billing])
        Runner.run_sync(triage, "hi")
    ''')
    write(tmp_path, "d/requirements.txt", "openai-agents\n")
    findings, _ = scan(run_connector, tmp_path)
    by_path = {f.metadata["path"]: f for f in findings if f.resource_type == "project"}
    assert "memory" not in by_path["a"].capabilities
    assert "memory" in by_path["b"].capabilities
    assert "multi-agent" not in by_path["c"].capabilities
    assert "multi-agent" in by_path["d"].capabilities


def test_terraform_agent_reports_wildcard_iam_and_declared_model(run_connector, tmp_path):
    write(tmp_path, "main.tf", '''
        resource "aws_bedrockagent_agent" "ops" {
          agent_name       = "ops-agent"
          foundation_model = "anthropic.claude-3-5-sonnet-20240620-v1:0"
        }
    ''')
    write(tmp_path, "iam.tf", '''
        resource "aws_iam_role_policy" "p" {
          policy = jsonencode({Statement=[{Effect="Allow",Action="*",Resource="*"}]})
        }
    ''')
    findings, _ = scan(run_connector, tmp_path)
    infra = [f for f in findings if f.kind == Kind.INFRA]
    assert len(infra) == 1 and len(findings) == 1
    assert "wildcard-permissions" in infra[0].tags
    assert {"provider.anthropic", "provider.aws-bedrock"} <= set(infra[0].model_providers)
    assert "memory" not in infra[0].capabilities


# ------------------------------------------------------------------ duplicates
@pytest.mark.parametrize(("rel", "text", "kind"), [
    (".well-known/agent-card.json", json.dumps({
        "name": "Travel Agent", "description": "Books travel", "url": "https://agents.example.com/travel",
        "version": "1.0.0", "capabilities": {}, "defaultInputModes": ["text"], "defaultOutputModes": ["text"],
        "skills": [{"id": "book", "name": "Book", "description": "Books flights", "tags": ["travel"]}]}), Kind.AGENT),
    (".mcp.json", json.dumps({"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.com/mcp"}}}), Kind.MCP_SERVER),
])
def test_artifact_only_repositories_report_one_finding(run_connector, tmp_path, rel, text, kind):
    write(tmp_path, rel, text)
    findings, _ = scan(run_connector, tmp_path)
    assert [f.kind for f in findings] == [kind]


def test_n8n_export_is_one_workflow_with_its_model_provider(run_connector, tmp_path):
    write(tmp_path, "workflow.json", json.dumps({"name": "triage", "nodes": [
        {"parameters": {}, "name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent", "typeVersion": 1.7, "position": [0, 0]},
        {"parameters": {}, "name": "Model", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1, "position": [0, 1]},
    ], "connections": {}}))
    findings, _ = scan(run_connector, tmp_path)
    assert [f.kind for f in findings] == [Kind.WORKFLOW]
    assert "provider.openai" in findings[0].model_providers
    assert findings[0].title.startswith("Exported AI workflow (n8n)")


# ------------------------------------------------------------ test code & fake credentials
def test_agents_only_in_tests_do_not_establish_an_agent(run_connector, tmp_path):
    write(tmp_path, "src/wrapper.py", "import crewai\n")
    write(tmp_path, "tests/test_crew.py", '''
        from crewai import Agent, Crew, Task
        researcher = Agent(role="Researcher", goal="g", backstory="b")
        Crew(agents=[researcher], tasks=[Task(description="d", agent=researcher, expected_output="o")]).kickoff()
    ''')
    write(tmp_path, "requirements.txt", "crewai\n")
    findings, _ = scan(run_connector, tmp_path)
    assert project(findings).kind == Kind.FRAMEWORK_USAGE
    findings, _ = scan(run_connector, tmp_path, include_tests=True)
    assert project(findings).kind == Kind.AGENT


def test_test_only_evidence_is_tagged(run_connector, tmp_path):
    write(tmp_path, "tests/test_agent.py", '''
        from crewai import Agent
        Agent(role="r", goal="g", backstory="b")
    ''')
    findings, _ = scan(run_connector, tmp_path)
    assert "test-code-only" in project(findings).tags


@pytest.mark.parametrize("value", [
    "sk-test-" + "0" * 40, "AKIA" + "IOSFODNN7EXAMPLE", "your-api-key-here", "sk-proj-" + "A" * 48,
    "AZURE_OPENAI_KEY=" + "0" * 32,
])
def test_placeholder_credentials(value):
    assert looks_like_placeholder(value)


@pytest.mark.parametrize("value", [OPENAI_LIKE_KEY, "AZURE_OPENAI_KEY=" + AZURE_LIKE_KEY])
def test_realistic_credentials_are_not_placeholders(value):
    assert not looks_like_placeholder(value)


def test_fake_keys_in_tests_are_ignored_but_real_format_keys_are_reported(run_connector, tmp_path):
    write(tmp_path, "tests/test_fake.py", f'FAKE = "{"sk-test-" + "0" * 40}"\n')
    findings, _ = scan(run_connector, tmp_path)
    assert findings == []
    write(tmp_path, "tests/test_real.py", f'KEY = "{OPENAI_LIKE_KEY}"\n')
    findings, _ = scan(run_connector, tmp_path)
    assert [f.kind for f in findings] == [Kind.SECRET]
    assert OPENAI_LIKE_KEY not in json.dumps(findings[0].to_dict())


def test_azure_openai_key_is_bound_to_its_variable_name(run_connector, tmp_path):
    write(tmp_path, ".env", f"AZURE_OPENAI_KEY={AZURE_LIKE_KEY}\n")
    findings, _ = scan(run_connector, tmp_path)
    secrets = [f for f in findings if f.kind == Kind.SECRET]
    assert len(secrets) == 1 and "provider.azure-openai" in secrets[0].model_providers
    assert AZURE_LIKE_KEY not in json.dumps(secrets[0].to_dict())


def test_mcp_inline_secret_evidence_names_its_location(run_connector, tmp_path):
    header = "Bearer " + "q8Zr1mNvB4tYc7Hs0pWe"
    write(tmp_path, ".mcp.json", json.dumps({"mcpServers": {"linear": {
        "type": "http", "url": "https://mcp.linear.app/mcp", "headers": {"Authorization": header}}}}))
    findings, _ = scan(run_connector, tmp_path)
    descriptions = [e.description for e in findings[0].evidence if e.signal == "secret:inline"]
    assert descriptions and "headers" in descriptions[0]


# ------------------------------------------------------------ coverage and limits
def test_unrelated_bound_calls_do_not_exhaust_the_binder(run_connector, tmp_path):
    body = "\n".join(f"    pytest.raises(ValueError, int, 'x{i}')" for i in range(700))
    write(tmp_path, "tests/test_big.py", "import pytest\n\ndef test_many():\n" + body + "\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not stats.incomplete


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_internal_symlinks_keep_coverage_complete(run_connector, tmp_path):
    write(tmp_path, "certs/valid/ca.pem", "certificate\n")
    (tmp_path / "certs" / "client").mkdir()
    (tmp_path / "certs" / "client" / "ca").symlink_to(tmp_path / "certs" / "valid")
    _, stats = scan(run_connector, tmp_path, strict_coverage=True)
    assert not stats.errors and not stats.warnings and not stats.incomplete


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_external_symlinks_make_coverage_incomplete_by_default(run_connector, tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    write(outside, "secret.txt", "not part of the repository\n")
    repo.mkdir()
    (repo / "link").symlink_to(outside)
    _, stats = scan(run_connector, repo)
    assert stats.warnings and not stats.errors and stats.incomplete
    _, stats = scan(run_connector, repo, strict_coverage=True)
    assert stats.errors and stats.incomplete


def test_oversize_files_make_coverage_incomplete_by_default(run_connector, tmp_path):
    write(tmp_path, "fixtures/cassette.yaml", "x: " + "y" * 400 + "\n")
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert stats.warnings and not stats.errors and stats.incomplete
    _, stats = scan(run_connector, tmp_path, max_file_size=100, strict_coverage=True)
    assert stats.errors and stats.incomplete


@pytest.mark.parametrize("key", ["strict_coverage", "include_tests"])
def test_coverage_options_must_be_booleans(run_connector, tmp_path, key):
    with pytest.raises(Exception, match=key):
        scan(run_connector, tmp_path, **{key: "yes"})


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_cli_incomplete_coverage_has_exit_code_three_by_default(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    outside.mkdir()
    repo.mkdir()
    (repo / "link").symlink_to(outside)
    runner = CliRunner()
    assert runner.invoke(main, ["code", str(repo), "--format", "json"]).exit_code == 3
    assert runner.invoke(main, ["code", str(repo), "--format", "json", "--strict-coverage"]).exit_code == 3


# ------------------------------------------------------------------------ risk
def finding(**kwargs) -> Finding:
    base = dict(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT, title="t", resource="r",
                resource_type="project", confidence=1.0)
    base.update(kwargs)
    return Finding(**base)


@pytest.mark.parametrize("confidence", [1.0, 0.55, 0.0])
def test_risk_factors_always_sum_to_the_score(confidence):
    heavy = finding(capabilities=["code-exec", "autonomous", "saas-actions", "browsing"],
                    tags=["policy.privileged-scopes", "hardcoded-credential", "wildcard-permissions", "public-principal"],
                    confidence=confidence, shadow=True)
    risk = assess(heavy, inventory_present=True)
    assert sum(f.weight for f in risk.factors) == risk.score
    if confidence == 1.0:
        assert risk.score == 100 and any(f.id == "bounds" for f in risk.factors)


def test_danger_score_excludes_governance_and_basis_controls_level():
    unregistered = finding(capabilities=["tool-use"], shadow=True)
    combined = assess(unregistered, inventory_present=True)
    danger = assess(unregistered, inventory_present=True, policy=RiskPolicy.from_options(basis="danger"))
    assert combined.score - combined.danger_score == 35  # shadow (25) + no owner (10)
    assert danger.score == danger.danger_score == combined.danger_score
    assert sum(f.weight for f in danger.factors) == danger.score


def test_risk_weights_override_defaults():
    policy = RiskPolicy.from_options({"capabilities": {"code-exec": 40}, "governance": {"shadow": 0}, "kinds": {"agent": 0}})
    risk = assess(finding(capabilities=["code-exec"], shadow=True, owner="team"), inventory_present=True, policy=policy)
    assert risk.score == 40


@pytest.mark.parametrize("weights", [
    {"unknown": {}}, {"tags": {"Bad Key": 1}}, {"tags": {"x": 1.5}}, {"tags": {"x": True}}, {"tags": {"x": 101}},
    {"kinds": {"not-a-kind": 1}}, {"governance": {"owner": 1}}, {"tags": []},
])
def test_invalid_risk_weights_fail_closed(weights):
    with pytest.raises(ValueError):
        RiskPolicy.from_options(weights)
    with pytest.raises(ConfigValidationError):
        ScanConfig(risk_weights=weights)


def test_invalid_risk_basis_fails_closed():
    with pytest.raises(ConfigValidationError):
        ScanConfig(risk_basis="severity")


def test_danger_score_round_trips_through_report_import():
    original = finding(capabilities=["code-exec"], shadow=True)
    original.risk = assess(original, inventory_present=True)
    restored = Finding.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored.risk.danger_score == original.risk.danger_score > 0
