"""Precision regressions for generic hosts, package names, model ids and Claude OAuth tokens."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from shadowscan.signatures import SignatureIndex

CLOUDFLARE_DNS_SCRIPT = (
    "import requests\n"
    "def update(zone):\n"
    '    return requests.get("https://api.cloudflare.com/client/v4/zones")\n'
)
HUGGINGFACE_DATASET_DOWNLOAD = (
    "import requests\n"
    "def fetch():\n"
    '    return requests.get("https://huggingface.co/datasets/acme/corpus/resolve/main/data.csv")\n'
)


def _ids(matches) -> set[str]:
    return {m.signature_id for m in matches}


def _weight(matches, signature_id: str) -> float:
    return max((m.weight for m in matches if m.signature_id == signature_id), default=0.0)


def _scan(tmp_path: Path, run_connector, files: dict[str, str]):
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    return findings


# ------------------------------------------------- generic vendor API hosts
def test_general_cloudflare_rest_api_host_is_corroboration_only(index: SignatureIndex):
    assert _weight(index.match_domain("api.cloudflare.com"), "provider.cloudflare-workers-ai") <= 0.15
    assert _weight(index.match_domain("gateway.ai.cloudflare.com"), "provider.cloudflare-workers-ai") >= 0.7


def test_bare_huggingface_host_is_corroboration_only(index: SignatureIndex):
    assert _weight(index.match_domain("huggingface.co"), "provider.huggingface") <= 0.2
    for host in ("api-inference.huggingface.co", "router.huggingface.co", "acme.endpoints.huggingface.cloud"):
        assert _weight(index.match_domain(host), "provider.huggingface") >= 0.8, host


def test_dns_script_and_dataset_download_are_not_confident_llm_usage(tmp_path: Path, run_connector):
    findings = _scan(
        tmp_path, run_connector, {"dns.py": CLOUDFLARE_DNS_SCRIPT, "data.py": HUGGINGFACE_DATASET_DOWNLOAD}
    )
    # A lone generic host stays a low-confidence hint, far below the 0.94 it scored.
    assert max((finding.confidence for finding in findings), default=0.0) < 0.3


# ------------------------------------------------ ambiguous package names
def test_pypi_swarm_is_not_openai_swarm(tmp_path: Path, run_connector, index: SignatureIndex):
    assert "framework.openai-swarm" not in _ids(index.match_dependency("pypi", "swarm"))
    findings = _scan(tmp_path, run_connector, {"requirements.txt": "swarm==1.0\n"})
    assert not [f for f in findings if "framework.openai-swarm" in f.frameworks]


def test_openai_swarm_is_still_identified_by_its_import_and_vendor_qualified_name(
    tmp_path: Path, run_connector, index: SignatureIndex
):
    assert "framework.openai-swarm" in _ids(index.match_dependency("pypi", "openai-swarm"))
    findings = _scan(
        tmp_path,
        run_connector,
        {
            "requirements.txt": "swarm @ git+https://github.com/openai/swarm.git\n",
            "app.py": "from swarm import Swarm, Agent\nclient = Swarm()\n",
        },
    )
    assert any("framework.openai-swarm" in f.frameworks for f in findings)


def test_generic_npm_weave_name_is_a_weak_signal(index: SignatureIndex):
    assert _weight(index.match_dependency("npm", "weave"), "observability.weave") <= 0.3
    assert _weight(index.match_dependency("pypi", "weave"), "observability.weave") >= 0.5


# --------------------------------------------------- Claude Code OAuth tokens
def _synthetic(prefix: str, length: int = 86) -> str:
    return prefix + hashlib.sha256(prefix.encode()).hexdigest()[:length] * 2


@pytest.mark.parametrize("prefix", ["sk-ant-oat01-", "sk-ant-oat02-", "sk-ant-api03-", "sk-ant-admin01-"])
def test_anthropic_token_families_are_attributed(index: SignatureIndex, prefix: str):
    matches = index.match_secrets(f'TOKEN="{_synthetic(prefix)}"')
    assert _ids(matches) == {"provider.anthropic"}
    assert matches[0].weight == 0.9


def test_oauth_token_prefix_needs_a_real_token_body(index: SignatureIndex):
    assert index.match_secrets("sk-ant-oat01-short") == []
    assert index.match_secrets("sk-ant-oat-" + "a" * 40) == []


def test_claude_code_oauth_token_in_source_is_reported_without_the_secret(tmp_path: Path, run_connector):
    token = _synthetic("sk-ant-oat01-")
    findings = _scan(tmp_path, run_connector, {"deploy.py": f'CLAUDE_CODE_OAUTH_TOKEN = "{token}"\n'})
    secrets = [f for f in findings if f.kind.value == "secret"]
    assert secrets, "OAuth token was not detected"
    assert any("provider.anthropic" in f.model_providers for f in secrets)
    assert token not in json.dumps([f.to_dict() for f in findings], default=str)


def test_generic_inline_credential_has_file_line_identity_and_is_redacted(tmp_path: Path, run_connector):
    secret = "R4nd0m9Qx2Vb7Lp6"
    findings = _scan(
        tmp_path,
        run_connector,
        {"credentials.env": f"comment=example\nCUSTOM_API_KEY={secret}\n"},
    )
    finding = next(f for f in findings if f.kind.value == "secret")
    serialized = json.dumps(finding.to_dict())
    assert finding.resource_type == "file"
    assert finding.identity_schema == "shadowscan.finding-identity/v2"
    assert [e.location for e in finding.evidence] == ["credentials.env:2"]
    assert secret not in serialized


# ------------------------------------------------------------ model-id shapes
@pytest.mark.parametrize(
    "model",
    [
        "amazon.com",
        "openai.com",
        "writer.md",
        "qwen.config",
        "meta.json",
        "o1ne",
        "tts-config",
        "sonar-qube",
        # Path-like and prose strings the benchmark found next to real ids.
        "bedrock/edition",
        "xai/README",
        "mistral/",
        "command-line",
        "command-lightning",
        "gpt-4-turbo-docs.md",
        "gpt-4-turbo.py",
        "gpt-5.",
        "gpt-4o-mini.invoke",
        "gpt-5.schema.kimi-chat",
        "vertex_ai/README",
        "groq/",
        "ollama/README",
        "huggingface/README",
        "openai/",
        "openai/docs",
        "claude-code-action",
        "claude-desktop-config",
        "deepseek-docs.md",
        "deepseek/",
        "chatgpt-token",
        "chatgpt-account-id",
        "chatgpt-plugin",
        "claude-code",
        "text-embedding-bge-m3",
        "voyage-",
        "embedding-model",
    ],
)
def test_ordinary_strings_are_not_model_ids(index: SignatureIndex, model: str):
    assert index.match_model(model) == []


def test_command_line_is_not_a_cohere_model(index: SignatureIndex):
    assert "provider.cohere" not in _ids(index.match_model("command-line"))
    for model in (
        "command",
        "command-r",
        "command-r-plus-08-2024",
        "command-r7b-12-2024",
        "command-a-03-2025",
    ):
        assert "provider.cohere" in _ids(index.match_model(model)), model
    for model in ("command-light", "command-light-nightly", "command-nightly"):
        assert "provider.cohere" in _ids(index.match_model(model)), model


@pytest.mark.parametrize(
    ("model", "provider"),
    [
        # OpenAI families keep their dotted versions and dated suffixes.
        ("gpt-4.1-mini", "provider.openai"),
        ("gpt-3.5-turbo-0125", "provider.openai"),
        ("gpt-5-codex", "provider.openai"),
        ("gpt-oss-120b", "provider.openai"),
        ("gpt-4o-mini-2024-07-18", "provider.openai"),
        ("o1-pro", "provider.openai"),
        ("o3-mini-2025-01-31", "provider.openai"),
        ("text-embedding-ada-002", "provider.openai"),
        ("chatgpt-4o-latest", "provider.openai"),
        # Ids outside the gpt-3.5/4/5/oss generations: Azure's GPT-3.5 deployment
        # name and the image, realtime and audio models.
        ("gpt-35-turbo", "provider.openai"),
        ("gpt-35-turbo-16k", "provider.openai"),
        ("gpt-image-1", "provider.openai"),
        ("gpt-realtime", "provider.openai"),
        ("gpt-audio", "provider.openai"),
        ("gpt-4.1", "provider.openai"),
        ("gpt-5-mini", "provider.openai"),
        # Ollama and OpenRouter tags on the open-weight and hosted ids.
        ("gpt-oss:20b", "provider.openai"),
        ("gpt-oss:120b-cloud", "provider.openai"),
        ("gpt-5.4:free", "provider.openai"),
        ("o4-mini@eu", "provider.openai"),
        ("chatgpt-image-latest", "provider.openai"),
        # Anthropic generations and tiers.
        ("claude-opus-4-1-20250805", "provider.anthropic"),
        ("claude-3-5-haiku-20241022", "provider.anthropic"),
        ("claude-instant-1.2", "provider.anthropic"),
        ("claude-2.1", "provider.anthropic"),
        ("claude-fable-5-1", "provider.anthropic"),
        ("claude-fable-5.1@eu", "provider.anthropic"),
        # Google.
        ("gemini-embedding-001", "provider.google-gemini"),
        ("text-embedding-004", "provider.google-gemini"),
        ("text-embedding-005", "provider.google-gemini"),
        # Mistral families.
        ("open-mistral-nemo", "provider.mistral"),
        ("codestral-latest", "provider.mistral"),
        ("mixtral-8x7b-instruct", "provider.mistral"),
        ("ministral-8b-latest", "provider.mistral"),
        ("pixtral-large-latest", "provider.mistral"),
        ("magistral-medium-latest", "provider.mistral"),
        ("devstral-small-latest", "provider.mistral"),
        # Cohere embeddings and rerankers.
        ("embed-english-v3.0", "provider.cohere"),
        ("embed-v4.0", "provider.cohere"),
        ("embed-multilingual-light-v3.0", "provider.cohere"),
        ("rerank-v3.5", "provider.cohere"),
        ("rerank-english-v3.0", "provider.cohere"),
        # xAI, DeepSeek.
        ("grok-4-0709", "provider.xai"),
        ("deepseek-reasoner", "provider.deepseek"),
        ("deepseek-chat", "provider.deepseek"),
        ("deepseek-coder", "provider.deepseek"),
        ("deepseek-r1", "provider.deepseek"),
        ("deepseek-v3", "provider.deepseek"),
        # Generations and families after the v3 line, and the Hugging Face org form.
        ("deepseek-v4-flash", "provider.deepseek"),
        ("deepseek-flash", "provider.deepseek"),
        ("deepseek-v4.1-flash:fast", "provider.deepseek"),
        ("deepseek-v4-pro-0813@eu", "provider.deepseek"),
        ("deepseek-ai/DeepSeek-V3.1-Terminus:thinking", "provider.deepseek"),
        ("deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B", "provider.deepseek"),
        # Voyage embeddings.
        ("voyage-3", "provider.voyage-ai"),
        ("voyage-3-large", "provider.voyage-ai"),
        ("voyage-3-lite", "provider.voyage-ai"),
        ("voyage-code-3", "provider.voyage-ai"),
        ("voyage-finance-2", "provider.voyage-ai"),
        ("voyage-law-2", "provider.voyage-ai"),
        ("voyage-multilingual-2", "provider.voyage-ai"),
        ("voyage-context-3", "provider.voyage-ai"),
        # Bedrock vendor ids, inference profiles and ARNs.
        ("amazon.nova-micro-v1:0", "provider.aws-bedrock"),
        ("amazon.titan-embed-text-v2:0", "provider.aws-bedrock"),
        ("eu.anthropic.claude-3-5-sonnet-20240620-v1:0", "provider.aws-bedrock"),
        ("global.anthropic.claude-sonnet-4-20250514-v1:0", "provider.aws-bedrock"),
    ],
)
def test_bare_model_id_families_attribute_their_provider(index: SignatureIndex, model: str, provider: str):
    assert provider in _ids(index.match_model(model)), model


def test_model_id_families_do_not_cross_vendors(index: SignatureIndex):
    # Google's text-embedding-004/005 ids are not OpenAI's text-embedding-3/ada.
    assert "provider.openai" not in _ids(index.match_model("text-embedding-004"))
    assert "provider.google-gemini" not in _ids(index.match_model("text-embedding-3-small"))
    # Cohere's rerankers are never Voyage's embeddings.
    assert "provider.voyage-ai" not in _ids(index.match_model("rerank-v3.5"))
    assert "provider.cohere" not in _ids(index.match_model("voyage-3"))
    # A Bedrock Claude id names both the platform and the model vendor (the
    # benchmark ground truth labels both); a bare Claude id is Anthropic alone.
    both = _ids(index.match_model("us.anthropic.claude-3-5-sonnet-20241022-v2:0"))
    assert {"provider.aws-bedrock", "provider.anthropic"} <= both
    assert _ids(index.match_model("claude-sonnet-4-5")) == {"provider.anthropic"}


@pytest.mark.parametrize(
    ("route", "provider"),
    [
        ("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0", "provider.aws-bedrock"),
        ("bedrock/us.anthropic.claude-3-7-sonnet-20250219-v1:0", "provider.aws-bedrock"),
        ("bedrock/converse/us.amazon.nova-pro-v1:0", "provider.aws-bedrock"),
        ("bedrock/invoke/meta.llama3-70b-instruct-v1:0", "provider.aws-bedrock"),
        (
            "bedrock/arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.amazon.nova-lite-v1:0",
            "provider.aws-bedrock",
        ),
        ("vertex_ai/gemini-2.5-pro", "provider.google-vertex-ai"),
        ("vertex_ai/claude-3-5-sonnet@20240620", "provider.google-vertex-ai"),
        ("vertex_ai/meta/llama3-405b-instruct-maas", "provider.google-vertex-ai"),
        ("vertex_ai/text-embedding-004", "provider.google-vertex-ai"),
        ("anthropic/claude-sonnet-4-5", "provider.anthropic"),
        ("openai/gpt-4o", "provider.openai"),
        ("openai/o3-mini", "provider.openai"),
        ("openai/text-embedding-3-small", "provider.openai"),
        ("openai/ft:gpt-4o-mini-2024-07-18:acme::abc123", "provider.openai"),
        ("gemini/gemini-2.5-flash", "provider.google-gemini"),
        ("gemini/gemini-embedding-001", "provider.google-gemini"),
        ("mistral/mistral-large-latest", "provider.mistral"),
        ("mistral/codestral-latest", "provider.mistral"),
        ("mistral/open-mixtral-8x22b", "provider.mistral"),
        ("cohere/command-r-plus", "provider.cohere"),
        ("cohere_chat/command-a-03-2025", "provider.cohere"),
        ("cohere/embed-english-v3.0", "provider.cohere"),
        ("xai/grok-4", "provider.xai"),
        ("deepseek/deepseek-chat", "provider.deepseek"),
        ("deepseek/deepseek-reasoner", "provider.deepseek"),
        ("openrouter/anthropic/claude-3.5-sonnet", "provider.openrouter"),
        ("openrouter/openai/gpt-4o:extended", "provider.openrouter"),
        ("together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo", "provider.together"),
        ("groq/llama-3.3-70b-versatile", "provider.groq"),
        ("groq/openai/gpt-oss-120b", "provider.groq"),
        ("ollama/llama3.1:8b", "provider.ollama"),
        ("ollama_chat/qwen2.5-coder", "provider.ollama"),
        ("huggingface/meta-llama/Llama-3.1-8B-Instruct", "provider.huggingface"),
        ("huggingface/Qwen/Qwen2.5-72B-Instruct", "provider.huggingface"),
        ("huggingface/mistralai/Mistral-7B-Instruct-v0.3", "provider.huggingface"),
        ("perplexity/sonar-pro", "provider.perplexity"),
        ("cerebras/llama-3.3-70b", "provider.cerebras"),
        ("voyage/voyage-3-large", "provider.voyage-ai"),
        ("azure/gpt-4o", "provider.azure-openai"),
    ],
)
def test_litellm_routes_attribute_the_routed_provider(index: SignatureIndex, route: str, provider: str):
    ids = _ids(index.match_model(route))
    assert provider in ids, route
    # A route names one provider; the model vendor behind an aggregator is not
    # attributed from the route alone (openrouter/anthropic/... is OpenRouter).
    if provider in {"provider.openrouter", "provider.together", "provider.groq", "provider.huggingface"}:
        assert ids == {provider}, route


def test_aggregator_routes_are_supporting_evidence(index: SignatureIndex):
    for route in (
        "openrouter/x/y",
        "groq/llama-3.3-70b-versatile",
        "together_ai/m/n",
        "ollama/llama3",
        "huggingface/org/m",
    ):
        [match] = index.match_model(route)
        assert match.weight == 0.6, route


# -------------------------------------------------- Browserbase / Stagehand
def test_browserbase_sdk_alone_is_hosted_browser_infrastructure(
    tmp_path: Path, run_connector, index: SignatureIndex
):
    assert _ids(index.match_dependency("npm", "@browserbasehq/sdk")) == {"platform.browserbase"}
    assert _ids(index.match_dependency("pypi", "browserbase")) == {"platform.browserbase"}
    assert _ids(index.match_env("BROWSERBASE_API_KEY")) == {"platform.browserbase"}
    assert _ids(index.match_domain("connect.browserbase.com")) == {"platform.browserbase"}
    assert not index.get("platform.browserbase").agent_indicator
    findings = _scan(
        tmp_path,
        run_connector,
        {
            "package.json": '{"name": "crawler", "dependencies": {"@browserbasehq/sdk": "^2.0.0"}}\n',
            ".env.example": "BROWSERBASE_API_KEY=\nBROWSERBASE_PROJECT_ID=\n",
        },
    )
    assert findings, "the hosted-browser SDK must still be reported as usage"
    assert all("platform.browserbase" in f.frameworks for f in findings)
    assert not [f for f in findings if f.kind.value == "agent"]
    assert not any("framework.stagehand" in f.frameworks for f in findings)
    # The signature declares the browsing surface; whether a dependency alone
    # establishes it as an observed capability is the code connector's call.
    assert index.get("platform.browserbase").capabilities == ["browsing"]


def test_stagehand_sdk_is_the_browser_agent(tmp_path: Path, run_connector, index: SignatureIndex):
    assert _ids(index.match_dependency("npm", "@browserbasehq/stagehand")) == {"framework.stagehand"}
    assert _ids(index.match_dependency("pypi", "stagehand-py")) == {"framework.stagehand"}
    assert "platform.browserbase" not in _ids(index.match_dependency("npm", "@browserbasehq/stagehand"))
    findings = _scan(
        tmp_path,
        run_connector,
        {
            "package.json": '{"name": "shopper", "dependencies": {"@browserbasehq/stagehand": "^2.0.0"}}\n',
            "index.ts": (
                'import { Stagehand } from "@browserbasehq/stagehand";\n'
                'const stagehand = new Stagehand({ env: "BROWSERBASE" });\n'
                "await stagehand.init();\n"
            ),
        },
    )
    agent = next(f for f in findings if "framework.stagehand" in f.frameworks)
    assert agent.kind.value == "agent"
    assert "browsing" in agent.capabilities


@pytest.mark.parametrize(
    "model",
    [
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        "amazon.titan-text-express-v1",
        "amazon.nova-pro-v1:0",
        "meta.llama3-70b-instruct-v1:0",
        "mistral.mistral-large-2402-v1:0",
        "cohere.command-r-plus-v1:0",
        "ai21.jamba-1-5-large-v1:0",
        "deepseek.r1-v1:0",
        "openai.gpt-oss-120b-1:0",
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.amazon.nova-lite-v1:0",
    ],
)
def test_bedrock_model_ids_still_match(index: SignatureIndex, model: str):
    assert "provider.aws-bedrock" in _ids(index.match_model(model))


@pytest.mark.parametrize(
    "model",
    [
        "gpt-4o",
        "gpt-5",
        "chatgpt-4o-latest",
        "o1",
        "o1-mini",
        "o1-2024-12-17",
        "o3",
        "o3-mini",
        "o4-mini",
        "text-embedding-3-small",
        "dall-e-3",
        "dall-e",
        "whisper-1",
        "tts-1",
        "tts-1-hd",
        "davinci-002",
        "babbage-002",
        "computer-use-preview",
        "codex-mini-latest",
    ],
)
def test_openai_model_ids_still_match(index: SignatureIndex, model: str):
    assert "provider.openai" in _ids(index.match_model(model))


@pytest.mark.parametrize(
    "model", ["sonar", "sonar-pro", "sonar-reasoning-pro", "sonar-deep-research", "pplx-7b-online"]
)
def test_perplexity_model_ids_still_match(index: SignatureIndex, model: str):
    assert "provider.perplexity" in _ids(index.match_model(model))


# ------------------------------------------------ OpenAI-compatible shape
PLAIN_OPENAI_APP = (
    "from openai import OpenAI\n"
    "client = OpenAI()\n"
    'answer = client.chat.completions.create(model="gpt-4o", messages=[])\n'
)


def test_plain_openai_sdk_project_is_not_an_openai_compatible_override(
    tmp_path: Path, run_connector, index: SignatureIndex
):
    # The request shape belongs to every compatible server, so for
    # provider.openai-compatible it is ambiguous: it counts only next to a
    # base-URL override of the same signature.
    shape = [
        m
        for m in index.match_code(PLAIN_OPENAI_APP, "python")
        if m.signature_id == "provider.openai-compatible"
    ]
    assert shape and all(m.signal.ambiguous for m in shape)
    findings = _scan(
        tmp_path, run_connector, {"requirements.txt": "openai>=1.0\n", "app.py": PLAIN_OPENAI_APP}
    )
    assert any("provider.openai" in f.model_providers for f in findings)
    assert not any("provider.openai-compatible" in f.model_providers for f in findings)


def test_openai_client_with_a_base_url_is_an_openai_compatible_override(tmp_path: Path, run_connector):
    override = (
        "from openai import OpenAI\n"
        'client = OpenAI(base_url="http://localhost:8000/v1", api_key="local")\n'
        'answer = client.chat.completions.create(model="local-model", messages=[])\n'
    )
    findings = _scan(tmp_path, run_connector, {"requirements.txt": "openai>=1.0\n", "app.py": override})
    assert any("provider.openai-compatible" in f.model_providers for f in findings)
