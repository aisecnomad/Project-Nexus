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
    ["amazon.com", "openai.com", "writer.md", "qwen.config", "meta.json", "o1ne", "tts-config", "sonar-qube"],
)
def test_ordinary_strings_are_not_model_ids(index: SignatureIndex, model: str):
    assert index.match_model(model) == []


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
