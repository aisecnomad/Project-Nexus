"""Detection-rule packs are data: the names and hosts they detect are not usage.

Scanning ShadowScan's own repository rated it CRITICAL, mostly from the
environment-variable names and domains its signature packs list as patterns.
Any repository vendoring Semgrep, Sigma or gitleaks rules had the same false
positive. Only files wholly shaped as a rule pack are recognized; everything
else, including a file mixing rule keys with configuration, is scanned as before.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import rule_packs
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.rule_packs import detection_rule_format
from shadowscan.models import Finding, Kind
from shadowscan.signatures.loader import builtin_signature_dir

SHADOWSCAN_PACK = """signatures:
  - id: custom.acme-llm
    name: Acme LLM gateway
    category: platform
    signals:
      - type: env
        names: [OPENAI_API_KEY, ANTHROPIC_API_KEY, ACME_LLM_TOKEN]
      - type: domain
        values: [api.openai.com, api.anthropic.com, "*.acme-llm.example"]
      - type: code
        patterns: ['from\\s+openai\\s+import', 'AgentExecutor\\(']
"""

# The loader's list form, describing MCP: its patterns name MCP configuration keys.
MCP_PACK = """- id: custom.acme-mcp
  name: Acme MCP gateway
  category: protocol
  signals:
    - type: code
      patterns: ['mcpServers:', '"mcp_servers"']
    - type: domain
      values: [mcp.acme.example]
"""

SEMGREP_YAML = """rules:
  - id: hardcoded-openai-key
    message: OPENAI_API_KEY is read from source; call api.openai.com through the gateway
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: os.environ["OPENAI_API_KEY"]
      - pattern-regex: https://api\\.anthropic\\.com/v1/messages
  - id: langchain-agent-executor
    message: AgentExecutor runs tools chosen by the model
    severity: WARNING
    languages: [python]
    pattern: AgentExecutor(...)
"""

SEMGREP_JSON = (
    '{"rules": [{"id": "anthropic-key", "message": "ANTHROPIC_API_KEY in code",'
    ' "languages": ["generic"], "severity": "ERROR",'
    ' "pattern-regex": "ANTHROPIC_API_KEY|api.anthropic.com"}]}\n'
)

SIGMA = """title: LLM API key exported in a shell profile
id: 3b5b2f2e-8a0e-4c6b-9a1a-1f4d6c2b7e10
status: experimental
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'OPENAI_API_KEY='
      - 'api.openai.com'
      - 'mcpServers'
  condition: selection
level: medium
---
title: Model gateway contacted from a build agent
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: 'api.anthropic.com'
  condition: selection
"""

GITLEAKS = """title = "custom gitleaks rules"

[extend]
useDefault = true

[[rules]]
id = "acme-llm-token"
description = "ACME_LLM_TOKEN or OPENAI_API_KEY assignment"
regex = '''(?i)(?:ACME_LLM_TOKEN|OPENAI_API_KEY)\\s*=\\s*['"]?[a-z0-9-]{24,}'''
keywords = ["acme_llm_token", "openai_api_key"]

[allowlist]
paths = ['''docs/''']
"""

PACKS = {
    "rules/acme.yaml": SHADOWSCAN_PACK,
    "rules/mcp.yml": MCP_PACK,
    "semgrep/llm.yml": SEMGREP_YAML,
    "semgrep/llm.json": SEMGREP_JSON,
    "sigma/llm_keys.yml": SIGMA,
    ".gitleaks.toml": GITLEAKS,
}
FORMATS = {
    "rules/acme.yaml": "shadowscan-signatures",
    "rules/mcp.yml": "shadowscan-signatures",
    "semgrep/llm.yml": "semgrep",
    "semgrep/llm.json": "semgrep",
    "sigma/llm_keys.yml": "sigma",
    ".gitleaks.toml": "gitleaks",
}


def _format(name: str, text: str) -> str | None:
    """Classify ``text`` as the connector does: with its single parsed document, if it has one."""
    parsed: Any = None
    try:
        if name.endswith(".toml"):
            parsed = tomllib.loads(text)
        elif name.endswith(".json"):
            parsed = json.loads(text)
        else:
            parsed = yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        pass  # several YAML documents, or a syntax error
    return detection_rule_format(name, text, parsed)


def _scan(root: Path, files: dict[str, str]) -> tuple[list[Finding], ConnectorContext]:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False})
    findings = FilesystemConnector(ctx).run()
    assert ctx.stats is not None and not ctx.stats.errors and not ctx.stats.warnings, ctx.stats
    return findings, ctx


@pytest.mark.parametrize("name", sorted(PACKS))
def test_rule_pack_alone_is_not_llm_usage(tmp_path, name):
    findings, _ = _scan(tmp_path, {name: PACKS[name]})
    assert findings == []
    assert _format(name, PACKS[name]) == FORMATS[name]


def test_rule_packs_are_listed_beside_real_usage(tmp_path):
    files = {**PACKS, "app.py": "from openai import OpenAI\n\nclient = OpenAI()\n"}
    findings, _ = _scan(tmp_path, files)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert project.model_providers == ["provider.openai"]
    assert not project.frameworks
    assert {e.location.split(":")[0] for e in project.evidence} == {"app.py"}
    listed = project.metadata["detection_rule_files"]
    assert listed["count"] == 6 and sorted(listed["files"]) == sorted(PACKS)
    assert listed["formats"] == {"gitleaks": 1, "semgrep": 2, "shadowscan-signatures": 2, "sigma": 1}


@pytest.mark.parametrize(
    ("name", "text"),
    [
        # Rule keys beside configuration keys: the file is configuration.
        (
            "compose.yaml",
            "rules:\n  - id: x\n    message: m\n    pattern: p\n"
            "services:\n  bot:\n    image: python:3.12\n    environment:\n      - OPENAI_API_KEY=${OPENAI_API_KEY}\n",
        ),
        ("eslint.yml", "rules:\n  no-console: error\nenv:\n  OPENAI_API_KEY: placeholder\n"),
        ("semgrep.yml", "rules:\n  - id: no-message\n    pattern: os.environ['OPENAI_API_KEY']\n"),
        (
            "sigma.yml",
            "title: t\nlogsource: {product: linux}\ndetection: {condition: s}\nendpoint: https://api.openai.com/v1\n",
        ),
        (
            "pack.yaml",
            "signatures:\n  - id: custom.x\n    category: platform\n    signals: [{type: env, names: [X_KEY]}]\n"
            "settings:\n  url: https://api.openai.com/v1\n",
        ),
    ],
)
def test_files_only_partly_shaped_like_rules_are_scanned(tmp_path, name, text):
    findings, _ = _scan(tmp_path, {name: text})
    assert _format(name, text) is None
    project = next(f for f in findings if f.resource_type == "project")
    assert "provider.openai" in project.model_providers


def test_mcp_servers_beside_gitleaks_rules_are_still_an_mcp_configuration(tmp_path):
    text = (
        GITLEAKS
        + '\n[mcp_servers.files]\ncommand = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem"]\n'
    )
    findings, _ = _scan(tmp_path, {"config.toml": text})
    assert _format("config.toml", text) is None
    assert [f.kind for f in findings if f.kind == Kind.MCP_SERVER] == [Kind.MCP_SERVER]


def test_a_credential_inside_a_rule_pack_is_still_reported(tmp_path):
    # Synthetic, split so a scan of this repository does not report it.
    key = "sk-proj-" + "aP9rVv3qN4zY7bC2hJ8L" + "m5Qw6Dt0KsX1eR7uT4p"
    text = SEMGREP_YAML.replace("severity: WARNING", f"severity: WARNING\n    metadata: {{example: {key}}}")
    findings, _ = _scan(tmp_path, {"semgrep/llm.yml": text})
    assert _format("semgrep/llm.yml", text) == "semgrep"
    assert [f.kind for f in findings] == [Kind.SECRET]


def test_the_bundled_signature_packs_are_rule_packs():
    root = builtin_signature_dir()
    packs = sorted(root.rglob("*.yaml"))
    assert len(packs) >= 10
    for path in packs:
        rel = path.relative_to(root).as_posix()
        assert _format(rel, path.read_text(encoding="utf-8")) == "shadowscan-signatures", rel


def test_scanning_the_bundled_signature_packs_reports_nothing(tmp_path):
    files = {
        path.relative_to(builtin_signature_dir()).as_posix(): path.read_text(encoding="utf-8")
        for path in builtin_signature_dir().rglob("*.yaml")
    }
    findings, _ = _scan(tmp_path, files)
    assert findings == []


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("a.yaml", "signatures:\n  - id: custom.x\n    category: [framework]\n    signals: [{type: env}]\n"),
        ("b.yaml", "signatures:\n  - id: custom.x\n    category: framework\n    signals: [{type: [env]}]\n"),
        ("c.yaml", "signatures:\n  - id: custom.x\n    category: framework\n    signals: []\n"),
        ("d.yaml", "signatures: {}\n"),
        ("e.yaml", "rules:\n  - id: x\n    message: m\n    pattern: [unclosed\n"),
        (
            "f.yaml",
            "- id: custom.x\n  category: framework\n  signals: [{type: env, names: [A_KEY]}]\n---\n7\n",
        ),
        ("g.json", '{"rules": [{"id": "x", "message": "m"}]}'),
        ("h.toml", 'rules = [{id = "x", regex = "y", entropy = 3.5, colour = "red"}]\n'),
        ("i.toml", "rules = [\n"),
        ("j.yml", "logsource: {product: linux}\ndetection: {selection: {a: b}}\n"),
        ("k.txt", "rules:\n  - id: x\n    message: m\n    pattern: p\n"),
        ("l.yaml", "id: custom.x\ncategory: framework\nsignals: [{type: env}\n---\nid: custom.y\n"),
    ],
)
def test_malformed_or_incomplete_rule_shapes_are_not_rule_packs(name, text):
    assert _format(name, text) is None


def test_every_document_form_of_the_signature_loader_is_a_pack():
    signature = "id: custom.x\ncategory: framework\nsignals:\n  - type: env\n    names: [ACME_KEY]\n"
    assert _format("one.yaml", signature) == "shadowscan-signatures"
    listed = "- " + signature.replace("\n", "\n  ").rstrip() + "\n"
    assert _format("list.yml", listed) == "shadowscan-signatures"
    second = signature.replace("custom.x", "custom.y")
    assert _format("two.yaml", f"{signature}---\n{second}") == "shadowscan-signatures"


def test_a_manifest_bundle_is_not_parsed_a_second_time(monkeypatch):
    # Several documents with `rules:` (Kubernetes RBAC) cannot be a Semgrep file;
    # only formats that span documents justify parsing a stream again.
    role = "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nrules:\n  - verbs: [get]\n"
    monkeypatch.setattr(rule_packs, "strict_bounded_safe_load_all", lambda *_, **__: pytest.fail("parsed"))
    assert _format("rbac.yaml", f"{role}---\n{role}") is None
