"""A product named in data or prose is a mention: it cannot by itself establish AI use.

The benchmark's false alarms included a crawler list linking to zapier.com, a
market-map CSV and RSS feed linking to openrouter.ai, and an app catalogue
whose summary named a model gateway. A host or variable name there is still
recorded, but only a call, a configured endpoint, an import or a dependency
anchors a project finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

NOTE = "only named in data or prose fields"


def _scan(tmp_path: Path, run_connector, files: dict[str, str]) -> tuple[list, object]:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False)


@pytest.mark.parametrize(
    "files",
    [
        {"market.csv": "date,name,url\n2025-12,Gateway,https://openrouter.ai/state-of-ai\n"},
        {
            "feeds/ai.xml": '<?xml version="1.0"?>\n<rss><item><link>https://openrouter.ai/rank</link></item></rss>\n'
        },
        {"crawlers.json": '[\n  {\n    "pattern": "Zapier",\n    "url": "https://zapier.com/"\n  }\n]\n'},
        {
            "apps/metadata.json": '{\n  "summary": "Bring your OpenRouter key from openrouter.ai to start"\n}\n'
        },
        {"site.yaml": "homepage: https://openrouter.ai\ndescription: links\n"},
    ],
    ids=["csv", "rss-feed", "json-link", "json-summary", "yaml-homepage"],
)
def test_names_in_data_or_prose_do_not_establish_ai_use(tmp_path: Path, run_connector, files) -> None:
    findings, ctx = _scan(tmp_path, run_connector, files)
    assert findings == []
    assert not ctx.stats.incomplete
    assert any(NOTE in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize(
    "files",
    [
        {"config.json": '{\n  "endpoint": "https://openrouter.ai/api/v1/chat/completions"\n}\n'},
        {"config.json": '{\n  "url": "https://openrouter.ai/api/v1"\n}\n'},
        {"settings.yaml": "base_url: https://openrouter.ai/api/v1\n"},
        {"page.html": '<script>fetch("https://openrouter.ai/api/v1/chat/completions")</script>\n'},
        {"network.xml": "<config><domain>openrouter.ai</domain></config>\n"},
    ],
    ids=["json-endpoint", "json-api-url", "yaml-base-url", "html-api-call", "plain-xml"],
)
def test_configured_endpoints_still_establish_ai_use(tmp_path: Path, run_connector, files) -> None:
    findings, ctx = _scan(tmp_path, run_connector, files)
    assert any("provider.openrouter" in f.model_providers for f in findings)
    assert not any(NOTE in warning for warning in ctx.stats.warnings)


def test_a_mention_is_still_evidence_of_a_project_with_ai_use(tmp_path: Path, run_connector) -> None:
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {
            "requirements.txt": "openai\n",
            "app.py": 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="m", messages=[])\n',
            "market.csv": "name,url\nGateway,https://openrouter.ai/state-of-ai\n",
        },
    )
    (project,) = [f for f in findings if f.resource_type == "project"]
    assert any(e.location.startswith("market.csv") for e in project.evidence)
