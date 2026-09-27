"""Webhook capability URLs and connection-string fields are credentials.

Credential-shaped strings are assembled at runtime from low-entropy fillers so
repository secret scanners do not flag this file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text


def _slack() -> str:
    return "https://hooks.slack.com/services/" + "T" + "0" * 8 + "/" + "B" + "0" * 8 + "/" + "x" * 24


def _discord() -> str:
    return "https://discord.com/api/webhooks/" + "1" * 18 + "/" + "y" * 68


WEBHOOKS = {
    "slack": (_slack, "https://hooks.slack.com/services/"),
    "slack-workflow": (lambda: "https://hooks.slack.com/triggers/" + "E" + "0" * 8 + "/" + "9" * 12 + "/" + "z" * 32,
                       "https://hooks.slack.com/triggers/"),
    "discord": (_discord, "https://discord.com/api/webhooks/"),
    "discord-versioned": (lambda: "https://discordapp.com/api/v10/webhooks/" + "1" * 18 + "/" + "y" * 68,
                          "https://discordapp.com/api/v10/webhooks/"),
    "teams": (lambda: "https://acme.webhook.office.com/webhookb2/" + "a" * 8 + "@tenant/IncomingWebhook/" + "b" * 32 + "/" + "c" * 8,
              "https://acme.webhook.office.com/webhookb2/"),
    "zapier": (lambda: "https://hooks.zapier.com/hooks/catch/" + "1" * 7 + "/" + "q" * 7 + "/", "https://hooks.zapier.com/hooks/"),
    "make": (lambda: "https://hook.eu1.make.com/" + "m" * 32, "https://hook.eu1.make.com/"),
    "ifttt": (lambda: "https://maker.ifttt.com/trigger/deploy/with/key/" + "k" * 22, "https://maker.ifttt.com/trigger/deploy/with/key/"),
    "telegram": (lambda: "https://api.telegram.org/bot" + "1" * 9 + ":AA" + "t" * 33 + "/sendMessage", "https://api.telegram.org/bot"),
    "n8n": (lambda: "https://n8n.acme.example/webhook/" + "5" * 8 + "-aaaa-bbbb-cccc-" + "6" * 12, "https://n8n.acme.example/webhook/"),
    "n8n-subpath": (lambda: "https://acme.example/automation/webhook-test/lead-intake", "https://acme.example/automation/webhook-test/"),
}


@pytest.mark.parametrize("name", sorted(WEBHOOKS))
def test_webhook_capability_urls_withhold_their_path_secret(name):
    build, prefix = WEBHOOKS[name]
    url = build()
    out = sanitize_text(f"notify via {url} now")
    assert out == f"notify via {prefix}{REDACTED} now"
    assert sanitize_text(out) == out


@pytest.mark.parametrize("text", [
    "https://api.github.com/repos/acme/app/hooks/123",
    "https://docs.slack.com/services/overview",
    "https://discord.com/channels/1/2",
    "https://hooks.slack.com/services/",
    "https://example.com/docs/webhooks",
    "my webapp-configuration-for-production-envs",
    "requests.get(url, timeout=30)",
])
def test_benign_urls_and_identifiers_are_unchanged(text):
    assert sanitize_text(text) == text


@pytest.mark.parametrize("key", ["webhookUrl", "webhook_uri", "webhookId", "AccountKey", "SharedAccessKey", "sas_token"])
def test_capability_and_connection_string_fields_are_sensitive(key):
    assert sanitize({key: "opaque-capability-value"}) == {key: REDACTED}


def test_record_exports_withhold_webhook_credentials(tmp_path: Path, index):
    """Regression: --dump-records wrote n8n webhook URLs verbatim."""
    slack, discord = _slack(), _discord()
    export = tmp_path / "n8n.json"
    export.write_text(json.dumps([{
        "id": "wf1", "name": "Lead triage", "active": True,
        "nodes": [
            {"type": "@n8n/n8n-nodes-langchain.agent", "name": "AI Agent", "parameters": {}},
            {"type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "name": "OpenAI", "parameters": {"model": "gpt-4o"}},
            {"type": "n8n-nodes-base.slack", "name": "Notify", "parameters": {"webhookUri": slack}},
            {"type": "n8n-nodes-base.httpRequest", "name": "Discord", "parameters": {"url": discord}},
        ],
    }]))
    config = ScanConfig(
        connectors=[ConnectorSpec(name="lowcode.n8n", config={"input": str(export)})],
        dump_records=str(tmp_path / "exports"),
    )
    result = Engine(config, index).run()
    assert result.complete and result.findings
    exported = "".join(path.read_text() for path in (tmp_path / "exports").glob("*.jsonl"))
    report = result.to_json()
    for secret_part in (slack.rsplit("/", 1)[1], discord.rsplit("/", 1)[1]):
        assert secret_part not in exported
        assert secret_part not in report
    assert '"webhookUri": "' + REDACTED + '"' in exported
    assert '"url": "https://discord.com/api/webhooks/' + REDACTED + '"' in exported
