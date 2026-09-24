"""Residual production fixes ported during the 0.1.1 consolidation.

Credential-shaped strings are assembled at runtime from low-entropy fillers so
repository secret scanners do not flag this file.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, RiskLevel, ScanResult, ScanStats, Surface, now_iso
from shadowscan.reporters import render
from shadowscan.utils.http import MAX_RETRY_DELAY, HttpClient, HttpError, _rate_limited, _retry_delay
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

# ------------------------------------------------------------------ HTTP retries


def _response(status: int, headers: dict[str, str] | None = None, body: bytes = b'{"ok": true}') -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp.headers.update(headers or {})
    resp._content = body
    resp._content_consumed = True  # type: ignore[attr-defined]
    return resp


class _ScriptedSession(requests.Session):
    def __init__(self, *responses: requests.Response):
        super().__init__()
        self.scripted = list(responses)
        self.calls = 0

    def request(self, method, url, **kwargs):  # type: ignore[override]
        self.calls += 1
        return self.scripted.pop(0)


@pytest.fixture
def sleep(monkeypatch):
    mock = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", mock)
    return mock


def _client(*responses: requests.Response) -> tuple[HttpClient, _ScriptedSession]:
    session = _ScriptedSession(*responses)
    return HttpClient("https://api.github.com", session=session), session


def test_primary_rate_limit_403_waits_for_reset_then_succeeds(sleep):
    reset = str(int(time.time()) + 30)
    http, session = _client(_response(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}), _response(200))
    assert http.get_json("/orgs/acme/repos") == {"ok": True} and session.calls == 2
    (delay,), _ = sleep.call_args
    assert 29 <= delay <= MAX_RETRY_DELAY


def test_secondary_rate_limit_403_honors_retry_after(sleep):
    http, _ = _client(_response(403, {"Retry-After": "7"}), _response(200))
    assert http.get_json("/search/code") == {"ok": True}
    (delay,), _ = sleep.call_args
    assert 7 <= delay <= 8


def test_permission_403_is_not_retried(sleep):
    http, session = _client(_response(403), _response(200))
    with pytest.raises(HttpError):
        http.get_json("/orgs/acme/repos")
    assert session.calls == 1 and not sleep.called


def test_backoff_without_hints_is_jittered_within_bounds():
    delays = {_retry_delay(_response(503), attempt=3) for _ in range(200)}
    assert all(4 <= d <= 8 for d in delays) and len(delays) > 50


def test_every_delay_is_capped():
    far = str(int(time.time()) + 3600)
    assert _retry_delay(_response(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": far}), 1) == MAX_RETRY_DELAY
    assert _retry_delay(_response(429, {"Retry-After": "999999"}), 1) == MAX_RETRY_DELAY
    assert _rate_limited(_response(403, {"Retry-After": "1"})) and not _rate_limited(_response(404, {"Retry-After": "1"}))


# ------------------------------------------------------------- webhook redaction


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


def test_record_exports_withhold_webhook_credentials(tmp_path: Path):
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
    result = Engine(config).run()
    assert result.complete and result.findings
    exported = "".join(path.read_text() for path in (tmp_path / "exports").glob("*.jsonl"))
    report = result.to_json()
    for secret_part in (slack.rsplit("/", 1)[1], discord.rsplit("/", 1)[1]):
        assert secret_part not in exported
        assert secret_part not in report
    assert '"webhookUri": "' + REDACTED + '"' in exported
    assert '"url": "https://discord.com/api/webhooks/' + REDACTED + '"' in exported


# ------------------------------------------------------------------ SARIF output


def _finding(location: str, root: str = "/repo", level: RiskLevel = RiskLevel.LOW, title: str = "Agent") -> Finding:
    finding = Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT, title=title,
                      resource=f"{root}/{title}", resource_type="project", frameworks=["framework.langchain"])
    finding.add_evidence(Evidence(signal="import", description="import", location=location))
    finding.metadata["scan_root"] = root
    finding.risk.level = level
    return finding


def _sarif(*findings: Finding) -> dict:
    result = ScanResult(findings=list(findings), stats=[ScanStats(connector="code.filesystem", started_at="t")])
    return json.loads(render(result, "sarif"))


def _uris(sarif: dict) -> list[dict]:
    return [loc["physicalLocation"]["artifactLocation"] for res in sarif["runs"][0]["results"] for loc in res["locations"]]


def test_sarif_uris_are_percent_encoded_and_root_relative():
    (artifact,) = _uris(_sarif(_finding("/repo/dir with space/agent#1%.py:3")))
    assert artifact == {"uri": "dir%20with%20space/agent%231%25.py", "uriBaseId": "%SRCROOT%"}


def test_sarif_root_prefix_respects_path_boundaries():
    (artifact,) = _uris(_sarif(_finding("/repo2/agent.py:1", root="/repo")))
    assert artifact == {"uri": "file:///repo2/agent.py"}


@pytest.mark.parametrize("order", [(RiskLevel.LOW, RiskLevel.CRITICAL), (RiskLevel.CRITICAL, RiskLevel.LOW)])
def test_sarif_rule_severity_is_the_most_severe_result(order):
    findings = [_finding(f"/repo/{i}.py:1", level=level, title=f"Agent {i}") for i, level in enumerate(order)]
    (rule,) = _sarif(*findings)["runs"][0]["tool"]["driver"]["rules"]
    assert rule["properties"]["security-severity"] == "9.5" and rule["defaultConfiguration"]["level"] == "error"


# ------------------------------------------------------- Keycloak classification


def _unsigned(claims: dict) -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}."


def _ctx(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at=now_iso())
    return ctx


def test_service_account_username_only_marks_keycloak_issuers(index):
    claims = {"sub": "u1", "iss": "https://id.example/oauth", "preferred_username": "service-account-ci"}
    keycloak = {**claims, "iss": "https://id.example/realms/prod"}
    other, kc = (JwtConnector(_ctx(index, tokens=[_unsigned(c)])).run()[0] for c in (claims, keycloak))
    assert other.metadata["identity_type"] == "human"
    assert kc.metadata["identity_type"] == "service" and "Keycloak service account" in str(kc.metadata)
