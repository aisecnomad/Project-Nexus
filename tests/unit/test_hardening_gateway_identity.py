"""Regressions for the production-review round: gateway and identity connectors."""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import Mock

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.gateway import logs as logs_module
from shadowscan.connectors.gateway.logs import GatewayLogConnector, _f, _i, parse_text_line
from shadowscan.connectors.identity import jwt as jwt_module
from shadowscan.connectors.identity.auth0 import Auth0Connector
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.connectors.identity.okta import OktaConnector
from shadowscan.models import ScanStats, now_iso


def _ctx(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at=now_iso())
    return ctx


# ---------------------------------------------------------------- gateway


def test_gateway_numeric_helpers_only_yield_finite_numbers():
    assert _f("nan") == 0.0 and _f(1e999) == 0.0 and _f("inf") == 0.0 and _f("1.5") == 1.5
    assert _i("inf") == 0 and _i(10**400) == 0 and _i("12") == 12


def test_text_line_parsers_are_linear_on_hostile_input():
    started = time.monotonic()
    hostile = "Bearer " + "e" * 200_000 + " status=200"
    assert parse_text_line(hostile) == {"status": "200"}
    unterminated = '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET ' + "/a" * 100_000
    assert parse_text_line(unterminated) is None
    assert time.monotonic() - started < 2
    normal = 'ts=2026-01-01T00:00:00Z method=POST path="/v1/chat/completions" status=200 ua="langchain/0.3"'
    assert parse_text_line(normal) == {"ts": "2026-01-01T00:00:00Z", "method": "POST", "path": "/v1/chat/completions", "status": "200", "ua": "langchain/0.3"}
    combined = '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /v1/chat/completions HTTP/1.1" 200 5 "-" "langchain/0.3"'
    parsed = parse_text_line(combined)
    assert parsed and parsed["request_uri"] == "/v1/chat/completions" and parsed["http_user_agent"] == "langchain/0.3"
    without_protocol = '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /v1/models" 200 5'
    assert parse_text_line(without_protocol)["request_uri"] == "/v1/models"


def test_gateway_memoizes_user_agents_and_strips_query_strings(index, tmp_path):
    export = tmp_path / "gateway.jsonl"
    with export.open("w") as stream:
        for i in range(60):
            stream.write(json.dumps({
                "api_key": "key-one", "model": "gpt-4o", "metadata": {"user_agent": "langchain/0.3"}, "spend": 0.01,
                "call_type": f"/v1/chat/completions?session={i}", "startTime": f"2026-01-01T10:{i % 60:02d}:00Z",
            }) + "\n")
    connector = GatewayLogConnector(_ctx(index, input=str(export), format="litellm"))
    findings = connector.run()
    assert len(findings) == 1
    assert list(findings[0].metadata["operations"]) == ["/v1/chat/completions"]
    assert list(connector._ua_frameworks) == ["langchain/0.3"]
    assert findings[0].metadata["events"] == 60


def test_gateway_json_fallback_reports_a_corrupt_document_once(index, tmp_path):
    pretty = json.dumps([{"api_key": "k", "model": "gpt-4o", "spend": 1} for _ in range(50)], indent=2)
    export = tmp_path / "export.json"
    export.write_text(pretty[:-5])
    ctx = _ctx(index, input=str(export))
    GatewayLogConnector(ctx).run()
    assert ctx.stats.errors.count("gateway.logs: invalid JSON export") == 1 and len(ctx.stats.errors) == 1
    lines = [json.dumps({"api_key": "k", "model": "gpt-4o", "spend": 1})] + ["{broken"] * 30
    export.write_text("\n".join(lines))
    ctx = _ctx(index, input=str(export))
    GatewayLogConnector(ctx).run()
    assert 1 <= len(ctx.stats.errors) <= logs_module._MAX_INVALID_LINE_ERRORS + 1


def test_base_json_lines_caps_per_line_errors():
    reports: list[str] = []
    text = "\n".join(['{"id": "ok"}'] + ["{broken"] * 40)
    records = list(BaseConnector._json_lines(text, reports.append))
    assert records == [{"id": "ok"}]
    assert len(reports) == BaseConnector._MAX_INVALID_LINE_ERRORS + 1
    reports.clear()
    assert list(BaseConnector._json_lines("[\n  {\"a\": 1},\n", reports.append)) == []
    assert reports == ["invalid JSON export"]


def test_gateway_observation_buckets_are_bounded(index, tmp_path):
    export = tmp_path / "gateway.jsonl"
    with export.open("w") as stream:
        for i in range(logs_module._MAX_DISTINCT_KEYS + 10):
            stream.write(json.dumps({"api_key": "key-one", "model": "gpt-4o", "spend": 0.01, "environment": f"env-{i}"}) + "\n")
    findings = GatewayLogConnector(_ctx(index, input=str(export), format="litellm")).run()
    assert len(findings) == 1
    assert len(findings[0].metadata["runtime_observations"]) == logs_module._MAX_DISTINCT_KEYS
    assert findings[0].metadata["runtime_observations_dropped"] == 10


# --------------------------------------------------------------- identity


def _unsigned(claims: dict) -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}."


def test_jwt_hostile_numeric_claims_do_not_abort_other_tokens(index, monkeypatch):
    tokens = [
        _unsigned({"sub": "svc-a", "iss": "https://issuer.example", "iat": 1_700_000_000, "exp": 1_700_003_600}),
        _unsigned({"sub": "svc-b", "iss": "https://issuer.example", "iat": 10**400, "exp": "1" * 5000}),
        _unsigned({"sub": "svc-c", "iss": "https://issuer.example"}),
    ]
    ctx = _ctx(index, tokens=tokens)
    assert len(JwtConnector(ctx).run()) == 3  # huge numbers are unparsable timestamps, not crashes
    ctx = _ctx(index, tokens=tokens)
    connector = JwtConnector(ctx)
    original = connector.analyze_token

    def failing(token, **kwargs):
        if token == tokens[1]:
            raise ValueError("synthetic")
        return original(token, **kwargs)

    monkeypatch.setattr(connector, "analyze_token", failing)
    assert len(connector.run()) == 2
    assert any("token analysis failed (ValueError)" in warning for warning in ctx.stats.warnings)


def test_jwks_is_fetched_once_per_run(index, monkeypatch):
    fetches: list[str] = []

    def fake_fetch(url):
        fetches.append(url)
        return {"keys": []}

    monkeypatch.setattr(jwt_module, "fetch_jwks", fake_fetch)
    tokens = [_unsigned({"sub": f"svc-{i}", "iss": "https://issuer.example"}) for i in range(3)]
    ctx = _ctx(index, tokens=tokens, jwks_url="https://keys.example/jwks")
    findings = JwtConnector(ctx).run()
    assert len(findings) == 3 and fetches == ["https://keys.example/jwks"]
    assert all(f.metadata.get("verified") is False for f in findings)


def _okta_app(app_id: str, **overrides):
    app = {
        "id": app_id, "name": "oidc_client", "label": f"Service {app_id}", "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "settings": {"oauthClient": {"application_type": "service", "grant_types": ["client_credentials"]}},
        "credentials": {"oauthClient": {"client_id": f"client-{app_id}"}},
        "_grants": [{"scopeId": "okta.users.read"}], "_tokens": [],
    }
    app.update(overrides)
    return app


def test_okta_isolates_a_malformed_application_record(index):
    ctx = _ctx(index)
    connector = OktaConnector(ctx)
    records = [_okta_app("a"), _okta_app("b", settings="not-an-object"), _okta_app("c")]
    findings = list(connector.analyze(records))
    assert [f.title for f in findings] == ["Okta service app: Service a", "Okta service app: Service c"]
    assert ctx.stats.incomplete and any("malformed application record" in w for w in ctx.stats.warnings)


def test_auth0_isolates_a_malformed_client_record(index):
    ctx = _ctx(index)
    connector = Auth0Connector(ctx)
    good = {"_kind": "client", "client_id": "c1", "name": "support-agent-m2m", "app_type": "non_interactive", "grant_types": ["client_credentials"]}
    bad = {**good, "client_id": "c2", "name": "broken", "client_metadata": ["x"]}
    findings = list(connector.analyze([good, bad, {**good, "client_id": "c3", "name": "other-m2m"}]))
    assert len(findings) == 2
    assert ctx.stats.incomplete and any("malformed client record" in w for w in ctx.stats.warnings)


def test_gitlab_group_records_keep_the_plain_group_path(index):
    connector = GitLabConnector(ConnectorContext(index=index))
    connector._optional_list = Mock(side_effect=[[{"id": 7, "name": "bot"}], [], [{"key": "OPENAI_API_KEY", "masked": True}]])
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}
    records = list(connector._group_identities("my-org/platform"))
    assert {record["_kind"] for record in records} == {"service_account", "group_variables"}
    assert all(record["group"] == "my-org/platform" for record in records)
    assert "%2F" not in str(records)
    calls = [call.args[0] for call in connector._optional_list.call_args_list]
    assert all("/groups/my-org%2Fplatform/" in call for call in calls)
