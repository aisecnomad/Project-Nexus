"""Ambiguous export objects cannot erase findings or attest complete coverage."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import jwt
import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.cloud.aws import _iam_policy_signals

_APP = '{"id":"observed-agent","name":"OpenAI ChatGPT"}'
_DUPLICATE_APP = '{"id":"ambiguous-agent","name":"OpenAI ChatGPT","name":"Calendar"}'
_EVENT = '{"service":"observed-agent","model":"gpt-4o","provider":"openai"}'
_DUPLICATE_EVENT = '{"service":"ambiguous-agent","model":"gpt-4o","model":"calendar"}'
_PRIVATE_KEY = "private-export-field-that-must-not-appear-in-diagnostics"


@pytest.mark.parametrize("suffix,body", [
    ("json", '{"apps":[' + _APP + '],"apps":[]}'),
    ("json", '[' + _DUPLICATE_APP + ']'),
    ("json", '{"apps":[' + _APP + '],"next_cursor":"next-page","next_cursor":null}'),
    ("json", '{"apps":[],"error":{"message":"denied"},"error":null}'),
    ("json", '{"apps":[],"response_metadata":{"next_cursor":"next-page","next_cursor":""}}'),
    ("yaml", "apps:\n  - id: observed-agent\n    name: OpenAI ChatGPT\napps: []\n"),
    ("yaml", "apps:\n  - id: ambiguous-agent\n    name: OpenAI ChatGPT\n    name: Calendar\n"),
    ("yaml", "apps: []\nnext_cursor: next-page\nnext_cursor: null\n"),
    ("yaml", "apps: []\nerror: denied\nerror: null\n"),
    ("yaml", "apps: [{<<: {name: Calendar, name: OpenAI ChatGPT}, id: ambiguous-agent}]\n"),
])
def test_duplicate_inventory_keys_cannot_attest_complete_coverage(tmp_path, run_connector, suffix, body):
    source = tmp_path / f"inventory.{suffix}"
    source.write_text(body, encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert ctx.stats.errors
    assert "next-page" not in str(ctx.stats.errors)


@pytest.mark.parametrize("suffix", ["json", "jsonl", "ndjson"])
def test_inventory_json_lines_preserve_valid_neighbors(tmp_path, fixtures, run_connector, suffix):
    source = tmp_path / f"inventory.{suffix}"
    # The .json case exercises the accepted one-object-per-line fallback.
    source.write_text((fixtures / "assurance" / "duplicate_inventory_keys.jsonl").read_text(), encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert len(findings) == 2
    assert ctx.stats.incomplete
    assert any("line 2" in error for error in ctx.stats.errors)
    assert all("ambiguous-agent" not in finding.resource for finding in findings)


@pytest.mark.parametrize("suffix", ["json", "yaml"])
def test_repeated_keys_in_separate_inventory_records_remain_valid(tmp_path, run_connector, suffix):
    source = tmp_path / f"inventory.{suffix}"
    if suffix == "json":
        body = '{"apps":[' + _APP + ',{"id":"another-agent","name":"OpenAI ChatGPT"}]}'
    else:
        body = "apps:\n  - id: observed-agent\n    name: OpenAI ChatGPT\n  - id: another-agent\n    name: OpenAI ChatGPT\n"
    source.write_text(body, encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert len(findings) == 2
    assert not ctx.stats.incomplete


def test_yaml_merge_defaults_and_explicit_overrides_remain_valid(tmp_path, run_connector):
    source = tmp_path / "inventory.yaml"
    source.write_text(
        "apps:\n"
        "  - &defaults\n"
        "    id: normal-app\n"
        "    name: Calendar\n"
        "  - <<: *defaults\n"
        "    id: observed-agent\n"
        "    name: OpenAI ChatGPT\n",
        encoding="utf-8",
    )

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert len(findings) == 1
    assert not ctx.stats.incomplete


def test_yaml_merge_does_not_hide_duplicate_explicit_keys(tmp_path, run_connector):
    source = tmp_path / "inventory.yaml"
    source.write_text(
        "apps:\n"
        "  - &defaults {id: normal-app, name: Calendar}\n"
        "  - <<: *defaults\n"
        "    id: ambiguous-agent\n"
        "    name: OpenAI ChatGPT\n"
        "    name: Calendar\n",
        encoding="utf-8",
    )

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete


@pytest.mark.parametrize("suffix,body", [
    ("json", '{"apps":[],"' + _PRIVATE_KEY + '":1,"' + _PRIVATE_KEY + '":2}'),
    ("yaml", "apps: []\n" + _PRIVATE_KEY + ": 1\n" + _PRIVATE_KEY + ": 2\n"),
])
def test_cli_rejects_ambiguous_exports_without_echoing_field_names(tmp_path: Path, suffix: str, body: str):
    source = tmp_path / f"inventory.{suffix}"
    source.write_text(body, encoding="utf-8")

    result = CliRunner().invoke(main, ["run", "saas.generic", "--input", str(source), "--format", "json"])

    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert report["findings"] == []
    assert _PRIVATE_KEY not in result.output


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_inventory_json_cannot_report_complete(tmp_path, run_connector, constant):
    source = tmp_path / "inventory.json"
    source.write_text('{"apps":[],"metadata":' + constant + '}', encoding="utf-8")

    findings, ctx = run_connector("saas.generic", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete


@pytest.mark.parametrize("suffix", ["json", "jsonl", "ndjson", "txt"])
def test_duplicate_jwt_export_fields_are_rejected(tmp_path, run_connector, suffix):
    token = jwt.encode({"sub": "synthetic-agent", "agent_id": "sample"}, "", algorithm="none")
    record = '{"token":' + json.dumps(token) + ',"token":' + json.dumps(token) + '}'
    source = tmp_path / f"tokens.{suffix}"
    source.write_text(record, encoding="utf-8")

    findings, ctx = run_connector("identity.jwt", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert token not in str(ctx.stats.errors)


@pytest.mark.parametrize("suffix", ["jsonl", "ndjson"])
def test_jwt_json_lines_preserve_valid_neighbors(tmp_path, run_connector, suffix):
    token = jwt.encode({"sub": "synthetic-agent", "agent_id": "sample"}, "", algorithm="none")
    good = json.dumps({"token": token})
    bad = '{"token":' + json.dumps(token) + ',"context":{"source":"one","source":"two"}}'
    source = tmp_path / f"tokens.{suffix}"
    source.write_text("\n".join([good, bad, good]), encoding="utf-8")

    findings, ctx = run_connector("identity.jwt", input=str(source))

    assert len(findings) == 2
    assert ctx.stats.incomplete
    assert any("line 2" in error for error in ctx.stats.errors)
    assert token not in str(ctx.stats.errors)


@pytest.mark.parametrize("header,claims", [
    ('{"alg":"none","alg":"none"}', '{"sub":"synthetic-agent"}'),
    ('{"alg":"none"}', '{"sub":"synthetic-agent","agent_id":"sample","agent_id":null}'),
    ('{"alg":"none"}', '{"sub":"synthetic-agent","act":{"sub":"first","sub":"second"}}'),
])
def test_duplicate_encoded_jwt_fields_are_rejected(tmp_path, run_connector, header, claims):
    segments = [base64.urlsafe_b64encode(part.encode()).decode().rstrip("=") for part in (header, claims)]
    token = ".".join([*segments, ""])
    source = tmp_path / "tokens.jwt"
    source.write_text(token, encoding="utf-8")

    findings, ctx = run_connector("identity.jwt", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert token not in str(ctx.stats.errors + ctx.stats.warnings)


@pytest.mark.parametrize("suffix", ["json", "jsonl", "ndjson", "log", "txt", "gz"])
def test_gateway_duplicate_json_lines_preserve_valid_neighbors(tmp_path, run_connector, suffix):
    source = tmp_path / f"gateway.{suffix}"
    body = "\n".join([_EVENT, _DUPLICATE_EVENT, _EVENT])
    if suffix == "gz":
        with gzip.open(source, "wt", encoding="utf-8") as stream:
            stream.write(body)
    else:
        source.write_text(body, encoding="utf-8")

    findings, ctx = run_connector("gateway.logs", input=str(source))

    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert ctx.stats.incomplete


@pytest.mark.parametrize("body", [
    '{"logEvents":[{"message":' + json.dumps(_EVENT) + '}],"logEvents":[]}',
    '{"logEvents":[],"next_cursor":"next-page","next_cursor":null}',
])
def test_gateway_duplicate_envelope_keys_are_rejected(tmp_path, run_connector, body):
    source = tmp_path / "gateway.json"
    source.write_text(body, encoding="utf-8")

    findings, ctx = run_connector("gateway.logs", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete


@pytest.mark.parametrize("field", ["message", "textPayload"])
def test_gateway_embedded_duplicate_json_preserves_valid_neighbors(tmp_path, run_connector, field):
    source = tmp_path / "gateway.json"
    source.write_text(json.dumps({"logEvents": [
        {field: _EVENT}, {field: _DUPLICATE_EVENT}, {field: _EVENT},
    ]}), encoding="utf-8")

    findings, ctx = run_connector("gateway.logs", input=str(source))

    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert ctx.stats.incomplete


@pytest.mark.parametrize("fields", [
    {"request_body": '{"tools":[{"type":"function"}],"tools":[]}'},
    {"request": {"tools": '[{"type":"function","type":"none"}]'}},
    {"response": '{"tool_calls":[{"id":"one"}],"tool_calls":[]}'},
    {"response": {"tool_calls": '[{"id":"one","id":"two"}]'}},
    {"category": "RequestResponse", "resourceId": "/synthetic/account",
     "properties": '{"modelName":"gpt-4o","modelName":"calendar"}'},
])
def test_gateway_duplicate_embedded_payloads_mark_partial_coverage(tmp_path, run_connector, fields):
    good = json.loads(_EVENT)
    source = tmp_path / "gateway.jsonl"
    source.write_text("\n".join(json.dumps(record) for record in [good, {**good, **fields}, good]), encoding="utf-8")

    findings, ctx = run_connector("gateway.logs", input=str(source))

    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert ctx.stats.incomplete


def test_iam_policy_duplicate_fields_are_partial_without_erasing_other_policies():
    ambiguous = '{"Statement":[{"Effect":"Allow","Action":"bedrock:*","Action":"s3:GetObject","Resource":"*"}]}'
    good = {"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}]}

    actions, _, _, limitations = _iam_policy_signals([ambiguous, good])

    assert actions == {"bedrock:InvokeModel"}
    assert "malformed-policy" in limitations


def test_workato_duplicate_embedded_recipe_code_marks_partial_coverage(tmp_path, run_connector):
    source = tmp_path / "recipes.json"
    source.write_text(json.dumps({"items": [{
        "id": 1, "name": "Synthetic recipe", "config": [{"provider": "openai"}],
        "code": '{"keyword":"trigger","keyword":"action","provider":"openai"}',
    }]}), encoding="utf-8")

    findings, ctx = run_connector("lowcode.workato", input=str(source))

    assert len(findings) == 1  # Independent configuration evidence remains useful.
    assert ctx.stats.incomplete
    assert any("trigger coverage incomplete" in warning for warning in ctx.stats.warnings)
