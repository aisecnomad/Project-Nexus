"""Regressions for credential exposure, report injection and scan completeness."""

from __future__ import annotations

import csv
import io
import json
import stat

import jwt
import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.code.filesystem import _excerpt
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.connectors.saas.generic import GenericSaaSConnector
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters.csv_ import render_csv
from shadowscan.signatures.loader import Signature
from shadowscan.signatures.matcher import SignatureIndex
from shadowscan.utils.redaction import REDACTED, credential_id, sanitize, sanitize_text

SECRET = "opaque-synthetic-credential-value"
PROVIDER_KEY = "sk-proj-syntheticcredentialvaluenotarealkey"


def _index():
    return SignatureIndex([Signature(id="framework.test", name="Test", category="framework")])


def _finding(**kwargs):
    return Finding(surface=Surface.CODE, connector="test", kind=Kind.AGENT,
                   title=kwargs.pop("title", "Agent"), resource="repo:example", resource_type="repository", **kwargs)


def test_sanitizes_structured_credentials_urls_argv_and_copies():
    original = {
        "api_key": SECRET,
        "note": f"debug copy {SECRET}",
        "config": {
            "env": {"CUSTOM_CREDENTIAL_NAME": SECRET, "MODE": "debug"},
            "args": ["--token", SECRET, "--model", "gpt-example", "PASSWORD='a value with spaces'"],
            "url": f"https://user:{SECRET}@example.com/path?token={SECRET}&model=gpt-example",
        },
        "environment": "production", "repository": "org/repo", "deployment_id": "deploy-1",
        "events": 15, "capabilities": ["tool-use", "memory"],
    }
    result = sanitize(original)
    assert SECRET not in json.dumps(result)
    assert "a value with spaces" not in json.dumps(result)
    assert result["config"]["env"] == {"CUSTOM_CREDENTIAL_NAME": REDACTED, "MODE": REDACTED}
    assert result["config"]["args"][3] == "gpt-example"
    assert "model=gpt-example" in result["config"]["url"]
    for key in ("environment", "repository", "deployment_id", "events", "capabilities"):
        assert result[key] == original[key]
    assert sanitize(result) == result
    assert original["api_key"] == SECRET  # analysis still receives the original input


@pytest.mark.parametrize("record", [
    {"env": [{"name": "PASSWORD", "value": SECRET}]},
    {"environment": [{"name": "CUSTOM_NAME", "value": SECRET}]},
    {"Environment": {"Variables": {"CUSTOM_NAME": SECRET}}},
    {"key": "OPENAI_API_KEY", "value": SECRET},
    {"Name": "CLIENT_SECRET", "Value": SECRET},
    {"SecretString": SECRET},
    {"keyString": SECRET},
    {"privateKeyData": SECRET},
])
def test_cloud_environment_and_name_value_exports(record):
    assert SECRET not in json.dumps(sanitize(record))


def test_gcp_api_key_string_never_reaches_report_or_record_dump(tmp_path, index):
    secret = "opaque-private-google-api-value-123"
    export = tmp_path / "api-keys.jsonl"
    export.write_text(json.dumps({
        "_kind": "api-key", "_project": "test-project",
        "name": "projects/test-project/locations/global/keys/example",
        "displayName": "Gemini service", "keyString": secret,
    }) + "\n")
    dumped = tmp_path / "dumped"
    config = ScanConfig(connectors=[ConnectorSpec("cloud.gcp", {"input": str(export)})],
                        dump_records=str(dumped))
    result = Engine(config, index).run()
    assert result.complete
    assert any(finding.kind == Kind.SECRET for finding in result.findings)
    dump_files = list(dumped.glob("*.jsonl"))
    assert len(dump_files) == 1
    assert json.loads(dump_files[0].read_text())["keyString"] == REDACTED
    assert secret not in result.to_json() and secret not in dump_files[0].read_text()


@pytest.mark.parametrize("value", [
    f'OPENAI_API_KEY = "{PROVIDER_KEY}"',
    f'password="{SECRET}"',
    f'wrapper = "api_key={SECRET}"',
    f"Authorization: Bearer {SECRET}",
    f"https://example.com?api_key={SECRET}&safe=yes",
    f"https://example.com?%61pi_key={SECRET}&safe=yes",
    f"https://user:{SECRET}@example.com/path",
    "-----BEGIN PRIVATE KEY-----\n" + SECRET + "\n-----END PRIVATE KEY-----",
])
def test_text_redaction_idempotent(value):
    result = sanitize_text(value)
    assert SECRET not in result and PROVIDER_KEY not in result
    assert sanitize_text(result) == result


def test_credential_fingerprint_is_stable_nonsecret_and_survives_sanitization():
    identity = credential_id(SECRET)
    assert identity == credential_id(SECRET) == credential_id(identity)
    assert identity != credential_id(SECRET + "other")
    assert SECRET not in identity
    assert sanitize({"api_key": identity, "caller": identity}) == {"api_key": identity, "caller": identity}


def test_finding_and_serialization_sanitize_sibling_evidence():
    f = _finding(title=f"Agent {PROVIDER_KEY}", metadata={"api_key": SECRET, "repository": "org/repo"},
                 evidence=[Evidence(signal="import", description=f"copy {SECRET}", snippet=f"import langchain; KEY='{PROVIDER_KEY}'")],
                 capabilities=["tool-use"])
    assert SECRET not in str(f.evidence)
    assert PROVIDER_KEY not in f.title
    f.metadata["password"] = SECRET
    f.title = f"Agent {PROVIDER_KEY}"
    result = f.to_dict()
    assert SECRET not in json.dumps(result) and PROVIDER_KEY not in json.dumps(result)
    assert f.capabilities == ["tool-use"] and f.metadata["repository"] == "org/repo"


class _RecordConnector(BaseConnector):
    name = "test.records"

    def collect(self):
        yield {"api_key": SECRET, "debug": SECRET, "environment": "production"}

    def analyze(self, records):
        for record in records:
            self.ctx.examined()
            finding = _finding()
            finding.metadata = record
            yield finding


def test_export_is_sanitized_atomic_and_owner_only(tmp_path):
    target = tmp_path / "records.jsonl"
    target.write_text("old contents")
    target.chmod(0o644)
    connector = _RecordConnector(ConnectorContext(config={"_dump_path": str(target)}, index=_index()))
    findings = connector.run()
    assert SECRET not in target.read_text()
    assert SECRET not in str(findings)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.loads(target.read_text())["environment"] == "production"
    assert list(tmp_path.iterdir()) == [target]
    assert not connector.ctx.stats.errors


def test_jwt_dump_never_writes_token_records(tmp_path):
    target = tmp_path / "jwt.jsonl"
    token = jwt.encode({"sub": "agent", "agent_id": "agent-1"}, "synthetic-test-signing-key-only-32-bytes", algorithm="HS256")
    connector = JwtConnector(ConnectorContext(config={"tokens": [token], "_dump_path": str(target)}, index=_index()))
    findings = connector.run()
    assert len(findings) == 1 and not connector.ctx.stats.errors
    assert not target.exists()
    assert token not in json.dumps(findings[0].to_dict())
    assert findings[0].metadata["agent_claims"]["agent_id"] == "agent-1"


def test_generic_saas_does_not_copy_arbitrary_export_columns():
    connector = GenericSaaSConnector(ConnectorContext(config={"keep_all": True}, index=_index()))
    result = list(connector.analyze([{"name": "Agent", "id": "app-1", "users": 4, "custom_private_column": SECRET}]))
    assert len(result) == 1
    assert SECRET not in json.dumps(result[0].to_dict())
    assert result[0].metadata["users"] == 4
    assert "raw" not in result[0].metadata


@pytest.mark.parametrize("formula", ["=1+1", "+1+1", "-1+1", "@SUM(1)", "\t=1+1", "\r=1+1", "\n=1+1", "  =1+1", "\ufeff=1+1"])
def test_csv_formula_values_are_literal_text(formula):
    f = _finding(title=formula, owner=formula, evidence=[Evidence(signal="test", description=formula)])
    row = next(csv.DictReader(io.StringIO(render_csv(ScanResult(findings=[f])))))
    for column in ("title", "owner", "top_evidence"):
        assert row[column] == "'" + formula
    assert row["confidence"] == "0.0"


def test_incomplete_status_and_sanitized_context_diagnostics(caplog):
    context = ConnectorContext(index=_index())
    context.stats = ScanStats(connector="test", started_at="now")
    assert ScanResult(stats=[context.stats]).complete
    context.warn("advisory only", incomplete=False)
    assert ScanResult(stats=[context.stats]).complete
    context.warn(f"could not access url?api_key={SECRET}")
    assert not ScanResult(stats=[context.stats]).complete
    context.error(f"password={SECRET}")
    assert SECRET not in str(context.stats) and SECRET not in caplog.text
    assert not ScanResult().complete
    assert ScanResult(stats=[context.stats]).summary()["status"] == "incomplete"


def test_completed_findings_survive_connector_failure():
    class PartialConnector(_RecordConnector):
        def analyze(self, records):
            yield from super().analyze(records)
            raise ValueError(f"bad token={SECRET}")

    connector = PartialConnector(ConnectorContext(index=_index()))
    findings = connector.run()
    assert len(findings) == 1
    result = ScanResult(findings=findings, stats=[connector.ctx.stats])
    assert not result.complete and result.summary()["errors"] == 1
    assert SECRET not in result.to_json()


def test_cyclic_untrusted_metadata_does_not_recurse_or_leak():
    record = {"token": SECRET}
    record["cycle"] = record
    safe = sanitize(record)
    assert safe == {"token": REDACTED, "cycle": REDACTED}
    assert SECRET not in str(_finding(metadata=record).to_dict())


def test_machine_signal_identifiers_and_jwt_fingerprints_are_preserved():
    for value in ("jwt:hygiene", "jwt:delegated-agent", "jwt:1234567890abcdef", "secret:provider.openai"):
        assert sanitize_text(value) == value


def test_source_secret_copies_are_redacted_using_parsed_environment_and_argv():
    parsed = {"env": {"CUSTOM_NAME": SECRET}, "args": ["--token", "other-opaque-credential"]}
    source = json.dumps(parsed)
    safe = sanitize({"source": source, "parsed": parsed})["source"]
    assert SECRET not in safe and "other-opaque-credential" not in safe


def test_safe_token_statistics_and_secret_reference_lists_are_preserved():
    value = {"tokens": 12, "secrets": ["approved-secret-reference"], "environment": "production"}
    assert sanitize(value) == value


def test_multiline_private_keys_preserve_source_line_numbers():
    source = "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----\nimport langchain"
    safe = sanitize_text(source)
    assert source.count("\n") == safe.count("\n")
    assert safe.splitlines()[3] == "import langchain"
    assert "secret-material" not in safe


@pytest.mark.parametrize("from_environment", [False, True])
def test_diagnostics_redact_opaque_configured_credentials(caplog, monkeypatch, from_environment):
    config = {} if from_environment else {"api_key": SECRET}
    context = ConnectorContext(config=config, index=_index())
    context.stats = ScanStats(connector="test", started_at="now")
    if from_environment:
        monkeypatch.setenv("TEST_PROVIDER_KEY", SECRET)
        assert context.get("api_key", env="TEST_PROVIDER_KEY") == SECRET
    message = f"remote server rejected supplied value {SECRET}"
    context.warn(message)
    context.error(message)
    assert SECRET not in str(context.stats) and SECRET not in caplog.text


@pytest.mark.parametrize("credential", [
    "gsk_" + "a" * 40,
    "pcsk_" + "a" * 20,
    "e2b_" + "a" * 40,
    "tgp_v1_" + "a" * 30,
    "lsv2_pt_" + "a" * 32 + "_" + "b" * 10,
    "tvly-prod-" + "a" * 20,
    "xai-" + "a" * 60,
    "pplx-" + "a" * 40,
    "csk-" + "a" * 30,
    "nvapi-" + "a" * 60,
    "r8_" + "a" * 30,
    "fc-" + "a" * 32,
    "app-" + "a" * 24,
])
def test_additional_provider_tokens_are_redacted(credential):
    assert credential not in sanitize_text(f"credential={credential}")


def test_ssws_authorization_is_redacted():
    credential = "synthetic-okta-token-value"
    assert credential not in sanitize_text(f"Authorization: SSWS {credential}")


def test_repr_escaped_configured_secret_is_redacted():
    credential = "first-line\nsecond-line"
    result = sanitize({"client_secret": credential, "debug": repr(credential)})
    assert credential not in result["debug"]
    assert repr(credential)[1:-1] not in result["debug"]


def test_long_secret_is_redacted_before_excerpt_truncation():
    credential = "opaque-" + "x" * 240
    excerpt = _excerpt([f"token={credential}"], 1, credential)
    assert credential not in excerpt
    assert credential[:120] not in excerpt
