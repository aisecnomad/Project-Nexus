"""SHADOWSCAN_IDENTITY_KEY: an opt-in stable key for gateway identities.

Without it, gateway pseudonyms and finding IDs are keyed per scan and reports
cannot be linked. With it, identical inputs keep identical IDs, findings say
``identity_scope: keyed`` and ``diff`` can match them. The key itself must
never leave the process: not in reports, record exports, caches, logs or
error text.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import IDENTITY_KEY_ENV, build_collection_scope, compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector
from shadowscan.engine import Engine
from shadowscan.errors import SetupError
from shadowscan.reporters import FORMATS
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.utils.redaction import credential_id

KEY = hashlib.sha256(b"shadowscan test identity key").digest()
OTHER_KEY = hashlib.sha256(b"another shadowscan test identity key").digest()
ROWS = [
    {"api_key": "opaque-gateway-key-1", "model": "gpt-4o", "user_agent": "langchain/0.3"},
    {"service": "svc-ops", "tenant_id": "tenant-a", "model": "gpt-4o"},
    {"user": "alice@example.com", "model": "claude-3-5-sonnet", "prompt_tokens": 12},
]


def _credential_source(tmp_path, surface):
    """Small low-entropy synthetic value, recognized by a local test signature."""
    candidate = "copper-73-moon"
    index = SignatureIndex(
        [
            signature_from_dict(
                {
                    "id": "provider.synthetic-credential",
                    "name": "Synthetic provider",
                    "category": "provider",
                    "signals": [
                        {"type": "env", "names": ["COPPER_API_KEY"]},
                        {"type": "secret", "patterns": [candidate]},
                    ],
                }
            )
        ]
    )
    if surface == "code":
        source = tmp_path / "repo"
        source.mkdir()
        (source / "agent.py").write_text(f"COPPER_API_KEY = '{candidate}'\n")
        spec = ConnectorSpec("code.filesystem", {"path": str(source), "use_git": False})
    else:
        source = tmp_path / "cloud.json"
        source.write_text(
            json.dumps(
                [
                    {"_kind": "account", "account": "123456789012"},
                    {
                        "_kind": "lambda",
                        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:worker",
                        "FunctionName": "worker",
                        "Environment": {"COPPER_API_KEY": candidate},
                    },
                ]
            )
        )
        spec = ConnectorSpec("cloud.aws", {"input": str(source)})
    return (
        ScanConfig(connectors=[spec], incremental=True, state_dir=str(tmp_path / "state")),
        index,
        candidate,
    )


def _credential_ids(result):
    return set(re.findall(r"credential:hmac-sha256:[a-f0-9]{64}", result.to_json()))


@pytest.mark.parametrize("surface", ["code", "cloud"])
def test_code_and_cloud_credentials_are_scan_local_without_a_stable_key(tmp_path, monkeypatch, surface):
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    config, index, candidate = _credential_source(tmp_path, surface)
    outside = credential_id(candidate)
    first, second = Engine(config, index).run(), Engine(config, index).run()
    assert first.complete and second.complete
    assert first.findings and second.findings
    assert _credential_ids(first) and _credential_ids(second)
    assert _credential_ids(first).isdisjoint(_credential_ids(second))
    assert _credential_ids(first).isdisjoint({outside})
    assert credential_id(candidate) == outside  # worker context did not leak to the caller
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert first.collection_scope["credential_identity_scope"] == "run"
    assert not first.stats[0].cached and not second.stats[0].cached
    assert not list((tmp_path / "state").glob("*.json"))
    public = "credential:sha256:" + hashlib.sha256(candidate.encode()).hexdigest()
    assert candidate not in first.to_json() and public not in first.to_json()


@pytest.mark.parametrize("surface", ["code", "cloud"])
def test_stable_credential_key_controls_cache_and_comparison_without_disclosure(
    tmp_path, monkeypatch, caplog, surface
):
    config, index, candidate = _credential_source(tmp_path, surface)
    monkeypatch.setenv(IDENTITY_KEY_ENV, KEY.hex())
    first, second = Engine(config, index).run(), Engine(config, index).run()
    assert first.complete and second.complete
    assert _credential_ids(first) and _credential_ids(first) == _credential_ids(second)
    assert second.stats[0].cached
    assert first.collection_scope["credential_identity_scope"] == "keyed"
    stored = "".join(path.read_text() for path in (tmp_path / "state").glob("*.json"))
    assert stored and candidate not in stored
    for form in _key_forms(KEY):
        assert form not in first.to_json() and form not in stored and form not in caplog.text
    monkeypatch.setenv(IDENTITY_KEY_ENV, OTHER_KEY.hex())
    rotated = Engine(config, index).run()
    assert rotated.complete and not rotated.stats[0].cached
    assert _credential_ids(rotated).isdisjoint(_credential_ids(first))
    assert rotated.collection_scope["fingerprint"] != first.collection_scope["fingerprint"]
    comparison = compare_reports(first.to_dict(), rotated.to_dict())
    assert not comparison["comparable"] and comparison["resolved"] == []


def test_parallel_code_and_cloud_workers_share_one_private_credential_key(tmp_path, monkeypatch):
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    code_dir, cloud_dir = tmp_path / "code", tmp_path / "cloud"
    code_dir.mkdir()
    cloud_dir.mkdir()
    code, index, _ = _credential_source(code_dir, "code")
    cloud, _, _ = _credential_source(cloud_dir, "cloud")
    result = Engine(ScanConfig(connectors=[*code.connectors, *cloud.connectors], parallel=2), index).run()
    assert result.complete and len(result.findings) >= 2
    assert len(_credential_ids(result)) == 1


def _key_forms(key: bytes) -> list[str]:
    """Every textual form in which the key could leak."""
    return [
        key.hex(),
        key.hex().upper(),
        base64.b64encode(key).decode(),
        base64.urlsafe_b64encode(key).decode(),
        key.decode("latin-1"),
    ]


def _export(tmp_path: Path, rows: list[dict] = ROWS) -> Path:
    export = tmp_path / "gateway.jsonl"
    export.write_text(
        "".join(json.dumps({**row, "timestamp": "2026-09-22T10:00:00Z"}) + "\n" for row in rows)
    )
    return export


def _config(export: Path) -> ScanConfig:
    return ScanConfig(connectors=[ConnectorSpec("gateway.logs", {"input": str(export)}, label="gw")])


def _scan(export: Path, index) -> dict:
    result = Engine(_config(export), index).run()
    assert result.complete
    return result.to_dict()


def _ids(report: dict) -> list[str]:
    return sorted(finding["id"] for finding in report["findings"])


def test_stable_key_keeps_gateway_ids_comparable_across_scans(tmp_path, index, monkeypatch):
    export = _export(tmp_path)
    monkeypatch.setenv(IDENTITY_KEY_ENV, KEY.hex())
    before = _scan(export, index)
    # The same key in its other accepted encoding is the same key.
    monkeypatch.setenv(IDENTITY_KEY_ENV, f" {base64.b64encode(KEY).decode()}\n")
    after = _scan(export, index)
    assert len(_ids(before)) == len(ROWS) and _ids(before) == _ids(after)
    assert all(f["metadata"]["identity_scope"] == "keyed" for f in before["findings"] + after["findings"])
    assert before["collection_scope"]["comparable"] is True
    assert before["collection_scope"] == after["collection_scope"]
    comparison = compare_reports(before, after)
    assert comparison["comparable"] and comparison["reasons"] == []
    assert comparison["new"] == comparison["resolved"] == comparison["unknown"] == comparison["changed"] == []
    assert comparison["not_comparable"] == {"baseline": [], "current": []}


def test_caller_missing_under_the_same_key_and_scope_is_resolved(tmp_path, index, monkeypatch):
    monkeypatch.setenv(IDENTITY_KEY_ENV, KEY.hex())
    before = _scan(_export(tmp_path), index)
    after = _scan(_export(tmp_path, ROWS[1:]), index)
    comparison = compare_reports(before, after)
    assert comparison["comparable"] and comparison["new"] == []
    assert [f["metadata"]["caller_kind"] for f in comparison["resolved"]] == ["api-key"]


def test_a_different_key_never_resolves_earlier_findings(tmp_path, index, monkeypatch):
    export = _export(tmp_path)
    monkeypatch.setenv(IDENTITY_KEY_ENV, KEY.hex())
    before = _scan(export, index)
    monkeypatch.setenv(IDENTITY_KEY_ENV, OTHER_KEY.hex())
    after = _scan(export, index)
    assert not set(_ids(before)) & set(_ids(after))
    comparison = compare_reports(before, after)
    assert not comparison["comparable"] and comparison["resolved"] == []
    assert "collection or detection scope differs" in comparison["reasons"]
    assert len(comparison["unknown"]) == len(ROWS)


def test_without_the_key_gateway_scope_stays_unattested(tmp_path, index, monkeypatch):
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    report = _scan(_export(tmp_path), index)
    assert all(f["metadata"]["identity_scope"] == "run" for f in report["findings"])
    scope = report["collection_scope"]
    assert scope["comparable"] is False and "fingerprint" not in scope
    assert IDENTITY_KEY_ENV in scope["reason"]


def test_keyed_gateway_scope_covers_configuration_without_disclosing_it(tmp_path, index):
    binding = {"caller": "principal:worker", "code_resource": "github:org/app", "scope": {"tenant": "t1"}}
    spec = ConnectorSpec(
        "gateway.logs", {"input": str(tmp_path / "g.jsonl"), "correlation_bindings": [binding]}
    )
    config = ScanConfig(connectors=[spec])
    scope = build_collection_scope(config, index, [spec], identity_key=KEY)
    assert scope["comparable"] is True and "t1" not in json.dumps(scope) and "worker" not in json.dumps(scope)
    assert build_collection_scope(config, index, [spec], identity_key=KEY) == scope
    assert build_collection_scope(config, index, [spec], identity_key=OTHER_KEY) != scope
    changed = ConnectorSpec("gateway.logs", {**spec.config, "correlation_bindings": []})
    assert build_collection_scope(config, index, [changed], identity_key=KEY) != scope
    assert build_collection_scope(config, index, [spec])["comparable"] is False


def test_direct_connector_scope_follows_the_context_key():
    stable = ConnectorContext(
        config={"input": "x.jsonl"},
        index=SignatureIndex([]),
        gateway_identity_key=KEY,
        gateway_identity_key_stable=True,
    )
    assert GatewayLogConnector(stable).identity_scope == "keyed"
    per_run = ConnectorContext(
        config={"input": "x.jsonl"}, index=SignatureIndex([]), gateway_identity_key=KEY
    )
    assert GatewayLogConnector(per_run).identity_scope == "run"
    keyless = ConnectorContext(
        config={"input": "x.jsonl"}, index=SignatureIndex([]), gateway_identity_key_stable=True
    )
    assert GatewayLogConnector(keyless).identity_scope == "run"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "00" * 31,
        "0" * 63,
        base64.b64encode(bytes(31)).decode(),
        "z" * 32,
        "not a key at all, though long enough to be one",
        "é" * 64,
    ],
    ids=[
        "empty",
        "blank",
        "31-bytes-hex",
        "odd-hex",
        "31-bytes-base64",
        "24-bytes-base64",
        "text",
        "non-ascii",
    ],
)
def test_short_or_malformed_key_is_a_setup_error_before_scanning(tmp_path, monkeypatch, value):
    export = _export(tmp_path)
    monkeypatch.setenv(IDENTITY_KEY_ENV, value)
    with pytest.raises(SetupError) as raised:
        Engine(_config(export), SignatureIndex([]))
    message = str(raised.value)
    assert IDENTITY_KEY_ENV in message
    assert not value.strip() or value.strip() not in message
    result = CliRunner().invoke(main, ["gateway", str(export)], env={IDENTITY_KEY_ENV: value})
    assert result.exit_code == 1, result.output
    assert IDENTITY_KEY_ENV in result.output and "Traceback" not in result.output
    assert not value.strip() or value.strip() not in result.output


def test_key_never_appears_in_reports_exports_caches_or_logs(tmp_path):
    export = _export(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\n")
    config = tmp_path / "shadowscan.yaml"
    config.write_text(
        "connectors:\n"
        f"  - name: code.filesystem\n    path: {repo}\n"
        f"  - name: gateway.logs\n    input: {export}\n    label: gw\n"
    )
    env = {IDENTITY_KEY_ENV: base64.b64encode(KEY).decode()}
    outputs: list[str] = []
    for number, fmt in enumerate(FORMATS):
        report = tmp_path / f"report-{number}.{fmt}"
        dumps = tmp_path / f"records-{number}"
        args = ["-vv", "scan", "-c", str(config), "--format", fmt, "-o", str(report)]
        args += ["--dump-records", str(dumps), "--incremental", "--state-dir", str(tmp_path / "state")]
        result = CliRunner().invoke(main, args, env=env)
        assert result.exit_code == 0, result.output
        outputs.append(result.output)
        if fmt in {"json", "table"}:  # table also writes its JSON report to the file
            findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
            gateway = [f for f in findings if f["connector"] == "gateway.logs"]
            assert gateway and all(f["metadata"]["identity_scope"] == "keyed" for f in gateway)
    written = [
        path.read_text(encoding="utf-8", errors="replace") for path in tmp_path.rglob("*") if path.is_file()
    ]
    assert len(written) > len(FORMATS)
    for text in [*outputs, *written]:
        for form in _key_forms(KEY):
            assert form not in text
