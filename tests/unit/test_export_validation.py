"""Export shape and filesystem failures must never become a clean cached scan."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface


class RecordConnector(BaseConnector):
    name = "test.export"

    def collect(self):
        return []

    def analyze(self, records):
        for rec in records:
            self.ctx.examined()
            yield Finding(
                surface=Surface.CLOUD, connector=self.name, kind=Kind.AGENT,
                title=str(rec.get("name", "record")), resource=str(rec.get("id", "record")),
                resource_type="test", metadata=rec,
            )


def scan(path: Path, index):
    connector = RecordConnector(ConnectorContext({"input": str(path)}, index=index))
    findings = connector.run()
    return findings, connector.ctx.stats


@pytest.mark.parametrize("suffix,body", [
    (".json", 'true'), (".yaml", 'true'), (".json", 'null'),
    (".json", '[1, "broken"]'), (".json", '{}'),
    (".json", '{"records": null}'), (".json", '{"data": {}}'),
    (".json", '{"records": "not-a-list"}'),
    (".json", '{"records": [], "items": []}'),
    (".yaml", 'records: [1, nope]'), (".yaml", '42: nope'),
    (".yaml", '&cycle {name: bad, items: [*cycle]}'),
    (".jsonl", '123\nnull\n[]'),
])
def test_invalid_exports_mark_incomplete(tmp_path, index, suffix, body):
    path = tmp_path / f"export{suffix}"
    path.write_text(body)
    findings, stats = scan(path, index)
    assert not findings
    assert stats.incomplete and stats.errors


@pytest.mark.parametrize("suffix,body", [
    (".json", '[{"id":"one"}, 1, {"id":"two"}]'),
    (".json", '{"records":[{"id":"one"},null,{"id":"two"}]}'),
    (".yaml", '- id: one\n- 1\n- id: two\n'),
    (".jsonl", '{"id":"one"}\n{bad-json}\nfalse\n{"id":"two"}\n'),
    (".json", '{"id":"one"}\n{bad-json}\n{"id":"two"}\n'),
    (".csv", 'id,name\none,One\nwrong,column,extra\nshort\ntwo,Two\n'),
])
def test_valid_neighbors_survive_malformed_records(tmp_path, index, suffix, body):
    path = tmp_path / f"export{suffix}"
    path.write_text(body)
    findings, stats = scan(path, index)
    assert [finding.resource for finding in findings] == ["one", "two"]
    assert stats.incomplete and stats.errors
    assert stats.objects_examined == 2


@pytest.mark.parametrize("body", ['[]', '{"items":[]}'])
def test_explicit_empty_inventory_is_complete(tmp_path, index, body):
    path = tmp_path / "export.json"
    path.write_text(body)
    findings, stats = scan(path, index)
    assert not findings and not stats.incomplete and not stats.errors


@pytest.mark.parametrize("suffix,body", [
    (".json", ''), (".yaml", ' \n'), (".jsonl", '\n'), (".csv", ''),
    (".csv", 'id,id\na,b\n'), (".csv", 'id,\na,b\n'),
    (".csv", 'id,name\na,"unterminated\n'),
])
def test_empty_and_malformed_csv_exports_fail(tmp_path, index, suffix, body):
    path = tmp_path / f"export{suffix}"
    path.write_text(body)
    _, stats = scan(path, index)
    assert stats.incomplete and stats.errors


def test_native_record_and_usage_bucket_are_not_unwrapped(tmp_path, index):
    records = [
        {"_kind": "role", "name": "role", "resources": ["scope"]},
        {"object": "bucket", "start_time": 1, "end_time": 2, "results": [{"num_model_requests": 10}]},
    ]
    for number, record in enumerate(records):
        path = tmp_path / f"export{number}.json"
        path.write_text(json.dumps(record))
        findings, stats = scan(path, index)
        assert len(findings) == 1 and not stats.incomplete
        assert findings[0].metadata == record
    assert list(BaseConnector._unwrap({"object": "list", "data": [records[1]]})) == [records[1]]


def test_unwrap_without_context_fails_explicitly():
    with pytest.raises(ConnectorError, match="array"):
        list(BaseConnector._unwrap(True))


def test_errors_never_echo_malformed_secret_contents(tmp_path, index, caplog):
    secret = "opaque-SENSITIVE-secret-value"
    path = tmp_path / "export.yaml"
    path.write_text('password: [' + secret + '\n')
    findings, stats = scan(path, index)
    assert not findings and stats.incomplete
    assert secret not in repr(stats) + caplog.text
    path = tmp_path / "export.jsonl"
    path.write_text('{"password": "' + secret + '\n{"id":"ok","password":"' + secret + '"}\n')
    findings, stats = scan(path, index)
    assert len(findings) == 1 and stats.incomplete
    assert secret not in repr(findings[0].to_dict()) + repr(stats) + caplog.text


def test_unreadable_and_invalid_utf8_files_fail(tmp_path, index, monkeypatch):
    path = tmp_path / "export.json"
    path.write_bytes(b'[{"id":"one"}, "\xff"]')
    _, stats = scan(path, index)
    assert stats.incomplete
    path.write_text('[]')
    original = os.open

    def denied(name, *args, **kwargs):
        if name == path.name:
            raise PermissionError("denied")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(os, "open", denied)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, denied})
    _, stats = scan(path, index)
    assert stats.incomplete and stats.errors


def test_missing_empty_directory_and_special_file_fail(tmp_path, index):
    _, missing = scan(tmp_path / "missing.json", index)
    directory = tmp_path / "exports"
    directory.mkdir()
    _, empty = scan(directory, index)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    _, special = scan(fifo, index)
    assert all(stats.incomplete and stats.errors for stats in (missing, empty, special))


def test_symlinks_are_rejected_and_valid_directory_neighbors_survive(tmp_path, index):
    outside = tmp_path / "outside.json"
    outside.write_text('{"id":"outside"}')
    root = tmp_path / "exports"
    root.mkdir()
    (root / "valid.json").write_text('{"id":"valid"}')
    (root / "file.json").symlink_to(outside)
    (root / "linked-directory").symlink_to(tmp_path, target_is_directory=True)
    os.mkfifo(root / "fifo.json")
    findings, stats = scan(root, index)
    assert [finding.resource for finding in findings] == ["valid"]
    assert stats.incomplete
    for path in (root / "file.json", root / "linked-directory" / "outside.json"):
        findings, stats = scan(path, index)
        assert not findings and stats.incomplete


def test_directory_swap_to_symlink_cannot_redirect_file_open(tmp_path, index):
    directory = tmp_path / "exports"
    directory.mkdir()
    (directory / "data.json").write_text('{"id":"original"}')
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "data.json").write_text('{"id":"outside"}')
    connector = RecordConnector(ConnectorContext({"input": str(directory)}, index=index))
    original = connector._offline_files

    def swap(path):
        for file in original(path):
            directory.rename(tmp_path / "old")
            directory.symlink_to(outside, target_is_directory=True)
            yield file

    connector._offline_files = swap
    findings = connector.run()
    assert not findings and connector.ctx.stats.incomplete


def test_size_and_total_limits_mark_incomplete(tmp_path, index, monkeypatch):
    directory = tmp_path / "exports"
    directory.mkdir()
    body = '{"id":"one"}'
    (directory / "a.json").write_text(body)
    (directory / "b.json").write_text(body)
    monkeypatch.setattr(RecordConnector, "_MAX_OFFLINE_FILE_BYTES", len(body) - 1)
    findings, stats = scan(directory, index)
    assert not findings and stats.incomplete
    monkeypatch.setattr(RecordConnector, "_MAX_OFFLINE_FILE_BYTES", len(body))
    monkeypatch.setattr(RecordConnector, "_MAX_OFFLINE_TOTAL_BYTES", len(body))
    findings, stats = scan(directory, index)
    assert len(findings) == 1 and stats.incomplete


@pytest.mark.parametrize("body", ['true', '[1,"broken"]', '{"records":null}'])
def test_malformed_cloud_exports_are_never_cached(tmp_path, index, body):
    path = tmp_path / "export.json"
    path.write_text(body)
    config = ScanConfig(
        connectors=[ConnectorSpec("cloud.aws", {"input": str(path)})],
        incremental=True, state_dir=str(tmp_path / "state"), parallel=1,
    )
    for _ in range(2):
        result = Engine(config, index).run()
        assert not result.complete and not result.stats[0].cached
    assert not list((tmp_path / "state").glob("*.json"))


@pytest.mark.parametrize("marker", [
    {"has_more": True}, {"next_page": "opaque-pagination-secret"},
    {"@odata.nextLink": "https://example.test?token=secret"},
])
def test_paginated_export_preserves_records_but_marks_incomplete(tmp_path, index, marker):
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"records": [{"id": "one"}], **marker}))
    findings, stats = scan(path, index)
    assert len(findings) == 1 and stats.incomplete
    assert "opaque-pagination-secret" not in repr(stats) and "https://" not in repr(stats)


def _token():
    import jwt

    return jwt.encode({"sub": "agent", "agent_id": "example"}, "synthetic-signing-key-at-least-32-bytes", algorithm="HS256")


@pytest.mark.parametrize("suffix,body", [
    (".json", 'true'), (".json", '{}'), (".json", '[null,123]'),
    (".json", '{"token":false}'), (".json", '{"token":"malformed"}'),
    (".json", '{bad'), (".txt", '{bad'), (".txt", ''),
    (".txt", 'opaque-token-must-not-appear-in-diagnostics'),
])
def test_jwt_invalid_inputs_are_incomplete(tmp_path, index, suffix, body, caplog):
    from shadowscan.connectors.identity.jwt import JwtConnector

    path = tmp_path / f"tokens{suffix}"
    path.write_text(body)
    connector = JwtConnector(ConnectorContext({"input": str(path)}, index=index))
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert "opaque-token-must-not-appear-in-diagnostics" not in repr(connector.ctx.stats) + caplog.text


@pytest.mark.parametrize("suffix", [".json", ".jsonl", ".txt"])
def test_jwt_valid_neighbors_survive_invalid_records(tmp_path, index, suffix):
    from shadowscan.connectors.identity.jwt import JwtConnector

    token = _token()
    path = tmp_path / f"tokens{suffix}"
    if suffix == ".json":
        body = json.dumps([token, None, {"context": "missing-token"}, {"access_token": token}])
    elif suffix == ".jsonl":
        body = json.dumps({"token": token}) + '\n{bad-json}\n' + json.dumps(token)
    else:
        body = token + '\nbad-token\nBearer ' + token
    path.write_text(body)
    connector = JwtConnector(ConnectorContext({"input": str(path)}, index=index))
    findings = connector.run()
    assert len(findings) == 2 and connector.ctx.stats.incomplete
    assert token not in repr(findings) + repr(connector.ctx.stats)


def test_jwt_symlinks_and_size_limits_use_secure_loader(tmp_path, index, monkeypatch):
    from shadowscan.connectors.identity.jwt import JwtConnector

    outside = tmp_path / "tokens.txt"
    outside.write_text(_token())
    link = tmp_path / "link.txt"
    link.symlink_to(outside)
    connector = JwtConnector(ConnectorContext({"input": str(link)}, index=index))
    assert connector.run() == [] and connector.ctx.stats.incomplete
    monkeypatch.setattr(JwtConnector, "_MAX_OFFLINE_FILE_BYTES", 8)
    connector = JwtConnector(ConnectorContext({"input": str(outside)}, index=index))
    assert connector.run() == [] and connector.ctx.stats.incomplete


def test_jwt_config_requires_token_list(index):
    from shadowscan.connectors.identity.jwt import JwtConnector

    connector = JwtConnector(ConnectorContext({"tokens": _token()}, index=index))
    assert connector.run() == [] and connector.ctx.stats.incomplete
