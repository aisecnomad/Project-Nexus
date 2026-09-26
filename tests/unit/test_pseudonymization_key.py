"""An operator-held key makes gateway pseudonyms stable across scans; nothing else does."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.utils.pseudonym import ENV_VAR, PseudonymKeyError, load_pseudonymization_key

FIXTURE = Path(__file__).parents[1] / "fixtures" / "gateway" / "litellm_spend.jsonl"
SECRET = b"k3y-material-" + b"x" * 40


def key_file(tmp_path: Path, name: str = "pseudonym.key", content: bytes = SECRET, mode: int = 0o600) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    path.chmod(mode)
    return path


def gateway_scan(key: Path | None, **options):
    cfg = ScanConfig(connectors=[ConnectorSpec(name="gateway.logs", config={"input": str(FIXTURE)})],
                     pseudonymization_key_file=str(key) if key else None, **options)
    return Engine(cfg).run()


def test_key_file_is_read_into_a_derived_key_and_short_identifier(tmp_path):
    loaded = load_pseudonymization_key(key_file(tmp_path))
    again = load_pseudonymization_key(key_file(tmp_path, "copy.key"))
    other = load_pseudonymization_key(key_file(tmp_path, "other.key", b"another-secret-" + b"y" * 40))
    assert loaded.key_id == again.key_id != other.key_id and len(loaded.key_id) == 16
    assert SECRET not in loaded.key and loaded.subkey("gateway") != loaded.key
    assert "key=" not in repr(loaded) and loaded.key.hex() not in repr(loaded)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
@pytest.mark.parametrize(("content", "mode", "message"), [
    (SECRET, 0o640, "only by its owner"),
    (SECRET, 0o604, "only by its owner"),
    (b"short", 0o600, "bytes of secret material"),
    (b"x" * 5000, 0o600, "exceeds"),
])
def test_unsafe_or_weak_key_files_are_refused(tmp_path, content, mode, message):
    with pytest.raises(PseudonymKeyError, match=message):
        load_pseudonymization_key(key_file(tmp_path, content=content, mode=mode))


def test_symlinked_or_missing_key_files_are_refused(tmp_path):
    target = key_file(tmp_path)
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(PseudonymKeyError, match="symbolic link"):
        load_pseudonymization_key(link)
    with pytest.raises(PseudonymKeyError, match="unreadable"):
        load_pseudonymization_key(tmp_path / "missing.key")


def test_gateway_identities_are_stable_with_a_key_and_scan_local_without(tmp_path):
    key = key_file(tmp_path)
    first, second = gateway_scan(key), gateway_scan(key)
    assert first.findings and sorted(f.id for f in first.findings) == sorted(f.id for f in second.findings)
    unkeyed = gateway_scan(None)
    assert sorted(f.id for f in unkeyed.findings) != sorted(f.id for f in first.findings)
    assert unkeyed.collection_scope["comparable"] is False


def test_keyed_gateway_scans_attest_comparable_scope_bound_to_the_key(tmp_path):
    key = key_file(tmp_path)
    first, second = gateway_scan(key), gateway_scan(key)
    other = gateway_scan(key_file(tmp_path, "other.key", b"another-secret-" + b"y" * 40))
    assert first.collection_scope["comparable"] is True
    assert first.collection_scope["fingerprint"] == second.collection_scope["fingerprint"]
    assert other.collection_scope["fingerprint"] != first.collection_scope["fingerprint"]
    report = json.dumps(first.to_dict())
    assert SECRET.decode() not in report and load_pseudonymization_key(key).key.hex() not in report
    diff = compare_reports(first.to_dict(), second.to_dict())
    assert diff["comparable"] is True, diff["reasons"]
    assert diff["new"] == [] and diff["resolved"] == [] and diff["changed"] == []


def test_environment_variable_supplies_the_key_file(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_VAR, str(key_file(tmp_path)))
    assert sorted(f.id for f in gateway_scan(None).findings) == sorted(f.id for f in gateway_scan(None).findings)


def test_cli_reports_an_unusable_key_file_clearly(tmp_path):
    bad = key_file(tmp_path, content=b"short")
    result = CliRunner().invoke(main, ["gateway", str(FIXTURE), "--format", "json", "-o", str(tmp_path / "r.json")],
                                env={ENV_VAR: str(bad)})
    assert result.exit_code == 1
    assert "pseudonymization key file must hold" in result.output
