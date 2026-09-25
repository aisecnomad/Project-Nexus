import json

from click.testing import CliRunner

from shadowscan.cli import main


def test_gateway_activity_refreshes_when_code_is_cached(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain==0.3.0\n")
    gateway = tmp_path / "gateway.jsonl"
    record = {
        "service": "svc-ops", "tenant_id": "tenant-a", "model": "gpt-4o",
        "user_agent": "langchain/0.3", "timestamp": "2026-09-22T10:00:00Z",
        "environment": "production",
    }
    gateway.write_text(json.dumps(record) + "\n")
    config = tmp_path / "scan.yaml"
    config.write_text("""
options:
  incremental: true
  state_dir: ./private-state
connectors:
  - name: code.filesystem
    path: ./repo
    label: github:acme/ops-agent
  - name: gateway.logs
    input: ./gateway.jsonl
    correlation_bindings:
      - code_resource: github:acme/ops-agent
        caller: principal:svc-ops
        scope: {tenant: tenant-a}
""")
    args = ["scan", "-c", str(config), "--format", "json"]
    first = CliRunner().invoke(main, args)
    assert first.exit_code == 0, first.output
    report = json.loads(first.stdout)
    code = next(f for f in report["findings"] if f["surface"] == "code")
    assert code["metadata"]["runtime_activity"]["production_observed"] is True
    assert code["metadata"]["runtime_activity"]["events"] == 1

    record.update(environment="staging", timestamp="2026-09-23T12:00:00Z")
    gateway.write_text(json.dumps(record) + "\n")
    second = CliRunner().invoke(main, args)
    assert second.exit_code == 0, second.output
    report = json.loads(second.stdout)
    code = next(f for f in report["findings"] if f["surface"] == "code")
    activity = code["metadata"]["runtime_activity"]
    assert activity["status"] == "observed"
    assert activity["production_observed"] is False
    assert activity["events"] == 1
    assert activity["last_seen"] == "2026-09-23T12:00:00+00:00"
    assert next(s for s in report["stats"] if s["connector"] == "github:acme/ops-agent")["cached"] is True
    assert next(s for s in report["stats"] if s["connector"] == "gateway.logs")["cached"] is False
