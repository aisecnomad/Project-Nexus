from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from pathlib import Path

from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters import FORMATS, render
from shadowscan.reporters.html import _JS


def _result(fixtures, index):
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec(
                name="code.filesystem", config={"path": str(fixtures / "sample_repo"), "label": "repo"}
            )
        ],
        inventory=[str(Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml")],
    )
    return Engine(cfg, index).run()


def test_all_formats_render(fixtures, index):
    result = _result(fixtures, index)
    out = render(result, "json")
    data = json.loads(out)
    assert data["summary"]["total"] == len(result.findings) and data["findings"][0]["risk"]["factors"]
    sarif = json.loads(render(result, "sarif"))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(result.findings)
    first = sarif["runs"][0]["results"][0]
    assert first["locations"] and first["ruleId"].startswith("shadowscan/")
    rows = list(csv.DictReader(io.StringIO(render(result, "csv"))))
    assert len(rows) == len(result.findings) and rows[0]["risk_level"] in {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    md = render(result, "markdown")
    assert md.startswith("# ShadowScan report") and "## Findings" in md and "Risk factors" in md
    html = render(result, "html")
    assert "<!doctype html>" in html and "tr class='row'" in html and "SHADOW" in html
    script_hash = base64.b64encode(hashlib.sha256(_JS.encode("utf-8")).digest()).decode("ascii")
    assert f"script-src 'sha256-{script_hash}'" in html
    assert "default-src 'none'" in html and "name='referrer' content='no-referrer'" in html
    assert set(FORMATS) == {"table", "csv", "cyclonedx", "html", "json", "markdown", "ocsf", "sarif"}
    cdx = json.loads(render(result, "cyclonedx"))
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6"
    ocsf = json.loads(render(result, "ocsf"))
    assert len(ocsf["events"]) == len(result.findings)
    assert {event["class_uid"] for event in ocsf["events"]} == {2004}
    assert all(event["severity_id"] in {1, 2, 3, 4, 5} for event in ocsf["events"])
    severity_ids = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    assert [event["severity_id"] for event in ocsf["events"]] == [
        severity_ids[f.risk.level.value] for f in result.findings
    ]
    assert ocsf["scan"]["status"] == "complete"


def test_reports_name_the_top_confidence_bucket_strong():
    findings = []
    for resource, weight in [("repo/high", 0.92), ("repo/mid", 0.5)]:
        finding = Finding(
            surface=Surface.CODE,
            connector="code.filesystem",
            kind=Kind.FRAMEWORK_USAGE,
            title=resource,
            resource=resource,
            resource_type="project",
            evidence=[Evidence(signal="dependency:pypi:openai", description="openai", weight=weight)],
        )
        finding.recompute_confidence()
        findings.append(finding)
    result = ScanResult(findings=findings, stats=[ScanStats(connector="code.filesystem", started_at="t")])

    data = json.loads(render(result, "json"))
    assert [item["likelihood"] for item in data["findings"]] == ["strong", "possible"]
    rows = list(csv.DictReader(io.StringIO(render(result, "csv"))))
    assert [row["likelihood"] for row in rows] == ["strong", "possible"]
    markdown = render(result, "markdown")
    assert "**Confidence:** 0.92 (strong)" in markdown and "(possible)" in markdown
    for fmt in sorted(set(FORMATS) - {"table"}):  # the table is drawn by the CLI and shows no label
        assert "confirmed" not in render(result, fmt).lower(), fmt


def test_markdown_report_defangs_untrusted_bare_urls(fixtures, index):
    result = _result(fixtures, index)
    finding = result.findings[0]
    finding.title = "Visit https://attacker.example/path or www.attacker.example"
    finding.evidence[0].description = "The source also referenced HTTP://login.attacker.example"

    report = render(result, "markdown")

    assert "hxxps://attacker.example/path" in report
    assert r"www\[.\]attacker.example" in report
    assert "hxxp://login.attacker.example" in report
    assert "https://attacker.example/path" not in report
    assert "HTTP://login.attacker.example" not in report


def test_cli_code_scan_and_outputs(tmp_path: Path, fixtures):
    runner = CliRunner()
    out = tmp_path / "r.json"
    res = runner.invoke(
        main, ["code", str(fixtures / "sample_repo"), "--format", "json", "-o", str(out), "--fail-on", "high"]
    )
    assert res.exit_code == 2, res.output  # high-risk findings present -> exit 2
    data = json.loads(out.read_text())
    assert data["summary"]["total"] >= 10
    res = runner.invoke(
        main,
        [
            "code",
            str(fixtures / "sample_repo"),
            "--max-rows",
            "3",
            "--inventory",
            str(Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml"),
        ],
    )
    assert res.exit_code == 0 and "ShadowScan" in res.output and "SHADOW" in res.output


def test_cli_run_gateway_jwt_and_utilities(tmp_path: Path, fixtures):
    runner = CliRunner()
    res = runner.invoke(
        main,
        [
            "run",
            "identity.okta",
            "--input",
            str(fixtures / "identity" / "okta_apps.json"),
            "--set",
            "org_url=https://acme.okta.com",
            "--format",
            "csv",
        ],
    )
    assert res.exit_code == 0 and "Otter.ai" in res.output
    res = runner.invoke(
        main, ["gateway", str(fixtures / "gateway" / "litellm_spend.jsonl"), "--format", "json"]
    )
    assert res.exit_code == 0 and json.loads(res.output)["summary"]["total"] == 2
    token = (fixtures / "identity" / "tokens.txt").read_text().splitlines()[1]
    res = runner.invoke(main, ["jwt", token, "--format", "json"])
    assert (
        res.exit_code == 0
        and json.loads(res.output)["findings"][0]["metadata"]["identity_type"] == "delegated-agent"
    )
    res = runner.invoke(main, ["connectors"])
    assert res.exit_code == 0 and "cloud.oci" in res.output and "identity.entra" in res.output
    res = runner.invoke(main, ["signatures", "list", "--category", "framework", "--json"])
    assert res.exit_code == 0 and any(s["id"] == "framework.crewai" for s in json.loads(res.output))
    res = runner.invoke(
        main, ["signatures", "test", "langchain-openai", "--kind", "dependency", "--ecosystem", "pypi"]
    )
    assert "framework.langchain" in res.output
    res = runner.invoke(main, ["signatures", "show", "protocol.mcp"])
    assert res.exit_code == 0 and "mcpServers" in res.output
    res = runner.invoke(
        main,
        [
            "inventory",
            "check",
            str(Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml"),
        ],
    )
    assert res.exit_code == 0 and "ops-provisioning-04" in res.output


def test_cli_scan_config_diff_and_stubs(tmp_path: Path, fixtures):
    runner = CliRunner()
    cfg = tmp_path / "s.yaml"
    cfg.write_text(
        f"connectors:\n  - name: cloud.aws\n    input: {fixtures / 'cloud' / 'aws_records.jsonl'}\n  - name: saas.slack\n    input: {fixtures / 'saas' / 'slack.json'}\n"
    )
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"

    def failure_details(output: str, report: Path) -> str:
        # With -o, the CLI prints only a fixed summary. Actual diagnostics live
        # in the reporter-sanitized stats; never print findings or raw inputs.
        try:
            stats = json.loads(report.read_text())["stats"]
        except (OSError, ValueError, KeyError):
            stats = "no readable JSON report stats"
        return f"{output}\nSanitized connector stats: {json.dumps(stats, indent=2)}"

    res = runner.invoke(
        main, ["scan", "-c", str(cfg), "--only", "cloud.aws", "--format", "json", "-o", str(a)]
    )
    assert res.exit_code == 0, failure_details(res.output, a)
    res = runner.invoke(main, ["scan", "-c", str(cfg), "--format", "json", "-o", str(b)])
    assert res.exit_code == 0, failure_details(res.output, b)
    res = runner.invoke(main, ["diff", str(a), str(b)])
    assert res.exit_code == 3 and "new" in res.output and "Slack" in res.output
    assert "scope differs" in res.output
    stubs = tmp_path / "stubs"
    res = runner.invoke(main, ["inventory", "stubs", str(b), "-o", str(stubs)])
    assert res.exit_code == 0 and list(stubs.glob("*.yaml"))
    text = next(stubs.glob("*.yaml")).read_text()
    assert "agent_id" in text and "discovery" in text
