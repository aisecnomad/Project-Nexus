"""CycloneDX output: one component per finding, properties, no evidence snippets or secrets."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.reporters import FORMATS

AGENT = """from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool

@tool
def lookup(q: str) -> str:
    return q

agent = create_react_agent(ChatOpenAI(model="gpt-4o"), [lookup])
"""


def _scan(tmp_path: Path, fmt: str) -> dict:
    out = tmp_path / f"report.{fmt}"
    result = CliRunner().invoke(main, ["code", str(tmp_path / "repo"), "--format", fmt, "-o", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text())


def test_cyclonedx_is_a_registered_format():
    assert "cyclonedx" in FORMATS


def test_cyclonedx_components_mirror_the_json_report(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text(AGENT)
    (repo / "requirements.txt").write_text("langchain==0.3.27\nlanggraph==0.6.6\nlangchain-openai==0.3.30\n")
    (repo / ".mcp.json").write_text(
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}\n'
    )
    report = _scan(tmp_path, "json")
    bom = _scan(tmp_path, "cyclonedx")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["tools"]["components"][0]["name"] == "ShadowScan"
    entries = bom["components"] + bom.get("services", [])
    by_ref = {c["bom-ref"]: c for c in entries}
    assert {f["id"] for f in report["findings"]} <= by_ref.keys()
    for finding in report["findings"]:
        component = by_ref[finding["id"]]
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["shadowscan:kind"] == finding["kind"]
        assert props["shadowscan:heuristic-risk"] == finding["risk"]["level"]
        assert component["name"] == finding["title"]
        assert "snippet" not in json.dumps(component)


def test_cyclonedx_is_deterministic_and_never_carries_credentials(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    key = "sk-proj-" + "Q7fL2mN9pX4vB8wE1rT6yU3iO5aS0dF2gH4jK6lZ8xC1vB3nM5qW7eR9tY"
    (repo / "config.py").write_text(f'OPENAI_API_KEY = "{key}"\n')
    (repo / "app.py").write_text("from openai import OpenAI\nclient = OpenAI()\n")
    first = _scan(tmp_path, "cyclonedx")
    second = _scan(tmp_path, "cyclonedx")
    secret = [
        c
        for c in first["components"]
        if any(p["name"] == "shadowscan:kind" and p["value"] == "secret" for p in c.get("properties", []))
    ]
    assert not secret  # Existing AI-BOM policy keeps credentials in JSON/SARIF reports.
    assert key not in json.dumps(first)
    assert [c["bom-ref"] for c in first["components"]] == [c["bom-ref"] for c in second["components"]]
