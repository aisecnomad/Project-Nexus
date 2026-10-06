"""CycloneDX 1.6 AI-BOM output (shadowscan.reporters.cyclonedx)."""

from __future__ import annotations

import json
from pathlib import Path

from shadowscan.config import ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, Risk, RiskLevel, ScanResult, ScanStats, Surface
from shadowscan.reporters import FORMATS, render
from shadowscan.reporters.cyclonedx import render_cyclonedx

ROOT = Path(__file__).resolve().parents[2]


def _finding(fid: str, kind: Kind = Kind.AGENT, **extra) -> Finding:
    f = Finding(
        surface=extra.pop("surface", Surface.CODE),
        connector="code.filesystem",
        kind=kind,
        title=extra.pop("title", f"Agent {fid}"),
        resource=f"repo:{fid}",
        resource_type="project",
        **extra,
    )
    f.id = fid
    f.risk = Risk(score=60, level=RiskLevel.HIGH)
    return f


def _result(findings: list[Finding], *, incomplete: bool = False) -> ScanResult:
    stats = ScanStats(connector="code.filesystem", started_at="2026-10-06T10:00:00+00:00")
    stats.incomplete = incomplete
    return ScanResult(
        findings=findings,
        stats=[stats],
        started_at="2026-10-06T10:00:00+00:00",
        finished_at="2026-10-06T10:00:05+00:00",
    )


def test_cyclonedx_is_a_listed_format():
    assert "cyclonedx" in FORMATS
    doc = json.loads(render(_result([]), "cyclonedx"))
    assert (doc["bomFormat"], doc["specVersion"], doc["version"]) == ("CycloneDX", "1.6", 1)
    assert doc["components"] == [] and "services" not in doc


def test_components_services_models_and_dependencies():
    agent = _finding(
        "ss-agent",
        frameworks=["framework.langgraph"],
        model_providers=["provider.openai"],
        models=["gpt-4o"],
        capabilities=["tool-use"],
        owner="team-a",
    )
    mcp = _finding(
        "ss-mcp",
        Kind.MCP_SERVER,
        metadata={
            "servers": [
                {
                    "name": "github",
                    "transport": "stdio",
                    "command": "npx",
                    "risks": [{"id": "mcp-unpinned-package"}],
                },
                {
                    "name": "docs",
                    "transport": "http",
                    "urls": ["https://mcp.example.com/mcp"],
                    "disabled": True,
                },
                {"transport": "stdio"},
                "bogus",
            ]
        },
    )
    secret = _finding("ss-secret", Kind.SECRET, title="LLM provider credential")
    doc = json.loads(render_cyclonedx(_result([agent, mcp, secret])))

    refs = {c["bom-ref"]: c for c in doc["components"]}
    assert "ss-secret" not in refs
    app = refs["ss-agent"]
    assert app["type"] == "application" and app["group"] == "code" and app["authors"] == [{"name": "team-a"}]
    props = {p["name"]: p["value"] for p in app["properties"]}
    assert props["shadowscan:heuristic-risk"] == "high" and props["shadowscan:capabilities"] == "tool-use"
    framework = refs["signature:framework.langgraph"]
    assert framework["type"] == "framework" and framework["name"] == "LangGraph"
    model = next(c for c in doc["components"] if c["type"] == "machine-learning-model")
    assert model["name"] == "gpt-4o"

    services = {s["bom-ref"]: s for s in doc["services"]}
    assert services["signature:provider.openai"]["trustZone"] == "external"
    mcp_services = [s for s in doc["services"] if s.get("group") == "mcp-server"]
    assert sorted(s["name"] for s in mcp_services) == ["docs", "github"]
    docs = next(s for s in mcp_services if s["name"] == "docs")
    assert docs["endpoints"] == ["https://mcp.example.com/mcp"]
    github = {
        p["name"]: p["value"] for p in next(s for s in mcp_services if s["name"] == "github")["properties"]
    }
    assert github["shadowscan:mcp:risks"] == "mcp-unpinned-package"

    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert set(deps["ss-agent"]) == {
        "signature:framework.langgraph",
        "signature:provider.openai",
        model["bom-ref"],
    }
    assert len(deps["ss-mcp"]) == 2
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["shadowscan:scan:credential-findings-excluded"] == "1"
    assert doc["metadata"]["timestamp"] == "2026-10-06T10:00:05Z"


def test_incomplete_scan_is_declared_incomplete_and_output_is_deterministic():
    findings = [_finding("ss-b"), _finding("ss-a")]
    first = render_cyclonedx(_result(findings, incomplete=True))
    second = render_cyclonedx(_result(list(reversed(findings)), incomplete=True))
    assert first == second
    doc = json.loads(first)
    assert doc["compositions"] == [{"aggregate": "incomplete", "assemblies": ["ss-a", "ss-b"]}]
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["shadowscan:scan:status"] == "incomplete"
    assert meta["shadowscan:scan:incomplete-connectors"] == "code.filesystem"
    complete = json.loads(render_cyclonedx(_result(findings)))
    assert complete["compositions"][0]["aggregate"] == "unknown"
    assert doc["serialNumber"].startswith("urn:uuid:")


def test_credentials_in_finding_text_never_reach_the_bom():
    token = "sk-ant-api03-" + "A" * 93 + "AA"
    f = _finding("ss-x", title=f"agent using {token}")
    f.evidence.append(Evidence(signal="code:x", description=f"key {token}", weight=0.5))
    out = render_cyclonedx(_result([f]))
    assert token not in out


def test_offline_demo_renders(index):
    result = Engine(ScanConfig.from_yaml(ROOT / "examples" / "shadowscan.offline.yaml"), index).run()
    doc = json.loads(render_cyclonedx(result, index))
    refs = {c["bom-ref"] for c in doc["components"]} | {s["bom-ref"] for s in doc.get("services", [])}
    for dep in doc["dependencies"]:
        assert dep["ref"] in refs and set(dep["dependsOn"]) <= refs
    assert set(doc["compositions"][0]["assemblies"]) <= refs
    assert len({c["bom-ref"] for c in doc["components"]}) == len(doc["components"])
