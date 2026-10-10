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
                    "risks": ["mcp-unpinned-package"],
                    "location": ".mcp.json",
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
    framework = refs["shadowscan:framework:framework.langgraph"]
    assert framework["type"] == "framework" and framework["name"] == "LangGraph"
    model = next(c for c in doc["components"] if c["type"] == "machine-learning-model")
    assert model["name"] == "gpt-4o"

    services = {s["bom-ref"]: s for s in doc["services"]}
    # No trust zone: a provider id can name a local runtime as well as a hosted API.
    assert "trustZone" not in services["shadowscan:provider:provider.openai"]
    mcp_services = [s for s in doc["services"] if s.get("group") == "mcp-server"]
    # An unnamed server is published under a placeholder; the non-object entry is counted as omitted.
    assert sorted(s["name"] for s in mcp_services) == ["(unnamed MCP server #3)", "docs", "github"]
    docs = next(s for s in mcp_services if s["name"] == "docs")
    assert docs["endpoints"] == ["https://mcp.example.com/mcp"]
    github = {
        p["name"]: p["value"] for p in next(s for s in mcp_services if s["name"] == "github")["properties"]
    }
    assert github["shadowscan:mcp:risks"] == "mcp-unpinned-package"
    assert github["shadowscan:mcp:file"] == ".mcp.json"

    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert set(deps["ss-agent"]) == {
        "shadowscan:framework:framework.langgraph",
        "shadowscan:provider:provider.openai",
        model["bom-ref"],
    }
    assert len(deps["ss-mcp"]) == 3
    mcp_entry = next(s for s in doc["services"] if s["bom-ref"] == "ss-mcp")
    assert {"name": "shadowscan:mcp:servers-omitted", "value": "1"} in mcp_entry["properties"]
    assert {"aggregate": "incomplete", "dependencies": ["ss-mcp"]} in doc["compositions"]
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


def _refs(doc: dict) -> list[str]:
    return [e["bom-ref"] for e in doc["components"] + doc.get("services", [])]


def _resolves(doc: dict) -> None:
    refs = _refs(doc)
    assert len(refs) == len(set(refs))
    for dep in doc["dependencies"]:
        assert dep["ref"] in refs and set(dep["dependsOn"]) <= set(refs)
    for composition in doc["compositions"]:
        assert set(composition.get("assemblies", []) + composition.get("dependencies", [])) <= set(refs)


def test_ollama_models_are_model_components_and_the_runtime_is_a_service():
    model = _finding("ss-llama", Kind.LOCAL_MODEL, surface=Surface.ENDPOINT, title="llama3:8b")
    model.connector = "endpoint.ollama"
    model.resource_type = "local-model"
    runtime = _finding("ss-ollama", Kind.AGENT, surface=Surface.ENDPOINT, title="Ollama")
    runtime.connector = "endpoint.ollama"
    doc = json.loads(render_cyclonedx(_result([model, runtime])))
    components = {c["bom-ref"]: c for c in doc["components"]}
    assert components["ss-llama"]["type"] == "machine-learning-model"
    assert "ss-ollama" not in components
    assert [s["bom-ref"] for s in doc["services"]] == ["ss-ollama"]
    _resolves(doc)


def test_empty_duplicate_and_reserved_ids_get_unique_refs():
    findings = [_finding(""), _finding("ss-dup", title="one"), _finding("ss-dup", title="two")]
    findings.append(_finding("shadowscan:framework:framework.langgraph", frameworks=["framework.langgraph"]))
    doc = json.loads(render_cyclonedx(_result(findings)))
    _resolves(doc)
    apps = [c for c in doc["components"] if c["type"] == "application"]
    assert len(apps) == 4
    assert sum(c["bom-ref"] == "ss-dup" for c in apps) == 1
    assert sum(c["bom-ref"].startswith("shadowscan:finding:") for c in apps) == 3
    framework = next(c for c in doc["components"] if c["type"] == "framework")
    assert framework["bom-ref"] == "shadowscan:framework:framework.langgraph"
    assert render_cyclonedx(_result(list(reversed(findings)))) == render_cyclonedx(_result(findings))


def test_implemented_mcp_server_is_a_service_the_application_depends_on():
    f = _finding(
        "ss-impl",
        Kind.FRAMEWORK_USAGE,
        title="MCP server in repository root: Model Context Protocol (MCP)",
        frameworks=["protocol.mcp"],
        capabilities=["tool-use", "mcp-server"],
        owner="team-tools",
        metadata={
            "mcp_tools": ["lookup", "read_file"],
            "mcp_server": {
                "constructions": [
                    {
                        "file": "server.py",
                        "line": 5,
                        "construct": "mcp.server.fastmcp:FastMCP(",
                        "bound": True,
                    },
                    {"file": "server.py", "line": 9, "construct": "mcp.server:Server(", "bound": True},
                    {
                        "file": "low/app.py",
                        "line": 2,
                        "construct": "mcp.server.lowlevel:Server(",
                        "bound": True,
                    },
                ],
                "languages": ["python"],
                "transports": ["stdio"],
            },
        },
    )
    doc = json.loads(render_cyclonedx(_result([f])))
    _resolves(doc)
    # The project stays an application with its framework dependency.
    app = next(c for c in doc["components"] if c["bom-ref"] == "ss-impl")
    assert app["type"] == "application" and app["authors"] == [{"name": "team-tools"}]
    [service] = [s for s in doc["services"] if s.get("group") == "mcp-server"]
    assert service["bom-ref"].startswith("shadowscan:mcp-server:")
    assert service["name"] == "MCP server in repository root: Model Context Protocol (MCP)"
    assert "endpoints" not in service
    props = {p["name"]: p["value"] for p in service["properties"]}
    assert props == {
        "shadowscan:mcp:implementation": "source",
        "shadowscan:mcp:languages": "python",
        "shadowscan:mcp:transport": "stdio",
        "shadowscan:mcp:tools": "lookup, read_file",
        "shadowscan:mcp:files": "server.py, low/app.py",
    }
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert set(deps["ss-impl"]) == {"shadowscan:framework:protocol.mcp", service["bom-ref"]}
    # Nothing was capped: no second, incomplete composition.
    assert [c["aggregate"] for c in doc["compositions"]] == ["unknown"]
    assert render_cyclonedx(_result([f])) == render_cyclonedx(_result([f]))


def test_implemented_server_lists_are_bounded_and_several_transports_name_none():
    f = _finding(
        "ss-many-tools",
        Kind.FRAMEWORK_USAGE,
        capabilities=["mcp-server"],
        metadata={
            "mcp_tools": [f"tool_{i:02d}" for i in range(25)],
            "mcp_server": {
                "constructions": [{"file": f"srv/{i}.ts", "line": 1} for i in range(12)],
                "languages": ["javascript", "python"],
                "transports": ["http", "stdio"],
            },
        },
    )
    doc = json.loads(render_cyclonedx(_result([f])))
    _resolves(doc)
    [service] = [s for s in doc["services"] if s.get("group") == "mcp-server"]
    props = {p["name"]: p["value"] for p in service["properties"]}
    assert (
        "shadowscan:mcp:transport" not in props and props["shadowscan:mcp:languages"] == "javascript, python"
    )
    assert (
        props["shadowscan:mcp:tools-omitted"] == "5" and len(props["shadowscan:mcp:tools"].split(", ")) == 20
    )
    assert (
        props["shadowscan:mcp:files-omitted"] == "2" and len(props["shadowscan:mcp:files"].split(", ")) == 10
    )
    assert {"aggregate": "incomplete", "dependencies": ["ss-many-tools"]} in doc["compositions"]
    # Two implementations never share a service, and a client configuration never gets one.
    other = _finding("ss-other", Kind.FRAMEWORK_USAGE, capabilities=["mcp-server"])
    config = _finding("ss-cfg", Kind.MCP_SERVER, capabilities=["mcp-server"], metadata={"servers": []})
    doc = json.loads(render_cyclonedx(_result([f, other, config])))
    _resolves(doc)
    assert len([s for s in doc["services"] if s.get("group") == "mcp-server"]) == 2
    assert {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}["ss-cfg"] == []


def test_same_named_servers_in_two_configurations_stay_apart():
    first = _finding(
        "ss-a", Kind.MCP_SERVER, metadata={"servers": [{"name": "github", "location": "a/.mcp.json"}]}
    )
    second = _finding(
        "ss-b", Kind.MCP_SERVER, metadata={"servers": [{"name": "github", "location": "b/.mcp.json"}]}
    )
    doc = json.loads(render_cyclonedx(_result([first, second])))
    _resolves(doc)
    servers = [s for s in doc["services"] if s.get("group") == "mcp-server"]
    assert len(servers) == 2 and len({s["bom-ref"] for s in servers}) == 2
    files = sorted(p["value"] for s in servers for p in s["properties"] if p["name"] == "shadowscan:mcp:file")
    assert files == ["a/.mcp.json", "b/.mcp.json"]


def test_bounded_entries_are_recorded_as_incomplete():
    servers = [{"name": f"server-{i}"} for i in range(60)]
    f = _finding(
        "ss-many", Kind.MCP_SERVER, metadata={"servers": servers}, models=[f"model-{i}" for i in range(25)]
    )
    doc = json.loads(render_cyclonedx(_result([f])))
    _resolves(doc)
    entry = next(s for s in doc["services"] if s["bom-ref"] == "ss-many")
    props = {p["name"]: p["value"] for p in entry["properties"]}
    assert props["shadowscan:mcp:servers-omitted"] == "10" and props["shadowscan:models-omitted"] == "5"
    assert {"aggregate": "incomplete", "dependencies": ["ss-many"]} in doc["compositions"]
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["shadowscan:bom:truncated-findings"] == "1"


def test_custom_technologies_use_the_names_the_scan_recorded():
    f = _finding(
        "ss-custom",
        frameworks=["custom.inhouse-agent"],
        metadata={
            "technologies": [
                {
                    "id": "custom.inhouse-agent",
                    "name": "In-house agent",
                    "category": "agent",
                    "vendor": "Acme",
                }
            ]
        },
    )
    doc = json.loads(render_cyclonedx(_result([f])))
    framework = next(c for c in doc["components"] if c["type"] == "framework")
    assert framework["name"] == "In-house agent" and framework["publisher"] == "Acme"


def test_large_scans_render_without_hitting_the_sanitizer_bound(monkeypatch):
    # Each entry is sanitized on its own, so the bound applies per entry, not to the whole BOM.
    monkeypatch.setattr("shadowscan.utils.redaction._MAX_SANITIZATION_NODES", 500)
    findings = [
        _finding(f"ss-{i:04d}", frameworks=["framework.langgraph"], capabilities=["tool-use"], tags=["t"])
        for i in range(40)
    ]
    doc = json.loads(render_cyclonedx(_result(findings)))
    assert len([c for c in doc["components"] if c["type"] == "application"]) == 40
    _resolves(doc)


def test_render_uses_the_scan_index_for_custom_packs():
    from types import SimpleNamespace

    acme = SimpleNamespace(
        name="ACME Agents",
        category="framework",
        vendor="ACME",
        description="In-house agents",
        homepage="https://acme.example/agents",
    )
    index = SimpleNamespace(get=lambda sid: acme if sid == "framework.acme-agents" else None)
    f = _finding("ss-acme", frameworks=["framework.acme-agents"])
    doc = json.loads(render(_result([f]), "cyclonedx", index))
    framework = next(c for c in doc["components"] if c["type"] == "framework")
    assert (framework["name"], framework["publisher"]) == ("ACME Agents", "ACME")
    assert framework["externalReferences"] == [{"type": "website", "url": "https://acme.example/agents"}]


def test_unnamed_servers_and_endpoint_bounds_are_never_silent(tmp_path):
    from shadowscan.connectors.mcp_risk import record_server_risks

    servers = [
        {"name": "", "command": "npx", "args": ["-y", "some-unpinned-pkg"]},
        {"name": "upper", "transport": "http", "url": "HTTP://mcp.example.com/mcp"},
        {"name": "many", "transport": "http", "urls": [f"https://r{i}.example/mcp" for i in range(7)]},
    ]
    f = _finding("ss-cfg", Kind.MCP_SERVER, metadata={"servers": servers})
    for server in f.metadata["servers"]:
        record_server_risks(f, server, ".mcp.json")
    doc = json.loads(render_cyclonedx(_result([f])))
    _resolves(doc)
    by_name = {s["name"]: s for s in doc["services"] if s.get("group") == "mcp-server"}
    unnamed = {p["name"]: p["value"] for p in by_name["(unnamed MCP server #1)"]["properties"]}
    assert unnamed["shadowscan:mcp:risks"] == "mcp-unpinned-package"
    assert by_name["upper"]["endpoints"] == ["HTTP://mcp.example.com/mcp"]
    many = by_name["many"]
    assert len(many["endpoints"]) == 5
    assert {"name": "shadowscan:mcp:endpoints-omitted", "value": "2"} in many["properties"]
    assert {"aggregate": "incomplete", "dependencies": ["ss-cfg"]} in doc["compositions"]


def test_mcp_registry_matches_become_service_properties():
    matched = {
        "registry": "official",
        "name": "io.github.acme/files",
        "match": "package",
        "latest_version": "1.1.0",
        "status": "active",
        "ambiguous": False,
    }
    corp = {"registry": "corp", "name": "com.acme/shared", "match": "package", "ambiguous": True}
    mcp = _finding(
        "ss-mcp",
        Kind.MCP_SERVER,
        metadata={
            "servers": [
                {"name": "files", "transport": "stdio", "registry": [corp, matched]},
                {"name": "unlisted", "transport": "stdio", "registry": []},
                # Report metadata can be shaped freely: malformed entries are skipped.
                {"name": "odd", "registry": ["bogus", {"name": "no registry id"}, {"registry": 7}]},
                {"name": "shapeless", "registry": "official"},
            ]
        },
    )
    doc = json.loads(render_cyclonedx(_result([mcp])))
    services = {
        s["name"]: {p["name"]: p["value"] for p in s["properties"]}
        for s in doc["services"]
        if s.get("group") == "mcp-server"
    }
    assert (
        services["files"]["shadowscan:mcp:registry-name"]
        == "corp:com.acme/shared, official:io.github.acme/files"
    )
    assert services["files"]["shadowscan:mcp:registry-version"] == "official:1.1.0"
    assert services["files"]["shadowscan:mcp:registry-status"] == "official:active"
    assert services["files"]["shadowscan:mcp:registry-source"] == "corp:package (ambiguous), official:package"
    for name in ("unlisted", "odd", "shapeless"):
        assert not any(key.startswith("shadowscan:mcp:registry-") for key in services[name]), name
