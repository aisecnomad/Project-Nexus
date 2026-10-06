"""network.logs: AI services contacted, from DNS, TLS SNI and flow logs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.network import logs as network_logs
from shadowscan.connectors.network.logs import NetworkLogConnector, _host, _int, _zeek_escape
from shadowscan.models import Kind, Surface
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "network"


def scan(run_connector, path: Path, **config):
    findings, ctx = run_connector("network.logs", input=str(path), label="hq", **config)
    by = {(f.metadata["client"], f.metadata["service"]): f for f in findings}
    assert len(by) == len(findings)
    return by, ctx.stats


def test_zeek_dns_ssl_and_conn_logs(run_connector):
    found, stats = scan(run_connector, FIXTURES / "zeek")
    assert not stats.errors and not stats.incomplete
    assert stats.warnings == [
        "network.logs: 1 flow(s) to addresses shared by AI and other hosts were not attributed"
    ]
    assert set(found) == {
        ("10.1.4.21", "provider.anthropic"),
        ("10.1.4.21", "provider.openai"),
        ("10.1.4.33", "identity-app.openai-chatgpt"),
        ("10.1.4.40", "protocol.mcp"),
        ("10.1.4.60", "identity-app.openai-chatgpt"),
        ("10.1.4.70", "provider.ollama"),
        ("10.1.4.80", "coding-agent.cursor"),
    }

    anthropic = found[("10.1.4.21", "provider.anthropic")]
    assert anthropic.surface == Surface.NETWORK and anthropic.kind == Kind.NETWORK_CONTACT
    assert anthropic.title == "AI service contacted: Anthropic (api.anthropic.com) from 10.1.4.21"
    assert anthropic.resource == "network:hq:10.1.4.21:provider.anthropic" and anthropic.account == "hq"
    assert (anthropic.metadata["dns_queries"], anthropic.metadata["tls_connections"]) == (1, 5)
    assert anthropic.metadata["flows"] == 5 and anthropic.metadata["bytes_out"] == 90010
    assert "agent-loop" in anthropic.tags and anthropic.model_providers == ["provider.anthropic"]
    assert anthropic.first_seen == "2025-09-29T08:00:00+00:00"

    # Resolved, but its address is shared with a non-AI host: the flow is not attributed.
    openai = found[("10.1.4.21", "provider.openai")]
    assert openai.metadata["flows"] == 0 and openai.metadata["ambiguous_flows_in_input"] == 1

    chatgpt = found[("10.1.4.33", "identity-app.openai-chatgpt")]
    assert chatgpt.metadata["flows"] == 2 and "agent-service" not in chatgpt.tags
    other = found[("10.1.4.60", "identity-app.openai-chatgpt")]
    assert other.title.endswith("(chatgpt.com) from 10.1.4.60")
    assert any("another client's DNS answers" in e.description for e in other.evidence)

    for key in [("10.1.4.40", "protocol.mcp"), ("10.1.4.80", "coding-agent.cursor")]:
        assert "agent-service" in found[key].tags and found[key].metadata["agent_indicators"] == 1
    assert found[("10.1.4.70", "provider.ollama")].metadata["hosts"] == {"10.9.0.5:11434": 2}
    assert not any(client in {"10.1.4.50"} for client, _ in found)


def test_route53_resolver_and_vpc_flow_logs(run_connector):
    found, stats = scan(run_connector, FIXTURES / "aws")
    assert not stats.warnings and not stats.incomplete
    assert set(found) == {("10.20.1.15", "provider.aws-bedrock"), ("10.20.1.15", "cloud.aws-bedrock-agents")}
    runtime = found[("10.20.1.15", "provider.aws-bedrock")]
    assert runtime.metadata["flows"] == 4 and runtime.metadata["bytes_out"] == 36000
    assert "agent-loop" in runtime.tags
    agents = found[("10.20.1.15", "cloud.aws-bedrock-agents")]
    assert "agent-service" in agents.tags and "agent-loop" not in agents.tags


def test_generic_dns_csv_keeps_only_ai_hosts(run_connector):
    found, stats = scan(run_connector, FIXTURES / "generic_dns.csv")
    assert not stats.warnings
    assert set(found) == {
        ("192.168.5.20", "provider.google-gemini"),
        ("192.168.5.20", "provider.openrouter"),
    }


def test_zeek_json_and_generic_json_documents(run_connector, tmp_path):
    lines = [
        {"_path": "dns", "ts": 1759132800.5, "uid": "D1", "id.orig_h": "10.0.0.9", "query": "api.openai.com",
         "answers": ["162.159.140.245"]},
        {"_path": "ssl", "ts": 1759132801.0, "uid": "C1", "id.orig_h": "10.0.0.9", "id.resp_h": "162.159.140.245",
         "id.resp_p": 443, "server_name": "api.openai.com"},
        {"_path": "conn", "ts": 1759132801.0, "uid": "C1", "id.orig_h": "10.0.0.9",
         "id.resp_h": "162.159.140.245", "id.resp_p": 443, "orig_bytes": 1000, "resp_bytes": 50},
        {"_path": "ssl", "ts": 1759132802.0, "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"},
    ]  # fmt: skip
    (tmp_path / "zeek.json").write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    (tmp_path / "sni.json").write_text(
        json.dumps(
            {
                "records": [
                    {"client_ip": "10.0.0.10", "sni": "API.Anthropic.com.", "ts": "2025-09-29T08:00:00Z"}
                ]
            }
        )
    )
    found, stats = scan(run_connector, tmp_path)
    assert not stats.warnings
    openai = found[("10.0.0.9", "provider.openai")]
    assert (openai.metadata["dns_queries"], openai.metadata["tls_connections"], openai.metadata["flows"]) == (
        1,
        1,
        1,
    )
    assert found[("10.0.0.10", "provider.anthropic")].metadata["hosts"] == {"api.anthropic.com": 1}


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("bad.log", "#separator \\x09\n#fields\tts\tquery\n1\ta\tb\n", "malformed Zeek line 3"),
        ("bad.log", "hello world\n", "unrecognized line 1"),
        ("bad.jsonl", '{"query": "api.openai.com"\n', "invalid JSON at line 1"),
        ("bad.json", "[1]", "records must be objects"),
        ("bad.json", '"text"', "unrecognized JSON document"),
        ("bad.json", '[{"query": "api.openai.com"}]', "DNS record without a client address"),
        ("bad.json", '[{"_path": "ssl", "server_name": "api.openai.com"}]', "TLS record without a client"),
        ("bad.json", '[{"_path": "http", "id.orig_h": "10.0.0.1"}]', "no query, server name or flow"),
        ("bad.json", '[{"color": "blue"}]', "unrecognized record"),
        ("bad.log", "version srcaddr dstaddr dstport action log-status\n2 x 10.0.0.2 443 ACCEPT OK\n",
         "malformed VPC flow record"),
        ("empty.log", "\n", "empty log"),
    ],
)  # fmt: skip
def test_malformed_input_makes_the_scan_incomplete(run_connector, tmp_path, name, content, message):
    path = tmp_path / name
    path.write_text(content)
    _, stats = scan(run_connector, path)
    assert stats.incomplete
    assert any(message in m for m in stats.warnings + stats.errors), stats.warnings + stats.errors


@pytest.mark.parametrize("content", ["", "\n\n"])
def test_empty_json_exports_are_errors(run_connector, tmp_path, content):
    for name in ("empty.json", "empty.jsonl"):
        (tmp_path / name).write_text(content)
    _, stats = scan(run_connector, tmp_path)
    assert stats.incomplete and stats.errors


def test_global_dns_attribution_is_refused_for_shared_addresses(run_connector, tmp_path):
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"]},
        {"client": "10.0.0.2", "query": "cdn.example.net", "answers": ["203.0.113.5"]},
        {"client": "10.0.0.3", "dst_ip": "203.0.113.5", "dst_port": 443, "bytes": 10},
        {"client": "10.0.0.3", "dst_ip": "198.51.100.1", "dst_port": 443, "bytes": 10},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert set(found) == {("10.0.0.1", "provider.openai")}
    assert not stats.incomplete and any("1 flow(s)" in w for w in stats.warnings)


def test_format_option_and_record_limit(run_connector, tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text(
        "".join(json.dumps({"client": f"10.0.0.{i}", "query": "api.openai.com"}) + "\n" for i in range(5))
    )
    found, stats = scan(run_connector, path, format="generic", max_records=3)
    assert len(found) == 3 and stats.incomplete
    assert any("max_records" in w for w in stats.warnings)


def test_vpc_flows_with_the_default_format_and_no_header(run_connector, tmp_path):
    (tmp_path / "dns.jsonl").write_text(
        json.dumps({"client": "10.0.0.4", "query": "api.mistral.ai", "answers": ["198.51.100.9"]}) + "\n"
    )
    (tmp_path / "flows.log").write_text(
        "2 1 eni-1 10.0.0.4 198.51.100.9 40000 443 6 3 1200 1759132800 1759132860 ACCEPT OK\n"
    )
    found, stats = scan(run_connector, tmp_path)
    assert not stats.warnings
    assert found[("10.0.0.4", "provider.mistral")].metadata["flows"] == 1


def test_caps_on_clients_and_pairs(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_CLIENTS", 2)
    monkeypatch.setattr(network_logs, "_MAX_PAIRS", 1)
    rows = [{"client": f"10.0.0.{i}", "query": "api.openai.com"} for i in range(3)]
    rows += [{"client": "10.0.0.0", "dst_ip": f"198.51.100.{i}", "dst_port": 443} for i in range(2)]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert len(found) == 2 and stats.incomplete
    assert any("beyond the first 2" in w for w in stats.warnings)
    assert any("beyond 1 client/server pairs" in w for w in stats.warnings)


def test_configuration_and_live_mode_are_refused(run_connector):
    with pytest.raises(ConnectorError):
        NetworkLogConnector(ConnectorContext(config={"format": "pcap"}, index=get_index()))
    _, ctx = run_connector("network.logs")
    assert ctx.stats.skipped and ctx.stats.incomplete


@pytest.mark.parametrize(
    ("value", "expected"),
    [("API.OpenAI.com.", "api.openai.com"), ("10.0.0.1", None), ("not a host", None), ("", None), ({}, None)],
)
def test_host_normalisation(value, expected):
    assert _host(value) == expected


def test_small_helpers():
    assert _zeek_escape("\\x09") == "\t"
    assert (_int("12"), _int(True), _int("-1"), _int("x")) == (12, None, None, None)
