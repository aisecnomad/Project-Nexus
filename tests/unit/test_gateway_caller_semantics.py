"""Gateway callers: direct API use is LLM use; only agent evidence makes a caller agentic."""

from __future__ import annotations

import pytest

from shadowscan.connectors.gateway.logs import parse_text_line
from shadowscan.models import Likelihood

LINE = '10.1.1.7 - - [01/Sep/2025:00:0{n}:00 +0000] "{method} {path} HTTP/1.1" 200 1201 "-" "{ua}" host={host}'


def log(tmp_path, rows):
    path = tmp_path / "egress.log"
    path.write_text("\n".join(LINE.format(n=i, **row) for i, row in enumerate(rows)) + "\n")
    return path


def test_plain_curl_requests_to_a_provider_are_llm_callers_not_agentic(tmp_path, run_connector):
    rows = [{"method": "POST", "path": "/v1/chat/completions", "ua": "curl/8.0.1", "host": "api.openai.com"}] * 3
    findings, _ = run_connector("gateway.logs", input=str(log(tmp_path, rows)))
    assert len(findings) == 1
    caller = findings[0]
    assert caller.title.startswith("LLM caller")
    assert caller.metadata.get("agent_indicators", 0) == 0
    assert caller.likelihood != Likelihood.CONFIRMED
    assert "identity-app.openai-chatgpt" not in caller.frameworks
    assert "provider.openai" in caller.model_providers
    # One observed host is one piece of evidence, even when a signal lists it twice.
    assert [e.signal for e in caller.evidence].count("domain:provider.openai") == 1


def test_framework_user_agent_still_makes_an_agentic_caller(tmp_path, run_connector):
    rows = [{"method": "POST", "path": "/v1/chat/completions", "ua": "crewai/0.80 python-requests/2.32", "host": "api.openai.com"}]
    findings, _ = run_connector("gateway.logs", input=str(log(tmp_path, rows)))
    assert len(findings) == 1
    assert findings[0].title.startswith("Agentic caller")
    assert "framework.crewai" in findings[0].frameworks


def test_llm_hosts_only_drops_internal_hosts_that_merely_serve_llm_looking_paths(tmp_path, run_connector):
    rows = [
        {"method": "GET", "path": "/v1/files/123", "ua": "Mozilla/5.0", "host": "files.internal.corp"},
        {"method": "GET", "path": "/sse", "ua": "Mozilla/5.0", "host": "dashboard.internal.corp"},
        {"method": "GET", "path": "/sse", "ua": "Mozilla/5.0", "host": "dashboard.internal.corp"},
    ]
    findings, _ = run_connector("gateway.logs", input=str(log(tmp_path, rows)))
    assert findings == []


def test_end_user_first_names_do_not_match_ai_product_signatures(tmp_path, run_connector):
    rows = [{"method": "POST", "path": "/v1/chat/completions", "ua": "python-requests/2.32", "host": "api.openai.com"}] * 2
    path = tmp_path / "users.log"
    path.write_text("\n".join(
        LINE.format(n=i, **row).replace('10.1.1.7 - -', '10.1.1.7 - olivia') for i, row in enumerate(rows)
    ) + "\n")
    findings, _ = run_connector("gateway.logs", input=str(path))
    for finding in findings:
        assert finding.metadata.get("agent_indicators", 0) == 0
        assert not any(f.startswith("identity-app.") for f in finding.frameworks)


def test_envoy_bracketed_text_lines_fall_through_to_text_parsing():
    line = '[2025-09-01T00:00:00.000Z] "POST /v1/chat/completions HTTP/1.1" 200 - 0 512 12 11 "-" "curl/8.0" "id" "api.openai.com" "1.2.3.4:443"'
    parse_text_line(line)  # must not raise a JSON decoding error
    with pytest.raises(ValueError):
        parse_text_line("[1, 2, 3]")


def test_domain_signals_report_each_signature_once_per_host(index):
    matches = index.match_domain("api.openai.com")
    keys = [(m.signature_id, id(m.signal)) for m in matches]
    assert len(keys) == len(set(keys))
    assert "provider.openai" in {m.signature_id for m in matches}


def test_inference_paths_count_on_internal_gateway_hosts(tmp_path, run_connector):
    rows = [{"method": "POST", "path": "/v1/chat/completions", "ua": "python-requests/2.32", "host": "llm-gateway.internal.corp"}] * 2
    findings, _ = run_connector("gateway.logs", input=str(log(tmp_path, rows)))
    assert len(findings) == 1 and findings[0].metadata["events"] == 2
