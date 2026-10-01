"""Untrusted gateway / SaaS / low-code input must not hide, forge or silently lose records."""

from __future__ import annotations

import gzip
import json
import time
from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.gateway.logs import GatewayLogConnector, parse_text_line
from shadowscan.connectors.lowcode import servicenow
from shadowscan.models import ScanStats

# ------------------------------------------------- access-log host spoofing

PREFIX = '10.0.0.1 - - [10/Sep/2025:10:00:{sec:02d} +0000] "POST /relay HTTP/1.1" 200 512'


def _access_lines(*, ua, trailer, referer="-", path="/relay", count=10):
    return [
        f'10.0.0.1 - - [10/Sep/2025:10:00:{sec:02d} +0000] "POST {path} HTTP/1.1" 200 512 "{referer}" "{ua}"{trailer}'
        for sec in range(count)
    ]


def _scan_access_log(run_connector, tmp_path, lines, **config):
    source = tmp_path / "access.log"
    source.write_text("\n".join(lines) + "\n")
    return run_connector("gateway.logs", input=str(source), **config)


def test_user_agent_host_token_cannot_hide_real_llm_traffic(run_connector, tmp_path):
    lines = _access_lines(ua="crewai/0.80 host=intranet.acme.com", trailer=" host=api.openai.com")
    findings, ctx = _scan_access_log(run_connector, tmp_path, lines)
    assert len(findings) == 1 and findings[0].metadata["events"] == 10
    assert findings[0].metadata["hosts"] == {"api.openai.com": 10}
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("host", ["api.cloudflare.com", "huggingface.co"])
def test_generic_vendor_hosts_are_not_llm_traffic(run_connector, tmp_path, host):
    lines = _access_lines(ua="curl/8.0", trailer=f" host={host}", path="/client/v4/zones")
    findings, ctx = _scan_access_log(run_connector, tmp_path, lines)
    assert findings == []
    assert not ctx.stats.errors


def test_user_agent_host_token_cannot_fabricate_llm_traffic(run_connector, tmp_path):
    lines = _access_lines(ua="Mozilla/5.0 host=api.openai.com", trailer=" host=intranet.acme.com")
    findings, ctx = _scan_access_log(run_connector, tmp_path, lines)
    assert findings == []
    assert not ctx.stats.errors


@pytest.mark.parametrize(
    "line",
    [
        # client-controlled user agent
        PREFIX.format(sec=0) + ' "-" "bot host=evil.example.com" host=api.openai.com',
        # client-controlled referer
        PREFIX.format(sec=0) + ' "https://x.test/?authority=evil.example.com" "bot" host=api.openai.com',
        # client-controlled request target
        PREFIX.replace("/relay", "/relay?server_name=evil.example.com").format(sec=0)
        + ' "-" "bot" host=api.openai.com',
    ],
)
def test_host_comes_only_from_the_trailing_token_after_the_last_quoted_field(line):
    assert parse_text_line(line)["host"] == "api.openai.com"


@pytest.mark.parametrize(
    "line",
    [
        PREFIX.format(sec=0) + ' "-" "bot host=api.openai.com"',
        PREFIX.format(sec=0) + ' "https://x.test/?host=api.openai.com" "bot"',
        PREFIX.replace("/relay", "/relay?host=api.openai.com").format(sec=0) + ' "-" "bot"',
        # an extra quoted field is not a structured position: a client can close
        # the user agent early and open one of its own
        PREFIX.format(sec=0) + ' "-" "bot" "host=api.openai.com"',
        # only text after the final quote is server-written; a token followed by
        # another quoted field could have been injected through an earlier one
        PREFIX.format(sec=0) + ' "-" "bot" "x" host=api.openai.com "z"',
    ],
)
def test_host_token_inside_quoted_client_fields_is_not_a_host(line):
    assert parse_text_line(line)["host"] is None


# --------------------------------------------- rotated / unsupported inputs


def test_unsupported_files_in_a_directory_make_the_scan_incomplete(run_connector, tmp_path):
    (tmp_path / "today.jsonl").write_text(
        json.dumps({"model": "gpt-4o", "api_key": "k", "prompt_tokens": 1}) + "\n"
    )
    for name in ("access.log.1", "access.log-20250901", "old.jsonl.zst", "y.jsonl.bak"):
        (tmp_path / name).write_text("{}\n")
    findings, ctx = run_connector("gateway.logs", input=str(tmp_path))
    assert len(findings) == 1
    assert ctx.stats.incomplete
    message = " ".join(ctx.stats.warnings)
    assert "unsupported" in message
    for name in ("access.log.1", "access.log-20250901", "old.jsonl.zst", "y.jsonl.bak"):
        assert name in message
    assert "today.jsonl" not in message


def test_skipped_file_list_is_bounded(run_connector, tmp_path):
    (tmp_path / "apps.csv").write_text("name,scopes\nChatGPT,read\n")
    for number in range(40):
        (tmp_path / f"apps.csv.{number:02d}").write_text("name\nx\n")
    _, ctx = run_connector("saas.generic", input=str(tmp_path))
    assert ctx.stats.incomplete
    skipped = [w for w in ctx.stats.warnings if "unsupported" in w]
    assert len(skipped) == 1 and len(skipped[0]) < 600
    assert "40" in skipped[0]


def test_directory_of_only_supported_files_is_complete(run_connector, tmp_path):
    (tmp_path / "apps.csv").write_text("name,scopes\nChatGPT,read\n")
    (tmp_path / "more.json").write_text(json.dumps([{"name": "Claude"}]))
    _, ctx = run_connector("saas.generic", input=str(tmp_path))
    assert not ctx.stats.incomplete and not ctx.stats.warnings


# ----------------------------------------------------- size-limit messages


def test_oversized_only_file_names_the_limit_instead_of_claiming_it_is_empty(run_connector, tmp_path):
    source = tmp_path / "big.jsonl"
    source.write_text(
        "\n".join(json.dumps({"model": "gpt-4o", "api_key": f"k{n}"}) for n in range(200)) + "\n"
    )
    findings, ctx = run_connector("gateway.logs", input=str(source), max_input_file_bytes=1000)
    assert findings == [] and ctx.stats.incomplete
    assert not any("empty offline export" in e for e in ctx.stats.errors)
    assert any("max_input_file_bytes" in e for e in ctx.stats.errors)


def test_genuinely_empty_jsonl_still_reports_an_empty_export(run_connector, tmp_path):
    source = tmp_path / "empty.jsonl"
    source.write_text("\n\n")
    _, ctx = run_connector("gateway.logs", input=str(source))
    assert ctx.stats.incomplete and any("empty offline export" in e for e in ctx.stats.errors)


def test_oversized_only_jsonl_in_a_generic_connector_names_the_limit(run_connector, tmp_path):
    source = tmp_path / "apps.jsonl"
    source.write_text("\n".join(json.dumps({"name": f"app{n}"}) for n in range(200)) + "\n")
    _, ctx = run_connector("saas.generic", input=str(source), max_input_file_bytes=1000)
    assert ctx.stats.incomplete
    assert not any("empty offline export" in e for e in ctx.stats.errors)
    assert any("max_input_file_bytes" in e for e in ctx.stats.errors)


# -------------------------------------------------------- reader deadline


def test_blank_line_padding_cannot_outrun_the_connector_deadline(index, tmp_path):
    source = tmp_path / "padding.jsonl.gz"
    source.write_bytes(gzip.compress(b"\n" * 20_000))
    ctx = ConnectorContext(index=index, deadline=time.monotonic() - 1)
    connector = GatewayLogConnector(ctx)
    budget = connector._offline_budget()
    with pytest.raises(ConnectorError, match="deadline"):
        for _ in connector._iter_bounded_lines(source, budget, compressed=True):
            pass


def test_line_reader_without_a_deadline_still_reads_everything(index, tmp_path):
    source = tmp_path / "plain.jsonl"
    source.write_bytes(b"\n" * 5000 + b'{"a": 1}\n')
    connector = GatewayLogConnector(ConnectorContext(index=index))
    lines = list(connector._iter_bounded_lines(source, connector._offline_budget()))
    assert len(lines) == 5001


# ------------------------------------------------- numeric usage validation


def _scan(index, records, **config):
    ctx = ConnectorContext(config={"input": "export.jsonl", **config}, index=index)
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    findings = list(GatewayLogConnector(ctx).analyze(records))
    return findings, ctx


def _litellm(i, **extra):
    return {
        "request_id": str(i),
        "api_key": "opaque-key-one",
        "api_key_alias": "svc-agent",
        "model": "gpt-4o",
        "custom_llm_provider": "openai",
        "startTime": "2026-01-05T09:00:00Z",
        **extra,
    }


def test_negative_usage_cannot_offset_real_usage_and_is_reported(index):
    records = [_litellm(i, spend=0.5, prompt_tokens=100, completion_tokens=10) for i in range(5)]
    records += [_litellm(10 + i, spend=-5, prompt_tokens=-100, completion_tokens=-10) for i in range(5)]
    findings, ctx = _scan(index, records, format="litellm")
    assert len(findings) == 1
    meta = findings[0].metadata
    assert meta["events"] == 10
    assert meta["tokens_in"] == 500 and meta["tokens_out"] == 50 and meta["cost"] == 2.5
    assert ctx.stats.incomplete
    assert len([w for w in ctx.stats.warnings if "out of range" in w]) == 1


def test_absurd_usage_is_not_reported_verbatim(index):
    records = [_litellm(i, spend=1e30, prompt_tokens=10**30, completion_tokens=3) for i in range(3)]
    findings, ctx = _scan(index, records, format="litellm")
    meta = findings[0].metadata
    assert meta["tokens_in"] == 0 and meta["cost"] == 0.0 and meta["tokens_out"] == 9
    assert ctx.stats.incomplete and any("out of range" in w for w in ctx.stats.warnings)


def test_ordinary_usage_is_unchanged_and_complete(index):
    records = [_litellm(i, spend=0.25, prompt_tokens=7, completion_tokens=0) for i in range(4)]
    findings, ctx = _scan(index, records, format="litellm")
    assert findings[0].metadata["tokens_in"] == 28 and findings[0].metadata["cost"] == 1.0
    assert not ctx.stats.incomplete and not ctx.stats.warnings


# ----------------------------------------------------------- saas.generic


def test_unrecognised_name_column_is_incomplete_not_empty(run_connector, tmp_path):
    source = tmp_path / "apps.csv"
    source.write_text("Software,Permissions\nChatGPT Enterprise,read write\nSlack,chat:write\n")
    findings, ctx = run_connector("saas.generic", input=str(source))
    assert findings == [] and ctx.stats.objects_examined == 2
    assert ctx.stats.incomplete
    assert len(ctx.stats.warnings) == 1 and "2 record" in ctx.stats.warnings[0]
    assert "fields" in ctx.stats.warnings[0]


def test_field_mapping_resolves_a_nonstandard_name_column(run_connector, tmp_path):
    source = tmp_path / "apps.csv"
    source.write_text("Software,Permissions\nChatGPT Enterprise,read write\n")
    findings, ctx = run_connector(
        "saas.generic", input=str(source), fields={"name": "Software", "scopes": "Permissions"}
    )
    assert len(findings) == 1 and not ctx.stats.incomplete


def test_unresolved_name_diagnostic_is_bounded(run_connector, tmp_path):
    source = tmp_path / "apps.jsonl"
    source.write_text("\n".join(json.dumps({"Software": f"app{n}"}) for n in range(3000)) + "\n")
    _, ctx = run_connector("saas.generic", input=str(source))
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1
    assert "3000 record" in ctx.stats.warnings[0]


def test_blank_csv_rows_are_not_unresolved_apps(run_connector, tmp_path):
    source = tmp_path / "apps.csv"
    source.write_text("name,scopes\nChatGPT,read\n,\n")
    findings, ctx = run_connector("saas.generic", input=str(source))
    assert len(findings) == 1 and not ctx.stats.incomplete


@pytest.mark.parametrize("connector", ["saas.generic", "lowcode.zapier"])
def test_wrong_schema_object_is_incomplete_like_an_error_body(run_connector, tmp_path, connector):
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"foo": "bar"}))
    findings, ctx = run_connector(connector, input=str(wrong))
    assert findings == [] and ctx.stats.incomplete
    denied = tmp_path / "denied.json"
    denied.write_text(json.dumps({"error": "unauthorized"}))
    _, ctx = run_connector(connector, input=str(denied))
    assert ctx.stats.incomplete


def test_zapier_records_with_an_identity_are_still_analysed(run_connector, tmp_path):
    source = tmp_path / "zaps.json"
    source.write_text(
        json.dumps(
            [
                {"id": 1, "title": "Triage", "steps": ["Gmail", "ChatGPT"]},
                {"title": "Notes only", "steps": []},
            ]
        )
    )
    findings, ctx = run_connector("lowcode.zapier", input=str(source))
    assert len(findings) == 1 and not ctx.stats.incomplete


@pytest.mark.parametrize("blank", [",,", ", ,\t", ",,\r\n,,", '"","",""'])
def test_blank_zapier_csv_rows_are_skipped_without_a_diagnostic(run_connector, tmp_path, blank):
    # Spreadsheet exports often end with comma-only rows; they carry no Zap.
    source = tmp_path / "zaps.csv"
    source.write_bytes(
        f"Zap,Steps,Status\r\nSummarize email,Gmail > ChatGPT > Slack,on\r\n{blank}\r\n".encode()
    )
    findings, ctx = run_connector("lowcode.zapier", input=str(source))
    assert len(findings) == 1
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize(
    "name,content",
    [
        ("zaps.csv", "Zap,Steps,Status\nSummarize email,Gmail > ChatGPT > Slack,on\n,Gmail > ChatGPT,on\n"),
        ("zaps.json", json.dumps([{"title": None, "steps": None}])),
        ("zaps.json", json.dumps([{"title": "", "steps": ["Gmail", "ChatGPT"]}])),
    ],
)
def test_zapier_row_with_data_but_no_zap_identity_is_still_incomplete(run_connector, tmp_path, name, content):
    source = tmp_path / name
    source.write_text(content)
    _, ctx = run_connector("lowcode.zapier", input=str(source))
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == ["lowcode.zapier: unsupported or malformed zap record; coverage incomplete"]


# ------------------------------------------------------------- ServiceNow


def _snow(index, responses):
    connector = servicenow.ServiceNowConnector(ConnectorContext(index=index, config={}))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.get_json.side_effect = responses
    return connector


def test_servicenow_server_side_page_cap_does_not_end_collection(index, monkeypatch):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    first = {"result": [{"sys_id": f"a{n}", "name": "A"} for n in range(100)]}
    second = {"result": [{"sys_id": f"b{n}", "name": "B"} for n in range(100)]}
    third = {"result": [{"sys_id": "c0", "name": "C"}]}
    connector = _snow(index, [first, second, third, {"result": []}])
    connector.ctx.stats = ScanStats(connector="lowcode.servicenow", started_at="now")
    records = list(connector.collect())
    assert len(records) == 201
    offsets = [call.kwargs["params"]["sysparm_offset"] for call in connector.http.get_json.call_args_list]
    assert offsets == [0, 100, 200, 201]
    assert not connector.ctx.stats.incomplete
