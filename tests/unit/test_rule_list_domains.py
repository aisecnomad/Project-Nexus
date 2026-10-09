"""Hosts that a hosts file, ad-block list, resolver or proxy rule list routes are mentions, not usage."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code.catalogs import HostLineFilter, rule_list_document, rule_list_line
from shadowscan.signatures import get_index


@pytest.mark.parametrize(
    "line",
    [
        "0.0.0.0 chatgpt.com",
        "127.0.0.1\tapi.openai.com",
        "  0.0.0.0   hook.integromat.com  # comment",
        ":: api.anthropic.com",
        "||api.openai.com^",
        "@@||api.openai.com^$third-party",
        "address=/api.openai.com/0.0.0.0",
        "server=/api.openai.com/1.1.1.1",
        "DOMAIN-SUFFIX,openai.com,PROXY",
        "host-keyword, openai, REJECT",
        "  - DOMAIN,chat.openai.com,Proxy",
        "- 'DOMAIN-SUFFIX,anthropic.com,PROXY'",
    ],
)
def test_rule_list_entries_are_recognised(line: str):
    assert rule_list_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "# 0.0.0.0 chatgpt.com",
        'OPENAI_BASE_URL = "https://api.openai.com/v1"',
        "base_url: https://api.openai.com/v1",
        "- https://api.openai.com/v1",
        "0.0.0.0",  # an address with no host
        "10.0.0.5 api.openai.com",  # a private address is a mapping to a proxy, not a block
        "url,https://api.openai.com",
        "DOMAIN-SUFFIX",  # a rule type without a value
        "proxy-groups: DOMAIN-SUFFIX is a rule type",
        "domain-keyword, openai, REJECT",  # proxy rule types are upper case (or the host-* forms)
        "api.openai.com^",  # an ad-block entry needs the leading ||
        "||api.openai.com || fallback",  # a logical-or continuation line is code
        "host, port = api.openai.com, 443",  # a Python assignment
        "HOST api.openai.com",
        "DOMAIN api.openai.com",
    ],
)
def test_other_lines_are_not_rule_list_entries(line: str):
    assert not rule_list_line(line)


def _hosts(text: str, skip=rule_list_line) -> list[tuple[str, int | None]]:
    return [(m.signature_id, m.line) for m in get_index().match_domains_in_text(text, skip_line=skip)]


def test_a_host_on_a_rule_line_is_skipped_and_the_same_host_elsewhere_still_counts():
    text = "0.0.0.0 api.openai.com\nDOMAIN-SUFFIX,openai.com,PROXY\nurl = https://api.openai.com/v1\n"
    counted = _hosts(text)
    assert counted and {line for _, line in counted} == {3}
    assert "provider.openai" in {signature for signature, _ in counted}
    # Without the filter the blocklist entries are where the hosts are found.
    assert {line for _, line in _hosts(text, skip=None)} >= {1, 2}


def test_a_file_of_rule_entries_matches_nothing():
    text = "\n".join(f"0.0.0.0 host{n}.example" for n in range(50)) + "\n0.0.0.0 hook.integromat.com\n"
    assert _hosts(text) == []


def test_a_very_long_minified_line_is_read_only_at_its_start():
    line = "x " + "api.openai.com " * 4000
    assert _hosts(line)  # not a rule line, so the host counts, and the scan stays fast


def test_a_hosts_file_does_not_make_a_project_an_ai_project(tmp_path):
    (tmp_path / "hosts").write_text(
        "# blocklist\n0.0.0.0 beacon.my.salesforce.com\n0.0.0.0 hook.integromat.com\n", encoding="utf-8"
    )
    (tmp_path / "proxy.yaml").write_text(
        "rules:\n  - DOMAIN-SUFFIX,chatgpt.com,PROXY\n  - DOMAIN-SUFFIX,openai.com,PROXY\n", encoding="utf-8"
    )
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    assert report["findings"] == []


def test_a_real_endpoint_beside_a_blocklist_is_still_found(tmp_path):
    (tmp_path / "hosts").write_text("0.0.0.0 api.openai.com\n", encoding="utf-8")
    (tmp_path / "settings.yaml").write_text("llm:\n  base_url: https://api.openai.com/v1\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    assert any("provider.openai" in finding["model_providers"] for finding in report["findings"])


_HOSTS = "# [integromat.com]\n127.0.0.1 hook.integromat.com\n" + "".join(
    f"127.0.0.1 ads{n}.example\n" for n in range(6)
)


def test_a_document_of_rule_entries_is_a_rule_list_and_its_comments_belong_to_it():
    assert rule_list_document(_HOSTS)
    skip = HostLineFilter(_HOSTS)
    assert skip("# [integromat.com]") and skip("127.0.0.1 hook.integromat.com")
    assert not skip('url: "https://api.openai.com/v1"')


@pytest.mark.parametrize(
    "text",
    [
        "# [integromat.com]\n127.0.0.1 hook.integromat.com\n",  # too few entries to be a list
        "llm:\n  base_url: https://api.openai.com/v1\n# 0.0.0.0 x\n",
        _HOSTS + "".join(f"setting{n}: value\n" for n in range(40)),  # mostly something else
        "",
    ],
)
def test_other_documents_are_not_rule_lists(text: str):
    assert not rule_list_document(text)
    assert not HostLineFilter(text)("# base_url: https://api.openai.com/v1")


def test_a_comment_in_a_rule_list_is_not_use_but_a_comment_in_a_configuration_is():
    assert _hosts(_HOSTS, skip=HostLineFilter(_HOSTS)) == []
    config = "# base_url: https://api.openai.com/v1\nmodel: gpt-4o\n"
    assert _hosts(config, skip=HostLineFilter(config))


def test_the_filter_applies_to_documents_that_are_not_source_files(tmp_path):
    source = "const hosts = [\n  'api.openai.com',\n]\nhost, port = 'api.openai.com', 443\n"
    (tmp_path / "client.ts").write_text(source, encoding="utf-8")
    (tmp_path / "blocklist.txt").write_text(
        "\n".join(f"0.0.0.0 host{n}.example" for n in range(8)) + "\n0.0.0.0 api.openai.com\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    locations = {
        str(evidence.get("location") or "")
        for finding in report["findings"]
        for evidence in finding.get("evidence", [])
    }
    assert any(location.startswith("client.ts") for location in locations)
    assert not any(location.startswith("blocklist.txt") for location in locations)
