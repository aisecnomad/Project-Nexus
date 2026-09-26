"""Large ordinary sources complete: speedups must not change what is matched."""

from __future__ import annotations

import re
import time

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import bound_source_matches
from shadowscan.signatures import matcher as matcher_module


def _sample_host(pattern: str) -> str:
    """A hostname matching one of the built-in domain expressions."""
    for optional, chosen in (
        ("(?:-runtime|-agent-runtime|-agent|-agentcore|-data-automation-runtime)?", "-agent-runtime"),
        ("(?:-runtime)?", "-runtime"), ("(?:-fips)?", ""), ("(?:-control)?", ""),
        ("(?:inference\\.)?", "inference."), ("(?:eu|us)", "eu"),
    ):
        pattern = pattern.replace(optional, chosen)
    for token, chosen in ((".*", "abc"), ("[a-z0-9-]+", "us-east-1"), ("[a-z]+", "com"), ("\\d*", "2"), ("[0-9]*", "4")):
        pattern = pattern.replace(token, chosen)
    return pattern.strip("^$").replace("\\.", ".")


def test_domain_gate_never_changes_domain_matches(index, monkeypatch):
    hosts = {"this.props", "module.exports", "api.openai.com", "localhost:8080/v1", "10.0.0.1:4000", "a" * 300 + ".n8n.cloud"}
    for rx, _, _ in index._domain_regex:
        host = _sample_host(rx.pattern)
        assert rx.search(host), (rx.pattern, host)
        hosts |= {host, host.upper(), "x." + host, host + ".evil.example", host + ":11434"}
    hosts |= {suffix.lstrip(".") for suffix, _, _ in index._domain_suffixes}

    def matches(host):
        return [(m.signature_id, id(m.signal), m.value) for m in index.match_domain(host)]

    gated = {host: matches(host) for host in hosts}
    monkeypatch.setattr(index, "_domain_gate", None)
    assert {host: matches(host) for host in hosts} == gated
    assert sum(bool(found) for found in gated.values()) > len(index._domain_regex)


def test_domain_gate_excludes_expressions_alternation_could_change():
    plain = matcher_module.regex.compile(r".*\.example\.com$", matcher_module.regex.IGNORECASE | matcher_module.regex.VERSION0)
    backreference = matcher_module.regex.compile(r"^(a)\1\.example$", matcher_module.regex.IGNORECASE | matcher_module.regex.VERSION0)
    inline = matcher_module.regex.compile(r"(?x) a \. example$", matcher_module.regex.IGNORECASE | matcher_module.regex.VERSION0)
    gate, ungated = matcher_module._domain_regex_gate([(plain, None, None), (backreference, None, None), (inline, None, None)])
    assert gate is not None and gate.pattern == r"(?:\.example\.com$)"
    assert [entry[0] for entry in ungated] == [backreference, inline]


def test_dotted_source_tokens_skip_per_signature_domain_searches(index, monkeypatch):
    calls = []
    original = matcher_module._search

    def counting(rx, text, context):
        calls.append(context)
        return original(rx, text, context)

    monkeypatch.setattr(matcher_module, "_search", counting)
    assert index.match_domain("this.state") == []
    assert calls == ["domain signatures", "domain signatures"]


def test_javascript_binder_ignores_unrecognized_imports_in_large_modules(index):
    imports = "".join(f"import {{ f{i} }} from 'lib{i}';\n" for i in range(400))
    body = "".join(f"export function g{i}(f{i % 400}, x) {{ return f{i % 400}(x) + (x < 3 ? x : 2) / 7; }}\n" for i in range(6000))
    text = imports + "import OpenAI from 'openai';\nconst client = new OpenAI();\n" + body
    ignored, ambiguous = noncode_ranges(text, "javascript")
    assert not ambiguous
    started = time.monotonic()
    with index.scan_budget(matcher_module.default_budget_for(len(text)), size=len(text)):  # as the connector does
        matches = bound_source_matches(index, text, "javascript", ignored)
    assert time.monotonic() - started < 5
    assert any(m.signature_id == "provider.openai" for m in matches)


@pytest.mark.parametrize("keyword", ["agent", "llm", "tool"])
def test_browsing_cooccurrence_is_linear_on_minified_lines_and_still_matches_code(index, keyword):
    minified = ";".join(f"window.playwright{i}=playwright.x({i})" for i in range(20_000)) + ";var z=" + "0" * 600 + ";" + keyword
    started = time.monotonic()
    found = [m for m in index.match_code(minified, "javascript") if m.signature_id == "heuristic.browsing"]
    assert time.monotonic() - started < 5
    assert not found  # the keyword is hundreds of characters away
    line = f"const browser = await playwright.chromium.launch(); // used by the {keyword}"
    code = f"const browser = await playwright.chromium.launch(); const {keyword} = 1;\n"
    assert any(m.signature_id == "heuristic.browsing" for m in index.match_code(code, "javascript"))
    assert re.search(r"\bplaywright\b[^\n]{0,500}\b(?:agent|llm|tool)\b", line)


@pytest.mark.parametrize("pattern", [r".*?\.llm\.corp\.example$", r".*+\.llm\.corp\.example$"])
def test_lazy_or_possessive_domain_prefixes_are_kept_in_the_gate(pattern):
    from shadowscan.signatures.loader import signature_from_dict
    from shadowscan.signatures.matcher import SignatureIndex

    index = SignatureIndex([signature_from_dict({
        "id": "custom.internal-llm", "name": "Internal LLM gateway", "category": "provider",
        "signals": [{"type": "domain", "values": [f"re:{pattern}"], "weight": 0.9}],
    })])
    assert [m.signature_id for m in index.match_domain("gw.llm.corp.example")] == (
        [] if pattern.startswith(".*+") else ["custom.internal-llm"])
