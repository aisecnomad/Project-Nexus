"""Source constructors are attributed through import binding, never by name alone."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.source_semantics import (
    MAX_AST_NODES,
    SourceBindingUnavailable,
    bound_source_matches,
)
from shadowscan.models import Kind

AIOHTTP_CLIENT = '''import subprocess
from aiohttp import ClientSession

async def fetch(url):
    async with ClientSession() as session:
        while True:
            async with session.get(url) as r:
                if r.status == 200:
                    return await r.text()

def run(cmd):
    return subprocess.Popen(cmd, shell=True)
'''

MCP_CLIENT = '''from mcp import ClientSession
from mcp.client.stdio import stdio_client

async def main(params):
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
'''

CREWAI_AGENT = '''from crewai import Agent, Crew, Task
researcher = Agent(role="Researcher", goal="find things", backstory="x", allow_delegation=True)
crew = Crew(agents=[researcher], tasks=[Task(description="d", agent=researcher)])
crew.kickoff()
'''


def scan(run_connector, root: Path):
    findings, ctx = run_connector("code.filesystem", path=str(root), use_git=False)
    return findings, ctx


def test_aiohttp_client_session_and_generic_loops_are_not_mcp_or_agent_evidence(tmp_path, run_connector):
    (tmp_path / "client.py").write_text(AIOHTTP_CLIENT)
    findings, ctx = scan(run_connector, tmp_path)
    assert findings == []
    assert ctx.stats.errors == []


def test_import_bound_mcp_client_session_is_protocol_evidence(tmp_path, run_connector):
    (tmp_path / "client.py").write_text(MCP_CLIENT)
    findings, _ = scan(run_connector, tmp_path)
    assert [f.kind for f in findings] == [Kind.FRAMEWORK_USAGE]
    assert "protocol.mcp" in findings[0].frameworks
    assert any(e.signal == "code:protocol.mcp" and "ClientSession" in e.description for e in findings[0].evidence)


def test_unparseable_source_keeps_lexical_agent_evidence_with_a_warning(tmp_path, run_connector):
    project = tmp_path / "svc"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "svc"\ndependencies = ["crewai"]\n')
    # Invalid on every interpreter; lexically clean, so only the binder fails.
    (project / "crew.py").write_text(CREWAI_AGENT + "def broken(:\n    pass\n")
    findings, ctx = scan(run_connector, project)
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert len(agents) == 1
    assert "framework.crewai" in agents[0].frameworks
    assert any("could not be parsed for import binding" in w for w in ctx.stats.warnings)
    assert ctx.stats.incomplete is False


@pytest.mark.skipif(sys.version_info >= (3, 12), reason="PEP 695 syntax parses on 3.12+")
def test_newer_python_grammar_does_not_erase_agent_evidence(tmp_path, run_connector):
    project = tmp_path / "svc"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "svc"\ndependencies = ["crewai"]\n')
    (project / "crew.py").write_text("type Alias = int\n" + CREWAI_AGENT)
    findings, _ = scan(run_connector, project)
    assert [f.kind for f in findings if f.kind == Kind.AGENT]


def test_binder_reports_unavailable_source_instead_of_silently_returning_nothing(index):
    with pytest.raises(SourceBindingUnavailable):
        bound_source_matches(index, "def broken(:\n    pass\n", "python", [])


def test_large_ordinary_module_binds_within_the_node_limit(index):
    # A 450 KB type checker has about 53k nodes; the limit must clear it comfortably.
    assert MAX_AST_NODES >= 200_000
    source = "from crewai import Agent\n" + "value = 1\n" * 30_000 + 'agent = Agent(role="x")\n'
    matches = bound_source_matches(index, source, "python", [])
    assert any(m.extra.get("verified_agent") for m in matches)


def test_file_budget_scales_with_size_and_is_capped(tmp_path, index):
    connector = FilesystemConnector(ConnectorContext(config={"scan_timeout": 2.0}, index=index))
    small = tmp_path / "small.py"
    small.write_text("x = 1\n")
    large = tmp_path / "large.py"
    large.write_bytes(b"x = 1\n" * 75_000)  # 450 KB
    huge = tmp_path / "huge.py"
    huge.write_bytes(b"x = 1\n" * 1_000_000)
    assert connector._file_budget(small) == 2.0
    assert connector._file_budget(large) == pytest.approx(9.0)
    assert connector._file_budget(huge) == 60.0
    assert connector._file_budget(tmp_path / "missing.py") == 2.0


def test_large_source_files_complete_instead_of_timing_out(tmp_path, run_connector):
    body = "def f%d(a, b):\n    return a + b\n\n" * 1
    lines = [body % i for i in range(9_000)]
    (tmp_path / "big.py").write_text("import os\n" + "".join(lines))
    findings, ctx = scan(run_connector, tmp_path)
    assert ctx.stats.errors == []
    assert ctx.stats.incomplete is False
    assert findings == []


def test_bound_only_signals_never_match_lexically(index):
    matches = index.match_code("async with ClientSession(r, w) as session:\n", "python")
    assert not any(m.signal.bound_only for m in matches)
    assert "protocol.mcp" not in {m.signature_id for m in matches}


def test_bound_only_is_accepted_only_on_code_signals():
    from shadowscan.signatures.loader import signature_from_dict

    base = {"id": "x.test", "category": "protocol", "name": "X"}
    signature_from_dict({**base, "signals": [{"type": "code", "patterns": ["Foo\\("], "bound_only": True}]})
    with pytest.raises(ValueError, match="bound_only"):
        signature_from_dict({**base, "signals": [{"type": "import", "patterns": ["foo"], "bound_only": True}]})
    with pytest.raises(ValueError, match="boolean"):
        signature_from_dict({**base, "signals": [{"type": "code", "patterns": ["Foo\\("], "bound_only": "yes"}]})


def test_other_lexical_protocol_code_evidence_is_kept(tmp_path, run_connector):
    (tmp_path / "server.py").write_text(
        "from fastmcp import FastMCP\nmcp = FastMCP('tools')\n\n@mcp.tool\ndef add(a: int, b: int) -> int:\n    return a + b\n"
    )
    findings, _ = scan(run_connector, tmp_path)
    descriptions = [e.description for f in findings for e in f.evidence if e.signal == "code:protocol.mcp"]
    assert any("@mcp.tool" in d for d in descriptions)


def test_per_file_connector_error_is_isolated_but_a_deadline_stops_the_walk(tmp_path, index, monkeypatch):
    from shadowscan.connectors.base import ConnectorError
    from shadowscan.connectors.code import filesystem
    from shadowscan.models import ScanStats

    (tmp_path / "a_bad.py").write_text("from crewai import Agent\n")
    (tmp_path / "b_good.py").write_text(CREWAI_AGENT)
    real = filesystem.read_text

    def flaky(path, *args, **kwargs):
        if path.name == "a_bad.py":
            raise ConnectorError("hostile file")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(filesystem, "read_text", flaky)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at="2026-09-25T00:00:00Z")
    findings = FilesystemConnector(ctx).run()
    assert any(f.kind == Kind.AGENT for f in findings)
    assert any("a_bad.py: file analysis incomplete (ConnectorError)" in e for e in ctx.stats.errors)


def test_bound_call_text_is_capped_per_file(index, monkeypatch):
    from shadowscan.connectors.code import source_semantics
    from shadowscan.signatures.matcher import MatchTimeoutError

    monkeypatch.setattr(source_semantics, "MAX_CALL_TEXT_TOTAL", 10_000)
    source = "from crewai import Agent\n" + "".join(f'a{i} = Agent(role="{"x" * 200}")\n' for i in range(100))
    with pytest.raises(MatchTimeoutError, match="call text"):
        bound_source_matches(index, source, "python", [])
    js = "import { Agent } from '@openai/agents';\n" + "".join(f'const a{i} = new Agent({{name: "{"x" * 200}"}});\n' for i in range(100))
    with pytest.raises(MatchTimeoutError, match="call text"):
        bound_source_matches(index, js, "javascript", [])


def test_javascript_bound_calls_report_correct_line_numbers(index):
    js = "import { Agent } from '@openai/agents';\n\n\nconst a = new Agent({ name: 'x', tools: [] });\n"
    lines = {m.line for m in bound_source_matches(index, js, "javascript", []) if m.extra.get("verified_agent")}
    assert lines == {4}


def test_per_pattern_cap_scales_with_input_size(index):
    from shadowscan.signatures.matcher import REGEX_TIMEOUT_SECONDS, pattern_timeout

    with index.scan_budget(30, size=900_000):
        assert pattern_timeout() > 8 * REGEX_TIMEOUT_SECONDS
    with index.scan_budget(30):
        assert pattern_timeout() == pytest.approx(REGEX_TIMEOUT_SECONDS)


def test_large_typescript_module_with_imports_completes(tmp_path, run_connector):
    header = "".join(f"import {{ helper{i} }} from './mod{i}';\n" for i in range(40))
    body = "".join(
        f"export const fn{i} = (value: number, other: string): number => helper{i % 40}(value) + other.length;\n"
        for i in range(9000)
    )
    (tmp_path / "big.ts").write_text(header + "import { Agent } from '@openai/agents';\n" + body)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.errors == [] and ctx.stats.incomplete is False


def test_binder_limit_keeps_lexical_evidence_and_marks_the_file_incomplete(tmp_path, run_connector, monkeypatch):
    from shadowscan.connectors.code import filesystem
    from shadowscan.signatures.matcher import MatchTimeoutError

    def exhausted(*_args, **_kwargs):
        raise MatchTimeoutError("source binding call limit exceeded")

    monkeypatch.setattr(filesystem, "bound_source_matches", exhausted)
    (tmp_path / "bundle.js").write_text(
        'import OpenAI from "openai";\nconst client = new OpenAI();\n'
        'const r = await client.chat.completions.create({model: "gpt-4o", tools: [{type: "function", function: {name: "f"}}], tool_choice: "auto"});\n'
    )
    findings, ctx = scan(run_connector, tmp_path)
    signals = {e.signal for f in findings for e in f.evidence}
    assert any(s.startswith("code:") for s in signals), signals
    assert any("import binding incomplete" in e for e in ctx.stats.errors)
    assert ctx.stats.incomplete is True


def test_unparseable_python_without_an_ai_library_is_never_an_agent(tmp_path, run_connector):
    (tmp_path / "search.py").write_text(
        'import urllib2\n\ndef google_search(query):\n    url = "https://www.example.com/search?q=" + query\n'
        '    return urllib2.urlopen(url).read()\n\nif __name__ == "__main__":\n    print "results:", google_search("weather")\n'
    )
    findings, _ = scan(run_connector, tmp_path)
    assert all(f.kind != Kind.AGENT for f in findings)
