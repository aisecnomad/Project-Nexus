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
