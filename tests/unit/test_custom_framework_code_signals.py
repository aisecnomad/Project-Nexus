"""Custom-pack framework code patterns take effect in every source language.

The bundled framework patterns are evaluated by the Python/JavaScript import
binder, which replaces their lexical matches. A custom pack's pattern has no
such semantics: it must count as lexical evidence there as in Go or Java,
not be dropped silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import Finding, Kind
from shadowscan.signatures import SignatureIndex, load_signatures

PACK = """signatures:
  - id: custom.acme-agent
    name: Acme Agent Kit
    category: framework
    agent_indicator: true
    signals:
      - type: code
        weight: 0.9
        patterns: ['AcmeAgentKit\\(']
"""

CORROBORATED_PACK = """signatures:
  - id: custom.acme-agent
    name: Acme Agent Kit
    category: framework
    agent_indicator: true
    signals:
      - type: dependency
        ecosystem: pypi
        names: [acme-agent-kit]
        weight: 0.9
      - type: import
        languages: [python]
        patterns: ['^[^\\S\\r\\n]*from\\s+acme_kit\\s+import\\b']
        weight: 0.9
      - type: code
        weight: 0.9
        patterns: ['AcmeAgentKit\\(']
"""

SOURCES = {
    "main.py": "kit = AcmeAgentKit()\nkit.run()\n",
    "main.ts": "const kit = AcmeAgentKit();\nkit.run();\n",
    "main.go": "package main\n\nfunc main() { kit := AcmeAgentKit(); kit.Run() }\n",
}


def _index(tmp_path: Path, pack: str) -> SignatureIndex:
    directory = tmp_path / "pack"
    directory.mkdir()
    (directory / "custom.yaml").write_text(pack)
    return SignatureIndex(load_signatures(extra_dirs=[directory]))


def _project(index: SignatureIndex, root: Path, files: dict[str, str]) -> Finding | None:
    root.mkdir()
    for name, text in files.items():
        (root / name).write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    assert ctx.stats is not None and not ctx.stats.incomplete, ctx.stats.errors if ctx.stats else None
    return next((f for f in findings if f.resource_type == "project"), None)


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_uncorroborated_custom_framework_pattern_is_reported_in_every_language(tmp_path, name):
    index = _index(tmp_path, PACK)
    # Like any lexical framework pattern without the product's import or
    # dependency, the pattern alone establishes nothing: no finding, and a
    # note names the file so the evidence does not disappear silently.
    alone = tmp_path / "alone"
    alone.mkdir()
    (alone / name).write_text(SOURCES[name])
    ctx = ConnectorContext(config={"path": str(alone), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    assert not [f for f in findings if f.resource_type == "project"], f"{name}: pattern alone established"
    assert ctx.stats is not None and not ctx.stats.incomplete and not ctx.stats.errors
    assert any(name in w and "evidence not reported" in w for w in ctx.stats.warnings)
    # Beside an established library the evidence is reported, capped below
    # the confirmed band and listed as potential: frameworks[] does not name
    # the custom framework, and the finding is usage, not an agent.
    finding = _project(index, tmp_path / "repo", {name: SOURCES[name], "requirements.txt": "openai>=1.0\n"})
    assert finding is not None, f"{name}: custom framework pattern was ignored"
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert finding.frameworks == [] and finding.model_providers == ["provider.openai"]
    assert finding.metadata["potential_frameworks"] == ["custom.acme-agent"]
    evidence = [e for e in finding.evidence if e.signal == "code:custom.acme-agent"]
    assert len(evidence) == 1 and evidence[0].attributes["confidence_group"] == "uncorroborated-lexical"
    assert evidence[0].weight == pytest.approx(0.6)


@pytest.mark.parametrize("name", ["main.py", "main.ts"])
def test_dependency_corroborates_a_custom_pattern_as_an_agent(tmp_path, name):
    files = {name: SOURCES[name], "requirements.txt": "acme-agent-kit==1.2\n"}
    finding = _project(_index(tmp_path, CORROBORATED_PACK), tmp_path / "repo", files)
    assert finding is not None and finding.kind == Kind.AGENT
    assert finding.metadata["agent_indicators"] >= 1


def test_import_bound_call_is_not_counted_twice(tmp_path):
    source = "from acme_kit import AcmeAgentKit\n\nkit = AcmeAgentKit(tools=[search])\n"
    finding = _project(_index(tmp_path, CORROBORATED_PACK), tmp_path / "repo", {"main.py": source})
    assert finding is not None and finding.kind == Kind.AGENT
    code = [e for e in finding.evidence if e.signal == "code:custom.acme-agent"]
    assert [e.location for e in code] == ["main.py:3"]


def test_bundled_framework_patterns_still_need_the_import_binder(tmp_path, index):
    # A local class named like a CrewAI export is not CrewAI.
    source = "class Crew:\n    def kickoff(self):\n        return 1\n\nCrew().kickoff()\n"
    assert _project(index, tmp_path / "repo", {"team.py": source}) is None
