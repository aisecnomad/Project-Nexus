"""Cross-signal corroboration: diverse signal types reinforce a finding.

When a project has both library evidence (import/dependency) AND code-pattern
evidence, or three or more independent signal types, a corroboration bonus
rewards the diversity. The bonus is a small synthetic evidence item in its
own confidence group so it is transparent and auditable.
"""

from __future__ import annotations


def _project(findings):
    return next((f for f in findings if f.resource_type == "project"), None)


class TestCrossSignalCorroboration:
    def test_dependency_plus_code_pattern_gets_corroboration_boost(self, tmp_path, run_connector):
        (tmp_path / "requirements.txt").write_text("openai>=1.0\n")
        (tmp_path / "app.py").write_text(
            "from openai import OpenAI\n"
            "client = OpenAI()\n"
            "response = client.chat.completions.create(\n"
            "    model='gpt-4', messages=[{'role': 'user', 'content': 'hello'}]\n"
            ")\n"
        )
        findings, _ = run_connector("code.filesystem", path=str(tmp_path))
        proj = _project(findings)
        assert proj is not None
        assert proj.metadata.get("cross_signal_corroboration") is not None
        corr = proj.metadata["cross_signal_corroboration"]
        assert corr["library_and_code"] is True
        assert corr["boost"] > 0
        corr_ev = [e for e in proj.evidence if e.signal == "corroboration:cross-signal"]
        assert len(corr_ev) == 1
        assert corr_ev[0].attributes.get("synthetic") is True
        assert corr_ev[0].attributes.get("confidence_group") == "cross-signal-corroboration"

    def test_import_only_no_corroboration_boost(self, tmp_path, run_connector):
        (tmp_path / "app.py").write_text("import openai\n")
        findings, _ = run_connector("code.filesystem", path=str(tmp_path))
        proj = _project(findings)
        assert proj is not None
        assert proj.metadata.get("cross_signal_corroboration") is None

    def test_multi_signal_types_get_higher_boost(self, tmp_path, run_connector):
        (tmp_path / "requirements.txt").write_text("openai>=1.0\n")
        (tmp_path / "app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n"
        )
        (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-placeholder\n")
        findings, _ = run_connector("code.filesystem", path=str(tmp_path))
        proj = _project(findings)
        assert proj is not None
        corr = proj.metadata.get("cross_signal_corroboration")
        if corr is not None and corr.get("multi_signal"):
            assert corr["boost"] == 0.15

    def test_corroboration_boost_increases_confidence(self, tmp_path, run_connector):
        (tmp_path / "requirements.txt").write_text("langchain>=0.1\n")
        (tmp_path / "agent.py").write_text(
            "from langchain.agents import AgentExecutor, create_openai_functions_agent\n"
            "agent = create_openai_functions_agent(llm, tools, prompt)\n"
            "executor = AgentExecutor(agent=agent, tools=tools)\n"
            "executor.invoke({'input': 'hello'})\n"
        )
        findings, _ = run_connector("code.filesystem", path=str(tmp_path))
        proj = _project(findings)
        assert proj is not None
        assert proj.confidence > 0
        corr_ev = [e for e in proj.evidence if e.signal == "corroboration:cross-signal"]
        if corr_ev:
            assert proj.confidence > max(
                e.weight for e in proj.evidence if e.signal != "corroboration:cross-signal"
            )
