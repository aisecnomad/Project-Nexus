"""Provider code adapters must preserve the finding identity contract."""

from __future__ import annotations

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_offline_provider_finding_identity_matches_final_connector(tmp_path, connector):
    clones = tmp_path / "clones"
    repo = clones / "agent-repository"
    repo.mkdir(parents=True)
    (repo / "requirements.txt").write_text("langchain\n")
    config = ScanConfig(
        connectors=[ConnectorSpec(connector, {"input": str(clones), "use_git": False})],
        incremental=True,
        state_dir=str(tmp_path / "state"),
        parallel=1,
    )

    first = Engine(config).run()
    second = Engine(config).run()
    for result in (first, second):
        assert result.complete
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.connector == connector
        assert finding.id == finding.compute_id()
        assert "framework.langchain" in finding.frameworks
    assert second.stats[0].cached
    assert first.findings[0].id == second.findings[0].id
