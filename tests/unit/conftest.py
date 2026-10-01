"""Shared fixtures for unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.config import ScanConfig
from shadowscan.models import Evidence, Finding, Kind, Surface

UNIT_FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def offline_config(tmp_path: Path) -> ScanConfig:
    """A minimal ScanConfig pointing at an empty workdir."""
    return ScanConfig(connectors=[], workdir=str(tmp_path))


@pytest.fixture
def sample_finding() -> Finding:
    """A minimal valid Finding for tests that need one."""
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="Test Agent",
        resource="/tmp/test",
        resource_type="repository",
        confidence=0.8,
        evidence=[
            Evidence(signal="framework:langchain", description="LangChain import detected"),
        ],
    )
