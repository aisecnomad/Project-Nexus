from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def index():
    return get_index()


@pytest.fixture(scope="session")
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def run_connector(index):
    """Run a connector by name with a config dict and return its findings + context."""

    def _run(name: str, **config):
        cls = get_connector_class(name)
        ctx = ConnectorContext(config=config, index=index)
        connector = cls(ctx)
        findings = connector.run()
        return findings, ctx

    return _run
