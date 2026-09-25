from __future__ import annotations

import functools
import subprocess
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).parent / "fixtures"


@functools.cache
def git_supports_metadata_policy() -> bool:
    """Opt-in history enrichment requires Git 2.45+ (``--no-lazy-fetch``).

    Ubuntu 24.04 LTS ships 2.43 and Debian bookworm ships 2.39, where the
    scanner fails closed by design; tests of the enrichment itself skip there.
    """
    try:
        result = subprocess.run(
            ["git", "--no-lazy-fetch", "--version"], capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


requires_git_metadata = pytest.mark.skipif(
    not git_supports_metadata_policy(), reason="Git 2.45+ with --no-lazy-fetch is required for history enrichment",
)


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
