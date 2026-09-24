from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).parent / "fixtures"


def _git_supports_metadata_reads() -> bool:
    """Git history enrichment fails closed without ``--no-lazy-fetch`` (Git 2.45+)."""
    try:
        return subprocess.run(["git", "--no-lazy-fetch", "--version"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "requires_git_metadata: needs Git 2.45+ (--no-lazy-fetch) for history enrichment to succeed",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    # Tests that assert successful git author/history enrichment need a Git that
    # accepts the scanner's mandatory lazy-fetch suppression; older stock Git
    # (for example 2.43 on Ubuntu 24.04) correctly yields an incomplete scan instead.
    if _git_supports_metadata_reads():
        return
    skip = pytest.mark.skip(reason="git metadata enrichment requires Git 2.45+ (--no-lazy-fetch)")
    for item in items:
        if "requires_git_metadata" in item.keywords:
            item.add_marker(skip)


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
