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


def _git_version() -> tuple[int, ...]:
    import re as _re
    import shutil as _shutil
    import subprocess as _subprocess
    if not _shutil.which("git"):
        return ()
    out = _subprocess.run(["git", "--version"], capture_output=True, text=True, check=False).stdout
    match = _re.search(r"(\d+)\.(\d+)", out)
    return tuple(int(part) for part in match.groups()) if match else ()


# Offline history enrichment (use_git) requires Git 2.45+; see docs/production.md.
GIT_HISTORY_SUPPORTED = _git_version() >= (2, 45)


def pytest_configure(config):
    config.addinivalue_line("markers", "requires_git_history: needs Git 2.45+ for offline history enrichment")


def pytest_collection_modifyitems(config, items):
    if GIT_HISTORY_SUPPORTED:
        return
    skip = pytest.mark.skip(reason="git history enrichment requires Git 2.45+")
    for item in items:
        if "requires_git_history" in item.keywords:
            item.add_marker(skip)
