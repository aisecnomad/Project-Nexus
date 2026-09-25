from __future__ import annotations

import functools
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).parent / "fixtures"

# Offline git enrichment passes ``--no-lazy-fetch``, which older Git rejects
# (fail closed). Tests that run real git enrichment need this host version.
GIT_ENRICHMENT_MIN_VERSION = (2, 45)


@functools.lru_cache(maxsize=1)
def host_git_version() -> tuple[int, int] | None:
    """Return the host ``git`` version as ``(major, minor)``, or None without a usable git.

    The result is parsed from ``git --version`` once per process. Any failure to
    locate or run git reports None so callers can skip rather than error.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        completed = subprocess.run([git, "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\bgit version (\d+)\.(\d+)", completed.stdout)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


# Applied by pytest_collection_modifyitems to every test marked
# ``@pytest.mark.requires_git_2_45``; the condition is fixed per host.
requires_git_2_45 = pytest.mark.skipif(
    (host_git_version() or (0, 0)) < GIT_ENRICHMENT_MIN_VERSION,
    reason="tool requires Git >= 2.45 for lazy-fetch suppression",
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_git_2_45: the test runs real git enrichment, which needs Git >= 2.45 on the host",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if item.get_closest_marker("requires_git_2_45") is not None:
            item.add_marker(requires_git_2_45)


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
