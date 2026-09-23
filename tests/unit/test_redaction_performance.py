"""URL credentials stay private without retrying unbounded query prefixes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

ROOT = Path(__file__).resolve().parents[2]
SECRET = "opaque-value-with-no-provider-prefix"


@pytest.mark.parametrize(("url", "expected"), [
    (
        f"https://example.test/path?%61pi%5Fkey={SECRET}&model=test#state=next",
        f"https://example.test/path?%61pi%5Fkey={REDACTED}&model=test#state=next",
    ),
    (
        f"https://example.test/#access_token={SECRET}&state=next",
        f"https://example.test/#access_token={REDACTED}&state=next",
    ),
    (
        f"https://user:{SECRET}@example.test?token={SECRET}&contact=a@b.test",
        f"https://{REDACTED}@example.test?token={REDACTED}&contact=a@b.test",
    ),
    (
        f"https://example.test?contact=a@b.test&signature={SECRET}",
        f"https://example.test?contact=a@b.test&signature={REDACTED}",
    ),
    (
        f"https://example.test?token={SECRET}?private-suffix&safe=a?b#code={SECRET}",
        f"https://example.test?token={REDACTED}&safe=a?b#code={REDACTED}",
    ),
    (
        f"https://example.test?token={SECRET}&token={SECRET}#%70assword={SECRET}",
        f"https://example.test?token={REDACTED}&token={REDACTED}#%70assword={REDACTED}",
    ),
    (
        "https://example.test/path?&&q=ordinary??text&flag#fragment",
        "https://example.test/path?&&q=ordinary??text&flag#fragment",
    ),
])
def test_url_redaction_preserves_structure_and_is_idempotent(url, expected):
    safe = sanitize_text(url)
    assert safe == expected
    assert SECRET not in safe
    assert sanitize_text(safe) == safe


def _bounded_process(script: str, *args: str) -> None:
    # This generous bound distinguishes linear work (well below a second on
    # ordinary hardware) from the former quadratic retry, which takes minutes.
    # No small wall-clock threshold or machine-dependent timing ratio is used.
    result = subprocess.run(
        [sys.executable, "-c", script, *args], cwd=ROOT,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_unmatched_url_query_prefix_has_bounded_work():
    _bounded_process("""
from shadowscan.utils.redaction import REDACTED, sanitize_text
url = 'https://example.test/' + '?' * 500_000
assert sanitize_text(url) == url
assert sanitize_text(url + '&%74oken=opaque-secret') == url + '&%74oken=' + REDACTED
""")


def test_full_source_scan_survives_hostile_url_preprocessing(tmp_path):
    (tmp_path / "a.py").write_text(
        "url = 'https://example.test/" + "?" * 500_000 + "'\n", encoding="utf-8",
    )
    (tmp_path / "b.py").write_text("from crewai import Agent\n", encoding="utf-8")
    _bounded_process("""
import sys
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.signatures import get_index
ctx = ConnectorContext(config={
    'path': sys.argv[1], 'use_git': False, 'scan_timeout': 0.05,
}, index=get_index())
findings = FilesystemConnector(ctx).run()
assert ctx.stats.objects_examined == 2, ctx.stats
assert any('framework.crewai' in finding.frameworks for finding in findings), ctx.stats
""", str(tmp_path))
