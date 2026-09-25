"""Identical inputs produce byte-identical reports, whatever the process hash seed.

Set iteration order depends on PYTHONHASHSEED. A report that changes between two
scans of the same input breaks baselines, SARIF deduplication and code review of
findings, so every connector must order its output explicitly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Gateway pseudonyms are keyed per scan by design; pin the key for this check.
RUNNER = (
    "import secrets, sys\n"
    "secrets.token_bytes = lambda n=32: b'k' * n\n"
    "from shadowscan.cli import main\n"
    "sys.exit(main(sys.argv[1:]))\n"
)


def _scan(tmp_path: Path, seed: str, args: list[str]) -> dict:
    out = tmp_path / f"report-{seed}.json"
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", RUNNER, *args, "--format", "json", "-o", str(out)],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode in {0, 2}, proc.stderr[-2000:]
    report = json.loads(out.read_text())
    for key in ("started_at", "finished_at"):
        report.pop(key, None)
    for stats in report.get("stats", []):
        stats.pop("started_at", None)
        stats.pop("finished_at", None)
    return report


@pytest.mark.parametrize("args", [
    ["scan", "-c", "examples/shadowscan.offline.yaml"],
    ["code", "tests/fixtures/sample_repo"],
], ids=["offline-demo", "sample-repo"])
def test_reports_do_not_depend_on_the_hash_seed(tmp_path, args):
    first = _scan(tmp_path, "1", args)
    second = _scan(tmp_path, "2", args)
    assert first["findings"], "the fixture scan must produce findings"
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
