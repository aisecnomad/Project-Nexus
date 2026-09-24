"""Bounded, deterministic offline throughput benchmark for code scanning.

The workload is synthetic. It does not substitute for a production-sized
repository benchmark or prove any specific deployment SLO.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.signatures import get_index
from tools.evaluation.evaluate import _percentile


def benchmark(*, files: int = 1000, runs: int = 3) -> dict:
    if type(files) is not int or not 1 <= files <= 10_000:
        raise ValueError("files must be from 1 to 10000")
    if type(runs) is not int or not 1 <= runs <= 10:
        raise ValueError("runs must be from 1 to 10")
    index = get_index()
    paths = min(20, files)
    durations = []
    findings_count = None
    file_bytes = 0
    with tempfile.TemporaryDirectory(prefix="shadowscan-benchmark-") as temp:
        root = Path(temp)
        for i in range(paths):
            project = root / f"project-{i:02d}"
            project.mkdir()
            manifest = "[project]\nname = 'performance-fixture'\nversion = '0.1'\n"
            (project / "pyproject.toml").write_text(manifest, encoding="utf-8")
            file_bytes += len(manifest.encode("utf-8"))
        for i in range(files):
            source = (
                "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n"
                if i % 10 == 0
                else f"def process_{i}(value):\n    return value + 1\n"
            )
            (root / f"project-{i % paths:02d}" / f"module_{i:05d}.py").write_text(source, encoding="utf-8")
            file_bytes += len(source.encode("utf-8"))
        for _ in range(runs):
            ctx = ConnectorContext(
                config={
                    "path": str(root),
                    "label": "eval:benchmark",
                    "use_git": False,
                    "scan_secrets": False,
                    "max_files": files + paths,
                },
                index=index,
            )
            started = time.perf_counter()
            findings = FilesystemConnector(ctx).run()
            duration = time.perf_counter() - started
            stats = ctx.stats
            if (
                stats is None
                or stats.incomplete
                or stats.skipped
                or stats.errors
                or stats.warnings
                or stats.objects_examined != files + paths
            ):
                raise RuntimeError("benchmark scan was incomplete or did not examine every generated file")
            if findings_count is not None and len(findings) != findings_count:
                raise RuntimeError("benchmark finding count varied across identical scans")
            findings_count = len(findings)
            durations.append(duration)
    median = statistics.median(durations)
    return {
        "schema": 1,
        "workload": "synthetic: 20 or fewer Python projects, 10% active LangGraph files",
        "files": files,
        "project_manifests": paths,
        "bytes": file_bytes,
        "runs": runs,
        "finding_count": findings_count,
        "elapsed_seconds": [round(value, 4) for value in durations],
        "median_seconds": round(median, 4),
        "p95_seconds": round(_percentile(durations, 0.95), 4),
        "files_per_second_at_median": round((files + paths) / median, 2),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path, help="create a JSON report, mode 0600; never overwrite")
    args = parser.parse_args(argv)
    try:
        report = benchmark(files=args.files, runs=args.runs)
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
