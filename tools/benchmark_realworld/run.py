"""Run the real-world benchmark's tools over the corpus; one JSONL file per tool.

``python -m tools.benchmark_realworld.run --manifest tools/benchmark_realworld/corpus.json
  --checkout-root /home/user --tool-root /opt/rwbench/tools
  --results tools/benchmark_realworld/results --raw /opt/rwbench/raw``

Every case runs as user ``nobody`` inside fresh network and PID namespaces, with
an empty environment and ``HOME`` set to the case directory. A checkout that is
not at its pinned commit stops the run before any tool starts. Raw tool output
goes to ``--raw``, outside the repository, after redaction; the committed
results hold verdicts and sanitized notes only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.benchmark.adapters import Adapter, Outcome, ShadowScan, ToolEnv, set_run_as
from tools.benchmark_realworld.adapters import ADAPTERS, ADAPTERS_V2, TOOL_PINS
from tools.benchmark_realworld.cases import (
    RealCase,
    build_cases,
    build_cases_v2,
    checkout_head,
    redact,
    sanitize_note,
    validate_manifest,
)

# Drop to ``nobody`` inside the namespaces (see ``tools.benchmark.adapters``).
NOBODY = ("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups")
SANDBOX = (
    "unshare --net --pid --fork --mount-proc; setpriv nobody; empty environment; "
    "HOME=case; no .git, no symlinks"
)
ROOT = Path(__file__).resolve().parents[2]


# The code that produces the verdict rows: the case builder, the adapters, the runner and the
# case base they share. The scorers and the report are not in this hash; they are frozen as files
# in FREEZE-v2.txt, so a change to them does not invalidate a run that was already made.
VERDICT_CODE = (
    "tools/benchmark/adapters.py",
    "tools/benchmark/common.py",
    "tools/benchmark_realworld/adapters.py",
    "tools/benchmark_realworld/cases.py",
    "tools/benchmark_realworld/run.py",
)


def code_sha256(root: Path) -> str:
    """SHA-256 over the verdict code (``VERDICT_CODE``), each file's path included."""
    digest = hashlib.sha256()
    for name in VERDICT_CODE:
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


def select_only(cases: list[RealCase], only_cases: Path) -> list[RealCase]:
    """The cases named in a sensitivity re-run's list. An unknown id is refused, never ignored."""
    keep = set(only_cases.read_text(encoding="utf-8").split())
    unknown = sorted(keep - {c.case_id for c in cases})
    if unknown:  # a misspelt id must not shrink a sensitivity re-run without a word
        raise ValueError(f"--only-cases names cases that do not exist: {unknown[:5]}")
    selected = [c for c in cases if c.case_id in keep]
    if not selected:
        raise ValueError("--only-cases lists no case")
    return selected


def provenance_conflict(previous: dict[str, Any], provenance: dict[str, Any], names: set[str]) -> str | None:
    """Why the summaries a run would keep came from other inputs or code; None when they did not."""
    kept = sorted(r["tool"] for r in previous.get("runs", []) if r["tool"] not in names)
    if kept and any(previous.get(key) != value for key, value in provenance.items()):
        return f"holds {kept} from a run with other inputs or code; use a new results directory"
    return None


def _run_one(adapter: Adapter, case: RealCase, env: ToolEnv, scratch: Path, checkout_root: Path) -> Outcome:
    """One adapter on one case. Any exception is an error outcome, never a negative."""
    work = Path(tempfile.mkdtemp(prefix=f"{adapter.name}-", dir=scratch))
    work.chmod(0o777)
    try:
        outcome = adapter.run(case, work, env)
    except Exception as exc:  # noqa: BLE001 - a broken adapter or report is an error, not a negative
        outcome = Outcome("error", note=f"adapter exception: {type(exc).__name__}")
    finally:
        outcome.note = sanitize_note(outcome.note, paths=(str(work), str(scratch), str(checkout_root)))
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(work.parent / f"{work.name}-baseline", ignore_errors=True)
    return outcome


def _write_raw(raw_dir: Path, tool: str, case_id: str, raw: dict[str, str]) -> None:
    for name, text in raw.items():
        path = raw_dir / tool / case_id.replace(":", "_") / Path(name).name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(redact(text), encoding="utf-8")


def run_tool(
    adapter: Adapter,
    cases: list[RealCase],
    env: ToolEnv,
    results: Path,
    raw_dir: Path,
    scratch: Path,
    checkout_root: Path,
    workers: int,
) -> dict[str, Any]:
    rows: dict[str, dict[str, Any]] = {}
    started = time.monotonic()

    def task(case: RealCase) -> None:
        outcome = _run_one(adapter, case, env, scratch, checkout_root)
        if outcome.raw:
            _write_raw(raw_dir, adapter.name, case.case_id, outcome.raw)
        rows[case.case_id] = {
            "case": case.case_id,
            "repo": case.case_id.split(":")[0],
            "surface": case.surface,
            "family": case.family,
            "label": case.label,
            "status": outcome.status,
            "detected": outcome.detected,
            "items": outcome.items,
            "agentic": outcome.agentic,
            "seconds": round(outcome.seconds, 3),
            "note": outcome.note,
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(task, cases))
    with (results / f"{adapter.name}.jsonl").open("w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(json.dumps(rows[case.case_id], sort_keys=True) + "\n")
    statuses = [r["status"] for r in rows.values()]
    return {
        "tool": adapter.name,
        "display": adapter.display,
        "source": adapter.source,
        "surfaces": adapter.surfaces,
        "wall_seconds": round(time.monotonic() - started, 1),
        "ok": statuses.count("ok"),
        "error": statuses.count("error"),
        "n/a": statuses.count("n/a"),
    }


def self_check(root: Path, env: ToolEnv, scratch: Path, raw_dir: Path) -> dict[str, Any]:
    """ShadowScan on this repository, descriptive only (the repository is not a corpus member)."""
    case = RealCase(
        case_id="self:repo",
        surface="repo",
        family="self-check",
        label="none",
        difficulty="n/a",
        rationale="self-check, not scored",
        source_dir=root,
    )
    outcome = _run_one(ShadowScan(), case, env, scratch, root)
    if outcome.raw:
        _write_raw(raw_dir, "shadowscan-self-check", case.case_id, outcome.raw)
    return {
        "repo": "aisecnomad/Project-Nexus",
        "status": outcome.status,
        "detected": outcome.detected,
        "items": outcome.items,
        "note": outcome.note,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--checkout-root", type=Path, required=True, help="directory the manifest's dir paths are under"
    )
    parser.add_argument(
        "--tool-root", type=Path, required=True, help="venvs/, bin/ and third_party/ from install_tools.sh"
    )
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument(
        "--raw", type=Path, required=True, help="raw tool output (redacted), kept outside the repository"
    )
    parser.add_argument("--scratch", type=Path, default=Path("/opt/rwbench/work"))
    parser.add_argument("--tools", default="all", help="comma-separated adapter names")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0, help="first N repositories (calibration only)")
    parser.add_argument("--self-check", action="store_true", help="also run ShadowScan on this repository")
    parser.add_argument(
        "--only-cases", type=Path, default=None, help="file of case ids to run (sensitivity re-runs only)"
    )
    parser.add_argument(
        "--protocol", type=Path, default=None, help="protocol file; its SHA-256 goes in the run manifest"
    )
    args = parser.parse_args(argv)

    # Work directories are created world-writable so the unprivileged tool runs can write to them.
    os.umask(0)
    manifest_bytes = args.manifest.read_bytes()
    doc = json.loads(manifest_bytes)
    version = int(doc.get("version", 1))  # v1 manifests carry no version field
    if version not in (1, 2):
        parser.error(f"unknown manifest version {version}")
    repos = validate_manifest(doc)
    if args.limit:
        repos = repos[: args.limit]
    subset = bool(args.only_cases or args.limit)
    if subset and (args.results / "run-manifest.json").exists():
        # A subset run writes its rows over the same tool files, so it needs its own results folder.
        parser.error("a subset run needs a results directory of its own")
    cases = (build_cases_v2 if version == 2 else build_cases)(repos, args.checkout_root)
    if args.only_cases:
        try:
            cases = select_only(cases, args.only_cases)
        except ValueError as exc:
            parser.error(str(exc))

    wanted = None if args.tools == "all" else set(args.tools.split(","))
    adapters = [a for a in (ADAPTERS_V2 if version == 2 else ADAPTERS) if wanted is None or a.name in wanted]
    if wanted and wanted - {a.name for a in adapters}:
        parser.error(f"unknown tools: {sorted(wanted - {a.name for a in adapters})}")

    # Summaries kept from an earlier run must come from the same manifest, protocol and code.
    provenance = {
        "manifest_version": version,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "protocol_sha256": hashlib.sha256(args.protocol.read_bytes()).hexdigest() if args.protocol else None,
        "code_sha256": code_sha256(ROOT),
        "tool_pins": TOOL_PINS,
        "sandbox": SANDBOX,
    }
    # A subset run (sensitivity or calibration) keeps its own manifest and never edits the full one.
    previous_path = args.results / ("run-subset-manifest.json" if subset else "run-manifest.json")
    previous: dict[str, Any] = {"runs": []}
    if previous_path.exists():
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
    names = {a.name for a in adapters}
    conflict = provenance_conflict(previous, provenance, names)
    if conflict:
        parser.error(f"{previous_path.name} {conflict}")
    only_sha = hashlib.sha256(args.only_cases.read_bytes()).hexdigest() if args.only_cases else None

    tool_root = args.tool_root.resolve()
    env = ToolEnv(root=tool_root, python=str(tool_root / "venvs" / "shadowscan" / "bin" / "python"))
    args.results.mkdir(parents=True, exist_ok=True)
    args.raw.mkdir(parents=True, exist_ok=True)
    args.scratch.mkdir(parents=True, exist_ok=True)
    args.scratch.chmod(0o777)
    set_run_as(NOBODY)

    summaries: list[dict[str, Any]] = []
    for adapter in adapters:
        summary = run_tool(
            adapter, cases, env, args.results, args.raw, args.scratch, args.checkout_root, args.workers
        )
        summary["only_cases_sha256"] = only_sha  # each tool may run its own case list
        summaries.append(summary)
        print(json.dumps(summary), flush=True)

    self_result = None
    if args.self_check:
        self_result = self_check(ROOT, env, args.scratch, args.raw)
        (args.results / "self-check.json").write_text(
            json.dumps(self_result, indent=2) + "\n", encoding="utf-8"
        )

    manifest = {
        **provenance,
        "manifest": args.manifest.name,
        "protocol": args.protocol.name if args.protocol else None,
        "only_cases": args.only_cases.name if args.only_cases else None,
        "workers": args.workers,
        "repos": len(repos),
        "cases": len(cases),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "finished_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "runs": [r for r in previous.get("runs", []) if r["tool"] not in names] + summaries,
        "self_check": self_result,
        "subset": subset,
        "shadowscan_commit": checkout_head(ROOT),
    }
    previous_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
