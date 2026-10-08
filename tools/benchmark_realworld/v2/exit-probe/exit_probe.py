"""Record each v2 configuration's exit codes on one positive and one clean case per surface.

A diagnostic run before the freeze (protocol v2, section 6). Each output line is one case: the
configuration, the surface, the case, its status, every exit code of the case (the baseline call
included) and the last stderr line of its final call. ``PROBE_TOOLS=a,b`` limits the tools.

    PYTHONPATH=<repo> python tools/benchmark_realworld/v2/exit-probe/exit_probe.py > exit-probe.jsonl
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import tools.benchmark.adapters as base
import tools.benchmark_realworld.adapters as realworld
from tools.benchmark.adapters import Run, ToolEnv, set_run_as
from tools.benchmark_realworld.adapters import ADAPTERS_V2
from tools.benchmark_realworld.cases import RealCase, build_cases_v2, validate_manifest
from tools.benchmark_realworld.run import NOBODY, _run_one

ROOT = Path("/home/user")
TOOLS = Path("/opt/rwbench/tools")
CORPUS = Path("tools/benchmark_realworld/corpus_v2.json")
SCRATCH = Path("/opt/rwbench/work")

CURRENT = {"tool": "?"}
CALLS: list[tuple[str, int, str]] = []  # (configuration, exit code, last stderr line) per process call


def _spy(original: Callable[..., Run]) -> Callable[..., Run]:
    def wrapped(cmd: list[str], **kwargs: Any) -> Run:
        code, out, err, secs = original(cmd, **kwargs)
        last = err.strip().splitlines()[-1][:90] if err and err.strip() else ""
        CALLS.append((CURRENT["tool"], code, last))
        return code, out, err, secs

    return wrapped


def _positive_and_clean(cases: list[RealCase], surface: str) -> list[tuple[str, RealCase]]:
    on_surface = [c for c in cases if c.surface == surface]
    pos = next((c for c in on_surface if c.label not in ("none", "n/a")), None)
    neg = next((c for c in on_surface if c.label == "none"), None)
    return [(kind, case) for kind, case in (("pos", pos), ("neg", neg)) if case is not None]


def main() -> int:
    os.umask(0)  # as run.py does: work folders must be writable by the unprivileged tool
    wanted = set(os.environ.get("PROBE_TOOLS", "").split(",")) - {""}
    cases = build_cases_v2(validate_manifest(json.loads(CORPUS.read_text(encoding="utf-8"))), ROOT)
    env = ToolEnv(root=TOOLS, python=str(TOOLS / "venvs" / "shadowscan" / "bin" / "python"))
    set_run_as(NOBODY)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    SCRATCH.chmod(0o777)
    with (
        patch.object(base, "_isolated", _spy(base._isolated)),
        patch.object(realworld, "_isolated", _spy(realworld._isolated)),
    ):
        for adapter in ADAPTERS_V2:
            if wanted and adapter.name not in wanted:
                continue
            CURRENT["tool"] = adapter.name
            for surface in adapter.surfaces:
                for kind, case in _positive_and_clean(cases, surface):
                    CALLS.clear()
                    outcome = _run_one(adapter, case, env, SCRATCH, ROOT)
                    print(
                        json.dumps(
                            {
                                "tool": adapter.name,
                                "surface": surface,
                                "case": case.case_id,
                                "kind": kind,
                                "status": outcome.status,
                                "detected": outcome.detected,
                                "note": outcome.note[:70],
                                "exit_codes": [code for _, code, _ in CALLS],
                                "stderr_tail": [last for _, _, last in CALLS][-1:],
                            }
                        ),
                        flush=True,
                    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
