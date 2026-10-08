"""Run every adapter against every checkout under a scrubbed, unprivileged environment.

Each (tool, repository) pair runs in its own output directory. When ``--as-user``
names an unprivileged account, commands are wrapped in ``setpriv`` so the tool
cannot write outside its output directory and cannot read the operator's
credentials. The environment is rebuilt from scratch: no API keys, a dead
proxy so outbound requests fail fast, telemetry opt-outs, a private HOME and
TMPDIR. Repository content is never executed by the harness itself.
"""

from __future__ import annotations

import json
import os
import platform
import pwd
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.discovery_benchmark.adapters import Adapter, Command, ToolConfig
from tools.discovery_benchmark.corpus import Corpus, Repo

MAX_CAPTURE_BYTES = 5_000_000
DEAD_PROXY = "http://127.0.0.1:9"


@dataclass
class CommandResult:
    argv: list[str]
    exit_code: int | None
    seconds: float
    timed_out: bool
    ok: bool
    stdout_file: str
    stderr_file: str


@dataclass
class RunResult:
    tool: str
    repo: str
    status: str  # ok | failed | timeout | skipped | error
    seconds: float
    facts: list[str] = field(default_factory=list)
    raw_count: int = 0
    commands: list[CommandResult] = field(default_factory=list)
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunPolicy:
    timeout: int = 900
    as_user: str | None = None
    path: str = "/usr/bin:/bin"
    extra_path: tuple[str, ...] = ()
    keep_network: bool = False


def scrubbed_env(policy: RunPolicy, home: Path, tmp: Path, extra: dict[str, str]) -> dict[str, str]:
    env = {
        "PATH": ":".join([*policy.extra_path, policy.path]),
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "TMP": str(tmp),
        "TEMP": str(tmp),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "TERM": "dumb",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "DO_NOT_TRACK": "1",
        "XBOM_DISABLE_TELEMETRY": "true",
        "AI_BOM_TELEMETRY": "false",
        "NODE_NO_WARNINGS": "1",
        "CI": "1",
    }
    if not policy.keep_network:
        env.update(
            {
                "HTTPS_PROXY": DEAD_PROXY,
                "HTTP_PROXY": DEAD_PROXY,
                "https_proxy": DEAD_PROXY,
                "http_proxy": DEAD_PROXY,
            }
        )
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
    env.update(extra)
    return env


def _wrap(policy: RunPolicy, argv: tuple[str, ...], env: dict[str, str]) -> list[str]:
    if not policy.as_user:
        return list(argv)
    user = pwd.getpwnam(policy.as_user)
    return [
        "setpriv",
        f"--reuid={user.pw_uid}",
        f"--regid={user.pw_gid}",
        "--clear-groups",
        "env",
        "-i",
        *[f"{k}={v}" for k, v in env.items()],
        *argv,
    ]


def _chown_tree(path: Path, user: str | None) -> None:
    if not user:
        return
    record = pwd.getpwnam(user)
    for root, dirs, files in os.walk(path):
        os.chown(root, record.pw_uid, record.pw_gid)
        for name in [*dirs, *files]:
            os.lchown(os.path.join(root, name), record.pw_uid, record.pw_gid)


def run_command(
    command: Command,
    *,
    index: int,
    policy: RunPolicy,
    repo_dir: Path,
    out_dir: Path,
    home: Path,
) -> CommandResult:
    tmp = out_dir / "tmp"
    tmp.mkdir(exist_ok=True)
    env = scrubbed_env(policy, home, tmp, command.env)
    argv = _wrap(policy, command.argv, env)
    cwd = repo_dir if command.cwd == "repo" else out_dir
    stdout_path = out_dir / f"{index}.stdout.txt"
    stderr_path = out_dir / f"{index}.stderr.txt"
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env if not policy.as_user else None,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        except OSError as exc:
            err.write(str(exc).encode())
            return CommandResult(
                list(command.argv), None, 0.0, False, False, stdout_path.name, stderr_path.name
            )
        try:
            exit_code = proc.wait(timeout=policy.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, 9)
            except ProcessLookupError:
                pass
            proc.wait()
    seconds = time.monotonic() - started
    for path in (stdout_path, stderr_path):
        if path.stat().st_size > MAX_CAPTURE_BYTES:
            with path.open("r+b") as handle:
                handle.truncate(MAX_CAPTURE_BYTES)
    ok = not timed_out and exit_code in command.ok_exit_codes
    return CommandResult(
        list(command.argv), exit_code, round(seconds, 3), timed_out, ok, stdout_path.name, stderr_path.name
    )


def run_pair(
    adapter: Adapter,
    cfg: ToolConfig,
    repo: Repo,
    repo_dir: Path,
    out_dir: Path,
    policy: RunPolicy,
) -> RunResult:
    tool_id = adapter.spec.id
    reason = adapter.unavailable_reason(cfg)
    if reason:
        return RunResult(tool_id, repo.id, "skipped", 0.0, error=reason)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    home = out_dir / "home"
    home.mkdir()
    (out_dir / "tmp").mkdir()
    commands = adapter.commands(cfg, repo_dir, out_dir)
    _chown_tree(out_dir, policy.as_user)
    results: list[CommandResult] = []
    started = time.monotonic()
    status = "ok"
    for index, command in enumerate(commands):
        result = run_command(
            command, index=index, policy=policy, repo_dir=repo_dir, out_dir=out_dir, home=home
        )
        results.append(result)
        if result.timed_out:
            status = "timeout"
            break
        if not result.ok:
            status = "failed"
    seconds = round(time.monotonic() - started, 3)
    normalized = adapter.normalize(out_dir)
    if normalized.error and status == "ok":
        status = "failed"
    run = RunResult(
        tool=tool_id,
        repo=repo.id,
        status=status,
        seconds=seconds,
        facts=sorted(normalized.facts),
        raw_count=normalized.raw_count,
        commands=results,
        error=normalized.error,
        detail=normalized.detail,
    )
    (out_dir / "result.json").write_text(json.dumps(run.to_dict(), indent=1), encoding="utf-8")
    shutil.rmtree(out_dir / "tmp", ignore_errors=True)
    return run


def run_matrix(
    corpus: Corpus,
    adapters: list[Adapter],
    cfg: ToolConfig,
    checkouts: Path,
    out_root: Path,
    policy: RunPolicy,
    *,
    workers: int = 4,
    repos: set[str] | None = None,
) -> dict[str, Any]:
    """Run every adapter on every repository and write ``runs.json`` under ``out_root``."""
    out_root.mkdir(parents=True, exist_ok=True)
    versions = {a.spec.id: a.version(cfg) for a in adapters if a.unavailable_reason(cfg) is None}
    skipped = {a.spec.id: a.unavailable_reason(cfg) for a in adapters if a.unavailable_reason(cfg)}
    manifest: dict[str, Any] = {
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpus": os.cpu_count(),
        },
        "policy": {**asdict(policy), "extra_path": list(policy.extra_path)},
        "tool_versions": versions,
        "tools_skipped": skipped,
        "workers": workers,
    }
    selected = [r for r in corpus.repos if repos is None or r.id in repos]
    jobs = [(a, r) for r in selected for a in adapters]
    results: list[RunResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_pair, a, cfg, r, checkouts / r.id, out_root / a.spec.id / r.id, policy): (
                a.spec.id,
                r.id,
            )
            for a, r in jobs
        }
        for future in as_completed(futures):
            tool_id, repo_id = futures[future]
            try:
                results.append(future.result())
            except (OSError, ValueError, RuntimeError) as exc:
                results.append(
                    RunResult(tool_id, repo_id, "error", 0.0, error=f"{type(exc).__name__}: {exc}")
                )
    results.sort(key=lambda r: (r.tool, r.repo))
    manifest["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    manifest["results"] = [r.to_dict() for r in results]
    (out_root / "runs.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def renormalize(out_root: Path, adapters: list[Adapter]) -> dict[str, Any]:
    """Re-read stored tool output with the current adapters and rewrite ``runs.json``.

    Lets a mapping fix be applied without re-running the tools; command results,
    timings and statuses are kept from the original run.
    """
    manifest_path = out_root / "runs.json"
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_id = {a.spec.id: a for a in adapters}
    results: list[dict[str, Any]] = []
    for item in manifest.get("results") or []:
        adapter = by_id.get(str(item.get("tool")))
        out_dir = out_root / str(item.get("tool")) / str(item.get("repo"))
        if adapter is None or item.get("status") in {"skipped", "error"} or not out_dir.exists():
            results.append(item)
            continue
        normalized = adapter.normalize(out_dir)
        item["facts"] = sorted(normalized.facts)
        item["raw_count"] = normalized.raw_count
        item["detail"] = normalized.detail
        item["error"] = normalized.error
        if normalized.error and item.get("status") == "ok":
            item["status"] = "failed"
        elif (
            not normalized.error
            and item.get("status") == "failed"
            and all(c.get("ok") for c in item.get("commands") or [])
        ):
            item["status"] = "ok"
        (out_dir / "result.json").write_text(json.dumps(item, indent=1), encoding="utf-8")
        results.append(item)
    manifest["results"] = results
    manifest["renormalized"] = datetime.now(UTC).isoformat(timespec="seconds")
    manifest_path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest
