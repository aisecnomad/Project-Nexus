"""Hardened git invocation helpers for clone and metadata reads."""

from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import time
from typing import TYPE_CHECKING, Any

_OBJECT_ID_RX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

if TYPE_CHECKING:
    from shadowscan.connectors.base import ConnectorContext

# Git refname rules we accept from untrusted API JSON. Hierarchical names
# (release/1.2) are allowed; option-like and traversal forms are not.
_REF_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


class CloneTimeoutError(TimeoutError):
    """The per-repository clone budget expired."""


def clone_limits(max_bytes: Any, timeout: Any) -> tuple[int, float]:
    """Validate clone limits before any network or filesystem work."""
    if isinstance(max_bytes, bool):
        raise ValueError("clone_max_bytes must be a positive integer")
    try:
        max_value = int(max_bytes)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("clone_max_bytes must be a positive integer") from exc
    if max_value < 1 or isinstance(max_bytes, float) and not max_bytes.is_integer():
        raise ValueError("clone_max_bytes must be a positive integer")
    if isinstance(timeout, bool):
        raise ValueError("clone_timeout_seconds must be positive and finite")
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("clone_timeout_seconds must be positive and finite") from exc
    if not math.isfinite(timeout_value) or timeout_value <= 0:
        raise ValueError("clone_timeout_seconds must be positive and finite")
    return max_value, timeout_value


def _stop_clone(proc: subprocess.Popen[bytes]) -> None:
    """Stop Git and its HTTPS transport subprocesses before API fallback.

    Git launches ``git-remote-https`` as a child. Killing only the Git parent
    can leave that transport downloading after the scanner has moved on.
    """
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        # Windows Popen.kill covers only Git itself; taskkill also requests
        # termination of its transport children. A containing job object is
        # still required to guarantee termination of a detached descendant.
        if proc.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=3, check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            if proc.poll() is None:
                proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def run_bounded_clone(cmd: list[str], env: dict[str, str], ctx: ConnectorContext, timeout: float) -> bool:
    """Run a clone with a per-repository deadline and cooperative cancellation.

    Output is discarded: an untrusted remote may print unlimited diagnostics,
    and Git can include a credential in an error message. On POSIX the clone
    has a new process group so timeout/cancellation kills transport children.
    """
    ctx.check_deadline()
    deadline = time.monotonic() + timeout
    if ctx.deadline is not None:
        deadline = min(deadline, ctx.deadline)
    if os.name == "posix":
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
    else:
        proc = subprocess.Popen(
            cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
    try:
        while True:
            ctx.check_deadline()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CloneTimeoutError("git clone timeout exceeded")
            try:
                status = proc.wait(timeout=min(remaining, 0.1))
            except subprocess.TimeoutExpired:
                continue
            ctx.check_deadline()
            if status != 0:
                _stop_clone(proc)
            return status == 0
    except BaseException:
        _stop_clone(proc)
        raise


def exceeds_clone_size(size: object, unit: int, max_bytes: int) -> bool:
    """Compare a provider's nonnegative integer size estimate with the cap.

    GitHub reports KB; GitLab's ``statistics.repository_size`` is bytes.
    Unknown or malformed estimates cannot act as a preflight check.
    """
    return isinstance(size, int) and not isinstance(size, bool) and size >= 0 and size * unit > max_bytes


def validate_git_ref(name: str | None) -> str | None:
    """Return *name* if it is a conservative branch/tag, otherwise None."""
    if not isinstance(name, str):
        return None
    value = name
    if not value or not _REF_RX.fullmatch(value):
        return None
    if value.startswith("-") or value.startswith("/") or value.endswith(("/", ".")):
        return None
    if ".." in value or "//" in value or "@{" in value or "\\" in value:
        return None
    if any(part.startswith(".") or part.endswith(".lock") for part in value.split("/")):
        return None
    return value


def safe_git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for git child processes.

    Drops inherited Git variables and ignores system/global gitconfig so
    ``url.*.insteadOf``, credential helpers and smudge filters cannot rewrite
    a clone of untrusted content. Callers may add ``GIT_CONFIG_*`` overlays
    for origin-scoped extraheaders.
    """
    # In particular, GIT_CONFIG_COUNT/KEY_n/VALUE_n must not survive: Git gives
    # them command-scope precedence over the otherwise-disabled config files.
    # Clear the namespace rather than maintain a partial list of overrides.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.pop("SSH_ASKPASS", None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    if extra:
        env.update(extra)
    return env


def git_config_overlay(pairs: list[tuple[str, str]]) -> dict[str, str]:
    """Encode ``-c key=value`` equivalents via ``GIT_CONFIG_COUNT``."""
    env: dict[str, str] = {}
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def clone_environment(origin: str, token: str | None, username: str) -> dict[str, str]:
    """Scope authentication to a verified HTTPS origin and disable redirects."""
    import base64

    config = [
        ("core.hooksPath", os.devnull),
        ("http.followRedirects", "false"),
        ("credential.helper", ""),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
    ]
    extra: dict[str, str] = {}
    if token:
        basic = base64.b64encode(f"{username}:{token}".encode()).decode()
        config.append((f"http.{origin.rstrip('/')}/.extraheader", f"Authorization: Basic {basic}"))
    extra.update(git_config_overlay(config))
    return safe_git_env(extra)


def git_argv_prefix() -> list[str]:
    """Force hooks off even if a repo-local config tries to re-enable them."""
    return ["git", "-c", f"core.hooksPath={os.devnull}"]


def metadata_git_env() -> dict[str, str]:
    """Keep opt-in history inspection offline, including promisor object reads.

    ``protocol.allow=never`` alone is insufficient: a repository can specify a
    more specific ``protocol.<helper>.allow=always``. An empty allow-list takes
    precedence over every such setting. Clone authentication must never be
    passed to this environment.
    """
    return safe_git_env({
        **git_config_overlay([
            ("core.hooksPath", os.devnull),
            ("credential.helper", ""),
            ("core.fsmonitor", "false"),
            ("maintenance.auto", "false"),
            ("gc.auto", "0"),
            ("protocol.allow", "never"),
        ]),
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    })


def metadata_git_argv_prefix() -> list[str]:
    """Require Git 2.45+ lazy-fetch suppression before opening a repository.

    Using the option as well as the environment variable makes older versions
    fail closed rather than silently ignore an unknown environment setting.
    """
    return [*git_argv_prefix(), "--no-lazy-fetch", "--no-pager", "--literal-pathspecs"]


def read_git_snapshot(path: str | os.PathLike[str], *, timeout: float = 10.0) -> dict[str, str] | None:
    """Read the checked-out commit and tree without invoking repo code or network.

    This deliberately uses the conservative metadata environment rather than
    clone credentials or inherited Git configuration. It is used to attach a
    stable source identity to remote-clone scans; failure is reported by the
    caller as incomplete provenance while preserving scan findings.
    """
    if timeout <= 0:
        return None
    root = os.fspath(path)
    if not root or "\x00" in root:
        return None

    env = metadata_git_env()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    deadline = time.monotonic() + min(timeout, 10.0)
    values: list[str] = []
    for revision in ("HEAD^{commit}", "HEAD^{tree}"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            result = subprocess.run(
                [*git_argv_prefix(), "-C", root, "rev-parse", "--verify", revision],
                env=env,
                capture_output=True,
                text=True,
                timeout=remaining,
                check=False,
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        if not _OBJECT_ID_RX.fullmatch(value):
            return None
        values.append(value)
    return {"commit_sha": values[0], "tree_sha": values[1]}
