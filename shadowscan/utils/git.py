"""Hardened git invocation helpers for clone and metadata reads."""

from __future__ import annotations

import contextlib
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from configparser import ConfigParser
from configparser import Error as ConfigError
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from shadowscan.utils.files import open_confined_directory, open_confined_file

_OBJECT_ID_RX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_METADATA_OUTPUT_BYTES = 16 * 1024

if TYPE_CHECKING:
    from types import FrameType

    from shadowscan.connectors.base import ConnectorContext

# Git refname rules we accept from untrusted API JSON. Hierarchical names
# (release/1.2) are allowed; option-like and traversal forms are not.
_REF_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
MAX_GITMODULES_BYTES = 1024 * 1024
_MAX_GITLINK_OUTPUT_BYTES = 8 * 1024 * 1024
# ConfigParser reads an option line with ``(.*?)\s*=``, which rescans a run of
# blanks before the delimiter from each of its positions: quadratic in the run,
# in C and holding the GIL, so neither the connector deadline nor the job
# deadline can interrupt it (one 1 MiB line took over an hour). Declarations
# never need a long run of blanks; a file with one is refused before parsing.
# With runs this short the parser stays linear in the size of the file.
_MAX_GITMODULES_BLANK_RUN = 32
_GITMODULES_BLANK_RUN = re.compile(rf"[^\S\n]{{{_MAX_GITMODULES_BLANK_RUN + 1},}}")
_MAX_GIT_METADATA_DEPTH = 64
_MAX_GIT_CONFIG_BYTES = 1024 * 1024
_GIT_CONFIG_FILES = frozenset({"config", "config.worktree"})
_GIT_METADATA_INDIRECTIONS = frozenset(
    {"commondir", "objects/info/alternates", "objects/info/http-alternates"}
)


def _submodule_path(value: str) -> str:
    """Accept a relative checkout path, never a filesystem escape or Git option."""
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or "\\" in value
        or ":" in path.parts[0]
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("invalid submodule path")
    return path.as_posix()


def _gitmodule_value(value: str) -> str:
    """Decode Git's quoted path values without expanding variables or includes."""
    out: list[str] = []
    quoted = False
    escaped = False
    trailing_space = 0
    escapes = {"n": "\n", "t": "\t", "b": "\b", '"': '"', "\\": "\\"}
    for char in value:
        if escaped:
            if char not in escapes:
                raise ValueError("unsupported submodule path escape")
            out.append(escapes[char])
            trailing_space = 0
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char in "#;" and not quoted:
            break
        else:
            out.append(char)
            trailing_space = trailing_space + 1 if char.isspace() and not quoted else 0
    if quoted or escaped:
        raise ValueError("invalid submodule path quoting")
    decoded = "".join(out)
    return _submodule_path(decoded[:-trailing_space] if trailing_space else decoded)


def declared_submodule_paths(text: str) -> list[str]:
    """Read only declarations from bounded .gitmodules text; never execute Git.

    Includes and URLs have no authority here. Unsupported/ambiguous syntax is
    a coverage error, so an unusual declaration cannot silently hide a module.
    A run of more than ``_MAX_GITMODULES_BLANK_RUN`` blanks is such syntax: it
    is refused before the parser, whose time it would square.
    """
    if _GITMODULES_BLANK_RUN.search(text):
        raise ValueError("submodule declarations contain an over-long run of blanks")
    parser = ConfigParser(interpolation=None, delimiters=("=",), empty_lines_in_values=False)
    try:
        parser.read_string(text)
        if parser.defaults():
            raise ValueError("submodule defaults are unsupported")
        paths: list[str] = []
        seen: set[str] = set()
        for section in parser.sections():
            if not re.match(r"submodule(?:\s|\.|$)", section, re.IGNORECASE):
                continue
            if not re.fullmatch(r'submodule\s+"(?:[^"\\]|\\.)*"', section, re.IGNORECASE):
                raise ValueError("invalid submodule section")
            if not parser.has_option(section, "path"):
                raise ValueError("submodule has no path")
            path = _gitmodule_value(parser.get(section, "path"))
            if path in seen:
                raise ValueError("duplicate submodule path")
            if len(paths) >= 10_000:
                raise ValueError("submodule declaration limit exceeded")
            seen.add(path)
            paths.append(path)
        return paths
    except ConfigError:
        raise ValueError("invalid submodule declarations") from None


class CloneTimeoutError(TimeoutError):
    """The per-repository clone budget expired."""


class CloneSizeError(RuntimeError):
    """The checkout exceeds its observed size budget or cannot be measured."""


class MetadataOutputLimitError(ValueError):
    """Combined Git metadata stdout and stderr exceeded the bounded read budget."""


class MetadataTimeoutError(TimeoutError):
    """The metadata subprocess did not finish within its execution budget."""


class CloneInterruptedError(RuntimeError):
    """A termination signal or hard exit stopped the clones; no new clone may start."""


_MAX_CLONE_ENTRIES = 100_000

# Clones and temporary checkouts this process owns right now. A termination
# signal or a hard exit (``os._exit``) skips the ``finally`` blocks that stop
# git and delete the checkout; git would otherwise keep running in its own
# session, unbounded, with the clone credential in its environment. Single
# dict and set operations are atomic under the GIL, so no lock is needed and
# the signal-handler and watchdog paths can never block on one.
_ACTIVE_CLONES: set[subprocess.Popen[bytes]] = set()
_ACTIVE_CHECKOUTS: set[str] = set()
_INTERRUPTED = threading.Event()
_CLEANUP_BUDGET_SECONDS = 3.0
_TERMINATION_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")


def _clone_disk_usage(root: str, max_bytes: int) -> int:
    """Measure the clone's files without following links or reading file data.

    Count both logical file size and allocated blocks where reported. Stop as
    soon as the budget is exceeded, so a large checkout need not be walked in
    full on every poll. Git can rename files during this walk; disappeared
    entries are checked by the next poll and the mandatory post-exit walk.
    """
    total = 0
    entries_seen = 0
    pending = [root]
    while pending:
        path = pending.pop()
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CloneSizeError("cannot inspect clone size") from exc
        if path == root and stat.S_ISLNK(info.st_mode):
            raise CloneSizeError("clone destination is an unexpected symlink")
        total += max(info.st_size, getattr(info, "st_blocks", 0) * 512)
        if total > max_bytes:
            raise CloneSizeError("observed clone size exceeds clone_max_bytes")
        if not stat.S_ISDIR(info.st_mode):
            continue
        try:
            # POSIX permits scandir on an open directory descriptor. Opening
            # with O_NOFOLLOW prevents a changing checkout from redirecting
            # a traversal through a symlink between lstat and scandir.
            if os.name == "posix":
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            entries_seen += 1
                            if entries_seen > _MAX_CLONE_ENTRIES:
                                raise CloneSizeError("clone entry count exceeds measurement safety limit")
                            pending.append(os.path.join(path, entry.name))
                finally:
                    os.close(fd)
            else:
                with os.scandir(path) as entries:
                    for entry in entries:
                        entries_seen += 1
                        if entries_seen > _MAX_CLONE_ENTRIES:
                            raise CloneSizeError("clone entry count exceeds measurement safety limit")
                        pending.append(entry.path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CloneSizeError("cannot inspect clone size") from exc
    return total


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


def _signal_clone_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill Git and its HTTPS transport subprocesses without waiting for them."""
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # Darwin's killpg() reports EPERM for a group that holds an
            # unreaped zombie: the child itself once it exited before the
            # reader stopped, or a helper it spawned while it still runs. The
            # direct child is ours to signal by pid; the wait below settles
            # whether it is gone.
            if proc.poll() is None:
                proc.kill()
    else:
        # Windows Popen.kill covers only Git itself; taskkill also requests
        # termination of its transport children. A containing job object is
        # still required to guarantee termination of a detached descendant.
        if proc.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            if proc.poll() is None:
                proc.kill()


def _stop_clone(proc: subprocess.Popen[bytes]) -> None:
    """Stop Git and its HTTPS transport subprocesses before API fallback.

    Git launches ``git-remote-https`` as a child. Killing only the Git parent
    can leave that transport downloading after the scanner has moved on.
    """
    _signal_clone_group(proc)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def register_checkout(path: str) -> None:
    """Record a temporary checkout so an interrupted process can delete it."""
    _ACTIVE_CHECKOUTS.add(path)


def unregister_checkout(path: str) -> None:
    """Forget a checkout the caller has removed itself."""
    _ACTIVE_CHECKOUTS.discard(path)


def terminate_active_clones(budget: float = _CLEANUP_BUDGET_SECONDS, *, refuse_new: bool = True) -> None:
    """Stop every live clone and delete the recorded checkouts; the process is ending.

    For the termination-signal handler and the job-deadline watchdog, whose
    exits skip the ``finally`` blocks that normally do this. Callable from any
    thread or signal handler; never raises and never waits longer than
    *budget* seconds. Unless *refuse_new* is false, no new clone starts
    afterwards (``CloneInterruptedError``): a worker that outlives the call
    must not spawn the clone that the exit would then orphan.
    """
    if refuse_new:
        _INTERRUPTED.set()
    deadline = time.monotonic() + max(0.0, budget)
    procs = list(_ACTIVE_CLONES)
    checkouts = sorted(_ACTIVE_CHECKOUTS)
    for proc in procs:
        with contextlib.suppress(Exception):
            _signal_clone_group(proc)
    for proc in procs:
        # Reap what we can so git is gone before its checkout is deleted.
        with contextlib.suppress(Exception):
            proc.wait(timeout=max(0.0, min(0.5, deadline - time.monotonic())))
    if not checkouts:
        return

    def remove() -> None:
        for path in checkouts:
            shutil.rmtree(path, ignore_errors=True)

    # A large checkout must not hold a hard exit past its budget.
    remover = threading.Thread(target=remove, name="shadowscan-checkout-cleanup", daemon=True)
    with contextlib.suppress(Exception):
        remover.start()
        remover.join(max(0.0, deadline - time.monotonic()))


class _TerminationHandler:
    """Stop the clones, then let the signal take the effect it would have had."""

    def __init__(self, previous: Any) -> None:
        self.previous = previous

    def __call__(self, signum: int, frame: FrameType | None) -> None:
        terminate_active_clones()
        if callable(self.previous):
            self.previous(signum, frame)
            return
        # Default disposition: end the process by the same signal.
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)


@contextlib.contextmanager
def terminate_clones_on_signal() -> Iterator[None]:
    """Make SIGINT, SIGTERM and SIGHUP stop live clones before they take effect.

    The previous handler runs afterwards and is restored on exit. Python runs
    signal handlers only on the main thread, while connectors run on worker
    threads: a command must enter this on its main thread around the scan.
    Elsewhere, and for a signal that is ignored or handled outside Python,
    it changes nothing.
    """
    installed: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for name in _TERMINATION_SIGNALS:
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                previous = signal.getsignal(signum)
                if (
                    previous is None
                    or previous == signal.SIG_IGN
                    or isinstance(previous, _TerminationHandler)
                ):
                    continue
                signal.signal(signum, _TerminationHandler(previous))
            except (OSError, ValueError):
                continue
            installed[signum] = previous
        if installed:
            # A new guarded run starts clean; a nested guard installs nothing.
            _INTERRUPTED.clear()
    try:
        yield
    finally:
        for signum, previous in installed.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(signum, previous)


def run_bounded_clone(
    cmd: list[str],
    env: dict[str, str],
    ctx: ConnectorContext,
    timeout: float,
    *,
    destination: str | None = None,
    max_bytes: int | None = None,
) -> bool:
    """Run a clone with a per-repository deadline and cooperative cancellation.

    Output is discarded: an untrusted remote may print unlimited diagnostics,
    and Git can include a credential in an error message. On POSIX the clone
    has a new process group so timeout/cancellation kills transport children.
    The destination is sampled while the clone runs and checked once again
    after exit. This bounds accepted checkout size but is not an atomic quota:
    a writer may exceed the cap between samples; use an OS disk quota for a
    strict disk ceiling.
    """
    if (destination is None) != (max_bytes is None):
        raise ValueError("destination and max_bytes must be set together")
    if max_bytes is not None and (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1
    ):
        raise ValueError("max_bytes must be a positive integer")
    ctx.check_deadline()
    deadline = time.monotonic() + timeout
    if ctx.deadline is not None:
        deadline = min(deadline, ctx.deadline)
    with terminate_clones_on_signal():
        # Checked inside the guard: on the main thread a new guarded run starts clean, while a worker
        # thread of an interrupted scan is refused (it cannot install handlers or reset anything).
        if _INTERRUPTED.is_set():
            raise CloneInterruptedError("clone not started: the scan was interrupted")
        if os.name == "posix":
            proc: subprocess.Popen[bytes] = subprocess.Popen(
                cmd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        else:
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        _ACTIVE_CLONES.add(proc)
        try:
            while True:
                ctx.check_deadline()
                if destination is not None and max_bytes is not None:
                    _clone_disk_usage(destination, max_bytes)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CloneTimeoutError("git clone timeout exceeded")
                try:
                    status = proc.wait(timeout=min(remaining, 0.1))
                except subprocess.TimeoutExpired:
                    continue
                ctx.check_deadline()
                if destination is not None and max_bytes is not None:
                    _clone_disk_usage(destination, max_bytes)
                if status != 0:
                    _stop_clone(proc)
                    if _INTERRUPTED.is_set():
                        # Stopped by the termination path: not a failed clone to retry through the API.
                        raise CloneInterruptedError("clone stopped: the scan was interrupted")
                return status == 0
        except BaseException:
            _stop_clone(proc)
            raise
        finally:
            _ACTIVE_CLONES.discard(proc)


def run_bounded_metadata(
    cmd: list[str],
    env: dict[str, str],
    ctx: ConnectorContext,
    *,
    timeout: float = 20.0,
    max_bytes: int = MAX_METADATA_OUTPUT_BYTES,
    strict_utf8: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Read metadata subprocess output within one combined byte/time budget.

    Git commit fields and diagnostics are untrusted and can expand far beyond
    their compressed objects. Read both pipes incrementally, retain only bounded
    stdout, and discard stderr after charging it to the same budget. Nonblocking
    pipes avoid reader threads that could outlive cancellation. Every failed read
    kills and reaps the process group before its descriptors are closed.
    Immutable IDs and tree paths select strict_utf8 so invalid bytes cannot
    silently become a different identifier; human author text remains lenient.
    """
    if os.name != "posix":
        raise ValueError("bounded Git metadata access is unavailable on this platform")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("metadata max_bytes must be a positive integer")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise ValueError("metadata timeout must be positive and finite")
    if timeout <= 0:
        raise ValueError("metadata timeout must be positive and finite")
    ctx.check_deadline()
    deadline = time.monotonic() + timeout
    if ctx.deadline is not None:
        deadline = min(deadline, ctx.deadline)
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    )
    stdout = bytearray()
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            assert proc.stdout is not None and proc.stderr is not None
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, stream is proc.stdout)
            while selector.get_map():
                ctx.check_deadline()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MetadataTimeoutError("git metadata completion deadline exceeded")
                for key, _ in selector.select(timeout=min(remaining, 0.05)):
                    ctx.check_deadline()
                    try:
                        chunk = os.read(key.fd, min(4096, max_bytes - total + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        raise MetadataOutputLimitError("git metadata output limit exceeded")
                    if key.data:
                        stdout.extend(chunk)
        while True:
            ctx.check_deadline()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MetadataTimeoutError("git metadata completion deadline exceeded")
            try:
                status = proc.wait(timeout=min(remaining, 0.05))
                break
            except subprocess.TimeoutExpired:
                continue
        if status != 0:
            _stop_clone(proc)
        return subprocess.CompletedProcess(
            cmd,
            status,
            stdout=stdout.decode("utf-8", errors="strict" if strict_utf8 else "replace"),
            stderr="",
        )
    except BaseException:
        _stop_clone(proc)
        raise
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()


def exceeds_clone_size(size: object, unit: int, max_bytes: int) -> bool:
    """Compare a provider's nonnegative integer size estimate with the cap.

    GitHub reports KB; GitLab's ``statistics.repository_size`` is bytes.
    Unknown or malformed estimates cannot act as a preflight check.
    """
    return isinstance(size, int) and not isinstance(size, bool) and size >= 0 and size * unit > max_bytes


def has_clone_size_estimate(size: object) -> bool:
    """Return whether a provider supplied a usable nonnegative size estimate."""
    return isinstance(size, int) and not isinstance(size, bool) and size >= 0


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
    # Git never needs the report identity key (comparison.IDENTITY_KEY_ENV),
    # so a child process of untrusted content never receives it.
    env.pop("SHADOWSCAN_IDENTITY_KEY", None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    if extra:
        env.update(extra)
    return env


# The clone protections (no redirects, origin-scoped credentials, no hooks, no helpers, no
# system or global configuration) are applied through GIT_CONFIG_COUNT (Git 2.31) and
# GIT_CONFIG_GLOBAL (Git 2.32). An older Git ignores both silently, follows a redirect to
# another host and finishes the scan, so cloning requires at least this version.
MINIMUM_CLONE_GIT = (2, 32)
_GIT_VERSION_RX = re.compile(rb"git version (\d+)\.(\d+)(?:\.(\d+))?")
_git_version_cache: tuple[int, int, int] | None = None


def git_version() -> tuple[int, int, int] | None:
    """The installed Git's version, read once per process; None when it cannot be determined."""
    global _git_version_cache
    if _git_version_cache is None:
        try:
            result = subprocess.run(
                ["git", "--version"],
                env=safe_git_env(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        output = result.stdout if isinstance(result.stdout, bytes) else b""
        match = _GIT_VERSION_RX.match(output) if result.returncode == 0 else None
        if match is None:
            return None  # not cached: a transient failure should not disable cloning for good
        _git_version_cache = (int(match[1]), int(match[2]), int(match[3] or 0))
    return _git_version_cache


def clone_git_supported() -> bool:
    """Whether the installed Git honours every clone protection; an unknown version does not."""
    version = git_version()
    return version is not None and version[:2] >= MINIMUM_CLONE_GIT


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
        # Refuse objects a well-formed repository never contains (a .git or malformed tree entry, a
        # symlinked .gitmodules, ...) instead of unpacking whatever the remote sends.
        ("transfer.fsckObjects", "true"),
        ("fetch.fsckObjects", "true"),
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
    return safe_git_env(
        {
            **git_config_overlay(
                [
                    ("core.hooksPath", os.devnull),
                    ("credential.helper", ""),
                    ("core.fsmonitor", "false"),
                    ("maintenance.auto", "false"),
                    ("gc.auto", "0"),
                    ("protocol.allow", "never"),
                ]
            ),
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )


def metadata_git_argv_prefix() -> list[str]:
    """Require Git 2.45+ lazy-fetch suppression before opening a repository.

    Using the option as well as the environment variable makes older versions
    fail closed rather than silently ignore an unknown environment setting.
    """
    return [*git_argv_prefix(), "--no-lazy-fetch", "--no-pager", "--literal-pathspecs"]


def _git_config_section(line: str) -> str:
    """Read a conservative single-line Git section without interpreting includes."""
    match = re.match(r"\[([A-Za-z0-9][A-Za-z0-9.-]*)", line)
    if match is None:
        raise ValueError("unsupported git metadata configuration syntax")
    section = match[1].split(".", 1)[0].lower()
    if section in {"include", "includeif"}:
        raise ValueError("git metadata configuration includes are unsupported")
    position = match.end()
    while position < len(line) and line[position] in " \t":
        position += 1
    if position < len(line) and line[position] == '"':
        position += 1
        while position < len(line) and line[position] != '"':
            if line[position] == "\\":
                position += 1
                if position >= len(line) or line[position] not in '\\"':
                    raise ValueError("unsupported git metadata configuration syntax")
            position += 1
        if position >= len(line):
            raise ValueError("unsupported git metadata configuration syntax")
        position += 1
        while position < len(line) and line[position] in " \t":
            position += 1
    if position >= len(line) or line[position] != "]":
        raise ValueError("unsupported git metadata configuration syntax")
    tail = line[position + 1 :].lstrip(" \t")
    if tail and tail[0] not in "#;":
        raise ValueError("unsupported git metadata configuration syntax")
    return section


def _require_git_config_without_includes(path: PurePosixPath, *, dir_fd: int, deadline: float) -> None:
    """Inspect only a bounded, confined config using a conservative physical-line grammar.

    Git's include/includeIf directives can read arbitrary paths even with all
    transports disabled. Do not ask Git to parse this file: parsing would
    already follow the directive. Unsupported encodings, continuations and
    multiline values fail closed rather than claiming to implement Git's full
    configuration language. Ordinary sections, quoted subsections, comments,
    boolean keys and single-line key/value settings are accepted.
    """
    with open_confined_file(path, label="git configuration", dir_fd=dir_fd) as (fh, info):
        if info.st_size > _MAX_GIT_CONFIG_BYTES:
            raise ValueError("git metadata configuration size limit exceeded")
        raw = fh.read(_MAX_GIT_CONFIG_BYTES + 1)
    if len(raw) > _MAX_GIT_CONFIG_BYTES:
        raise ValueError("git metadata configuration size limit exceeded")
    if time.monotonic() >= deadline:
        raise ValueError("git metadata inspection deadline exceeded")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("unsupported git metadata configuration encoding") from None
    if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
        raise ValueError("unsupported git metadata configuration syntax")
    for physical in text.split("\n"):
        if time.monotonic() >= deadline:
            raise ValueError("git metadata inspection deadline exceeded")
        line = physical.strip(" \t\r")
        if not line or line[0] in "#;":
            continue
        # Refuse physical-line joins, including ones that would construct a
        # section name. Rejecting them avoids a second, subtly different Git
        # lexer at the trust boundary.
        if line.endswith("\\"):
            raise ValueError("unsupported git metadata configuration syntax")
        if line[0] == "[":
            _git_config_section(line)
            continue
        # Values cannot add an include without a section header. Check only
        # their quote/escape boundaries so a later header is never hidden in
        # a multiline value; leave ordinary key/value semantics to Git.
        quoted = escaped = False
        for char in line:
            if escaped:
                if char not in 'ntb\\"':
                    raise ValueError("unsupported git metadata configuration syntax")
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif char in "#;" and not quoted:
                break
        if quoted or escaped:
            raise ValueError("unsupported git metadata configuration syntax")
    if time.monotonic() >= deadline:
        raise ValueError("git metadata inspection deadline exceeded")


def require_local_git_metadata(path: Path, *, timeout: float = 10.0) -> None:
    """Refuse metadata layouts that can redirect Git beyond this checkout.

    A directory named .git alone is insufficient: common directories, alternate
    object stores, local config includes and internal filesystem links still
    redirect metadata reads. Local configuration must use the conservative
    bounded single-line syntax accepted above.
    Inspect only bounded, regular metadata through confined directory opens.
    Inputs must remain immutable while Git runs; this preflight is not a
    filesystem snapshot or a sandbox for the Git subprocess.
    """
    if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("git metadata inspection deadline exceeded")
    deadline = time.monotonic() + timeout
    marker = path / ".git"
    pending = [PurePosixPath(".")]
    examined = 0
    try:
        while pending:
            if time.monotonic() >= deadline:
                raise ValueError("git metadata inspection deadline exceeded")
            relative = pending.pop()
            anchor = open_confined_directory(marker / relative)
            try:
                directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=anchor)
            finally:
                os.close(anchor)
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        examined += 1
                        if examined > _MAX_CLONE_ENTRIES or time.monotonic() >= deadline:
                            raise ValueError("git metadata inspection limit exceeded")
                        child = relative / entry.name
                        # Git's conventional paths can resolve to differently
                        # cased names on case-insensitive filesystems.
                        metadata_name = child.as_posix().lower()
                        if metadata_name in _GIT_METADATA_INDIRECTIONS:
                            raise ValueError("git metadata indirections are unsupported")
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if len(child.parts) > _MAX_GIT_METADATA_DEPTH:
                                raise ValueError("git metadata nesting limit exceeded")
                            pending.append(child)
                        elif not stat.S_ISREG(info.st_mode):
                            raise ValueError("git metadata links and special files are unsupported")
                        elif metadata_name in _GIT_CONFIG_FILES:
                            _require_git_config_without_includes(
                                PurePosixPath(entry.name), dir_fd=directory, deadline=deadline
                            )
            finally:
                os.close(directory)
    except OSError:
        raise ValueError("git metadata must be a confined local directory") from None


def _gitlink_failure(diagnostics: list[str] | None, reason: str, error: BaseException | None = None) -> None:
    """Retain a controlled failure category without paths, stderr or exception text."""
    if diagnostics is None:
        return
    # The confined metadata preflight translates OS errors to ValueError. Its
    # context still carries the numeric errno, which distinguishes a permission
    # failure from an unavailable descriptor without exposing the private path.
    underlying = error if isinstance(error, OSError) else error.__context__ if error is not None else None
    number = underlying.errno if isinstance(underlying, OSError) else None
    if type(number) is int and 0 < number < 4096:
        reason += f" (errno {number})"
    diagnostics.append(reason)


def read_gitlink_paths(
    path: Path, *, timeout: float = 10.0, diagnostics: list[str] | None = None
) -> list[str] | None:
    """Inventory committed gitlinks only where the caller already permits Git.

    Clone scans call this for their own checkout. Local scans require the
    existing ``use_git`` opt-in; default scans inspect .gitmodules instead.
    No network, fsmonitor, hooks, pager or external gitfile is permitted. The
    output and wall time are bounded before any returned path is trusted.
    None means coverage is unknown, including unsupported Git versions.
    HEAD also anchors incremental cache identity; staged-only modules require
    .gitmodules declarations, just as they do in metadata-free local scans.
    An optional diagnostics list receives one controlled failure category, never
    subprocess stderr, exception text or a path. Unknown coverage still returns
    None; diagnostics must never turn a failed inventory into an empty one.
    """
    if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        _gitlink_failure(diagnostics, "invalid inventory deadline")
        return None
    duration = min(timeout, 10.0)
    deadline = time.monotonic() + duration
    try:
        require_local_git_metadata(path, timeout=duration)
    except ValueError as exc:
        _gitlink_failure(diagnostics, "metadata preflight refused input", exc)
        return None
    env = metadata_git_env()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    from shadowscan.connectors.base import ConnectorContext

    try:
        result = run_bounded_metadata(
            [*metadata_git_argv_prefix(), "-C", str(path), "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
            env=env,
            ctx=ConnectorContext(),
            timeout=deadline - time.monotonic(),
            max_bytes=_MAX_GITLINK_OUTPUT_BYTES,
            strict_utf8=True,
        )
    except MetadataTimeoutError:
        _gitlink_failure(diagnostics, "metadata subprocess deadline exceeded")
        return None
    except MetadataOutputLimitError:
        _gitlink_failure(diagnostics, "metadata subprocess output limit exceeded")
        return None
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        _gitlink_failure(diagnostics, "metadata subprocess could not be read", exc)
        return None
    if result.returncode != 0:
        _gitlink_failure(
            diagnostics, f"metadata subprocess exited unsuccessfully (status {result.returncode})"
        )
        return None
    output = result.stdout.encode("utf-8")
    if output and not output.endswith(b"\0"):
        _gitlink_failure(diagnostics, "metadata output is not NUL-terminated")
        return None
    paths: set[str] = set()
    try:
        for entry in output.split(b"\0")[:-1]:
            fields, name = entry.split(b"\t", 1)
            mode, object_type, object_id = fields.decode("ascii").split(" ")
            if not re.fullmatch(r"[0-7]{6}", mode) or not _OBJECT_ID_RX.fullmatch(object_id):
                _gitlink_failure(diagnostics, "metadata output contains an invalid tree record")
                return None
            if object_type not in {"blob", "commit"}:
                _gitlink_failure(diagnostics, "metadata output contains an invalid object type")
                return None
            if mode == "160000":
                if object_type != "commit":
                    _gitlink_failure(diagnostics, "metadata output contains an invalid gitlink type")
                    return None
                paths.add(_submodule_path(name.decode("utf-8")))
            elif object_type != "blob":
                _gitlink_failure(diagnostics, "metadata output contains an invalid file type")
                return None
        return sorted(paths)
    except (ValueError, UnicodeError):
        _gitlink_failure(diagnostics, "metadata output contains a malformed tree record")
        return None


def read_git_snapshot(path: str | os.PathLike[str], *, timeout: float = 10.0) -> dict[str, str] | None:
    """Read the checked-out commit and tree without invoking repo code or network.

    This deliberately uses the conservative metadata environment rather than
    clone credentials or inherited Git configuration. It is used to attach a
    stable source identity to remote-clone scans; failure is reported by the
    caller as incomplete provenance while preserving scan findings.
    """
    if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        return None
    root = os.fspath(path)
    if not root or "\x00" in root:
        return None

    deadline = time.monotonic() + min(timeout, 10.0)
    try:
        require_local_git_metadata(Path(root), timeout=min(timeout, 10.0))
    except ValueError:
        return None
    env = metadata_git_env()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    from shadowscan.connectors.base import ConnectorContext

    ctx = ConnectorContext()
    values: list[str] = []
    for revision in ("HEAD^{commit}", "HEAD^{tree}"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            result = run_bounded_metadata(
                [*metadata_git_argv_prefix(), "-C", root, "rev-parse", "--verify", revision],
                env=env,
                ctx=ctx,
                timeout=remaining,
                max_bytes=256,
                strict_utf8=True,
            )
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        if not _OBJECT_ID_RX.fullmatch(value):
            return None
        values.append(value)
    return {"commit_sha": values[0], "tree_sha": values[1]}


# ------------------------------------------------------------------ Git LFS pointers
# Git LFS stores a pointer file of under 1 KiB that opens with this line. The clone has no
# smudge filter, so the large object it points to is never fetched and cannot be scanned.
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"
LFS_POINTER_MAX_BYTES = 1024


def checkout_has_lfs_pointers(
    path: str | os.PathLike[str], *, check_deadline: Callable[[], None] | None = None
) -> bool | None:
    """Whether a regular file in the checkout is a Git LFS pointer; None when that cannot be told.

    Only small regular files are opened, and only for their first bytes. Links are never followed and
    the repository metadata directory is not entered. The walk is bounded by the same entry limit as the
    size measurement, so a checkout that was accepted can be walked.
    """
    root = os.fspath(path)
    if not root or "\x00" in root:
        return None
    entries = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as scan:
                for entry in scan:
                    entries += 1
                    if entries > _MAX_CLONE_ENTRIES:
                        return None
                    if check_deadline is not None and entries % 1000 == 0:
                        check_deadline()
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        if directory != root or entry.name != ".git":
                            pending.append(entry.path)
                    elif (
                        stat.S_ISREG(info.st_mode)
                        and len(LFS_POINTER_PREFIX) <= info.st_size <= LFS_POINTER_MAX_BYTES
                        and _opens_with_lfs_pointer(entry.path)
                    ):
                        return True
        except OSError:
            return None
    return False


def _opens_with_lfs_pointer(path: str) -> bool:
    # O_NOFOLLOW and O_NONBLOCK: never traverse a link or wait on a special file.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        return os.read(fd, len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX
    finally:
        os.close(fd)
