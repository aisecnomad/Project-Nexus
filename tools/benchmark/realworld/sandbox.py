"""Run a tool on one repository snapshot inside a throw-away sandbox.

Every real-world repository is untrusted data and some tools under test launch
subprocesses or contact services, so a run gets:

* its own copy of the snapshot, owned by an unprivileged user (the pristine
  corpus is never exposed to the tool),
* fresh network, PID, mount, IPC and UTS namespaces (no network at all: not even
  the proxy, so nothing can be uploaded and no remote MCP server or LLM is reached),
* a minimal root file system (``pivot_root`` into a tmpfs that holds read-only ``/usr``, a few ``/etc``
  entries, the tool root and the interpreter directory, plus this session's own directory), so a tool
  that follows a symlink or runs project code sees no host home directory, no corpus, no labels and no
  other session,
* a dropped uid/gid, an empty capability bounding set and ``no_new_privs``,
* an empty ``HOME`` and a minimal environment (no proxy variables, no credentials),
* memory and process-count cgroup caps, CPU and file-size rlimits, and a wall-clock
  kill that also ends every descendant (the PID namespace dies with its init).

It needs root (``unshare`` and cgroups) and a user named ``rwb`` (``useradd -r -M rwb``).
"""

from __future__ import annotations

import os
import pwd
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO

SANDBOX_USER = "rwb"
DEFAULT_TIMEOUT_S = 600
MEMORY_BYTES = 4 * 1024**3
MAX_PIDS = 512
MAX_STREAM_BYTES = 8_000_000
CGROUP_ROOT = Path("/sys/fs/cgroup")
BASE_PATH = "/usr/local/bin:/usr/bin:/bin"
JAIL_ETC = (
    "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "passwd", "group", "nsswitch.conf", "alternatives",
    "ssl/certs", "ssl/openssl.cnf", "ca-certificates", "localtime", "hosts", "os-release", "mime.types",
)  # fmt: skip
JAIL_RO_DIRS = ("/usr", "/opt/node22")
JAIL_DEVICES = ("null", "zero", "full", "random", "urandom", "tty")


class SandboxUnavailableError(RuntimeError):
    """Raised when the host cannot provide the isolation this benchmark requires."""


@dataclass
class RunResult:
    code: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool


def sandbox_ids() -> tuple[int, int]:
    try:
        entry = pwd.getpwnam(SANDBOX_USER)
    except KeyError as exc:
        raise SandboxUnavailableError(f"create the sandbox user first: useradd -r -M {SANDBOX_USER}") from exc
    return entry.pw_uid, entry.pw_gid


def _decode(data: bytes | None) -> str:
    return (data or b"")[:MAX_STREAM_BYTES].decode("utf-8", errors="replace")


def _drain(stream: IO[bytes], sink: list[bytes]) -> None:
    """Read a pipe to the end, keeping the first ``MAX_STREAM_BYTES`` so a noisy tool cannot fill memory."""
    kept = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        if kept < MAX_STREAM_BYTES:
            piece = chunk[: MAX_STREAM_BYTES - kept]
            sink.append(piece)
            kept += len(piece)


class Session:
    """One sandboxed working area; ``run`` may be called several times (for multi-step tools)."""

    def __init__(
        self, scratch: Path, tree: Path | None, timeout: int, memory_bytes: int, expose: tuple[Path, ...] = ()
    ) -> None:
        if os.geteuid() != 0:
            raise SandboxUnavailableError("the sandbox needs root for namespaces and cgroups")
        self.uid, self.gid = sandbox_ids()
        self.timeout = timeout
        self.expose = expose
        self.root = Path(tempfile.mkdtemp(prefix="run-", dir=scratch))
        self.name = f"rwb-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.jail = scratch / f"jail-{self.name}"
        self._cgroups = [CGROUP_ROOT / "memory" / self.name, CGROUP_ROOT / "pids" / self.name]
        self.home, self.tmp, self.out, self.work = (self.root / n for n in ("home", "tmp", "out", "work"))
        self.tree = self.root / "tree"
        try:
            for directory in (self.home, self.tmp, self.out, self.work, self.tree, self.jail):
                directory.mkdir()
            if tree is not None:
                subprocess.run(["cp", "-a", f"{tree}/.", str(self.tree)], check=True)
            subprocess.run(["chown", "-R", f"{self.uid}:{self.gid}", str(self.root)], check=True)
            self.root.chmod(0o755)
            limits = {
                self._cgroups[0] / "memory.limit_in_bytes": str(memory_bytes),
                self._cgroups[1] / "pids.max": str(MAX_PIDS),
            }
            for cg in self._cgroups:
                try:
                    cg.mkdir()
                except OSError as exc:
                    raise SandboxUnavailableError(f"cannot create cgroup {cg}: {exc}") from exc
            for path, value in limits.items():
                path.write_text(value)
        except BaseException:
            self.close()
            raise

    def environment(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        env = {
            "HOME": str(self.home), "TMPDIR": str(self.tmp), "PATH": BASE_PATH, "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1", "CI": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1", "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"), "XDG_DATA_HOME": str(self.home / ".local/share"),
        }  # fmt: skip
        env.update(extra or {})
        return env

    def jail_script(self) -> str:
        """Root shell inside the new mount namespace: build the minimal root and ``pivot_root`` into it."""
        q = shlex.quote
        read_only = " ".join(q(str(d)) for d in (*JAIL_RO_DIRS, *self.expose))
        etc = " ".join(JAIL_ETC)
        devices = " ".join(JAIL_DEVICES)
        lines = [
            f"NR={q(str(self.jail))}",
            f"SESS={q(str(self.root))}",
            "mount --make-rprivate /",
            'mount -t tmpfs -o mode=0755,size=64m tmpfs "$NR"',
            'bindro() { if [ -d "$1" ]; then mkdir -p "$2"; else mkdir -p "$(dirname "$2")"; : > "$2"; fi;'
            ' mount --rbind "$1" "$2" && { mount -o remount,ro,bind "$2" 2>/dev/null || true; }; }',
            'mkdir -p "$NR/etc" "$NR/dev" "$NR/proc" "$NR/tmp"',
            f'for d in {read_only}; do bindro "$d" "$NR$d"; done',
            'for l in bin lib lib64 sbin; do if [ -e "/usr/$l" ]; then ln -s "usr/$l" "$NR/$l"; fi; done',
            f'for f in {etc}; do if [ -e "/etc/$f" ]; then bindro "/etc/$f" "$NR/etc/$f"; fi; done',
            f'for d in {devices}; do : > "$NR/dev/$d"; mount --bind "/dev/$d" "$NR/dev/$d"; done',
            'mkdir -p "$NR/dev/shm"',
            'mount -t tmpfs -o size=256m tmpfs "$NR/dev/shm"',
            'ln -s /proc/self/fd "$NR/dev/fd"',
            'mount -t tmpfs -o mode=1777,size=1g tmpfs "$NR/tmp"',
            'mount -t proc proc "$NR/proc"',
            'mkdir -p "$NR$SESS"',
            'mount --bind "$SESS" "$NR$SESS"',
            'cd "$NR"',
            "mkdir .oldroot",
            "pivot_root . .oldroot",
            "cd /",
            "umount -l /.oldroot",
            "rmdir /.oldroot",
        ]
        return "; ".join(lines)

    def run(
        self, argv: Sequence[str], *, env: Mapping[str, str] | None = None, timeout: int | None = None
    ) -> RunResult:
        limit = timeout or self.timeout
        inner = shlex.join(
            [
                "setpriv",
                f"--reuid={self.uid}",
                f"--regid={self.gid}",
                "--clear-groups",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--",
                "prlimit",
                f"--cpu={limit * 4}",
                "--nofile=8192",
                "--fsize=1073741824",
                "--",
                "timeout",
                "-k",
                "5",
                str(limit),
                "env",
                "-i",
                *[f"{k}={v}" for k, v in self.environment(env).items()],
                *argv,
            ]  # fmt: skip
        )
        joins = "; ".join(f"echo $$ > {shlex.quote(str(cg / 'cgroup.procs'))}" for cg in self._cgroups)
        script = f"set -e; {joins}; ip link set lo up 2>/dev/null || true; {self.jail_script()}; exec {inner}"
        cmd = ["unshare", "--net", "--pid", "--fork", "--mount-proc", "--mount", "--ipc", "--uts", "--",
               "sh", "-c", script]  # fmt: skip
        started = time.monotonic()
        proc = subprocess.Popen(
            cmd, cwd=self.work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )  # fmt: skip
        assert proc.stdout is not None and proc.stderr is not None
        out_parts: list[bytes] = []
        err_parts: list[bytes] = []
        readers = [
            threading.Thread(target=_drain, args=(proc.stdout, out_parts), daemon=True),
            threading.Thread(target=_drain, args=(proc.stderr, err_parts), daemon=True),
        ]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            proc.wait(timeout=limit + 30)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        for reader in readers:
            reader.join(timeout=30)
        code = proc.returncode
        return RunResult(
            124 if timed_out else code, _decode(b"".join(out_parts)), _decode(b"".join(err_parts)),
            time.monotonic() - started, timed_out or code == 124,
        )  # fmt: skip

    def contained(self, path: Path) -> str | None:
        """The absolute path when it is inside this session and no component is a symlink, else None.

        The tool runs as another user and can plant symlinks (even a symlinked directory) to make
        the privileged benchmark process read a host file, so every read of a tool-written file
        goes through this check.
        """
        absolute = os.path.abspath(path)
        if os.path.realpath(absolute) != absolute:
            return None
        return absolute if absolute.startswith(os.path.realpath(self.root) + os.sep) else None

    def read(self, path: Path, limit: int = 30_000_000) -> str | None:
        """Read a regular file produced by the tool (None when absent, unsafe or too large)."""
        safe = self.contained(path)
        if safe is None:
            return None
        try:
            if not stat.S_ISREG(os.stat(safe).st_mode) or os.stat(safe).st_size > limit:
                return None
            with open(safe, "rb") as fh:
                return fh.read().decode("utf-8", errors="replace")
        except OSError:
            return None

    def close(self) -> None:
        for cg in self._cgroups:
            procs = cg / "cgroup.procs"
            for _ in range(3):
                try:
                    pids = [int(p) for p in procs.read_text().split()]
                except OSError:
                    break
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                if not pids:
                    break
                time.sleep(0.2)
            try:
                cg.rmdir()
            except OSError:
                pass
        shutil.rmtree(self.root, ignore_errors=True)
        try:
            self.jail.rmdir()
        except OSError:
            pass

    def __enter__(self) -> Session:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()


class Sandbox:
    """Factory for sessions. ``expose`` lists extra directories (the tool root) that tools may read."""

    def __init__(
        self,
        scratch: Path,
        timeout: int = DEFAULT_TIMEOUT_S,
        memory_bytes: int = MEMORY_BYTES,
        expose: tuple[Path, ...] = (),
    ) -> None:
        self.scratch = scratch
        self.timeout = timeout
        self.memory_bytes = memory_bytes
        self.expose = tuple(Path(p).resolve() for p in expose)
        scratch.mkdir(parents=True, exist_ok=True)

    def session(self, tree: Path | None = None) -> Session:
        return Session(self.scratch, tree, self.timeout, self.memory_bytes, self.expose)

    def selftest(self) -> list[str]:
        """Problems with the isolation, empty when the sandbox hides the host as documented."""
        problems: list[str] = []
        probe = (
            "import os,sys\n"
            "bad=[]\n"
            "for p in ('/home','/root','/mnt','/nix','/var','/srv','/etc/shadow','/proc/1/environ-nope'):\n"
            "    if os.path.exists(p) and p not in ('/proc/1/environ-nope',): bad.append(p)\n"
            "scratch=sys.argv[1]\n"
            "siblings=[n for n in os.listdir(scratch)] if os.path.isdir(scratch) else []\n"
            "print('BAD', ','.join(bad)); print('SIBLINGS', len(siblings)); print('UID', os.getuid())\n"
            "try:\n"
            "    open('/etc/ssl/private/x')\n"
            "except OSError: pass\n"
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 80), timeout=2); print('NET yes')\n"
            "except OSError: print('NET no')\n"
        )
        with self.session(None) as s:
            res = s.run(["python3", "-I", "-c", probe, str(self.scratch)], timeout=60)
            lines = dict(line.split(" ", 1) for line in res.stdout.splitlines() if " " in line)
            if res.code != 0:
                problems.append(f"probe failed with exit {res.code}")
            if lines.get("BAD", "").strip():
                problems.append(f"host paths visible: {lines['BAD']}")
            if int(lines.get("SIBLINGS", "99")) > 1:
                problems.append("other sessions visible")
            if lines.get("UID", "").strip() == "0":
                problems.append("running as root")
            if lines.get("NET", "").strip() != "no":
                problems.append("network reachable")
        return problems
