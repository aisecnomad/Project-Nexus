"""Runtime processes: AI agents, MCP servers and model servers seen running.

``runtime.processes`` reads process inventories and reports, per host and
user, the AI tools that were running: coding-agent CLIs, AI desktop apps, MCP
servers launched by a client, local model servers and agent frameworks'
development servers. A running process is the strongest local evidence that a
configured tool is in use; the engine links these findings to the
``endpoint.inventory`` findings for the same tool on the same device (see
``shadowscan.correlation``).

Offline, ``input`` reads osquery ``processes`` results (an array of rows or
logger lines with ``columns`` and ``hostIdentifier``), Microsoft Defender
``DeviceProcessEvents``, CrowdStrike process events, or any JSON/CSV with a
command line or executable name. Live, the connector reads ``/proc`` on Linux
without following the ``exe`` link.

Command lines can carry credentials (``--api-key sk-...``), so a command line
never enters a finding or a ``--dump-records`` export: only the matched tool,
the executable's base name and, for an MCP server, its package name are kept.
"""

from __future__ import annotations

import os
import platform
import re
import socket
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _NoDump,
    _positive_limit,
)
from shadowscan.connectors.common import finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.text import parse_timestamp


@dataclass(frozen=True, slots=True)
class ProcessRule:
    tool: str  # stable id used in resources
    product: str
    signature: str | None
    role: str  # agent | app | mcp-server | model-server | framework


# Executable base names (lower case, without ``.exe``) that are the tool itself.
EXECUTABLES: dict[str, ProcessRule] = {
    "claude": ProcessRule("claude-code", "Claude Code", "coding-agent.claude-code", "agent"),
    "codex": ProcessRule("codex", "OpenAI Codex CLI", "coding-agent.openai-codex", "agent"),
    "gemini": ProcessRule("gemini-cli", "Gemini CLI", "coding-agent.gemini-cli", "agent"),
    "aider": ProcessRule("aider", "Aider", "coding-agent.aider", "agent"),
    "goose": ProcessRule("goose", "Goose", "coding-agent.goose", "agent"),
    "goosed": ProcessRule("goose", "Goose", "coding-agent.goose", "agent"),
    "openclaw": ProcessRule("openclaw", "OpenClaw", "coding-agent.openclaw", "agent"),
    "opencode": ProcessRule("opencode", "OpenCode", None, "agent"),
    "cursor-agent": ProcessRule("cursor-agent", "Cursor CLI", "coding-agent.cursor", "agent"),
    "kiro-cli": ProcessRule("kiro-cli", "Kiro CLI", None, "agent"),
    "ollama": ProcessRule("ollama", "Ollama", None, "model-server"),
    "llama-server": ProcessRule("llama-cpp", "llama.cpp server", None, "model-server"),
    "lms": ProcessRule("lm-studio", "LM Studio", None, "model-server"),
    "github-mcp-server": ProcessRule(
        "mcp:github-mcp-server", "GitHub MCP server", "protocol.mcp", "mcp-server"
    ),
}
# Desktop applications, by executable base name and a path fragment that identifies the vendor's bundle.
DESKTOP_APPS: tuple[tuple[str, str, ProcessRule], ...] = (
    ("claude", "claude.app/", ProcessRule("claude-desktop", "Claude Desktop", None, "app")),
    ("claude", "anthropicclaude", ProcessRule("claude-desktop", "Claude Desktop", None, "app")),
    ("chatgpt", "chatgpt.app/", ProcessRule("chatgpt-desktop", "ChatGPT desktop", None, "app")),
    ("chatgpt", "openai.chatgpt", ProcessRule("chatgpt-desktop", "ChatGPT desktop", None, "app")),
    ("cursor", "cursor", ProcessRule("cursor", "Cursor", "coding-agent.cursor", "app")),
    ("windsurf", "windsurf", ProcessRule("windsurf", "Windsurf", "coding-agent.windsurf", "app")),
    ("lm studio", "lm studio", ProcessRule("lm-studio", "LM Studio", None, "model-server")),
    ("ollama", "ollama.app/", ProcessRule("ollama", "Ollama", None, "model-server")),
)
# Packages run through node, npx, uvx, pipx or python -m.
PACKAGES: tuple[tuple[re.Pattern[str], ProcessRule], ...] = (
    (re.compile(r"@anthropic-ai/claude-code(?:@|/|$)"), EXECUTABLES["claude"]),
    (re.compile(r"@openai/codex(?:@|/|$)"), EXECUTABLES["codex"]),
    (re.compile(r"@google/gemini-cli(?:@|/|$)"), EXECUTABLES["gemini"]),
    (re.compile(r"(?:^|/)openclaw(?:@|/|$)"), EXECUTABLES["openclaw"]),
    (re.compile(r"^aider(?:\.main)?$|(?:^|/)aider-chat(?:@|$)"), EXECUTABLES["aider"]),
    (
        re.compile(r"^vllm(?:\.entrypoints\.[\w.]+)?$"),
        ProcessRule("vllm", "vLLM", "provider.vllm", "model-server"),
    ),
    (re.compile(r"^open[-_]webui$"), ProcessRule("open-webui", "Open WebUI", None, "app")),
    (
        re.compile(r"^litellm(?:\.proxy[\w.]*)?$"),
        ProcessRule("litellm", "LiteLLM proxy", "platform.litellm", "app"),
    ),
    (re.compile(r"^crewai$"), ProcessRule("crewai", "CrewAI", "framework.crewai", "framework")),
    (
        re.compile(r"^langgraph(?:[-_]cli)?$"),
        ProcessRule("langgraph", "LangGraph server", "framework.langgraph", "framework"),
    ),
)
_MCP_PACKAGE = re.compile(
    r"^(?:@modelcontextprotocol/server-[\w.-]+|@[\w.-]+/[\w.-]*mcp[\w.-]*|[\w.-]*mcp[-_]server[\w.-]*|"
    r"mcp[-_][\w.-]+|[\w.-]+[-_]mcp)(?:@[\w.^~<>=-]+)?$",
    re.IGNORECASE,
)
_LAUNCHERS = {
    "node", "nodejs", "npx", "npm", "bunx", "bun", "deno", "uvx", "uv", "pipx", "python", "python3",
    "pnpm", "yarn",
}  # fmt: skip
# A package manager subcommand that installs or inspects rather than runs: nothing after it is running.
_NOT_RUNNING = {
    "install", "i", "ci", "add", "remove", "rm", "uninstall", "update", "upgrade", "list", "ls", "init",
    "publish", "pip", "sync", "lock", "build", "audit", "outdated", "info", "view", "show",
}  # fmt: skip
_PYTHON = re.compile(r"^python(?:\d+(?:\.\d+)?)?w?$")
_SKIP_ARGS = {"-y", "--yes", "-q", "--quiet", "x", "dlx", "exec", "run", "tool", "--", "-u", "-b", "-e"}

# Field names of process exports, in order of preference.
_HOST_FIELDS = (
    "host",
    "hostname",
    "host_name",
    "computer_name",
    "ComputerName",
    "DeviceName",
    "device",
    "aid",
)
_USER_FIELDS = ("user", "username", "user_name", "UserName", "AccountName", "InitiatingProcessAccountName")
_CMD_FIELDS = ("cmdline", "command_line", "CommandLine", "ProcessCommandLine", "command", "args")
_EXE_FIELDS = ("path", "exe", "executable", "image", "ImageFileName", "FolderPath", "process_path")
_NAME_FIELDS = ("name", "process_name", "FileName", "comm")
_TIME_FIELDS = ("start_time", "Timestamp", "timestamp", "ts", "time", "ProcessCreationTime", "@timestamp")
_PID_FIELDS = ("pid", "ProcessId", "process_id", "TargetProcessId")
_PROC = Path("/proc")
_MAX_CMDLINE_BYTES = 64 * 1024


def classify(executable: str | None, argv: list[str]) -> tuple[ProcessRule, str | None] | None:
    """The AI tool a process runs, and an MCP package name when it is an MCP server."""
    exe = (executable or (argv[0] if argv else "") or "").replace("\\", "/")
    base = exe.rsplit("/", 1)[-1].lower()
    base = base[:-4] if base.endswith(".exe") else base
    lowered = exe.lower()
    for name, fragment, rule in DESKTOP_APPS:
        if base == name and fragment in lowered:
            return rule, None
    if base in EXECUTABLES:
        rule = EXECUTABLES[base]
        if base == "ollama" and not any(a in {"serve", "run", "runner"} for a in argv[1:3]):
            return None  # `ollama list` and `ollama pull` do not run a model
        return rule, None
    if base not in _LAUNCHERS and not _PYTHON.match(base):
        return None
    for package in _packages(base, argv[1:]):
        for pattern, rule in PACKAGES:
            if pattern.search(package):
                return rule, None
        if _MCP_PACKAGE.match(package):
            name = (
                package.rsplit("@", 1)[0]
                if package.count("@") > (1 if package.startswith("@") else 0)
                else package
            )
            return ProcessRule(f"mcp:{name.lower()}", "MCP server", "protocol.mcp", "mcp-server"), name
    return None


def _packages(launcher: str, args: list[str]) -> Iterator[str]:
    """Candidate package or module names in a launcher's arguments (the first few positional ones)."""
    seen = 0
    i = 0
    while i < len(args) and seen < 3:
        arg = args[i]
        i += 1
        if arg in {"-m", "--from", "-p", "--package"} and i < len(args):
            yield args[i]
            seen += 1
            i += 1
            continue
        if arg.startswith("-") or arg in _SKIP_ARGS:
            continue
        if arg in _NOT_RUNNING:
            return
        seen += 1
        name = arg.replace("\\", "/")
        if "/node_modules/" in name:
            # node /usr/lib/node_modules/@scope/pkg/dist/cli.js -> @scope/pkg
            tail = name.split("/node_modules/")[-1].split("/")
            name = "/".join(tail[:2]) if tail and tail[0].startswith("@") else tail[0]
        elif _PYTHON.match(launcher) and name.endswith(".py"):
            continue
        yield name


@dataclass
class _Run:
    host: str
    user: str
    rule: ProcessRule
    processes: int = 0
    pids: list[int] = field(default_factory=list)
    executables: Counter = field(default_factory=Counter)
    packages: Counter = field(default_factory=Counter)
    first: str | None = None
    last: str | None = None


class RuntimeProcessConnector(BaseConnector, _NoDump):
    # Command lines can carry credentials: records are never exported with --dump-records.

    name: ClassVar[str] = "runtime.processes"
    surface: ClassVar[Surface] = Surface.RUNTIME
    provider: ClassVar[str | None] = "runtime"
    description: ClassVar[str] = (
        "AI agents, desktop apps, MCP servers and model servers running on hosts, from process inventories "
        "(osquery, EDR exports) or the local /proc."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "label": "host name used when records carry none (default: the host name)",
        "max_processes": "maximum processes read from /proc in live mode (default 100,000)",
        "input": (
            "offline: osquery processes results, Defender DeviceProcessEvents, CrowdStrike process events or "
            "JSON/CSV with a command line or executable"
        ),
    }
    offline_formats: ClassVar[str] = "JSON / JSONL / CSV process inventories (osquery, Defender, CrowdStrike)"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.label = str(ctx.get("label") or socket.gethostname() or "host")
        self.max_processes = _positive_limit(ctx.get("max_processes", 100_000), "max_processes")

    # ------------------------------------------------------------------ live
    def collect(self) -> Iterable[dict[str, Any]]:
        proc = _PROC
        if platform.system() != "Linux" or not proc.is_dir():
            raise ConnectorError(
                "runtime.processes: live mode reads /proc on Linux; elsewhere export osquery processes and "
                "set 'input'"
            )
        restricted = _restricted_view(proc)
        if restricted:
            # Processes this view cannot list are invisible, not merely unreadable.
            self.ctx.warn(f"runtime.processes: not every process is visible: {restricted}")
        seen = 0
        unreadable = 0
        users: dict[int, str] = {}
        for entry in os.scandir(proc):
            if not entry.name.isdigit():
                continue
            if seen >= self.max_processes:
                self.ctx.warn(
                    f"runtime.processes: stopped after max_processes ({self.max_processes:,}) processes"
                )
                break
            seen += 1
            try:
                fd = os.open(proc / entry.name / "cmdline", os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    raw = os.read(fd, _MAX_CMDLINE_BYTES)
                finally:
                    os.close(fd)
                uid = os.stat(proc / entry.name, follow_symlinks=False).st_uid
            except FileNotFoundError:
                continue  # exited while listing
            except OSError:
                unreadable += 1
                continue
            argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
            if not argv or classify(None, argv) is None:
                continue
            if uid not in users:
                users[uid] = _user_name(uid)
            yield {"host": self.label, "user": users[uid], "pid": int(entry.name), "argv": argv}
        if unreadable:
            self.ctx.warn(f"runtime.processes: {unreadable} process(es) could not be read")

    # --------------------------------------------------------------- analyse
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        runs: dict[tuple[str, str, str], _Run] = {}
        for raw in records:
            self.ctx.examined()
            rec = self._normalise(raw)
            if rec is None:
                continue
            match = classify(rec["exe"], rec["argv"])
            if match is None:
                continue
            rule, package = match
            key = (rec["host"], rec["user"], rule.tool)
            run = runs.get(key)
            if run is None:
                run = runs[key] = _Run(rec["host"], rec["user"], rule)
            run.processes += 1
            if isinstance(rec["pid"], int) and len(run.pids) < 10:
                run.pids.append(rec["pid"])
            exe = (
                (rec["exe"] or (rec["argv"][0] if rec["argv"] else "")).replace("\\", "/").rsplit("/", 1)[-1]
            )
            run.executables[exe[:80]] += 1
            if package:
                run.packages[package[:120]] += 1
            when = rec["started"]
            if when:
                run.first = when if run.first is None or when < run.first else run.first
                run.last = when if run.last is None or when > run.last else run.last
        for run in sorted(runs.values(), key=lambda r: (r.host, r.user, r.rule.tool)):
            yield self._finding(run)

    def _normalise(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        nested = raw.get("columns")
        row: dict[str, Any] = nested if isinstance(nested, dict) else raw
        if "argv" in row and isinstance(row["argv"], list):
            argv = [str(a) for a in row["argv"] if isinstance(a, (str, int))]
        else:
            command = _first(row, _CMD_FIELDS)
            argv = _split(command) if isinstance(command, str) else []
        exe = _first(row, _EXE_FIELDS)
        name = _first(row, _NAME_FIELDS)
        if not isinstance(exe, str) or not exe:
            exe = name if isinstance(name, str) and name else None
        elif (
            isinstance(name, str)
            and name
            and not exe.replace("\\", "/").rstrip("/").lower().endswith(name.lower())
        ):
            # Defender FolderPath is a directory; FileName is the executable.
            exe = f"{exe.rstrip('/').rstrip(chr(92))}/{name}"
        if not argv and not exe:
            self.ctx.warn("runtime.processes: record has no command line or executable")
            return None
        host = _first(raw, ("hostIdentifier", "host_identifier")) or _first(row, _HOST_FIELDS) or self.label
        user = _first(row, _USER_FIELDS)
        if user is None and row.get("uid") not in (None, ""):
            user = f"uid-{row['uid']}"
        pid = _first(row, _PID_FIELDS)
        started = parse_timestamp(_first(row, _TIME_FIELDS))
        return {
            "host": str(host)[:120],
            "user": str(user or "unknown")[:120],
            "argv": argv[:64],
            "exe": exe,
            "pid": _pid(pid),
            "started": started.isoformat() if started else None,
        }

    def _finding(self, run: _Run) -> Finding:
        rule = run.rule
        package = run.packages.most_common(1)[0][0] if run.packages else None
        what = f"{rule.product}: {package}" if package else rule.product
        f = Finding(
            surface=Surface.RUNTIME,
            connector=self.name,
            kind=Kind.RUNTIME_PROCESS,
            title=f"{what} running on {run.host} ({run.user})",
            resource=f"runtime:{run.host}:{run.user}:{rule.tool}",
            resource_type=f"process/{rule.role}",
            provider="runtime",
            account=run.host,
            owner=run.user,
            first_seen=run.first,
            last_seen=run.last,
        )
        sig = self.index.get(rule.signature) if rule.signature else None
        if sig is not None:
            if sig.category == "provider":
                f.add_model_provider(sig.id)
            else:
                f.add_framework(sig.id)
            for capability in sig.capabilities:
                f.add_capability(capability)
            if sig.agent_indicator and sig.category != "identity-app":
                f.metadata["agent_indicators"] = 1
        if rule.role == "model-server" and rule.tool in {"ollama", "lm-studio"}:
            provider = "provider.ollama" if rule.tool == "ollama" else "provider.lm-studio"
            if self.index.get(provider) is not None:
                f.add_model_provider(provider)
        f.add_evidence(
            Evidence(
                signal=f"runtime:process:{rule.role}",
                description=(
                    f"{run.processes} running process(es) of {what} ({', '.join(sorted(run.executables))})"
                ),
                location=f"{run.host}",
                weight=0.85,
                signature=rule.signature,
            )
        )
        f.add_tag("observed-running")
        f.metadata.update(
            {
                "tool": rule.tool,
                "product": rule.product,
                "role": rule.role,
                "host": run.host,
                "user": run.user,
                "processes": run.processes,
                "pids": run.pids,
                "executables": dict(run.executables.most_common(5)),
                "mcp_packages": dict(run.packages.most_common(10)),
            }
        )
        return finalize(f, self.index)


def _pid(value: Any) -> int | None:
    """A process id from an export: a non-negative integer below 2**64, as an int or ASCII digits.

    The bound is a width, not a typical pid range: CrowdStrike's TargetProcessId
    is a 64-bit id.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    if isinstance(value, int):
        return value if 0 <= value < 2**64 else None
    return None


# include/linux/proc_ns.h: PROC_PID_INIT_INO, the inode of the initial PID namespace.
_INIT_PID_NS_INO = 0xEFFFFFFC
# hidepid values (older kernels print numbers) that the mount's gid= group is exempt
# from; ptraceable hides every process the account may not trace, from root too.
_HIDEPID_OFF = {"0", "off"}
_HIDEPID_GROUP_EXEMPT = {"1", "2", "noaccess", "invisible"}


def _restricted_view(proc: Path) -> str | None:
    """Why this /proc may not list every process on the host, or None when it lists all of them."""
    # /proc/1 is the init of the PID namespace this procfs belongs to; when it
    # is hidden, this process's own namespace stands in. NSpid cannot answer
    # this: it starts at the procfs's namespace, so a container's own /proc
    # shows a single entry, as the host's does.
    for link in (proc / "1" / "ns" / "pid", proc / "self" / "ns" / "pid"):
        try:
            inode = os.stat(link).st_ino
        except OSError:
            continue
        if inode != _INIT_PID_NS_INO:
            return (
                "/proc belongs to a separate PID namespace (a container); processes outside it are not listed"
            )
        break
    else:
        return "the PID namespace of /proc could not be determined"
    options = _proc_mount_options(proc)
    if options is None:
        return "the mount options of /proc could not be read"
    hidepid = options.get("hidepid", "off")
    if hidepid in _HIDEPID_OFF:
        return None  # subset=pid hides only entries that are not processes
    if hidepid in _HIDEPID_GROUP_EXEMPT and options.get("gid", "0") in _own_groups(proc):
        return None  # the mount's gid= group (root's group 0 by default) sees every process
    return f"/proc is mounted with hidepid={hidepid}, so processes this account may not trace are hidden"


def _proc_mount_options(proc: Path) -> dict[str, str] | None:
    """The superblock options of the procfs mounted on /proc; the last mount there is the visible one."""
    try:
        mounts = (proc / "self" / "mountinfo").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    found: str | None = None
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == "/proc":
            found = fields[-1]
    if found is None:
        return None
    return {name: value for name, _, value in (option.partition("=") for option in found.split(","))}


def _own_groups(proc: Path) -> set[str]:
    """This process's filesystem gid and supplementary groups, when its gids are the host's."""
    try:
        gid_map = (proc / "self" / "gid_map").read_text(encoding="ascii", errors="replace").split()
        status = (proc / "self" / "status").read_text(encoding="ascii", errors="replace")
    except OSError:
        return set()
    if gid_map != ["0", "0", "4294967295"]:
        return set()  # inside a user namespace, a gid need not be the mount's gid
    groups: set[str] = set()
    for line in status.splitlines():
        parts = line.split()
        if parts[:1] == ["Gid:"] and len(parts) > 4:
            groups.add(parts[4])  # the filesystem gid, which the kernel's in_group_p() checks
        elif parts[:1] == ["Groups:"]:
            groups.update(parts[1:])
    return groups


def _user_name(uid: int) -> str:
    try:
        import pwd  # POSIX only; live mode runs on Linux

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return f"uid-{uid}"


def _first(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|(\S+)')


def _split(command: str) -> list[str]:
    """Split a command line into arguments, honouring simple quoting on any platform."""
    out = []
    for match in _TOKEN.finditer(command[: 64 * 1024]):
        out.append(next(group for group in match.groups() if group is not None))
        if len(out) >= 64:
            break
    return out
