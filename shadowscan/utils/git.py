"""Hardened git invocation helpers for clone and metadata reads."""

from __future__ import annotations

import os
import re
import subprocess
import time

_OBJECT_ID_RX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

# Git refname rules we accept from untrusted API JSON. Hierarchical names
# (release/1.2) are allowed; option-like and traversal forms are not.
_REF_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


def validate_git_ref(name: str | None) -> str | None:
    """Return *name* if it is a conservative branch/tag, otherwise None."""
    if not isinstance(name, str):
        return None
    value = name
    # The character class already rejects option-like, absolute, escaped and
    # reflog (@{) spellings; only sequence and boundary rules remain.
    if not value or not _REF_RX.fullmatch(value):
        return None
    if value.endswith(("/", ".")) or ".." in value or "//" in value:
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
                [*metadata_git_argv_prefix(), "-C", root, "rev-parse", "--verify", revision],
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
