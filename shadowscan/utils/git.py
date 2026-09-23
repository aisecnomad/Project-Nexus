"""Hardened git invocation helpers for clone and metadata reads."""

from __future__ import annotations

import os
import re

# Git refname rules we accept from untrusted API JSON. Hierarchical names
# (release/1.2) are allowed; option-like and traversal forms are not.
_REF_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


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
