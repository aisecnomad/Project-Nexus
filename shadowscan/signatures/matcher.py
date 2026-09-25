"""Fast lookup structures over the loaded signatures."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import threading
import time
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, fields
from itertools import islice
from operator import itemgetter
from typing import Any, NamedTuple

import regex

from shadowscan.signatures.loader import Signal, Signature, load_signatures, normalise_package_name
from shadowscan.utils.redaction import sanitize_text

_SCAN_DEADLINE: ContextVar[float | None] = ContextVar("signature_scan_deadline", default=None)
REGEX_TIMEOUT_SECONDS = 0.1
DEFAULT_SCAN_BUDGET_SECONDS = 2.0
# A briefly busy worker can exhaust several regex wall-clock attempts before
# this thread has used its own 100 ms CPU allowance. Keep retries finite and
# inside the original per-pattern CPU and per-input wall deadlines.
_MAX_CONTENTION_RETRIES = 16


class MatchTimeoutError(RuntimeError):
    """Matching did not finish; callers must mark the input/scan incomplete."""


def _remaining_timeout() -> float:
    deadline = _SCAN_DEADLINE.get()
    remaining = REGEX_TIMEOUT_SECONDS if deadline is None else min(REGEX_TIMEOUT_SECONDS, deadline - time.monotonic())
    if remaining <= 0:
        raise MatchTimeoutError("signature matching exceeded the input execution budget")
    return remaining


def pattern_timeout(default: float = REGEX_TIMEOUT_SECONDS) -> float:
    """Cap external pattern calls by the active per-input execution budget."""
    deadline = _SCAN_DEADLINE.get()
    if deadline is None:
        return default
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise MatchTimeoutError("signature matching exceeded the input execution budget")
    return min(default, remaining)


def _run_regex(operation: Callable[[float], Any], context: str) -> Any:
    """Retry clear scheduler contention within the original execution budget.

    regex can charge CPU used by other threads while a scanner is suspended,
    including between iterator construction and its first next(). Only retry
    when this thread used less than half its original pattern budget. Genuine
    expensive matching, exhausted input deadlines and repeated contention still
    fail closed; retries never receive a fresh cumulative CPU budget.
    """
    budget = _remaining_timeout()
    started = time.thread_time()
    for attempt in range(_MAX_CONTENTION_RETRIES + 1):
        elapsed = time.thread_time() - started
        remaining = min(_remaining_timeout(), budget - elapsed)
        if remaining <= 0:
            raise MatchTimeoutError(f"signature matching timed out ({context}); input scan is incomplete")
        try:
            result = operation(remaining)
            _remaining_timeout()
            if time.thread_time() - started >= budget:
                raise MatchTimeoutError(f"signature matching timed out ({context}); input scan is incomplete")
            return result
        except TimeoutError as exc:
            if attempt == _MAX_CONTENTION_RETRIES or time.thread_time() - started >= budget / 2:
                raise MatchTimeoutError(f"signature matching timed out ({context}); input scan is incomplete") from exc


def _finditer(
    rx: Any, text: str, context: str, limit: int,
    excluded: Callable[[int], bool] | None = None,
) -> list[Any]:
    def collect(timeout: float) -> list[Any]:
        # Tiny patterns dominate this workload. Releasing/reacquiring the GIL
        # for every token under parallel connectors can spend the entire wall
        # deadline waiting for another thread. Engine timeouts remain preemptive
        # with concurrent=False and also bound any period holding the GIL.
        # The regex engine's iterator timeout also charges CPU work performed
        # between next() calls. Consume only the caller's remaining match quota
        # before redaction or other connector threads can process yielded hits.
        # Never materialize the unbounded sequence of matches in a large input.
        matches = rx.finditer(text, timeout=timeout, concurrent=False)
        if excluded is not None:
            matches = (match for match in matches if not excluded(match.start()))
        return list(islice(matches, limit))

    return _run_regex(collect, context)


def _search(rx: Any, text: str, context: str):
    return _run_regex(lambda timeout: rx.search(text, timeout=timeout, concurrent=False), context)


def _plain_search(rx: Any, text: str, context: str, timeout: float) -> Any:
    """Search one short host token with a timeout the caller checked once per token.

    Tokens are at most 253 characters and the domain patterns are anchored, so
    the engine's own preemption is the only bookkeeping most calls need. A
    wall-clock timeout can still come from a sibling thread's CPU charged to
    this one; the retrying path then decides whether it was contention.
    """
    try:
        return rx.search(text, timeout=timeout, concurrent=False)
    except TimeoutError:
        return _search(rx, text, context)


def _budgeted_search(rx: Any, text: str, context: str, timeout: float) -> Any:
    """Full per-call bookkeeping for hosts supplied by connectors rather than the tokenizer."""
    return _search(rx, text, context)


# ------------------------------------------------------- domain prefilters
# A plain host is lower-case ASCII made of ``[a-z0-9.-]`` with no port, path
# or newline: every token the text tokenizer produces. For such hosts ``$``
# means end of string, ``\.`` means a dot and an ASCII literal matches only
# itself under IGNORECASE, so the required ending or beginning of an anchored
# ``re:`` domain value can be read off its literal characters. Anything the
# shape scanner does not understand stays unkeyed and runs for every host;
# every rejection is therefore conservative and results stay identical.
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
_ALLOWED_ESCAPES = frozenset("dwsDWSbBAZntr")
_GROUP_OPENER_RX = re.compile(r"\(\?(?::|=|!|<=|<!|P<[A-Za-z_]\w*>|<[A-Za-z_]\w*>|[ims-]+[:)])")
_BRACE_QUANTIFIER_RX = re.compile(r"\{\d*(?:,\d*)?\}")
_ORDER = itemgetter(0)


class _HostHints(NamedTuple):
    impossible: bool = False  # the pattern requires ``:`` or ``/``, which no plain host contains
    suffix: str | None = None  # every match ends with ``.<suffix>`` or equals ``<suffix>``
    prefix: str | None = None  # every match starts with ``<prefix>.``


def _escaped_at(pattern: str, index: int) -> bool:
    """Whether an odd run of backslashes precedes ``pattern[index]``."""
    count = 0
    while index - count - 1 >= 0 and pattern[index - count - 1] == "\\":
        count += 1
    return count % 2 == 1


def _plain_shape(pattern: str) -> bool:
    """Accept only syntax whose structure the hint scanners understand.

    Top-level alternation (``$`` would bind to one branch only), inline flags
    other than ``ims``, fuzzy or malformed braces, POSIX classes and escapes
    beyond the common ASCII classes are rejected.
    """
    depth = 0
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n:
                return False
            following = pattern[i + 1]
            if following.isalnum() and following not in _ALLOWED_ESCAPES:
                return False
            i += 2
        elif in_class:
            if c == "]":
                in_class = False
            elif c == "[" and pattern[i + 1:i + 2] in {":", ".", "="}:
                return False
            i += 1
        elif c == "[":
            in_class = True
            i += 1
            if pattern[i:i + 1] == "^":
                i += 1
            if pattern[i:i + 1] == "]":
                i += 1
        elif c == "(":
            if pattern[i + 1:i + 2] == "?":
                opener = _GROUP_OPENER_RX.match(pattern, i)
                if opener is None:
                    return False
                i = opener.end()
                if pattern[i - 1] != ")":
                    depth += 1
            else:
                depth += 1
                i += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
            i += 1
        elif c == "|" and depth == 0:
            return False
        elif c == "{":
            quantifier = _BRACE_QUANTIFIER_RX.match(pattern, i)
            if quantifier is None:
                return False
            i = quantifier.end()
        else:
            i += 1
    return depth == 0 and not in_class


def _anchored_prefix(pattern: str) -> str | None:
    """First label every match must start with, from ``^label\\.`` with no quantifier."""
    if not pattern.startswith("^"):
        return None
    i = 1
    while i < len(pattern) and pattern[i] in _LABEL_CHARS:
        i += 1
    if i == 1 or pattern[i:i + 2] != "\\." or pattern[i + 2:i + 3] in {"?", "*", "+", "{"}:
        return None
    return pattern[1:i].lower()


def plain_host_hints(pattern: str) -> _HostHints:
    """Derive what any plain host matched by a domain regex must contain.

    The suffix hint reads the literal labels before a final ``$`` backwards.
    Each accepted character sits at group depth zero with no quantifier after
    it (a quantifier would have stopped the scan first), so it is required.
    Two labels bounded by escaped dots, or by ``^`` on the left, give the
    two-label key; a required ``:`` or ``/`` makes a plain host impossible.
    """
    if not _plain_shape(pattern):
        return _HostHints()
    hints = _HostHints(prefix=_anchored_prefix(pattern))
    if not pattern.endswith("$") or _escaped_at(pattern, len(pattern) - 1):
        return hints
    labels: list[str] = []
    current: list[str] = []
    i = len(pattern) - 2
    while i >= 0:
        c = pattern[i]
        escaped = _escaped_at(pattern, i)
        if not escaped and c in _LABEL_CHARS:
            current.append(c)
            i -= 1
            continue
        if not escaped and c in ":/":
            return _HostHints(impossible=True)
        if escaped and c == ".":
            labels.append("".join(reversed(current)).lower())
            current = []
            i -= 2
            if len(labels) == 2:
                break
            continue
        if not escaped and c == "^" and current:
            labels.append("".join(reversed(current)).lower())
        break
    if len(labels) < 2:
        return hints
    return _HostHints(suffix=f"{labels[1]}.{labels[0]}", prefix=hints.prefix)


def _last_two_labels(host: str) -> str | None:
    tail = host.rsplit(".", 2)
    return f"{tail[-2]}.{tail[-1]}" if len(tail) > 1 else None


# ------------------------------------------------------- literal prefilter
# Escapes that stand for the escaped character itself in every regex flavour
# this matcher runs; ``\<`` and ``\>`` are left out as some engines treat
# them as word boundaries.
_PUNCT_ESCAPES = frozenset(".()[]{}*+?|^$\\/-:\"'@#,;= ")
_CONTROL_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}
_INLINE_IGNORECASE_RX = re.compile(r"\(\?[a-zA-Z-]*i")


def _fold(text: str) -> str:
    """Casefold consistently with the regex engine's IGNORECASE.

    ``str.casefold`` maps U+0130 (capital I with dot) to two code points and
    leaves U+0131 (dotless i) unchanged, whereas the regex engine treats both
    as equivalent to ``i``; folding them to ``i`` keeps the literal prefilter
    sound for every text the engine would match.
    """
    return text.casefold().replace("i\u0307", "i").replace("\u0131", "i")
_LEADING_FLAGS_RX = re.compile(r"\(\?([ims]+)\)")
_QUANTIFIER_STARTS = frozenset("*+?{")
_GROUP_STOP_CHARS = frozenset("()[].^$*+?{")


class _LiteralHints(NamedTuple):
    """What every match of a pattern must contain: each group holds alternatives, one of which appears.

    ``fold`` marks a case-insensitive pattern whose literals are casefolded
    and must be tested against a casefolded text.
    """

    fold: bool = False
    groups: tuple[tuple[str, ...], ...] = ()


def _literal_alternatives(pattern: str, start: int) -> tuple[tuple[str, ...], int] | None:
    """Parse ``(a|b)`` or ``(?:a|b)`` at ``start`` when every alternative is a plain literal.

    Returns the alternatives and the index of the closing parenthesis, or
    None for lookarounds, named or flagged groups, nested constructs, classes,
    quantifiers and empty alternatives.
    """
    i = start + 1
    if pattern.startswith("?:", i):
        i += 2
    elif pattern[i:i + 1] == "?":
        return None
    alternatives: list[str] = []
    current: list[str] = []
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            following = pattern[i + 1:i + 2]
            literal = following if following in _PUNCT_ESCAPES else _CONTROL_ESCAPES.get(following)
            if literal is None:
                return None
            current.append(literal)
            i += 2
        elif c == ")":
            alternatives.append("".join(current))
            return (tuple(alternatives), i) if all(alternatives) else None
        elif c == "|":
            alternatives.append("".join(current))
            current = []
            i += 1
        elif c in _GROUP_STOP_CHARS:
            return None
        else:
            current.append(c)
            i += 1
    return None


def required_literal(pattern: str) -> str | None:
    """Return the longest single literal every match of a case-sensitive ``pattern`` must contain, or None."""
    hints = required_literals(pattern)
    if hints.fold:
        return None
    return max((group[0] for group in hints.groups if len(group) == 1), key=len, default=None)


def required_literals(pattern: str) -> _LiteralHints:
    """Derive literals every match of ``pattern`` must contain, in pattern order.

    Each run of literal characters at group depth zero is required. A
    character followed by ``?``, ``*`` or a zero-minimum brace quantifier is
    optional and ends a run without joining it; ``+`` and ``{n,}`` keep the
    character but end the run, since the repeat may separate it from what
    follows. A depth-zero group of plain literal alternatives that is not
    optional requires one of its alternatives. A leading ``(?i)`` makes the
    comparison casefolded. Top-level alternation, other case-insensitive
    flags and syntax the shape scanner rejects yield no hints, so the caller
    runs the regex.
    """
    if not _plain_shape(pattern):
        return _LiteralHints()
    fold = False
    i = 0
    flags = _LEADING_FLAGS_RX.match(pattern)
    if flags is not None:
        fold = "i" in flags.group(1)
        i = flags.end()
    if _INLINE_IGNORECASE_RX.search(pattern, i):
        return _LiteralHints()
    groups: list[tuple[str, ...]] = []
    run: list[str] = []
    depth = 0
    in_class = False
    n = len(pattern)

    def flush() -> None:
        nonlocal run
        if run:
            groups.append(("".join(run),))
        run = []

    def require(alternatives: tuple[str, ...], position: int) -> int:
        """Record a group's alternatives unless its quantifier makes it optional; return the next index."""
        after = pattern[position:position + 1]
        if after in {"?", "*"}:
            return skip_quantifier(position)
        if after == "{":
            brace = _BRACE_QUANTIFIER_RX.match(pattern, position)
            minimum = brace.group(0)[1:-1].split(",")[0] if brace is not None else ""
            if minimum and int(minimum) >= 1:
                groups.append(alternatives)
            return skip_quantifier(position)
        groups.append(alternatives)
        return skip_quantifier(position) if after == "+" else position

    def skip_quantifier(position: int) -> int:
        """Return the index after a quantifier at ``position`` and its lazy/possessive suffix."""
        if pattern[position] == "{":
            brace = _BRACE_QUANTIFIER_RX.match(pattern, position)
            position = brace.end() if brace is not None else position + 1
        else:
            position += 1
        if pattern[position:position + 1] in {"?", "+"}:
            position += 1
        return position

    def open_class(position: int) -> int:
        position += 1
        if pattern[position:position + 1] == "^":
            position += 1
        if pattern[position:position + 1] == "]":
            position += 1
        return position

    while i < n:
        c = pattern[i]
        if in_class:
            if c == "\\":
                i += 2
                continue
            if c == "]":
                in_class = False
            i += 1
            continue
        if depth > 0:
            if c == "\\":
                i += 2
            elif c == "[":
                in_class = True
                i = open_class(i)
            elif c == "(":
                depth += 1
                i += 1
            elif c == ")":
                depth -= 1
                i += 1
            else:
                i += 1
            continue
        literal: str | None = None
        width = 1
        if c == "\\":
            following = pattern[i + 1]
            width = 2
            if following in _PUNCT_ESCAPES:
                literal = following
            else:
                literal = _CONTROL_ESCAPES.get(following)
        elif c == "[":
            flush()
            in_class = True
            i = open_class(i)
            continue
        elif c == "(":
            flush()
            parsed = _literal_alternatives(pattern, i)
            if parsed is not None:
                alternatives, close = parsed
                i = require(alternatives, close + 1)
                continue
            depth += 1
            i += 1
            continue
        elif c in _QUANTIFIER_STARTS:
            flush()
            i = skip_quantifier(i)
            continue
        elif c not in ".^$)":
            literal = c
        if literal is None:
            flush()
            i += width
            continue
        after = pattern[i + width:i + width + 1]
        if after in {"?", "*"}:
            flush()
            i = skip_quantifier(i + width)
            continue
        if after == "{":
            brace = _BRACE_QUANTIFIER_RX.match(pattern, i + width)
            minimum = brace.group(0)[1:-1].split(",")[0] if brace is not None else ""
            if minimum and int(minimum) >= 1:
                run.append(literal)
            flush()
            i = skip_quantifier(i + width)
            continue
        if after == "+":
            run.append(literal)
            flush()
            i = skip_quantifier(i + width)
            continue
        run.append(literal)
        i += width
    flush()
    if fold:
        return _LiteralHints(True, tuple(tuple(_fold(alt) for alt in group) for group in groups))
    return _LiteralHints(False, tuple(groups))


def _ordered_hints(source: Any) -> _LiteralHints:
    hints = required_literals(source) if isinstance(source, str) else _LiteralHints()
    ordered = sorted(hints.groups, key=lambda group: (len(group), -max(len(alternative) for alternative in group)))
    return _LiteralHints(hints.fold, tuple(ordered))


def _hints_present(groups: tuple[tuple[str, ...], ...], haystack: str, memo: dict[str, bool]) -> bool:
    """Whether every group has an alternative in ``haystack``; ``memo`` caches per literal."""
    for group in groups:
        for alternative in group:
            found = memo.get(alternative)
            if found is None:
                found = memo[alternative] = alternative in haystack
            if found:
                break
        else:
            return False
    return True


class _PlainHostCandidates:
    """Domain suffixes and regexes bucketed by what a matching plain host must contain.

    Original pack order is kept through the leading index of every entry so
    the first match per signature, and therefore every result, is unchanged.
    """

    __slots__ = ("regex_by_first", "regex_by_key", "regex_unkeyed", "suffix_by_key", "suffix_unkeyed")

    def __init__(
        self, suffixes: list[tuple[str, Signature, Signal]], regexes: list[tuple[Any, Signature, Signal]],
    ) -> None:
        self.suffix_by_key: dict[str, list[tuple[int, str, str, Signature, Signal]]] = {}
        self.suffix_unkeyed: list[tuple[int, str, str, Signature, Signal]] = []
        for n, (suffix, sig, s) in enumerate(suffixes):
            bare = suffix.lstrip(".")
            key = _last_two_labels(bare)
            bucket = self.suffix_by_key.setdefault(key, []) if key is not None else self.suffix_unkeyed
            bucket.append((n, suffix, bare, sig, s))
        self.regex_by_key: dict[str, list[tuple[int, Any, Signature, Signal]]] = {}
        self.regex_by_first: dict[str, list[tuple[int, Any, Signature, Signal]]] = {}
        self.regex_unkeyed: list[tuple[int, Any, Signature, Signal]] = []
        for n, (rx, sig, s) in enumerate(regexes):
            hints = plain_host_hints(rx.pattern)
            if hints.impossible:
                continue
            if hints.suffix is not None:
                self.regex_by_key.setdefault(hints.suffix, []).append((n, rx, sig, s))
            elif hints.prefix is not None:
                self.regex_by_first.setdefault(hints.prefix, []).append((n, rx, sig, s))
            else:
                self.regex_unkeyed.append((n, rx, sig, s))

    def suffixes(self, key: str | None) -> list[tuple[int, str, str, Signature, Signal]]:
        keyed = self.suffix_by_key.get(key) if key is not None else None
        if not keyed:
            return self.suffix_unkeyed
        if not self.suffix_unkeyed:
            return keyed
        return sorted(keyed + self.suffix_unkeyed, key=_ORDER)

    def regexes(self, key: str | None, first: str) -> list[tuple[int, Any, Signature, Signal]]:
        keyed = self.regex_by_key.get(key) if key is not None else None
        prefixed = self.regex_by_first.get(first)
        if not keyed and not prefixed:
            return self.regex_unkeyed
        merged = [*self.regex_unkeyed, *(keyed or ()), *(prefixed or ())]
        if len(merged) > 1:
            merged.sort(key=_ORDER)
        return merged

_LANG_ALIASES = {
    "py": "python",
    "python": "python",
    "ipynb": "python",
    "js": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "jsx": "javascript",
    "ts": "javascript",
    "tsx": "javascript",
    "mts": "javascript",
    "cts": "javascript",
    "javascript": "javascript",
    "typescript": "javascript",
    "go": "go",
    "rs": "rust",
    "rust": "rust",
    "java": "java",
    "kt": "java",
    "kts": "java",
    "scala": "java",
    "cs": "dotnet",
    "fs": "dotnet",
    "vb": "dotnet",
    "dotnet": "dotnet",
    "rb": "ruby",
    "ruby": "ruby",
    "php": "php",
    "swift": "swift",
    "dart": "dart",
}

SOURCE_EXTENSIONS = {
    ".py",
    ".ipynb",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".cs",
    ".fs",
    ".rb",
    ".php",
    ".swift",
    ".dart",
}


def language_for_path(path: str) -> str | None:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _LANG_ALIASES.get(ext)


@dataclass(slots=True)
class Match:
    signature: Signature
    signal: Signal
    value: str  # what matched (package name, line excerpt, host...)
    weight: float
    line: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def signature_id(self) -> str:
        return self.signature.id

    def capabilities(self) -> list[str]:
        caps = list(self.signature.capabilities)
        for c in self.signal.capabilities:
            if c not in caps:
                caps.append(c)
        return caps

    @property
    def agent_indicator(self) -> bool:
        return self.signature.agent_indicator or self.signal.agent_indicator


def _prefix_excluded(signal: Signal, norm: str) -> bool:
    """True when a prefix signal explicitly carves ``norm`` out (exact name or sub-prefix)."""
    if any(norm == normalise_package_name(n) for n in signal.exclude_names):
        return True
    return any(norm.startswith(normalise_package_name(p)) for p in signal.exclude_prefixes)


class SignatureIndex:
    """Indexes signatures by signal type for efficient matching."""

    def __init__(self, signatures: list[Signature]):
        self.signatures: dict[str, Signature] = {s.id: s for s in signatures}
        self._dep_exact: dict[tuple[str, str], list[tuple[Signature, Signal]]] = {}
        self._dep_prefix: dict[str, list[tuple[str, Signature, Signal]]] = {}
        self._env_exact: dict[str, list[tuple[Signature, Signal]]] = {}
        self._env_patterns: list[tuple[Signature, Signal]] = []
        self._client_ids: dict[str, list[tuple[Signature, Signal]]] = {}
        self._domains: dict[str, list[tuple[Signature, Signal]]] = {}
        self._domain_suffixes: list[tuple[str, Signature, Signal]] = []
        self._domain_regex: list[tuple[Any, Signature, Signal]] = []
        self._scopes: dict[str, list[tuple[Signature, Signal]]] = {}
        self._iac: dict[str, list[tuple[Signature, Signal]]] = {}
        self._files: list[tuple[Signature, Signal]] = []
        self._by_type: dict[str, list[tuple[Signature, Signal]]] = {}
        # Per compiled pattern, literals every match must contain, keyed by
        # the signal object; cheap substring tests then skip most patterns
        # for most inputs. Single long literals are tested first so a miss
        # costs one search. Signals live as long as the index.
        self._literals: dict[int, list[_LiteralHints]] = {}
        for sig in signatures:
            for s in sig.signals:
                self._by_type.setdefault(s.type, []).append((sig, s))
                if s.bounded_compiled:
                    self._literals[id(s)] = [_ordered_hints(getattr(rx, "pattern", None)) for rx in s.bounded_compiled]
                if s.type == "dependency":
                    eco = (s.ecosystem or "any").lower()
                    for n in s.names:
                        self._dep_exact.setdefault((eco, normalise_package_name(n)), []).append((sig, s))
                    for p in s.prefixes:
                        self._dep_prefix.setdefault(eco, []).append((normalise_package_name(p), sig, s))
                elif s.type == "env":
                    for n in s.names:
                        self._env_exact.setdefault(n.upper(), []).append((sig, s))
                    if s.patterns:
                        self._env_patterns.append((sig, s))
                elif s.type == "client_id":
                    for n in s.names:
                        self._client_ids.setdefault(n.lower(), []).append((sig, s))
                elif s.type == "domain":
                    for v in s.values:
                        v = v.strip()
                        if v.startswith("re:"):
                            self._domain_regex.append((regex.compile(v[3:], regex.IGNORECASE | regex.VERSION0), sig, s))
                            continue
                        v = v.lower()
                        if v.startswith("*."):
                            self._domain_suffixes.append((v[1:], sig, s))
                        elif v.startswith("."):
                            self._domain_suffixes.append((v, sig, s))
                        else:
                            self._domains.setdefault(v, []).append((sig, s))
                elif s.type == "scope":
                    for v in s.values:
                        self._scopes.setdefault(v.lower(), []).append((sig, s))
                elif s.type == "iac":
                    for v in s.values:
                        self._iac.setdefault(v.lower(), []).append((sig, s))
                elif s.type == "file":
                    self._files.append((sig, s))
        self._plain_hosts = _PlainHostCandidates(self._domain_suffixes, self._domain_regex)
        # fnmatch semantics, precompiled: normcase both sides, translate, match.
        # One alternation of every glob rejects the typical file in one pass.
        self._file_globs: list[tuple[Signature, Signal, list[tuple[re.Pattern[str], re.Pattern[str] | None]]]] = []
        translated: list[str] = []
        for sig, s in self._files:
            compiled = []
            for g in s.globs:
                whole = fnmatch.translate(os.path.normcase(g))
                tail = fnmatch.translate(os.path.normcase(g[3:])) if g.startswith("**/") else None
                translated.append(whole)
                if tail is not None:
                    translated.append(tail)
                compiled.append((re.compile(whole), re.compile(tail) if tail is not None else None))
            self._file_globs.append((sig, s, compiled))
        self._file_prefilter = re.compile("|".join(translated)) if translated else None

    # ------------------------------------------------------------------ basic
    def get(self, sig_id: str) -> Signature | None:
        return self.signatures.get(sig_id)

    def by_category(self, category: str) -> list[Signature]:
        return [s for s in self.signatures.values() if s.category == category]

    def __len__(self) -> int:
        return len(self.signatures)

    def fingerprint(self) -> str:
        """Stable digest of detection semantics; independent of load paths/order."""
        values = []
        for sig in sorted(self.signatures.values(), key=lambda item: item.id):
            value = {f.name: getattr(sig, f.name) for f in fields(sig) if f.name not in {"source", "signals"}}
            value["signals"] = [
                {f.name: getattr(signal, f.name) for f in fields(signal) if f.name not in {"compiled", "bounded_compiled"}}
                for signal in sig.signals
            ]
            values.append(value)
        return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    @contextmanager
    def scan_budget(self, seconds: float = DEFAULT_SCAN_BUDGET_SECONDS):
        """Share one deadline across all signature operations for an input file.

        Individual regex executions are also preempted by the regex engine. An
        elapsed deadline always raises, including after non-matching work.
        """
        if not 0 < seconds <= 60:
            raise ValueError("signature scan budget must be greater than zero and at most 60 seconds")
        deadline = time.monotonic() + seconds
        outer = _SCAN_DEADLINE.get()
        token = _SCAN_DEADLINE.set(min(deadline, outer) if outer is not None else deadline)
        try:
            _remaining_timeout()
            yield
            _remaining_timeout()
        finally:
            _SCAN_DEADLINE.reset(token)

    # ------------------------------------------------------------- matchers
    def match_dependency(self, ecosystem: str, name: str) -> list[Match]:
        eco = ecosystem.lower()
        norm = normalise_package_name(name)
        out: list[Match] = []
        seen: set[str] = set()
        for key in ((eco, norm), ("any", norm)):
            for sig, s in self._dep_exact.get(key, []):
                if sig.id not in seen:
                    seen.add(sig.id)
                    out.append(Match(sig, s, name, s.weight))
        for e in (eco, "any"):
            for prefix, sig, s in self._dep_prefix.get(e, []):
                if norm.startswith(prefix) and sig.id not in seen and not _prefix_excluded(s, norm):
                    seen.add(sig.id)
                    out.append(Match(sig, s, name, s.weight))
        return out

    @contextmanager
    def _input_budget(self):
        """Preserve a caller's explicit budget or open the default input budget."""
        if _SCAN_DEADLINE.get() is not None:
            _remaining_timeout()
            yield
            _remaining_timeout()
            return
        with self.scan_budget():
            yield

    def _match_regex_signals(
        self, signal_type: str, text: str, language: str | None = None, max_per_signal: int = 3,
        ignore_spans: Sequence[tuple[int, int]] = (),
    ) -> list[Match]:
        # One deadline covers the whole signal class even outside filesystem scans.
        with self._input_budget():
            return self._match_regex_signals_with_budget(signal_type, text, language, max_per_signal, ignore_spans)

    def _match_regex_signals_with_budget(
        self, signal_type: str, text: str, language: str | None, max_per_signal: int,
        ignore_spans: Sequence[tuple[int, int]],
    ) -> list[Match]:
        out: list[Match] = []
        # Ignore matches beginning inside comments and literals before applying
        # the per-signal quota. A file with many examples must not hide live code.
        newlines: list[int] | None = None
        starts = [start for start, _ in ignore_spans]
        ends = [end for _, end in ignore_spans]

        def excluded(offset: int) -> bool:
            previous = bisect_right(starts, offset) - 1
            return previous >= 0 and offset < ends[previous]

        # literal -> occurs in the text; patterns share literals, and the
        # casefolded text for case-insensitive patterns is built on demand.
        present: dict[str, bool] = {}
        folded_present: dict[str, bool] = {}
        folded_text: str | None = None
        for sig, s in self._by_type.get(signal_type, []):
            if language and s.languages and language not in s.languages:
                continue
            hits = 0
            literals = self._literals.get(id(s), ())
            for number, rx in enumerate(s.bounded_compiled):
                hints = literals[number] if number < len(literals) else None
                if hints is not None and hints.groups:
                    if hints.fold:
                        if folded_text is None:
                            folded_text = _fold(text)
                        if not _hints_present(hints.groups, folded_text, folded_present):
                            continue
                    elif not _hints_present(hints.groups, text, present):
                        continue
                for m in _finditer(rx, text, sig.id, max_per_signal - hits, excluded if starts else None):
                    if newlines is None:
                        newlines = [newline.start() for newline in re.finditer("\n", text)]
                    line = bisect_left(newlines, m.start()) + 1
                    excerpt = m.group(0)
                    # Never cut away a credential's recognizable context before
                    # redaction. Dedicated secret detectors need the raw match
                    # to create their redacted evidence/fingerprint downstream.
                    value = excerpt if signal_type == "secret" else sanitize_text(excerpt)[:200]
                    out.append(Match(sig, s, value, s.weight, line=line, extra={"start": m.start(), "end": m.end()}))
                    hits += 1
                    if hits >= max_per_signal:
                        break
                if hits >= max_per_signal:
                    break
        return out

    def match_imports(
        self, text: str, language: str | None, ignore_spans: Sequence[tuple[int, int]] = (),
    ) -> list[Match]:
        return self._match_regex_signals("import", text, language, ignore_spans=ignore_spans)

    def match_code(
        self, text: str, language: str | None = None, ignore_spans: Sequence[tuple[int, int]] = (),
    ) -> list[Match]:
        return self._match_regex_signals("code", text, language, ignore_spans=ignore_spans)

    def match_secrets(self, text: str) -> list[Match]:
        return self._match_regex_signals("secret", text, None, max_per_signal=5)

    def match_user_agent(self, ua: str) -> list[Match]:
        if not ua:
            return []
        return self._match_regex_signals("user_agent", ua)

    def match_name(self, name: str) -> list[Match]:
        if not name:
            return []
        return self._match_regex_signals("name", name)

    def match_model(self, model: str) -> list[Match]:
        if not model:
            return []
        return self._match_regex_signals("model", model)

    def match_image(self, image: str) -> list[Match]:
        if not image:
            return []
        return self._match_regex_signals("image", image)

    def match_file(self, relpath: str) -> list[Match]:
        rel = relpath.replace("\\", "/")
        key = os.path.normcase(rel)
        base = key.rsplit("/", 1)[-1]
        prefilter = self._file_prefilter
        if prefilter is None or not (prefilter.match(key) or prefilter.match(base)):
            return []
        out: list[Match] = []
        for sig, s, compiled in self._file_globs:
            for whole, tail in compiled:
                if whole.match(key) or whole.match(base) or (tail is not None and tail.match(key)):
                    out.append(Match(sig, s, rel, s.weight))
                    break
        return out

    def match_env(self, name: str) -> list[Match]:
        out: list[Match] = []
        for sig, s in self._env_exact.get(name.upper(), []):
            out.append(Match(sig, s, name, s.weight))
        for sig, s in self._env_patterns:
            if any(_search(rx, name, sig.id) for rx in s.bounded_compiled):
                out.append(Match(sig, s, name, s.weight))
        return out

    def match_client_id(self, client_id: str) -> list[Match]:
        if not client_id:
            return []
        out = [Match(sig, s, client_id, s.weight) for sig, s in self._client_ids.get(client_id.lower(), [])]
        for sig, s in self._by_type.get("client_id", []):
            if s.bounded_compiled and any(_search(rx, client_id, sig.id) for rx in s.bounded_compiled):
                out.append(Match(sig, s, client_id, s.weight))
        return out

    def match_domain(self, host: str) -> list[Match]:
        if not host:
            return []
        h = host.lower().strip().rstrip(".")
        if "://" in h:
            h = h.split("://", 1)[1]
        h_with_port = h.split("/", 1)[0]
        h = h_with_port.split(":", 1)[0]
        if h == h_with_port and h.isascii() and "\n" not in h:
            # Ports, paths, newlines and non-ASCII keep the exhaustive scan
            # below, where ``$`` and case folding retain full regex semantics.
            return self._match_plain_host(h, _budgeted_search)
        out: list[Match] = [Match(sig, s, h, s.weight) for sig, s in self._domains.get(h, [])]
        for suffix, sig, s in self._domain_suffixes:
            if h.endswith(suffix) or h == suffix.lstrip("."):
                out.append(Match(sig, s, h, s.weight))
        for rx, sig, s in self._domain_regex:
            if _search(rx, h, sig.id) or _search(rx, h_with_port, sig.id):
                out.append(Match(sig, s, h_with_port, s.weight))
        return out

    def _match_plain_host(self, h: str, search: Callable[[Any, str, str, float], Any]) -> list[Match]:
        """Match a plain host (see ``_PlainHostCandidates``) against its candidate signals only."""
        out: list[Match] = [Match(sig, s, h, s.weight) for sig, s in self._domains.get(h, [])]
        key = _last_two_labels(h)
        for _, suffix, bare, sig, s in self._plain_hosts.suffixes(key):
            if h.endswith(suffix) or h == bare:
                out.append(Match(sig, s, h, s.weight))
        regexes = self._plain_hosts.regexes(key, h.partition(".")[0])
        if regexes:
            # One deadline check per host bounds every candidate's timeout.
            timeout = _remaining_timeout()
            for _, rx, sig, s in regexes:
                if search(rx, h, sig.id, timeout):
                    out.append(Match(sig, s, h, s.weight))
        return out

    def match_domains_in_text(self, text: str) -> list[Match]:
        with self._input_budget():
            return self._match_domains_in_text_with_budget(text)

    def _match_domains_in_text_with_budget(self, text: str) -> list[Match]:
        out: list[Match] = []
        seen: set[str] = set()
        newlines: list[int] | None = None
        # This fixed tokenizer is a single character class, with linear work.
        # A regex iterator's timeout also counts caller work between yields;
        # applying a 100 ms pattern timeout here incorrectly charges all domain
        # lookup/deduplication work to tokenization. The shared input deadline
        # below bounds iteration instead, checked once per 64 tokens so the
        # bookkeeping stays far below the cost of the tokens. User-defined
        # expressions still use preemptive regex-engine timeouts.
        for count, m in enumerate(_HOST_TOKEN_RX.finditer(text)):
            if not (count & 63):
                _remaining_timeout()
            raw = m.group(0)
            if "." not in raw:
                continue
            host = raw.lower().strip(".")
            # DNS names are bounded by the protocol. Consume each entire token
            # once instead of retrying a suffix from every dot on malformed input.
            if host in seen or len(host) > 253 or "." not in host:
                continue
            seen.add(host)
            labels = host.split(".")
            if len(labels[-1]) < 2 or not labels[-1].isalpha() or any(
                not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum()
                for label in labels
            ):
                continue
            # Tokens never carry a port, path or newline; only case folding of
            # non-ASCII letters needs the exhaustive path.
            matches = self._match_plain_host(host, _plain_search) if host.isascii() else self.match_domain(host)
            if not matches:
                continue
            if newlines is None:
                newlines = [newline.start() for newline in re.finditer("\n", text)]
            line = bisect_right(newlines, m.start()) + 1
            matched_signatures: set[str] = set()
            for match in matches:
                if match.signature_id in matched_signatures:
                    continue
                matched_signatures.add(match.signature_id)
                match.line = line
                out.append(match)
        return out

    def match_scope(self, scope: str) -> list[Match]:
        return [Match(sig, s, scope, s.weight) for sig, s in self._scopes.get(scope.lower(), [])]

    def match_iac(self, resource_type: str) -> list[Match]:
        return [Match(sig, s, resource_type, s.weight) for sig, s in self._iac.get(resource_type.lower(), [])]

    def match_envs_in_text(self, text: str) -> list[Match]:
        """Find environment variable style identifiers inside arbitrary text."""
        with self._input_budget():
            return self._match_envs_in_text_with_budget(text)

    def _match_envs_in_text_with_budget(self, text: str) -> list[Match]:
        out: list[Match] = []
        seen: set[str] = set()
        newlines: list[int] | None = None
        for m in _ENV_RX.finditer(text):
            _remaining_timeout()
            name = m.group(0)
            if name in seen:
                continue
            seen.add(name)
            matched_signatures: set[str] = set()
            for match in self.match_env(name):
                if match.signature_id in matched_signatures:
                    continue
                matched_signatures.add(match.signature_id)
                if newlines is None:
                    newlines = [newline.start() for newline in re.finditer("\n", text)]
                match.line = bisect_right(newlines, m.start()) + 1
                out.append(match)
        return out


_HOST_TOKEN_RX = re.compile(r"[a-z0-9.-]+", re.IGNORECASE)
# Underscores delimit disjoint alphanumeric groups; neither tokenizer has nested
# ambiguous repetition. Both operate under the shared input deadline.
_ENV_RX = re.compile(r"\b[A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+){1,6}\b")

_index_lock = threading.Lock()
_default_index: SignatureIndex | None = None


def get_index(extra_dirs: list[str] | None = None, reload: bool = False, *, allow_override: bool = False) -> SignatureIndex:
    """Return the process-wide signature index (built lazily)."""
    global _default_index
    with _index_lock:
        if _default_index is None or reload or extra_dirs:
            dirs: list[str | os.PathLike[str]] | None = list(extra_dirs) if extra_dirs else None
            idx = SignatureIndex(load_signatures(extra_dirs=dirs, allow_override=allow_override))
            if not extra_dirs:
                _default_index = idx
            return idx
        return _default_index
