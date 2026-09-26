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
from typing import Any

import regex

from shadowscan.signatures.loader import Signal, Signature, load_signatures, normalise_package_name
from shadowscan.utils.redaction import sanitize_text

_SCAN_DEADLINE: ContextVar[float | None] = ContextVar("signature_scan_deadline", default=None)
# Per-pattern caps scale with the size of the input under the active budget:
# one linear pass over a 900 KB module legitimately takes longer than 100 ms.
_SCAN_SCALE: ContextVar[float] = ContextVar("signature_scan_scale", default=1.0)
REGEX_TIMEOUT_SECONDS = 0.1
DEFAULT_SCAN_BUDGET_SECONDS = 2.0
MAX_SCAN_BUDGET_SECONDS = 60.0
# The default budget covers a typical input; larger records (a 300 KB workflow
# export, a generated module) get proportionally more, up to the maximum.
BUDGET_SCALE_BYTES = 100_000


def size_scale(size: int) -> float:
    """Multiplier for per-pattern and per-input budgets of an input of ``size`` characters."""
    return max(1.0, size / BUDGET_SCALE_BYTES)


def default_budget_for(size: int, base: float = DEFAULT_SCAN_BUDGET_SECONDS) -> float:
    """Scale a per-input budget with the input size, within the validated range."""
    return min(MAX_SCAN_BUDGET_SECONDS, base * size_scale(size))
# A briefly busy worker can exhaust several regex wall-clock attempts before
# this thread has used its own 100 ms CPU allowance. Keep retries finite and
# inside the original per-pattern CPU and per-input wall deadlines.
_MAX_CONTENTION_RETRIES = 16


class MatchTimeoutError(RuntimeError):
    """Matching did not finish; callers must mark the input/scan incomplete."""


def _remaining_timeout() -> float:
    deadline = _SCAN_DEADLINE.get()
    per_pattern = REGEX_TIMEOUT_SECONDS * _SCAN_SCALE.get()
    remaining = per_pattern if deadline is None else min(per_pattern, deadline - time.monotonic())
    if remaining <= 0:
        raise MatchTimeoutError("signature matching exceeded the input execution budget")
    return remaining


def pattern_timeout(default: float = REGEX_TIMEOUT_SECONDS) -> float:
    """Cap external pattern calls by the active per-input execution budget."""
    deadline = _SCAN_DEADLINE.get()
    scaled = default * _SCAN_SCALE.get()
    if deadline is None:
        return scaled
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise MatchTimeoutError("signature matching exceeded the input execution budget")
    return min(scaled, remaining)


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


# An expression joins the gate only when alternation cannot change its meaning:
# no inline flags, named or numbered back-references, or other (?...) syntax
# except non-capturing groups.
_UNGATEABLE = re.compile(r"\(\?(?!:)|\\[1-9gk]")


def _domain_regex_gate(entries: list[tuple[Any, Signature, Signal]]) -> tuple[Any | None, list[tuple[Any, Signature, Signal]]]:
    """Build one alternation of gateable domain expressions.

    ``search(A|B|...)`` finds a match exactly when one alternative matches, so
    a miss proves no gated expression matches. Returns the gate (None when no
    expression qualifies) and the entries that must always run.
    """
    gated = [rx for rx, _, _ in entries if not _UNGATEABLE.search(rx.pattern)]
    ungated = [entry for entry in entries if _UNGATEABLE.search(entry[0].pattern)]
    if not gated:
        return None, ungated
    flags = {rx.flags for rx in gated}
    if len(flags) != 1:
        return None, list(entries)
    # A leading unanchored ".*" cannot change whether a search finds a match,
    # and dropping it keeps the gate linear on long tokens.
    alternatives = [rx.pattern[2:] if rx.pattern.startswith(".*") else rx.pattern for rx in gated]
    return regex.compile("|".join(f"(?:{pattern})" for pattern in alternatives), flags.pop()), ungated

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
        for sig in signatures:
            for s in sig.signals:
                self._by_type.setdefault(s.type, []).append((sig, s))
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
        self._domain_gate, self._domain_regex_ungated = _domain_regex_gate(self._domain_regex)

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
    def scan_budget(self, seconds: float = DEFAULT_SCAN_BUDGET_SECONDS, *, size: int = 0):
        """Share one deadline across all signature operations for an input file.

        Individual regex executions are also preempted by the regex engine. An
        elapsed deadline always raises, including after non-matching work.
        ``size`` (characters) scales the per-pattern cap for large inputs.
        """
        if not 0 < seconds <= MAX_SCAN_BUDGET_SECONDS:
            raise ValueError("signature scan budget must be greater than zero and at most 60 seconds")
        deadline = time.monotonic() + seconds
        outer = _SCAN_DEADLINE.get()
        token = _SCAN_DEADLINE.set(min(deadline, outer) if outer is not None else deadline)
        scale_token = _SCAN_SCALE.set(max(_SCAN_SCALE.get(), size_scale(size)))
        try:
            _remaining_timeout()
            yield
            _remaining_timeout()
        finally:
            _SCAN_SCALE.reset(scale_token)
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
                if norm.startswith(prefix) and sig.id not in seen:
                    seen.add(sig.id)
                    out.append(Match(sig, s, name, s.weight))
        return out

    @contextmanager
    def _input_budget(self, size: int = 0):
        """Preserve a caller's explicit budget or open a size-scaled default budget."""
        if _SCAN_DEADLINE.get() is not None:
            _remaining_timeout()
            yield
            _remaining_timeout()
            return
        with self.scan_budget(default_budget_for(size), size=size):
            yield

    def _match_regex_signals(
        self, signal_type: str, text: str, language: str | None = None, max_per_signal: int = 3,
        ignore_spans: Sequence[tuple[int, int]] = (),
    ) -> list[Match]:
        # One deadline covers the whole signal class even outside filesystem scans.
        with self._input_budget(len(text)):
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

        for sig, s in self._by_type.get(signal_type, []):
            if language and s.languages and language not in s.languages:
                continue
            if s.bound_only:
                continue  # attributed only through import binding
            hits = 0
            for rx in s.bounded_compiled:
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
        base = rel.rsplit("/", 1)[-1]
        out: list[Match] = []
        for sig, s in self._files:
            for g in s.globs:
                if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(base, g) or (g.startswith("**/") and fnmatch.fnmatch(rel, g[3:])):
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
        # One signal can list a host both exactly and as a wildcard suffix
        # (api.openai.com and *.api.openai.com). Report each signal once so a
        # single observed host cannot count twice in noisy-OR confidence.
        out: list[Match] = []
        seen: set[tuple[str, int]] = set()

        def add(sig: Signature, s: Signal, value: str) -> None:
            key = (sig.id, id(s))
            if key not in seen:
                seen.add(key)
                out.append(Match(sig, s, value, s.weight))

        for sig, s in self._domains.get(h, []):
            add(sig, s, h)
        for suffix, sig, s in self._domain_suffixes:
            if h.endswith(suffix) or h == suffix.lstrip("."):
                add(sig, s, h)
        # Source text yields many dotted tokens (obj.prop) that look like hosts.
        # One alternation of the simple domain expressions matches exactly when
        # one of them does, so it rules most tokens out in a single search.
        gate = self._domain_gate
        try:
            gated_in = gate is None or bool(_search(gate, h, "domain signatures") or _search(gate, h_with_port, "domain signatures"))
        except MatchTimeoutError:
            gated_in = True  # decide with the individual expressions, as without the gate
        for rx, sig, s in self._domain_regex if gated_in else self._domain_regex_ungated:
            if _search(rx, h, sig.id) or _search(rx, h_with_port, sig.id):
                add(sig, s, h_with_port)
        return out

    def match_domains_in_text(self, text: str) -> list[Match]:
        with self._input_budget(len(text)):
            return self._match_domains_in_text_with_budget(text)

    def _match_domains_in_text_with_budget(self, text: str) -> list[Match]:
        out: list[Match] = []
        seen: set[str] = set()
        newlines = [m.start() for m in re.finditer("\n", text)]
        # This fixed tokenizer is a single character class, with linear work.
        # A regex iterator's timeout also counts caller work between yields;
        # applying a 100 ms pattern timeout here incorrectly charges all domain
        # lookup/deduplication work to tokenization. The shared input deadline
        # below bounds iteration instead. User-defined expressions still use
        # preemptive regex-engine timeouts.
        for m in _HOST_TOKEN_RX.finditer(text):
            _remaining_timeout()
            host = m.group(0).lower().strip(".")
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
            matched_signatures: set[str] = set()
            for match in self.match_domain(host):
                if match.signature_id in matched_signatures:
                    continue
                matched_signatures.add(match.signature_id)
                match.line = bisect_right(newlines, m.start()) + 1
                out.append(match)
        return out

    def match_scope(self, scope: str) -> list[Match]:
        return [Match(sig, s, scope, s.weight) for sig, s in self._scopes.get(scope.lower(), [])]

    def match_iac(self, resource_type: str) -> list[Match]:
        return [Match(sig, s, resource_type, s.weight) for sig, s in self._iac.get(resource_type.lower(), [])]

    def match_envs_in_text(self, text: str) -> list[Match]:
        """Find environment variable style identifiers inside arbitrary text."""
        with self._input_budget(len(text)):
            return self._match_envs_in_text_with_budget(text)

    def _match_envs_in_text_with_budget(self, text: str) -> list[Match]:
        out: list[Match] = []
        seen: set[str] = set()
        newlines = [m.start() for m in re.finditer("\n", text)]
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
