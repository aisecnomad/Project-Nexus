"""Module-level regular expressions must not run in superlinear time on hostile input.

CPython's ``re`` holds the GIL for an entire search and cannot be interrupted, so a
quadratic or exponential pattern defeats ``--connector-timeout-seconds`` and
``--job-deadline-seconds`` for as long as the hostile input lets it run (a 110 KB
Terraform file kept a scan busy for 137 s against a 120 s deadline). The patterns that
were found this way are linear now; this sweep keeps it so.

For every compiled ``re`` pattern reachable from a ``shadowscan`` module or class
namespace, the sweep builds hostile inputs from the pattern's own words and punctuation
(a seed, a long run of one separator, a tail that makes the match fail), times the
method the code uses at two sizes and fails when the time grows like a power of the
input. Each pattern runs in a forked child that is killed when it stalls, because an
exponential pattern never returns.

The redaction passes are not swept pattern by pattern: they are reached only through
``sanitize_text``, whose own prefilters decide what each pattern sees, so the sweep would
report shapes that cannot occur there. ``test_redaction_scales_linearly_on_hostile_text``
times the real entry point on the same kind of input instead.

A new failure means the pattern needs one of:

* a linear form (possessive quantifiers or atomic groups from the third-party ``regex``
  module, run with ``timeout=pattern_timeout()`` as ``signatures/matcher.py`` does);
* a bounded input where it runs; or
* an entry in ``ALLOWED`` with the reason the sweep's input cannot reach it.
"""

from __future__ import annotations

import ast
import importlib
import multiprocessing
import pkgutil
import queue
import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import regex

import shadowscan
from shadowscan.utils.redaction import sanitize_text

pytestmark = pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="the sweep forks one child per pattern"
)

# Input sizes. A quadratic pattern quadruples between them; the constants are large enough
# that the smaller size already exceeds timer noise and the larger one stays well under a
# second for a pattern with a small constant factor.
SMALL, LARGE = 4000, 8000
MIN_SECONDS = 0.05  # a case that finishes faster than this at the larger size is not a risk
MIN_GROWTH = 3.0  # linear is 2; quadratic is 4
STALL_SECONDS = 15.0  # a child that reports nothing for this long is exponential

SEPARATORS = (" ", "\t", "\n", "\r\n", "a", "0", '"', "'", "\\", "-", "_", ".", "/", ",", ":", "=", "(", "[")
TAILS = ("x", "")
PUNCTUATION_SEEDS = ("---", "://", "==", "=>", "<!--", "/*", "//", "`")
MAX_SEEDS = 14

# Patterns the sweep flags that are safe, by source text, with the reason. Keep the reasons
# specific: "used with match()" is only true when every call site anchors the match.
ALLOWED: dict[str, str] = {}
# Checked end to end by test_redaction_scales_linearly_on_hostile_text.
REDACTION_MODULES = ("shadowscan.utils.redaction",)


def _patterns() -> list[tuple[str, Any]]:
    """Every distinct compiled stdlib pattern in a shadowscan module, class or small container."""
    found: list[tuple[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    def walk(path: str, value: Any, depth: int) -> None:
        if isinstance(value, re.Pattern):
            key = (value.pattern if isinstance(value.pattern, str) else repr(value.pattern), value.flags)
            if key not in seen:
                seen.add(key)
                found.append((path, value))
        elif depth < 3 and isinstance(value, (tuple, list, set, frozenset)):
            for index, item in enumerate(list(value)[:200]):
                walk(f"{path}[{index}]", item, depth + 1)
        elif depth < 3 and isinstance(value, dict):
            for name, item in list(value.items())[:200]:
                walk(f"{path}[{name!r}]", item, depth + 1)

    for info in pkgutil.walk_packages(shadowscan.__path__, "shadowscan."):
        try:
            module = importlib.import_module(info.name)
        except Exception:  # an optional SDK that is not installed
            continue
        for name, value in list(vars(module).items()):
            if not name.startswith("__"):
                walk(f"{info.name}.{name}", value, 0)
            if isinstance(value, type) and value.__module__ == info.name:
                for attribute, member in list(vars(value).items()):
                    if not attribute.startswith("__"):
                        walk(f"{info.name}.{name}.{attribute}", member, 0)
    return found


def _methods_by_name() -> dict[str, set[str]]:
    """Methods called on each pattern name (``NAME.match(...)``, ``self.NAME.search(...)``)."""
    methods: dict[str, set[str]] = {}
    for source in Path(shadowscan.__file__).parent.rglob("*.py"):
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                name = receiver.id if isinstance(receiver, ast.Name) else getattr(receiver, "attr", None)
                if name:
                    methods.setdefault(name, set()).add(node.func.attr)
            # A pattern handed to another function can be searched there.
            for argument in node.args:
                if isinstance(argument, ast.Name):
                    methods.setdefault(argument.id, set()).add("<passed>")
    return methods


def _seeds(pattern: re.Pattern[str]) -> list[str]:
    """Words and punctuation of the pattern's own source, which make a hostile prefix."""
    source = pattern.pattern if isinstance(pattern.pattern, str) else pattern.pattern.decode("latin-1")
    cleaned = re.sub(r"\\[A-Za-z]", " ", source)  # \b \s \d are not the words "b", "s", "d"
    cleaned = re.sub(r"\(\?(?:[:=!]|<[=!]|P<[A-Za-z_]+>|[a-zA-Z]+\))", " ", cleaned)
    words: list[str] = []
    for word in re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", cleaned):
        if (
            word.lower() not in {"ignorecase", "unicode", "verbose", "dotall", "multiline"}
            and word not in words
        ):
            words.append(word)
    longest = sorted(words, key=lambda word: (-len(word), word))[:3]
    chosen = list(dict.fromkeys(words[:6] + longest))
    punctuation = [
        seed for seed in PUNCTUATION_SEEDS if seed in source or seed.replace("\\", "\\\\") in source
    ]
    glue = [c for c in ":=,;|/-.@#\"'(" if c in source]
    glued = [word + c for word in chosen[:4] for c in glue[:3]]
    return list(dict.fromkeys(["", *chosen, *punctuation[:2], *glued]))[:MAX_SEEDS]


def _cases(seed: str) -> Iterator[tuple[str, Any]]:
    for separator in SEPARATORS:
        for tail in TAILS:
            yield (
                f"{seed!r} + {separator!r} * n + {tail!r}",
                lambda n, s=seed, p=separator, t=tail: s + p * n + t,
            )
        unit = (seed or "a") + separator
        yield f"({seed!r} + {separator!r}) * n", lambda n, u=unit: u * max(1, n // len(u))


def _timed(call: Any, text: str, repeat: int = 1) -> float:
    best = float("inf")
    for _ in range(repeat):
        started = time.perf_counter()
        try:
            call(text)
        except Exception:  # a pattern that rejects the input still did its work
            pass
        best = min(best, time.perf_counter() - started)
    return best


def _sweep_child(pattern: re.Pattern[str], anchored: bool, channel: Any) -> None:
    call = pattern.match if anchored else pattern.search
    for seed in _seeds(pattern):
        for label, build in _cases(seed):
            channel.put(("start", label))
            small = _timed(call, build(SMALL))
            if small * 4 < MIN_SECONDS / 2:
                continue
            large = _timed(call, build(LARGE))
            if large < MIN_SECONDS or large / max(small, 1e-9) < MIN_GROWTH:
                continue
            # Confirm with the best of three runs each, so a scheduling pause is not a finding.
            small, large = _timed(call, build(SMALL), 3), _timed(call, build(LARGE), 3)
            if large >= MIN_SECONDS and large / max(small, 1e-9) >= MIN_GROWTH:
                channel.put(("hit", label, round(small, 3), round(large, 3)))
                channel.put(("done",))
                return
    channel.put(("done",))


def _sweep(pattern: re.Pattern[str], anchored: bool, stall: float = STALL_SECONDS) -> str | None:
    """Return a description of the first superlinear case, or None."""
    context = multiprocessing.get_context("fork")
    channel = context.Queue()
    child = context.Process(target=_sweep_child, args=(pattern, anchored, channel), daemon=True)
    child.start()
    last, last_message, finding = "(nothing yet)", time.monotonic(), None
    try:
        while True:
            try:
                message = channel.get(timeout=0.5)
            except queue.Empty:
                if not child.is_alive():
                    break
                if time.monotonic() - last_message > stall:
                    finding = f"stalled for {stall:.0f} s on {last}"
                    break
                continue
            last_message = time.monotonic()
            if message[0] == "start":
                last = message[1]
            elif message[0] == "hit":
                finding = f"{message[1]}: {message[2]} s at {SMALL}, {message[3]} s at {LARGE}"
                break
            elif message[0] == "done":
                break
    finally:
        if child.is_alive():
            child.kill()
        child.join(1)
    return finding


def test_module_level_patterns_are_not_superlinear():
    methods = _methods_by_name()
    flagged: list[str] = []
    swept = 0
    patterns = _patterns()
    assert len(patterns) > 150, "the sweep found suspiciously few patterns; discovery is broken"
    for path, pattern in patterns:
        source = pattern.pattern if isinstance(pattern.pattern, str) else repr(pattern.pattern)
        if source in ALLOWED or path.startswith(REDACTION_MODULES):
            continue
        keyed = re.search(r"\['([A-Za-z_]\w*)'\]$", path)  # a pattern held in a dict, such as a binding table
        name = keyed.group(1) if keyed else path.rsplit(".", 1)[-1].split("[", 1)[0]
        used = methods.get(name, set())
        anchored = bool(used) and used <= {"match", "fullmatch"}
        swept += 1
        finding = _sweep(pattern, anchored)
        if finding:
            how = "match" if anchored else "search"
            flagged.append(f"{path} ({how}): /{source[:120]}/ {finding}")
    assert swept > 50, "most patterns were skipped; the sweep no longer covers the package"
    assert not flagged, (
        "superlinear regular expressions (see the module docstring for the options):\n  "
        + "\n  ".join(flagged)
    )


def test_allowlist_entries_name_real_patterns_and_give_reasons():
    sources = {p.pattern for _, p in _patterns() if isinstance(p.pattern, str)}
    for source, reason in ALLOWED.items():
        assert source in sources, f"stale allowlist entry: {source!r}"
        assert len(reason.split()) >= 5, f"explain why /{source}/ is safe"


class _NeverReturns:
    """Stands in for an exponential pattern: the search does not come back within the stall limit."""

    pattern = "never"
    flags = 0

    def search(self, text: str) -> None:
        time.sleep(60)

    match = search


def test_the_sweep_flags_quadratic_and_stalled_patterns_and_passes_linear_ones():
    # The sweep has to keep biting: a quadratic pattern, one that never returns, and a linear control.
    assert _sweep(re.compile(r"\w+\s*=\s*\w+!"), anchored=False) is not None
    stalled = _sweep(_NeverReturns(), anchored=False, stall=2.0)  # type: ignore[arg-type]
    assert stalled is not None and "stalled" in stalled
    # Starts at a literal, so a long run of letters is skipped in one pass: linear.
    assert _sweep(re.compile(r"=[a-z]+;"), anchored=False) is None


def test_the_possessive_form_of_a_flagged_pattern_is_linear():
    # The supported fix: the third-party engine's possessive quantifiers never backtrack.
    fixed = regex.compile(r"\w++\s*+=\s*+\w++!")
    started = time.perf_counter()
    assert fixed.search("a" * 100_000 + "x") is None
    assert time.perf_counter() - started < 1.0


REDACTION_SHAPES: dict[str, Any] = {
    "letters": lambda n: "a" * n + "x",
    "blanks": lambda n: " " * n + "x",
    "brackets": lambda n: "[" * n,
    "slashes": lambda n: "/" * n,
    "dots": lambda n: "a." * (n // 2),
    "path segments": lambda n: "a/" * (n // 2),
    "words": lambda n: "a_" * (n // 2),
    "lines": lambda n: "a\n" * (n // 2),
    "assignments": lambda n: "k=v " * (n // 4),
    "spaced assignment": lambda n: "a=" + " " * n + "b",
    "calls": lambda n: "f(a=" * (n // 4),
    "colons": lambda n: "x:" * (n // 2),
    "operators": lambda n: "token => '" * (n // 10),
    "comparisons": lambda n: "if token == " * (n // 12),
    "quoted passwords": lambda n: 'password="' * (n // 10),
    "record keys": lambda n: '{"webhook_secret": ' * (n // 19),
    "block scalars": lambda n: "password: |\n  " * (n // 15),
    "headers": lambda n: '-H "X-Token: ' * (n // 12),
    "connection strings": lambda n: ";Pwd=" * (n // 5),
    "registry logins": lambda n: "docker login " * (n // 13),
    "xml elements": lambda n: "<password>" * (n // 10),
    "provider tokens": lambda n: "sk-proj-" * (n // 8),
    "glued tokens": lambda n: "_sk-proj-" * (n // 9),
    "escaped tokens": lambda n: "\\nsk-proj-" * (n // 9),
    "json web tokens": lambda n: "eyJ-" * (n // 4),
    "dotted web tokens": lambda n: "eyJ." * (n // 4),
    "urls": lambda n: "https://u:p@h/?" * (n // 15),
    "bare authorities": lambda n: "https://" + "u:" * (n // 2),
    "webhook hosts": lambda n: "a." * (n // 2) + "webhook.office.comx",
    "authorization schemes": lambda n: "Bearer a " * (n // 9),
    "key blocks": lambda n: "-----BEGIN PRIVATE KEY-----\n" * (n // 28),
    "unterminated key block": lambda n: "-----BEGIN PRIVATE KEY-----" + "A" * n,
}


def test_redaction_scales_linearly_on_hostile_text():
    """Quadrupling the text must not cost sixteen times as much (linear is four)."""
    slow: list[str] = []
    for shape, build in REDACTION_SHAPES.items():
        small, large = build(32_000), build(128_000)
        small_time = _timed(sanitize_text, small, repeat=2)
        large_time = _timed(sanitize_text, large, repeat=2)
        if large_time > 0.5 and large_time / max(small_time, 1e-9) > 9:
            slow.append(f"{shape}: {small_time:.2f} s for 32 KB, {large_time:.2f} s for 128 KB")
    assert not slow, "sanitize_text is superlinear on:\n  " + "\n  ".join(slow)
