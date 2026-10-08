"""CI entry point: ``python -m shadowscan.signatures.validate [PACK_DIR ...]``.

Per-signature shape rules live in :mod:`shadowscan.signatures.schema` and run
at load time. This module adds the checks that need the whole signature set:
regexes claimed by competing signatures and namespace hygiene of the built-in
packs.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from itertools import islice

from shadowscan.signatures.loader import Signature, builtin_signature_dir, load_signatures
from shadowscan.signatures.schema import NAMESPACE_CATEGORIES

# One mebichar of the measured worst case for credential patterns: markdown
# link lists dense in the keywords that pass the literal prefilter, with the
# dot/hyphen-rich runs that make keyword patterns re-scan. Deterministic by
# construction (no randomness) so timings are comparable across runs.
_THROUGHPUT_LINE = (
    "- [awesome-api-key-manager](https://api.key-manager.example-host.io/docs/access-token) "
    "manage every API key, access token, client secret, password and credential store.\n"
)
_THROUGHPUT_CHARS = 1_048_576
_THROUGHPUT_ATTEMPTS = 3
_THROUGHPUT_MATCH_CAP = 50


def _regexes(signature: Signature) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for signal in signature.signals:
        out.extend((signal.type, pattern) for pattern in signal.patterns)
        if signal.type == "domain":
            out.extend(("domain", value) for value in signal.values if value.startswith("re:"))
    return out


def cross_signature_duplicates(signatures: Sequence[Signature]) -> list[str]:
    """Report identical regexes claimed by more than one non-heuristic signature.

    A regex shared by two product signatures cannot attribute an observation
    to either of them: every match would pin both, and the wrong one may win.
    Vendor-neutral ``heuristic.*`` signatures may legitimately restate a
    product idiom to attach a capability, so a duplicate is only an error when
    two or more non-heuristic signatures claim the same regex for the same
    signal type.
    """
    owners: dict[tuple[str, str], list[Signature]] = {}
    for signature in signatures:
        for key in dict.fromkeys(_regexes(signature)):
            owners.setdefault(key, []).append(signature)
    problems: list[str] = []
    for (signal_type, pattern), claimants in sorted(owners.items()):
        competing = sorted(s.id for s in claimants if s.category != "heuristic")
        if len(competing) > 1:
            problems.append(
                f"{signal_type} regex {pattern!r} is claimed by competing signatures {', '.join(competing)}"
            )
    return problems


def builtin_namespace_violations(signatures: Sequence[Signature]) -> list[str]:
    """Built-in signatures must use a namespace from the category table."""
    root = str(builtin_signature_dir())
    problems: list[str] = []
    for signature in signatures:
        if signature.source is None or not signature.source.startswith(root):
            continue
        namespace = signature.id.split(".", 1)[0]
        if namespace not in NAMESPACE_CATEGORIES:
            problems.append(
                f"{signature.source}: {signature.id}: built-in signatures must use a known namespace"
            )
    return problems


def secret_pattern_throughput(signatures: Sequence[Signature]) -> list[str]:
    """Reject secret patterns slower than the matcher's linear time allowance.

    The matcher grants each execution ``LINEAR_SECONDS_PER_MILLION_CHARS`` of
    work per million input characters (see :mod:`shadowscan.signatures.matcher`).
    A credential pattern that cannot sweep the keyword-dense worst-case corpus
    within that allowance would time out on real megabyte files and fail
    scans closed, so it must be rewritten rather than shipped. Timing takes
    the best of three attempts, which discards scheduler contention.
    """
    from shadowscan.signatures.matcher import LINEAR_SECONDS_PER_MILLION_CHARS

    corpus = _THROUGHPUT_LINE * (_THROUGHPUT_CHARS // len(_THROUGHPUT_LINE) + 1)
    corpus = corpus[:_THROUGHPUT_CHARS]
    allowance = LINEAR_SECONDS_PER_MILLION_CHARS * (_THROUGHPUT_CHARS / 1_000_000)
    problems: list[str] = []
    for signature in signatures:
        for signal in signature.signals:
            if signal.type != "secret":
                continue
            for pattern, compiled in zip(signal.patterns, signal.bounded_compiled, strict=True):
                best = None
                for _ in range(_THROUGHPUT_ATTEMPTS):
                    started = time.perf_counter()
                    try:
                        # Bound a pathological pattern instead of hanging the
                        # validator; a timeout is far beyond the allowance.
                        matches = compiled.finditer(corpus, timeout=4 * allowance, concurrent=False)
                        list(islice(matches, _THROUGHPUT_MATCH_CAP))
                    except TimeoutError:
                        best = 4 * allowance
                        break
                    elapsed = time.perf_counter() - started
                    best = elapsed if best is None or elapsed < best else best
                if best is not None and best > allowance:
                    problems.append(
                        f"{signature.id}: secret pattern {pattern!r} needs {best:.3f}s per "
                        f"{_THROUGHPUT_CHARS} chars; the matcher allows {allowance:.3f}s — "
                        "rewrite the pattern rather than raising budgets"
                    )
    return problems


def validate_signature_set(signatures: Sequence[Signature]) -> list[str]:
    """Return every whole-set problem, in a stable order (empty when valid)."""
    return (
        builtin_namespace_violations(signatures)
        + cross_signature_duplicates(signatures)
        + secret_pattern_throughput(signatures)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate YAML signature schemas and compile all regexes.")
    parser.add_argument("directories", nargs="*", help="Additional signature pack directories")
    parser.add_argument("--no-builtin", action="store_true", help="Validate only the supplied directories")
    parser.add_argument(
        "--allow-signature-override",
        action="store_true",
        help="Allow custom packs to replace built-in signature IDs",
    )
    args = parser.parse_args(argv)
    if args.no_builtin and not args.directories:
        parser.error("--no-builtin requires at least one directory")
    try:
        signatures = load_signatures(
            args.directories,
            include_builtin=not args.no_builtin,
            allow_override=args.allow_signature_override,
        )
        if not signatures:
            raise ValueError("no signature YAML files found")
        problems = validate_signature_set(signatures)
        if problems:
            raise ValueError("; ".join(problems))
    except (ValueError, OSError) as exc:
        print(f"Signature validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Validated {len(signatures)} signatures and {sum(len(s.signals) for s in signatures)} signals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
