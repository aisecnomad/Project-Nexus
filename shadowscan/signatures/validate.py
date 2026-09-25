"""CI entry point: ``python -m shadowscan.signatures.validate [PACK_DIR ...]``.

Per-signature shape rules live in :mod:`shadowscan.signatures.schema` and run
at load time. This module adds the checks that need the whole signature set:
regexes claimed by competing signatures and namespace hygiene of the built-in
packs.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from shadowscan.signatures.loader import Signature, builtin_signature_dir, load_signatures
from shadowscan.signatures.schema import NAMESPACE_CATEGORIES


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
            problems.append(f"{signal_type} regex {pattern!r} is claimed by competing signatures {', '.join(competing)}")
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
            problems.append(f"{signature.source}: {signature.id}: built-in signatures must use a known namespace")
    return problems


def validate_signature_set(signatures: Sequence[Signature]) -> list[str]:
    """Return every whole-set problem, in a stable order (empty when valid)."""
    return builtin_namespace_violations(signatures) + cross_signature_duplicates(signatures)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate YAML signature schemas and compile all regexes.")
    parser.add_argument("directories", nargs="*", help="Additional signature pack directories")
    parser.add_argument("--no-builtin", action="store_true", help="Validate only the supplied directories")
    parser.add_argument("--allow-signature-override", action="store_true", help="Allow custom packs to replace built-in signature IDs")
    args = parser.parse_args(argv)
    if args.no_builtin and not args.directories:
        parser.error("--no-builtin requires at least one directory")
    try:
        signatures = load_signatures(args.directories, include_builtin=not args.no_builtin, allow_override=args.allow_signature_override)
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
