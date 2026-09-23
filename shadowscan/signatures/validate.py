"""CI entry point: ``python -m shadowscan.signatures.validate [PACK_DIR ...]``."""

from __future__ import annotations

import argparse
import sys

from shadowscan.signatures.loader import load_signatures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate YAML signature schemas and compile all regexes.")
    parser.add_argument("directories", nargs="*", help="Additional signature pack directories")
    parser.add_argument("--no-builtin", action="store_true", help="Validate only the supplied directories")
    args = parser.parse_args(argv)
    if args.no_builtin and not args.directories:
        parser.error("--no-builtin requires at least one directory")
    try:
        signatures = load_signatures(args.directories, include_builtin=not args.no_builtin)
        if not signatures:
            raise ValueError("no signature YAML files found")
    except (ValueError, OSError) as exc:
        print(f"Signature validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Validated {len(signatures)} signatures and {sum(len(s.signals) for s in signatures)} signals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
