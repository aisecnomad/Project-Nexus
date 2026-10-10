"""CI entry point: ``python -m shadowscan.mappings.validate``.

Validates the packaged threat and control catalogs and their rules: entry and
rule ids, references that resolve to a catalog of the rule file's kind, and
tags, capabilities, kinds and metadata values the scanner knows. Every problem
is printed, one per line.
"""

from __future__ import annotations

import argparse
import sys

from shadowscan.mappings import MappingIndex
from shadowscan.mappings.loader import builtin_mapping_dir
from shadowscan.mappings.schema import MappingCatalogError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the packaged threat and control mapping catalogs.")
    parser.parse_args(argv)
    try:
        index = MappingIndex.from_directory(builtin_mapping_dir())
    except MappingCatalogError as exc:
        print("Mapping validation failed:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    counts = (len(index.catalogs), len(index.entries), len(index.rules))
    print("Validated {} catalogs, {} entries and {} rules.".format(*counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
