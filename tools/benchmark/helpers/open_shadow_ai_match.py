"""Run Open Shadow AI's squid parser and catalog matcher over one log file.

Usage: python -I open_shadow_ai_match.py <catalog dir> <access.log>

Runs inside the Open Shadow AI virtual environment; it needs no database.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from shadai.engine.catalog_loader import (  # type: ignore[import-not-found]
    build_catalog_index,
    load_catalog_from_yaml,
)
from shadai.engine.matcher import CatalogMatcher  # type: ignore[import-not-found]
from shadai.parsers.proxy.squid import SquidAccessLogParser  # type: ignore[import-not-found]


def main(argv: list[str]) -> int:
    catalog, log = Path(argv[1]), Path(argv[2])
    items = load_catalog_from_yaml(str(catalog / "builtin"), str(catalog / "local"))
    matcher = CatalogMatcher(build_catalog_index(items))
    parser = SquidAccessLogParser()
    events = []
    for line in log.read_text(encoding="utf-8").splitlines():
        event = parser.parse(line)
        if event is None:
            events.append({"parsed": False, "match": None})
            continue
        match = matcher.match_event(event)
        item = match.catalog_item_id if match else None
        events.append({"parsed": True, "domain": event.domain, "match": item})
    print(json.dumps({"events": events}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
