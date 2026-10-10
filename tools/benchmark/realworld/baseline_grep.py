"""Naive keyword baselines for the real-world benchmark (standard library only).

``python -I baseline_grep.py ROOT any|code`` prints a JSON object with the files that mention
an AI vendor or framework by name. ``any`` searches every text file (prose included);
``code`` skips prose and lock files. These are the floor: what a one-line ``grep -ri`` scores,
which shows how much the real tools add. The pattern is fixed here and does not use the
benchmark registry.
"""

from __future__ import annotations

import json
import os
import re
import sys

PATTERN = re.compile(
    r"\b(openai|anthropic|langchain|langgraph|llama[-_ ]?index|crewai|autogen|ollama|gemini|claude|mcp"
    r"|model context protocol|chatgpt|gpt-?[345])\b",
    re.IGNORECASE,
)
PROSE = {".md", ".rst", ".txt", ".mdx", ".adoc"}
LOCKS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "cargo.lock", "go.sum",
    "gemfile.lock", "composer.lock",
}  # fmt: skip
SKIP_DIRS = {".git", "node_modules"}
MAX_BYTES = 1_000_000


def scan(root: str, mode: str) -> dict[str, object]:
    hits: list[str] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            path = os.path.join(current, name)
            ext = os.path.splitext(name)[1].lower()
            if os.path.islink(path) or (mode == "code" and (ext in PROSE or name.lower() in LOCKS)):
                continue
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if b"\x00" in data[:8000]:
                continue
            if PATTERN.search(data.decode("utf-8", errors="replace")):
                hits.append(os.path.relpath(path, root))
    return {"mode": mode, "hits": len(hits), "files": sorted(hits)[:50]}


if __name__ == "__main__":
    print(json.dumps(scan(sys.argv[1], sys.argv[2])))
