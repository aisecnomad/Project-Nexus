"""Why does ShadowScan call a scan incomplete? Count the causes over the repositories where it did.

``python -m tools.benchmark.realworld.diagnose_shadowscan --manifest manifest.jsonl --corpus CORPUS
--tool-root TOOL_ROOT --results results --out results/shadowscan-incomplete-causes.json [--workers 2]``

A diagnostic, not a score. For every repository where the default ``shadowscan`` row is partial or an
incomplete-scan error, the scan is repeated (same command, same sandbox) and each error, and each warning that
says coverage is incomplete, is mapped to a fixed cause label (warnings that leave a scan complete are
dropped). Only the labels and counts are stored: no path, snippet or message leaves the sandbox.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from tools.benchmark.realworld.adapters import ToolEnv
from tools.benchmark.realworld.run import load_rows
from tools.benchmark.realworld.sandbox import Sandbox

CAUSES = (
    ("file over max_file_size", re.compile(r"exceeds max_file_size|over max_file_size")),
    ("credential detection timed out (MatchTimeoutError)", re.compile(r"MatchTimeoutError")),
    ("structured sanitization limit (SanitizationLimitError)", re.compile(r"SanitizationLimitError")),
    ("invalid structured configuration syntax", re.compile(r"invalid structured configuration syntax")),
    ("malformed MCP or agent configuration", re.compile(r"MCP servers must be|must be an object")),
    ("checkout missing, empty or unsafe", re.compile(r"checkout is missing, empty or unsafe")),
    ("symbolic link whose target is unavailable", re.compile(r"symbolic link")),
    ("non-empty build or vendor directory skipped", re.compile(r"set default_excludes: false")),
    ("syntax-tree node limit (max_ast_nodes)", re.compile(r"max_ast_nodes|partially analyzed")),
    ("connector deadline", re.compile(r"deadline|timed out")),
    ("incomplete source lexical analysis", re.compile(r"incomplete source lexical analysis")),
    ("source did not parse (import analysis skipped)", re.compile(r"source did not parse")),
    ("binary or undecodable content in a source file", re.compile(r"binary or undecodable")),
    ("MCP analysis limit (syntax-tree nodes, tool names)", re.compile(r"MCP syntax-tree node|MCP tool-name")),
    ("import analysis limit (syntax-tree nodes)", re.compile(r"source binding AST limit")),
)  # fmt: skip


def label(message: str) -> str:
    return next((name for name, pattern in CAUSES if pattern.search(message)), "other")


def counts(level: str, message: str) -> bool:
    """Whether a diagnostic can make a scan incomplete (exit 3).

    Every error does. A warning does only when it says the coverage is incomplete: skipped build or vendor
    directories, skip-listed oversize files (images, lockfiles, archives) and unparsable files in test paths
    are disclosed as warnings that leave the scan complete.
    """
    return level == "errors" or "coverage incomplete" in message


def extension(message: str) -> str:
    """The file extension a message names (``.json``), or its bare name; nothing else of the path is kept."""
    found = re.match(r"code\.filesystem: ([^:]+?): ", message)
    if not found:
        return ""
    name = found.group(1).rsplit("/", 1)[-1].lower()
    return name[name.rfind(".") :] if "." in name.lstrip(".") else name


def diagnose(row: dict[str, Any], corpus: Path, env: ToolEnv) -> dict[str, Any]:
    with env.sandbox.session(corpus / row["dir"]) as s:
        connector = {"name": "code.filesystem", "path": str(s.tree), "use_git": False}
        config = s.out / "shadowscan.yaml"
        config.write_text(json.dumps({"connectors": [connector]}))
        s.run([
            env.venv_bin("shadowscan", "python"), "-m", "shadowscan", "scan", "-c", str(config),
            "-f", "json", "-o", str(s.out / "report.json"),
        ])  # fmt: skip
        text = s.read(s.out / "report.json")
    if text is None:
        return {"id": row["id"], "causes": ["no report"]}
    report = json.loads(text)
    messages = [
        str(m)
        for st in report.get("stats", [])
        if isinstance(st, dict)
        for level in ("warnings", "errors")
        for m in st.get(level, [])
        if counts(level, str(m))
    ]
    oversize = sorted({extension(m) for m in messages if label(m) == "file over max_file_size"})
    return {
        "id": row["id"],
        "causes": sorted({label(m) for m in messages}) or ["incomplete, no message"],
        "oversize_extensions": oversize,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, default=Path("/opt/rwb/runs"))
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(argv)
    rows = {r["id"]: r for r in load_rows(args.manifest)}
    first = [
        json.loads(line)
        for line in (args.results / "shadowscan.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    todo = [rows[r["id"]] for r in first if r.get("partial") or str(r["note"]).startswith("incomplete scan")]
    tool_root = args.tool_root.resolve()
    env = ToolEnv(root=tool_root, sandbox=Sandbox(args.scratch, timeout=600, expose=(tool_root,)))
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        found = list(pool.map(lambda row: diagnose(row, args.corpus, env), todo))
    tally = Counter(cause for item in found for cause in item["causes"])
    document = {
        "scans_repeated": len(found),
        "repositories_by_cause": dict(tally.most_common()),
        "oversize_extensions": dict(
            Counter(e for item in found for e in item["oversize_extensions"]).most_common()
        ),
        "per_repository": {item["id"]: item["causes"] for item in found},
    }
    args.out.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(document["repositories_by_cause"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
