"""Validate annotations, measure agreement and freeze the labels.

``python -m tools.realbench.labels validate --corpus DIR --manifest corpus.json FILE.jsonl...``
``python -m tools.realbench.labels agree A.jsonl B.jsonl``
``python -m tools.realbench.labels queue A.jsonl B.jsonl --output disagreements.json``
``python -m tools.realbench.labels freeze A.jsonl B.jsonl --adjudication ADJ.jsonl --output labels.json``
``python -m tools.realbench.labels merge --batches batches.json --side A --dir DIR --output OUT.jsonl``

Evidence is checked mechanically: the cited path must be a regular file inside
the checkout, the line must exist, and the excerpt must appear on that line or
an adjacent one (whitespace-insensitive; ``<redacted>`` matches anything).
Excerpts are redacted again before anything is written to the repository.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

LABELS = ("agent", "llm", "none")
SUBTYPES = frozenset({"A1", "A2", "A3", "A4", "A5", "A6", "L1", "L2", "L3"})
TRAITS = frozenset(
    {
        "agent-word", "user-agent", "provider-name", "product-name", "mcp-acronym", "key-patterns",
        "key-verification", "ai-names-as-data", "prompt-word", "chatbot", "non-generative-ml", "ai-prose",
    }
)  # fmt: skip
CRITERIA = SUBTYPES | {"none-note", "assistant"}
CONFIDENCE = ("high", "medium", "low")
MAX_EXCERPT = 100

_SECRET = re.compile(
    r"(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}|AIza[0-9A-Za-z_\-]{30,}|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|hf_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"
    r"|(?=[A-Za-z0-9+/_\-]*\d)(?=[A-Za-z0-9+/_\-]*[A-Za-z])[A-Za-z0-9+/_\-]{40,})"
)
_ASSIGNED_SECRET = re.compile(
    r"""(?i)((?:api[_-]?key|token|secret|password|passwd|bearer)["']?\s*[:=]\s*["']?)([^"'\s,;)]{8,})"""
)


def redact(text: str) -> str:
    """Remove anything shaped like a credential and clip to ``MAX_EXCERPT`` characters."""
    text = _SECRET.sub("<redacted>", text)
    text = _ASSIGNED_SECRET.sub(lambda m: m.group(1) + "<redacted>", text)
    text = " ".join(text.split())
    return text if len(text) <= MAX_EXCERPT else text[: MAX_EXCERPT - 3] + "..."


def load(path: Path) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
    return rows


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def excerpt_matches(lines: list[str], line: int, excerpt: str) -> bool:
    """True when the excerpt is on or next to ``line`` (``<redacted>`` and a final ``...`` match anything)."""
    core = excerpt.strip()
    if core.endswith("..."):
        core = core[:-3]
    parts = [re.escape(_norm(p)) for p in core.split("<redacted>")]
    pattern = re.compile(".*?".join(parts))
    window = lines[max(0, line - 2) : line + 1]
    return any(pattern.search(_norm(candidate)) for candidate in window)


def check_evidence(root: Path, item: dict[str, Any]) -> str | None:
    rel = str(item.get("path", ""))
    if not rel or rel.startswith("/") or ".." in Path(rel).parts:
        return f"bad path {rel!r}"
    path = root / rel
    try:
        resolved = path.resolve()
    except OSError:
        return f"unresolvable {rel}"
    if not resolved.is_relative_to(root.resolve()) or path.is_symlink() or not path.is_file():
        return f"not a regular file in the checkout: {rel}"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"unreadable {rel}: {exc}"
    line = item.get("line")
    if not isinstance(line, int) or not 1 <= line <= max(1, len(lines)):
        return f"{rel}: line {line} outside 1..{len(lines)}"
    excerpt = str(item.get("excerpt", ""))
    if excerpt and not excerpt_matches(lines, line, excerpt):
        return f"{rel}:{line}: excerpt not found near the line"
    return None


def validate_row(row: dict[str, Any], root: Path | None) -> list[str]:
    problems = []
    if row.get("label") not in LABELS:
        problems.append(f"label {row.get('label')!r}")
    for key in ("assistant_artifacts", "ml_only"):
        if not isinstance(row.get(key), bool):
            problems.append(f"{key} must be true/false")
    bad_sub = set(row.get("subtypes") or []) - SUBTYPES
    if bad_sub:
        problems.append(f"unknown subtypes {sorted(bad_sub)}")
    bad_traits = set(row.get("traits") or []) - TRAITS
    if bad_traits:
        problems.append(f"unknown traits {sorted(bad_traits)}")
    if row.get("label") in ("agent", "llm"):
        prefix = "A" if row["label"] == "agent" else "L"
        if not any(s.startswith(prefix) for s in row.get("subtypes") or []):
            problems.append(f"label {row['label']} needs a {prefix} subtype")
        if not row.get("evidence"):
            problems.append("positive label without evidence")
    if row.get("label") == "llm" and any(s.startswith("A") for s in row.get("subtypes") or []):
        problems.append("llm label with an A subtype")
    if row.get("confidence") not in CONFIDENCE:
        problems.append(f"confidence {row.get('confidence')!r}")
    evidence = row.get("evidence") or []
    if not isinstance(evidence, list) or len(evidence) > 5:
        problems.append("evidence must be a list of at most 5 items")
        evidence = []
    for item in evidence:
        if item.get("criterion") not in CRITERIA:
            problems.append(f"criterion {item.get('criterion')!r}")
        if root is not None:
            issue = check_evidence(root, item)
            if issue:
                problems.append(issue)
    return problems


def cohen_kappa(a: list[str], b: list[str]) -> float | None:
    n = len(a)
    if n == 0:
        return None
    observed = sum(x == y for x, y in zip(a, b, strict=True)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return None if expected == 1 else (observed - expected) / (1 - expected)


def _by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["id"] in out:
            raise ValueError(f"duplicate annotation for {row['id']}")
        out[row["id"]] = row
    return out


def agreement(a_rows: list[dict[str, Any]], b_rows: list[dict[str, Any]]) -> dict[str, Any]:
    a, b = _by_id(a_rows), _by_id(b_rows)
    ids = sorted(set(a) & set(b))
    views = {
        "label": lambda r: r["label"],
        "t1_genai": lambda r: str(r["label"] != "none"),
        "t2_agent": lambda r: str(r["label"] == "agent"),
        "assistant_artifacts": lambda r: str(r["assistant_artifacts"]),
    }
    out: dict[str, Any] = {
        "n": len(ids),
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
    }
    for name, view in views.items():
        xa = [view(a[i]) for i in ids]
        xb = [view(b[i]) for i in ids]
        agree = sum(x == y for x, y in zip(xa, xb, strict=True))
        out[name] = {
            "agreement": agree / len(ids) if ids else None,
            "kappa": cohen_kappa(xa, xb),
            "confusion_a_by_b": dict(
                sorted(Counter(f"{x}|{y}" for x, y in zip(xa, xb, strict=True)).items())
            ),
        }
    return out


def disagreements(a_rows: list[dict[str, Any]], b_rows: list[dict[str, Any]]) -> list[str]:
    a, b = _by_id(a_rows), _by_id(b_rows)
    return sorted(
        i
        for i in set(a) & set(b)
        if a[i]["label"] != b[i]["label"] or a[i]["assistant_artifacts"] != b[i]["assistant_artifacts"]
    )


def _merge_evidence(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int]] = set()
    merged = []
    for group in groups:
        for item in group or []:
            key = (str(item.get("path")), int(item.get("line") or 0))
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                {
                    "path": item.get("path"),
                    "line": item.get("line"),
                    "criterion": item.get("criterion"),
                    "excerpt": redact(str(item.get("excerpt", ""))),
                }
            )
    return merged[:6]


def freeze(
    a_rows: list[dict[str, Any]], b_rows: list[dict[str, Any]], adjudication: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    a, b = _by_id(a_rows), _by_id(b_rows)
    adj = _by_id(adjudication) if adjudication else {}
    missing = sorted(set(a) ^ set(b))
    if missing:
        raise ValueError(f"annotations missing on one side: {missing}")
    out = []
    for i in sorted(a):
        ra, rb = a[i], b[i]
        disputed = ra["label"] != rb["label"] or ra["assistant_artifacts"] != rb["assistant_artifacts"]
        if disputed and i not in adj:
            raise ValueError(f"{i}: annotators disagree and there is no adjudication")
        final = adj.get(i) if disputed else None
        label = final["label"] if final else ra["label"]
        assistant = final["assistant_artifacts"] if final else ra["assistant_artifacts"]
        if final:
            subtypes = sorted(set(final.get("subtypes") or []))
        else:
            subtypes = sorted(set(ra.get("subtypes") or []) | set(rb.get("subtypes") or []))
        if label != "agent":
            subtypes = [s for s in subtypes if not s.startswith("A")]
        if label == "none":
            subtypes = []
        evidence_groups = [final.get("evidence") or []] if final else []
        evidence_groups += [ra.get("evidence") or [], rb.get("evidence") or []]
        if label != "none":
            evidence_groups = [[e for e in g if e.get("criterion") != "none-note"] for g in evidence_groups]
        out.append(
            {
                "id": i,
                "label": label,
                "assistant_artifacts": assistant,
                "ml_only": label == "none" and bool(ra.get("ml_only") or rb.get("ml_only")),
                "subtypes": subtypes,
                "traits": sorted(set(ra.get("traits") or []) | set(rb.get("traits") or []))
                if label == "none"
                else [],
                "evidence": _merge_evidence(*evidence_groups),
                "provenance": {
                    "a": ra["label"],
                    "b": rb["label"],
                    "a_assistant": ra["assistant_artifacts"],
                    "b_assistant": rb["assistant_artifacts"],
                    "a_confidence": ra.get("confidence"),
                    "b_confidence": rb.get("confidence"),
                    "adjudicated": bool(final),
                    "reason": redact(str(final.get("reason", ""))) if final else "",
                },
            }
        )
    return out


def merge(batches: list[list[str]], directory: Path) -> list[dict[str, Any]]:
    """One annotator's rows from its batch files: only each batch's own ids, redacted, sorted by id."""
    rows: dict[str, dict[str, Any]] = {}
    for number, ids in enumerate(batches, start=1):
        path = directory / f"batch-{number:02d}.jsonl"
        for row in load(path):
            if row.get("id") not in ids:
                continue  # a line written into the wrong batch file is not this batch's annotation
            if row["id"] in rows:
                raise ValueError(f"{row['id']} annotated twice in {path.name}")
            row = dict(row)
            row["evidence"] = [
                {**e, "excerpt": redact(str(e.get("excerpt", "")))} for e in row.get("evidence") or []
            ]
            row["notes"] = redact(str(row.get("notes", "")))[:300]
            rows[row["id"]] = row
    missing = sorted({i for ids in batches for i in ids} - set(rows))
    if missing:
        raise ValueError(f"no annotation for {missing}")
    return [rows[i] for i in sorted(rows)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--corpus", type=Path, required=True)
    v.add_argument("--manifest", type=Path, required=True)
    v.add_argument("files", type=Path, nargs="+")
    g = sub.add_parser("agree")
    g.add_argument("a", type=Path)
    g.add_argument("b", type=Path)
    q = sub.add_parser("queue")
    q.add_argument("a", type=Path)
    q.add_argument("b", type=Path)
    q.add_argument("--output", type=Path, required=True)
    f = sub.add_parser("freeze")
    f.add_argument("a", type=Path)
    f.add_argument("b", type=Path)
    f.add_argument("--adjudication", type=Path)
    f.add_argument("--output", type=Path, required=True)
    m = sub.add_parser("merge")
    m.add_argument("--batches", type=Path, required=True)
    m.add_argument("--side", choices=("A", "B"), required=True)
    m.add_argument("--dir", type=Path, required=True)
    m.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "merge":
        batches = json.loads(args.batches.read_text(encoding="utf-8"))[args.side]
        merged = merge(batches, args.dir)
        args.output.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in merged), encoding="utf-8"
        )
        print(f"{len(merged)} annotation(s)")
        return 0
    if args.command == "validate":
        ids = {r["id"] for r in json.loads(args.manifest.read_text(encoding="utf-8"))["repos"]}
        bad = 0
        for file in args.files:
            seen: Counter[str] = Counter()
            for row in load(file):
                seen[row.get("id", "?")] += 1
                problems = [] if row.get("id") in ids else [f"unknown id {row.get('id')!r}"]
                problems += validate_row(row, args.corpus / row["id"] if row.get("id") in ids else None)
                for p in problems:
                    bad += 1
                    print(f"{file.name}:{row.get('id')}: {p}")
            for i, count in seen.items():
                if count > 1:
                    bad += 1
                    print(f"{file.name}:{i}: annotated {count} times")
        print(f"{bad} problem(s)")
        return 1 if bad else 0
    a_rows = load(args.a)
    b_rows = load(args.b)
    if args.command == "agree":
        print(json.dumps(agreement(a_rows, b_rows), indent=1))
    elif args.command == "queue":
        queue = disagreements(a_rows, b_rows)
        args.output.write_text(json.dumps(queue, indent=1) + "\n", encoding="utf-8")
        print(f"{len(queue)} disagreement(s)")
    else:
        adjudication = load(args.adjudication) if args.adjudication else []
        frozen = freeze(a_rows, b_rows, adjudication)
        args.output.write_text(
            json.dumps({"labels": frozen, "agreement": agreement(a_rows, b_rows)}, indent=1) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(Counter(r["label"] for r in frozen)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
