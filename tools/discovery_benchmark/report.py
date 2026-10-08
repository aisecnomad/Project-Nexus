"""Render ``metrics.json`` as a Markdown report."""

from __future__ import annotations

from typing import Any

from tools.discovery_benchmark.corpus import Corpus
from tools.discovery_benchmark.taxonomy import CATEGORIES


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.0f}%"


def _num(value: float | None) -> str:
    return "n/a" if value is None else f"{value:g}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def _ordered_tools(metrics: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    tools = metrics["tools"]

    def key(item: tuple[str, dict[str, Any]]) -> tuple[float, float]:
        value = item[1]["value_level"]["in_scope"]["f1"]
        detect = item[1]["repo_level"]["f1"]
        return (-(value if value is not None else -1), -(detect if detect is not None else -1))

    return sorted(tools.items(), key=key)


def render(metrics: dict[str, Any], corpus: Corpus, *, title: str) -> str:
    c = metrics["corpus"]
    run = metrics["run"]
    out: list[str] = [f"# {title}", ""]
    out.append(
        f"Corpus: {c['repos']} pinned repositories ({c['positive']} positive, {c['control']} control, "
        f"{c['nearmiss']} near-miss) carrying {c['expected_facts']} expected facts. "
        f"Run started {run.get('started')} and finished {run.get('finished')} on "
        f"{(run.get('host') or {}).get('platform')} with {run.get('workers')} parallel workers; "
        f"timings therefore include contention and are indicative only."
    )
    out.append("")
    out.append(
        "Ground truth was labeled in this session from dependency manifests, imports, committed "
        "configuration paths, code constructs and infrastructure resources (see the README). It is "
        "author-written evidence, not independent human review."
    )
    out.append("")
    skipped = run.get("tools_skipped") or {}
    if skipped:
        out.append("Tools skipped in this run:")
        out.append("")
        out.extend(f"- `{tool}`: {reason}" for tool, reason in sorted(skipped.items()))
        out.append("")
    out.append("## Headline")
    out.append("")
    rows: list[list[str]] = []
    for _tool_id, t in _ordered_tools(metrics):
        if t["runs"].get("skipped", 0) == c["repos"]:
            continue
        v = t["value_level"]["in_scope"]
        va = t["value_level"]["all"]
        cat = t["category_level"]["in_scope"]
        r = t["repo_level"]
        s = t["seconds"]
        rows.append(
            [
                f"{t['name']} ({t.get('version') or '?'})",
                ", ".join(t["categories"]),
                f"{_pct(v['precision'])} / {_pct(v['recall'])} / {_pct(v['f1'])}",
                f"{_pct(cat['precision'])} / {_pct(cat['recall'])} / {_pct(cat['f1'])}",
                f"{_pct(va['f1'])}",
                f"{r['positives_detected']}/{r['positives']}",
                f"{r['controls_flagged']}/{r['controls']}",
                f"{r['nearmiss_flagged']}/{r['nearmiss']}",
                f"{_num(s['median'])} / {_num(s['p90'])} / {_num(s['max'])}",
                f"{t['runs'].get('failed', 0)} failed, {t['runs'].get('timeout', 0)} timed out",
            ]
        )
    out.append(
        _table(
            [
                "Tool",
                "Declared categories",
                "In-scope value P / R / F1",
                "In-scope category P / R / F1",
                "All-category value F1",
                "Positives detected",
                "Controls flagged",
                "Near-misses flagged",
                "Seconds median / p90 / max",
                "Runs",
            ],
            rows,
        )
    )
    out.append("")
    out.append(
        "In-scope metrics count only the categories a tool declares; the all-category value F1 "
        "charges every tool for every expected fact in the corpus. Repository-level detection "
        "counts a repository as flagged when the tool reports any in-scope fact."
    )
    out.append("")
    out.append("## Value-level F1 by category")
    out.append("")
    header = ["Tool", *[f"{cat} (n={c['expected_by_category'][cat]})" for cat in CATEGORIES]]
    rows = []
    for _tool_id, t in _ordered_tools(metrics):
        if t["runs"].get("skipped", 0) == c["repos"]:
            continue
        cells = [t["name"]]
        for cat in CATEGORIES:
            bc = t["value_level"]["by_category"][cat]
            if cat not in t["categories"]:
                cells.append(f"out of scope ({bc['tp']}/{bc['fp']}/{bc['fn']})")
            else:
                cells.append(f"{_pct(bc['f1'])} ({bc['tp']}/{bc['fp']}/{bc['fn']})")
        rows.append(cells)
    out.append(_table(header, rows))
    out.append("")
    out.append("Cells read F1 (true positives / false positives / false negatives).")
    out.append("")
    out.append("## Near-miss and control repositories")
    out.append("")
    negatives = [r for r in corpus.repos if r.klass != "positive"]
    header = [
        "Repository",
        "Class",
        *[t["name"] for _, t in _ordered_tools(metrics) if t["runs"].get("skipped", 0) != c["repos"]],
    ]
    rows = []
    for repo in negatives:
        cells = [repo.path, repo.klass]
        for _, t in _ordered_tools(metrics):
            if t["runs"].get("skipped", 0) == c["repos"]:
                continue
            pr = t["per_repo"].get(repo.id) or {}
            fps = pr.get("fp") or []
            cells.append(
                "clean"
                if not fps and pr.get("status") in {"ok", "failed"}
                else (", ".join(fps) if fps else pr.get("status", "?"))
            )
        rows.append(cells)
    out.append(_table(header, rows))
    out.append("")
    out.append("## Per-repository results (positives)")
    out.append("")
    header = [
        "Repository",
        "Expected",
        *[t["name"] for _, t in _ordered_tools(metrics) if t["runs"].get("skipped", 0) != c["repos"]],
    ]
    rows = []
    for repo in corpus.by_class("positive"):
        cells = [repo.path, str(len(repo.expected))]
        for _, t in _ordered_tools(metrics):
            if t["runs"].get("skipped", 0) == c["repos"]:
                continue
            pr = t["per_repo"].get(repo.id) or {}
            status = pr.get("status", "missing")
            if status in {"timeout", "error", "missing", "skipped"}:
                cells.append(status)
            else:
                suffix = "" if status == "ok" else " (tool reported failure)"
                cells.append(
                    f"{len(pr.get('tp') or [])}/{len(pr.get('fp') or [])}/{len(pr.get('fn') or [])}{suffix}"
                )
        rows.append(cells)
    out.append(_table(header, rows))
    out.append("")
    out.append(
        "Cells read true positives / false positives / false negatives at value level, all categories."
    )
    out.append("")
    out.append("## Misses and false positives by tool")
    out.append("")
    for _tool_id, t in _ordered_tools(metrics):
        if t["runs"].get("skipped", 0) == c["repos"]:
            continue
        fn_counter: dict[str, int] = {}
        fp_counter: dict[str, int] = {}
        for pr in t["per_repo"].values():
            for fact in pr.get("fn") or []:
                fn_counter[fact] = fn_counter.get(fact, 0) + 1
            for fact in pr.get("fp") or []:
                fp_counter[fact] = fp_counter.get(fact, 0) + 1
        top_fn = sorted(fn_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
        top_fp = sorted(fp_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
        out.append(f"### {t['name']}")
        out.append("")
        out.append("Most missed facts: " + (", ".join(f"{f} ({n})" for f, n in top_fn) if top_fn else "none"))
        out.append("")
        out.append(
            "Most frequent false positives: "
            + (", ".join(f"{f} ({n})" for f, n in top_fp) if top_fp else "none")
        )
        out.append("")
    return "\n".join(out).rstrip() + "\n"
