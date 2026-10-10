"""Command line entry point: ``python -m tools.discovery_benchmark <command>``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.discovery_benchmark import compare, evidence, fetch, report, score
from tools.discovery_benchmark.adapters import ToolConfig
from tools.discovery_benchmark.adapters.registry import adapters_by_id, all_adapters
from tools.discovery_benchmark.corpus import Corpus, CorpusError, load_corpus
from tools.discovery_benchmark.runner import RunPolicy, renormalize, run_matrix


def _repo_ids(corpus: Corpus, text: str | None) -> set[str] | None:
    """The corpus repository ids named by a comma-separated ``--repos``; None selects every one."""
    if not text:
        return None
    ids = {item.strip() for item in text.split(",") if item.strip()}
    unknown = sorted(ids - {r.id for r in corpus.repos})
    if unknown:
        raise CorpusError("unknown repository id(s): " + ", ".join(unknown))
    return ids


def cmd_fetch(args: argparse.Namespace) -> int:
    corpus = load_corpus(Path(args.corpus))
    outcome = (
        fetch.verify_all(corpus, Path(args.dest)) if args.verify else fetch.fetch_all(corpus, Path(args.dest))
    )
    bad = 0
    for repo_id, status in outcome.items():
        print(f"{repo_id}\t{status}")
        if status not in {"OK"} and not (len(status) == 40 and not status.startswith("ERROR")):
            bad += 1
    return 1 if bad else 0


def cmd_evidence(args: argparse.Namespace) -> int:
    root = Path(args.checkouts)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    targets = [p for p in sorted(root.iterdir()) if p.is_dir()] if args.all else [Path(args.repo_dir)]
    for target in targets:
        ev = evidence.extract_to_file(target, out / f"{target.name}.json")
        print(f"{target.name}\tfiles={ev.files}\tfacts={len(ev.facts)}\ttolerated={len(ev.tolerated)}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    corpus = load_corpus(Path(args.corpus))
    cfg = ToolConfig.load(Path(args.tools))
    selected = all_adapters()
    if args.only:
        wanted = set(args.only.split(","))
        selected = [a for a in selected if a.spec.id in wanted]
    policy = RunPolicy(
        timeout=args.timeout,
        as_user=args.as_user,
        extra_path=tuple(p for p in cfg.setting("extra_path").split(":") if p),
        keep_network=args.keep_network,
    )
    repos = _repo_ids(corpus, args.repos)
    manifest = run_matrix(
        corpus, selected, cfg, Path(args.checkouts), Path(args.out), policy, workers=args.workers, repos=repos
    )
    statuses: dict[str, int] = {}
    for result in manifest["results"]:
        statuses[result["status"]] = statuses.get(result["status"], 0) + 1
    print(
        json.dumps(
            {
                "runs": len(manifest["results"]),
                "statuses": statuses,
                "tool_versions": manifest["tool_versions"],
            }
        )
    )
    return 0


def cmd_renormalize(args: argparse.Namespace) -> int:
    manifest = renormalize(Path(args.out), all_adapters())
    statuses: dict[str, int] = {}
    for result in manifest["results"]:
        statuses[result["status"]] = statuses.get(result["status"], 0) + 1
    print(json.dumps({"runs": len(manifest["results"]), "statuses": statuses}))
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    corpus = load_corpus(Path(args.corpus))
    manifest = json.loads(Path(args.runs).read_text(encoding="utf-8"))
    adapters = adapters_by_id()
    scopes = {tid: a.spec.categories for tid, a in adapters.items()}
    names = {tid: a.spec.name for tid, a in adapters.items()}
    metrics = score.score_all(corpus, manifest, scopes, names, _repo_ids(corpus, args.repos))
    Path(args.out).write_text(json.dumps(metrics, indent=1) + "\n", encoding="utf-8")
    for tool_id, t in metrics["tools"].items():
        v = t["value_level"]["in_scope"]
        print(
            f"{tool_id}\tin-scope value F1={v['f1']}\trepo-level F1={t['repo_level']['f1']}"
            f"\tincomplete runs={t['incomplete_runs']['count']}"
        )
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    corpus = load_corpus(Path(args.corpus))
    classes = {r.id: r.klass for r in corpus.repos}
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    if args.baseline_runs:
        runs = json.loads(Path(args.baseline_runs).read_text(encoding="utf-8"))
        baseline = compare.with_run_incompleteness(baseline, runs)
    current = json.loads(Path(args.current).read_text(encoding="utf-8"))
    tools = args.tools.split(",") if args.tools else None
    results = compare.compare(
        baseline,
        current,
        classes,
        tools=tools,
        f1_tolerance=args.f1_tolerance,
        repos=_repo_ids(corpus, args.repos),
    )
    for item in results:
        state = "ok" if item.ok else "REGRESSION"
        f1 = f"F1 {item.baseline_f1} -> {item.current_f1}"
        recall = f"repo recall {item.baseline_recall} -> {item.current_recall}"
        incomplete = f"incomplete runs {item.baseline_incomplete} -> {item.current_incomplete}"
        print(f"{item.tool}\t{state}\t{f1}\t{recall}\t{incomplete}")
        for reason in item.regressions:
            print(f"\t{reason}")
        for repo_id in item.newly_clean:
            print(f"\tnow clean: {repo_id}")
    if args.out:
        Path(args.out).write_text(
            json.dumps([r.to_dict() for r in results], indent=1) + "\n", encoding="utf-8"
        )
    return 0 if all(r.ok for r in results) else 1


def cmd_report(args: argparse.Namespace) -> int:
    corpus = load_corpus(Path(args.corpus))
    metrics = json.loads(Path(args.metrics).read_text(encoding="utf-8"))
    text = report.render(metrics, corpus, title=args.title)
    Path(args.out).write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.discovery_benchmark")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fetch", help="fetch (or --verify) every corpus repository at its pinned commit")
    p.add_argument("--corpus", required=True)
    p.add_argument("--dest", required=True)
    p.add_argument("--verify", action="store_true")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("evidence", help="extract labeling evidence from checkouts")
    p.add_argument("--checkouts", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--all", action="store_true", help="every directory under --checkouts")
    p.add_argument("--repo-dir", help="one checkout directory")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("run", help="run every tool on every repository")
    p.add_argument("--corpus", required=True)
    p.add_argument("--tools", required=True, help="JSON file with tool binaries")
    p.add_argument("--checkouts", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--as-user", default=None, help="unprivileged account to run tools as (setpriv)")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--only", help="comma-separated tool ids")
    p.add_argument("--repos", help="comma-separated repo ids")
    p.add_argument("--keep-network", action="store_true", help="do not point tools at a dead proxy")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("renormalize", help="re-map stored tool output with the current adapters")
    p.add_argument("--out", required=True, help="run directory holding runs.json")
    p.set_defaults(func=cmd_renormalize)

    p = sub.add_parser("score", help="score runs.json against the corpus")
    p.add_argument("--corpus", required=True)
    p.add_argument("--runs", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--repos", help="comma-separated repo ids a partial run covered (default: all)")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("compare", help="fail when metrics regress against a committed baseline")
    p.add_argument("--corpus", required=True)
    p.add_argument("--baseline", required=True, help="baseline metrics.json")
    p.add_argument("--current", required=True, help="new metrics.json")
    p.add_argument(
        "--baseline-runs",
        help="the baseline's runs.json, for metrics scored before incomplete runs were recorded",
    )
    p.add_argument("--repos", help="compare only these comma-separated repo ids (a partial run)")
    p.add_argument("--tools", help="comma-separated tool ids (default: every tool in the baseline)")
    p.add_argument("--f1-tolerance", type=float, default=0.01)
    p.add_argument("--out", help="write the comparison as JSON")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("report", help="render metrics.json as Markdown")
    p.add_argument("--corpus", required=True)
    p.add_argument("--metrics", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--title", default="Shadow AI agent discovery benchmark")
    p.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result: int = args.func(args)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2
    return result


if __name__ == "__main__":
    sys.exit(main())
