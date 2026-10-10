"""Build the v2 corpus manifest: the v1 entries unchanged, plus the v2 repository and endpoint entries.

Every input is an explicit file, so the build can be repeated:

- the v1 manifest (``corpus.json``), copied through unchanged;
- ``candidates-S1.tsv``: the repository candidates with their design category and
  stratum, fixed before any was attached;
- ``attach-S1.list`` and ``attach-S2.list``: one line per attached repository,
  ``<clone_url> <checkout directory> [design group]``;
- ``labels/<group>-chunk-<n>.tsv``: the three blinded labelers' rows (B2, C2, D2);
- ``adjudication.json``: a decision, with the cited lines, for each repository the
  labelers do not all agree on.

The build fails closed. A repository with a missing labeler row, an undecided
disagreement, or evidence that cites no existing path stops the build, and the
manifest is not written. The disagreements are always written to
``disagreements.json`` so they can be adjudicated from the cited lines.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from tools.benchmark_realworld.cases import HOME_VIEW_PATHS, detect_license, validate_manifest
from tools.benchmark_realworld.score import cohen_kappa

LABELERS = ("B2", "C2", "D2")  # labeler slots A, B and C in the manifest
LABELS = ("agent", "llm", "none", "ambiguous")
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
REPO_IDS_START = 42  # v1 used rw-01..rw-41
ENDPOINT_IDS_START = 85
# A cited item counts as a path when it has a slash or a file extension.
PATH_EXTENSION = re.compile(
    r"\.(py|ts|tsx|js|jsx|mjs|go|rs|java|kt|cs|rb|php|swift|md|rst|txt|yml|yaml|json|toml|ini|cfg|"
    r"xml|gradle|lock|ipynb|sh|lua|vue|svelte|html|css|csproj|sln)$",
    re.IGNORECASE,
)


def read_list(path: Path) -> list[tuple[str, Path, str]]:
    """``(clone_url, checkout directory, design group)`` per attached repository."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        url, dest = fields[0], Path(fields[1])
        group = fields[2] if len(fields) > 2 else ""
        rows.append((url, dest, group))
    return rows


def read_candidates(path: Path) -> dict[str, tuple[str, str]]:
    """Lower-cased ``owner/repo`` -> (design category, design stratum)."""
    table: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t") if "\t" in line else line.split()
        category, repo, stratum = fields[0], fields[1], fields[2]
        table[repo.lower()] = (category, stratum)
    return table


def owner_repo(url: str) -> str:
    return url.removeprefix("https://github.com/").rstrip("/")


def slug(repo: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", repo.split("/", 1)[1].lower()).strip("-")


def head_sha(root: Path) -> str:
    done = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def read_labeler_rows(labels_dir: Path) -> dict[str, dict[str, dict[str, Any]]]:
    """labeler -> checkout directory -> row. Malformed rows stop the build."""
    rows: dict[str, dict[str, dict[str, Any]]] = {group: {} for group in LABELERS}
    for group in LABELERS:
        for path in sorted(labels_dir.glob(f"{group}-chunk-*.tsv")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                fields = line.split("\t")
                if len(fields) != 5:
                    raise SystemExit(f"{path}:{number}: expected 5 tab-separated columns")
                directory, label, confidence, evidence, rationale = fields
                if label not in LABELS or confidence not in CONFIDENCE_RANK:
                    raise SystemExit(f"{path}:{number}: bad label or confidence")
                directory = directory.rstrip("/")
                if directory in rows[group]:
                    raise SystemExit(f"{path}:{number}: second row for {directory} from {group}")
                items = [item.strip() for item in evidence.split(";")]
                rows[group][directory] = {
                    "label": label,
                    "confidence": confidence,
                    "evidence": [item for item in items if item and item != "-"],
                    "rationale": rationale,
                }
    return rows


def cited_paths(items: list[str]) -> list[str]:
    """Repository-relative paths in the evidence items: ``path``, ``path (symbol)`` or ``path: note``.

    A path may contain spaces, so only a parenthesis or a colon ends it. A leading ``./``
    is removed; any other leading dot is part of the name (``.cursor``).
    """
    found = []
    for item in items:
        token = re.split(r"\s+\(|:\s", item.strip(), maxsplit=1)[0].strip()
        token = token.split(":", 1)[0]  # path:symbol keeps the path
        if token.startswith("./"):
            token = token[2:]
        if token and ("/" in token or PATH_EXTENSION.search(token)):
            found.append(token)
    return found


def fleiss_kappa(ratings: list[list[str]]) -> float | None:
    """Fleiss' kappa for a fixed number of raters per subject (here three)."""
    if not ratings:
        return None
    n = len(ratings[0])
    subjects = len(ratings)
    categories = sorted({value for row in ratings for value in row})
    p_bar = sum((sum(c * c for c in Counter(row).values()) - n) / (n * (n - 1)) for row in ratings) / subjects
    p_e = sum((sum(Counter(row)[cat] for row in ratings) / (subjects * n)) ** 2 for cat in categories)
    if p_e == 1:
        return None
    return (p_bar - p_e) / (1 - p_e)


def check_citations(cited: list[str], checkout: Path) -> tuple[list[str], list[str], list[str]]:
    """Split cited paths into (literal paths, paths that are bad, glob citations).

    Every literal path must exist in the checkout. A path that is absolute or has a ``..`` part
    points outside the checkout, so it is bad whatever exists. A glob is not a literal path and is
    returned for a warning only (protocol v2, section 4.2)."""
    literal: list[str] = []
    bad: list[str] = []
    globs: list[str] = []
    for p in cited:
        if p.startswith("/") or ".." in Path(p).parts:
            bad.append(p)
        elif any(ch in p for ch in "*?["):
            globs.append(p)
        else:
            literal.append(p)
            if not (checkout / p).exists():
                bad.append(p)
    return literal, bad, globs


def build(args: argparse.Namespace) -> int:
    root = args.checkout_root
    v1_doc = json.loads(args.v1.read_text(encoding="utf-8"))
    candidates = read_candidates(args.candidates)
    labels = read_labeler_rows(args.labels_dir)
    adjudication = (
        json.loads(args.adjudication.read_text(encoding="utf-8")) if args.adjudication.exists() else {}
    )
    decisions: dict[str, dict[str, Any]] = adjudication.get("decisions", {})

    problems: list[str] = []
    warnings: list[str] = []
    disagreements: list[dict[str, Any]] = []
    repo_entries: list[dict[str, Any]] = []
    unanimous = 0
    ratings_three: list[list[str]] = []
    ratings_binary: list[list[str]] = []
    pair_rows: dict[tuple[str, str], list[tuple[str, str]]] = {
        ("B2", "C2"): [],
        ("B2", "D2"): [],
        ("C2", "D2"): [],
    }

    for offset, (url, dest, _group) in enumerate(read_list(args.repo_list)):
        repo = owner_repo(url)
        rel = dest.relative_to(root).as_posix()
        if repo.lower() not in candidates:
            problems.append(f"{repo}: not in the candidate table")
            continue
        category, stratum = candidates[repo.lower()]
        rows: dict[str, dict[str, Any]] = {}
        for group in LABELERS:
            row = labels[group].get(str(dest))
            if row is not None:
                rows[group] = row
        missing = [group for group in LABELERS if group not in rows]
        if missing:
            problems.append(f"{repo}: no row from {missing}")
            continue
        names = {group: rows[group]["label"] for group in LABELERS}
        for a, b in pair_rows:
            pair_rows[(a, b)].append((names[a], names[b]))
        ratings_three.append([names[g] for g in LABELERS])
        if "ambiguous" not in names.values():
            ratings_binary.append(["none" if names[g] == "none" else "pos" for g in LABELERS])

        if len(set(names.values())) == 1:
            unanimous += 1
            adopted = names["B2"]
            confidence = min((rows[g]["confidence"] for g in LABELERS), key=lambda c: CONFIDENCE_RANK[c])
            evidence = list(dict.fromkeys(item for g in LABELERS for item in rows[g]["evidence"]))
            adjudicated = False
        else:
            disagreements.append({"dir": rel, "repo": repo, "rows": rows})
            decision = decisions.get(rel)
            if decision is None:
                problems.append(f"{repo}: labelers disagree ({names}) and no adjudication decision")
                continue
            if decision.get("label") not in LABELS or not decision.get("cited"):
                problems.append(f"{repo}: adjudication needs a label and cited lines")
                continue
            adopted = decision["label"]
            confidence = decision["confidence"]
            evidence = list(decision["cited"])
            adjudicated = True

        checkout = root / rel
        literal, bad, globs = check_citations(cited_paths(evidence), checkout)
        warnings += [f"{repo}: glob citation, not checked as a path: {g}" for g in globs]
        if bad:
            problems.append(f"{repo}: cited path missing or outside the checkout: {bad[:3]}")
            continue
        if not literal:
            problems.append(f"{repo}: no literal cited path for label {adopted}")
            continue
        repo_entries.append(
            {
                "id": f"rw-{REPO_IDS_START + offset:02d}-{slug(repo)}",
                "repo": repo,
                "url": f"https://github.com/{repo}",
                "dir": rel,
                "sha": head_sha(checkout),
                "license": detect_license(checkout),
                "stratum": stratum,
                "category": category,
                "label": adopted,
                "confidence": confidence,
                "labels": {"A": names["B2"], "B": names["C2"], "C": names["D2"]},
                "adjudicated": adjudicated,
                "evidence": evidence,
                "surfaces": ["repo"],
            }
        )

    endpoint_entries: list[dict[str, Any]] = []
    for offset, (url, dest, group) in enumerate(read_list(args.endpoint_list)):
        repo = owner_repo(url)
        rel = dest.relative_to(root).as_posix()
        checkout = root / rel
        matched = []
        for path in HOME_VIEW_PATHS:
            target = checkout / path
            if target.is_symlink():
                continue
            if (target.is_file() and target.stat().st_size > 0) or (
                target.is_dir() and any(target.iterdir())
            ):
                matched.append(path)
        endpoint_entries.append(
            {
                "id": f"rw-{ENDPOINT_IDS_START + offset}-{slug(repo)}",
                "repo": repo,
                "url": f"https://github.com/{repo}",
                "dir": rel,
                "sha": head_sha(checkout),
                "license": detect_license(checkout),
                "stratum": "dotfiles",
                "design": group or "unspecified",
                "label": "n/a",
                "confidence": "high",
                "home_paths": matched,
                "surfaces": ["home"],
            }
        )

    if problems:
        print("build stopped (fail closed); nothing written to the manifest:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        args.disagreements_out.write_text(json.dumps(disagreements, indent=2) + "\n", encoding="utf-8")
        return 2

    doc = {key: value for key, value in v1_doc.items() if key != "repos"}
    doc["version"] = 2
    doc["repos"] = list(v1_doc["repos"]) + repo_entries + endpoint_entries
    validate_manifest(doc)  # the same schema checks the runner applies

    kappa_pairs = {f"{a}-{b}": cohen_kappa(pairs) for (a, b), pairs in pair_rows.items()}
    agreement = {
        "subjects_repo_s1": len(repo_entries),
        "unanimous": unanimous,
        "disagreements": len(disagreements),
        "adjudicated_adopted": sum(entry["adjudicated"] for entry in repo_entries),
        "pairwise_cohen_kappa_three_way": kappa_pairs,
        "fleiss_kappa_three_way": fleiss_kappa(ratings_three),
        "fleiss_kappa_positive_vs_none": fleiss_kappa(ratings_binary),
        "warnings": warnings,
    }
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    args.agreement_out.write_text(json.dumps(agreement, indent=2) + "\n", encoding="utf-8")
    args.disagreements_out.write_text(json.dumps(disagreements, indent=2) + "\n", encoding="utf-8")
    args.report_out.write_text(_labelling_text(agreement, len(endpoint_entries)), encoding="utf-8")
    print(
        f"wrote {args.out}: {len(doc['repos'])} entries "
        f"({len(v1_doc['repos'])} v1, {len(repo_entries)} repo, {len(endpoint_entries)} endpoint)"
    )
    return 0


def _labelling_text(agreement: dict[str, Any], endpoint_count: int) -> str:
    def fmt(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.2f}"

    pairs = ", ".join(f"{k} {fmt(v)}" for k, v in agreement["pairwise_cohen_kappa_three_way"].items())
    return (
        f"Three blinded labelers (B2, C2, D2) labelled the {agreement['subjects_repo_s1']} repository "
        f"candidates added in v2. The v1 labels stand unchanged for the 41 earlier repositories. "
        f"Unanimous: {agreement['unanimous']}. Disagreements, each adjudicated by reading the cited "
        f"lines: {agreement['disagreements']}. Fleiss' kappa, three-way labels: "
        f"{fmt(agreement['fleiss_kappa_three_way'])}; positive versus none: "
        f"{fmt(agreement['fleiss_kappa_positive_vs_none'])}. Pairwise Cohen's kappa: {pairs}. "
        f"Endpoint entries ({endpoint_count}) are labelled by the path rule (protocol section 6), "
        f"so no labeler is involved. Labels are model-based, not human review.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--v1", type=Path, required=True, help="the v1 manifest (corpus.json)")
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--repo-list", type=Path, required=True)
    parser.add_argument("--endpoint-list", type=Path, required=True)
    parser.add_argument("--labels-dir", type=Path, required=True)
    parser.add_argument("--adjudication", type=Path, required=True)
    parser.add_argument("--checkout-root", type=Path, default=Path("/home/user"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--agreement-out", type=Path, required=True)
    parser.add_argument("--disagreements-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    return build(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
