"""Draw the calibration and scored corpora from the committed frame snapshot.

``python -m tools.realbench.sample --frames tools/realbench/frames --workdir DIR --manifest OUT.json``

The draw is a pre-registered, seeded procedure:

1. Calibration first (seed ``CALIBRATION_SEED``, ``CALIBRATION_PER_STRATUM`` per
   sampled stratum). Calibration repositories are used only to make each tool
   run and to read its report; their owners are excluded from the scored draw.
2. Scored strata in ``QUOTAS`` order (seed ``SCORED_SEED``). Within a stratum,
   a frame (one list, npm keyword or GitLab topic) is chosen uniformly at random
   and then a candidate uniformly from that frame, without replacement, until
   the quota of eligible repositories is met.
3. The purposive sets from ``purposive.json`` are added in file order. They are
   not replaced when ineligible.

A candidate is eligible when it is not excluded, its owner has no repository in
the corpus yet (sampled strata only), a shallow clone of its default branch
succeeds within ``CLONE_TIMEOUT_S``, the checkout is at most ``MAX_BYTES`` and
``MAX_FILES``, its tree differs from every accepted tree, and (sampled strata
only) it contains at least one source or infrastructure file. Every attempt and
its outcome is logged. Accepted repositories get neutral, shuffled identifiers
so that a directory name reveals nothing about the stratum.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.realbench.frames import load_frames

SCORED_SEED = 20261008
CALIBRATION_SEED = 1
CALIBRATION_PER_STRATUM = 2
QUOTAS: dict[str, int] = {
    "gh-agents": 25,
    "gh-mcp": 15,
    "gh-genai": 20,
    "npm-ai": 15,
    "gitlab-ai": 20,
    "gh-general": 20,
    "npm-general": 10,
    "gitlab-general": 15,
}
MAX_BYTES = 250 * 1024 * 1024
MAX_FILES = 25_000
CLONE_TIMEOUT_S = 600
PARALLEL_CLONES = 6

CODE_EXT = frozenset(
    (
        ".py", ".ipynb", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".kts",
        ".scala", ".cs", ".fs", ".vb", ".rb", ".php", ".rs", ".swift", ".m", ".mm", ".c", ".h", ".cc",
        ".cpp", ".cxx", ".hpp", ".dart", ".lua", ".pl", ".r", ".jl", ".ex", ".exs", ".erl", ".clj",
        ".hs", ".ml", ".sh", ".bash", ".zsh", ".ps1", ".tf", ".hcl", ".bicep", ".sql", ".vue",
        ".svelte", ".astro", ".groovy", ".zig", ".nim", ".cr", ".sol",
    )
)  # fmt: skip

# Repositories that must never enter the corpus: the tools under evaluation (and
# this repository), the probe repositories used while writing adapters, and the
# lists the frames came from.
EXCLUDED = frozenset(
    k.lower()
    for k in (
        "github.com/aisecnomad/project-nexus",
        "github.com/cisco-ai-defense/aibom",
        "github.com/cisco-ai-defense/mcp-scanner",
        "github.com/msaad00/agent-bom",
        "github.com/defend-ai-tech-inc/agent-discover-scanner",
        "github.com/snyk/agent-scan",
        "github.com/invariantlabs-ai/mcp-scan",
        "github.com/safedep/vet",
        "github.com/ak2dev/agentguard-v1",
        "github.com/giggsoinc/patronai",
        "github.com/cyclonedx/cdxgen",
        "github.com/knostic/agentsonar",
        "github.com/alebgl77/open-shadow-ai",
        "github.com/mizcausevic-dev/shadow-ai-detector",
        "github.com/backslash-security/claw-hunter",
        "github.com/shamo0/ai-detector",
        "github.com/langchain-ai/react-agent",
        "github.com/modelcontextprotocol/quickstart-resources",
        "github.com/pallets/click",
    )
)


@dataclass(frozen=True)
class Candidate:
    url: str
    key: str  # host/path, lower case
    owner: str  # host/first path segment, lower case
    host: str
    stratum: str
    frame: str


def repo_key(url: str) -> tuple[str, str, str] | None:
    """``(key, owner, host)`` for a GitHub or GitLab repository URL."""
    url = url.strip().rstrip("/").removesuffix(".git")
    for host in ("github.com", "gitlab.com"):
        marker = f"://{host}/"
        if marker in url:
            path = url.split(marker, 1)[1].split("#")[0].split("?")[0]
            parts = [p for p in path.split("/") if p]
            if "-" in parts:  # GitLab's /-/ separates the project from its pages
                parts = parts[: parts.index("-")]
            if len(parts) < 2:
                return None
            if host == "github.com":
                parts = parts[:2]
            key = f"{host}/{'/'.join(parts)}".lower()
            return key, f"{host}/{parts[0]}".lower(), host.split(".")[0]
    return None


def frame_candidates(frames: list[dict[str, Any]], stratum: str) -> list[list[Candidate]]:
    pools: list[list[Candidate]] = []
    for frame in frames:
        pool: list[Candidate] = []
        for entry in frame["candidates"]:
            url = entry if isinstance(entry, str) else entry["url"]
            parsed = repo_key(url)
            if parsed is None:
                continue
            key, owner, host = parsed
            pool.append(Candidate(url, key, owner, host, stratum, frame["name"]))
        pools.append(pool)
    return pools


def two_stage(pools: list[list[Candidate]], rng: random.Random) -> Iterator[Candidate]:
    """Pick a frame uniformly, then a candidate uniformly from it, without replacement."""
    pools = [list(p) for p in pools]
    seen: set[str] = set()
    while True:
        live = [i for i, p in enumerate(pools) if p]
        if not live:
            return
        pool = pools[rng.choice(live)]
        cand = pool.pop(rng.randrange(len(pool)))
        if cand.key not in seen:
            seen.add(cand.key)
            yield cand


def _git(args: list[str], cwd: Path | None = None, timeout: int = 120) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=True
    ).stdout.strip()


def inspect_checkout(path: Path) -> dict[str, Any]:
    files = 0
    size = 0
    ext: Counter[str] = Counter()
    for root, dirs, names in os.walk(path):
        if ".git" in dirs:
            dirs.remove(".git")
        for name in names:
            full = Path(root) / name
            try:
                st = full.lstat()
            except OSError:
                continue
            files += 1
            size += st.st_size
            ext[full.suffix.lower()] += 1
    return {
        "files": files,
        "bytes": size,
        "ext": dict(ext.most_common(12)),
        "code": any(e in CODE_EXT for e in ext),
    }


def clone(cand_url: str, dest: Path) -> dict[str, Any]:
    """Shallow-clone the default branch; return facts or ``{"reject": reason}``."""
    if dest.exists():
        shutil.rmtree(dest)
    try:
        _git(
            ["clone", "--quiet", "--depth", "1", "--no-tags", "--single-branch", cand_url, str(dest)],
            timeout=CLONE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        return {"reject": "clone-timeout"}
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        detail = (exc.stderr or "").strip().splitlines()
        return {"reject": "clone-failed", "detail": (detail[-1] if detail else "")[:160]}
    facts = inspect_checkout(dest)
    facts["sha"] = _git(["rev-parse", "HEAD"], cwd=dest)
    facts["tree"] = _git(["rev-parse", "HEAD^{tree}"], cwd=dest)
    facts["commit_date"] = _git(["log", "-1", "--format=%cI"], cwd=dest)
    facts["branch"] = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dest)
    if facts["bytes"] > MAX_BYTES:
        facts["reject"] = "too-large-bytes"
    elif facts["files"] > MAX_FILES:
        facts["reject"] = "too-many-files"
    elif facts["files"] == 0:
        facts["reject"] = "empty"
    if "reject" in facts:
        shutil.rmtree(dest, ignore_errors=True)
    return facts


class Drawer:
    def __init__(self, workdir: Path, log: Any) -> None:
        self.workdir = workdir
        self.staging = workdir / "staging"
        self.staging.mkdir(parents=True, exist_ok=True)
        self.log = log
        self.owners: set[str] = set()
        self.keys: set[str] = set(EXCLUDED)
        self.trees: set[str] = set()
        self._facts: dict[str, dict[str, Any]] = {}

    def _stage(self, cand: Candidate) -> dict[str, Any]:
        if cand.key not in self._facts:
            name = hashlib.sha256(cand.key.encode()).hexdigest()[:16]
            self._facts[cand.key] = {**clone(cand.url, self.staging / name), "staged": name}
        return self._facts[cand.key]

    def _record(self, phase: str, cand: Candidate, outcome: str, facts: dict[str, Any] | None = None) -> None:
        row = {
            "phase": phase,
            "stratum": cand.stratum,
            "frame": cand.frame,
            "url": cand.url,
            "outcome": outcome,
        }
        if facts:
            row.update({k: facts[k] for k in ("sha", "files", "bytes", "detail") if k in facts})
        self.log.write(json.dumps(row) + "\n")

    def _decide(self, phase: str, cand: Candidate, facts: dict[str, Any], need_code: bool) -> bool:
        if "reject" in facts:
            self._record(phase, cand, facts["reject"], facts)
            return False
        if facts["tree"] in self.trees:
            self._record(phase, cand, "duplicate-tree", facts)
            return False
        if need_code and not facts["code"]:
            self._record(phase, cand, "no-source-files", facts)
            return False
        self._record(phase, cand, "accepted", facts)
        return True

    def draw(
        self, phase: str, stratum: str, pools: list[list[Candidate]], quota: int, seed: int
    ) -> list[dict[str, Any]]:
        rng = random.Random(f"{seed}:{stratum}")
        stream = two_stage(pools, rng)
        accepted: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=PARALLEL_CLONES) as pool:
            while len(accepted) < quota:
                window: list[Candidate] = []
                for cand in stream:
                    if cand.key in self.keys:
                        self._record(phase, cand, "excluded-or-taken")
                        continue
                    if cand.owner in self.owners:
                        self._record(phase, cand, "owner-taken")
                        continue
                    window.append(cand)
                    if len(window) == PARALLEL_CLONES:
                        break
                if not window:
                    break
                staged = list(pool.map(self._stage, window))
                for cand, facts in zip(window, staged, strict=True):
                    if len(accepted) >= quota or cand.owner in self.owners:
                        if len(accepted) < quota:
                            self._record(phase, cand, "owner-taken")
                        continue
                    if self._decide(phase, cand, facts, need_code=True):
                        self._accept(cand, facts)
                        accepted.append(self._entry(cand, facts, "sampled"))
        return accepted

    def _accept(self, cand: Candidate, facts: dict[str, Any]) -> None:
        self.owners.add(cand.owner)
        self.keys.add(cand.key)
        self.trees.add(facts["tree"])

    @staticmethod
    def _entry(cand: Candidate, facts: dict[str, Any], kind: str) -> dict[str, Any]:
        return {
            "url": cand.url,
            "host": cand.host,
            "stratum": cand.stratum,
            "frame": cand.frame,
            "set": kind,
            "sha": facts["sha"],
            "tree": facts["tree"],
            "branch": facts["branch"],
            "commit_date": facts["commit_date"],
            "files": facts["files"],
            "bytes": facts["bytes"],
            "top_ext": facts["ext"],
            "staged": facts["staged"],
        }

    def purposive(self, stratum: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for item in entries:
            parsed = repo_key(item["url"])
            if parsed is None:
                raise ValueError(f"bad purposive URL {item['url']}")
            key, owner, host = parsed
            cand = Candidate(item["url"], key, owner, host, stratum, "purposive")
            if key in self.keys:
                self._record("scored", cand, "excluded-or-taken")
                continue
            facts = self._stage(cand)
            if self._decide("scored", cand, facts, need_code=False):
                self._accept(cand, facts)
                entry = self._entry(cand, facts, stratum)
                entry["purposive"] = {"traits": item["traits"], "reason": item["reason"]}
                out.append(entry)
        return out

    def place(self, entries: list[dict[str, Any]], prefix: str, dest: Path, seed: int) -> None:
        """Assign shuffled neutral ids and move checkouts into ``dest/<id>``."""
        dest.mkdir(parents=True, exist_ok=True)
        order = list(range(len(entries)))
        random.Random(f"{seed}:ids").shuffle(order)
        width = max(3, len(str(len(entries))))
        for number, index in enumerate(order, start=1):
            entry = entries[index]
            entry["id"] = f"{prefix}{number:0{width}d}"
            target = dest / entry["id"]
            if target.exists():
                shutil.rmtree(target)
            shutil.move(str(self.staging / entry.pop("staged")), target)
        entries.sort(key=lambda e: e["id"])

    def cleanup(self) -> None:
        shutil.rmtree(self.staging, ignore_errors=True)


def frames_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.glob("*.jsonl.gz")):
        with gzip.open(path, "rb") as fh:
            digest.update(path.name.encode() + b"\0" + hashlib.sha256(fh.read()).digest())
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=Path, required=True)
    parser.add_argument("--purposive", type=Path, default=Path(__file__).with_name("purposive.json"))
    parser.add_argument(
        "--workdir", type=Path, required=True, help="checkouts go to corpus/ and calibration/"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--calibration-manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True, help="gzipped JSONL of every draw attempt")
    args = parser.parse_args(argv)

    frames = load_frames(args.frames)
    missing = set(QUOTAS) - set(frames)
    if missing:
        parser.error(f"frame snapshot lacks strata {sorted(missing)}")
    purposive = json.loads(args.purposive.read_text(encoding="utf-8"))
    started = datetime.now(UTC).replace(microsecond=0).isoformat()
    args.workdir.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.log, "wt", encoding="utf-8") as log:
        drawer = Drawer(args.workdir, log)
        # Purposive repositories are reserved first so the random draws skip them.
        reserved = {
            parsed[0]
            for stratum in ("hard-negatives", "config-positives")
            for item in purposive[stratum]
            if (parsed := repo_key(item["url"])) is not None
        }
        drawer.keys |= reserved
        calibration: list[dict[str, Any]] = []
        for stratum in QUOTAS:
            pools = frame_candidates(frames[stratum], stratum)
            calibration += drawer.draw(
                "calibration", stratum, pools, CALIBRATION_PER_STRATUM, CALIBRATION_SEED
            )
        drawer.place(calibration, "c", args.workdir / "calibration", CALIBRATION_SEED)
        scored: list[dict[str, Any]] = []
        for stratum, quota in QUOTAS.items():
            pools = frame_candidates(frames[stratum], stratum)
            got = drawer.draw("scored", stratum, pools, quota, SCORED_SEED)
            if len(got) < quota:
                print(f"warning: {stratum} filled {len(got)}/{quota}", file=sys.stderr)
            scored += got
        drawer.keys -= reserved
        for stratum in ("hard-negatives", "config-positives"):
            scored += drawer.purposive(stratum, purposive[stratum])
        drawer.place(scored, "r", args.workdir / "corpus", SCORED_SEED)
        drawer.cleanup()
    meta = {
        "created_at": started,
        "frames_sha256": frames_digest(args.frames),
        "scored_seed": SCORED_SEED,
        "calibration_seed": CALIBRATION_SEED,
        "quotas": QUOTAS,
        "max_bytes": MAX_BYTES,
        "max_files": MAX_FILES,
        "clone": "git clone --depth 1 --no-tags --single-branch (no submodules, LFS smudge skipped)",
    }
    args.manifest.write_text(json.dumps({**meta, "repos": scored}, indent=1) + "\n", encoding="utf-8")
    args.calibration_manifest.write_text(
        json.dumps({**meta, "repos": calibration}, indent=1) + "\n", encoding="utf-8"
    )
    counts = Counter(e["stratum"] for e in scored)
    print(json.dumps({"scored": len(scored), "calibration": len(calibration), "by_stratum": counts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
