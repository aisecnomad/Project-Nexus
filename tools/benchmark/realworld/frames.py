"""Candidate acquisition: where the benchmark's repositories come from.

This module is provenance tooling. The committed ``manifest.jsonl`` (with pinned
commit SHAs) is the benchmark artifact; the live registries and APIs queried
here change over time, so re-running this module yields different candidates.

Only unauthenticated public endpoints are used: the PyPI and npm registries, the Go
module index, the GitLab public projects API, and anonymous ``git`` reads. The
GitHub REST API is deliberately not used (it is not needed, and this benchmark
must not search GitHub with credentials that were issued for other work).
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from tools.benchmark.realworld.oracle import Index

USER_AGENT = "shadowscan-realworld-benchmark/1 (research; contact via repository issues)"
RESERVED_OWNERS = frozenset(
    {"sponsors", "orgs", "topics", "features", "marketplace", "settings", "apps", "login", "about",
     "collections", "search", "explore", "pricing", "enterprise", "site", "customer-stories", "readme",
     "security", "trending"}
)  # fmt: skip
_REPO_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_GITHUB_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
_SCP_REPO = re.compile(r"git@([A-Za-z0-9.-]+):(.+)")
AI_NAME = re.compile(
    r"(?i)(mcp|llm|agent|openai|anthropic|claude|gemini|gpt|langchain|langgraph|rag|ollama|copilot|genai|chatbot)"
)


@dataclass
class Candidate:
    url: str
    host: str
    owner: str
    repo: str
    frame: str
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.host}/{self.owner}/{self.repo}".lower()


def canonical(url: str, frame: str, meta: dict[str, Any] | None = None) -> Candidate | None:
    """Normalise a repository URL only after validating its complete origin and path."""
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url) or "\\" in url:
        return None
    cleaned = url.strip().removeprefix("git+")
    scp = _SCP_REPO.fullmatch(cleaned)
    if scp:
        cleaned = f"ssh://git@{scp.group(1)}/{scp.group(2)}"
    elif "://" not in cleaned:
        cleaned = "https://" + cleaned
    try:
        parsed = urllib.parse.urlsplit(cleaned)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https", "ssh", "git"} or host not in {"github.com", "gitlab.com"}:
            return None
        if parsed.password is not None or (
            parsed.username is not None and not (parsed.scheme == "ssh" and parsed.username == "git")
        ):
            return None
        if (
            parsed.port is not None
            and parsed.port != {"http": 80, "https": 443, "ssh": 22, "git": 9418}[parsed.scheme]
        ):
            return None
    except ValueError:
        return None
    path = parsed.path
    if host == "gitlab.com":
        for marker in ("/-/", "/tree/", "/blob/"):
            path = path.split(marker, 1)[0]
    segments = path.strip("/").split("/")
    if len(segments) < 2 or any(
        part in {"", ".", ".."} or not _REPO_SEGMENT.fullmatch(part) for part in segments
    ):
        return None
    if host == "github.com":
        segments = segments[:2]
        if not _GITHUB_OWNER.fullmatch(segments[0]) or segments[0].lower() in RESERVED_OWNERS:
            return None
    elif segments[0].lower() in {"explore", "users", "groups", "-", "help"}:
        return None
    segments[-1] = segments[-1].removesuffix(".git")
    if segments[-1] in {"", ".", ".."}:
        return None
    return Candidate(
        f"https://{host}/{'/'.join(segments)}", host, segments[0], segments[-1], frame, meta or {}
    )


class Http:
    """A tiny cached JSON client; the cache makes a sampling run reproducible and cheap to resume."""

    def __init__(self, cache: Path, pause: float = 0.0) -> None:
        self.cache = cache
        self.cache.mkdir(parents=True, exist_ok=True)
        self.pause = pause

    def get(self, url: str, *, accept: str = "application/json", binary: bool = False) -> Any:
        key = hashlib.sha256((accept + url).encode()).hexdigest()
        path = self.cache / key
        if path.exists():
            raw = path.read_bytes()
        else:
            raw = self._fetch(url, accept)
            path.write_bytes(raw)
        return raw if binary else json.loads(raw)

    def _fetch(self, url: str, accept: str) -> bytes:
        last: Exception | None = None
        for attempt in range(4):
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data: bytes = resp.read()
                if self.pause:
                    time.sleep(self.pause)
                return data
            except urllib.error.HTTPError as exc:
                if exc.code in {404, 410}:
                    return b"null"
                last = exc
                time.sleep(2 * (attempt + 1) if exc.code in {429, 500, 502, 503} else 1)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last = exc
                time.sleep(1 + attempt)
        raise RuntimeError(f"giving up on {url}: {last}")


def _parallel(items: list[Any], fn: Callable[[Any], Any], workers: int) -> list[Any]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


# --- PyPI ------------------------------------------------------------------


def pypi_candidates(
    http: Http, index: Index, seed: int, n_names: int, since: str, workers: int = 8
) -> tuple[list[Candidate], list[Candidate]]:
    """A uniform random sample of PyPI project names, split by whether they depend on an LLM/agent package."""
    listing = http.get("https://pypi.org/simple/", accept="application/vnd.pypi.simple.v1+json")
    names = sorted(p["name"] for p in listing["projects"])
    chosen = random.Random(seed).sample(names, n_names)

    def one(name: str) -> Candidate | None:
        doc = http.get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        if not doc:
            return None
        info = doc["info"]
        uploads = [u.get("upload_time_iso_8601", "") for u in doc.get("urls", [])]
        released = max(uploads, default="")
        if not released or released < since:
            return None
        urls = dict(info.get("project_urls") or {})
        urls["__home"] = info.get("home_page") or ""
        ordered = sorted(
            urls.items(), key=lambda kv: 0 if re.search(r"(?i)source|repo|code|github|gitlab", kv[0]) else 1
        )
        cand = next((c for _, u in ordered if u and (c := canonical(u, "pypi"))), None)
        if cand is None:
            return None
        deps = {re.split(r"[\s;<>=!~\[(]", d, maxsplit=1)[0] for d in (info.get("requires_dist") or [])}
        classes = {index.tier_class.get(index.tier[t]) for d in deps if (t := index.pypi_dist(d))}
        cand.meta = {
            "ecosystem": "pypi", "package": name, "version": info.get("version"), "released": released[:10],
            "ai_dep": bool(classes & {"agent", "llm"}), "ml_dep": "ml" in classes,
            "adjacent_dep": "adjacent" in classes,
        }  # fmt: skip
        return cand

    found = [c for c in _parallel(chosen, one, workers) if c is not None]
    return [c for c in found if c.meta["ai_dep"]], [
        c for c in found if not c.meta["ai_dep"] and not c.meta["adjacent_dep"]
    ]


# --- npm -------------------------------------------------------------------

NPM_AI_QUERIES = tuple(
    f"keywords:{k}"
    for k in (
        "mcp-server",
        "model-context-protocol",
        "langchain",
        "llm",
        "openai",
        "ai-agent",
        "anthropic",
        "claude",
        "rag",
        "ollama",
        "langgraph",
        "agents",
        "chatbot",
        "gemini",
    )  # fmt: skip
)
NPM_OTHER_QUERIES = tuple(
    f"keywords:{k}"
    for k in (
        "cli",
        "react",
        "utils",
        "parser",
        "logger",
        "eslint",
        "typescript",
        "express",
        "database",
        "testing",
        "date",
        "validation",
        "webpack",
        "vue",
        "markdown",
        "cache",
        "http",
        "css",
        "docker",
        "crypto",
    )  # fmt: skip
)


def npm_candidates(
    http: Http, index: Index, queries: tuple[str, ...], pages: int, since: str, frame: str
) -> list[Candidate]:
    found: dict[str, Candidate] = {}
    ai_keywords = re.compile(
        r"(?i)(mcp|llm|openai|anthropic|claude|gpt|langchain|agent|rag\b|gemini|ollama|ai\b|chatbot)"
    )
    for query in queries:
        for page in range(pages):
            text = urllib.parse.quote(query)
            doc = http.get(f"https://registry.npmjs.org/-/v1/search?text={text}&size=250&from={page * 250}")
            for obj in (doc or {}).get("objects", []):
                pkg = obj.get("package", {})
                date = str(pkg.get("date", ""))
                repo_url = (pkg.get("links") or {}).get("repository")
                if not repo_url or date < since:
                    continue
                cand = canonical(repo_url, frame)
                if cand is None or cand.key in found:
                    continue
                keywords = pkg.get("keywords") or []
                if frame.endswith("other") and any(ai_keywords.search(k) for k in keywords):
                    continue
                cand.meta = {"ecosystem": "npm", "package": pkg.get("name"), "version": pkg.get("version"),
                             "released": date[:10], "query": query}  # fmt: skip
                found[cand.key] = cand
    return list(found.values())


def npm_has_ai_dep(http: Http, index: Index, package: str) -> bool:
    doc = http.get(f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}/latest")
    if not doc:
        return False
    names = [
        *(doc.get("dependencies") or {}),
        *(doc.get("devDependencies") or {}),
        *(doc.get("peerDependencies") or {}),
    ]
    return any(
        index.tier_class.get(index.tier[t]) in {"agent", "llm", "adjacent"}
        for n in names
        if (t := index.npm_pkg(n))
    )


# --- Go module index -------------------------------------------------------


def go_candidates(
    http: Http, seed: int, windows: int, since: str, until: str
) -> tuple[list[Candidate], list[Candidate]]:
    """Repositories behind Go modules first published in random windows of the public module index."""
    rng = random.Random(seed)
    start = time.mktime(time.strptime(since, "%Y-%m-%d"))
    end = time.mktime(time.strptime(until, "%Y-%m-%d"))
    seen: dict[str, Candidate] = {}
    for _ in range(windows):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(rng.uniform(start, end)))
        raw = http.get(
            f"https://index.golang.org/index?since={ts}&limit=2000", accept="text/plain", binary=True
        )
        for line in raw.decode("utf-8", "replace").splitlines():
            try:
                path = json.loads(line)["Path"]
            except (ValueError, KeyError):
                continue
            if not isinstance(path, str):
                continue
            cand = canonical("https://" + path, "go")
            if cand and cand.key not in seen:
                cand.meta = {"ecosystem": "go", "module": path}
                seen[cand.key] = cand
    pool = list(seen.values())
    ai = [c for c in pool if AI_NAME.search(c.repo)]
    other = [c for c in pool if not AI_NAME.search(c.repo)]
    return ai, other


# --- GitLab public projects API -------------------------------------------

GITLAB_AI_KEYWORDS = (
    "langchain", "llm", "mcp", "openai", "anthropic", "claude", "agent", "rag", "gemini", "chatgpt", "ollama",
    "langgraph", "crewai",
)  # fmt: skip


def _gitlab_projects(http: Http, query: str) -> list[dict[str, Any]]:
    doc = http.get(f"https://gitlab.com/api/v4/projects?{query}")
    return [p for p in (doc or []) if isinstance(p, dict)]


def _gitlab_ok(p: dict[str, Any]) -> bool:
    return bool(
        p.get("default_branch") and not p.get("archived") and not p.get("empty_repo")
        and "forked_from_project" not in p and p.get("path_with_namespace")
    )  # fmt: skip


def gitlab_candidates(
    http: Http, seed: int, starts: int, since: str
) -> tuple[list[Candidate], list[Candidate]]:
    rng = random.Random(seed)
    newest = _gitlab_projects(http, "order_by=id&sort=desc&per_page=1&visibility=public")
    max_id = int(newest[0]["id"]) if newest else 70_000_000
    random_pool: dict[str, Candidate] = {}
    for _ in range(starts):
        start = rng.randrange(1, max_id)
        query = (f"id_after={start}&order_by=id&sort=asc&per_page=40&visibility=public&archived=false"
                 f"&last_activity_after={urllib.parse.quote(since + 'T00:00:00Z')}")  # fmt: skip
        taken = 0
        for p in _gitlab_projects(http, query):
            if _gitlab_ok(p) and taken < 3:
                cand = canonical("https://gitlab.com/" + p["path_with_namespace"], "gitlab-random")
                if cand and cand.key not in random_pool:
                    cand.meta = {"ecosystem": "gitlab", "id": p["id"], "stars": p.get("star_count", 0),
                                 "last_activity": str(p.get("last_activity_at", ""))[:10]}  # fmt: skip
                    random_pool[cand.key] = cand
                    taken += 1
    ai_pool: dict[str, Candidate] = {}
    for kw in GITLAB_AI_KEYWORDS:
        for page in (1, 2):
            after = urllib.parse.quote(since + "T00:00:00Z")
            query = (
                f"search={kw}&order_by=last_activity_at&sort=desc&per_page=100&page={page}"
                f"&visibility=public&archived=false&last_activity_after={after}"
            )
            for p in _gitlab_projects(http, query):
                if _gitlab_ok(p):
                    cand = canonical("https://gitlab.com/" + p["path_with_namespace"], "gitlab-ai")
                    if cand and cand.key not in ai_pool:
                        cand.meta = {"ecosystem": "gitlab", "id": p["id"], "keyword": kw,
                                     "stars": p.get("star_count", 0)}  # fmt: skip
                        ai_pool[cand.key] = cand
    return list(ai_pool.values()), list(random_pool.values())


# --- curated lists and purposive challenge sets ----------------------------


def list_links(text: str, frame: str, source: str) -> list[Candidate]:
    seen: dict[str, Candidate] = {}
    for match in re.finditer(r"https?://(?:www\.)?(?:github|gitlab)\.com/[^\s)\]\"'<>]+", text):
        cand = canonical(match.group(0), frame, {"list": source})
        if cand and cand.key not in seen:
            seen[cand.key] = cand
    return list(seen.values())


def read_list_repo(directory: Path, frame: str, source: str) -> list[Candidate]:
    """Parse repository links out of a cloned awesome-list (data only: nothing in it is executed)."""
    out: dict[str, Candidate] = {}
    patterns = ("README*", "readme*", "software/*.yml", "*.md")
    for pattern in patterns:
        for path in sorted(directory.glob(pattern))[:3000]:
            if path.is_file() and not path.is_symlink() and path.stat().st_size < 20_000_000:
                for cand in list_links(path.read_text(encoding="utf-8", errors="replace"), frame, source):
                    out.setdefault(cand.key, cand)
    return list(out.values())


def purposive(path: Path) -> dict[str, list[Candidate]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, list[Candidate]] = {}
    for frame, entries in doc["frames"].items():
        cands = []
        for entry in entries:
            cand = canonical(entry["url"], frame, {"why": entry["why"]})
            if cand:
                cands.append(cand)
        out[frame] = cands
    return out


def to_json(cands: list[Candidate]) -> list[dict[str, Any]]:
    return [asdict(c) for c in cands]
