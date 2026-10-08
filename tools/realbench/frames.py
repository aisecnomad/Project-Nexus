"""Snapshot the public sampling frames the real-world corpus is drawn from.

``python -m tools.realbench.frames --output tools/realbench/frames``

A frame is a list of candidate repository URLs from one public source:

- an awesome list's README at a pinned commit (``raw.githubusercontent.com``);
- an npm registry keyword search (the top results by npm's own ranking);
- a GitLab.com API topic query (public, non-fork projects, most recently active first).

Each snapshot records the source, the fetch time and, for lists, the commit, so
the draw in ``sample.py`` can be repeated from the committed files even after
the live sources change. The frame definitions below are part of the
pre-registered protocol.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# stratum -> GitHub awesome lists (owner/repo, README path)
GITHUB_LISTS: dict[str, list[tuple[str, str]]] = {
    "gh-agents": [
        ("e2b-dev/awesome-ai-agents", "README.md"),
        ("kyrolabs/awesome-agents", "README.md"),
        ("ashishpatel26/500-AI-Agents-Projects", "README.md"),
        ("Jenqyang/Awesome-AI-Agents", "README.md"),
        ("slavakurilyak/awesome-ai-agents", "README.md"),
        ("kaushikb11/awesome-llm-agents", "README.md"),
    ],
    "gh-mcp": [
        ("punkpeye/awesome-mcp-servers", "README.md"),
        ("appcypher/awesome-mcp-servers", "README.md"),
        ("wong2/awesome-mcp-servers", "README.md"),
    ],
    "gh-genai": [
        ("humanloop/awesome-chatgpt", "README.md"),
        ("sindresorhus/awesome-chatgpt", "readme.md"),
        ("Hannibal046/Awesome-LLM", "README.md"),
        ("filipecalegario/awesome-generative-ai", "README.md"),
        ("steven2358/awesome-generative-ai", "README.md"),
    ],
    "gh-general": [
        ("vinta/awesome-python", "README.md"),
        ("avelino/awesome-go", "README.md"),
        ("sindresorhus/awesome-nodejs", "readme.md"),
        ("awesome-selfhosted/awesome-selfhosted", "README.md"),
        ("rust-unofficial/awesome-rust", "README.md"),
        ("akullpp/awesome-java", "README.md"),
        ("ziadoz/awesome-php", "README.md"),
        ("markets/awesome-ruby", "README.md"),
        ("quozd/awesome-dotnet", "README.md"),
    ],
}

# stratum -> npm search keywords (``keywords:<k>``), top NPM_SIZE results each
NPM_KEYWORDS: dict[str, list[str]] = {
    "npm-ai": ["ai-agent", "langchain", "mcp-server", "openai", "llm", "anthropic", "ai-sdk", "agent"],
    "npm-general": ["cli", "express", "react", "eslint-plugin", "vite-plugin", "webpack-plugin", "utility"],
}
NPM_SIZE = 250

# stratum -> GitLab.com topics, most recently active public projects, GITLAB_MAX each
GITLAB_TOPICS: dict[str, list[str]] = {
    "gitlab-ai": [
        "llm", "langchain", "openai", "chatgpt", "ai-agent", "ai-agents", "chatbot",
        "ollama", "generative-ai", "gpt", "mcp", "llms",
    ],
    "gitlab-general": [
        "python", "javascript", "go", "java", "rust", "php", "ruby", "typescript",
        "docker", "terraform", "kubernetes", "django", "react",
    ],
}  # fmt: skip
GITLAB_MAX = 300

_GITHUB_LINK = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
# First path segments on github.com that are site pages, not repository owners.
_NOT_OWNERS = frozenset(
    {
        "about", "apps", "collections", "contact", "customer-stories", "enterprise",
        "explore", "features", "github", "issues", "login", "marketplace", "new",
        "notifications", "orgs", "pricing", "pulls", "readme", "search", "settings",
        "site", "sponsors", "topics", "trending", "users",
    }
)  # fmt: skip
_USER_AGENT = "realbench-frames/1 (+https://github.com/aisecnomad/Project-Nexus)"


def _get(url: str, attempts: int = 4) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read(), {k.lower(): v for k, v in response.headers.items()}
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(2 ** (attempt + 1))
    raise AssertionError("unreachable")


def normalize_github(owner: str, repo: str) -> str | None:
    """Return ``https://github.com/owner/repo`` or ``None`` for site pages and anchors."""
    repo = repo.removesuffix(".git").rstrip(".")
    if not owner or not repo or owner.lower() in _NOT_OWNERS:
        return None
    if repo.lower() in {"blob", "tree", "wiki", "issues", "pulls", "releases"}:
        return None
    return f"https://github.com/{owner}/{repo}"


def github_links(markdown: str) -> list[str]:
    """Distinct repository URLs linked from an awesome list, in first-seen order and spelling."""
    seen: dict[str, str] = {}
    for owner, repo in _GITHUB_LINK.findall(markdown):
        url = normalize_github(owner, repo)
        if url is not None:
            seen.setdefault(url.lower(), url)
    return list(seen.values())


def _head(owner_repo: str) -> str:
    out = subprocess.run(
        ["git", "ls-remote", f"https://github.com/{owner_repo}", "HEAD"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    return out.split()[0]


def github_list_frame(owner_repo: str, path: str) -> dict[str, Any]:
    sha = _head(owner_repo)
    url = f"https://raw.githubusercontent.com/{owner_repo}/{sha}/{path}"
    body, _ = _get(url)
    own = f"https://github.com/{owner_repo}".lower()
    links = [u for u in github_links(body.decode("utf-8", "replace")) if u.lower() != own]
    return {"kind": "github-list", "source": owner_repo, "commit": sha, "url": url, "candidates": links}


def _repository_url(raw: str | None) -> str | None:
    if not raw:
        return None
    raw = raw.removeprefix("git+").removesuffix(".git")
    match = _GITHUB_LINK.search(raw.replace("git://", "https://").replace("ssh://git@", "https://"))
    if match:
        return normalize_github(*match.groups())
    gitlab = re.search(r"gitlab\.com[/:]([A-Za-z0-9_./-]+)", raw)
    if gitlab:
        return "https://gitlab.com/" + gitlab.group(1).strip("/").removesuffix(".git")
    return None


def npm_frame(keyword: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"text": f"keywords:{keyword}", "size": NPM_SIZE})
    url = f"https://registry.npmjs.org/-/v1/search?{query}"
    body, _ = _get(url)
    seen: dict[str, dict[str, str]] = {}
    for obj in json.loads(body)["objects"]:
        package = obj["package"]
        repo = _repository_url((package.get("links") or {}).get("repository"))
        if repo and repo.lower() not in seen:
            seen[repo.lower()] = {"url": repo, "package": package["name"]}
    return {
        "kind": "npm-search",
        "source": f"keywords:{keyword}",
        "url": url,
        "candidates": list(seen.values()),
    }


def gitlab_frame(topic: str) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    page = 1
    while len(candidates) < GITLAB_MAX:
        query = urllib.parse.urlencode(
            {
                "topic": topic,
                "visibility": "public",
                "order_by": "last_activity_at",
                "sort": "desc",
                "per_page": 100,
                "page": page,
            }
        )
        body, headers = _get(f"https://gitlab.com/api/v4/projects?{query}")
        batch = json.loads(body)
        for p in batch:
            if p.get("forked_from_project") or p.get("mirror") or p.get("empty_repo") or p.get("archived"):
                continue
            candidates.append(
                {
                    "url": p["web_url"],
                    "path": p["path_with_namespace"],
                    "last_activity_at": p.get("last_activity_at"),
                    "star_count": p.get("star_count"),
                }
            )
        if not headers.get("x-next-page") or not batch:
            break
        page += 1
    return {
        "kind": "gitlab-topic",
        "source": f"topic:{topic}",
        "url": "https://gitlab.com/api/v4/projects?topic=" + urllib.parse.quote(topic),
        "candidates": candidates[:GITLAB_MAX],
    }


def snapshot(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    fetched = datetime.now(UTC).replace(microsecond=0).isoformat()
    index: dict[str, Any] = {"fetched_at": fetched, "strata": {}}
    jobs: list[tuple[str, str, Any]] = []
    for stratum, lists in GITHUB_LISTS.items():
        jobs += [(stratum, f"{o}:{p}", (github_list_frame, o, p)) for o, p in lists]
    for stratum, keywords in NPM_KEYWORDS.items():
        jobs += [(stratum, f"npm:{k}", (npm_frame, k)) for k in keywords]
    for stratum, topics in GITLAB_TOPICS.items():
        jobs += [(stratum, f"gitlab:{t}", (gitlab_frame, t)) for t in topics]
    for stratum, name, (fn, *args) in jobs:
        frame = fn(*args)
        frame["fetched_at"] = fetched
        index["strata"].setdefault(stratum, []).append(
            {"name": name, "kind": frame["kind"], "count": len(frame["candidates"])}
        )
        path = output / f"{stratum}.jsonl.gz"
        with gzip.open(path, "at", encoding="utf-8") as fh:
            fh.write(json.dumps({"name": name, **frame}, sort_keys=True) + "\n")
        print(f"{stratum:15} {name:55} {len(frame['candidates']):5}", flush=True)
    (output / "index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    return index


def load_frames(directory: Path) -> dict[str, list[dict[str, Any]]]:
    """Read the committed snapshot: stratum -> list of frames, each with ``candidates``."""
    out: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(directory.glob("*.jsonl.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            out[path.name.removesuffix(".jsonl.gz")] = [json.loads(line) for line in fh if line.strip()]
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if any(args.output.glob("*.jsonl.gz")):
        parser.error(f"{args.output} already holds a snapshot; frames are written once")
    snapshot(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
