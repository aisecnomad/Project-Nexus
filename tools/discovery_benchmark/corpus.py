"""Corpus model: pinned repositories with session-labeled expected facts."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from tools.discovery_benchmark.taxonomy import is_fact

SCHEMA = 1
CLASSES = ("positive", "control", "nearmiss")
HOSTS = {"github": "https://github.com/", "gitlab": "https://gitlab.com/"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,120}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)+\Z")
MAX_CORPUS_BYTES = 4_000_000


class CorpusError(ValueError):
    """The corpus file is malformed."""


@dataclass(frozen=True)
class Expected:
    fact: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Repo:
    id: str
    host: str
    path: str
    commit: str
    default_branch: str
    klass: str
    expected: tuple[Expected, ...] = ()
    tolerated: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    size_kb: int = 0
    file_count: int = 0
    notes: str = ""

    @property
    def url(self) -> str:
        return f"{HOSTS[self.host]}{self.path}.git"

    @property
    def expected_facts(self) -> frozenset[str]:
        return frozenset(e.fact for e in self.expected)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["class"] = data.pop("klass")
        data["expected"] = [{"fact": e.fact, "evidence": list(e.evidence)} for e in self.expected]
        data["tolerated"] = list(self.tolerated)
        data["languages"] = list(self.languages)
        return data


@dataclass(frozen=True)
class Corpus:
    metadata: dict[str, Any]
    repos: tuple[Repo, ...]
    schema: int = SCHEMA
    extra: dict[str, Any] = field(default_factory=dict)

    def by_class(self, klass: str) -> list[Repo]:
        return [r for r in self.repos if r.klass == klass]

    def get(self, repo_id: str) -> Repo:
        for repo in self.repos:
            if repo.id == repo_id:
                return repo
        raise KeyError(repo_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "metadata": self.metadata,
            **self.extra,
            "repos": [r.to_dict() for r in self.repos],
        }


def _str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise CorpusError(f"{name} must be a string")
    return value


def repo_from_dict(data: dict[str, Any]) -> Repo:
    repo_id = _str(data.get("id"), "id")
    if not _ID.match(repo_id):
        raise CorpusError(f"invalid repo id {repo_id!r}")
    host = _str(data.get("host"), f"{repo_id}.host")
    if host not in HOSTS:
        raise CorpusError(f"{repo_id}: unknown host {host!r}")
    path = _str(data.get("path"), f"{repo_id}.path")
    if not _PATH.match(path):
        raise CorpusError(f"{repo_id}: invalid path {path!r}")
    commit = _str(data.get("commit"), f"{repo_id}.commit")
    if not _SHA.match(commit):
        raise CorpusError(f"{repo_id}: commit must be a 40-character lowercase SHA")
    klass = _str(data.get("class"), f"{repo_id}.class")
    if klass not in CLASSES:
        raise CorpusError(f"{repo_id}: class must be one of {CLASSES}")
    expected: list[Expected] = []
    seen: set[str] = set()
    for item in data.get("expected") or []:
        if not isinstance(item, dict):
            raise CorpusError(f"{repo_id}: expected entries must be objects")
        fact = _str(item.get("fact"), f"{repo_id}.expected.fact")
        if not is_fact(fact):
            raise CorpusError(f"{repo_id}: malformed fact {fact!r}")
        if fact in seen:
            raise CorpusError(f"{repo_id}: duplicate expected fact {fact!r}")
        seen.add(fact)
        evidence = tuple(_str(e, f"{repo_id}.expected.evidence") for e in item.get("evidence") or [])
        if not evidence:
            raise CorpusError(f"{repo_id}: expected fact {fact!r} has no evidence pointer")
        expected.append(Expected(fact, evidence))
    if klass != "positive" and expected:
        raise CorpusError(f"{repo_id}: {klass} repositories carry no expected facts")
    if klass == "positive" and not expected:
        raise CorpusError(f"{repo_id}: positive repositories need at least one expected fact")
    tolerated = tuple(_str(t, f"{repo_id}.tolerated") for t in data.get("tolerated") or [])
    for fact in tolerated:
        if not is_fact(fact):
            raise CorpusError(f"{repo_id}: malformed tolerated fact {fact!r}")
        if fact in seen:
            raise CorpusError(f"{repo_id}: {fact!r} is both expected and tolerated")
    return Repo(
        id=repo_id,
        host=host,
        path=path,
        commit=commit,
        default_branch=_str(data.get("default_branch", "main"), f"{repo_id}.default_branch"),
        klass=klass,
        expected=tuple(expected),
        tolerated=tolerated,
        languages=tuple(_str(x, f"{repo_id}.languages") for x in data.get("languages") or []),
        size_kb=int(data.get("size_kb") or 0),
        file_count=int(data.get("file_count") or 0),
        notes=_str(data.get("notes", ""), f"{repo_id}.notes"),
    )


def corpus_from_dict(data: dict[str, Any]) -> Corpus:
    if data.get("schema") != SCHEMA:
        raise CorpusError(f"unsupported corpus schema {data.get('schema')!r}")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        raise CorpusError("metadata must be an object")
    raw = data.get("repos")
    if not isinstance(raw, list) or not raw:
        raise CorpusError("repos must be a non-empty list")
    repos = tuple(repo_from_dict(item) for item in raw)
    ids = [r.id for r in repos]
    if len(set(ids)) != len(ids):
        raise CorpusError("repo ids must be unique")
    extra = {k: v for k, v in data.items() if k not in {"schema", "metadata", "repos"}}
    return Corpus(metadata=metadata, repos=repos, extra=extra)


def load_corpus(path: Path) -> Corpus:
    if path.stat().st_size > MAX_CORPUS_BYTES:
        raise CorpusError(f"{path} exceeds {MAX_CORPUS_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{path}: {exc}") from None
    if not isinstance(data, dict):
        raise CorpusError(f"{path}: top level must be an object")
    return corpus_from_dict(data)


def save_corpus(corpus: Corpus, path: Path) -> None:
    path.write_text(json.dumps(corpus.to_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
