"""Load and validate YAML signature packs."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import regex
import yaml

from shadowscan.signatures.schema import require_list, validate_signature_shape
from shadowscan.utils.files import policy_files, read_policy_text
from shadowscan.utils.safe_yaml import BoundedSafeLoader

VALID_CATEGORIES = {
    "framework",  # agent orchestration frameworks (LangChain, CrewAI, ADK...)
    "provider",  # model providers / inference APIs (OpenAI, Bedrock, Ollama...)
    "protocol",  # MCP, A2A, ACP, AG-UI...
    "coding-agent",  # Claude Code, Copilot, Cursor, Codex, Cline...
    "platform",  # hosted agent platforms / low-code (Dify, Flowise, n8n, Copilot Studio...)
    "observability",  # LangSmith, Langfuse, AgentOps...
    "memory",  # vector stores / memory layers
    "sandbox",  # code execution sandboxes (E2B, Daytona, Modal...)
    "identity-app",  # known AI SaaS apps appearing as OAuth grants / bots
    "cloud-service",  # managed cloud AI services (Bedrock Agents, Vertex Agent Engine...)
    "heuristic",  # vendor-neutral idioms (tool registration, agent loops, autonomy flags)
    "policy",  # permission classification used by the risk engine
}

VALID_SIGNAL_TYPES = {
    "dependency",
    "import",
    "code",
    "file",
    "env",
    "domain",
    "user_agent",
    "image",
    "iac",
    "name",
    "scope",
    "model",
    "secret",
    "client_id",
}

_NAME_NORMALISE = re.compile(r"[-_.]+")


def normalise_package_name(name: str) -> str:
    """PEP 503 style normalisation, also applied to other ecosystems for leniency."""
    return _NAME_NORMALISE.sub("-", name.strip().lower())


@dataclass(slots=True)
class Signal:
    type: str
    weight: float = 0.5
    ecosystem: str | None = None  # dependency
    languages: list[str] = field(default_factory=list)  # import / code
    names: list[str] = field(default_factory=list)  # dependency / env / client_id
    prefixes: list[str] = field(default_factory=list)  # dependency
    patterns: list[str] = field(default_factory=list)  # regexes
    globs: list[str] = field(default_factory=list)  # file
    values: list[str] = field(default_factory=list)  # domain / scope / iac
    capabilities: list[str] = field(default_factory=list)  # capabilities implied when matched
    agent_indicator: bool = False  # this signal by itself indicates an *agent* (not just LLM use)
    # Lexical matches are ignored; only a call bound to an import of this
    # signature's library counts (for ambiguous names such as ClientSession).
    bound_only: bool = False
    description: str | None = None
    compiled: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    bounded_compiled: list[Any] = field(default_factory=list, repr=False)

    def compile(self) -> None:
        self.compiled = []
        self.bounded_compiled = []
        for p in self.patterns:
            try:
                self.compiled.append(re.compile(p, re.MULTILINE))
                self.bounded_compiled.append(regex.compile(p, regex.MULTILINE | regex.VERSION0))
            except (re.error, regex.error) as exc:
                raise ValueError(f"invalid regex {p!r}: {exc}") from exc
        if self.type == "domain":
            for value in self.values:
                if value.startswith("re:"):
                    try:
                        re.compile(value[3:], re.IGNORECASE)
                        regex.compile(value[3:], regex.IGNORECASE | regex.VERSION0)
                    except (re.error, regex.error) as exc:
                        raise ValueError(f"invalid domain regex {value!r}: {exc}") from exc


@dataclass(slots=True)
class Signature:
    id: str
    name: str
    category: str
    vendor: str | None = None
    homepage: str | None = None
    description: str | None = None
    tags: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    agent_indicator: bool = False  # presence alone implies an agent
    risk_notes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    source: str | None = None  # file it came from

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", self.id):
            raise ValueError(f"{self.source}: invalid signature id {self.id!r}")
        if self.category not in VALID_CATEGORIES:
            raise ValueError(f"{self.source}: {self.id}: invalid category {self.category!r}")
        for s in self.signals:
            if s.type not in VALID_SIGNAL_TYPES:
                raise ValueError(f"{self.source}: {self.id}: invalid signal type {s.type!r}")
            if not 0.0 <= s.weight <= 1.0:
                raise ValueError(f"{self.source}: {self.id}: signal weight out of range")
            if s.type == "dependency" and not (s.names or s.prefixes):
                raise ValueError(f"{self.source}: {self.id}: dependency signal needs names/prefixes")
            if s.type in {"import", "code", "user_agent", "name", "model", "secret", "image"} and not s.patterns:
                raise ValueError(f"{self.source}: {self.id}: {s.type} signal needs patterns")
            if s.type == "file" and not s.globs:
                raise ValueError(f"{self.source}: {self.id}: file signal needs globs")
            if s.type in {"domain", "scope", "iac"} and not s.values:
                raise ValueError(f"{self.source}: {self.id}: {s.type} signal needs values")
            if s.type in {"env", "client_id"} and not (s.names or s.patterns):
                raise ValueError(f"{self.source}: {self.id}: {s.type} signal needs names or patterns")
            s.compile()


def _signal_from_dict(d: dict[str, Any]) -> Signal:
    return Signal(
        type=str(d["type"]),
        weight=float(d.get("weight", 0.5)),
        ecosystem=d.get("ecosystem"),
        languages=list(d.get("languages", []) or []),
        names=[str(x) for x in d.get("names", []) or []],
        prefixes=[str(x) for x in d.get("prefixes", []) or []],
        patterns=[str(x) for x in d.get("patterns", []) or []],
        globs=[str(x) for x in d.get("globs", []) or []],
        values=[str(x) for x in d.get("values", []) or []],
        capabilities=list(d.get("capabilities", []) or []),
        agent_indicator=bool(d.get("agent_indicator", False)),
        bound_only=bool(d.get("bound_only", False)),
        description=d.get("description"),
    )


def signature_from_dict(d: dict[str, Any], source: str | None = None) -> Signature:
    validate_signature_shape(d, source or "signature")
    sig = Signature(
        id=str(d["id"]),
        name=str(d.get("name", d["id"])),
        category=str(d.get("category", "framework")),
        vendor=d.get("vendor"),
        homepage=d.get("homepage"),
        description=d.get("description"),
        tags=list(d.get("tags", []) or []),
        capabilities=list(d.get("capabilities", []) or []),
        agent_indicator=bool(d.get("agent_indicator", False)),
        risk_notes=list(d.get("risk_notes", []) or []),
        references=list(d.get("references", []) or []),
        signals=[_signal_from_dict(s) for s in d.get("signals", []) or []],
        source=source,
    )
    sig.validate()
    return sig


def _iter_yaml_files(root: Path):
    yield from policy_files(root, {".yaml", ".yml"})


class _UniqueKeyLoader(BoundedSafeLoader):
    """Reject duplicate YAML keys instead of silently retaining the last value."""


def _unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    out = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ValueError(f"YAML mapping key must be a string at {key_node.start_mark}")
        if key in out:
            raise ValueError(f"duplicate YAML key {key!r} at {key_node.start_mark}")
        out[key] = loader.construct_object(value_node, deep=deep)
    return out


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_signature_file(path: Path) -> list[Signature]:
    try:
        docs = list(yaml.load_all(read_policy_text(path), Loader=_UniqueKeyLoader))
    except (yaml.YAMLError, ValueError) as exc:
        raise ValueError(f"{path}: invalid YAML: {exc}") from exc
    out: list[Signature] = []
    for i, doc in enumerate(docs, 1):
        context = f"{path}: document {i}"
        if isinstance(doc, dict) and "signatures" in doc:
            if set(doc) != {"signatures"}:
                raise ValueError(f"{context}: only the 'signatures' key is allowed on a pack")
            for item in require_list(doc["signatures"], context, nonempty=True):
                out.append(signature_from_dict(item, source=context))
        elif isinstance(doc, dict):
            out.append(signature_from_dict(doc, source=context))
        elif isinstance(doc, list):
            for item in require_list(doc, context, nonempty=True):
                out.append(signature_from_dict(item, source=context))
        else:
            raise ValueError(f"{context}: expected a signature, signature list, or signatures pack")
    if not out:
        raise ValueError(f"{path}: empty signature pack")
    ids = [sig.id for sig in out]
    if len(set(ids)) != len(ids):
        raise ValueError(f"{path}: duplicate signature ids in a file")
    return out


def builtin_signature_dir() -> Path:
    return Path(str(resources.files("shadowscan.signatures") / "data"))


def load_signatures(
    extra_dirs: Sequence[str | os.PathLike[str]] | None = None,
    include_builtin: bool = True,
    *, allow_override: bool = False,
) -> list[Signature]:
    """Load built-in signatures plus any extra packs.

    Built-in IDs are reserved unless ``allow_override`` is explicitly enabled.
    Later organization packs may replace IDs from earlier organization packs.
    """
    if not isinstance(allow_override, bool):
        raise ValueError("allow_override must be a boolean")
    by_id: dict[str, Signature] = {}
    dirs: list[Path] = []
    if include_builtin:
        dirs.append(builtin_signature_dir())
    for d in extra_dirs or []:
        dirs.append(Path(d))
    reserved: set[str] = set()
    for number, d in enumerate(dirs):
        if not d.is_dir():
            raise FileNotFoundError(f"signature directory not found: {d}")
        pack_ids: set[str] = set()
        for f in _iter_yaml_files(d):
            for sig in load_signature_file(f):
                if sig.id in pack_ids:
                    raise ValueError(f"{f}: duplicate signature id {sig.id!r} in {d}")
                if sig.id in reserved and not allow_override:
                    raise ValueError(f"{f}: signature id {sig.id!r} is reserved by a built-in; explicitly enable signature overrides")
                pack_ids.add(sig.id)
                by_id[sig.id] = sig
        if include_builtin and number == 0:
            reserved.update(pack_ids)
    return list(by_id.values())
