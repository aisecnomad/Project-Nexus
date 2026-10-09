"""Catalog-like data files: lists that name technologies without using them.

A proxy blocklist of AI-provider domains, an egress allowlist, a vendor policy
or a copy of this scanner's own signature packs names many products and runs
none of them. Their domain and variable names are *mentions*. Left to count as
evidence they once reported "LLM usage: CrewAI" with confidence 1.0 for a
repository whose only content was a blocklist.

A file is catalog-like when all of the following hold:

* it is a data or prose format (YAML, JSON, TOML, INI, XML, CSV, text,
  Markdown), not source code, and not a manifest that declares what the
  project builds or runs with (dotenv files, Compose files, Helm values,
  CI pipelines, Spring configuration, dependency manifests, IaC);
* it is not a configuration document (``configuration_document``): a
  Kubernetes-style resource, an ECS task definition, a file in a
  configuration directory (``.devcontainer/`` anywhere; ``config/``, ``conf/``
  or ``settings/`` at the top of the scan or of the file's project), or a file
  that assigns a variable it names: under an ``env``, ``environment``,
  ``variables``, ``secrets``, ``containerEnv`` or ``remoteEnv`` key, as a key
  with a scalar value at any depth, or as a ``NAME=value`` / ``NAME: value``
  line (``.devcontainer/sample_keys.cfg`` with five provider keys). A key with
  no value (``OPENAI_API_KEY:`` alone) or whose value is a mapping or a list,
  in block or flow style (``OPENAI_API_KEY: {vendor: OpenAI}``), assigns
  nothing, so a policy keyed by variable name stays a list in any format;
* no source file, shell script or notebook of the same project loads it by
  name (``referenced_data_files``: a quoted path literal ending in a data
  suffix, ``open("model-settings.yml")``, ``include_str!("../providers.json")``).
  Data under a documentation or website directory (``docs/``, ``website/``,
  ``_data/`` and the like) is published, not loaded, so a reference to a
  leaderboard or gallery file leaves it a catalog. The reference is by name
  and the directory list is fixed, which is the accepted cost: a quoted
  ``"settings.yaml"`` anywhere in code, a docstring included, exempts every
  data file of that name in the project, and published data outside those
  directories (``public/``, ``static/``) is configuration once a build script
  names it;
* every non-heuristic match in it is a mention-class signal (``domain``,
  ``env`` or ``name``, or a model identifier found in a data file, which the
  filesystem connector marks ``data_mention``), so the file holds no import,
  dependency, code, file-name, image, IaC or credential anchor and no model
  selected by a manifest or IaC; and
* its matches span at least ``CATALOG_MIN_SIGNATURES`` distinct signatures.

Why four is a judgement from the data at hand: the bundled evaluation corpora's
multi-provider configurations are dotenv files naming three or four products
(exempt as manifests), the regression fixtures' blocklists and vendor policies
name six to ten, and the bundled signature packs seven to thirty-six per file.
Four keeps a three-provider configuration and catches every list of four or
more; a list of two or three products cannot be told from configuration.

Small data files cannot be told from configuration on their own (one domain
in ``policies.yaml`` looks like one ``base_url`` in ``config.yaml``). When a
project holds a catalog and nothing else but mention-only data files, those
files are one catalog: nothing in the project uses a technology it names. A
configuration document or a file that code loads is not mention-only data, so
it keeps its small neighbours out of the catalog.

Observations from a catalog count as mentions: they establish a technology only
when the same signature also has library evidence (an import, a dependency or a
specific code pattern) elsewhere in the project, as for an ambiguous pattern.
A shape cannot tell every configuration from a list (four providers configured
by base URL read like a vendor policy), so the filesystem connector reports a
project whose only evidence is in catalogs as a scan note instead of dropping
it silently.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from pathlib import PurePosixPath
from typing import Any, Protocol

import regex

from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, _finditer

# The snippet is text, an excerpt the connector produces on demand, or none.
Observation = tuple[Match, str, Any]  # match, relpath, snippet

# Distinct signatures one data file must name before it reads as a list.
CATALOG_MIN_SIGNATURES = 4
# Signals that name a product without configuring or running it. A model id
# selected by a manifest or IaC is a selection, and an image, resource type or
# credential belongs to a deployment, so none of those is a mention; a model id
# found in a data file (``extra["data_mention"]``) is, see ``_mention``.
CATALOG_MENTION_SIGNALS = frozenset({"domain", "env", "name"})
# Files listed in ``metadata.catalog_mentions``.
MAX_CATALOG_FILES = 20
# Files whose text names the data files it loads: source code, notebooks (their
# code cells) and shell scripts.
LOADER_EXTENSIONS = frozenset(SOURCE_EXTENSIONS) | {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
# Distinct names and paths ``referenced_data_files`` records per file.
MAX_REFERENCES_PER_FILE = 400
# Assignment lines one data file is judged on, and quoted data-file literals one
# loader file is read for, before the pass stops. The engine charges the work
# between matches to the pattern's budget, so without a cap a file of 100,000
# ``X=1`` lines read as a timed-out input and marked the scan incomplete.
MAX_ASSIGNMENT_LINES = 10_000
MAX_PATH_LITERALS = 2_000

# Formats that hold data or prose rather than code or deployment declarations.
_DATA_SUFFIXES = frozenset(
    {
        ".yaml",
        ".yml",
        ".json",
        ".jsonc",
        ".json5",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".xml",
        ".csv",
        ".txt",
        ".md",
        ".mdc",
        ".mdx",
    }
)
# Data suffixes a path literal in code ends with when it names a file the code loads.
_REFERENCE_SUFFIXES = (
    ".yaml",
    ".yml",
    ".json",
    ".json5",
    ".jsonc",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".csv",
    ".txt",
)
# Vendor-neutral heuristics are never an anchor; policy signatures are not code evidence.
_IGNORED_CATEGORIES = frozenset({"heuristic", "policy"})
# CI pipelines hand variables and endpoints to the jobs they run, wherever they
# keep them (GitHub workflows are recognized by their directory).
_PIPELINE_NAMES = frozenset(
    {
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "bitbucket-pipelines.yml",
        "buildspec.yml",
        "buildspec.yaml",
        ".travis.yml",
        ".drone.yml",
        ".drone.yaml",
        "appveyor.yml",
        ".appveyor.yml",
        ".woodpecker.yml",
        ".woodpecker.yaml",
    }
)
_PIPELINE_DIRECTORIES = frozenset({".circleci", ".buildkite", ".woodpecker", ".gitlab"})
# A development container's files configure the workspace wherever the directory sits.
_WORKSPACE_DIRECTORIES = frozenset({".devcontainer"})
# Directories that hold a project's configuration when they sit at its top; deeper
# down (src/main/resources/config/, tests/config/) the name says less.
_CONFIGURATION_DIRECTORIES = frozenset({"config", "conf", "settings"})
# Documentation and website sources, as the benchmark labeler reads them. Data
# there (a leaderboard, a gallery, a pricing table) is published, not loaded.
_DOCUMENTATION_DIRECTORIES = frozenset(
    {"docs", "doc", "website", "site", "_data", "_posts", "_includes", "blog"}
)
_POLICY_FILE = re.compile(
    r"(?:block|deny|reject|drop|firewall|acl|egress|ingress|waf|security)[_-]?"
    r"|(?:blocklist|denylist|blacklist|allowlist|whitelist)",
    re.IGNORECASE,
)
# Spring application and bootstrap configuration, including profiles (application-prod.yml).
_SERVICE_CONFIGURATION = re.compile(r"(?:application|bootstrap)(?:-[\w.-]+)?\.(?:ya?ml|properties)")
# Keys whose entries assign variables to a container, a job or a function. Compared without
# case, "_" or "-": env, environment, variables, vars, envVars, environment_variables, secrets,
# and a development container's containerEnv / remoteEnv.
_ENVIRONMENT_KEYS = frozenset(
    {
        "env",
        "envs",
        "environment",
        "variables",
        "vars",
        "envvars",
        "environmentvariables",
        "secrets",
        "containerenv",
        "remoteenv",
    }
)
# Top-level keys of a Kubernetes-style resource, read from the text: a stream of several
# documents has no single parsed form, and each of its resources starts with them.
_RESOURCE_KEY = re.compile(r"^(apiVersion|kind)[ \t]*:", re.MULTILINE)
# A line that assigns a variable: dotenv and INI ``NAME=value``, YAML and
# ``.properties`` ``NAME: value``, shell ``export NAME=value``, JSON ``"NAME": value``.
# The name is an environment-variable identifier (upper case, digits and
# underscores: the shape the matcher's env pass tokenizes, so every name it can
# hand over has it) and starts the line, so a vendor policy's
# ``key_env: OPENAI_API_KEY`` and the lower-case keys that make up a properties or
# JSON file match nothing. The value is a scalar's first character: a key with no
# value (``NAME:`` alone) or one opening a mapping or a list (``NAME: {vendor: x}``,
# ``"NAME": [``, ``NAME = { vendor = "x" }``) assigns nothing. Possessive
# quantifiers keep the bounded engine linear on runs of blanks.
_ASSIGNMENT_LINE = regex.compile(
    r"""(?m)^[ \t]*+(?:export[ \t]++)?+["']?+([A-Z][A-Z0-9_]*+)["']?+[ \t]*+[=:][ \t]*+[^\s#;{\[]"""
)
# A path literal closed by a quote: a run of path characters that no path character
# (or a URL scheme's colon) precedes and that ends in a data suffix, so
# ``"aider/resources/model-settings.yml"`` and the tail of ``f"{root}/settings.toml"``
# match and ``https://host/schema.json``, ``"settings.py"`` and ``"index.html"`` do
# not. The pattern is anchored on the closing quote and reads the literal in a
# lookbehind, so the engine attempts it once per quote character (not once per
# word, which is ten times as often in source code) and gives up at the first
# character before the quote unless a data suffix ends there. The run is bounded
# and possessive, so the pattern is linear on hostile input.
_REFERENCE_SUFFIX_ALTERNATION = "|".join(re.escape(suffix[1:]) for suffix in _REFERENCE_SUFFIXES)
_PATH_LITERAL = regex.compile(
    r"""(?<=(?<![\w./\\:-])([\w./\\-]{1,200}+)(?<=\.(?i:""" + _REFERENCE_SUFFIX_ALTERNATION + r""")))["'`]"""
)
# Mappings and lists inspected per document for variable assignments.
_MAX_CONFIGURATION_NODES = 100_000


class _ProjectMatches(Protocol):
    @property
    def root(self) -> str: ...

    @property
    def matches(self) -> Sequence[Observation]: ...

    @property
    def coding_agent_matches(self) -> Mapping[str, Sequence[Observation]]: ...


# The addresses a hosts file or a resolver maps a blocked name to.
_BLOCKING_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "127.0.1.1", "255.255.255.255", "::", "::1"})
# Rule types of the proxy rule formats that route a host: Clash and Surge write them upper case,
# Quantumult X lower case. Bare "host" and "domain" are not listed: `host, port = ...` is code.
_PROXY_RULE_TYPES = frozenset(
    {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-SET", "HOST-SUFFIX", "HOST-KEYWORD"}
    | {"host-suffix", "host-keyword"}
)
# Resolver directives that blackhole or redirect a name (dnsmasq).
_RESOLVER_DIRECTIVES = ("address=/", "server=/", "ipset=/", "nftset=/")


def _adblock_entry(line: str) -> bool:
    """``||host^`` or ``@@||host^`` (optionally followed by options): a host, then the separator."""
    body = line[4:] if line.startswith("@@||") else line[2:] if line.startswith("||") else ""
    host = body.partition("^")
    return bool(host[1]) and bool(host[0]) and all(ch.isalnum() or ch in ".-*_" for ch in host[0])


def rule_list_line(line: str) -> bool:
    """Whether ``line`` is an entry of a hosts file, ad-block list, resolver or proxy rule list.

    Such a line routes or blocks a host: ``0.0.0.0 chatgpt.com``, ``||api.openai.com^``,
    ``address=/api.openai.com/0.0.0.0`` or ``DOMAIN-SUFFIX,openai.com,PROXY``. Nothing in the
    project calls the host, so a match on it is a mention, whether one product or twenty are named
    (the file-level test in ``catalog_files`` needs four, and does not apply to files without an
    extension such as ``hosts``). A blocklist of ad servers once reported "Make" and "Salesforce
    Agentforce" because two of its entries were their hosts.
    """
    stripped = line.strip()
    if stripped.startswith("- "):  # a YAML list item
        stripped = stripped[2:].lstrip(" \t").lstrip("\"'")
    if not stripped or stripped.startswith("#"):
        return False
    if stripped.startswith(_RESOLVER_DIRECTIVES) or _adblock_entry(stripped):
        return True
    head, _, rest = stripped.partition(",")
    if rest and head.strip() in _PROXY_RULE_TYPES:
        return True
    address, _, host = stripped.partition(" ")
    if not host:
        address, _, host = stripped.partition("\t")
    return address in _BLOCKING_ADDRESSES and bool(host.strip())


# Lines read to decide whether a document is a rule list, and how many entries it needs.
_RULE_LIST_SAMPLE_LINES = 4000
_RULE_LIST_LINE_CHARS = 256
_RULE_LIST_MIN_ENTRIES = 5


def rule_list_document(text: str) -> bool:
    """Whether most of the entries in ``text`` are rule-list lines (see ``rule_list_line``).

    Blank lines and comments do not count. In such a document a comment is part of the list, not a
    note on the configuration: a hosts file groups its entries under headings like
    ``# [integromat.com]``, and a heading is no more a use of the host than the entries below it.
    Only the start of each of the first lines is read, so a minified file costs one pass.
    """
    entries = others = position = 0
    size = len(text)
    for _ in range(_RULE_LIST_SAMPLE_LINES):
        if position >= size:
            break
        end = text.find("\n", position)
        stop = size if end < 0 else end
        head = text[position : min(stop, position + _RULE_LIST_LINE_CHARS)].strip()
        position = stop + 1
        if not head or head.startswith("#"):
            continue
        if rule_list_line(head):
            entries += 1
        else:
            others += 1
    return entries >= _RULE_LIST_MIN_ENTRIES and entries >= 4 * others


class HostLineFilter:
    """The ``skip_line`` predicate for the hosts of one text, decided on first use.

    Most files name no signature host, so whether the document is a rule list is only worked out
    when the matcher finds a host and asks.
    """

    __slots__ = ("_skip", "_text")

    def __init__(self, text: str) -> None:
        self._text = text
        self._skip: Callable[[str], bool] | None = None

    def __call__(self, line: str) -> bool:
        if self._skip is None:
            if rule_list_document(self._text):
                self._skip = lambda candidate: rule_list_line(candidate) or candidate.lstrip().startswith("#")
            else:
                self._skip = rule_list_line
        return self._skip(line)


def _is_data_file(rel: str) -> bool:
    path = PurePosixPath(rel)
    parts = path.parts
    name = path.name.lower()
    return (
        path.suffix.lower() in _DATA_SUFFIXES
        and not is_manifest_name(path.name)
        and not (".github" in parts and "workflows" in parts)
        and name not in _PIPELINE_NAMES
        and _PIPELINE_DIRECTORIES.isdisjoint(parts[:-1])
        and _SERVICE_CONFIGURATION.fullmatch(name) is None
    )


def _configuration_directory(rel: str, root: str = ".") -> bool:
    """Whether ``rel`` sits in a directory that holds configuration.

    ``.devcontainer/`` configures the workspace wherever it sits. ``config/``,
    ``conf/`` and ``settings/`` do so at the top of the scan or of the file's
    project ``root`` (the directory with its manifest), not at any depth.
    """
    parents = [part.lower() for part in PurePosixPath(rel).parts[:-1]]
    if not parents:
        return False
    if not _WORKSPACE_DIRECTORIES.isdisjoint(parents) or parents[0] in _CONFIGURATION_DIRECTORIES:
        return True
    root_parts = [part.lower() for part in PurePosixPath(root).parts] if root not in {"", "."} else []
    return (
        bool(root_parts)
        and len(parents) > len(root_parts)
        and parents[: len(root_parts)] == root_parts
        and parents[len(root_parts)] in _CONFIGURATION_DIRECTORIES
    )


def _documentation_path(rel: str) -> bool:
    """Whether ``rel`` is documentation or website source, where data is published rather than loaded."""
    return not _DOCUMENTATION_DIRECTORIES.isdisjoint(part.lower() for part in PurePosixPath(rel).parts[:-1])


def referenced_data_files(text: str, *, limits: list[str] | None = None) -> set[str]:
    """Lowercased basenames and trailing relative paths of the data files ``text`` names.

    A quoted path literal ending in a data suffix names a file the code loads:
    ``open("model-settings.yml")``, ``include_str!("../provider_catalog.json")``,
    ``source "$HOME/keys.cfg"``, ``Path(root) / "config/models.yaml"``. Each is
    recorded as its path (``./`` and ``../`` prefixes dropped, backslashes read
    as separators) and as its basename, so ``catalog_files`` can match a file
    by either. URLs are not paths. The pattern runs under the per-input
    matching budget and reads at most ``MAX_PATH_LITERALS`` literals, keeping
    at most ``MAX_REFERENCES_PER_FILE`` entries per text. Unread content is
    reported through ``limits`` so the connector can mark coverage incomplete.
    """
    found: set[str] = set()
    matches = _finditer(_PATH_LITERAL, text, "data-file references", MAX_PATH_LITERALS + 1)
    if len(matches) > MAX_PATH_LITERALS and limits is not None:
        limits.append("catalog data-file reference literal limit exceeded; later literals were not read")
    for match in matches[:MAX_PATH_LITERALS]:
        literal = match[1].lower().replace("\\", "/")
        parts: list[str] = []
        for part in literal.split("/"):
            if part in {".", ".."}:
                parts.clear()  # relative to the loader's location: keep what follows
            elif part:
                parts.append(part)
        if parts:
            additions = {"/".join(parts), parts[-1]} - found
            if len(found) + len(additions) > MAX_REFERENCES_PER_FILE:
                if limits is not None:
                    limits.append(
                        "catalog data-file reference limit exceeded; later references were not read"
                    )
                break
            found.update(additions)
    return found


def _referenced(rel: str, referenced: Collection[str]) -> bool:
    """Whether a recorded reference names ``rel`` by its basename or by a trailing path."""
    if not referenced:
        return False
    parts = rel.lower().split("/")
    return any("/".join(parts[index:]) in referenced for index in range(len(parts)))


def _loaded_by_code(rel: str, referenced: Collection[str]) -> bool:
    """Whether code of the project loads ``rel``; documentation and website data count as published."""
    return _referenced(rel, referenced) and not _documentation_path(rel)


def _mention(match: Match) -> bool:
    """Whether ``match`` names a product without configuring or running it."""
    return match.signal.type in CATALOG_MENTION_SIGNALS or (
        match.signal.type == "model" and bool(match.extra.get("data_mention"))
    )


def _kubernetes_resource(text: str, parsed: Any) -> bool:
    if isinstance(parsed, dict):
        return "apiVersion" in parsed and "kind" in parsed
    if "apiVersion" not in text:
        return False
    keys: set[str] = set()
    for match in _RESOURCE_KEY.finditer(text):
        keys.add(match[1])
        if len(keys) == 2:
            return True
    return False


def _ecs_task_definition(parsed: Any) -> bool:
    # A registered definition, or the output of `aws ecs describe-task-definition`.
    definition = parsed.get("taskDefinition", parsed) if isinstance(parsed, dict) else None
    return isinstance(definition, dict) and "containerDefinitions" in definition


def _environment_key(key: str) -> bool:
    return key.replace("_", "").replace("-", "").lower() in _ENVIRONMENT_KEYS


def _scalar(value: Any) -> bool:
    # A key with no value (YAML ``NAME:`` alone, JSON ``null``) lists a name, as a
    # bare ``NAME`` line does for the lexical rule; neither assigns anything.
    return isinstance(value, (str, int, float, bool))


def _assigned_names(value: Any) -> set[str]:
    """Variable names one env, environment, variables or secrets entry assigns."""
    if isinstance(value, dict):
        return {key for key in value if isinstance(key, str)}
    names: set[str] = set()
    for item in value if isinstance(value, list) else ():
        if isinstance(item, dict):
            # Kubernetes and ECS `name`, Render `key`.
            names.update(item[field] for field in ("name", "key") if isinstance(item.get(field), str))
        elif isinstance(item, str):
            names.add(item.partition("=")[0].strip())  # Compose-style NAME=value
    return names


def _configured_variables(document: Any, candidates: AbstractSet[str] = frozenset()) -> set[str]:
    """Variable names ``document`` assigns, at any depth.

    A name is assigned under an environment key (``env``, ``environment``,
    ``variables``, ``secrets``, ``containerEnv`` ...), or, for the names in
    ``candidates``, as a key whose value is a scalar: ``OPENAI_API_KEY: sk-...``
    in a settings file. A key with no value (``OPENAI_API_KEY:`` alone), one
    with a mapping or list value (a policy entry per variable) and a name that
    is only a value (``key_env: OPENAI_API_KEY``) assign nothing.
    """
    names: set[str] = set()
    pending = [document]
    budget = _MAX_CONFIGURATION_NODES
    while pending and budget:
        node = pending.pop()
        budget -= 1
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    if _environment_key(key):
                        names.update(_assigned_names(value))
                    if key in candidates and _scalar(value):
                        names.add(key)
                if isinstance(value, (dict, list)):
                    pending.append(value)
        elif isinstance(node, list):
            pending.extend(item for item in node if isinstance(item, (dict, list)))
    return names


def _assigns_in_text(text: str, env_names: AbstractSet[str], limits: list[str] | None = None) -> bool:
    """Whether a line of ``text`` assigns one of ``env_names`` (``NAME=value``, ``NAME: value``).

    The pass runs under the per-input matching budget and reads the first
    ``MAX_ASSIGNMENT_LINES`` assignment lines; a file with more has incomplete
    classification unless a configuration assignment is already found. Lower-case
    keys, the bulk of a properties, INI or JSON file, are not
    variable names and cost no match.
    """
    matches = _finditer(_ASSIGNMENT_LINE, text, "catalog assignment lines", MAX_ASSIGNMENT_LINES + 1)
    if any(match[1] in env_names for match in matches[:MAX_ASSIGNMENT_LINES]):
        return True
    if len(matches) > MAX_ASSIGNMENT_LINES and limits is not None:
        limits.append("catalog assignment line limit exceeded; later assignments were not read")
    return False


def configuration_document(
    rel: str,
    text: str,
    parsed: Any,
    env_names: AbstractSet[str],
    root: str = ".",
    *,
    limits: list[str] | None = None,
) -> bool:
    """Whether data file ``rel`` declares what a service or a job runs with, so it is never a catalog.

    ``parsed`` is the file's single parsed document, or None (a stream of several,
    text its parser rejects, or a format without one such as INI); ``env_names``
    are the variable names it mentions; ``root`` is its project's directory.
    A Kubernetes-style resource (``apiVersion`` and ``kind``) or an ECS task
    definition is a deployment, whatever it names, and a file in a configuration
    directory (``_configuration_directory``) is configuration. Any other document
    is configuration when it assigns one of ``env_names``: under an env,
    environment, variables, secrets, containerEnv or remoteEnv key (as a key, or
    as the ``name`` or ``key`` of an item); as a key with a scalar value at any
    depth; or on a line of its own, ``NAME=value`` or ``NAME: value``, with or
    without ``export`` or quotes. A vendor policy that names each product's
    variable as a value (``key_env: OPENAI_API_KEY``), keys a mapping or a list
    by it (in block or flow style, or a TOML inline table) or lists it as a key
    with no value assigns nothing.
    """
    if not _is_data_file(rel):
        return False  # source code and manifests are never catalogs
    if (
        _configuration_directory(rel, root)
        or _kubernetes_resource(text, parsed)
        or _ecs_task_definition(parsed)
    ):
        return True
    if not env_names:
        return False
    return not env_names.isdisjoint(_configured_variables(parsed, env_names)) or _assigns_in_text(
        text, env_names, limits
    )


def catalog_files(
    observations: Iterable[Observation],
    configuration: AbstractSet[str] = frozenset(),
    referenced: Collection[str] = frozenset(),
    root: str = ".",
) -> frozenset[str]:
    """Return the files among ``observations`` that only list technologies.

    ``configuration`` names the files ``configuration_document`` recognized and
    ``referenced`` the data-file names and paths the project's code loads
    (``referenced_data_files``); ``root`` is the project's directory. Neither a
    configuration document, a file in a configuration directory nor a file code
    loads (outside documentation and website directories) is a catalog, and
    their evidence keeps small data files beside a catalog from joining it.
    """
    references = referenced if isinstance(referenced, AbstractSet) else frozenset(referenced)
    signatures: dict[str, set[str]] = defaultdict(set)
    anchored: set[str] = set()
    for match, rel, _ in observations:
        if match.signature.category in _IGNORED_CATEGORIES:
            continue
        signatures[rel].add(match.signature_id)
        if not _mention(match):
            anchored.add(rel)
    mention_only = {
        rel
        for rel in signatures
        if rel not in anchored
        and _is_data_file(rel)
        and rel not in configuration
        and not _configuration_directory(rel, root)
        and not _loaded_by_code(rel, references)
    }
    catalogs = {rel for rel in mention_only if len(signatures[rel]) >= CATALOG_MIN_SIGNATURES}
    # A file whose name indicates a blocklist or policy is a catalog even with
    # fewer signatures: its domain/env mentions are deny rules, not usage.
    for rel in mention_only - catalogs:
        if signatures[rel] and _POLICY_FILE.search(PurePosixPath(rel).stem):
            catalogs.add(rel)
    if catalogs and mention_only.issuperset(signatures):
        # Nothing but mention-only data files names a technology here.
        return frozenset(mention_only)
    return frozenset(catalogs)


def project_catalog_files(
    proj: _ProjectMatches,
    configuration: AbstractSet[str] = frozenset(),
    referenced: Collection[str] = frozenset(),
) -> frozenset[str]:
    """Return a project's catalog-like files, judged over framework and coding-agent matches."""
    return catalog_files(
        [*proj.matches, *(item for items in proj.coding_agent_matches.values() for item in items)],
        configuration,
        referenced,
        root=proj.root,
    )


def catalog_metadata(files: frozenset[str]) -> dict[str, Any]:
    """The ``metadata.catalog_mentions`` value that tells an analyst what was discounted."""
    return {"files": sorted(files)[:MAX_CATALOG_FILES], "min_signatures": CATALOG_MIN_SIGNATURES}
