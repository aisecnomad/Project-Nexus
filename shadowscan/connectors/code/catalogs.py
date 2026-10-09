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
  CI pipelines, Spring configuration, dependency manifests, IaC), nor a
  configuration document (``configuration_document``: a Kubernetes-style
  resource, an ECS task definition, or a file that assigns a variable it
  names under an ``env``, ``environment``, ``variables`` or ``secrets`` key);
* every non-heuristic match in it is a mention-class signal (``domain``,
  ``env`` or ``name``), so the file holds no import, dependency, code,
  file-name, image, IaC, model or credential anchor; and
* its matches span at least ``CATALOG_MIN_SIGNATURES`` distinct signatures, or
  its file stem names a deny list: a whole word, or two adjacent words, spell
  ``blocklist``, ``denylist`` or ``blacklist`` (``ai-blocklist.yaml``,
  ``deny_list.json``). An allowlist, a whitelist, an egress policy or a
  firewall or WAF rule set is not a deny list: it permits traffic, often to
  exactly the hosts it names, so a bare ``block``, ``deny``, ``firewall`` or
  ``waf`` (``firewall-rules.json``, ``default-deny.yaml``) is not enough.

Why four is a judgement from the data at hand: the bundled evaluation corpora's
multi-provider configurations are dotenv files naming three or four products
(exempt as manifests), the regression fixtures' blocklists and vendor policies
name six to ten, and the bundled signature packs seven to thirty-six per file.
Four keeps a three-provider configuration and catches every list of four or
more; a list of two or three products cannot be told from configuration.

Small data files cannot be told from configuration on their own (one domain
in ``policies.yaml`` looks like one ``base_url`` in ``config.yaml``). When a
project holds a catalog and nothing else but mention-only data files, those
files are one catalog: nothing in the project uses a technology it names.

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
from collections.abc import Callable, Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Any, Protocol

from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.signatures import Match

Observation = tuple[Match, str, str | None]  # match, relpath, snippet

# Distinct signatures one data file must name before it reads as a list.
CATALOG_MIN_SIGNATURES = 4
# Signals that name a product without configuring or running it. A model id in
# a configuration is a selection, and an image, resource type or credential
# belongs to a deployment, so none of those is a mention.
CATALOG_MENTION_SIGNALS = frozenset({"domain", "env", "name"})
# Files listed in ``metadata.catalog_mentions``.
MAX_CATALOG_FILES = 20

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
# Whole words of a file stem that name a deny list. An allowlist, a whitelist, an
# egress policy or a firewall or WAF rule set (a default-deny policy with allow
# exceptions) permits the traffic it names, which is evidence of use, and a
# substring would also match "oracle" (acl), "dropdown" or "blockchain".
_DENY_LIST_WORDS = frozenset({"blocklist", "denylist", "blacklist"})
_STEM_SEPARATORS = re.compile(r"[._-]+")
# Spring application and bootstrap configuration, including profiles (application-prod.yml).
_SERVICE_CONFIGURATION = re.compile(r"(?:application|bootstrap)(?:-[\w.-]+)?\.(?:ya?ml|properties)")
# Keys whose entries assign variables to a container, a job or a function. Compared without
# case, "_" or "-": env, environment, variables, vars, envVars, environment_variables, secrets.
_ENVIRONMENT_KEYS = frozenset(
    {"env", "envs", "environment", "variables", "vars", "envvars", "environmentvariables", "secrets"}
)
# Top-level keys of a Kubernetes-style resource, read from the text: a stream of several
# documents has no single parsed form, and each of its resources starts with them.
_RESOURCE_KEY = re.compile(r"^(apiVersion|kind)[ \t]*:", re.MULTILINE)
# Mappings and lists inspected per document for variable assignments.
_MAX_CONFIGURATION_NODES = 100_000


class _ProjectMatches(Protocol):
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


def _configured_variables(document: Any) -> set[str]:
    """Variable names ``document`` assigns under an environment key, at any depth."""
    names: set[str] = set()
    pending = [document]
    budget = _MAX_CONFIGURATION_NODES
    while pending and budget:
        node = pending.pop()
        budget -= 1
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and _environment_key(key):
                    names.update(_assigned_names(value))
                if isinstance(value, (dict, list)):
                    pending.append(value)
        elif isinstance(node, list):
            pending.extend(item for item in node if isinstance(item, (dict, list)))
    return names


def configuration_document(rel: str, text: str, parsed: Any, env_names: AbstractSet[str]) -> bool:
    """Whether data file ``rel`` declares what a service or a job runs with, so it is never a catalog.

    ``parsed`` is the file's single parsed document, or None (a stream of several,
    or text its parser rejects); ``env_names`` are the variable names it mentions.
    A Kubernetes-style resource (``apiVersion`` and ``kind``) or an ECS task
    definition is a deployment, whatever it names. Any other document is
    configuration when it assigns one of ``env_names``: as a key, or as the
    ``name`` or ``key`` of an item, under an env, environment, variables or
    secrets key. A vendor policy that names each product's variable as a value
    (``key_env: OPENAI_API_KEY``) assigns nothing.
    """
    if not _is_data_file(rel):
        return False  # source code and manifests are never catalogs
    if _kubernetes_resource(text, parsed) or _ecs_task_definition(parsed):
        return True
    return bool(env_names) and not env_names.isdisjoint(_configured_variables(parsed))


def deny_list_file(rel: str) -> bool:
    """Whether ``rel`` is named as a block or deny list (``ai-blocklist.yaml``, ``deny_list.json``)."""
    words = _STEM_SEPARATORS.split(PurePosixPath(rel).stem.lower())
    # "block-list" and "deny_list" spell the same nouns as two words.
    terms = {*words, *(first + second for first, second in pairwise(words))}
    return not _DENY_LIST_WORDS.isdisjoint(terms)


def catalog_files(
    observations: Iterable[Observation], configuration: AbstractSet[str] = frozenset()
) -> frozenset[str]:
    """Return the files among ``observations`` that only list technologies.

    ``configuration`` names the files ``configuration_document`` recognized:
    they are never catalogs, and their evidence keeps small data files beside a
    catalog from joining it.
    """
    signal_types: dict[str, set[str]] = defaultdict(set)
    signatures: dict[str, set[str]] = defaultdict(set)
    for match, rel, _ in observations:
        if match.signature.category in _IGNORED_CATEGORIES:
            continue
        signal_types[rel].add(match.signal.type)
        signatures[rel].add(match.signature_id)
    mention_only = {
        rel
        for rel, types in signal_types.items()
        if types <= CATALOG_MENTION_SIGNALS and _is_data_file(rel) and rel not in configuration
    }
    catalogs = {rel for rel in mention_only if len(signatures[rel]) >= CATALOG_MIN_SIGNATURES}
    # A file named as a block or deny list is a catalog even with fewer
    # signatures: its domain and variable mentions are deny rules, not usage.
    for rel in mention_only - catalogs:
        if signatures[rel] and deny_list_file(rel):
            catalogs.add(rel)
    if catalogs and mention_only.issuperset(signal_types):
        # Nothing but mention-only data files names a technology here.
        return frozenset(mention_only)
    return frozenset(catalogs)


def project_catalog_files(
    proj: _ProjectMatches, configuration: AbstractSet[str] = frozenset()
) -> frozenset[str]:
    """Return a project's catalog-like files, judged over framework and coding-agent matches."""
    return catalog_files(
        [*proj.matches, *(item for items in proj.coding_agent_matches.values() for item in items)],
        configuration,
    )


def catalog_metadata(files: frozenset[str]) -> dict[str, Any]:
    """The ``metadata.catalog_mentions`` value that tells an analyst what was discounted."""
    return {"files": sorted(files)[:MAX_CATALOG_FILES], "min_signatures": CATALOG_MIN_SIGNATURES}
