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
  CI workflows, dependency manifests, IaC);
* every non-heuristic match in it is a mention-class signal (``domain``,
  ``env`` or ``name``), so the file holds no import, dependency, code,
  file-name, image, IaC, model or credential anchor; and
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
files are one catalog: nothing in the project uses a technology it names.

Observations from a catalog count as mentions: they establish a technology only
when the same signature also has library evidence (an import, a dependency or a
specific code pattern) elsewhere in the project, as for an ambiguous pattern.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
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


class _ProjectMatches(Protocol):
    @property
    def matches(self) -> Sequence[Observation]: ...

    @property
    def coding_agent_matches(self) -> Mapping[str, Sequence[Observation]]: ...


def _is_data_file(rel: str) -> bool:
    path = PurePosixPath(rel)
    parts = path.parts
    return (
        path.suffix.lower() in _DATA_SUFFIXES
        and not is_manifest_name(path.name)
        and not (".github" in parts and "workflows" in parts)
    )


def catalog_files(observations: Iterable[Observation]) -> frozenset[str]:
    """Return the files among ``observations`` that only list technologies."""
    signal_types: dict[str, set[str]] = defaultdict(set)
    signatures: dict[str, set[str]] = defaultdict(set)
    for match, rel, _ in observations:
        if match.signature.category in _IGNORED_CATEGORIES:
            continue
        signal_types[rel].add(match.signal.type)
        signatures[rel].add(match.signature_id)
    mention_only = {
        rel for rel, types in signal_types.items() if types <= CATALOG_MENTION_SIGNALS and _is_data_file(rel)
    }
    catalogs = {rel for rel in mention_only if len(signatures[rel]) >= CATALOG_MIN_SIGNATURES}
    if catalogs and mention_only.issuperset(signal_types):
        # Nothing but mention-only data files names a technology here.
        return frozenset(mention_only)
    return frozenset(catalogs)


def project_catalog_files(proj: _ProjectMatches) -> frozenset[str]:
    """Return a project's catalog-like files, judged over framework and coding-agent matches."""
    return catalog_files(
        [*proj.matches, *(item for items in proj.coding_agent_matches.values() for item in items)]
    )


def catalog_metadata(files: frozenset[str]) -> dict[str, Any]:
    """The ``metadata.catalog_mentions`` value that tells an analyst what was discounted."""
    return {"files": sorted(files)[:MAX_CATALOG_FILES], "min_signatures": CATALOG_MIN_SIGNATURES}
