"""Load the packaged mapping catalogs and rules, refusing links and malformed files.

The data directory holds ``frameworks/*.yaml`` (one catalog per framework
edition) and ``rules/{threats,layers,controls}.yaml``. Nothing else is
accepted there: a symbolic link, another file type or a missing rules file is
a problem, never silently skipped. Only the packaged directory is read by the
scanner; tests and the validator may name another directory.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from shadowscan.errors import yaml_error_position
from shadowscan.mappings.schema import (
    RULE_FILES,
    Catalog,
    MappingCatalogError,
    MappingEntry,
    Rule,
    parse_catalog,
    parse_rules,
)
from shadowscan.utils.files import SKIPPED_LINK, policy_files, read_policy_text
from shadowscan.utils.safe_yaml import strict_bounded_safe_load

MAX_MAPPING_FILE_BYTES = 1024 * 1024


def builtin_mapping_dir() -> Path:
    return Path(str(resources.files("shadowscan.mappings") / "data"))


def _yaml_files(root: Path, directory: str, problems: list[str]) -> dict[str, Path]:
    """The ``.yaml`` files directly in ``root/directory``, by name; anything else is a problem."""
    skipped: list[tuple[str, str]] = []
    try:
        found = list(policy_files(root / directory, {".yaml"}, skipped))
    except (OSError, ValueError):
        problems.append(f"{directory}: directory is missing, unreadable or reached through a symbolic link")
        return {}
    for name, reason in skipped:
        what = "symbolic links are not followed" if reason == SKIPPED_LINK else "only .yaml files are allowed"
        problems.append(f"{directory}/{name}: {what}")
    files: dict[str, Path] = {}
    for path in found:
        relative = path.relative_to(root / directory)
        if len(relative.parts) != 1:
            problems.append(f"{directory}/{relative.as_posix()}: subdirectories are not allowed")
            continue
        files[path.name] = path
    return files


def _load(path: Path, source: str, problems: list[str]) -> Any:
    try:
        return strict_bounded_safe_load(read_policy_text(path, MAX_MAPPING_FILE_BYTES))
    except yaml.YAMLError as exc:
        # PyYAML can quote the offending source line; keep only its position.
        problems.append(f"{source}: invalid YAML{yaml_error_position(exc)}")
    except (OSError, ValueError):
        problems.append(f"{source}: cannot be read as a regular UTF-8 file within the size limit")
    return None


def load_mapping_directory(root: Path) -> tuple[tuple[Catalog, ...], tuple[Rule, ...]]:
    """Validate and load every catalog and rule below ``root``.

    Raises MappingCatalogError listing every problem found.
    """
    problems: list[str] = []
    catalogs: list[Catalog] = []
    for name, path in sorted(_yaml_files(root, "frameworks", problems).items()):
        source = f"frameworks/{name}"
        data = _load(path, source, problems)
        if data is not None:
            catalog = parse_catalog(data, source, problems)
            if catalog is not None:
                catalogs.append(catalog)
    if not catalogs and not problems:
        problems.append("frameworks: no catalogs found")
    entries: dict[str, MappingEntry] = {}
    seen_prefixes: dict[str, str] = {}
    for catalog in catalogs:
        if catalog.prefix in seen_prefixes:
            problems.append(
                f"{catalog.source}: prefix {catalog.prefix} is also used by {seen_prefixes[catalog.prefix]}"
            )
            continue
        seen_prefixes[catalog.prefix] = catalog.source
        entries.update((entry.ref, entry) for entry in catalog.entries)
    rule_files = _yaml_files(root, "rules", problems)
    for name in sorted(set(rule_files) - set(RULE_FILES)):
        problems.append(f"rules/{name}: unexpected rules file; use {', '.join(RULE_FILES)}")
    rules: list[Rule] = []
    for name, kind in RULE_FILES.items():
        source = f"rules/{name}"
        if name not in rule_files:
            problems.append(f"{source}: missing")
            continue
        data = _load(rule_files[name], source, problems)
        if data is not None:
            rules.extend(parse_rules(data, source, kind, entries, problems))
    seen_rules: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen_rules:
            problems.append(f"{rule.source}: rule id {rule.id} is also used in {seen_rules[rule.id]}")
        seen_rules.setdefault(rule.id, rule.source)
    if problems:
        raise MappingCatalogError(problems)
    return tuple(catalogs), tuple(rules)
