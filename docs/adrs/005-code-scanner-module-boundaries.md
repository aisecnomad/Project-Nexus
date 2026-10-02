# ADR-005: Code scanner module boundaries

**Status:** Proposed
**Date:** 2026-10-01

## Context

`FilesystemConnector` (`connectors/code/filesystem.py`, lines 776–2799) is one
class of about 2,000 lines and 77 methods. It walks the tree, accounts for
coverage, reads and redacts files, dispatches them by type, resolves ownership
and builds every kind of code finding. The `github` and `gitlab` connectors
reuse it for cloned repositories, so any defect or change in it reaches three
connectors.

The methods already fall into four groups with few calls between them:

| Group | Methods (current lines) | Responsibility |
|---|---|---|
| Walk | `_excluded` … `_walk_entries` (948–1292) | Root opening, exclusions, links, oversize files, deadlines and coverage accounting |
| File scan | `_scan_file` … `_record_special_files` (1293–1754) | Reading, redacted excerpts, and dispatch to the manifest, IaC, config, source and secret paths |
| Ownership | `_git_info` … `_owners_for_files` (1980–2127) | Git history and CODEOWNERS (next to the existing `code/ownership.py`) |
| Findings | `_emit_findings` … `_parse_agent_definition` (1755–1979, 2128–2799) | Projects, coding agents, MCP servers, cards, manifests, workflows, IaC and secret findings |

Tests depend on the current layout: 23 `monkeypatch.setattr` calls target
filesystem internals and 6 test modules import private names from it.

The earlier split of `utils/redaction.py` into `redaction_*` modules kept such
patches working by replacing the module's class so that one assignment writes
to every module (`redaction.py`, end of file). That kept the tests unchanged,
but patched names now behave differently depending on which module they are
set on. This split should not repeat that pattern.

## Decision (proposed)

Split along the four groups into collaborator classes, not mixins:

- `code/walk.py` — a tree walker that yields entries and coverage events.
- `code/file_scan.py` — a file scanner that reads, redacts and dispatches one
  file.
- `code/ownership.py` — gains git-history and CODEOWNERS resolution.
- `code/project_findings.py` — builds findings from project and file
  observations.

`FilesystemConnector` stays the façade that implements `collect()` and
`analyze()`, owns the `ConnectorContext`, and wires the collaborators
together.

Rules for the migration:

1. **Sequence after #107.** That pull request changes `filesystem.py` in
   several places; moving code first would make it unmergeable.
2. **One pull request per group,** moving code without changing behaviour.
3. **Prove "no behaviour change" with output equality:** identical JSON reports
   (ignoring timestamps) on every evaluation corpus, the offline demo, and a
   fixed list of public repositories like the one used for the 2026-10-01
   field scan.
4. **Migrate test seams in the same pull request:** patch the collaborator or
   inject it, rather than adding forwarding or module-class tricks.

## Consequences

**Positive:**

- Each module can be read, owned and tested on its own; the coverage and
  fail-closed accounting in particular becomes reviewable in isolation.
- Defects in one area, such as tree walking, cannot silently change finding
  construction.

**Negative:**

- Four pull requests of pure code movement, each needing the output-equality
  check.
- Test changes in the same pull requests as the moves.
