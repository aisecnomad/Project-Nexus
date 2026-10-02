# ADR-004: Source parsing strategy

**Status:** Proposed
**Date:** 2026-10-01

## Context

The code scanner needs to know which parts of a source file are code, strings
and comments before it can bind imports, recognise agent idioms and withhold
credentials from excerpts. Today that knowledge comes from three places:

- Python uses the standard library (`ast` and `tokenize`) under AST and time
  budgets.
- Every other language goes through hand-written lexers:
  `connectors/code/source_ranges.py` (about 1,200 lines) covers JavaScript and
  TypeScript including JSX, Go, Rust, Java and Kotlin, C#, Ruby, PHP, Swift
  and Dart; `_SourceLexer._code` alone has a cyclomatic complexity of 57.
- The redaction pipeline carries its own call and statement lexers
  (`utils/redaction_calls.py`, `utils/redaction_statements.py`).

Hand-written lexers keep the runtime free of native dependencies, share the
scanner's deadline and budget model, and fail closed on input they cannot
read. They also produce a steady stream of field defects: the 2026-10-01 field
scan found a JSX lexer bug that had marked 139 valid TSX files incomplete
(fixed in #106), and each newly supported language adds another branch to the
same functions.

[tree-sitter](https://tree-sitter.github.io/) is the obvious alternative: a
maintained incremental parser with error recovery and grammars for every
language above.

## Options

**A. Keep the hand-written lexers.** No new runtime dependency; defects keep
arriving through field scans and are fixed one at a time.

**B. Replace them with tree-sitter at runtime.** Real syntax trees and far less
hand-written lexing. Costs:

- A native extension plus one grammar package per language. Each is a
  platform-specific wheel that must be hash-locked for Linux and macOS and for
  Python 3.11–3.13. The tree-sitter organisation maintains only some of the
  grammars; Swift, Dart and Kotlin come from community projects, so wheel
  availability and maintenance have to be checked when adopting them.
- Native code parsing untrusted repositories inside the scanner process. A
  crash ends the scan (it fails closed, but it is a denial of service), so
  parsing would need a subprocess or another isolation boundary.
- Parse cancellation has to be wired into the existing per-input deadline and
  matcher budgets.
- Version coupling between the runtime and each grammar's ABI.

**C. Keep the lexers at runtime and add tree-sitter as a test oracle.** Add
tree-sitter to the development lock only. A differential test compares the
lexers' code, string and comment ranges with tree-sitter's on the evaluation
corpora and on a fixed set of public repositories, and reports disagreements
as candidate defects.

## Decision (proposed)

Adopt **C** now: keep the runtime free of native parsers and use tree-sitter
to find lexer defects before field scans do.

Revisit **B** if either of these holds:

- Differential testing keeps finding lexer defects that targeted fixes cannot
  contain.
- A new language would need another hand-written lexer.

Runtime adoption would require hash-locked wheels for every supported
platform, an optional extra rather than a core dependency, crash isolation,
and deadline enforcement equivalent to today's budgets.

## Consequences

**Positive:**

- The supply chain and the runtime's trust boundary stay as they are.
- Lexer defects become measurable, so the decision to switch can rest on data.

**Negative:**

- The complexity of `source_ranges.py` stays until B is adopted.
- The development lock grows by the tree-sitter wheels, and the differential
  test needs triage whenever a grammar and a lexer legitimately disagree.
