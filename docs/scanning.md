# Scan state and runtime correlation

## Coverage policy

A code scan is *complete* when every file it was asked to assess was assessed.
Situations that are deliberately outside a repository's own content, and gaps
that are never silent:

* **Symbolic links** are never entered by the walk. A link that resolves inside
  the scan root is analyzed as a copy of its target would be at the link's
  path, which is what a client that follows the link reads (a coding agent
  loading `.claude/skills -> ../.agents/skills`). The target is read at its
  real path, relative to the opened scan root and without following a link in
  any path component, and every rule that depends on a path sees the link's
  path: exclusions, file names, projects, test classification, coding-agent
  settings and agent-definition directories, plugin roots, template paths and
  local Python modules (looked up beside the link). Findings name the link's
  path, so content reachable at two paths is reported at both, as two copies
  would be. Content is decoded and judged under the link's name (a link
  `agent.ipynb` to a JSON file is read as a notebook). A directory link's target
  is listed at its real path, and its files count toward `max_files`; at most
  20,000 files and directories per scan root are analyzed this way. Evidence
  limits keep the first items found in walk order, and a directory link's files
  are found after its parent directory's own, so a capped evidence list can
  differ from a copy's. A dangling link whose own name carries no file-name
  signal and whose target would be inside the tree hides nothing and is noted
  with a warning. Every other link makes the scan incomplete (exit code 3):
  links that leave the root or do not resolve, a link whose target cannot be
  inspected, a cycle (a link inside its own target), an unreadable directory, a
  link or `.gitmodules` file below a linked directory, and links beyond the
  20,000-entry budget.
  Files are read relative to the opened scan root without following a link in
  any path component, so a directory replaced by a link after the walk listed it
  fails that file's read (incomplete) instead of reading content outside the
  root. Like a read by path, this needs only search permission on the
  directories above each file.
* **Oversize files** (`max_file_size`, default 4 MiB) that the scanner would
  inspect make the scan incomplete when skipped. Documentation and data files
  (JSON, YAML, TOML, XML, Markdown, text, reStructuredText, HTML) and files
  under a test path are read and analyzed in full up to `max_data_file_size`
  (default 32 MiB) instead; a limit
  their analysis reaches, such as the YAML parser's, still makes the scan
  incomplete. Known generated, binary and lockfile names in
  `oversize_skip_globs` are declared omissions and remain warnings, including
  when `strict_coverage` is enabled. An oversize compiled or packed binary with
  no file extension is skipped as a smaller one is (below). A test file over
  `max_data_file_size` stays a gap.
* **Binary or undecodable content.** Text with a UTF-8, UTF-16 or UTF-32
  byte-order mark is decoded and the mark removed. A Python source is decoded
  with the codec its `# coding:` cookie declares. Any other file the scanner
  analyzes by name (source, configuration, documents, `.env`, extensionless
  files) that has a NUL byte in its first 8 KiB, or that its declared codec
  cannot decode or does not read as ASCII where the bytes are ASCII (UTF-16 or
  UTF-32 without a byte-order mark, UTF-7, HZ, EBCDIC code pages), makes the
  scan incomplete (exit code 3) with `binary or
  undecodable content in analyzable file`; it is never silently treated as
  empty. Two kinds of text are read despite that: a JavaScript or TypeScript
  source that is valid UTF-8 and in which NUL bytes are at most 1% of the bytes
  (or at most four), since the engines accept a NUL character in a string
  literal; and text in a legacy code page
  (Windows-1252, Shift-JIS) without such NULs, decoded with replacement
  characters and noted with the warning `not valid UTF-8; undecodable bytes
  replaced and the text analyzed`. The decoder never consumes an ASCII byte,
  so every ASCII token is read as written; while a loaded signature pattern
  contains a non-ASCII character, such text stays a gap. A Git repository kept
  in the tree under another name (a bare `name.git` fixture, a test's
  `dotGit`) is recognised by a valid `HEAD`, `objects/` and `refs/` and nothing
  but Git's own entries, and noted with a warning (five per root by name).
  Only its binary formats are skipped, each verified by path and content: a
  loose object must inflate to a Git object header, and packs, their indexes
  and companions, commit graphs and the index must start with their signature
  and binary version. Its hooks and other files are analyzed. Binary content under a test path is a gap like anywhere else. A
  compiled or packed artifact with no file extension and a known header (ELF,
  Mach-O, WebAssembly, gzip, zip, bzip2, xz, zstd, 7z, PNG, JPEG, GIF, PDF,
  WebP and other RIFF media, Ogg, FLAC, MP3, TIFF, ICO) is skipped quietly, as
  are names the scanner never analyzes
  (images, archives, fonts, lockfiles, minified bundles). Exclude a directory
  of binary data that carries an analyzed extension.
* **Default-excluded directories.** The walk skips a built-in list of directory
  names (see `default_excludes` in the [code connector](connectors/code.md)).
  Tool metadata, caches, virtualenvs and dependency trees are skipped without
  comment. A skipped `bin`, `build`, `dist`, `out`, `target`, `obj`, `coverage`,
  `vendor`, `third_party`, `thirdparty` or `external` directory that holds a
  file is a warning (the scan stays complete) naming each such directory name
  with its count, because projects also keep their own code there.
  `default_excludes: false` (`--no-default-excludes`) scans them.
* **Submodules** are never initialized or fetched. Bounded `.gitmodules`
  declarations identify missing, empty or unsafe source directories as coverage
  gaps, including declarations inside materialized nested directories. Ordinary
  files in materialized submodule directories are scanned by the same confined
  walker. GitHub/GitLab clone collection additionally inventories gitlinks in
  the committed `HEAD` tree (this needs Git 2.45 or newer); local scans do so only with `use_git: true` and a
  local `.git` directory. Malformed declarations or a failed authorized Git
  inventory make coverage incomplete. Explicitly excluded submodule paths are
  outside the declared scan scope. A nonempty directory establishes only that
  source is available to scan, not that it matches an authentic remote commit.
* **Undecodable or binary content** in a file whose name the scanner would
  analyze (source, manifests, `.env`, configuration, MCP and agent files,
  notebooks) makes the scan incomplete with `binary or undecodable content in
  analyzable file`. Text with a UTF-8, UTF-16 or UTF-32 byte-order mark is
  decoded and analyzed (the mark is removed, so a BOM-prefixed `.mcp.json`
  parses). A file with a NUL byte in its first 8 KiB and no byte-order mark is
  not text in any supported encoding, yet interpreters such as Node and `sh`
  still run a script with a NUL in a comment, so it is a gap, not an empty file;
  this includes UTF-16 without a byte-order mark. Invalid UTF-8 and malformed
  BOM-declared content also make coverage incomplete, with a fixed diagnostic
  that does not expose the rejected bytes. Names the scanner
  never reads (images, archives, `.bin`, compiled artifacts) stay silent, and so
  does a recognised binary artifact (an executable, archive, image, PDF or
  SQLite database, by its header) that has no file extension, that only a
  directory-wide signature glob such as `.cursor/rules/**` selected.
  Unrecognised binary content stays a gap in those places too. An operator can
  exclude a known binary with an `exclude` file glob.
* **Entries that are not regular files** (a directory, FIFO, socket or device)
  named like a file the scanner analyzes, such as `.mcp.json` or
  `requirements.txt`, make the scan incomplete, and so does a symbolic link of the
  same name whose target is one. A directory is only reported when its name is an MCP configuration
  file name such as `.mcp.json`; directories that agent tools read as
  directories (`.roo/rules/`, `.clinerules/`, `.cursor/rules/`) are not. Its
  contents are still scanned.
* **Directory nesting** of any depth is walked on an explicit stack, so a tree
  deeper than the Python runtime's recursion limit loses no findings.

Default directory excludes are part of the documented scope and never make a
scan incomplete, but they are not silent. The names in `DEFAULT_EXCLUDES` are
skipped at any depth (`bin`, `build`, `dist`, `external`, `obj`, `out`, `target`,
`vendor`, `third_party`, `coverage` and others, plus version-control metadata,
dependency trees and tool caches). For each scan root one warning lists the
non-empty first-party-capable directories that were skipped, with how many
carried each name (`default-excluded directories not scanned: build (2),
vendor (1); set default_excludes: false to scan them`). Version-control
metadata, dependency trees, virtual environments and tool caches (`.git`,
`node_modules`, `venv`, `__pycache__`, `.idea` and similar) are not listed, and
neither is a name the operator listed in `exclude`. Code under a listed name was
not assessed; `default_excludes: false` (`--no-default-excludes`) scans it, or
scan that directory as its own root.

Default local scans do not execute Git: an undeclared gitlink without a
`.gitmodules` file is therefore not discoverable in that mode. The opt-in Git
inventory reads committed `HEAD`, not staged-only index entries; an undeclared,
staged-only gitlink is likewise outside that check. Use a reviewed committed
checkout and declared submodule paths when completeness matters.

By default, incomplete coverage is recorded as a warning and exits 3.
`strict_coverage: true` (`--strict-coverage`) elevates the diagnostic to an
error; it does not change the exit code. Raise `max_file_size`, explicitly
exclude known data, or review `oversize_skip_globs` for the intended scope.

Analysis limits are reported with their reason, for example
`file analysis incomplete (MatchTimeoutError: source binding call limit exceeded)`.
The import binder only counts calls into modules that a signature describes,
so large ordinary files (test suites, HTTP clients) no longer hit the limit.
Its node budget (`max_ast_nodes`) and nesting limit likewise apply only to a
Python module with an import that can resolve to a signature. The binder is
skipped for any other module, of any size, because it could not contribute
evidence there. Deciding that is linear in the module and matches at most
4,096 distinct import statements, so it cannot exhaust a file's matching budget.
A large module that does import such a library, or has more imports than that,
still reports
`import-bound analysis skipped (source binding AST limit exceeded); lexical evidence retained`.

The JavaScript and TypeScript lexer that masks comments, strings and JSX text
has a look-ahead allowance of its own: a fixed floor plus four characters of
look-ahead per character of the file. Real components use under one percent of
it. A JSX file that exhausts it, such as tens of thousands of repeated `<A>(`,
ends in well under a second with
`file analysis incomplete (MatchTimeoutError: JavaScript lexical analysis look-ahead budget exceeded)`
instead of stalling the scan until the connector deadline. Other files are
unaffected and the scan exits 3.

## Test and fixture code

Library test suites often construct agents to exercise integrations. Evidence
found only under test or fixture paths (`tests/`, `fixtures/`, `cassettes/`,
`__mocks__/`, `test_*.py`, `*_test.go`, `*.spec.ts`, …) has half weight and cannot
promote a project to an *agent*; a project whose evidence is entirely test code
is tagged `test-code-only`. Exported low-code workflows found under those paths
follow the same rule. Set `include_tests: true` (`--include-tests`) to
treat test code like any other source. A real-format credential under a test,
fixture or `cassettes/` path is still reported as a `secret` finding, because
recorded cassettes capture real traffic and a committed key is exposed wherever
it lives; without `include_tests` it has half weight and the `test-code-only`
tag. Recognisable placeholders (repeated characters, marker words such as
`EXAMPLE`, or very low character diversity) are never reported.
Evidence that only names a coding agent in a test path (an environment variable,
a display name, a dependency or a code pattern) likewise does not establish a
coding-agent configuration; instruction documents and coding-agent config
files still do. Test suites keep malformed files on purpose, so a parse or
validation issue in a file under a test path (an invalid `package.json` or
agent manifest fixture) is a warning rather than a coverage gap, as the
import-bound analysis limits in test code already are; `include_tests` or
`strict_coverage` keeps it incomplete. The same holds for a parser resource
limit and a missing submodule under a test path. Binary content and a test
file over `max_data_file_size` stay gaps, since test evidence is still
reported. An MCP configuration is the other exception: its finding is not
discounted in test code, so an issue in it keeps the scan incomplete. When an
excerpt cannot be sanitized within its limits, anywhere, the excerpts are
withheld with a warning and the findings kept; evidence is still found in the
raw text and reported without an excerpt. The test directory names include `test_resources` and
`test-resources`.

## Incremental scans

Incremental mode reuses a completed connector result when the fingerprint of its
inputs, connector options, signature definitions and scanner implementation is
unchanged. The fingerprint is a SHA-256 digest over the content of every file the
scanner can read plus the size, modification and change times, mode, device and
inode of every file and directory, so a fresh checkout at a new inode does not hit
the cache. Files over `max_file_size` contribute only that metadata. The scanner
never opens most of them; notebooks and documentation or data files that it
reads beyond that limit are tracked the same way, and an edit changes their
change time, which the metadata includes. Inventory approval,
risk scoring and runtime correlation always run again. New, edited and deleted
files invalidate the affected repository.

```bash
shadowscan code ./repo-a ./repo-b --incremental
shadowscan run cloud.aws --input ./exports/aws.jsonl --incremental
shadowscan scan -c shadowscan.yaml --no-incremental
```

Equivalent YAML:

```yaml
options:
  incremental: true
  state_dir: ../private-scan-state
connectors:
  - name: code.filesystem
    paths: [./repo-a, ./repo-b]
  - name: cloud.aws
    input: ./exports/aws.jsonl
```

Each `code.filesystem.paths` root is a separate cache unit. Offline local directory
inputs to `code.github` / `code.gitlab` and static exports to the four `cloud.*`
connectors are also eligible. Live remote repositories, live cloud APIs, gateway
logs, identity, SaaS inputs and third-party connectors are collected anew: unchanged configuration cannot
establish that remote state is unchanged. Hashing still reads eligible inputs;
the saving is avoiding repeated parsing and signature evaluation.

When a shared `label` is set for multiple `code.filesystem.paths`, add
`root_ids: [repo-a, repo-b]` in the same order as `paths`. This keeps each root's
finding identity stable when the checkout location or list length changes.
Without `root_ids`, the canonical local path determines a distinct root suffix.
Using a scalar `path` with its own connector `label` preserves the older ID.

The default state location is `$XDG_STATE_HOME/shadowscan`, or
`~/.local/state/shadowscan` when `XDG_STATE_HOME` is unset, empty or relative
(as the XDG specification requires). `--state-dir` overrides it; YAML relative paths are
resolved against the configuration file. Keep the directory outside every scan
input. State uses a private 0700 directory and atomic 0600 JSON files containing
sanitized, unscored findings, not source content or raw credentials. Protect the
state as local security data; a checksum detects corruption, not a malicious user
who controls the scanner account. Remove the state directory to clear it.

Incomplete scans are never cached; a complete scan whose only diagnostics are
warnings, such as skipped oversize generated files, is cached and replays those
warnings on every hit. Corrupt, incompatible or unsafe state and
symlink-bearing eligible inputs cause a full scan. Hashing has conservative limits:
512 MiB total, 200,000 entries, 30 seconds per snapshot, and 64 MiB per hashed
file; code files over `max_file_size` (default 4 MiB) are tracked by
metadata rather than hashed. Exceeding a
limit falls back to normal scanning. Git replacement refs, grafts or externally
overridden history also disable reuse; HEAD and shallow boundaries are tracked.
Symlinked roots and ancestor path components are also ineligible for reuse.
Input changes detected between hashing and collection make the result
incomplete and require a rerun. `--dump-records` disables cache reuse to ensure the
requested export is actually collected. JSON connector statistics expose `cached`;
the private cache fingerprint stays in the access-restricted state directory.
Cached connectors examine zero objects during analysis.
Pre/post hashes do not form an atomic snapshot: inputs must remain immutable
throughout the scan to exclude changes that occur and revert between reads.

## Offline input limits

Offline connectors skip symlinks and bound directory walks and file parsing. The
defaults are 10,000 files, 32 MiB per file, and 256 MiB total per connector input.
JSONL, CSV and gateway text logs are streamed; individual lines are capped at
4 MiB. Gzip gateway logs are limited by expanded size as well as compressed file
size. JSON and YAML documents are parsed only after their file and aggregate byte
limits pass.

Set `max_input_files`, `max_input_file_bytes` or `max_input_bytes` on a connector
to change these limits. Gateway scans also honor `max_records` (default 5,000,000)
while analyzing streamed events. If any limit is reached, ShadowScan retains the
findings already collected and marks the connector incomplete; check the warnings
and rerun with an appropriate limit to claim full coverage. The existing hard
ceilings remain 200,000 directory entries, 64 MiB per file and 512 MiB total.
`options.min_confidence` must be a finite number from 0 through 1, inclusive.

YAML also has structural limits before object construction: 100,000 composed or
expanded nodes, 1,000 aliases, depth 64 and 64 MiB of expanded scalar content.
Recursive aliases and excessive merge expansion are rejected. Sanitization uses
separate structure and work budgets; rejected records mark collection incomplete
while valid neighboring records remain available. CODEOWNERS matching has a
bounded per-lookup work budget; an exhausted lookup marks the root's ownership
coverage incomplete.

Record dumps use a private directory and distinct filenames per configured
connector instance. `manifest.json` maps configuration ordinals to committed
export files and records each instance's completion status. Use only entries
marked `exported: true`; a failed attempt may leave an older file in place.
`gateway.logs` does not export source records through `--dump-records`: provider
key IDs and arbitrary log payloads can be sensitive even when a generic field
sanitizer does not recognize them. Its manifest entry has `exported: false`;
gateway findings and scan completion are unaffected.
See [deployment and migration](production.md) for explicit plugin, signature
override and private-endpoint policies, output changes and rollout checks.

## Large and generated files

`code.filesystem.max_file_size` (default 4 MiB) bounds every source file the
scanner reads. A larger file is never analyzed. Each signature pattern may use
0.1 s of CPU per 1,000,000 characters of a file (and at least 0.1 s), within
the file's matching budget; a pattern that exceeds it marks the scan
incomplete. Whether a skipped file makes the scan incomplete depends on what it
could hide:

* A file whose name matches `oversize_skip_globs` is skipped with a warning and
  the scan stays complete. The default list names lockfiles (`package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`,
  `Gemfile.lock`, `composer.lock`, `go.sum`), minified bundles and source maps
  (`*.min.js`, `*.min.css`, `*.map`), data and vector graphics (`*.svg`, `*.csv`,
  `*.parquet`), compiled or packaged artifacts (`*.wasm`, `*.so`, `*.dylib`,
  `*.dll`, `*.jar`, `*.pyc`, `*.class`), documents, images and fonts (`*.pdf`,
  `*.png`, `*.jpg`, `*.jpeg`, `*.gif`, `*.woff`, `*.woff2`, `*.ttf`) and archives
  (`*.zip`, `*.gz`, `*.tar`). Such content is generated from sources the scanner
  does inspect, or is binary, so no agent configuration, framework usage or
  credential evidence is lost by skipping it. The warning still names each file
  so the omission is visible. Lockfiles, minified bundles, source maps and
  bytecode below the limit are skipped silently because they are never analyzed.
* Every other oversize file, for example a 2 MiB Python module, JSON or YAML
  document, is skipped and makes the scan incomplete (exit 3). With
  `strict_coverage: true` (`--strict-coverage`) it is recorded as an error
  instead of a warning. Raise `max_file_size`,
  exclude the directory, or add the name to `oversize_skip_globs` after
  confirming it carries no agent evidence.

`oversize_skip_globs` replaces the default list with case-insensitive file-name
globs; a pattern containing `/` is matched against the path relative to the scan
root. A matching file stays a warning even under `strict_coverage`; an empty
list makes every oversize file that the scanner would read incomplete. Oversize files that are never read at any size, such as executables or
media in other formats, are skipped silently as before.

The per-file matching budget also grows with size. `scan_timeout` (default 2
seconds) covers files up to 256 KiB; each further 256 KiB adds one more budget,
with the final 64 KiB of the first band receiving the next budget early. This
avoids a sharp timeout cliff for mid-sized source files just below the first
boundary while remaining capped at 10 seconds, or at `scan_timeout` when that
is higher. A 900 KB JSON index gets 8 seconds by default and a pathological
file still fails fast. An exhausted budget marks the file's analysis incomplete
and the scan incomplete.

IAM wildcard and agent-definition front-matter parsing use this same bounded
matching mechanism. The matching budget does not replace an external process
or job timeout for the complete worker.

## Connector deadlines and parallelism

`options.connector_timeout_seconds` (or `--connector-timeout-seconds`) sets a
positive, finite completion deadline for each connector, defaulting to 120 seconds.
It starts when the connector worker begins; split filesystem roots share that
connector's deadline. Legacy `options.connector_timeout` and `--connector-timeout`
are deprecated compatibility aliases; the YAML alias logs a deprecation warning
once per process. Configure only one YAML key; supplying both is rejected.
Legacy YAML `connector_timeout: null` uses the 120-second default; it does not
disable the deadline.

Setup failures that name only paths, option names and positions are printed
verbatim by the CLI: a missing inventory path or signature directory, a
malformed signature pack (file and document number), an unknown connector key,
and YAML syntax errors in the configuration (line and column, never the source
line). Any other exception raised while a scan is being set up is masked as
`scan setup failed` with its type name, because third-party error text can
echo credentials.

The filesystem scanner stops cooperatively before the deadline: it never starts a
file whose matching budget could run into a safety margin (5% of the budget that
remained when the walk began, at least 250 ms), records one error naming how many
files it examined and how many remain (`connector deadline reached after N of M
files ... results incomplete`), and returns the findings collected so far. The
engine keeps those findings and reports the scan incomplete (exit 3), so a large
tree yields partial inventory rather than nothing. Split roots share the deadline;
a root that starts inside the margin records that error for all of its files.

On expiry, the engine discards that connector's results, records incomplete
coverage and the reason, retains other completed connectors' findings, and
returns an incomplete scan (CLI exit 3). Cancellation is cooperative: Python
cannot forcibly interrupt a thread blocked in a vendor SDK or plugin call. Such
a call may outlive `Engine.run()`; once timeout handling returns, the CLI writes
the incomplete report and exits without joining the abandoned thread. A worker
already publishing a cache or record artifact can delay timeout handling while
its filesystem replacement finishes. Embedded callers must supervise their
process, and a reusable Engine refuses another scan while an abandoned worker
remains active. No replacement
workers are created beyond the configured parallelism; if all slots remain
occupied by timed-out calls, queued connectors are skipped with incomplete
coverage. Enforce an external process or CI job deadline for a hard runtime limit.

`options.parallel` (default 4) is the maximum number of worker threads. Additional
workers can improve throughput when connectors wait on network APIs. Offline
exports and repository scans also perform CPU-intensive parsing and matching;
extra threads can add contention. The offline example uses two workers as a
starting point; measure representative workloads before increasing parallelism.

## Link code to gateway activity

A static dependency alone cannot establish runtime use. Configure a binding
between a specific code `resource` and gateway caller from your own inventory:

```yaml
connectors:
  - name: code.filesystem
    path: ./ops-agent
    label: github:acme/ops-agent
  - name: gateway.logs
    input: ./gateway.jsonl
    correlation_bindings:
      - code_resource: github:acme/ops-agent
        caller: principal:svc-ops
        scope: {tenant: tenant-a}
```

An example generic gateway record:

```json
{"service":"svc-ops","tenant_id":"tenant-a","user_agent":"langchain/0.3","model":"gpt-4o","timestamp":"2026-09-22T10:00:00Z","environment":"production"}
```

In this example, `service` and `environment` are assertions made by the export.
An operator should verify that the log producer supplies a trustworthy workload
identity and deployment label before using the result as production evidence.

`scope` is required. It must exactly match all detected canonical `tenant`,
`account`, `project` and `workspace` fields. Use `{}` only for an unscoped export.
Names, shared providers, shared frameworks and pre-existing `related` links do
not establish workload identity. User-agent/IP address, anonymous, and shared
gateway or workspace fallback callers cannot be bound to a code resource,
even when the string is an exact match. A duplicated code resource across
distinct accounts, providers or connectors is ambiguous and remains unknown.
The gateway must also identify an LLM transaction by model or compatible
endpoint/host. Access logs with a path require a recognized LLM/API route;
a framework user agent or model field on `/favicon.ico` does not qualify as
execution evidence.

API-key callers use a private, connector-local `credential:hmac-sha256:<64 hex
digits>` report identifier. A public SHA-256 fingerprint of a short key or key
ID is recoverable by guessing it offline. An operator can still configure an
exact `api-key:credential:sha256:...` binding computed privately from the raw
key, which the connector checks in memory without writing that public digest to
findings. Keep binding configuration private: publishing a public digest of a
guessable key would itself disclose the key. The exported HMAC is scan-local
unless a stable identity key is set (below), and in either case cannot be
pasted into a binding. Other caller names changed by
credential redaction remain `unverified` for runtime attribution. Do not put
raw API keys into bindings.

If a gateway scope label overlaps a credential or uses an opaque scope prefix,
the report contains a `scope:hmac-sha256:…` value instead. The connector uses
an ephemeral private key so these values preserve distinct tenant groups within
one connector instance without exposing short labels to offline guessing. They
change across independent scans and cannot serve as cross-run identifiers or
correlation binding values. Gateway source IDs always use a private scan-local
key because configuration can include short labels or bindings even if no
accepted event uses that scope. The configured gateway label itself is written
to findings; do not put secrets in labels. The engine shares that key across gateway
jobs in one report, so duplicate sources retain one identity, and creates a new
key for each scan. Direct connector instances use independent keys. Redacted scope scans are
marked incomplete; gateway exports are noncomparable across independent runs.
Resolve the scope/credential overlap before interpreting a report comparison
as evidence that a finding was resolved.

To compare gateway callers across scans, set `SHADOWSCAN_IDENTITY_KEY` to at
least 32 random bytes in the environment of every scan that should be
comparable. Encode it explicitly as `hex:<value>` or `base64:<value>` (for
example, prefix the output of `openssl rand -hex 32` with `hex:`). Bare
encodings are accepted only when exactly one canonical encoding is valid;
ambiguous bare values stop the scan and require one of these prefixes.
Prefix names are case-insensitive. The engine then uses this key instead of a
new key per scan: identical inputs and
configuration give identical caller, scope and source pseudonyms and finding
IDs, findings carry `metadata.identity_scope: keyed`, and the `collection_scope` fingerprint covers
the gateway configuration through an HMAC under the key. The key is read only
from the environment, never from a configuration file, and is never logged or
written to reports, caches or record exports. A set value that does not decode
to at least 32 bytes stops the command before any collection (exit 1). Treat
the key as a secret: with it and a report, anyone can test guesses of short API
keys, labels and bindings against the pseudonyms, and reports made under one key
can be linked to each other. A different key changes every gateway ID and the
collection scope, so `diff` never resolves findings across keys; rotating the key
requires a fresh baseline. A caller that is missing from a complete export of
the same source under the same key is reported resolved: the new export has no
requests from it, which does not prove that the workload was removed.

Code findings with frameworks gain `metadata.runtime_activity`:

| Field | Meaning |
|---|---|
| `status: observed` | The bound gateway export contains timestamped, LLM-classified requests bearing a matching framework fingerprint. |
| `status: unobserved` | Linked telemetry exists but contains no matching framework fingerprint within the export window. |
| `status: unknown` | No eligible binding, ambiguous code identity, or missing matching-event timestamps. |
| `window`, `last_seen`, `events` | Time bounds and counts of matching timestamped events. |
| `production_observed` | At least one matching event carries `prod`/`production` in `environment` or `deployment_environment` (including event metadata). This is a label in the supplied data, not independently established deployment state. |
| `production_label_verified` | `false`: ShadowScan cannot establish the origin or accuracy of deployment labels in imported logs. |
| `sources` | Gateway finding IDs, export provenance, scope, identity and environment assurance, and per-observation details. |

Timestamp, framework and production label must belong to the same event. A caller
named `prod-agent` is insufficient. Generic service or principal fields carry
`operator-asserted` identity assurance. A recognized provider field can carry
`provider-authenticated-field` assurance when it originates from a trusted
provider export, but ShadowScan does not cryptographically verify that provenance.
Framework fingerprints in user agents can be spoofed. Inspect the source
assurance and validate the export's trust chain before claiming an identified
workload is executing in production. Missing logs do not prove inactivity, and
old events do not establish current execution. Correlation does not increase
static confidence or reduce risk.

Gateway finding IDs include the canonical input path and relevant connector
configuration (label, format, filters and bindings). This changes IDs from older
reports. Repeating an identical configured source within one connector instance
is idempotent for nonredacted principal/service callers; API-key callers and
redacted scopes use connector-local HMAC IDs. Without `SHADOWSCAN_IDENTITY_KEY`,
gateway exports are noncomparable across independent scans to avoid claiming
that a missing scan-local ID is a resolved finding: their findings carry
`metadata.identity_scope: run`, and `diff` lists them as not comparable (see
[comparing reports](#comparing-reports)). Distinct exports retain
separate provenance. Overlapping exports count observations from each source,
so aggregate counts are not guaranteed to represent unique requests.

OpenAI organization usage exports with `data[].results[]` are supported.
`metadata.events` counts requests and `metadata.records` counts exported rows;
`usage_intervals` preserves bucket boundaries and counts. A bucket is not a
per-request timestamp: it cannot establish hourly continuous activity or confirm
timestamped framework execution for runtime correlation.

## Precision safeguards

Constructing an agent and defining a tool in the same project does not prove
that the agent can invoke that tool. Python and JavaScript source execution
helpers and unused tool declarations remain zero-weight evidence with
`capability_basis: contextual-unlinked-source`; their features appear in
`metadata.contextual_capabilities` and unproven features in
`metadata.potential_capabilities`. They do not raise confidence or risk.
Supported literal tool registrations connect local Python tool bodies and
direct unshadowed same-scope helpers; registered SDK execution tools and
MCP sinks retain their connected capabilities. Rebinding, parameters that
shadow helper names, mutable aliases and dynamic collections cannot establish
that connection. Configured opaque tools can establish `tool-use`, while an
unresolved implementation cannot establish its execution capability.
Registration is source evidence, not proof that a deployed workload ran it.

JavaScript/TypeScript binding skips only provably constant-dead literal
`if`/`else` and `while` branches, including supported parentheses and negation,
and preserves executed alternatives. Hoisted-name shadow uncertainty remains
conservative. Dynamic guards, comparisons, compound expressions and ambiguous
statement boundaries are outside this narrow recognition; the scanner does
not claim complete control-flow or data-flow analysis.

Responses API tool dispatch requires linked source evidence from the SDK client,
request, returned output and function-call guard to the dispatch. A single
verified dispatch establishes `tool-use`; `autonomous` requires a verified
iterative feedback loop. JavaScript recognition is deliberately conservative:
it accepts a small, complete top-level program with static imports and request
options. Extra statements, nested scopes, mutations and dynamic options cannot
establish this proof. Unsupported shapes, including files longer than such a
program can be, still produce ordinary SDK evidence and leave coverage complete.

Several rules keep weak observations from producing strong or high-risk
findings. A credential whose value looks like a documentation placeholder
(`REPLACE_ME`, `<your-key>`, `xxxx`, all zeros, `abcdef...` or `1234567890`
sequences after the provider prefix) is never a `secret` finding; it is listed
on the project finding as low-weight `example-credential` evidence. A key alone
does not establish LLM usage, a coding-agent configuration needs more than an
environment-variable or display-name mention (`GOOSE_PROVIDER` in a detector
list is not "Goose configured"; a config file, instruction document,
dependency or workflow step still is), MCP parsing skips
`*.lock.yml` / `*.lock.yaml` files (compiled agentic workflows) and cookiecutter
`{{...}}` template paths, and vendor-neutral heuristics (agent loops,
`subprocess.run`, auto-approve flags) only count in a project that also matches
a framework, provider, platform, protocol or cloud-service signature. When every
observation for a project other than those heuristics is an environment-variable
or display-name reference, the heuristics are dropped and the finding is built
from the name references alone: it is tagged `env-names-only`, its evidence
weights are halved and its confidence is capped at 0.8 (`likely`), however many
names appear. A data or prose file that only lists four or more products by
domain or variable name (a proxy blocklist, a vendor policy, a copy of the
signature packs) is a catalog: its mentions count only for a product with an
import, dependency or code pattern elsewhere in the project, and the discounted
files are listed in `metadata.catalog_mentions` (see
[Code connectors](connectors/code.md)). MCP servers
for files and databases carry the `data-access` capability, browser servers
`browsing`, and shells `code-exec`. In gateway logs, round-the-clock activity
keeps the informational `always-on` tag but only marks a caller as agentic,
with the `autonomous` capability, when tool use, an agent-framework user agent,
a service or principal identity, or missing end-user attribution corroborates
it. `tools/evaluation/corpus.json` carries regression cases for each rule.

## Comparing reports

`shadowscan diff baseline.json current.json` reports new findings and substantive
changes, including permissions, classification, ownership, registration and risk
score/factors within the same risk band. Each changed item includes
`changed_fields`. Missing findings count as resolved only when both reports
completed, declare the same supported finding-identity schema, carry a
`summary` whose `total` (and `by_surface`/`by_kind` counts) match their
`findings` array, and have the same `collection_scope` fingerprint. A truncated
or filtered report is therefore unknown (exit 3), not a resolution. The
fingerprint is an opaque digest that covers
selected source paths, connector settings, filters, confidence threshold,
signatures and scanner implementation. File contents and inventory approvals
are excluded so real removals and approval changes can be compared. A public
digest does not hide guessable paths or labels; keep these settings nonsecret.
Credential-bearing configurations omit the digest. Gateway exports attest
comparable scope only when `SHADOWSCAN_IDENTITY_KEY` is set: an HMAC under that
key stands in for their configuration, which can hold guessable labels and
bindings. Without the key their private caller/scope identities change between
scans.

Incomplete scans, changed scope, older reports without provenance, live provider
collections and third-party connectors cannot establish equivalent coverage.
Their missing findings are reported as `unknown`, and diff exits 3. New and
changed findings remain visible. Currently only local repositories and offline
exports from built-in connectors can attest comparable scope, `gateway.logs`
only when both scans were keyed with the same identity key; live account and
permission coverage require additional provider-specific provenance. The digest
covers the resolved absolute scan paths, so compare scans of the same checkout
location; a label does not stand in for the path, because a narrower scan under
the same label would otherwise make out-of-scope findings look resolved.

By default `diff` exits 0 when the comparison is complete, whatever it finds.
`--fail-on-new` exits 2 when there are new findings or a finding's risk level
rose; an incomplete comparison still exits 3.

Connectors that were disabled or left out by `--only` do not make a scan
incomplete (that is operator intent), but the JSON report lists them as
`collection_scope.not_run` with the reason. The list is not part of the scope
digest.

A finding with `metadata.identity_scope: run`, which `gateway.logs` findings
carry unless `SHADOWSCAN_IDENTITY_KEY` is set, has an ID derived from a key that
is random for each scan: the same caller has a different ID in the next report.
Diff therefore never reports such a finding as new, resolved or unknown because
the other report lacks its ID. It lists it under `not_comparable` (`baseline` or
`current`; marked `<` or `>` in text output), states the reason and exits 3. A
finding whose ID appears in both reports is compared as usual. Any declared
`identity_scope` other than `keyed`, the scope of findings made under
`SHADOWSCAN_IDENTITY_KEY`, is treated the same way.

Finding IDs do not depend on inferred kind. Stable resource-type families (or an
explicit plugin `identity_discriminator`) separate distinct observations on a
resource. Regenerate comparison baselines after upgrading from legacy IDs;
cross-schema comparisons retain missing findings as unknown. Incompatible cache
entries cause a full rescan.

## Completion and migration

| CLI exit | Meaning |
|---|---|
| `0` | Scan completed and the configured risk threshold was not reached. |
| `1` | Usage, setup or configuration error (unknown option or command, invalid config, missing inventory or signature path, unwritable report); no scan result. |
| `2` | Completed scan reached `--fail-on`. |
| `3` | Collection or analysis was incomplete, including empty or partly invalid connector selection. |

An incomplete scan that also reaches `--fail-on` exits 3. In CI, fail on any
non-zero exit rather than only on 2 and 3.

`--min-confidence` and YAML `options.min_confidence` accept finite values in
`[0, 1]`; invalid thresholds stop the scan instead of silently clearing the gate.

Incomplete results preserve valid findings, set `summary.complete` to false and
SARIF `invocations[].executionSuccessful` to false, and include diagnostics.
An incomplete CSV report starts with a `SCAN-INCOMPLETE` status row
(`kind` = `scan-status`, the unfinished connectors in `connector`) right after the
header, so it cannot be mistaken for a complete scan with no findings.
Failed or denied live collection for an enabled source marks coverage incomplete;
review per-connector diagnostics and rerun after restoring access.
Malformed files are isolated, so one bad manifest cannot suppress neighboring
findings. Regex matches have time budgets; exhausted budgets mark the scan
incomplete. Configure `code.filesystem.scan_timeout` in seconds to adjust the
shared per-file regex budget (default 2 seconds for files up to 256 KiB, growing
with file size as described under [large and generated files](#large-and-generated-files));
manifest parsers additionally cap each pattern at one second within that budget.

Denied or failed API requests and exhausted pagination mark collection incomplete.
Offline exports require valid objects or arrays of objects; scalar records,
invalid envelopes and malformed rows are errors. Use `[]` in JSON/YAML or
`{"records": []}` in JSONL for an explicitly empty inventory; an empty file does
not establish successful collection. Valid neighboring records are retained.
Export files are capped at 64 MiB each, 512 MiB total and 200,000 filesystem
entries; symlinks and special files are rejected. Gateway gzip input is bounded
before and after decompression. These limits also apply to custom gateway and
JWT loaders.

Cloud offline inputs use ShadowScan's normalized record format, including a
recognized `_kind` discriminator (see `tests/fixtures/cloud/`). Arbitrary raw
provider responses need conversion to that format. Missing or unsupported
record kinds and malformed resource identifiers make collection incomplete;
they are never treated as a successfully scanned empty inventory.

Existing inventory entries that rely on names alone must add reviewed `resources`
bindings. Names now offer review suggestions without approving a finding or
reducing risk. Surface, provider and account restrictions are enforced; multiple
matching approvals remain ambiguous. See [inventory](inventory.md).

Signature files are validated before use and in CI. Unknown fields (including
`severity`), malformed regexes, duplicate definitions and invalid weights fail
validation. Severity is computed centrally by the risk engine rather than set in
a signature. See [signature authoring](signatures.md).
