# Production review, round 3 — 26 September 2026

## Scope and method

Review began with `main` at `f2ce31d`, the tip after PR #43 (round 2) merged
and several further pull requests landed (a production scanner refactor, a
detection-reliability pass, dependency updates, community-profile files, and
a verified repository hygiene audit). It covered the full current tree: the
engine, configuration and plugin registry, every built-in connector family,
the credential sanitizer, and the reporters.

Eight independent reviewers each covered one area, weighted toward code with
comparatively less prior scrutiny (the OpenAI Responses tool-loop
recognizer, import provenance, the gateway log normalizer split, the shared
deadline/digest helpers, and the new evaluation-acceptance and
release-evidence tooling). Every candidate finding was then checked by three
independent verifiers, instructed to read the live code themselves and
default to refuting a claim they could not personally confirm. Ten
candidates were raised; all ten were confirmed unanimously (3/3 votes) and
none were refuted.

Every confirmed finding was reproduced against the real code before it was
fixed — either directly (a crafted source fixture through the real
connector) or, where the finding's own verification already included a
concrete before/after reproduction, by re-running that reproduction — and
every fix carries a regression test that was confirmed to fail against the
pre-fix code and pass against the fix. All credentials, tokens and tenant
identifiers used for reproduction were synthetic.

## Confirmed findings and corrections

| Priority | Defect and impact | Correction |
|---|---|---|
| High | An approved plugin classified as `CODE` surface bypassed the credential-mixing isolation guard whenever its entry-point name did not start with `code.`, because the guard matched on that literal string prefix rather than the plugin's own declared surface. A scan could run such a plugin against untrusted repository content alongside a live cloud, identity, SaaS or low-code connector's credentials in the same process, with `allow_credential_mixing` never set. | `ScanConfig.validate_connector_isolation` now classifies every connector — built-in or plugin — by its declared `Surface`, resolved through the same registry lookup and identity contract every connector is already held to. A lookup failure (an unresolvable name) is treated as neither side, since that connector fails its own job separately with the real error. |
| High | The OpenAI Responses tool-loop recognizer's dispatch check matched only a plain-name callable already bound to a resolved handler, so it never recognized a process/code-execution sink (`subprocess.run`, `os.system`, `exec`, `eval`) fed with the model's tool arguments, nor the equally common inline dispatch-table call (`FUNCTIONS[item.name](...)` in one line). The mirrored Chat Completions/Anthropic recognizer already modeled both. A Responses-API agent loop that can run shell commands, written either way, produced zero findings. | The recognizer now imports the same `EXECUTION_SINKS`/`_execution_sink` check and unwraps a trailing attribute access on the dispatch call (`subprocess.run(...).stdout`) exactly as the mirrored recognizer does, and recognizes an inline subscript dispatch table the same way the two-step `handler = FUNCTIONS[item.name]` form already was. |
| High | The JavaScript/TypeScript lexer's `//` comment, regex-literal and string-literal termination recognized only a literal `\n`. A CR-only file (old-Mac line endings) or a source file using a Unicode line/paragraph separator (` `/` `, both real ECMAScript line terminators) had the remainder of the file masked as inert comment text, silently discarding any executable code and any agent-framework signal after it — without the scan being flagged ambiguous. | Comment, regex and string termination now search for any ECMAScript line terminator (`\r`, `\n`, ` `, ` `), matching real engine behavior; ordinary LF- and CRLF-terminated files are unaffected. |
| Medium | In API mode, GitHub and GitLab repository fetch wrapped every per-path failure except the final directory-creation and write step. An untrusted tree listing that described a path and a descendant of that same path as two separate blobs (impossible for a real git tree, but never checked) crashed the whole repository fetch with an uncaught `FileExistsError`, discarding every finding already collected for that repository instead of skipping the one conflicting file. | The write is now wrapped in the same per-path isolation as every other failure in the loop; an `OSError` is reported as a warning and that one file is skipped. |
| High | `GcpConnector._h_iam_policy`'s collection-time gate accepted any IAM binding matching a `policy.privileged-scopes` or `policy.data-access-scopes` signature, but the emission gate two lines later only counted a narrow AI-specific role whitelist plus the literal `roles/owner`/`roles/editor`. Every other privileged role (`roles/iam.serviceAccountTokenCreator`, `roles/secretmanager.secretAccessor`, `roles/storage.admin`, ...) and narrow data-access role (`roles/bigquery.dataViewer`, `roles/storage.objectViewer`, `roles/datastore.user`, `roles/spanner.databaseReader`, ...) was collected, scored and tagged as evidence, then silently discarded with no finding and no coverage warning. | Emission now also counts any role the collection gate already accepted beyond `roles/owner`/`roles/editor`. `roles/viewer` — the ubiquitous basic project role nearly every principal holds — is excluded from that count on its own, preserving the existing, deliberate "viewer alone is not finding-worthy" behavior; it still contributes when combined with any other privileged or AI-specific grant. |
| Medium | `MakeConnector.collect()` subscripted an untrusted `/teams` record with `t["id"]` and an untrusted `/scenarios` record with `s["id"]`. A missing `id` on a single team record raised `KeyError`, aborting collection for the entire organization before any team was scanned; a missing `id` on a single scenario record aborted collection for the rest of that team and every subsequent team, contradicting this connector's own documented "one malformed record is skipped, not fatal" policy. | Both records are validated with `.get("id")` and skipped with a warning, isolating the one malformed record. |
| Medium | `host_of()`'s host-extraction regex captured up to the first `:`, `/`, `?` or `#`. A URL with embedded basic-auth credentials (`https://user:pass@host/path`) returned the username instead of the host. This feeds the `host` field the gateway log normalizer derives from `api_base`/`upstream_uri`/`request_path`/`target_url`/`resource_id`, which gateway log classification later matches against known LLM-provider domains — an upstream configured with embedded credentials could silently miss that match. | The regex now skips an optional userinfo component before capturing the host, matching real URL authority syntax; unaffected inputs (no userinfo, IPv6 literals, bare hostnames) are unchanged. |
| Low | The Markdown reporter's URL-defanging pass recognized `http(s)://` and `www.` but not a bare, protocol-relative `//host` URL. `markdown-it`/`linkify-it`-based renderers — used by many wikis and ticket trackers, one of this reporter's stated destinations — autolink a leading `//` on its own, so an attacker-controlled finding field containing one stayed live in those renderers although the module's own stated goal is to prevent exactly that. | The autolink regex gained a third alternative for a `//` not preceded by a word character (matching start-of-string, whitespace or punctuation, not a mid-token occurrence); it is defanged to `/[/]`, consistent with the existing `hxxp(s)://` and `www[.]` markers. |

## Verification

On the fixed tree (before further commits landed on `main`, see below):
`ruff`, the full `mypy` target (`shadowscan` plus `tools/evaluation`,
`tools/canaries`, `tools/acceptance`, `tools/release`), signature validation
(215 signatures, 994 signals), `pip-audit`, and all five bundled evaluation
corpora (precision/recall 1.0 on every graded case; the three pre-existing,
documented gaps in the realistic corpus are unchanged) all pass. The full
test suite passes on Python 3.11, 3.12 and 3.13 (4,457 passed, 2 skipped —
the two Git-2.45 tests, on this container's older Git — on every
interpreter; overall statement coverage 90.4%, every built-in connector
module above the 75% floor).

Each of the ten fixes above was independently confirmed to change the
outcome: its regression test fails against the pre-fix code (reproducing the
exact failure scenario in the finding) and passes against the fix, checked
by reverting only that one file and re-running the new test.

## Merge with `main` after this review

While this review's fixes were being verified, three further pull requests
merged into `main` (a scanner-evidence hardening pass adding a single-call
JavaScript dispatch recognizer and n8n unresolved-identity handling, a
follow-up hardening PR, and an added Jekyll GitHub Pages deployment
workflow). Each file this review also touched was diffed against `main` in
isolation (`git diff <base>..<main> -- <file>`) before trusting the
automatic merge, to confirm the incoming changes were disjoint from this
review's edits — in every case they were: `main` added new, separate
functions or touched unrelated call sites in the same file, and no line this
review changed was touched by the other side. Both sets of changes are
present and independently correct in the merged tree.

Re-running the full verification above against the merged tree (`ruff`,
`mypy`, signature validation, `pip-audit`, all five evaluation corpora, and
the full test suite on Python 3.11/3.12/3.13) reproduces the same result
with one exception: `tests/test_repository_policy.py::test_workflows_use_pinned_actions_and_scoped_permissions[jekyll-gh-pages.yml]`
now fails, identically on all three interpreters (4,724 passed, 2 skipped,
1 failed on each). This failure is pre-existing on `main` alone — confirmed
by checking out `main` in an isolated worktree and reproducing the identical
failure there, with no other change involved.

The new `.github/workflows/jekyll-gh-pages.yml` grants `pages: write` and
`id-token: write` at the top level (this repository's policy requires
top-level `permissions` to be read-only, with write scopes granted only to
the specific job that needs them) and pins no action by commit SHA,
violating this repository's own SHA-pinning hard rule. It also appears to
duplicate the existing `docs.yml` workflow, which already deploys this
repository's documentation to GitHub Pages via a more conservative,
manually-gated `mkdocs` build with per-job scoped permissions and pinned
actions.

This defect is out of scope for this review — it was introduced by a
different, already-merged pull request, unrelated to anything this review
set out to examine — and is not fixed here. A correct fix (mirroring
`docs.yml`'s pattern: read-only top-level permissions, `pages`/`id-token`
scoped to the `deploy` job only, `persist-credentials: false` on the
checkout, a `timeout-minutes` on every job, and pinning `actions/configure-pages`
and `actions/jekyll-build-pages` by full commit SHA) needs those two
actions' real release commit SHAs verified through a trustworthy channel;
this review could not obtain that independent verification and deliberately
left the file unchanged rather than pin an unverified SHA in a
security-sensitive CI permissions file. This is flagged here for a
maintainer to fix directly, with a verified SHA, or to remove the
duplicate workflow.

## Areas examined and found sound

* The Chat Completions/Anthropic provider tool-loop recognizer that the
  Responses recognizer was compared against; its own execution-sink,
  dispatcher-table and shadowed-sink handling all remain correct.
* The rest of the JavaScript/TypeScript lexer (JSX, template literals,
  nested interpolation, control-flow-sensitive regex/division
  disambiguation) and the other-language lexer (`_other_source_ranges`) —
  the line-terminator gap was specific to the ECMAScript-only U+2028/U+2029
  rule and did not extend there.
* Every other cloud, identity, gateway, low-code and SaaS connector's error
  isolation, which already matched the "one malformed record is a warning,
  not a fatal error" policy this review's Make connector fix now also
  satisfies.
* The plugin identity contract itself (`_verify_connector_class`): the
  isolation guard's fix consumes it as already designed; no change to that
  contract was needed.

## Residual recommendations (not changed)

* The plugin-surface lookup added to `validate_connector_isolation` imports
  the plugin's module (as the scan was already about to do moments later);
  an operator who wants to validate a configuration's isolation policy
  without ever importing an approved plugin's code has no way to do so
  today.
* `roles/viewer`'s exclusion from GCP privileged/data-access role counting is
  a judgment call about noise versus completeness, not a mechanical
  consequence of the signature data (which lists it alongside the narrower
  roles this review restored). Revisit if the ambient rate of viewer-only
  false positives changes with the signature pack's own base-rate exposure.
* See [production](production.md) and [evaluation](evaluation.md) for the
  standing requirements (tenant canaries, container runtime acceptance, a
  held-out detection set, independent human review) before enforcing a
  policy gate on any of this round's changes.
