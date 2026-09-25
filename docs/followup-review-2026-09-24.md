# Follow-up security and reliability review

Base: `65486cc77d0632471409c9d9a618431d18698583` on `main`.
This review examined implementation behavior and added regression tests for
reproducible defects. It is not a certification of production detection accuracy
or tenant coverage. The scanner remains an unreleased 0.1.1 candidate.

## Findings addressed

| Boundary | Reproduced failure | Corrected behavior |
| --- | --- | --- |
| Imported reports | `diff` returned raw imported findings, including credentials and copied opaque secrets. Child evidence sanitization could erase the context needed to redact copies in other fields. | Export only known model fields through collective sanitization; retain child credential context until the parent finding sanitizes it. Preserve generated identity and schema protections. |
| Terminal output | Rich `Text`/`markup=False` preserved an injected OSC 52 sequence in a finding title. | Render untrusted control and bidirectional formatting characters visibly in finding tables, diff rows, diagnostics and progress/path notices. |
| Comparison completeness | Missing or falsey malformed completion fields could still resolve a vanished finding. Matching scope hashes did not detect missing connector statistics. | Require explicit successful completion and matching connector-statistic coverage. Preserve disappeared findings as unknown when these conditions fail. |
| Runtime attribution | Two distinct credential-bearing code resource labels redacted to the same display value and both inherited production activity from one binding. | Require intact code identities, consider region when detecting ambiguity, accept only recognized caller assurance, and clear stale derived observations. A rejected binding produces unknown activity. |
| API JSON | Duplicate collection fields could overwrite observed records with an empty array; duplicate pagination or JWK fields were also accepted. | Reject duplicate decoded keys at every depth and nonfinite/overflowed numbers before using API data. Diagnostics do not echo provider content. |
| Offline collection | An empty Slack page carrying `response_metadata.next_cursor` exited successfully with `summary.complete=true`. AWS truncation flags and additional continuation markers were also ignored. | Report uncollected pages or malformed supported pagination metadata as incomplete while retaining observed records. The CLI returns exit 3 for the incomplete scan. |
| Evaluation integrity | A case family named `all` appended into the same list being iterated, causing unbounded growth. Corpus reads used a check-then-read path, and annotation validation could check a different concurrent snapshot. | Reserve the aggregate family name, use bounded descriptor-based reads, and require annotation validation to report the digest of the exact evaluated corpus. Malformed source paths fail validation cleanly. |

The API and pagination changes reject ambiguous data; they do not infer that an
empty result proves a complete inventory. Slack's continuation convention is
documented in its [pagination guide](https://docs.slack.dev/apis/web-api/pagination/),
and AWS's truncation flag in the [IAM ListRoles API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html).

## Validation and overlap

The patch has focused regressions for each boundary, including actual Engine
and CLI paths, malformed API/JWKS payloads, credential copies, short-secret
schema protection, terminal rendering and concurrent corpus replacement.
The review also runs the repository's full Python suite with coverage, Ruff,
mypy, signature validation, evaluation corpora, replay canaries, dependency audit
and installed-wheel smoke checks. The pull request records exact observed
results; its required CI checks apply to the final published commit.

A snapshot of the overlapping fixes applied cleanly to draft PR #40 at
`a5bcdbccd6f7007c4ebbfcc8f3389e611b272df0`. In an isolated tree, 80 assurance,
private-holdout acceptance and canary tests plus 141 overlapping collection and
security regressions passed. This is compatibility evidence for those scopes,
not approval of that entire draft. Its clone bounds, collection refinements,
source detection changes and holdout acceptance feature remain separate work.

## Remaining production gates

- Run live read-only canaries with approved credentials and independently
  reviewed real controls for every deployed connector. AWS/Slack replay and
  mocked SDK tests establish test behavior only.
- Validate enforcement thresholds on a fresh representative private holdout.
  The frozen 42-file public corpus is now a regression set after feedback;
  perfect results on it are not a field precision/recall estimate.
- Run in a disposable worker with an external job deadline, memory/process
  limits and writable-disk quotas. Soft thread deadlines cannot forcibly cancel
  an in-flight socket, SDK or plugin call; per-read timeouts are not total
  response deadlines.
- Pin the reviewed commit, dependency lock and deployment image digest; verify
  the built container in the target environment and retain rollback evidence.
- Require the final Python 3.11/3.12 and CodeQL checks and an eligible independent
  review. At this review, both repository rulesets are active; the required-check
  ruleset requires one approval and has no bypass actors. Settings must be
  checked again at release time.

No live tenant API was called, no ruleset was weakened, and this review does not
merge the open drafts or release a production artifact.
