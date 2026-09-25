# Human holdout acceptance for code discovery

The bundled 42-case independent corpus was double-labeled by AI reviewers and
was used to improve the scanner after its first evaluation. It remains useful
for regression testing, but cannot be used as a fresh human holdout. A new
holdout needs actual human reviewers and a separate source selection process.

1. Collect complete, legally reusable source files from repositories that have
   not appeared in any prior scanner evaluation or development set. Include
   realistic hard negatives such as ordinary workers and local module names
   that resemble SDKs, plus diverse agent frameworks and custom tool loops.
   Record source URL, immutable commit, file hash, license, and label evidence.
   Use the existing bounded `adjudicated` corpus schema in
   `tools/evaluation/independent_corpus.json` as a *format example only*.
2. Give each of two human reviewers a packet of the source files and a written
   agent-presence rule, without scanner findings or the other's labels. Freeze
   their independent judgments in an annotation ledger with method
   `independent-human-double-label-before-scan`. Record and resolve each
   disagreement from source evidence; set corpus `present` to the resolved
   label. The ledger structure follows
   `tools/evaluation/independent_annotations.json`. The validator checks the
   declarations and consistency; it cannot authenticate people or prove that
   they were blind to results.
3. Freeze the exact corpus and annotation-ledger SHA-256 digests, selection plan,
   target kinds, sample size, and error limits in a policy **before** running the
   candidate scanner. Set positive/negative minima and false-positive/false-negative
   limits for **each** target kind as well as the aggregate; an aggregate pass
   must not conceal a weak or failing kind. An
   example policy for an agent-only assessment is below. The numbers are
   illustrative acceptance criteria, not demonstrated field accuracy or a
   universal deployment threshold. Choose thresholds using the specific
   consequences of false positives and missed agents.

```json
{
  "schema": 1,
  "corpus_sha256": "<64-lowercase-hex-digit-SHA256-of-the-frozen-JSON-file>",
  "annotations_sha256": "<64-lowercase-hex-digit-SHA256-of-the-frozen-ledger>",
  "target_kinds": ["agent"],
  "minimums": {"positive": 25, "negative": 75, "repositories": 8},
  "max_errors": {"false_positive": 0, "false_negative": 0},
  "per_kind": {
    "agent": {
      "minimums": {"positive": 25, "negative": 75},
      "max_errors": {"false_positive": 0, "false_negative": 0}
    }
  }
}
```

Run from the project checkout with installed dependencies:

```bash
python -m tools.evaluation.holdout_gate \
  --corpus /approved/holdout.json \
  --annotations /approved/human-annotations.json \
  --policy /approved/acceptance-policy.json \
  --exclude-corpus /approved/other-previous-evaluations.json \
  --output /approved/holdout-receipt.json
```

The bundled synthetic, public and AI-reviewed corpora are excluded by default.
Repeat `--exclude-corpus` for every additional prior evaluation corpus. Exact
source file bytes and source locations cannot be repeated within the holdout or
reused from prior corpora. Near duplicates and unrecorded prior access require
human review. The runner checks the frozen ledger digest before and after the
scan. It uses the offline
`code.filesystem` evaluator: it never executes or fetches sample code. Exit 0
means the declared policy passed, 1 means a valid evaluated holdout missed a
threshold, and 2 means the policy, labels, overlap checks, scanner run or
receipt writing was invalid. The output file is private mode 0600 and is never
overwritten. Keep the corpus, annotation ledger, policy, receipt, scanner
commit and CI run together for audit; do not publish confidential source.

The report includes the overall confusion matrix, per-finding-kind matrices,
annotation declarations, source/signature fingerprints, and any failed gate
conditions. Accuracy on selected files is conditional on that selection; class
balance changes precision. An accepted code holdout establishes neither
connector coverage outside `code.filesystem` nor live AWS/Slack tenant behavior.
Complete the separate read-only live controls in `docs/canaries.md` before
claiming tenant acceptance. If the scanner is tuned in response to failures,
record the failures as development data and assess the revised scanner against
another unseen human-labeled holdout.
