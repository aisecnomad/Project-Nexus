# Holdout acceptance gate

`python -m tools.evaluation.accept` is the release-evidence command for
code-filesystem detection quality. It is **not** live tenant acceptance and it
cannot certify an estate.

## What it will not accept

The following in-tree files are regression suites only:

- `tools/evaluation/corpus.json` (`synthetic`)
- `tools/evaluation/public_corpus.json` (`public-pinned`)
- `tools/evaluation/independent_corpus.json` (`adjudicated`, but labeled by two AI reviewers)
- `tools/evaluation/realistic_corpus.json` and `review_corpus.json` (synthetic)

The command rejects every corpus stored inside the source checkout, including
future bundled suites. Private holdouts belong outside the repository.

The independent sample stays typed `adjudicated` so annotation-integrity checks
keep working. The acceptance command still refuses it because:

1. the path is bundled in this repository, and
2. its ledger method is `independent-ai-double-label-before-scan`.

Copying that file out of tree and changing the method string does not make the
labels human. Reviewers have to re-label blindly.

## What a real gate needs

1. A private corpus kept outside this repository.
2. `metadata.type: "adjudicated"`.
3. A two-reviewer ledger with method `independent-human-double-label-before-scan`.
4. A policy whose `corpus_sha256` is the SHA-256 of those exact corpus bytes.
5. Predeclared per-family floors and Wilson 95% lower bounds.
6. A reviewer who inspects sampling, disagreements and exclusions *before*
   seeing scanner scores.

```bash
sha256sum /restricted/holdout.json
python -m tools.evaluation.accept \
  --corpus /restricted/holdout.json \
  --policy /restricted/acceptance-policy.json \
  --annotations /restricted/holdout-annotations.json \
  --output /restricted/acceptance-result.json
```

Exit `0` passes the predeclared bounds. Exit `1` fails a bound or assertion.
Exit `2` means invalid inputs, a bundled corpus, an AI-labeled ledger, incomplete
coverage or an output error.

A passing code-filesystem gate does not prove cloud, identity, SaaS or gateway
recall, and it does not prove an agent executed. Run the AWS/Slack canary
runners with approved tenant credentials before enabling `--fail-on`.
