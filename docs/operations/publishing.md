# Publishing a release

This runbook is for the maintainer. It covers the one-time setup and the
per-release steps that put a reviewed ShadowScan release on PyPI as
`NexusShadowScan`, so that `pip install NexusShadowScan` installs it.

Publishing is a manual maintainer action and comes after the
[release process](https://github.com/aisecnomad/Project-Nexus/blob/main/GOVERNANCE.md#release-process):
independent human review of the exact candidate commit and the acceptance
evidence for its deployment scope. Coding agents prepare candidates. They
never push a version tag, dispatch the workflow with `publish` set, or approve
a deployment.

## How an upload is gated

The [release-evidence workflow](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/workflows/release.yml)
(**Release candidate evidence**) is the only path to the package index. No
package-index token exists: PyPI trusts this repository's workflow and
environment through OpenID Connect (trusted publishing).

Release tags are annotated and may be unsigned. No personal SSH or GPG signing
key is required: package provenance comes from the workflow's GitHub
attestations and the PyPI publish attestations. These identify the build and
publishing workflow; they do not establish a personal signature on the Git tag
or replace independent human review.

| Job | What it enforces | Permissions |
|---|---|---|
| `build` | Runs on `main` only. The commit must equal `expected_commit` and have successful push CI and CodeQL runs. Checks the live merge ruleset against the administrator readback passed at dispatch (see below), builds the wheel from a clean `git archive`, installs it outside the checkout, smoke-scans, and records the SBOM and `SHA256SUMS`. | read |
| `attest` | GitHub provenance and SBOM attestations for the candidate files. No checkout. | `id-token`, `attestations` |
| `publication-input` | Reassembles the attested bytes and checks for exactly one wheel. | none |
| `publication-gate` | Runs only when `publish` is `testpypi` or `pypi`. Requires one wheel whose digest matches, a public release version (no `.dev`, `.post` or local part), and, for `pypi`, the tag `v<version>` on the reviewed commit. | `contents: read` |
| `publish` | Waits for approval in the protected environment named by `publish`. Checks out nothing, verifies the digests, and uploads only that wheel with [`pypa/gh-action-pypi-publish`](https://github.com/pypa/gh-action-pypi-publish), which adds PEP 740 attestations. | `id-token` only |

With the default `publish: none`, the workflow builds and attests a review
bundle and uploads nothing. `tests/test_repository_policy.py` fails CI if any
of these gates is removed, or if any other workflow, job or command uploads a
package.

## One-time setup

1. **PyPI and TestPyPI accounts.** They are separate accounts. Both require
   two-factor authentication; prefer a hardware security key.
2. **Pending trusted publishers.** On PyPI, open
   [Publishing](https://pypi.org/manage/account/publishing/) and add a GitHub
   pending publisher:

   | Field | Value |
   |---|---|
   | PyPI project name | `NexusShadowScan` |
   | Owner | `aisecnomad` |
   | Repository name | `Project-Nexus` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   Repeat on [TestPyPI](https://test.pypi.org/manage/account/publishing/) with
   the environment name `testpypi`. A pending publisher does not reserve the
   name, and someone else can still register it. Publish the first release
   soon after you register the publisher. Do not remove the publisher
   afterwards; it becomes the project's publisher.
3. **GitHub environments.** Under **Settings → Environments**, create `pypi`
   and `testpypi`:
   - **Required reviewers:** the maintainer. Add a second reviewer and turn on
     **Prevent self-review** as soon as one exists.
   - **Deployment branches and tags:** selected branches only, `main`.
   - **Secrets:** none. Trusted publishing needs no token, and a stored token
     would bypass these gates.
4. **Protect release tags.** Use an active tag ruleset targeting `v*` that
   blocks updates and deletion, with no bypass actors. The maintainer creates
   the initial tag after review. The publication gate reads the tag before the
   approval wait, and the ruleset keeps that answer true until the upload.

## Per release

1. **Prepare the candidate.** Set the same version in `pyproject.toml`,
   `shadowscan/__init__.py` and `CITATION.cff` (CI checks that they match).
   Date the release headings in `CHANGELOG.md` and `RELEASE_NOTES.md` and
   remove "unreleased" from them. Merge through the normal review process.
2. **Review and accept the exact commit**, as the
   [release process](https://github.com/aisecnomad/Project-Nexus/blob/main/GOVERNANCE.md#release-process)
   requires. A green CI run is not that review.
3. **Rehearse on TestPyPI.** Dispatch **Release candidate evidence** on `main`
   from an administrator-authenticated GitHub CLI, then approve the
   `testpypi` deployment:

   ```bash
   gh workflow run release.yml --repo aisecnomad/Project-Nexus --ref main \
     -f expected_commit=<reviewed-40-character-sha> \
     -f ci_run_id=<its successful push CI run> \
     -f codeql_run_id=<its successful push CodeQL run> \
     -f ruleset_readback="$(gh api repos/aisecnomad/Project-Nexus/rulesets/23913372)" \
     -f publish=testpypi
   ```

   GitHub withholds the ruleset's `bypass_actors` from the workflow's
   read-only token, and an omitted field cannot prove that nobody can bypass
   the rules. `ruleset_readback` supplies it from your administrator read. The
   build job accepts the readback only if it matches the job's own read in
   every other field, `updated_at` included, so take it just before you
   dispatch, and the evidence records where `bypass_actors` came from.
   Check the project page renders, then install in a throwaway environment.
   Use `--no-deps`, so that TestPyPI, where anyone can register names, never
   supplies a dependency:

   ```bash
   python -m venv /tmp/nss && . /tmp/nss/bin/activate
   python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
   python -m pip install --no-deps --index-url https://test.pypi.org/simple/ NexusShadowScan==0.1.2
   shadowscan --help && python -m shadowscan.signatures.validate
   ```

4. **Tag the reviewed commit.** Create an annotated tag on that exact commit.
   The default release path uses an unsigned tag and needs no personal signing
   key. `--no-sign` overrides any local `tag.gpgSign` preference:

   ```bash
   git tag --no-sign -a v0.1.2 -m "NexusShadowScan 0.1.2" <reviewed-40-character-sha>
   git push origin refs/tags/v0.1.2
   ```

   A maintainer may instead sign the annotated tag with `git tag -s` when a
   signing key is available. Signing is optional. Both routes require the
   reviewed commit, immutable tag protections, successful CI and CodeQL,
   artifact attestations, and approval in the protected publishing environment.

5. **Publish.** Dispatch the workflow again with the same inputs, a fresh
   `ruleset_readback`, and `publish: pypi`, then approve the `pypi`
   deployment. The gate rejects the
   run unless `v<version>` points at `expected_commit`.
6. **Verify what was published:**

   ```bash
   python -m pip download --no-deps --dest wheels NexusShadowScan==0.1.2
   gh attestation verify wheels/nexusshadowscan-0.1.2-py3-none-any.whl --repo aisecnomad/Project-Nexus
   ```

   Compare the wheel's SHA-256 with `SHA256SUMS` in the retained
   `release-candidate-<SHA>` artifact. On PyPI, the file's provenance should
   name this repository, `release.yml` and the `pypi` environment.
7. **Optionally, create the GitHub release by hand** from the tag, using the
   version's `RELEASE_NOTES.md` section. The workflow never creates one.
8. **Open the next candidate.** Bump the version (for example to `0.1.3`) and
   add a new unreleased section to the changelog and release notes.

## When something goes wrong

- **A gate fails.** Fix the cause and dispatch again. Check the tag's target
  before pushing; a mistaken local tag can be corrected before it reaches the
  remote. Once pushed, the tag is immutable even if no package was uploaded.
  Prepare a new version if an incorrect tag reached the remote.
- **A bad file reached PyPI.** PyPI never accepts the same file name twice,
  even after deletion. Yank the release in the PyPI project settings, so
  that resolvers skip it unless it is pinned exactly, and publish a fixed
  version. Prefer yanking to deleting, and explain the reason in the yank
  message and the release notes.
- **Suspected compromise of the repository or its workflow.** Remove the trusted
  publisher on PyPI first; this stops further uploads with nothing to rotate.
  Then follow [SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md).
