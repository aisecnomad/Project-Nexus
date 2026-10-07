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
4. **Protect release tags.** Add a tag ruleset that targets `v*` and restricts
   creation, updates and deletion to the maintainer, so a published version's
   tag cannot be moved. The publication gate reads the tag before the approval
   wait, and the ruleset keeps that answer true until the upload.

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
   python -m pip install --no-deps --index-url https://test.pypi.org/simple/ NexusShadowScan==0.1.1
   shadowscan --help && python -m shadowscan.signatures.validate
   ```

4. **Tag the reviewed commit.** Use a signed, annotated tag:

   ```bash
   git tag -s v0.1.1 -m "NexusShadowScan 0.1.1" <reviewed-40-character-sha>
   git push origin v0.1.1
   ```

5. **Publish.** Dispatch the workflow again with the same inputs, a fresh
   `ruleset_readback`, and `publish: pypi`, then approve the `pypi`
   deployment. The gate rejects the
   run unless `v<version>` points at `expected_commit`.
6. **Verify what was published:**

   ```bash
   python -m pip download --no-deps --dest wheels NexusShadowScan==0.1.1
   gh attestation verify wheels/nexusshadowscan-0.1.1-py3-none-any.whl --repo aisecnomad/Project-Nexus
   ```

   Compare the wheel's SHA-256 with `SHA256SUMS` in the retained
   `release-candidate-<SHA>` artifact. On PyPI, the file's provenance should
   name this repository, `release.yml` and the `pypi` environment.
7. **Optionally, create the GitHub release by hand** from the tag, using the
   version's `RELEASE_NOTES.md` section. The workflow never creates one.
8. **Open the next candidate.** Bump the version (for example to `0.1.2`) and
   add a new unreleased section to the changelog and release notes.

## When something goes wrong

- **A gate fails.** Fix the cause and dispatch again. If the tag points at the
  wrong commit and nothing was uploaded, delete and recreate it on the reviewed
  commit. Never move the tag of a version that was uploaded.
- **A bad file reached PyPI.** PyPI never accepts the same file name twice,
  even after deletion. Yank the release in the PyPI project settings, so
  that resolvers skip it unless it is pinned exactly, and publish a fixed
  version. Prefer yanking to deleting, and explain the reason in the yank
  message and the release notes.
- **Suspected compromise of the repository or its workflow.** Remove the trusted
  publisher on PyPI first; this stops further uploads with nothing to rotate.
  Then follow [SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md).
