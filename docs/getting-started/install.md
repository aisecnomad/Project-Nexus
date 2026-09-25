# Installation

For deployment on Linux x86_64, use a reviewed full commit SHA and the
repository's hash-locked runtime dependencies. The required CI gates cover
Python 3.11 and 3.12. Python 3.13 awaits successful hosted matrix validation;
see [production deployment](../production.md#install-from-a-reviewed-revision)
for the release evidence and platform limits.

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
git clone https://github.com/aisecnomad/Project-Nexus.git
cd Project-Nexus
git checkout --detach "$SHADOWSCAN_REVISION"
test "$(git rev-parse HEAD)" = "$SHADOWSCAN_REVISION"
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade --only-binary=:all: \
  pip==26.2.1 setuptools==84.0.0 wheel==0.48.0
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m pip install --no-deps dist/shadowscan-*.whl
python -m pip check
python -m shadowscan.signatures.validate
shadowscan --help
```

The runtime lock includes core and all cloud SDK dependencies, even for a
code-only worker. Retain the selected commit and built wheel hash. Other
platforms need a separately validated lock; a commit SHA alone does not pin
transitive dependencies.

## Docker

The disposable non-root worker requires a reviewed index digest for its
`python:3.12-slim-bookworm` base image:

```bash
PYTHON_BASE_DIGEST="REPLACE_WITH_APPROVED_64_HEX_DIGEST"
[[ "$PYTHON_BASE_DIGEST" =~ ^[a-f0-9]{64}$ ]]
docker build --build-arg "PYTHON_BASE_DIGEST=$PYTHON_BASE_DIGEST" \
  --tag shadowscan:reviewed .
```

See [production deployment](../production.md) for container isolation and
rollout acceptance requirements.
