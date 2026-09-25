# Disposable ShadowScan worker with hash-locked core and cloud dependencies.
# Provide audit credentials at runtime only.
#
# Run from a non-root Linux account. Match the host UID/GID so the private bind
# mount is writable without making report directories world-writable.
#   mkdir -p out && chmod 700 out
#   docker build -t shadowscan:reviewed .
#   docker run --rm --read-only --user "$(id -u):$(id -g)" \
#     --cap-drop ALL --security-opt no-new-privileges \
#     --tmpfs /tmp:mode=1777 --env HOME=/tmp \
#     --network none \
#     -v "$PWD/repo:/input:ro" -v "$PWD/out:/output" \
#     shadowscan:reviewed code /input --format sarif -o /output/shadowscan.sarif
#
# Drop --network none for live API collection. Never mount production
# credential files into a container that also mounts an untrusted repo.
#
# Base image: python:3.12-slim-bookworm pinned to its multi-arch image index
# digest (the Docker-Content-Digest of the tag's OCI index, which covers the
# linux/amd64 manifest), resolved from Docker Hub on 2026-09-24. The digest
# lives on a literal FROM line because Dependabot's docker parser reads only
# literal FROM lines; the weekly docker entry in .github/dependabot.yml
# proposes digest refreshes. To refresh by hand, run
#   docker buildx imagetools inspect python:3.12-slim-bookworm
# and copy the top-level Digest (equivalently, the Docker-Content-Digest header
# of GET https://registry-1.docker.io/v2/library/python/manifests/3.12-slim-bookworm
# requested with Accept: application/vnd.oci.image.index.v1+json), then update
# the date in this comment.
#
# PYTHON_IMAGE selects the base and defaults to the pinned stage below. Build an
# immutable deployment image at a digest your own review approved instead:
#   docker build --build-arg PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:<digest> .
ARG PYTHON_IMAGE=pinned-base
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS pinned-base
FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.source="https://github.com/aisecnomad/Project-Nexus" \
      org.opencontainers.image.description="ShadowScan disposable scan worker" \
      org.opencontainers.image.licenses="Apache-2.0"

# apt packages are deliberately not version-pinned: Debian removes superseded
# package versions from its mirrors, so an exact pin fails at the next bookworm
# security update instead of reproducing the build. The base image digest fixes
# the package set the build starts from; apt-get update still reads the live
# archive, so the image is not byte-for-byte reproducible from this file alone.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/nonroot nonroot

WORKDIR /opt/shadowscan
COPY pyproject.toml requirements.lock requirements-build.lock README.md LICENSE NOTICE /opt/shadowscan/
COPY shadowscan /opt/shadowscan/shadowscan
COPY agent-card.yaml /opt/shadowscan/agent-card.yaml

# Do not `pip install --upgrade pip` from a floating index; the image's default
# pip installs both locks under --require-hashes. requirements-build.lock pins
# the [build-system] backend declared in pyproject.toml, and --no-build-isolation
# then builds the package with that backend instead of letting pip download one
# from the live index on a version pin alone. Build leftovers under
# /opt/shadowscan (bytecode, in-tree build output, egg-info) are removed so the
# retained source tree matches the reviewed checkout.
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
    && pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-build.lock \
    && pip install --no-cache-dir --no-deps --no-build-isolation /opt/shadowscan \
    && pip check \
    && find /opt/shadowscan -name __pycache__ -type d -prune -exec rm -rf {} + \
    && rm -rf /opt/shadowscan/build /opt/shadowscan/*.egg-info \
    && mkdir -p /work /output \
    && chown nonroot:nonroot /work /output

USER 65532:65532
WORKDIR /work
ENV HOME=/home/nonroot \
    XDG_STATE_HOME=/tmp/shadowscan-state \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["shadowscan"]
CMD ["--help"]
