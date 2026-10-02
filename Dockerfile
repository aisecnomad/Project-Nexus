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
# Base image: python:3.12-slim-trixie pinned to its multi-arch image index
# digest (the Docker-Content-Digest of the tag's OCI index, which covers the
# linux/amd64 manifest), resolved from Docker Hub on 2026-10-02. It carries
# Python 3.12.15, whose bundled expat 2.8.5 parses every XML file the scanner
# reads from a repository; expat 2.8.3 and earlier have denial-of-service and
# memory-safety advisories, and an image scan cannot see Python's bundled copy.
# Debian 13 (trixie) ships Git 2.47; `use_git` history enrichment needs 2.45+,
# and the build below fails on an older git. Review Dependabot's proposed digest
# refreshes. The literal FROM cannot be substituted by a mutable build argument.
# To refresh by hand, run
#   docker buildx imagetools inspect python:3.12-slim-trixie
# and copy the top-level image index Digest into this literal FROM line after
# reviewing its source and updating the resolution date above.
FROM python:3.12-slim-trixie@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

LABEL org.opencontainers.image.source="https://github.com/aisecnomad/Project-Nexus" \
      org.opencontainers.image.description="ShadowScan disposable scan worker" \
      org.opencontainers.image.licenses="Apache-2.0"

# apt packages are deliberately not version-pinned: Debian removes superseded
# package versions from its mirrors, so an exact pin fails at the next trixie
# security update instead of reproducing the build. The base image digest fixes
# the package set the build starts from; apt-get update still reads the live
# archive, so the image is not byte-for-byte reproducible from this file alone.
# Upgrade installed base packages too: installing git does not update existing
# OpenSSL or PCRE2 libraries. The 2026-10-02 image scan found security fixes in
# trixie-security (OpenSSL 3.5.7-1~deb13u3 and PCRE2 10.46-1~deb13u3):
#   https://security-tracker.debian.org/tracker/DSA-6531-1
#   https://security-tracker.debian.org/tracker/CVE-2026-103111
# Other upstream findings can remain without a stable Debian fix. The CI image
# scan still blocks every detected HIGH/CRITICAL finding, including unfixed ones.
# The worker never needs to gain privileges, so no file keeps a setuid or setgid
# bit (mount, su, passwd, ...); the build fails if one remains.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && test -z "$(find / -xdev -type f -perm /6000 -print -quit)" \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/nonroot nonroot \
    && python3 -c "import re, subprocess, sys; v = tuple(map(int, re.search(r'(\d+)\.(\d+)', subprocess.run(['git', '--version'], capture_output=True, text=True, check=True).stdout).groups())); sys.exit(0 if v >= (2, 45) else 'git >= 2.45 is required for use_git history enrichment')"

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
