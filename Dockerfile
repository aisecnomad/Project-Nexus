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
# Base image: Chainguard's Wolfi base (glibc, rolling security fixes), pinned in
# both stages to the multi-arch image index digest of chainguard/wolfi-base:latest
# (the Docker-Content-Digest of the tag's OCI index, which covers the
# linux/amd64 manifest), resolved from Docker Hub on 2026-10-02. Python 3.12,
# Git and every native library they load are Wolfi packages, so the CI image
# scan inventories the interpreter as well; a Python built outside the package
# manager, as in the official python images, is invisible to it. util-linux,
# ncurses, Perl and systemd, whose unfixed Debian advisories kept the previous
# Debian base from passing the scan, are not installed. Git is 2.45 or newer
# (`use_git` history enrichment needs it), and the build fails on an older git.
# Review Dependabot's proposed digest refreshes and keep both FROM lines equal.
# The literal FROM cannot be substituted by a mutable build argument.
# apk reads the live Wolfi repository at build time, so this image is not
# byte-for-byte reproducible. Retain built images by immutable digest for
# repeatable deployment; reproducible rebuilds additionally need an immutable
# package-repository snapshot and a validated reproducible build process.
# Both FROM lines and both
# apk python-3.12 and python-3.12-base pins MUST stay identical across the build
# and runtime stages.
# To refresh by hand, run
#   docker buildx imagetools inspect chainguard/wolfi-base:latest
# and copy the top-level image index Digest into both FROM lines after
# reviewing its source and updating the resolution date above.
# Anonymous Docker Hub pulls are rate limited. CI pulls this digest through the
# mirror.gcr.io pull-through cache; a digest pull is content-verified, so any
# builder can do the same (docs/production.md).
FROM chainguard/wolfi-base:latest@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d AS build

# apk packages are deliberately not version-pinned: Wolfi is a rolling
# distribution, and a pinned package stops receiving security fixes. The base
# image digest fixes the package set the build starts from; apk still reads the
# live Wolfi repository and checks its signatures against the keys in the base
# image, so the image is not byte-for-byte reproducible from this file alone.
#
# Temporary exception: python-3.12 3.12.15-r1, published on 2026-10-02, has no
# SHA-224 or SHA3-224 (no builtin _sha2 module, and its OpenSSL refuses both),
# while pip uses SHA-224 for its cache keys, so every pip install fails on it.
# Both stages stay on 3.12.15-r0, the last revision that built this image (the
# runtime copies a virtual environment bound to its interpreter). Drop both pins
# once a newer revision passes `python3.12 -c "import hashlib; hashlib.sha224"`.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache python-3.12=3.12.15-r0 python-3.12-base=3.12.15-r0 py3.12-pip

WORKDIR /opt/shadowscan
COPY pyproject.toml requirements.lock requirements-build.lock README.md LICENSE NOTICE /opt/shadowscan/
COPY shadowscan /opt/shadowscan/shadowscan

# The worker's packages go into a virtual environment that the runtime stage
# copies; pip itself stays in this stage. Do not `pip install --upgrade pip`
# from a floating index; Wolfi's pip installs both locks under
# --require-hashes. requirements-build.lock pins the [build-system] backend
# declared in pyproject.toml. It goes into a separate build environment that
# builds the wheel with --no-build-isolation, instead of letting pip download a
# backend from the live index on a version pin alone, and is never copied: the
# runtime environment holds only the runtime lock and the built wheel.
RUN python3.12 -m venv --without-pip /opt/venv \
    && python3.12 -m venv --without-pip /opt/build \
    && python3.12 -m pip --python /opt/venv/bin/python install --no-cache-dir --require-hashes \
        --only-binary=:all: -r requirements.lock \
    && python3.12 -m pip --python /opt/build/bin/python install --no-cache-dir --require-hashes \
        --only-binary=:all: -r requirements-build.lock \
    && python3.12 -m pip --python /opt/build/bin/python wheel --no-cache-dir --no-deps \
        --no-build-isolation --wheel-dir /opt/wheel /opt/shadowscan \
    && python3.12 -m pip --python /opt/venv/bin/python install --no-cache-dir --no-deps \
        /opt/wheel/nexusshadowscan-*.whl \
    && python3.12 -m pip --python /opt/venv/bin/python check

FROM chainguard/wolfi-base:latest@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d

LABEL org.opencontainers.image.source="https://github.com/aisecnomad/Project-Nexus" \
      org.opencontainers.image.description="ShadowScan disposable scan worker" \
      org.opencontainers.image.licenses="Apache-2.0"

# The runtime needs only the interpreter and Git with its HTTPS transport; pip
# and the build tools stay in the build stage. The worker never needs to gain
# privileges, so no file keeps a setuid or setgid bit; the build fails if one
# remains. The base image provides the nonroot account (65532).
# python-3.12 is pinned with the build stage (see there).
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache python-3.12=3.12.15-r0 python-3.12-base=3.12.15-r0 git \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && test -z "$(find / -xdev -type f -perm /6000 -print -quit)" \
    && mkdir -p /work /output \
    && chown 65532:65532 /work /output \
    && python3.12 -c "import re, subprocess, sys; v = tuple(map(int, re.search(r'(\d+)\.(\d+)', subprocess.run(['git', '--version'], capture_output=True, text=True, check=True).stdout).groups())); sys.exit(0 if v >= (2, 45) else 'git >= 2.45 is required for use_git history enrichment')"

COPY --from=build /opt/venv /opt/venv
COPY agent-card.yaml /opt/shadowscan/agent-card.yaml

USER 65532:65532
WORKDIR /work
ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/home/nonroot \
    XDG_STATE_HOME=/tmp/shadowscan-state \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["shadowscan"]
CMD ["--help"]
