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
# Supply an approved image digest for immutable deployment builds:
#   docker build --build-arg PYTHON_IMAGE=python:3.12-slim-trixie@sha256:<digest> .
# Debian 13 (trixie) ships Git 2.47; `use_git` history enrichment needs 2.45+.
ARG PYTHON_IMAGE=python:3.12-slim-trixie
FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.source="https://github.com/aisecnomad/Project-Nexus" \
      org.opencontainers.image.description="ShadowScan disposable scan worker" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/nonroot nonroot \
    && python3 -c "import re, subprocess, sys; v = tuple(map(int, re.search(r'(\d+)\.(\d+)', subprocess.run(['git', '--version'], capture_output=True, text=True, check=True).stdout).groups())); sys.exit(0 if v >= (2, 45) else 'git >= 2.45 is required for use_git history enrichment')"

WORKDIR /opt/shadowscan
COPY pyproject.toml requirements.lock README.md LICENSE NOTICE /opt/shadowscan/
COPY shadowscan /opt/shadowscan/shadowscan
COPY agent-card.yaml /opt/shadowscan/agent-card.yaml

# Do not `pip install --upgrade pip` from a floating index. The lockfile pins
# runtime dependencies; the image's default pip is sufficient to install them.
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock \
    && pip install --no-cache-dir --no-deps /opt/shadowscan \
    && pip check \
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
