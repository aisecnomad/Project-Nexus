# Disposable ShadowScan worker with core dependencies (offline scans and REST
# connectors). Cloud SDK extras are not installed. Provide secrets at runtime.
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
FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/nonroot nonroot

WORKDIR /opt/shadowscan
COPY pyproject.toml README.md LICENSE NOTICE /opt/shadowscan/
COPY shadowscan /opt/shadowscan/shadowscan
COPY agent-card.yaml /opt/shadowscan/agent-card.yaml

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir /opt/shadowscan \
    && mkdir -p /work /output \
    && chown nonroot:nonroot /work /output

USER 65532:65532
WORKDIR /work
ENV HOME=/home/nonroot \
    XDG_STATE_HOME=/tmp/shadowscan-state \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Validate installed package data from outside the source directory as non-root.
RUN python -m shadowscan.signatures.validate && shadowscan --help > /dev/null

ENTRYPOINT ["shadowscan"]
CMD ["--help"]
