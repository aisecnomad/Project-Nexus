# Installation

## Requirements

- Python 3.11 or later
- pip 22.0 or later

## Core install

The core package includes code, identity, gateway, low-code, and SaaS connectors
(REST-based). Cloud SDKs are optional.

```bash
pip install "git+https://github.com/aisecnomad/Project-Nexus.git"
```

## With cloud connectors

To include AWS, GCP, Azure, and OCI SDK support:

```bash
pip install "shadowscan[cloud] @ git+https://github.com/aisecnomad/Project-Nexus.git"
```

Individual cloud providers can be installed selectively:

```bash
pip install "shadowscan[aws] @ git+https://github.com/aisecnomad/Project-Nexus.git"   # boto3
pip install "shadowscan[gcp] @ git+https://github.com/aisecnomad/Project-Nexus.git"   # google-auth
pip install "shadowscan[azure] @ git+https://github.com/aisecnomad/Project-Nexus.git" # azure-identity
pip install "shadowscan[oci] @ git+https://github.com/aisecnomad/Project-Nexus.git"   # oci
```

## From a reviewed commit

Pin to a specific commit SHA for reproducible installs:

```bash
pip install "git+https://github.com/aisecnomad/Project-Nexus.git@COMMIT_SHA"
```

!!! warning "Do not follow `main`"
    Install from a reviewed tag or commit SHA. The `main` branch receives
    changes that may not yet be validated against production tenants.

## Docker

A disposable non-root worker image is provided:

```bash
docker build -t shadowscan:local .
```

See [Production deployment](../production.md) for secure container usage.

## Verifying the installation

```bash
shadowscan --version
shadowscan --help
python -m shadowscan.signatures.validate  # validates 212 signatures / 990 signals
```

## Dependencies

Core dependencies are deliberately small: `click`, `rich`, `PyYAML`,
`requests`, `PyJWT`, `regex`. All runtime dependencies are version- and
hash-locked in `requirements.lock`.
