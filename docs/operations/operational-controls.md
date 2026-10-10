# Operational Controls for Production Use

These controls implement the production security recommendations for ShadowScan beyond the core scanner design.

## Mandatory External Process Supervision

Python cooperative timeouts cannot forcibly interrupt blocked threads, external SDK calls, or plugins. For any production, CI, or unattended use, enforce a hard external process or container deadline that terminates the entire process.

Examples:
- systemd: `TimeoutStartSec=900` and `KillMode=control-group`
- Kubernetes Job: `activeDeadlineSeconds: 1200`
- Shell: `timeout 900 shadowscan scan -c config.yaml`
- CI: job timeout of 15-30 minutes

An incomplete scan (exit code 3) must fail the pipeline. Do not treat a timed-out report as authoritative.

## Network Egress Policy

The shared HttpClient enforces HTTPS, origin pinning, and private/metadata destination blocking at connection time. Cloud SDKs (boto3, google-auth, azure-identity, oci) and Git use separate transports.

Deploy with an explicit egress allowlist at the network layer:
- Deny private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), metadata (169.254.169.254), and all other egress by default.
- Allow only the specific HTTPS endpoints required by enabled connectors.
- Prefer an approved egress proxy for live collection.

See `examples/k8s-network-policy.yaml` for a baseline Kubernetes NetworkPolicy.

## Plugin Trust Model

Plugins listed in `options.plugins` or `--allow-plugin` run with the full privileges of the scanner process. Process isolation (spawn + JSON IPC, no pickle) protects against crashes and certain IPC attacks but is **not a security sandbox**. A malicious or compromised plugin can access credentials, make arbitrary network calls, and influence findings. Treat every plugin as trusted code equivalent to a built-in connector. Prefer built-in connectors only in high-assurance environments, or run the entire scanner inside a restricted container with seccomp/AppArmor and network policies.

## Detection Expectations

ShadowScan produces evidence of signals matching its signatures within the scanned scope and the supplied inventory. It is not exhaustive proof of unauthorized agents, complete estate coverage, or runtime execution. Shadow status is only as accurate as the freshness and completeness of the provided Agent Cards. Novel frameworks, obfuscated agents, or pure API usage without recognizable signals may produce false negatives. Treat findings as starting points for investigation, not as definitive enforcement decisions.

## SBOM and Provenance

Generate and retain an SBOM for the wheel and the container image alongside the attested artifacts.

```bash
# After building the wheel
cyclonedx-py -o sbom.json || syft packages dir:. -o cyclonedx-json=sbom.json
# For the container image
syft shadowscan:reviewed -o cyclonedx-json=container-sbom.json
```

Retain the SBOM with the release evidence.
