# Operational Controls

These controls are required for any production, CI, or unattended use of ShadowScan. They complement the in-process limits documented in [production.md](../production.md) and [SECURITY.md](../SECURITY.md).

## Mandatory external process supervision

Connector timeouts and the `--job-deadline-seconds` watchdog are cooperative. Python threads and many cloud SDK calls cannot be forcibly interrupted. **For any production, CI, or unattended use, enforce a hard external process or container deadline that terminates the entire scanner process.**

An incomplete scan (exit code 3) must fail the pipeline. Do not treat a timed-out report as authoritative.

**Examples**

- **systemd**
  ```ini
  [Service]
  TimeoutStartSec=900
  TimeoutStopSec=30
  KillMode=control-group
  ExecStart=/usr/bin/shadowscan scan -c /etc/shadowscan/config.yaml
  ```

- **Kubernetes Job**
  ```yaml
  spec:
    activeDeadlineSeconds: 1200
    backoffLimit: 0
  ```

- **Wrapper / CI**
  ```bash
  timeout 900 shadowscan scan -c config.yaml
  ```
  or set the GitHub Actions / GitLab CI job timeout to 15–30 minutes.

## Network egress policy

The shared `HttpClient` enforces HTTPS, origin pinning, and private/metadata denial at connect time. Cloud SDKs (`boto3`, `google-auth`, `azure-identity`, `oci`) and Git use their own transports and **do not** inherit these controls.

Deploy with an explicit egress allowlist that covers both the HttpClient destinations and the SDK endpoints required by enabled connectors.

**Baseline recommendations**

- Deny private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local, and cloud metadata (`169.254.169.254`) by default.
- Allow only the specific HTTPS endpoints needed for the connectors that are actually enabled (e.g. `api.github.com`, `graph.microsoft.com`, `bedrock.*.amazonaws.com`, `oauth2.googleapis.com`, etc.).
- Prefer routing live collection through an approved egress proxy when possible.
- See `examples/k8s-network-policy.yaml` for a starting Kubernetes NetworkPolicy.

## Plugin trust model

An allowlisted plugin (`options.plugins` or `--allow-plugin`) runs with the **full privileges** of the scanner process (network, credentials in the environment, ability to write findings and files).

Process isolation (spawn context + length-prefixed JSON over a socket, no pickle) protects against crashes and certain IPC attacks. It is **not a security sandbox**.

Treat every plugin as trusted code equivalent to a built-in connector. In high-assurance environments prefer built-in connectors only, or run the entire scanner inside a restricted container with seccomp/AppArmor and the network policy above.

## Detection expectations

ShadowScan produces **evidence of signals** that match its signatures within the scanned scope and the supplied inventory. It is not exhaustive proof of unauthorized agents or of runtime execution.

- Shadow status is only as good as the quality and freshness of the Agent Cards you provide.
- Novel frameworks, obfuscated agents, or pure API usage without recognizable signals produce false negatives.
- Confidence scores are heuristics, not probabilities.
- Treat results as a starting point for investigation, not as an enforcement verdict.

## SBOM and provenance

After building a wheel or container image from a reviewed SHA:

```bash
# Python runtime SBOM (example)
cyclonedx-py -o sbom-python.json
# or
syft packages dir:. -o cyclonedx-json=sbom-python.json

# Container image SBOM
syft packages <image>:<tag> -o cyclonedx-json=sbom-image.json
```

Retain the SBOM together with the attested wheel/image digests produced by the release-evidence workflow.
