# Operational controls

These controls apply to any production, CI or unattended use of ShadowScan.
They complement the in-process limits in
[production deployment](../production.md#resource-limits-and-incomplete-scans)
and the trust model in
[SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md).

## External process supervision

Connector timeouts and the CLI's `--job-deadline-seconds` watchdog are
cooperative. Python threads, native code and many cloud SDK calls cannot be
interrupted from inside the process, and SIGKILL or an OOM kill skips all
cleanup. Bound every unattended run with an external deadline that terminates
the whole process group or container.

An incomplete scan exits with code `3`. Fail the pipeline on it, and never treat
a timed-out or incomplete report as an authoritative inventory.

- **systemd**: run the scan as a `oneshot` unit. `TimeoutStartSec=` bounds a
  oneshot unit's whole run; for a `simple` unit it bounds only start-up, and
  `RuntimeMaxSec=` is the limit that applies.

  ```ini
  [Service]
  Type=oneshot
  TimeoutStartSec=900
  KillMode=control-group
  ExecStart=/usr/bin/shadowscan scan -c /etc/shadowscan/config.yaml
  ```

- **Kubernetes**: set `activeDeadlineSeconds` and `backoffLimit: 0` on the Job,
  as the [offline Job example](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/k8s-job.yaml)
  does.
- **CI or a wrapper script**: `timeout --kill-after=30s 900 shadowscan scan -c config.yaml`,
  together with the CI system's job timeout.

## Network egress

The shared HTTP client enforces HTTPS, origin pinning and private, link-local
and metadata address denial at connect time. Cloud SDKs (`boto3`,
`google-auth`, `azure-identity`, `oci`) and Git use their own transports and do
not inherit these controls, so enforce egress outside the process as well.

- **Offline scans** need no network. The offline Job example pairs the Job with
  a NetworkPolicy that denies all egress.
- **Live collection** needs named API hosts. A standard Kubernetes
  NetworkPolicy matches addresses, not DNS names, so it cannot express "only
  `graph.microsoft.com`". Enforce the allowlist of the enabled connectors' hosts
  in a layer that sees names: a transparent egress gateway or firewall that
  filters on TLS SNI, or a CNI with FQDN policies. ShadowScan's HTTP client
  refuses configured proxies, both from the environment and explicit ones, so
  that a proxy cannot route around its destination checks. The
  [live egress example](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/k8s-network-policy.yaml)
  is the address-level baseline underneath that allowlist: cluster DNS and HTTPS
  to public addresses only. It works only with a CNI that enforces
  NetworkPolicy.

## Plugin trust

An allowlisted plugin (`options.plugins` or `--allow-plugin`) runs with the
scanner's privileges: its network access, the credentials in its environment
and its ability to write findings and files. Process mode runs each plugin in a
spawned worker that returns one length-prefixed, size-bounded JSON message over
a socket, never pickle. That isolates crashes and the result channel; it is not
a security sandbox. Treat every plugin as trusted code equivalent to a built-in
connector. In high-assurance environments use built-in connectors only, or run
the whole scanner in a restricted container with the egress controls above.

## Detection expectations

ShadowScan reports evidence of signals that match its signatures within the
scanned scope and the supplied inventory. It does not prove that unauthorized
agents exist or that they ran.

- Shadow status is only as good as the coverage and freshness of the inventory.
  A scan without an inventory leaves registration unassessed.
- Novel frameworks, obfuscated agents and API use without recognizable signals
  produce false negatives.
- Confidence and risk scores are heuristics, not calibrated probabilities.
- Treat results as the start of an investigation, not an enforcement verdict.

## SBOM and provenance

The [release-evidence workflow](publishing.md) builds the wheel from the
selected commit, writes a CycloneDX SBOM of the locked runtime dependencies
(`runtime-sbom.cdx.json`) and attests the wheel's provenance and that SBOM.
Retain those attestations with the wheel digest you deploy.

The workflow does not build or attest a container image. If you build the
worker image yourself, generate its SBOM from the pushed digest and keep it with
the image, for example:

```bash
syft registry.example.com/shadowscan@sha256:<digest> -o cyclonedx-json=sbom-image.cdx.json
```
