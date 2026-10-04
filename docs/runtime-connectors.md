# Runtime connectors

Registered built-ins on this branch:

- `cloud.kubernetes` — offline kubectl JSON and read-only kubectl list. AI images, GGUF mounts, MCP annotations.
- `cloud.openshift` — same contract for oc, plus Routes, ImageStreams, and KServe InferenceService.
- `cloud.runtime-flows` — offline Tetragon or process-to-domain JSON. No in-tree eBPF program.
- `code.endpoint` — opt-in walk or offline inventory of MCP configs, coding-agent dirs, Ollama Modelfiles, and GGUF files.

Live cluster mode fails closed when kubectl/oc is absent. These connectors do not mutate the cluster and do not load a kernel probe.

```yaml
connectors:
  - name: cloud.kubernetes
    input: ./exports/pods.json
  - name: cloud.openshift
    input: ./exports/oc.json
  - name: cloud.runtime-flows
    input: ./exports/flows.json
  - name: code.endpoint
    input: ./exports/endpoint.json
```
