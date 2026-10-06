# Opt-in LLM triage

ShadowScan can ask a language model for an advisory second opinion on its
highest-risk findings. Triage is **off by default** and does nothing unless a
scan configuration enables it.

```yaml
options:
  llm_triage:
    enabled: true
    provider: anthropic          # or openai (any OpenAI-compatible chat endpoint)
    model: <model-id>            # required; there is no default model
    api_key_env: ANTHROPIC_API_KEY
    # base_url: https://llm-gateway.example.com   # optional, https only
    max_findings: 25             # 1 to 500, highest risk first
    min_level: medium            # lowest heuristic risk level triaged
    timeout_seconds: 30
```

The key is read from the environment variable named by `api_key_env`
(`ANTHROPIC_API_KEY` or `OPENAI_API_KEY` by default). A key written into the
configuration is refused.

## What the model sees

For each selected finding: its title, surface, kind, connector, resource type,
technology and model-provider names, capabilities, tags, heuristic risk
level, confidence, shadow status, and up to twelve evidence signals with their
descriptions. **Resource ids, owners, accounts, file locations and code
snippets are not sent as fields**, and their values (with the host, user,
path, file and network client names a connector records) are replaced by
`[withheld]` wherever they appear in the title or an evidence description; a
one- or two-character value is replaced where it stands as a whole word. Every value has
passed the report sanitizer, so credentials ShadowScan redacted stay
redacted. Other free text can still name a product, repository or app; do not
enable triage for scans whose findings must not leave your environment, or
point `base_url` at a model endpoint you operate.

The request goes through the scanner's HTTP client: HTTPS only, no redirect
to another origin, and private or loopback endpoints refused unless the scan
allows private origins (`--allow-private-origin`).

## What triage changes

Only `metadata.llm_triage` on each triaged finding:

```json
{"status": "ok", "advisory": true, "provider": "anthropic", "model": "<model-id>",
 "verdict": "likely-agent", "rationale": "…", "suggested_action": "…"}
```

`verdict` is one of `likely-agent`, `likely-llm-use`, `likely-benign` or
`uncertain`. Triage never changes a finding's kind, confidence, risk, shadow
status or the scan's completeness, and `--fail-on` ignores it.

Finding text comes from scanned repositories and remote APIs and is
untrusted. The model is told to treat it as data, and a reply is accepted
only as a JSON object with one of the four verdicts; anything else is
recorded as `status: unparseable`. Free text is truncated (rationale 500
characters, suggested action 200) and sanitized before it is stored.

A failed request is recorded as `status: failed` on the finding and as a
warning on the `engine.llm-triage` entry of the scan statistics. An API key
that is not a valid header value, or any other triage failure, is a warning
on that entry too; the key is never echoed. A triage
failure is not a discovery gap, so it does not make the scan incomplete.

Model verdicts are not measured: no evaluation of triage accuracy is
published. Treat a verdict as a reviewer's note, not as a label.
