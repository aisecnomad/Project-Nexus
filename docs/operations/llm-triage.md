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
    budget_seconds: 300          # 1 to 3600, the whole triage run
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
recorded as `status: unparseable`, as is a reply longer than 16 KiB, which is
refused unread (the response body is capped at 64 KiB). A reply that contains
more than one verdict object, such as one quoted from injected finding text
beside the model's own, is unparseable too, and requests ask for
`temperature: 0`. Free text is truncated (rationale 500 characters, suggested
action 200) and sanitized with the rest of the finding when the report is
written. These controls limit, but cannot prevent, a model being persuaded by
finding text: never let a pipeline suppress or close findings because of
`metadata.llm_triage`.

A failed request, including an unexpected error in the HTTP client, is
recorded as `status: failed` on the finding and as a
warning on the `engine.llm-triage` entry of the scan statistics. An API key
that is not a valid header value, or any other triage failure, is a warning
on that entry too; the key is never echoed. A triage
failure is not a discovery gap, so it does not make the scan incomplete.

A triage run is bounded. It sends no request after `budget_seconds` (default
300) have passed since it started, and the HTTP client's retries,
`Retry-After` waits, connection set-up and response reads end at the same
time: a retry wait that would pass the budget fails the request instead. Name
resolution is the exception: the operating system's resolver is not bounded,
so a slow resolver can use part of the job deadline's reserve.
After three consecutive failed requests the run stops, so an endpoint that is
down or rate-limited costs three failed requests, not one per selected
finding. Selected findings that a stopped run did not reach are recorded as
`status: skipped`, and the `engine.llm-triage` entry gets a warning that
names the reason and how many findings were skipped. Raising `max_findings`
usually needs a larger `budget_seconds` too; otherwise the later findings are
recorded as skipped.

In a CLI scan with a job deadline (`--job-deadline-seconds`, or
`options.job_deadline_seconds` read by the CLI), triage also stops early
enough to reserve time for writing the report before the deadline exits the
process: 10% of the deadline, at least 5 and at most 60 seconds. When less
than that is left after collection, triage is skipped: the selected findings
are recorded as `status: skipped` and, if there are any, the entry carries a
warning. The reserve is a heuristic: a collection or report write that
outlasts it still reaches the deadline, which exits 3 as before. A library
caller that stops its own process at a deadline passes it as
`Engine.run(job_deadline=<time.monotonic() value>)`; the reserve is then 10%
of `options.job_deadline_seconds` (5 to 60 seconds), or 5 seconds when that
option is not set. `options.job_deadline_seconds` alone does not bound triage
in a library scan.

Model verdicts are not measured: no evaluation of triage accuracy is
published. Treat a verdict as a reviewer's note, not as a label.
