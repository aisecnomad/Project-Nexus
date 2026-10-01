# Field scan of five public agent repositories

> **Internal, AI-assisted field scan. Not an independent review.** The scans
> were run and the findings were read against the scanned source by an AI
> assistant working for the maintainer. No second person verified them. The
> assessments below are not labeled ground truth, and nothing here estimates
> precision, recall or calibration.

Scanner: `0b69d4ac515d0de9a71d785f38b7ea3ec464a68d` on `main` (0.1.1, unreleased),
215 signatures / 1001 signals. Installed into a clean virtual environment from
`requirements.lock` with `--require-hashes`, then
`pip install --no-deps --no-build-isolation -e .`.
Python 3.11.15 on Linux x86_64. Date: 2026-10-01.

Each repository was shallow-cloned at its default branch and scanned with the
documented defaults:

```bash
shadowscan code <checkout> --format json -o <name>.json
```

That means a 120-second connector deadline, secret scanning on, test code at
half weight and no Git enrichment. Dify was scanned a second time with
`--connector-timeout-seconds 1200`. Two scans were repeated to check that the
results are stable.

## Targets

None of these repositories was part of the 2026-09-25 field review (discord.py,
anthropic-quickstarts, modelcontextprotocol/servers, crewAI-examples).

| Repository | Commit | Tracked files | Why it was chosen |
| --- | --- | --- | --- |
| [openai/openai-agents-python](https://github.com/openai/openai-agents-python/tree/28e9f4fca26dd1c7e679398b87182868ecfad714) | `28e9f4f` | 1,667 | Python agent SDK with many runnable examples |
| [browser-use/browser-use](https://github.com/browser-use/browser-use/tree/4cbe921673b48a488f5415d9159249afd12a625b) | `4cbe921` | 518 | Autonomous browser agent supporting about 18 model providers |
| [google-gemini/gemini-cli](https://github.com/google-gemini/gemini-cli/tree/c6bccb7ecbf6d8368d995455dd725ed34466faad) | `c6bccb7` | 3,022 | TypeScript/React coding agent, MCP client, A2A server, CI agents |
| [github/github-mcp-server](https://github.com/github/github-mcp-server/tree/5a1a3866d4a681d771162d35680d6c7219eac3b0) | `5a1a386` | 587 | Official GitHub MCP server in Go |
| [langgenius/dify](https://github.com/langgenius/dify/tree/431c1857062d09225dc2b51104b51b0ad1ef6f18) | `431c185` | 14,165 | Low-code agent platform, Python and Next.js monorepo |

## Results

| Repository | Exit | Wall time | Peak RSS | Files examined | Findings | Risk levels |
| --- | --- | --- | --- | --- | --- | --- |
| openai-agents-python | 3 | 41 s | 92 MiB | 1,664 | 7: 4 framework-usage, 2 agent-config, 1 agent | 1 high, 2 medium, 4 low |
| browser-use | **0** | 12 s | 78 MiB | 513 | 4: 1 framework-usage, 2 agent-config, 1 mcp-server | 1 critical, 2 medium, 1 low |
| gemini-cli | 3 | 50 s | 63 MiB | 3,009 | 20: 11 framework-usage, 8 agent-config, 1 mcp-server | 2 high, 11 medium, 7 low |
| github-mcp-server | 3 | 8 s | 52 MiB | 585 | 5: 2 framework-usage, 2 mcp-server, 1 agent-config | 3 medium, 2 low |
| dify, default deadline | 3 | 115 s | 75 MiB | 12,082 of 14,143 | 49 | 2 high, 4 medium, 43 low |
| dify, 1,200 s deadline | 3 | 127 s | 78 MiB | 14,143 | 49: 25 framework-usage, 11 workflow, 9 agent-config, 3 infra, 1 agent | 2 high, 4 medium, 43 low |

Only browser-use completed. The scanner never presented an incomplete scan as
complete, and `diff` declined to establish resolution between incomplete
reports. Fail-closed behavior worked as documented. Most of the incompleteness,
however, came from scanner defects rather than from the repositories.

## Why four of five scans were incomplete

| Cause | Where | Count | Assessment |
| --- | --- | --- | --- |
| JSX lexer ambiguity, 3 patterns below | dify, gemini-cli | 134 + 5 files | Defect. All three are valid TSX constructs. |
| Gemini CLI `httpUrl` MCP transport key | github-mcp-server `gemini-extension.json` | 1 | Defect. Also misses the remote server. |
| Workflow YAML parsed as MCP config by the strict loader | gemini-cli `.github/workflows/*dedup.yml` | 2 | Defect. `on:` is a boolean key. |
| Connector deadline | dify | 1 | Default too short: the full walk takes 127 s. |
| Regex timeout (`heuristic.named-tool-lookup`) | dify vendored Monaco `web/public/vs/**/cssWorker.js` | 1 | Vendored bundle. Exclude it, or treat it as generated. |
| Oversize files not in `oversize_skip_globs` | dify `*.min.mjs`, Monaco workers; fixtures elsewhere | 5 | Configuration. `*.min.mjs` is missing from the defaults. |
| Symlinks: `CLAUDE.md -> AGENTS.md`, `docs/CONTRIBUTING.md`, `.claude/skills/<dir>` | 3 repos | 3 | Documented policy. `CLAUDE.md -> AGENTS.md` is a common real-world layout. |

### JSX lexer

`source_ranges._javascript_ranges` loses track of JSX nesting in three valid
TSX patterns. Each minimal reproducer below returns `ambiguous=True` from
`noncode_ranges(src, "javascript", ".tsx", jsx=True)`. Plain JSX and
`<T,>(x: T) => x` controls pass.

To attribute all 139 affected files, each candidate correction was applied
separately to a scratch copy of the lexer. Each file was resolved by exactly
one correction: 129 by the first below, 9 by the second and 1 by the third.
The prototype also left the plain JSX, `<T,>`, `<T extends object>` and
regex/comparison controls unambiguous. It is not a reviewed patch and was not
run against the test suite.

1. **Type arguments on a child element (129 files).** `_jsx_open_name` rejects
   `<Select<` because the name is followed by `<`. The walk then steps over the
   `<` and treats the type argument `<Option>` as an opening tag that never
   closes. At expression position the tag is lexed as plain code instead. That
   happens to pass for a self-closing element, but a closing tag such as
   `</Form>` then lexes as a regular expression.

   ```tsx
   export const A = () => (
     <Box>
       <Select<Option> value={v} onChange={set} />
     </Box>
   );
   ```

   String-literal and object type arguments (`<Picker<'day' | 'hour'>`,
   `<Form<{ email: string }>`) fail the same way.

2. **Comments between attributes (9 files).** `jsx_tag` mode recognizes quotes and `{`
   but not `//` or `/* */`. An apostrophe in a comment opens an attribute
   string, and `// style={{` opens an expression that its commented-out close
   cannot end.

   ```tsx
   export const C = () => (
     <ul
       // the browser's default list role
       role="list"
     >
       <li>x</li>
     </ul>
   );
   ```

3. **Child text that starts with `(` (1 file).** `<Text>(` matches the
   generic-arrow-function guard (`<T>(...)`), so the tag is not opened and
   `</Text>` lexes as an unterminated regex.

   ```tsx
   export const E = ({ n }: { n: number }) => <Text>({n})</Text>;
   ```

### MCP configuration parsing

`_parse_mcp_servers` accepts `url`, `serverUrl` and `endpoint`, but not Gemini
CLI's `httpUrl` (Streamable HTTP). The official server's extension manifest
therefore produces "MCP server entry has no command, URL, or valid package",
and its remote endpoint is not reported:

```json
{"name": "x", "version": "1.0.0",
 "mcpServers": {"remote": {"httpUrl": "https://mcp.example.com/mcp/"}}}
```

Any `.yml` that contains the text `"mcpServers"` qualifies as an MCP candidate
(`_looks_like_mcp_config`). A GitHub Actions workflow passing Gemini settings to
`google-github-actions/run-gemini-cli` qualifies, and
`strict_bounded_safe_load(text)` then rejects its `on:` key, which YAML 1.1
parses as `True`. The `with.settings` string is never inspected, so the
docker-based MCP server those workflows give `GITHUB_TOKEN` and `GEMINI_API_KEY`
to is not reported. The `run-gemini-cli` step itself is still detected as a
Gemini CLI configuration.

## Detection observations

| Observation | Evidence | Assessment |
| --- | --- | --- |
| Gemini CLI's agent core is not classified as an agent | `packages/core`: `agent_indicators` 0, despite 73 agent-loop, 51 tool-use, 53 autonomy and 21 code-execution matches, with `@google/genai` as the model SDK | Recall gap for hand-written Gemini SDK tool loops in TypeScript. Reported as framework-usage, high 63. |
| Google ADK attributed without ADK | 3 gemini-cli findings name ADK. The only ADK evidence is `GOOGLE_GENAI_USE_VERTEXAI`, mapped to `framework.google-adk` in `frameworks/orchestrators.yaml`. No `@google/adk` dependency or import exists. | Attribution error. The variable belongs to the google-genai SDK and is already a Vertex AI provider signal. |
| GitHub MCP server's tools are not read | `mcp_tools.py` extracts Python and TypeScript registrations only. The Go server has more than 120 `mcp.Tool{...}` definitions, including `push_files`, `delete_file`, `create_or_update_file`, `merge_pull_request`, `actions_run_trigger` and `delete_repository`. | The server is reported as framework-usage, low 15, with only `tool-use`. The capabilities of what it exposes are missing. |
| Test-fixture workflows reported as workflows | 10 of 11 Dify DSL findings are under `api/tests/fixtures/workflow/` or `cli/test/e2e/fixtures/`, at confidence 0.84 with no `test-code-only` tag | `_workflow_finding` ignores the test-path policy that project findings apply. |
| Spurious project root | `src/agents/tracing/setup.py` is an ordinary module (no setuptools or distutils), but `setup.py` is in `PROJECT_ROOT_MARKERS` | Splits off a separate "LLM usage in src/agents/tracing" finding. |
| Provider support drives risk | browser-use root: critical 98 for a framework-usage finding. 38 points come from 8 per-provider factors (DeepSeek +10, OpenRouter +10, …) across the 18 providers it supports. Without them it would score 60 (high). | Supporting a provider is scored like using one. A framework's adapter list inflates risk. |
| Framework repositories are not agents | openai-agents-python and browser-use import their own package. The local-module rule leaves `agent_indicators` at 0, so the 111 example files in openai-agents-python that construct `Agent(...)` do not establish agents. | Works as designed. Only `examples/live/app`, with its own manifest, is an agent. |
| Repeated evidence | `integration-tests/*.test.ts:11` appears 5 times as the same `@google/genai` import | Cosmetic. Confidence grouping prevents inflation. |
| Per-package agent configuration | gemini-cli ships `GEMINI.md` in 8 packages, giving 8 agent-config findings. Monorepo-internal `@google/gemini-cli-core` dependencies are also counted as "configured" evidence. | The findings are correct, but repetitive. |

Findings that read correctly against the source:

- Claude Code, Codex skills (`.agents/skills/*/agents/openai.yaml`), Copilot
  custom agents (`.github/agents/*.md`), Gemini CLI and `AGENTS.md`
  configurations.
- MCP registry `server.json` files (browser-use, github-mcp-server),
  `agent-plugin/mcp.json`, and Gemini's MCP extension example.
- The Pydantic AI agent in `dify-agent`, and the OpenAI Agents SDK app in
  `examples/live/app`.
- Dify's Docker Compose deployments, reported as infrastructure.

## What held up

- **Credentials.** No `secret` findings were raised. A separate regex sweep for
  key-shaped strings (OpenAI, Anthropic, Google, GitHub, AWS, Groq, Hugging Face)
  found 51 matches, all of them test placeholders. Where the scanner reported a
  credential-shaped value, it recorded an example credential with a
  placeholder-word or low-entropy reason, as a SHA-256 fingerprint. Source
  excerpts show `[REDACTED]`, and none of the 51 matched values appears in any
  report.
- **Determinism.** Repeat scans of github-mcp-server and browser-use produced
  identical finding IDs, scores and confidences.
- **Cost.** Peak RSS stayed between 52 and 92 MiB. Throughput was about 110
  files per second on Dify, with roots in one connector scanned sequentially. A
  combined five-repository run took 240 s and produced 85 findings, the same
  total as the individual runs.

## Limits

These are shallow clones of default branches at one point in time. The
assessments are AI judgments from reading the scanned source, without a labeled
corpus or a second reviewer. Only the code surface was exercised: no live
connectors, inventories or gateway logs. The selection favors well-known agent
projects, so it says nothing about false-positive rates on ordinary
repositories.

## Suggested follow-ups

In priority order. Each needs a regression case written from scratch, not
copied from these projects.

1. JSX lexer: accept type arguments after a tag name, skip comments in
   `jsx_tag` mode, and narrow the generic-arrow guard to what follows the
   matching `)`.
2. MCP: accept `httpUrl` as a URL alias. Load workflow YAML with the config
   loader, or skip structural MCP parsing for `.github/workflows/`. Consider
   extracting `settings` / `mcp_config` inputs of known agent actions.
3. Signatures: drop `GOOGLE_GENAI_USE_VERTEXAI` from `framework.google-adk`.
4. Extract MCP tool names from Go registrations (`mcp.Tool{Name: ...}`,
   `mcp.NewTool("...")`).
5. Apply the test-path policy to workflow exports. Require a `setup(` call or a
   setuptools import before treating `setup.py` as a project root.
6. Add `*.min.mjs` to the default `oversize_skip_globs`. Document a connector
   deadline for repositories over about 10,000 files.
7. Consider capping per-provider risk factors on framework-usage findings.
