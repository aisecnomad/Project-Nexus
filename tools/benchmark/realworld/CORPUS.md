# Corpus summary (generated)

326 scored repositories; oracle version 2.

## Frames and oracle states

| frame | class | repos | positive | negative | ambiguous | ai-library |
|---|---|---|---|---|---|---|
| classical-ml | challenge | 14 | 2 | 12 | 0 | 0 |
| hard-negative | challenge | 24 | 3 | 20 | 1 | 0 |
| prose-only | challenge | 8 | 2 | 6 | 0 | 0 |
| list-agents | list | 20 | 15 | 0 | 2 | 3 |
| list-claude-code | list | 20 | 19 | 0 | 1 | 0 |
| list-mcp | list | 20 | 20 | 0 | 0 | 0 |
| list-ordinary | list | 30 | 8 | 22 | 0 | 0 |
| gitlab-random | probability | 30 | 1 | 29 | 0 | 0 |
| go-ai | probability | 12 | 10 | 1 | 0 | 1 |
| go-random | probability | 24 | 6 | 18 | 0 | 0 |
| pypi-ai | probability | 26 | 24 | 1 | 0 | 1 |
| pypi-other | probability | 26 | 4 | 22 | 0 | 0 |
| gitlab-ai | search | 20 | 15 | 5 | 0 | 0 |
| npm-ai | search | 26 | 23 | 2 | 0 | 1 |
| npm-other | search | 26 | 2 | 24 | 0 | 0 |
| **all** |  | 326 | 154 | 162 | 4 | 6 |

## Primary analysis set

315 repositories: the 326 scored, less 4 ambiguous and 6 AI-library repositories, and less 1 repository (rw-121) that a file of the ShadowScan repository names. A second named repository (rw-111) is an AI library and was already out.

| class | primary repositories | of which positive |
|---|---|---|
| probability | 115 | 44 |
| search | 71 | 40 |
| list | 84 | 62 |
| challenge | 45 | 7 |

Among the 153 positives: 144 involve an agent-type artifact (agent framework, MCP, coding-agent configuration), 9 are LLM-SDK use only, 111 have application-level evidence (dependency, import, workflow, IaC), and 42 are developer-tooling configuration only (for example AGENTS.md, CLAUDE.md, .mcp.json).

This benchmark therefore measures mostly agent-type integrations; plain LLM-SDK use is a small share.

## Languages (primary set, by most common source extension)

| language | repos |
|---|---|
| python | 106 |
| typescript | 65 |
| go | 55 |
| javascript | 33 |
| shell | 11 |
| rust | 9 |
| java | 8 |
| c | 6 |
| php | 5 |
| cpp | 5 |
| none | 5 |
| csharp | 3 |
| ruby | 2 |
| lua | 1 |
| swift | 1 |

## Hosts and size

| host | repos |
|---|---|
| github.com | 275 |
| gitlab.com | 51 |

Snapshot size: median 1.5 MB, max 154.4 MB. At sampling time 283 symlinks were recorded and 10 neutralised by the first (lexical) check; a later physical-resolution audit of the stored corpus neutralised 19 more (PROTOCOL.md section 3.2).

## Owners

322 distinct owners (cap 2 per owner).
