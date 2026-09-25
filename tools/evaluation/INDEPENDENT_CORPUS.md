# Independent public-file corpus

`independent_corpus.json` is a purposive, negative-heavy evaluation of **agent
presence in the supplied file**. It contains 42 complete source files from 15
public repositories: 30 negatives and 12 positives. The source languages are
Python (21), TypeScript (11), JavaScript (6), Go (2), and Rust (2).

Each case preserves one complete upstream Git blob, including comments, at its
original repository-relative path. No sample was edited, reduced to a matching
snippet, or executed. Git commits are pinned in full; source URLs and SHA-256
digests are recorded in every case. The 42 embedded files total 154,838 bytes;
each is below the evaluator's 32,000-byte per-file limit.

## Label rule

A positive file contains meaningful AI-agent construction or configuration:
explicit construction through an AI-agent SDK, or model-directed tool/action
selection. Agent creation need not prove that the program was deployed or
executed. An explicit AI-agent SDK with instructions and typed output or retry
configuration qualifies even if it has no external tool.

Ordinary worker processes, scheduled jobs, retry loops, event streams, build
orchestration, graph traversal, and generic function queues are negative unless
the file also establishes an AI agent. Provider API calls alone, including
structured output and fine-tuning polling, are negative. An MCP tool server alone
is negative for **agent** presence even though an MCP-server finding could be
valid under a different target kind.

Every label is justified from the complete supplied source file. Imports and
repository-relative paths remain intact; this is a static source-evidence
evaluation, not a claim that one isolated file is runnable without dependencies.
No label relies on guessing whether an omitted caller might use a generic
utility inside an agent.

| Source category | Cases | Agent label |
| --- | ---: | --- |
| Conventional web routes and template rendering | 4 | Negative |
| Scheduled tasks, worker jobs, and job wrappers | 6 | Negative |
| Graph algorithms and data structures | 3 | Negative |
| Queue concurrency control | 2 | Negative |
| Retry, concurrency, and memory utilities | 4 | Negative |
| Build-file generation and jobserver pool | 2 | Negative |
| Provider API clients without agent construction | 8 | Negative |
| Standalone MCP tool service | 1 | Negative |
| OpenAI Agents SDK, Python | 4 | Positive |
| OpenAI Agents SDK, TypeScript | 2 | Positive |
| Pydantic AI agents | 4 | Positive |
| smolagents agents | 2 | Positive |

## Annotation and freezing

The first annotation pass was performed by a separate AI-agent curator that did
not inspect this scanner's implementation, existing case contents, scanner
tests, prior review documents, or scanner outputs. The evaluator's schema was
read only to learn the file format. A sourcing subagent supplied conventional
utility candidates; the curator also read those complete files before including
them in the first pass.

Before any scanner observation, the curator wrote a neutral packet containing
only case IDs, complete source text, provenance, and the label rule. It omitted
the first pass's labels, families, descriptions, and label evidence. A separate
blind AI-agent reviewer labeled that packet. Both passes agreed on all 42 labels;
there were no ambiguous cases or disagreements requiring adjudication. The accompanying annotation ledger
must preserve both passes, the frozen corpus digest, and any adjudication;
scanner results are not a reason to change a label. The evaluator's adjudicated
corpus mode requires the reviewed annotation sidecar.

This is independent **AI-agent annotation relative to scanner implementation**,
not human annotation, third-party certification, or statistically independent
reviewers. The reviewers share model capabilities and may share biases.

The initial source packet SHA-256 is
`1a34734a7cb11d43ea5f4bb7ea3569aca247529208de0df51797a5b641f0519e`.
The initial corpus SHA-256 is
`128cf2c972cb13b11bafe141d584b910828899d689d5a457135ad7746f98eff3`.
These identify the initial selection and first-pass labels; the final annotation
ledger identifies the version actually evaluated.

## Attribution and limitations

`independent_provenance.json` maps repository commits to retained upstream
license texts in `independent_licenses/`. Files are distributed under their
upstream MIT, BSD-3-Clause, or Apache-2.0 licenses; copied source copyright
headers remain intact. Crossbeam is available under MIT OR Apache-2.0; this
corpus retains and uses its MIT option. The scanner project's license does not
replace the included upstream licenses.

This corpus deliberately tests semantic distinctions that can cause false
positives and includes explicit agent examples. It is not a random sample of
enterprise source estates or a measurement of shadow-agent prevalence. Several
cases share repositories, maintainers, SDKs, and implementation patterns. Case
counts therefore do not represent independent draws from a deployment
population. Report its confusion matrix, class counts, and uncertainty without
extrapolating field precision or recall. Keep failures visible; adding these
files to a regression suite does not make them a permanently held-out test set.
