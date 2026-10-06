"""Behavioural indicators that an LLM caller is an agent, from request metadata alone.

Gateway, proxy and flow logs rarely carry request bodies, so tool definitions
cannot always be seen. These checks read only what such logs keep: the
operation path, the host, the user agent and request times.

* **Hosted agent runtime operations**: the request invokes a managed agent
  (Amazon Bedrock ``InvokeAgent``, Bedrock AgentCore runtimes, the OpenAI and
  Azure Assistants API, Vertex AI Agent Engine, Dialogflow CX sessions).
* **MCP endpoints**: the request reaches a Model Context Protocol server
  (``/mcp`` streamable HTTP, or ``/sse`` on a known MCP host).
* **Agent-loop cadence**: several model calls follow each other within
  seconds, the model → tool → model shape of an agent working through a task.
  A batch script or a chat front end that makes several calls per message
  has the same shape, so callers decide how much weight it carries.

Nothing here inspects payloads, and no function raises on hostile input.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

# (label, framework signature id or None, compiled pattern over the path without its query string)
_AGENT_OPERATIONS: tuple[tuple[str, str | None, re.Pattern[str]], ...] = (
    (
        "Amazon Bedrock InvokeAgent",
        "cloud.aws-bedrock-agents",
        re.compile(r"/agents/[^/]+/agentAliases/[^/]+/sessions/[^/]+/text/?$"),
    ),
    (
        "Amazon Bedrock AgentCore runtime",
        "cloud.aws-bedrock-agents",
        re.compile(r"/runtimes/[^/]+/invocations/?$"),
    ),
    (
        "Assistants API run",
        None,
        re.compile(r"/threads/[^/]+/runs(?:/[^/]+)?(?:/submit_tool_outputs)?/?$|/threads/runs/?$"),
    ),
    ("Assistants API", None, re.compile(r"/assistants(?:/[^/]+)?/?$")),
    (
        "Vertex AI Agent Engine",
        "cloud.gcp-vertex-agent-engine",
        re.compile(r"/reasoningEngines/[^/:]+:(?:stream)?[qQ]uery$"),
    ),
    (
        "Dialogflow CX agent session",
        None,
        re.compile(
            r"/agents/[^/]+/(?:environments/[^/]+/)?sessions/[^/:]+:(?:detectIntent|streamingDetectIntent)$"
        ),
    ),
)
_MCP_PATH = re.compile(r"(?:^|/)mcp/?$", re.IGNORECASE)
_MCP_HOST_PATH = re.compile(r"(?:^|/)(?:sse|messages)/?$", re.IGNORECASE)
# Operations that are not a generation step of an agent loop.
_NON_GENERATION = re.compile(
    r"embed|moderation|rerank|tokeni[sz]e|count_tokens|/models/?$|/files\b|/batches\b|/audio/|/images/|"
    r"/fine[_-]?tun",
    re.IGNORECASE,
)
_BROWSER = re.compile(r"^Mozilla/5\.0 \(")
_AUTOMATION = re.compile(
    r"bot\b|crawler|spider|headless|python|curl|node|axios|okhttp|go-http", re.IGNORECASE
)

LOOP_MAX_GAP_SECONDS = 30.0
LOOP_MIN_CALLS = 3


@dataclass(frozen=True, slots=True)
class AgentOperation:
    label: str
    signature: str | None
    requests: int


def agent_operations(paths: Mapping[str, int]) -> list[AgentOperation]:
    """Hosted agent runtime operations among request paths, with request counts."""
    counts: Counter[tuple[str, str | None]] = Counter()
    for path, n in paths.items():
        bare = str(path).split("?", 1)[0]
        for label, signature, pattern in _AGENT_OPERATIONS:
            if pattern.search(bare):
                counts[(label, signature)] += int(n)
                break
    return [AgentOperation(label, sig, n) for (label, sig), n in counts.most_common()]


def is_mcp_request(path: str | None, mcp_host: bool) -> bool:
    """Whether a request reaches an MCP endpoint.

    ``/mcp`` is the conventional streamable HTTP endpoint on any host;
    ``/sse`` and ``/messages`` are generic names, so they count only on a host
    a signature identifies as an MCP server.
    """
    bare = str(path or "").split("?", 1)[0]
    if _MCP_PATH.search(bare):
        return True
    return mcp_host and bool(_MCP_HOST_PATH.search(bare))


def is_generation(path: str | None, model: str | None = None) -> bool:
    """Whether a request is a model generation step (not embeddings, listing or file handling)."""
    return not (_NON_GENERATION.search(str(path or "")) or _NON_GENERATION.search(str(model or "")))


def is_browser_user_agent(user_agent: str | None) -> bool:
    """A desktop or mobile browser, as opposed to an SDK, CLI or headless client."""
    ua = str(user_agent or "")
    return bool(_BROWSER.match(ua)) and not _AUTOMATION.search(ua)


@dataclass(frozen=True, slots=True)
class LoopCadence:
    loops: int  # runs of at least LOOP_MIN_CALLS calls
    longest: int  # calls in the longest run
    calls_in_loops: int
    calls: int  # timestamped generation calls examined

    @property
    def share(self) -> float:
        return self.calls_in_loops / self.calls if self.calls else 0.0


def loop_cadence(
    times: Iterable[float],
    *,
    max_gap: float = LOOP_MAX_GAP_SECONDS,
    min_calls: int = LOOP_MIN_CALLS,
) -> LoopCadence:
    """Runs of consecutive calls no more than ``max_gap`` seconds apart.

    ``times`` are POSIX timestamps in any order. A run counts as a loop when
    it holds at least ``min_calls`` calls. Calls at the same instant are fan-out
    or duplicated log lines, not sequential steps of a loop, so each distinct
    time counts once.
    """
    ordered = sorted({t for t in times if t == t})  # distinct, without NaN
    loops = longest = in_loops = 0
    run = 0
    previous: float | None = None
    for t in ordered:
        run = run + 1 if previous is not None and t - previous <= max_gap else 1
        previous = t
        if run == min_calls:
            loops += 1
            in_loops += min_calls
        elif run > min_calls:
            in_loops += 1
        longest = max(longest, run)
    return LoopCadence(loops, longest if loops else 0, in_loops, len(ordered))
