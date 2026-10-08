"""Behavioural indicators that an LLM caller is an agent, from request metadata alone.

Gateway, proxy and flow logs rarely carry request bodies, so tool definitions
cannot always be seen. These checks read only what such logs keep: the
operation path and HTTP method, the host, the user agent and request times.

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

from shadowscan.signatures import Match

# Execution paths are bound to the service that implements them. A path seen
# on another provider (or a local proxy with no upstream host) proves nothing.
_AWS_HOST = r"(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?"
_VERTEX_HOST = re.compile(r"(?:[a-z0-9-]+-)?aiplatform\.googleapis\.com")
_ASSISTANTS_RUN = r"/threads(?:/[^/]+/runs(?:/[^/]+/submit_tool_outputs)?|/runs)/?"
_AGENT_OPERATIONS: tuple[tuple[str, str | None, re.Pattern[str], re.Pattern[str]], ...] = (
    (
        "Amazon Bedrock InvokeAgent",
        "cloud.aws-bedrock-agents",
        re.compile(r"bedrock-agent-runtime" + _AWS_HOST),
        re.compile(r"/agents/[^/]+/agentAliases/[^/]+/sessions/[^/]+/text/?"),
    ),
    (
        "Amazon Bedrock AgentCore runtime",
        "cloud.aws-bedrock-agents",
        re.compile(r"bedrock-agentcore" + _AWS_HOST),
        re.compile(r"/runtimes/[^/]+/invocations/?"),
    ),
    (
        "Assistants API run",
        None,
        re.compile(r"api\.openai\.com"),
        re.compile(r"/v1" + _ASSISTANTS_RUN),
    ),
    (
        "Assistants API run",
        None,
        re.compile(r"\A[a-z0-9-]+\.openai\.azure\.(?:com|us|cn)\Z"),
        re.compile(r"/openai(?:/v1)?" + _ASSISTANTS_RUN),
    ),
    (
        "Vertex AI Agent Engine",
        "cloud.gcp-vertex-agent-engine",
        _VERTEX_HOST,
        re.compile(
            r"/v1(?:beta1)?/projects/[^/]+/locations/[^/]+/reasoningEngines/[^/:]+:(?:query|streamQuery)"
        ),
    ),
    (
        "Dialogflow CX agent session",
        None,
        re.compile(r"\A(?:[a-z0-9-]+-)?dialogflow\.googleapis\.com\Z"),
        re.compile(
            r"/v3(?:beta1)?/projects/[^/]+/locations/[^/]+/agents/[^/]+/"
            r"(?:environments/[^/]+/)?sessions/[^/:]+:(?:detectIntent|streamingDetectIntent)"
        ),
    ),
)
_VERTEX_EXECUTION = re.compile(
    r"google\.cloud\.aiplatform\.v1(?:beta1)?\.ReasoningEngineExecutionService\."
    r"(?:QueryReasoningEngine|StreamQueryReasoningEngine)"
)
_MCP_PATH = re.compile(r"(?:^|/)mcp/?$", re.IGNORECASE)
_MCP_HOST_PATH = re.compile(r"(?:^|/)(?:sse|messages)/?$", re.IGNORECASE)
# Operations that are not a generation step of an agent loop.
_NON_GENERATION = re.compile(
    r"embed|moderation|rerank|tokeni[sz]e|count_tokens|/models/?$|/files\b|/batches\b|/audio/|/images/|"
    r"/fine[_-]?tun|/(?:assistants|threads|runs|agents|runtimes|reasoningEngines)(?:/|$|:)",
    re.IGNORECASE,
)
_BROWSER = re.compile(r"^Mozilla/5\.0 \(")
_AUTOMATION = re.compile(
    r"bot\b|crawler|spider|headless|python|curl|node|axios|okhttp|go-http", re.IGNORECASE
)

# Which signature names a host's service when several match it with the same weight.
_SERVICE_ORDER = {
    "coding-agent": 0,
    "protocol": 1,
    "platform": 2,
    "framework": 3,
    "provider": 4,
    "identity-app": 5,
}

LOOP_MAX_GAP_SECONDS = 30.0
LOOP_MIN_CALLS = 3


def host_service(matches: Iterable[Match]) -> Match | None:
    """The signature a host belongs to: its highest-weight domain match.

    ``api.openai.com`` is OpenAI's model API (the ChatGPT app's ``*.openai.com``
    wildcard ties and loses to the provider); ``chatgpt.com`` is the ChatGPT
    app, not the lower-weight plugin protocol that also lists it.
    """
    return min(
        matches,
        key=lambda m: (-m.weight, _SERVICE_ORDER.get(m.signature.category, 9), m.signature.id),
        default=None,
    )


@dataclass(frozen=True, slots=True)
class AgentOperation:
    label: str
    signature: str | None
    requests: int


def agent_operations(
    paths: Mapping[str, int],
    *,
    method: str | None = None,
    host: str | None = None,
    schema: str | None = None,
) -> list[AgentOperation]:
    """Invocation requests supported by a method, exact execution path and service.

    Native Vertex audit RPC names identify the operation without an HTTP verb.
    Schema labels or free-form provider names alone never substitute for the
    destination service. Requests identify attempted invocation, not successful
    execution or tool use.
    """
    if method not in (None, "POST"):
        return []
    counts: Counter[tuple[str, str | None]] = Counter()
    destination = str(host or "").lower().removesuffix(":443").rstrip(".")
    for path, n in paths.items():
        bare = str(path).split("?", 1)[0]
        if schema == "vertex" and _VERTEX_HOST.fullmatch(destination) and _VERTEX_EXECUTION.fullmatch(bare):
            counts[("Vertex AI Agent Engine", "cloud.gcp-vertex-agent-engine")] += int(n)
        elif method == "POST":
            for label, signature, service, pattern in _AGENT_OPERATIONS:
                if service.fullmatch(destination) and pattern.fullmatch(bare):
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


def is_generation(path: str | None, model: str | None = None, method: str | None = None) -> bool:
    """Whether metadata supports a possible generation step for cadence analysis.

    Unknown or read-only HTTP operations never become model steps simply
    because they were sent to an AI provider. Native model records can carry
    a model without an HTTP path or method.
    """
    if method is not None and method != "POST":
        return False
    bare = str(path or "").split("?", 1)[0]
    if _NON_GENERATION.search(bare) or _NON_GENERATION.search(str(model or "")):
        return False
    if bare.startswith("/"):
        return method == "POST" and bool(
            re.fullmatch(
                r"(?:/v1|/openai/deployments/[^/]+)?/(?:chat/completions|completions|messages|responses)"
                r"|/api/(?:chat|generate)|/model/[^/]+/(?:invoke|invoke-with-response-stream|converse|converse-stream)"
                r"|/v1(?:beta1)?/projects/[^/]+/locations/[^/]+/publishers/[^/]+/models/[^/:]+:"
                r"(?:generateContent|streamGenerateContent)",
                bare.rstrip("/"),
            )
        )
    return bool(model) and (
        not bare
        or bare
        in {
            "completion",
            "acompletion",
            "InvokeModel",
            "Converse",
            "ConverseStream",
            "InvokeModelWithResponseStream",
        }
    )


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
