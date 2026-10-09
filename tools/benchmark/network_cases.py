"""Network egress case families.

A case is a short window of connection records from one workstation or
service: background traffic plus, for positives, AI traffic. Each record has
the union of fields that proxy logs, gateway logs and flow sensors expose; an
adapter converts the records into the format its tool ingests.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from tools.benchmark.common import DEPARTMENTS, GEMINI_MODELS, USERS, Draft, Rand

BASE_TIME = datetime(2026, 9, 29, 8, 0, tzinfo=UTC)

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
)

# (host, path, method, process, user_agent, programmatic)
BACKGROUND: tuple[tuple[str, str, str, str, str, bool], ...] = (
    ("github.com", "/acme/web/pull/412", "GET", "chrome", "browser", False),
    ("api.github.com", "/repos/acme/web/pulls", "GET", "gh", "GitHub CLI 2.60.1", True),
    ("registry.npmjs.org", "/react", "GET", "node", "npm/10.8.2 node/v22.9.0 linux x64", True),
    ("pypi.org", "/simple/requests/", "GET", "pip", "pip/24.2 {\"python\":\"3.12.6\"}", True),
    ("files.pythonhosted.org", "/packages/requests-2.32.3-py3-none-any.whl", "GET", "pip", "pip/24.2", True),
    ("slack.com", "/api/conversations.history", "POST", "slack", "Slack/4.40.128 Electron", True),
    ("zoom.us", "/wc/join/81234567890", "GET", "chrome", "browser", False),
    ("acme-assets.s3.amazonaws.com", "/reports/q3.pdf", "GET", "aws", "aws-cli/2.17.50 Python/3.12.6", True),
    ("www.googleapis.com", "/drive/v3/files", "GET", "chrome", "browser", False),
    ("login.microsoftonline.com", "/common/oauth2/v2.0/token", "POST", "teams", "Microsoft Teams 24215", True),
    ("outlook.office365.com", "/owa/", "GET", "chrome", "browser", False),
    ("api.stripe.com", "/v1/charges", "POST", "python3", "Stripe/v1 PythonBindings/10.12.0", True),
    ("o450123.ingest.sentry.io", "/api/12/envelope/", "POST", "node", "sentry.javascript.node/8.33.1", True),
    ("browser-intake-datadoghq.com", "/api/v2/rum", "POST", "chrome", "browser", False),
    ("www.youtube.com", "/watch", "GET", "chrome", "browser", False),
    ("en.wikipedia.org", "/wiki/Bayesian_inference", "GET", "firefox", "browser", False),
    ("docs.python.org", "/3/library/asyncio.html", "GET", "chrome", "browser", False),
    ("hub.docker.com", "/v2/repositories/library/postgres/tags", "GET", "docker", "docker/27.3.1", True),
)  # fmt: skip


class Window:
    """Builds the flow records of one case."""

    def __init__(self, rd: Rand) -> None:
        self.rd = rd
        self.user = rd.choice(USERS)
        self.department = rd.choice(DEPARTMENTS)
        self.src_ip = f"10.{rd.randint(1, 40)}.{rd.randint(0, 255)}.{rd.randint(2, 250)}"
        self.start = BASE_TIME + timedelta(days=rd.randint(0, 4), minutes=rd.randint(0, 600))
        self.span_s = rd.randint(1800, 8 * 3600)
        self.flows: list[dict[str, Any]] = []
        self.browser = rd.choice(BROWSER_UA)

    def add(
        self,
        host: str,
        path: str,
        method: str,
        process: str,
        ua: str,
        programmatic: bool,
        *,
        dst_ip: str | None = None,
        port: int = 443,
        out_range: tuple[int, int] = (300, 4000),
        in_range: tuple[int, int] = (500, 60000),
        dur_range: tuple[int, int] = (40, 1500),
        at: float | None = None,
        status: int = 200,
    ) -> None:
        rd = self.rd
        offset = at if at is not None else rd.random() * self.span_s
        bytes_out = rd.randint(*out_range)
        bytes_in = rd.randint(*in_range)
        self.flows.append(
            {
                "ts": (self.start + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"),
                "src_ip": self.src_ip,
                "user": self.user,
                "department": self.department,
                "process": process,
                "pid": rd.randint(300, 65000),
                "host": host,
                "dst_ip": dst_ip
                or f"{rd.randint(13, 199)}.{rd.randint(0, 255)}.{rd.randint(0, 255)}.{rd.randint(1, 254)}",
                "port": port,
                "scheme": "http" if port in (80, 11434, 8000) else "https",
                "method": method,
                "path": path,
                "status": status,
                "user_agent": self.browser if ua == "browser" else ua,
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "packets_out": max(1, bytes_out // rd.randint(500, 1400)),
                "packets_in": max(1, bytes_in // rd.randint(300, 1400)),
                "duration_ms": rd.randint(*dur_range),
                "programmatic": programmatic,
            }
        )

    def background(self, lo: int = 8, hi: int = 26) -> None:
        for host, path, method, proc, ua, prog in (
            self.rd.choice(BACKGROUND) for _ in range(self.rd.randint(lo, hi))
        ):
            self.add(host, path, method, proc, ua, prog)

    def burst(
        self,
        n: int,
        host: str,
        path: str,
        process: str,
        ua: str,
        *,
        port: int = 443,
        dst_ip: str | None = None,
        method: str = "POST",
    ) -> None:
        """Back-to-back programmatic model calls, the shape of an agent loop."""
        t0 = self.rd.random() * self.span_s * 0.8
        for i in range(n):
            self.add(
                host,
                path,
                method,
                process,
                ua,
                True,
                port=port,
                dst_ip=dst_ip,
                out_range=(1500, 30000),
                in_range=(800, 24000),
                dur_range=(1200, 45000),
                at=t0 + i * self.rd.randint(2, 20),
            )

    def done(self) -> list[dict[str, Any]]:
        return sorted(self.flows, key=lambda f: f["ts"])


def _sdk_ua(rd: Rand, lang: str, vendor: str) -> str:
    if vendor == "openai":
        return (
            f"OpenAI/Python 1.{rd.randint(40, 99)}.0"
            if lang == "py"
            else f"OpenAI/JS 4.{rd.randint(60, 99)}.0"
        )
    return (
        f"anthropic-python/0.{rd.randint(30, 70)}.0"
        if lang == "py"
        else f"anthropic-typescript/0.{rd.randint(30, 60)}.0"
    )


# --------------------------------------------------------------------------
# agent positives


def net_openai_loop(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    lang = rd.choice(("py", "js"))
    path = rd.choice(("/v1/chat/completions", "/v1/responses"))
    w.burst(
        rd.randint(4, 18),
        "api.openai.com",
        path,
        "python3" if lang == "py" else "node",
        _sdk_ua(rd, lang, "openai"),
    )
    return Draft(
        "net-agent-openai-loop",
        "agent",
        "easy",
        f"Programmatic burst of OpenAI {path} calls.",
        flows=w.done(),
    )


def net_anthropic_loop(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    if rd.chance(0.5):
        proc, ua = "claude", f"claude-cli/2.{rd.randint(0, 9)}.{rd.randint(0, 40)} (external, cli)"
    else:
        lang = rd.choice(("py", "js"))
        proc, ua = ("python3" if lang == "py" else "node"), _sdk_ua(rd, lang, "anthropic")
    w.burst(rd.randint(4, 18), "api.anthropic.com", "/v1/messages", proc, ua)
    return Draft(
        "net-agent-anthropic-loop",
        "agent",
        "easy",
        "Programmatic burst of Anthropic Messages calls.",
        flows=w.done(),
    )


def net_bedrock(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    region = rd.choice(("us-east-1", "us-west-2", "eu-central-1"))
    ua = f"Boto3/1.35.{rd.randint(0, 40)} md/Botocore#1.35.{rd.randint(0, 40)} ua/2.0 os/linux lang/python#3.12.6"
    if rd.chance(0.5):
        model = "anthropic.claude-3-5-sonnet-20240620-v1:0"
        w.burst(
            rd.randint(3, 12),
            f"bedrock-runtime.{region}.amazonaws.com",
            f"/model/{model}/converse",
            "python3",
            ua,
        )
    else:
        agent_id = rd.hexid(10).upper()
        path = f"/agents/{agent_id}/agentAliases/TSTALIASID/sessions/{rd.hexid(16)}/text"
        w.burst(rd.randint(2, 8), f"bedrock-agent-runtime.{region}.amazonaws.com", path, "python3", ua)
    return Draft(
        "net-agent-bedrock", "agent", "medium", "AWS Bedrock runtime or InvokeAgent traffic.", flows=w.done()
    )


def net_azure_openai(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    res = rd.ident().replace("_", "-")
    dep = rd.choice(("gpt4o-prod", "chat-mini", "assistant"))
    path = f"/openai/deployments/{dep}/chat/completions?api-version=2024-10-21"
    w.burst(
        rd.randint(3, 14),
        f"{res}.openai.azure.com",
        path,
        "dotnet",
        "azsdk-net-AI.OpenAI/2.1.0 (.NET 8.0.8; Linux)",
    )
    return Draft(
        "net-agent-azure-openai", "agent", "medium", "Azure OpenAI deployment calls.", flows=w.done()
    )


def net_mcp_remote(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    proc = rd.choice(("cursor", "claude", "node", "code"))
    mcp_host, mcp_path = rd.choice(
        (
            ("mcp.linear.app", "/sse"),
            ("mcp.sentry.dev", "/mcp"),
            ("mcp.atlassian.com", "/v1/sse"),
            ("api.githubcopilot.com", "/mcp/"),
        )
    )
    for _ in range(rd.randint(2, 6)):
        w.add(mcp_host, mcp_path, "POST", proc, "node", True, dur_range=(5000, 600000))
    if rd.chance(0.6):
        w.burst(rd.randint(2, 8), "api.anthropic.com", "/v1/messages", proc, _sdk_ua(rd, "js", "anthropic"))
    return Draft(
        "net-agent-mcp-remote",
        "agent",
        "hard",
        "Remote MCP server sessions from an AI client.",
        flows=w.done(),
    )


def net_openrouter(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    ua = rd.choice(("aider/0.86.1", "OpenAI/Python 1.51.0", "python-httpx/0.27.2"))
    w.burst(rd.randint(4, 14), "openrouter.ai", "/api/v1/chat/completions", "python3", ua)
    return Draft(
        "net-agent-openrouter", "agent", "medium", "OpenRouter chat-completions loop.", flows=w.done()
    )


def net_local_vllm(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    ip = f"10.{rd.randint(50, 60)}.{rd.randint(0, 255)}.{rd.randint(2, 250)}"
    w.burst(
        rd.randint(4, 16),
        ip,
        "/v1/chat/completions",
        "python3",
        f"OpenAI/Python 1.{rd.randint(40, 99)}.0",
        port=8000,
        dst_ip=ip,
    )
    return Draft(
        "net-agent-local-vllm",
        "agent",
        "hard",
        "Self-hosted OpenAI-compatible server on a private address.",
        flows=w.done(),
    )


def net_gemini_api(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    model = rd.choice(GEMINI_MODELS)
    w.burst(
        rd.randint(3, 12),
        "generativelanguage.googleapis.com",
        f"/v1beta/models/{model}:generateContent",
        "python3",
        "google-genai-sdk/1.38.0 gl-python/3.12.6",
    )
    return Draft("net-agent-gemini-api", "agent", "easy", "Gemini API calls from a script.", flows=w.done())


def net_openclaw(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    w.burst(
        rd.randint(3, 10), "api.anthropic.com", "/v1/messages", "openclaw", _sdk_ua(rd, "js", "anthropic")
    )
    for _ in range(rd.randint(2, 6)):
        w.add(
            "api.telegram.org",
            f"/bot{rd.randint(10**8, 10**9)}:redacted/getUpdates",
            "POST",
            "openclaw",
            "node",
            True,
        )
    return Draft(
        "net-agent-openclaw",
        "agent",
        "medium",
        "OpenClaw gateway calling a model and a chat channel.",
        flows=w.done(),
    )


# --------------------------------------------------------------------------
# LLM-only positives


def net_consumer_web(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    host, path = rd.choice(
        (
            ("chatgpt.com", "/backend-api/conversation"),
            ("claude.ai", "/api/organizations/x/chat_conversations"),
            ("gemini.google.com", "/app"),
            ("www.perplexity.ai", "/search"),
            ("copilot.microsoft.com", "/c/api/conversations"),
        )
    )
    for _ in range(rd.randint(1, 5)):
        w.add(host, path, rd.choice(("GET", "POST")), rd.choice(("chrome", "firefox")), "browser", False)
    return Draft(
        "net-llm-consumer-web", "llm", "easy", "Browser use of a consumer AI chat site.", flows=w.done()
    )


def net_single_api(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    host, path = rd.choice(
        (
            ("api.mistral.ai", "/v1/chat/completions"),
            ("api.groq.com", "/openai/v1/chat/completions"),
            ("api.together.xyz", "/v1/chat/completions"),
            ("api.deepseek.com", "/chat/completions"),
            ("api.cohere.com", "/v2/chat"),
        )
    )
    for _ in range(rd.randint(1, 2)):
        w.add(host, path, "POST", "python3", "python-requests/2.32.3", True, out_range=(400, 6000))
    return Draft(
        "net-llm-single-api", "llm", "medium", "One or two calls to an LLM inference API.", flows=w.done()
    )


def net_ollama_local(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    for _ in range(rd.randint(1, 4)):
        w.add(
            "127.0.0.1",
            "/api/chat",
            "POST",
            "python3",
            "ollama-python/0.4.4",
            True,
            port=11434,
            dst_ip="127.0.0.1",
        )
    return Draft(
        "net-llm-ollama-local", "llm", "hard", "Loopback calls to a local Ollama server.", flows=w.done()
    )


# --------------------------------------------------------------------------
# negatives


def net_plain(rd: Rand) -> Draft:
    w = Window(rd)
    w.background(12, 30)
    return Draft("net-neg-plain", "none", "easy", "Ordinary SaaS and developer traffic.", flows=w.done())


def net_gemini_exchange(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    for _ in range(rd.randint(3, 12)):
        w.add("api.gemini.com", "/v1/pubticker/btcusd", "GET", "python3", "python-requests/2.32.3", True)
    return Draft(
        "net-neg-gemini-exchange", "none", "hard", "Gemini crypto-exchange API polling.", flows=w.done()
    )


def net_lookalike_hosts(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    for host, path in rd.sample(
        (
            ("www.anthropologie.com", "/new-clothes"),
            ("api.openaire.eu", "/search/publications"),
            ("geo.hivebedrock.network", "/"),
            ("www.claude-monet.org", "/water-lilies"),
            ("llamas.example-farm.org", "/visit"),
        ),
        rd.randint(1, 3),
    ):
        w.add(host, path, "GET", "chrome", "browser", False)
    return Draft(
        "net-neg-lookalike-hosts", "none", "hard", "Hosts whose names resemble AI vendors.", flows=w.done()
    )


def net_streaming(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    for _ in range(rd.randint(3, 10)):
        w.add(
            "stream.binance.com",
            "/ws/btcusdt@trade",
            "GET",
            "python3",
            "Python/3.12 websockets/13.1",
            True,
            out_range=(300, 1200),
            in_range=(40000, 900000),
            dur_range=(30000, 900000),
        )
    return Draft(
        "net-neg-streaming",
        "none",
        "hard",
        "Long-lived programmatic streams shaped like LLM streaming.",
        flows=w.done(),
    )


def net_agent_ua(rd: Rand) -> Draft:
    w = Window(rd)
    w.background()
    for _ in range(rd.randint(3, 10)):
        w.add(
            "agent-intake.logs.datadoghq.com", "/api/v2/logs", "POST", "agent", "datadog-agent/7.58.0", True
        )
    return Draft("net-neg-agent-ua", "none", "medium", "Monitoring agent telemetry.", flows=w.done())


NET_AGENT: tuple[Callable[[Rand], Draft], ...] = (
    net_openai_loop, net_anthropic_loop, net_bedrock, net_azure_openai, net_mcp_remote, net_openrouter,
    net_local_vllm, net_gemini_api, net_openclaw,
)  # fmt: skip
NET_LLM: tuple[Callable[[Rand], Draft], ...] = (net_consumer_web, net_single_api, net_ollama_local)
NET_NEG: tuple[Callable[[Rand], Draft], ...] = (
    net_plain,
    net_gemini_exchange,
    net_lookalike_hosts,
    net_streaming,
    net_agent_ua,
)
