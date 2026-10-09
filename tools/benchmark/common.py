"""Shared case model and randomization helpers for the benchmark generator."""

from __future__ import annotations

import json
import random
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

SURFACES = ("repo", "endpoint", "network")
LABELS = ("agent", "llm", "none")
DIFFICULTIES = ("easy", "medium", "hard")

_PLACEHOLDER = re.compile(r"@@([a-z_][a-z0-9_]*)@@")


@dataclass
class Case:
    """One labeled input.

    ``label`` is ``agent`` (an autonomous or tool-using AI agent, or an agent
    integration such as a configured MCP server), ``llm`` (AI/LLM use without
    agent evidence) or ``none`` (no AI use; a hard or ordinary negative).
    Repository and endpoint cases carry ``files`` (relative path to text);
    network cases carry ``flows`` (one dict per observed connection).
    """

    case_id: str
    surface: str
    family: str
    label: str
    difficulty: str
    rationale: str
    files: dict[str, str] = field(default_factory=dict)
    flows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def positive(self) -> bool:
        return self.label != "none"

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.case_id,
            "surface": self.surface,
            "family": self.family,
            "label": self.label,
            "difficulty": self.difficulty,
            "rationale": self.rationale,
        }
        if self.files:
            out["files"] = dict(sorted(self.files.items()))
        if self.flows:
            out["flows"] = self.flows
        return out

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Case:
        return cls(
            case_id=data["id"],
            surface=data["surface"],
            family=data["family"],
            label=data["label"],
            difficulty=data["difficulty"],
            rationale=data["rationale"],
            files=dict(data.get("files", {})),
            flows=list(data.get("flows", [])),
        )


@dataclass
class Draft:
    """What a family template returns before the generator assigns an id."""

    family: str
    label: str
    difficulty: str
    rationale: str
    files: dict[str, str] = field(default_factory=dict)
    flows: list[dict[str, Any]] = field(default_factory=list)


def fill(template: str, **values: str) -> str:
    """Replace ``@@name@@`` placeholders; unknown names are an error."""

    def sub(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            raise KeyError(f"template placeholder {key!r} has no value")
        return values[key]

    return _PLACEHOLDER.sub(sub, template)


def dump_json(value: Any) -> str:
    return json.dumps(value, indent=2) + "\n"


WORDS = (
    "atlas", "beacon", "cedar", "delta", "ember", "falcon", "garnet", "harbor",
    "iris", "juniper", "kestrel", "lumen", "meridian", "nova", "orchid", "pioneer",
    "quartz", "raven", "sierra", "tundra", "umber", "vertex", "willow", "yarrow",
    "zephyr", "basalt", "cobalt", "dune", "fjord", "grove", "helix", "indigo",
)  # fmt: skip
DOMAINS = (
    "billing", "support", "research", "claims", "inventory", "hr", "finance",
    "sales", "security", "ops", "legal", "marketing", "procurement", "logistics",
)  # fmt: skip
USERS = (
    "alice", "bilal", "chen", "dana", "eitan", "fatima", "gopal", "hana", "ivan",
    "jules", "kofi", "lena", "mateo", "nadia", "omar", "priya", "quinn", "rosa",
    "sven", "tomoko", "uma", "victor", "wen", "ximena", "yusuf", "zoe",
)  # fmt: skip
DEPARTMENTS = ("engineering", "sales", "finance", "hr", "legal", "marketing", "support", "product")

OPENAI_MODELS = ("gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "gpt-5", "o4-mini")
ANTHROPIC_MODELS = ("claude-sonnet-4-5", "claude-opus-4-1", "claude-3-5-haiku-latest", "claude-haiku-4-5")
GEMINI_MODELS = ("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash")
OLLAMA_MODELS = ("llama3.1", "qwen2.5-coder", "mistral", "phi4", "gemma3")

TOOL_SPECS = (
    ("lookup_invoice", "Look up an invoice by its number.", "invoice_id"),
    ("search_tickets", "Search the support ticket index.", "query"),
    ("get_order_status", "Return the shipping status for an order.", "order_id"),
    ("query_warehouse", "Run a read-only query against the analytics warehouse.", "sql"),
    ("fetch_policy", "Fetch an internal policy document by title.", "title"),
    ("create_jira_issue", "Open a Jira issue in the team backlog.", "summary"),
    ("send_slack_message", "Post a message to a Slack channel.", "text"),
    ("read_customer_record", "Read a customer record from the CRM.", "customer_id"),
    ("run_shell", "Run a shell command on the build host.", "command"),
    ("list_open_prs", "List open pull requests for a repository.", "repo"),
    ("convert_currency", "Convert an amount between currencies.", "amount"),
    ("get_weather", "Get the weather forecast for a city.", "city"),
)  # fmt: skip


class Rand:
    """Thin wrapper over :class:`random.Random` with corpus-specific helpers."""

    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)

    def choice(self, seq: Sequence[Any]) -> Any:
        return self.r.choice(seq)

    def sample(self, seq: Sequence[Any], k: int) -> list[Any]:
        return self.r.sample(list(seq), k)

    def randint(self, a: int, b: int) -> int:
        return self.r.randint(a, b)

    def random(self) -> float:
        return self.r.random()

    def chance(self, p: float) -> bool:
        return self.r.random() < p

    def shuffle(self, seq: list[Any]) -> None:
        self.r.shuffle(seq)

    def name(self) -> str:
        return f"{self.choice(WORDS)}-{self.choice(DOMAINS)}"

    def ident(self) -> str:
        return f"{self.choice(WORDS)}_{self.choice(DOMAINS)}"

    def camel(self) -> str:
        return str(self.choice(WORDS)).capitalize() + str(self.choice(DOMAINS)).capitalize()

    def tools(self, k: int) -> list[tuple[str, str, str]]:
        return self.sample(TOOL_SPECS, k)

    def hexid(self, n: int) -> str:
        return "".join(self.choice("0123456789abcdef") for _ in range(n))

    def version(self) -> str:
        return f"{self.randint(0, 3)}.{self.randint(0, 40)}.{self.randint(0, 20)}"
