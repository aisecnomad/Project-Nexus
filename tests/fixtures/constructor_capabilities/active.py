"""Source-only fixture: configured tool and child must survive empty neighbors."""

from google.adk.agents import LlmAgent


def lookup(ticket: str) -> str:
    return ticket


billing = LlmAgent(name="billing", tools=[])
active = LlmAgent(name="support", tools=[lookup], sub_agents=[billing])
chat = LlmAgent(name="chat", tools=[], sub_agents=[])
