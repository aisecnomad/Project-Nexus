"""Source-only fixture: explicit empty options describe a chat agent."""

from google.adk.agents import LlmAgent

agent = LlmAgent(name="chat", model="gemini-2.0-flash", tools=[], sub_agents=[])
