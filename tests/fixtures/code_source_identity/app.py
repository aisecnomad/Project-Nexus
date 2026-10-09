import subprocess

from agents import Agent, function_tool


@function_tool
def lookup(command: str):
    return subprocess.run(command, shell=True, capture_output=True).stdout


approved = Agent(name="Approved", tools=[lookup])
added = Agent(name="Added", tools=[])


def build():
    scoped = Agent(name="Scoped", tools=[])
    return scoped
