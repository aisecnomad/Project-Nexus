import os
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langgraph.graph import StateGraph, MessagesState
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from langchain_community.tools.tavily_search import TavilySearchResults
from langchain_experimental.tools import PythonREPLTool

SYSTEM_PROMPT = "You are an autonomous research agent. Plan, search and write reports without asking."

llm = ChatOpenAI(model="gpt-4o", api_key=os.environ["OPENAI_API_KEY"])
tools = [TavilySearchResults(max_results=5), PythonREPLTool()]
agent = create_react_agent(llm, tools, checkpointer=MemorySaver())

def run(task: str):
    return agent.invoke({"messages": [("system", SYSTEM_PROMPT), ("user", task)]},
                        config={"configurable": {"thread_id": "1"}, "recursion_limit": 50})
