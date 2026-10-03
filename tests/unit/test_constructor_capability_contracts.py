"""Observed capabilities must follow SDK options, not a framework's feature list.

These are source-only scanner inputs; no agent SDK is installed or executed.
The constructor contracts are linked from docs/connectors/code.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.models import Kind
from shadowscan.risk import assess


def _scan(tmp_path, run_connector, source, suffix=".py"):
    (tmp_path / f"app{suffix}").write_text(source)
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False
    )
    assert not context.stats.incomplete, context.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


@pytest.mark.parametrize("value", ["[]", "None", "unknown", "load_tools()"])
@pytest.mark.parametrize(
    "source",
    [
        'from google.adk.agents import LlmAgent\na = LlmAgent(name="chat", tools=VALUE, sub_agents=VALUE)\n',
        "from strands import Agent\na = Agent(tools=VALUE)\n",
        'from autogen_agentchat.agents import AssistantAgent\na = AssistantAgent("chat", model_client=client, tools=VALUE, handoffs=VALUE)\n',
        "from llama_index.core.agent.workflow import FunctionAgent\na = FunctionAgent(tools=VALUE)\n",
        "from semantic_kernel.agents import ChatCompletionAgent\na = ChatCompletionAgent(plugins=VALUE)\n",
    ],
)
def test_empty_or_unknown_constructor_collections_are_potential(tmp_path, run_connector, source, value):
    finding = _scan(tmp_path, run_connector, source.replace("VALUE", value))
    assert finding.kind == Kind.AGENT
    assert finding.capabilities == []
    assert "tool-use" in finding.metadata["potential_capabilities"]
    assert not any(factor.id.startswith("capability:") for factor in assess(finding).factors)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'from google.adk.agents import LlmAgent\na = LlmAgent(name="chat", tools=[lookup], sub_agents=[billing])\n',
            {"tool-use", "multi-agent"},
        ),
        (
            'from google.adk.agents import SequentialAgent\na = SequentialAgent(name="chain", sub_agents=[billing])\n',
            {"multi-agent"},
        ),
        ("from strands import Agent\na = Agent(tools=[lookup])\n", {"tool-use"}),
        ("from strands import Agent\na = Agent(None, None, [lookup])\n", {"tool-use"}),
        ("from strands.multiagent import Swarm\na = Swarm(nodes=[billing, support])\n", {"multi-agent"}),
        ("from strands.multiagent import Swarm\na = Swarm([billing, support])\n", {"multi-agent"}),
        (
            'from autogen_agentchat.agents import AssistantAgent\na = AssistantAgent("chat", model_client=client, tools=[lookup], handoffs=[billing])\n',
            {"tool-use", "multi-agent"},
        ),
        (
            "from autogen_agentchat.teams import RoundRobinGroupChat\na = RoundRobinGroupChat([billing, support])\n",
            {"multi-agent"},
        ),
        (
            "from autogen_agentchat.teams import Swarm\na = Swarm(participants=[billing, support])\n",
            {"multi-agent"},
        ),
        (
            "from llama_index.core.agent.workflow import FunctionAgent\na = FunctionAgent(tools=[lookup])\n",
            {"tool-use"},
        ),
        (
            'from llama_index.core.agent.workflow import FunctionAgent\na = FunctionAgent("chat", "description", None, [lookup])\n',
            {"tool-use"},
        ),
        (
            "from llama_index.core.agent import ReActAgent\na = ReActAgent.from_tools([lookup])\n",
            {"tool-use"},
        ),
        (
            "from llama_index.core.agent.workflow import AgentWorkflow\na = AgentWorkflow([billing, support])\n",
            {"multi-agent"},
        ),
        (
            "from semantic_kernel.agents import ChatCompletionAgent\na = ChatCompletionAgent(plugins=[lookup])\n",
            {"tool-use"},
        ),
    ],
)
def test_enabled_constructor_options_preserve_supported_capabilities(
    tmp_path, run_connector, source, expected
):
    finding = _scan(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT
    assert set(finding.capabilities) == expected


@pytest.mark.parametrize("participants", ["[]", "[billing]", "unknown"])
@pytest.mark.parametrize(
    "source",
    [
        "from strands.multiagent import Swarm\na = Swarm(nodes=VALUE)\n",
        "from autogen_agentchat.teams import RoundRobinGroupChat\na = RoundRobinGroupChat(VALUE)\n",
        "from llama_index.core.agent.workflow import AgentWorkflow\na = AgentWorkflow(VALUE)\n",
    ],
)
def test_single_or_unknown_participant_cannot_establish_multiple_agents(
    tmp_path, run_connector, source, participants
):
    finding = _scan(tmp_path, run_connector, source.replace("VALUE", participants))
    assert finding.kind == Kind.AGENT
    assert "multi-agent" not in finding.capabilities


def test_empty_graph_builder_does_not_establish_participants(tmp_path, run_connector):
    finding = _scan(
        tmp_path, run_connector, "from strands.multiagent import GraphBuilder\na = GraphBuilder()\n"
    )
    assert not finding.capabilities


@pytest.mark.parametrize("config", ["False", "None", "unknown", "load_config()"])
def test_disabled_or_unknown_legacy_code_execution_is_unscored(tmp_path, run_connector, config):
    finding = _scan(
        tmp_path,
        run_connector,
        f'from autogen import ConversableAgent\na = ConversableAgent("chat", code_execution_config={config})\n',
    )
    assert finding.kind == Kind.AGENT
    assert not finding.capabilities


def test_empty_legacy_execution_dictionary_explicitly_enables_execution(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'from autogen import ConversableAgent\na = ConversableAgent("chat", code_execution_config={}, human_input_mode="NEVER")\n',
    )
    assert set(finding.capabilities) == {"code-exec", "autonomous"}


@pytest.mark.parametrize("options", ["tools=[lookup], **options", "tools=unknown, sub_agents=[]"])
def test_adk_ambiguous_options_do_not_reappear_as_lexical_capabilities(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        f'from google.adk.agents import LlmAgent\na = LlmAgent(name="chat", {options})\n',
    )
    assert finding.capabilities == []


@pytest.mark.parametrize("reverse", [False, True])
def test_adk_empty_agent_does_not_erase_independent_positive_configuration(tmp_path, run_connector, reverse):
    calls = [
        'a = LlmAgent(name="active", tools=[lookup], sub_agents=[billing])',
        'b = LlmAgent(name="chat", tools=[], sub_agents=[])',
    ]
    finding = _scan(
        tmp_path,
        run_connector,
        "from google.adk.agents import LlmAgent\n" + "\n".join(calls[:: -1 if reverse else 1]),
    )
    assert set(finding.capabilities) == {"tool-use", "multi-agent"}


@pytest.mark.parametrize("code", ["sub_agents = []", "supervisor = None", "max_steps = 0", "handoff = False"])
def test_planning_vocabulary_alone_does_not_establish_autonomy(tmp_path, run_connector, code):
    finding = _scan(
        tmp_path, run_connector, 'from agents import Agent\na = Agent(name="chat", tools=[])\n' + code
    )
    assert finding.kind == Kind.AGENT
    assert "autonomous" not in finding.capabilities


def test_explicit_semantic_kernel_behavior_remains_unknown(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from semantic_kernel.agents import ChatCompletionAgent\na = ChatCompletionAgent(plugins=[lookup], function_choice_behavior=behavior)\n",
    )
    assert "tool-use" not in finding.capabilities


def test_empty_adk_configuration_does_not_add_risk_points(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'from google.adk.agents import LlmAgent\na = LlmAgent(name="chat", tools=[], sub_agents=[])\n',
    )
    assert finding.capabilities == []
    assert assess(finding).score == 25


@pytest.mark.parametrize(
    "source",
    [
        "from strands import Agent\na = Agent(*prefix, None, [lookup])\n",
        'from llama_index.core.agent.workflow import FunctionAgent\na = FunctionAgent(*prefix, "chat", None, [lookup])\n',
        "from langchain.agents import create_agent\na = create_agent(*prefix, [lookup])\n",
    ],
)
def test_starred_arguments_cannot_establish_a_later_positional_tool_list(tmp_path, run_connector, source):
    finding = _scan(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT
    assert not finding.capabilities


@pytest.mark.parametrize("target", ['"user"', '"billing"'])
def test_autogen_string_handoff_target_is_not_proof_of_another_ai_agent(tmp_path, run_connector, target):
    finding = _scan(
        tmp_path,
        run_connector,
        f'from autogen_agentchat.agents import AssistantAgent\na = AssistantAgent("chat", model_client=client, handoffs=[{target}])\n',
    )
    assert "multi-agent" not in finding.capabilities


def test_semantic_kernel_arguments_may_override_plugin_invocation(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from semantic_kernel.agents import ChatCompletionAgent\na = ChatCompletionAgent(plugins=[lookup], arguments=settings)\n",
    )
    assert "tool-use" not in finding.capabilities


@pytest.mark.parametrize(
    "options",
    ["tools: [], subAgents: []", "tools: unknown, subAgents: unknown", "tools: [lookup], ...options"],
)
def test_javascript_adk_empty_or_unknown_options_are_unscored(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        "import { LlmAgent } from '@google/adk';\n"
        + f"const agent = new LlmAgent({{name: 'chat', {options}}});\n",
        ".ts",
    )
    assert finding.kind == Kind.AGENT
    assert not finding.capabilities


def test_javascript_adk_explicit_tool_and_child_are_preserved(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "import { LlmAgent } from '@google/adk';\nconst agent = new LlmAgent({name: 'chat', tools: [lookup], subAgents: [billing]});\n",
        ".ts",
    )
    assert set(finding.capabilities) == {"tool-use", "multi-agent"}


def test_autogen_concrete_code_executor_retains_inherent_execution(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'from autogen_agentchat.agents import CodeExecutorAgent\na = CodeExecutorAgent("runner", code_executor=executor)\n',
    )
    assert finding.kind == Kind.AGENT
    assert "code-exec" in finding.capabilities


@pytest.mark.parametrize(
    ("fixture", "expected"), [("empty.py", set()), ("active.py", {"tool-use", "multi-agent"})]
)
def test_offline_adk_constructor_fixtures(tmp_path, run_connector, fixture, expected):
    source = Path(__file__).parents[1] / "fixtures" / "constructor_capabilities" / fixture
    finding = _scan(tmp_path, run_connector, source.read_text())
    assert finding.kind == Kind.AGENT
    assert set(finding.capabilities) == expected
