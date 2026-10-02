"""Conservative import-bound calls for Python and common JavaScript/TypeScript.

This is static evidence of construction, not execution. Python uses its AST;
JavaScript uses a bounded lexical resolver for imports and direct calls. Dynamic
imports, re-exports and uncertain/shadowed JavaScript bindings remain supporting
framework evidence. No scanned code is imported or executed.

Python AST work is capped at 50,000 nodes and source calls at 512 per file;
call expressions are bounded to 8 KiB. A Python file whose imports provably
cannot resolve to any signature skips the binder at any size, since it could
yield no evidence (``_python_bindable``, linear in the file and bounded to 4,096
statement matches). Regex operations share the scanner's per-input deadline.
Other source languages do not use this resolver: filesystem
classification requires matching import/dependency evidence for their lexical
framework signals, and caps uncorroborated code evidence at 0.6.
"""

from __future__ import annotations

import ast
import re
import threading
import weakref
from bisect import bisect_right
from collections import ChainMap
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field

import regex

from shadowscan.connectors.code.javascript_dispatch import javascript_responses_dispatch_lines
from shadowscan.connectors.code.langgraph_semantics import langgraph_agent_lines
from shadowscan.connectors.code.provider_loops import provider_tool_loop_lines
from shadowscan.connectors.code.responses_loops import responses_dispatch_lines, responses_tool_loop_lines
from shadowscan.connectors.code.source_capabilities import CallCapabilities, configured_capabilities
from shadowscan.connectors.code.vercel_tools import has_executable_vercel_tools, has_vercel_tool_loop
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import Signal, Signature
from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout, required_literals
from shadowscan.utils.redaction import sanitize_text

MAX_AST_NODES = 50_000
MAX_BOUND_CALLS = 512
MAX_CALL_TEXT = 8192
# Proving a file unbindable matches at most this many distinct synthesized
# statements (real modules need a few hundred), of which at most 512 name an
# attribute of an imported module; a file needing more keeps the binder.
_MAX_PROOF_MATCHES = 4096
_MAX_PROOF_STATEMENTS = 512


class SourceBudgetExceeded(MatchTimeoutError):
    """A file exceeded a structural analysis budget (AST nodes or nesting depth).

    Unlike a matching deadline, this is a property of the file itself: callers
    keep its lexical evidence and report the import-bound analysis as partial.
    """


@dataclass(frozen=True)
class _Binding:
    module: str
    symbol: str
    constructed: bool = False


@dataclass(frozen=True)
class _Call:
    binding: _Binding
    arguments: str
    line: int
    structural_arguments: str = ""
    node: ast.Call | None = None
    tool_factories: tuple[str, ...] = ()
    start: int = 0
    end: int = 0
    decorator: bool = False


@dataclass
class _LoopTransfers:
    scope_depth: int
    scope: dict[str, _Binding | None] | None = None
    has_break: bool = False


# These APIs construct agents even when their arguments have a different order
# from older lexical signatures. Names have meaning only after import binding.
_FACTORIES = {
    "framework.langchain": (
        r"(?:AgentExecutor|initialize_agent|create_\w*agent|createReactAgent|createToolCallingAgent)"
    ),
    # A StateGraph is an agent only with a static tool cycle (see
    # langgraph_semantics); bound_source_matches verifies it separately.
    "framework.langgraph": r"(?:create_react_agent|createReactAgent|create_supervisor|create_swarm)",
    "framework.llamaindex": (
        r"(?:ReActAgent|FunctionAgent|FunctionCallingAgent|OpenAIAgent|AgentWorkflow|"
        r"CodeActAgent|AgentRunner)(?:\.from_tools)?"
    ),
    "framework.crewai": r"(?:Agent|Crew)",
    "framework.google-adk": (
        r"(?:Agent|LlmAgent|SequentialAgent|ParallelAgent|LoopAgent|Runner|InMemoryRunner)"
    ),
    "framework.aws-strands": r"(?:Agent|GraphBuilder|Swarm)",
    "framework.microsoft-agent-framework": r"(?:ChatAgent|WorkflowBuilder|MagenticBuilder|HandoffBuilder)",
    "framework.semantic-kernel": (
        r"(?:ChatCompletionAgent|OpenAIAssistantAgent|AzureAIAgent|AgentGroupChat|BedrockAgent|"
        r"CopilotStudioAgent)"
    ),
    "framework.autogen": (
        r"(?:AssistantAgent|ConversableAgent|UserProxyAgent|RoundRobinGroupChat|SelectorGroupChat|"
        r"MagenticOneGroupChat|Swarm|GroupChatManager|CodeExecutorAgent)"
    ),
    "framework.smolagents": r"(?:CodeAgent|ToolCallingAgent|ManagedAgent)",
    "framework.transformers-agents": r"(?:ReactCodeAgent|ReactJsonAgent|HfAgent)",
    "framework.openai-agents-sdk": r"(?:Agent|Runner\.run(?:_sync|_streamed|Sync)?)",
    "framework.openai-swarm": r"(?:Agent|Swarm)",
    "framework.claude-agent-sdk": r"(?:ClaudeSDKClient|query)",
    "framework.pydantic-ai": r"Agent",
    "framework.vercel-ai-sdk": r"(?:ToolLoopAgent|Experimental_Agent|Agent)",
    "framework.mastra": r"(?:Agent|Mastra)",
    "framework.haystack": r"(?:Agent|ToolInvoker)",
    "framework.dspy": r"(?:ReAct|ProgramOfThought)",
    "framework.agno": r"(?:Agent|Team|AgentOS)",
    "framework.browser-use": r"Agent",
    "framework.nova-act": r"NovaAct",
    "framework.inngest-agentkit": r"(?:createAgent|createNetwork)",
    "framework.voltagent": r"(?:Agent|VoltAgent)",
    "framework.langroid": r"(?:ChatAgent|Task)",
    "framework.beeai": r"(?:ReActAgent|ToolCallingAgent|RequirementAgent)",
}


# A provider SDK request that offers the model tools lets the model choose
# actions. That is tool-use capability and provider attribution; only the
# dispatch/feedback loop recognized by ``provider_loops`` shows that the program
# executes what the model selected.
_TOOL_REQUEST_METHODS = re.compile(
    r"(?:^|\.)(?:create|stream|parse|converse|converse_stream|generate_content|generateContent|"
    r"send_message|chat)$"
)
_TOOL_ARGUMENTS = re.compile(r"(?<![\w$])(?:tools|toolConfig|functions|function_declarations)\s*[=:]")
# Import-bound request calls whose response shape the loop recognizer understands.
_LOOP_REQUESTS: dict[str, tuple[str, frozenset[str]]] = {
    # Plain, raw-response (``.parse()`` returns the message) and streaming
    # (``get_final_message()`` / ``get_final_completion()``) request forms.
    "openai": (
        "provider.openai",
        frozenset(
            {
                f"{client}.{api}chat.completions.{method}"
                for client in ("OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI")
                for api in ("", "beta.")
                for method in ("create", "with_raw_response.create", "stream")
            }
        ),
    ),
    "anthropic": (
        "provider.anthropic",
        frozenset(
            {
                f"{client}.{api}messages.{method}"
                for client in (
                    "Anthropic",
                    "AsyncAnthropic",
                    "AnthropicBedrock",
                    "AsyncAnthropicBedrock",
                    "AnthropicVertex",
                    "AsyncAnthropicVertex",
                )
                for api in ("", "beta.")
                for method in ("create", "with_raw_response.create", "stream")
            }
        ),
    ),
}
# Keyword arguments that evidence a specific capability of a bound construction.
_KEYWORD_CAPABILITIES: dict[str, tuple[tuple[str, str], ...]] = {
    "framework.openai-agents-sdk": (("handoffs", "multi-agent"),),
    "framework.langgraph": (("checkpointer", "memory"), ("store", "memory")),
}


def _symbol_tail(symbol: str) -> str:
    # Module paths may precede the exported class/function. Keep class methods.
    parts = symbol.split(".")
    return ".".join(parts[-2:]) if len(parts) > 1 and parts[-2][:1].isupper() else parts[-1]


class _PythonBindings(ast.NodeVisitor):
    def __init__(self, text: str, relevant: Callable[[_Binding], bool] | None = None):
        self.text = text
        # Only calls into modules that some signature describes can produce
        # evidence. Counting every bound call (``pytest.raises``, ``requests.get``)
        # against MAX_BOUND_CALLS made ordinary large files fail as incomplete.
        self.relevant = relevant
        self.lines = text.splitlines(keepends=True)
        self.offsets = [0]
        for line in self.lines:
            self.offsets.append(self.offsets[-1] + len(line))
        self.scopes: list[MutableMapping[str, _Binding | None]] = [{}]
        self.scope_kinds = ["module"]
        self.calls: list[_Call] = []
        self.imports: list[tuple[_Binding, int]] = []
        self._loop_transfers: list[_LoopTransfers] = []
        self.decorator_calls: set[int] = set()

    def _visit_block(self, statements: Sequence[ast.AST]) -> bool:
        """Visit a syntactic suite until an explicit, unconditional transfer.

        This only proves local reachability: return/raise/break/continue and
        constant or fully terminating if branches. Calls, exception handlers,
        context-manager suppression and interprocedural/global mutation timing
        are not assumed to establish that a surrounding suite terminates.
        """
        return any(self.visit(statement) is True for statement in statements)

    def generic_visit(self, node: ast.AST) -> None:
        # Generic constructs (notably try suites) keep their existing bounded
        # lexical traversal, but a return cannot make later statements in the
        # same suite into reachable construction evidence.
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                if value and all(isinstance(item, ast.stmt) for item in value):
                    self._visit_block(value)
                else:
                    for item in value:
                        if isinstance(item, ast.AST):
                            self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    @staticmethod
    def _join_scopes(*outcomes: Mapping[str, _Binding | None]) -> dict[str, _Binding | None]:
        """Keep a binding only when every possible lexical outcome agrees."""
        return {
            name: outcomes[0].get(name)
            if all(outcome.get(name) == outcomes[0].get(name) for outcome in outcomes[1:])
            else None
            for name in set().union(*outcomes)
        }

    def visit_Return(self, node: ast.Return) -> bool:
        if node.value is not None:
            self.visit(node.value)
        return True

    def visit_Raise(self, node: ast.Raise) -> bool:
        if node.exc is not None:
            self.visit(node.exc)
        if node.cause is not None:
            self.visit(node.cause)
        return True

    def visit_Break(self, node: ast.Break) -> bool:
        self._record_loop_transfer(is_break=True)
        return True

    def visit_Continue(self, node: ast.Continue) -> bool:
        self._record_loop_transfer(is_break=False)
        return True

    def _record_loop_transfer(self, *, is_break: bool) -> None:
        if self._loop_transfers and self._loop_transfers[-1].scope_depth == len(self.scopes):
            # A conditional break/continue may leave its branch before later
            # statements restore a binding. Keep that earlier mutation as a
            # possible loop outcome rather than letting visit_If discard it.
            # Merge in place: retain at most one transfer scope per loop,
            # rather than a full symbol table for every hostile break site.
            transfers = self._loop_transfers[-1]
            transfers.scope = (
                self._join_scopes(transfers.scope, self.scopes[-1])
                if transfers.scope is not None
                else dict(self.scopes[-1])
            )
            transfers.has_break |= is_break

    def _visit_loop_body(
        self, statements: list[ast.stmt]
    ) -> tuple[list[Mapping[str, _Binding | None]], bool]:
        transfers = _LoopTransfers(len(self.scopes))
        self._loop_transfers.append(transfers)
        try:
            self._visit_block(statements)
        finally:
            self._loop_transfers.pop()
        outcomes: list[Mapping[str, _Binding | None]] = [self.scopes[-1]]
        if transfers.scope is not None:
            outcomes.append(transfers.scope)
        return outcomes, transfers.has_break

    def _offset(self, line: int, column: int) -> int:
        # AST columns are UTF-8 bytes, not Unicode code points.
        content = self.lines[line - 1]
        return self.offsets[line - 1] + len(content.encode("utf-8")[:column].decode("utf-8", errors="ignore"))

    def _resolve(self, node: ast.AST) -> _Binding | None:
        if isinstance(node, ast.Name):
            for number in reversed(range(len(self.scopes))):
                # A class namespace is not an enclosing lexical scope for its
                # methods or comprehensions (unqualified names skip it).
                if number != len(self.scopes) - 1 and self.scope_kinds[number] == "class":
                    continue
                scope = self.scopes[number]
                if node.id in scope:
                    return scope[node.id]
        elif isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            if base:
                return _Binding(
                    base.module, ".".join(filter(None, (base.symbol, node.attr))), base.constructed
                )
        elif isinstance(node, ast.Call):
            binding = self._resolve(node.func)
            return _Binding(binding.module, binding.symbol, True) if binding else None
        elif isinstance(node, ast.Subscript):
            # Generic constructors retain their imported runtime identity:
            # Agent[Dependencies, Result](...) and aliased equivalents.
            return self._resolve(node.value)
        return None

    def _store(self, target: ast.AST, binding: _Binding | None = None) -> None:
        if isinstance(target, ast.Name):
            self.scopes[-1][target.id] = binding
        elif isinstance(target, (ast.List, ast.Tuple)):
            for element in target.elts:
                self._store(element)
        elif isinstance(target, ast.Starred):
            self._store(target.value)
        elif isinstance(target, ast.Attribute):
            # Mutating an imported namespace destroys proof of its members.
            root = target.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                self.scopes[-1][root.id] = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            binding = _Binding(alias.name if alias.asname else alias.name.split(".")[0], "")
            self.scopes[-1][alias.asname or alias.name.split(".")[0]] = binding
            self.imports.append((_Binding(alias.name, ""), node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            # Relative/star imports cannot identify a third-party library.
            if alias.name == "*":
                self.scopes[-1] = dict.fromkeys(self.scopes[-1])
                continue
            binding = (
                _Binding(node.module or "", alias.name) if not node.level and alias.name != "*" else None
            )
            self.scopes[-1][alias.asname or alias.name] = binding
            if binding:
                self.imports.append((binding, node.lineno))

    def visit_Call(self, node: ast.Call) -> None:
        binding = self._resolve(node.func)
        if binding and (self.relevant is None or self.relevant(binding)):
            if len(self.calls) >= MAX_BOUND_CALLS:
                raise SourceBudgetExceeded("source binding call limit exceeded")
            start = self._offset(node.func.end_lineno or node.lineno, node.func.end_col_offset or 0)
            end = self._offset(node.end_lineno or node.lineno, node.end_col_offset or 0)
            keywords = " ".join(f"{keyword.arg}=" for keyword in node.keywords if keyword.arg)
            self.calls.append(
                _Call(
                    binding,
                    self.text[start : min(end, start + MAX_CALL_TEXT)],
                    node.lineno,
                    keywords,
                    node=node,
                    start=self._offset(node.lineno, node.col_offset),
                    end=end,
                    decorator=id(node) in self.decorator_calls,
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        binding = self._resolve(node.value)
        for target in node.targets:
            self._store(target, binding)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self.visit(node.value)
        self._store(node.target, self._resolve(node.value) if node.value else None)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._store(node.target, self._resolve(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._store(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._store(target)

    def _decorator(self, node: ast.expr) -> None:
        if isinstance(node, ast.Call):
            self.decorator_calls.add(id(node))
            self.visit(node)
            self.decorator_calls.remove(id(node))
            return
        binding = self._resolve(node)
        if (
            binding
            and binding.constructed
            and (binding.module == "pydantic_ai" or binding.module.startswith("pydantic_ai."))
            and _symbol_tail(binding.symbol) in {"Agent.tool", "Agent.tool_plain"}
            and (self.relevant is None or self.relevant(binding))
        ):
            if len(self.calls) >= MAX_BOUND_CALLS:
                raise SourceBudgetExceeded("source binding call limit exceeded")
            self.calls.append(
                _Call(
                    binding,
                    "()",
                    node.lineno,
                    start=self._offset(node.lineno, node.col_offset),
                    end=self._offset(node.end_lineno or node.lineno, node.end_col_offset or 0),
                    decorator=True,
                )
            )
        self.visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default:
                self.visit(default)
        if not isinstance(node, ast.Lambda):
            for decorator in node.decorator_list:
                self._decorator(decorator)
            self.scopes[-1][node.name] = None
        locals_: dict[str, _Binding | None] = {
            arg.arg: None for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        }
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                locals_[arg.arg] = None
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        pending = list(body)
        while pending:
            item = pending.pop()
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                locals_[item.name] = None
                continue
            if isinstance(item, ast.Lambda):
                continue
            if isinstance(item, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                # Comprehension targets are separate locals. Assignment
                # expressions are the exception and bind the outer function.
                for expression in ast.walk(item):
                    if isinstance(expression, ast.NamedExpr) and isinstance(expression.target, ast.Name):
                        locals_[expression.target.id] = None
                continue
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                locals_[item.id] = None
            if isinstance(item, ast.ExceptHandler) and item.name:
                locals_[item.name] = None
            if isinstance(item, (ast.MatchAs, ast.MatchStar)) and item.name:
                locals_[item.name] = None
            if isinstance(item, ast.MatchMapping) and item.rest:
                locals_[item.rest] = None
            if isinstance(item, (ast.Import, ast.ImportFrom)):
                for alias in item.names:
                    locals_[alias.asname or alias.name.split(".")[0]] = None
            pending.extend(ast.iter_child_nodes(item))
        self.scopes.append(locals_)
        self.scope_kinds.append("function")
        self._visit_block(body)
        self.scopes.pop()
        self.scope_kinds.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.bases, *node.decorator_list]:
            self.visit(expression)
        self.scopes[-1][node.name] = None
        self.scopes.append({})
        self.scope_kinds.append("class")
        self._visit_block(node.body)
        self.scopes.pop()
        self.scope_kinds.pop()

    def visit_For(self, node: ast.For | ast.AsyncFor) -> bool:
        self.visit(node.iter)
        # Empty literal collections cannot enter a synchronous for body.
        # Async iteration and calls (including range()) are not evaluated.
        if not isinstance(node, ast.AsyncFor) and (
            isinstance(node.iter, (ast.List, ast.Tuple, ast.Set))
            and not node.iter.elts
            or isinstance(node.iter, ast.Dict)
            and not node.iter.keys
            or isinstance(node.iter, ast.Constant)
            and isinstance(node.iter.value, (str, bytes))
            and not node.iter.value
        ):
            return self._visit_block(node.orelse)
        before = dict(self.scopes[-1])
        self._store(node.target)
        outcomes, has_break = self._visit_loop_body(node.body)
        # The iterable may be empty, and further iterations may overwrite an
        # imported namespace. A single lexical iteration never proves the
        # binding left behind by an unknown runtime iteration count.
        self.scopes[-1] = self._join_scopes(before, *outcomes)
        return self._loop_else(node.orelse, has_break=has_break)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> bool:
        self.visit(node.test)
        if isinstance(node.test, ast.Constant) and not node.test.value:
            # The else suite runs on the zero-iteration path. Neither calls nor
            # assignments in the body can alter the incoming bindings.
            return self._visit_block(node.orelse)
        before = dict(self.scopes[-1])
        outcomes, has_break = self._visit_loop_body(node.body)
        self.scopes[-1] = self._join_scopes(before, *outcomes)
        if isinstance(node.test, ast.Constant) and node.test.value:
            # A constant-true condition cannot reach else. Without an outer
            # loop break, it cannot reach the following statement either.
            return not has_break
        return self._loop_else(node.orelse, has_break=has_break)

    def _loop_else(self, otherwise: list[ast.stmt], *, has_break: bool) -> bool:
        before_else = dict(self.scopes[-1])
        # This runs after the loop's transfer frame is popped. A break in a
        # nested loop's else belongs to the enclosing loop, unlike its body.
        stopped = self._visit_block(otherwise)
        if has_break:
            # A break bypasses else, so its mutations cannot become certain.
            self.scopes[-1] = self._join_scopes(before_else, self.scopes[-1])
        return stopped and not has_break

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._store(item.optional_vars, self._resolve(item.context_expr))
        self._visit_block(node.body)

    visit_AsyncWith = visit_With

    def _comprehension(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        # The first iterable is evaluated in the outer scope; targets and the
        # result expression live in the comprehension's implicit local scope.
        self.visit(node.generators[0].iter)
        self.scopes.append({})
        self.scope_kinds.append("comprehension")
        for number, generator in enumerate(node.generators):
            if number:
                self.visit(generator.iter)
            self._store(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.scopes.pop()
        self.scope_kinds.pop()

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type:
            self.visit(node.type)
        if node.name:
            self.scopes[-1][node.name] = None
        self._visit_block(node.body)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        for case in node.cases:
            for pattern in ast.walk(case.pattern):
                if isinstance(pattern, (ast.MatchAs, ast.MatchStar)) and pattern.name:
                    self.scopes[-1][pattern.name] = None
                elif isinstance(pattern, ast.MatchMapping) and pattern.rest:
                    self.scopes[-1][pattern.rest] = None
            if case.guard:
                self.visit(case.guard)
            self._visit_block(case.body)

    def visit_If(self, node: ast.If) -> bool:
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            return self._visit_block(node.body if node.test.value else node.orelse)
        # Neither branch is assumed to execute. Only bindings identical after
        # both branches survive into subsequent code. Each branch writes to an
        # overlay of the enclosing bindings, so the merge costs the branches'
        # own assignments rather than a copy of the whole scope per ``if``,
        # which made a file of many top-level names and ifs quadratic. A branch
        # that ends in an unconditional transfer (return, raise, break,
        # continue) contributes no bindings to the code after the ``if``.
        before = self.scopes[-1]
        outcomes: list[Mapping[str, _Binding | None]] = []
        continuing: list[Mapping[str, _Binding | None]] = []
        for branch in (node.body, node.orelse):
            overlay: dict[str, _Binding | None] = {}
            chain = ChainMap(overlay, before)
            self.scopes[-1] = chain
            stopped = self._visit_block(branch)
            # A star import replaces the branch's scope with a plain mapping
            # of every name; that mapping is then the branch's whole outcome.
            scope = self.scopes[-1]
            outcome = overlay if scope is chain else scope
            outcomes.append(outcome)
            if not stopped:
                continuing.append(outcome)
        self.scopes[-1] = before
        joined = continuing or outcomes
        for name in set().union(*joined):
            values = [outcome.get(name, before.get(name)) for outcome in joined]
            before[name] = values[0] if all(value == values[0] for value in values[1:]) else None
        return not continuing


_LiteralGroups = tuple[tuple[str, ...], ...]
# Per index: for each Python import pattern, the required literal groups that
# a synthesized "from M import A" can hold only through M or A, or None when
# some pattern cannot rule such a statement out (``_python_import_hints``).
_IMPORT_HINTS: weakref.WeakKeyDictionary[SignatureIndex, tuple[_LiteralGroups, ...] | None] = (
    weakref.WeakKeyDictionary()
)
_IMPORT_HINTS_LOCK = threading.Lock()


def _python_statement(binding: _Binding) -> str:
    """Return the import statement whose signature matches give a Python binding its provenance."""
    if binding.symbol:
        return f"from {binding.module} import {binding.symbol.split('.')[0]}"
    return f"import {binding.module}"


def _python_import_hints(index: SignatureIndex) -> tuple[_LiteralGroups, ...] | None:
    """Return what ``from M import A`` must hold in M or A to match each Python import pattern, cached.

    Every match of a pattern contains an alternative of each of its required
    literal groups: the ``required_literals`` contract that the matcher's own
    prefilter relies on. M (a dotted name) and A (an identifier) hold no space,
    so an alternative without one lies within "from", M, "import" or A. A
    group that "from" or "import" already satisfies constrains neither name,
    and neither does one with an alternative holding a space, which may span
    the parts; both are dropped. None means some pattern has no case-sensitive
    literals, or no group is left, so no attribute statement can be ruled out
    without running it.
    """
    with _IMPORT_HINTS_LOCK:
        if index in _IMPORT_HINTS:
            return _IMPORT_HINTS[index]
    result = _collect_import_hints(index)
    with _IMPORT_HINTS_LOCK:
        _IMPORT_HINTS[index] = result
    return result


def _collect_import_hints(index: SignatureIndex) -> tuple[_LiteralGroups, ...] | None:
    patterns: dict[_LiteralGroups, None] = {}
    # The (signature, signal) pairs the matcher's own regex plan runs, so a
    # signature id that two signatures of the index share is covered too.
    for _, signal in index.signals_of_type("import"):
        if signal.languages and "python" not in signal.languages:
            continue
        for compiled in signal.bounded_compiled:
            pattern = getattr(compiled, "pattern", None)
            if not isinstance(pattern, str):
                return None
            hints = required_literals(pattern)
            if hints.fold or not hints.groups:
                return None
            groups = tuple(
                group
                for group in hints.groups
                if not any(" " in literal or literal in "from" or literal in "import" for literal in group)
            )
            if not groups:
                return None
            patterns[groups] = None
    return tuple(patterns)


class _Names:
    """Distinct names joined one per line, so finding those holding a literal costs one search."""

    def __init__(self, names: set[str]) -> None:
        self.names = sorted(names)
        self.text = "\n".join(self.names)
        self.starts = [0]
        for name in self.names[:-1]:
            self.starts.append(self.starts[-1] + len(name) + 1)
        self._holding: dict[str, tuple[str, ...]] = {}

    def holding(self, literal: str) -> tuple[str, ...]:
        """Return the names containing ``literal`` (and any that a match across a line break starts in)."""
        found = self._holding.get(literal)
        if found is None:
            names: list[str] = []
            position = self.text.find(literal) if self.names else -1
            while position >= 0:
                number = bisect_right(self.starts, position) - 1
                names.append(self.names[number])
                # Continue at the next name: each holder costs one search.
                if number + 1 == len(self.names):
                    break
                position = self.text.find(literal, self.starts[number + 1])
            found = self._holding[literal] = tuple(names)
        return found

    def masks(self, groups: _LiteralGroups) -> dict[str, int]:
        """Return, for each name holding an alternative of some group, the bit mask of the groups it holds."""
        masks: dict[str, int] = {}
        for bit, group in enumerate(groups):
            for literal in group:
                for name in self.holding(literal):
                    masks[name] = masks.get(name, 0) | 1 << bit
        return masks


def _by_mask(masks: dict[str, int]) -> dict[int, list[str]]:
    buckets: dict[int, list[str]] = {}
    for name, mask in masks.items():
        buckets.setdefault(mask, []).append(name)
    return buckets


def _attribute_statements(
    hints: tuple[_LiteralGroups, ...],
    modules: set[str],
    attributes: set[str],
) -> set[tuple[str, str]] | None:
    """Return each (M, A) whose ``from M import A`` holds an alternative of every group of some pattern.

    Only these statements can match. Per pattern, a module and an attribute
    name each reduce to the bit mask of the groups they hold, and a pair
    qualifies when its two masks cover every group. Pairs are counted per
    combination of masks, never per module and name, and each literal is
    searched once among all modules and once among all names, so the work is
    linear in the names and the qualifying pairs. None means a module alone
    holds every group of a pattern, so any attribute qualifies, or more than
    ``_MAX_PROOF_STATEMENTS`` pairs qualify: too many to match either way.
    """
    module_names, attribute_names = _Names(modules), _Names(attributes)
    statements: set[tuple[str, str]] = set()
    for groups in hints:
        if not all(
            any(module_names.holding(literal) or attribute_names.holding(literal) for literal in group)
            for group in groups
        ):
            continue  # a group no module and no name holds
        module_masks = module_names.masks(groups)
        full = (1 << len(groups)) - 1
        if full in module_masks.values():
            return None
        by_module, by_name = _by_mask(module_masks), _by_mask(attribute_names.masks(groups))
        # Mask 0 stands for the modules that hold no group.
        pairs = [(mask, other) for mask in (0, *by_module) for other in by_name if mask | other == full]
        unheld = len(modules) - len(module_masks)
        count = sum((len(by_module[mask]) if mask else unheld) * len(by_name[other]) for mask, other in pairs)
        if count > _MAX_PROOF_STATEMENTS:
            return None
        for mask, other in pairs:
            holders = by_module.get(mask) or [module for module in modules if module not in module_masks]
            statements.update((module, name) for module in holders for name in by_name[other])
        if len(statements) > _MAX_PROOF_STATEMENTS:
            return None
    return statements


def _python_bindable(index: SignatureIndex, tree: ast.AST) -> bool:
    """Whether a binding ``_PythonBindings`` can create for ``tree`` has signature matches.

    False proves the binder yields no evidence for the file, whatever its size:
    every import and call it reports needs such a binding, and the provider
    loop and LangGraph recognizers only follow those calls. Bindings
    originate in absolute imports and resolve through ``_python_statement``.
    ``from M import A`` (A and its attributes) and ``import M`` (M or its
    first component) are checked exactly. Attributes of an ``import M``
    binding give ``from M import <attribute>`` for any attribute name in the
    file; only the statements ``_attribute_statements`` returns can match,
    and those are checked exactly. The work is linear in the tree plus at most
    ``_MAX_PROOF_MATCHES`` distinct statement matches; beyond that, or with
    too many attribute statements, the answer is True. True may be
    conservative (repository-local modules are not excluded either); it never
    changes a result.
    """
    checked: set[str] = set()

    def matched(module: str, symbol: str) -> bool:
        """Whether the statement has matches; beyond the budget, assume it may."""
        statement = _python_statement(_Binding(module, symbol))
        if statement in checked:
            return False  # an earlier check found no match
        checked.add(statement)
        return len(checked) > _MAX_PROOF_MATCHES or bool(index.match_import_statement(statement, "python"))

    modules: set[str] = set()
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            attributes.add(node.attr)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                modules.update((alias.name, alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom) and not node.level:
            for alias in node.names:
                if alias.name != "*" and matched(node.module or "", alias.name):
                    return True
    if not modules:
        return False
    hints = _python_import_hints(index)
    if hints is None or len(checked) + len(modules) > _MAX_PROOF_MATCHES:
        return True
    if any(matched(module, "") for module in sorted(modules)):
        return True
    statements = _attribute_statements(hints, modules, attributes)
    return statements is None or any(matched(module, name) for module, name in sorted(statements))


def _python_bindings(
    text: str,
    relevant: Callable[[_Binding], bool] | None = None,
    max_nodes: int | None = None,
    bindable: Callable[[ast.AST], bool] | None = None,
) -> tuple[list[_Call], list[tuple[_Binding, int]], ast.AST]:
    tree = ast.parse(text)
    if bindable is not None and not bindable(tree):
        # Proven to yield nothing: skipping the binder loses no evidence, so
        # a file of any size is complete without it.
        return [], [], tree
    limit = MAX_AST_NODES if max_nodes is None else max_nodes
    for count, _ in enumerate(ast.walk(tree)):
        if count >= limit:
            raise SourceBudgetExceeded("source binding AST limit exceeded")
    visitor = _PythonBindings(text, relevant)
    visitor.visit(tree)
    return visitor.calls, visitor.imports, tree


def _javascript_bindings(
    text: str,
    ignored: list[tuple[int, int]],
    relevant: Callable[[_Binding], bool] | None = None,
) -> tuple[list[_Call], list[tuple[_Binding, int]]]:
    starts = [start for start, _ in ignored]

    def excluded(offset: int) -> bool:
        pos = bisect_right(starts, offset) - 1
        return pos >= 0 and offset < ignored[pos][1]

    pieces: list[str] = []
    previous = 0
    for start, end in ignored:
        pieces.extend((text[previous:start], re.sub(r"[^\r\n]", " ", text[start:end])))
        previous = end
    pieces.append(text[previous:])
    masked = "".join(pieces)
    bindings: dict[str, _Binding] = {}
    imports: list[tuple[_Binding, int]] = []
    declaration_spans: list[tuple[int, int]] = []

    def bind(name: str, module: str, symbol: str, line: int) -> None:
        if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            bindings[name] = _Binding(module, symbol)
            imports.append((bindings[name], line))

    rx = regex.compile(r"\bimport\s+(?!type\b)([^;]{1,2000}?)\s+from\s*(['\"])([^'\"\r\n]{1,240})\2")
    for match in rx.finditer(text, timeout=pattern_timeout(), concurrent=False):
        if excluded(match.start()):
            continue
        spec, module = match.group(1), match.group(3)
        line = text.count("\n", 0, match.start()) + 1
        declaration_spans.append(match.span())
        namespace = re.search(r"\*\s+as\s+([\w$]+)", spec)
        if namespace:
            bind(namespace.group(1), module, "", line)
        named = re.search(r"\{([^}]+)\}", spec)
        if named:
            for item in named.group(1).split(","):
                parts = re.split(r"\s+as\s+", item.strip())
                if parts and not parts[0].startswith("type "):
                    bind(parts[-1], module, parts[0], line)
        default = re.match(r"\s*([A-Za-z_$][\w$]*)\s*(?:,|$)", spec)
        if default:
            bind(default.group(1), module, "default", line)

    rx = regex.compile(
        r"\b(?:const|let|var)\s+([\w$]+|\{[^}\r\n]{1,1000}\})\s*=\s*"
        r"require\s*\(\s*(['\"])([^'\"\r\n]{1,240})\2\s*\)"
    )
    for match in rx.finditer(text, timeout=pattern_timeout(), concurrent=False):
        if excluded(match.start()):
            continue
        spec, module = match.group(1), match.group(3)
        line = text.count("\n", 0, match.start()) + 1
        declaration_spans.append(match.span())
        if spec.startswith("{"):
            for item in spec[1:-1].split(","):
                parts = [part.strip() for part in item.split(":")]
                bind(parts[-1], module, parts[0], line)
        else:
            bind(spec, module, "", line)

    # Only imported roots that can resolve to a loaded signature can produce
    # bound evidence. Narrow before the per-name shadow checks and call scan so
    # large ordinary source files do not spend their input deadline matching
    # thousands of unrelated calls. Keep ``imports`` intact: the caller still
    # reports every relevant import through its own signature lookup.
    if relevant is not None:
        bindings = {name: binding for name, binding in bindings.items() if relevant(binding)}
    _drop_uncertain_bindings(bindings, masked, declaration_spans)
    return _javascript_calls(text, masked, bindings), imports


def _drop_uncertain_bindings(
    bindings: dict[str, _Binding],
    masked: str,
    declaration_spans: list[tuple[int, int]],
) -> None:
    """Forget each binding that is declared again, reassigned or shadowed outside its import declaration."""
    # Treat any local shadow/reassignment as uncertain across this source. This
    # sacrifices some recall instead of attributing unrelated calls to an SDK.
    declaration_mask = list(masked)
    for start, end in declaration_spans:
        declaration_mask[start:end] = " " * (end - start)
    rest = "".join(declaration_mask)
    for name in list(bindings):
        escaped = re.escape(name)
        patterns = [
            rf"\b(?:const|let|var|class|function)\s+{escaped}\b",
            rf"(?<![\w$.]){escaped}\s*(?:=(?!=|>)|\+=|-=|\+\+|--)",
            rf"\bfunction\b[^(){{}};]*\([^)]*\b{escaped}\b[^)]*\)",
            rf"\([^()]*\b{escaped}\b[^()]*\)\s*(?::[^=;{{}}]+)?=>",
            rf"(?<![\w$.]){escaped}\s*=>",
            rf"(?<![\w$.]){escaped}\s*\.\s*[\w$]+\s*=(?!=)",
            rf"\bcatch\s*\(\s*{escaped}\b",
            rf"(?:^|[;{{}}\n])\s*(?:async\s+)?[\w$]+\s*\([^)]*\b{escaped}\b[^)]*\)\s*(?::[^{{}};]+)?\{{",
        ]
        if any(
            regex.search(pattern, rest, timeout=pattern_timeout(), concurrent=False) for pattern in patterns
        ):
            del bindings[name]


def _javascript_calls(text: str, masked: str, bindings: dict[str, _Binding]) -> list[_Call]:
    """Return the calls through ``bindings`` in code, each with its balanced argument text.

    Only calls rooted at a bound name are matched, so the scan's cost follows
    the relevant imports rather than every call in a large source file.
    """
    calls: list[_Call] = []
    # Vercel AI SDK tool() factories, by the local name a call spells them with.
    tool_factories = tuple(
        name if binding.symbol == "tool" else f"{name}.tool"
        for name, binding in bindings.items()
        if binding.module == "ai" and binding.symbol in {"tool", ""}
    )
    if not bindings:
        return calls
    roots = "|".join(re.escape(name) for name in sorted(bindings, key=len, reverse=True))
    rx = regex.compile(
        rf"(?<![\w$.])((?:{roots})(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"
        rf"\s*(?:<[^;(){{}}]{{1,1000}}>)?\s*\("
    )
    for match in rx.finditer(masked, timeout=pattern_timeout(), concurrent=False):
        parts = re.split(r"\s*\.\s*", match.group(1))
        binding = bindings.get(parts[0])
        if binding is None:
            continue
        if len(calls) >= MAX_BOUND_CALLS:
            raise SourceBudgetExceeded("source binding call limit exceeded")
        opening = match.end() - 1
        depth, end = 1, opening + 1
        while end < min(len(masked), opening + MAX_CALL_TEXT) and depth:
            depth += (masked[end] == "(") - (masked[end] == ")")
            end += 1
        if depth:
            continue
        symbol = ".".join(filter(None, (binding.symbol, *parts[1:])))
        calls.append(
            _Call(
                _Binding(binding.module, symbol),
                text[opening:end],
                text.count("\n", 0, match.start()) + 1,
                masked[opening:end],
                tool_factories=tool_factories,
                start=match.start(),
                end=end,
            )
        )
    return calls


class _ModuleMatches:
    """The import signature matches of each bound module, looked up once per file."""

    def __init__(
        self,
        index: SignatureIndex,
        language: str,
        is_local_module: Callable[[str], bool] | None,
    ) -> None:
        self.index = index
        self.language = language
        self.is_local_module = is_local_module
        self._cache: dict[_Binding, list[Match]] = {}

    def __call__(self, binding: _Binding) -> list[Match]:
        if binding not in self._cache:
            self._cache[binding] = self._lookup(binding)
        return self._cache[binding]

    def relevant(self, binding: _Binding) -> bool:
        """Whether calls through ``binding`` can carry evidence: its module resolves to a signature."""
        return bool(self(binding))

    def _lookup(self, binding: _Binding) -> list[Match]:
        index, language = self.index, self.language
        if language == "python":
            matches = list(index.match_import_statement(_python_statement(binding), language))
            if matches and self.is_local_module is not None and self.is_local_module(binding.module):
                matches = []
            return matches
        statement = f"import {{ example }} from '{binding.module}'"
        matches = list(index.match_import_statement(statement, language))
        matches += index.match_dependency("npm", binding.module)
        if binding.module.startswith("@langchain/langgraph"):
            matches = [m for m in matches if m.signature_id != "framework.langchain"]
        return matches


_JAVASCRIPT_OPENAI_CONSTRUCTORS = frozenset(
    {
        "default",
        "OpenAI",
        "AsyncOpenAI",
        "AzureOpenAI",
        "AsyncAzureOpenAI",
    }
)
_RESPONSES_CREATE = frozenset(
    {
        "OpenAI.responses.create",
        "AsyncOpenAI.responses.create",
        "AzureOpenAI.responses.create",
        "AsyncAzureOpenAI.responses.create",
    }
)


@dataclass
class _LoopRequests:
    """Import-bound request calls that the tool loop and dispatch recognizers follow."""

    provider: set[int] = field(default_factory=set)
    responses: set[int] = field(default_factory=set)
    javascript_constructors: set[int] = field(default_factory=set)

    def record(self, language: str, call: _Call, signatures: dict[str, Signature], parsed: bool) -> None:
        """Remember ``call`` if a recognizer follows it; ``parsed`` says a Python tree exists."""
        if (
            language == "javascript"
            and "provider.openai" in signatures
            and call.binding.module == "openai"
            and call.binding.symbol in _JAVASCRIPT_OPENAI_CONSTRUCTORS
        ):
            self.javascript_constructors.add(call.line)
        if not parsed or call.node is None:
            return
        loop_request = _LOOP_REQUESTS.get(call.binding.module)
        if (
            loop_request is not None
            and loop_request[0] in signatures
            and call.binding.symbol in loop_request[1]
        ):
            self.provider.add(id(call.node))
        if (
            "provider.openai" in signatures
            and call.binding.module == "openai"
            and call.binding.symbol in _RESPONSES_CREATE
        ):
            self.responses.add(id(call.node))


def bound_source_matches(
    index: SignatureIndex,
    text: str,
    language: str,
    ignored: list[tuple[int, int]],
    *,
    is_local_module: Callable[[str], bool] | None = None,
    max_ast_nodes: int | None = None,
) -> list[Match]:
    """Return import and call evidence whose module provenance is resolved.

    Invalid Python cannot establish bound constructions. The caller already
    retains lexical import/supporting evidence and reports lexical ambiguity.
    """
    module_matches = _ModuleMatches(index, language, is_local_module)
    tree = None
    try:
        if language == "python":
            calls, imports, tree = _python_bindings(
                text,
                module_matches.relevant,
                max_ast_nodes,
                bindable=lambda parsed: _python_bindable(index, parsed),
            )
        else:
            calls, imports = _javascript_bindings(text, ignored, module_matches.relevant)
    except RecursionError as exc:
        raise SourceBudgetExceeded("source binding recursion limit exceeded") from exc
    except (SyntaxError, ValueError):
        return []

    found = _import_evidence(index, language, imports, module_matches)
    requests = _LoopRequests()
    graph_lines = _langgraph_agent_lines(tree, calls)
    for call in calls:
        signatures = {m.signature_id: m.signature for m in module_matches(call.binding)}
        requests.record(language, call, signatures, tree is not None)
        found.extend(_call_evidence(language, call, signatures, graph_lines))
    found.extend(_protocol_evidence(index, tree, text, ignored, requests))
    return found


def _langgraph_agent_lines(tree: ast.AST | None, calls: list[_Call]) -> set[int]:
    """Return the lines of import-bound StateGraph constructions with static tool-cycle evidence.

    The graph pass runs only when a Python tree has a bound LangGraph
    StateGraph call; it sees every bound call so it can follow tools and
    models into the graph.
    """
    if tree is None or not any(
        call.binding.module.startswith("langgraph") and _symbol_tail(call.binding.symbol) == "StateGraph"
        for call in calls
    ):
        return set()
    return langgraph_agent_lines(
        tree,
        [(call.node, call.binding.module, call.binding.symbol) for call in calls if call.node is not None],
    )


def _import_evidence(
    index: SignatureIndex,
    language: str,
    imports: list[tuple[_Binding, int]],
    module_matches: _ModuleMatches,
) -> list[Match]:
    """Return the evidence of each bound import: its module's signatures and their import-line code."""
    found: list[Match] = []
    for binding, line in imports:
        for match in module_matches(binding):
            found.append(
                Match(
                    match.signature,
                    Signal(type="import", weight=match.weight),
                    sanitize_text(binding.module),
                    match.weight,
                    line=line,
                    extra={"verified_agent": False},
                )
            )
        # Some signatures describe capabilities conveyed by a particular
        # imported tool. Retain those as supporting evidence, never an agent.
        resolved = {m.signature_id for m in module_matches(binding)}
        if language == "python" and resolved:
            # Only matches of signatures this import resolves to are kept, so
            # an unresolved import (most of them) needs no code pass at all.
            statement = (
                f"from {binding.module} import {binding.symbol}"
                if binding.symbol
                else f"import {binding.module}"
            )
            for match in index.match_code(statement, language):
                if match.signature_id in resolved:
                    match.line = line
                    match.extra["verified_agent"] = False
                    found.append(match)
    return found


def _call_evidence(
    language: str,
    call: _Call,
    signatures: dict[str, Signature],
    graph_lines: set[int],
) -> list[Match]:
    """Return the evidence of one bound call for each signature its module resolves to.

    ``graph_lines`` holds the StateGraph construction lines that
    ``_langgraph_agent_lines`` verified as agents.
    """
    found: list[Match] = []
    symbol = _symbol_tail(call.binding.symbol)
    canonical = symbol + call.arguments
    for signature in signatures.values():
        factory = _FACTORIES.get(signature.id)
        verified = bool(factory and re.fullmatch(factory, symbol))
        construction = "import-bound agent construction"
        if signature.id == "framework.langgraph" and symbol == "StateGraph":
            verified = call.line in graph_lines
        if signature.id == "framework.vercel-ai-sdk" and symbol in {"generateText", "streamText"}:
            # A schema alone does not dispatch tools, and toolChoice/activeTools
            # can explicitly disable them. Preserve SDK usage on unknown shapes.
            verified = has_executable_vercel_tools(
                call.arguments, call.structural_arguments, call.tool_factories
            )
            if not verified and has_vercel_tool_loop(call.arguments, call.structural_arguments):
                # Tool results go back to the model until the stop condition:
                # an agent loop even when the tools are imported definitions.
                verified, construction = True, "import-bound multi-step tool loop"
        configured = configured_capabilities(
            signature.id,
            symbol,
            node=call.node,
            arguments=call.arguments,
            masked=call.structural_arguments,
            verified_graph=signature.id == "framework.langgraph" and symbol == "StateGraph" and verified,
        )

        capabilities = CallCapabilities(signature.id, verified, configured, (call.start, call.end))

        if (
            language == "python"
            and signature.id == "framework.pydantic-ai"
            and call.binding.constructed
            and symbol in {"Agent.tool", "Agent.tool_plain"}
            and (
                call.decorator
                or (
                    call.node is not None
                    and bool(call.node.args)
                    and isinstance(call.node.args[0], (ast.Name, ast.Attribute, ast.Lambda))
                )
            )
        ):
            # Both @agent.tool_plain and @agent.tool_plain(...) register the
            # decorated function. Merely obtaining agent.tool_plain() outside
            # a decorator does not register one. A class or foreign receiver
            # cannot acquire SDK provenance from its method's spelling.
            found.append(
                Match(
                    signature,
                    Signal(
                        type="code",
                        weight=0.8,
                        capabilities=["tool-use"],
                        description="import-bound Pydantic agent tool registration",
                    ),
                    sanitize_text(f"{call.binding.module}:{symbol}("),
                    0.8,
                    line=call.line,
                    extra=capabilities.metadata(False, ["tool-use"]),
                )
            )

        if (
            signature.category == "provider"
            and _TOOL_REQUEST_METHODS.search(call.binding.symbol)
            and _TOOL_ARGUMENTS.search(call.structural_arguments)
        ):
            # Schema-only requests stay tool-enabled LLM usage: the loop
            # evidence below decides whether selected tools are executed.
            found.append(
                Match(
                    signature,
                    Signal(
                        type="code",
                        weight=0.7,
                        capabilities=["tool-use"],
                        description="import-bound request offering tools",
                    ),
                    sanitize_text(f"{call.binding.module}:{symbol}(tools="),
                    0.7,
                    line=call.line,
                    extra={"verified_agent": False},
                )
            )
        for keyword, capability in _KEYWORD_CAPABILITIES.get(signature.id, ()):
            if re.search(rf"(?<![\w$]){keyword}\s*[=:]", call.structural_arguments):
                found.append(
                    Match(
                        signature,
                        Signal(
                            type="code",
                            weight=0.6,
                            capabilities=[capability],
                            description=f"{keyword} argument",
                        ),
                        sanitize_text(f"{symbol}({keyword}="),
                        0.6,
                        line=call.line,
                        extra=capabilities.metadata(False, [capability], option=True),
                    )
                )
        for signal in signature.signals:
            if signal.type != "code" or signal.languages and language not in signal.languages:
                continue
            for pattern in signal.bounded_compiled:
                match = pattern.search(canonical, timeout=pattern_timeout(), concurrent=False)
                if match is None or match.start() > len(symbol):
                    continue
                # A known factory list excludes memory/model utility calls
                # from inherited broad agent_indicator declarations.
                indicator = verified if factory else signature.agent_indicator or signal.agent_indicator
                found.append(
                    Match(
                        signature,
                        signal,
                        sanitize_text(canonical[: len(symbol) + 1]),
                        signal.weight,
                        line=call.line,
                        extra=capabilities.metadata(indicator, signal.capabilities),
                    )
                )
                break
        if verified:
            found.append(
                Match(
                    signature,
                    Signal(
                        type="code",
                        weight=0.9,
                        agent_indicator=True,
                        description=construction,
                    ),
                    sanitize_text(f"{call.binding.module}:{symbol}("),
                    0.9,
                    line=call.line,
                    extra=capabilities.metadata(True, []),
                )
            )
    return found


def _protocol_evidence(
    index: SignatureIndex,
    tree: ast.AST | None,
    text: str,
    ignored: list[tuple[int, int]],
    requests: _LoopRequests,
) -> list[Match]:
    """Return tool-calling protocol evidence from the loops and dispatch around bound requests."""
    protocol = index.get("protocol.openai-function-calling")
    if protocol is None:
        return []
    found: list[Match] = []
    if tree is not None:
        for line in provider_tool_loop_lines(tree, requests.provider):
            found.append(
                Match(
                    protocol,
                    Signal(
                        type="code",
                        weight=0.9,
                        agent_indicator=True,
                        capabilities=["tool-use", "autonomous"],
                        description="import-bound model-selected tool dispatch with conversation feedback",
                    ),
                    "provider tool-selection/dispatch/feedback loop",
                    0.9,
                    line=line,
                    extra={"verified_agent": True},
                )
            )
        for line in responses_tool_loop_lines(tree, requests.responses):
            found.append(
                Match(
                    protocol,
                    Signal(
                        type="code",
                        weight=0.9,
                        agent_indicator=True,
                        capabilities=["tool-use", "autonomous"],
                        description="import-bound Responses function dispatch with ordered "
                        "conversation feedback",
                    ),
                    "OpenAI Responses tool-selection/dispatch/feedback loop",
                    0.9,
                    line=line,
                    extra={"verified_agent": True},
                )
            )
    dispatch_lines = (
        responses_dispatch_lines(tree, requests.responses)
        if tree is not None
        else javascript_responses_dispatch_lines(text, ignored, requests.javascript_constructors)
    )
    for line in dispatch_lines:
        found.append(
            Match(
                protocol,
                Signal(
                    type="code",
                    weight=0.85,
                    agent_indicator=True,
                    capabilities=["tool-use"],
                    description="import-bound Responses selected-action dispatch",
                ),
                "OpenAI Responses selected-action dispatch",
                0.85,
                line=line,
                extra={"verified_agent": True, "agent_classification": "openai-responses-tool-dispatch"},
            )
        )
    return found
