"""Conservative import-bound calls for Python and common JavaScript/TypeScript.

This is static evidence of construction, not execution. Python uses its AST;
JavaScript uses a bounded lexical resolver for imports and direct calls. Dynamic
imports, re-exports and uncertain/shadowed JavaScript bindings remain supporting
framework evidence. No scanned code is imported or executed.

Python AST work is capped at 50,000 nodes and source calls at 512 per file;
call expressions are bounded to 8 KiB. Regex operations share the scanner's
per-input deadline. Other source languages do not use this resolver: filesystem
classification requires matching import/dependency evidence for their lexical
framework signals, and caps uncorroborated code evidence at 0.6.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass

import regex

from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import Signal
from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout
from shadowscan.utils.redaction import sanitize_text

MAX_AST_NODES = 50_000
MAX_BOUND_CALLS = 512
MAX_CALL_TEXT = 8192
MAX_TOOL_LOOP_AST_WORK = 200_000


@dataclass(frozen=True)
class _Binding:
    module: str
    symbol: str


@dataclass(frozen=True)
class _Call:
    binding: _Binding
    arguments: str
    line: int
    structural_arguments: str = ""
    node: ast.Call | None = None


# These APIs construct agents even when their arguments have a different order
# from older lexical signatures. Names have meaning only after import binding.
_FACTORIES = {
    "framework.langchain": r"(?:AgentExecutor|initialize_agent|create_\w*agent|createReactAgent|createToolCallingAgent)",
    "framework.langgraph": r"(?:StateGraph|create_react_agent|createReactAgent|create_supervisor|create_swarm)",
    "framework.llamaindex": r"(?:ReActAgent|FunctionAgent|FunctionCallingAgent|OpenAIAgent|AgentWorkflow|CodeActAgent|AgentRunner)(?:\.from_tools)?",
    "framework.crewai": r"(?:Agent|Crew|Flow)",
    "framework.google-adk": r"(?:Agent|LlmAgent|SequentialAgent|ParallelAgent|LoopAgent|Runner|InMemoryRunner)",
    "framework.aws-strands": r"(?:Agent|GraphBuilder|Swarm)",
    "framework.microsoft-agent-framework": r"(?:ChatAgent|WorkflowBuilder|MagenticBuilder|HandoffBuilder)",
    "framework.semantic-kernel": r"(?:ChatCompletionAgent|OpenAIAssistantAgent|AzureAIAgent|AgentGroupChat|BedrockAgent|CopilotStudioAgent)",
    "framework.autogen": r"(?:AssistantAgent|ConversableAgent|UserProxyAgent|RoundRobinGroupChat|SelectorGroupChat|MagenticOneGroupChat|Swarm|GroupChatManager|CodeExecutorAgent)",
    "framework.smolagents": r"(?:CodeAgent|ToolCallingAgent|ManagedAgent)",
    "framework.transformers-agents": r"(?:ReactCodeAgent|ReactJsonAgent|HfAgent)",
    "framework.openai-agents-sdk": r"(?:Agent|Runner\.run(?:_sync|_streamed|Sync)?)",
    "framework.openai-swarm": r"(?:Agent|Swarm)",
    "framework.claude-agent-sdk": r"(?:ClaudeSDKClient|query)",
    "framework.pydantic-ai": r"Agent",
    "framework.vercel-ai-sdk": r"(?:ToolLoopAgent|Experimental_Agent)",
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


def _symbol_tail(symbol: str) -> str:
    # Module paths may precede the exported class/function. Keep class methods.
    parts = symbol.split(".")
    return ".".join(parts[-2:]) if len(parts) > 1 and parts[-2][:1].isupper() else parts[-1]


class _PythonBindings(ast.NodeVisitor):
    def __init__(self, text: str):
        self.text = text
        self.lines = text.splitlines(keepends=True)
        self.offsets = [0]
        for line in self.lines:
            self.offsets.append(self.offsets[-1] + len(line))
        self.scopes: list[dict[str, _Binding | None]] = [{}]
        self.scope_kinds = ["module"]
        self.calls: list[_Call] = []
        self.imports: list[tuple[_Binding, int]] = []

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
                return _Binding(base.module, ".".join(filter(None, (base.symbol, node.attr))))
        elif isinstance(node, ast.Call):
            return self._resolve(node.func)
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
            binding = _Binding(node.module or "", alias.name) if not node.level and alias.name != "*" else None
            self.scopes[-1][alias.asname or alias.name] = binding
            if binding:
                self.imports.append((binding, node.lineno))

    def visit_Call(self, node: ast.Call) -> None:
        binding = self._resolve(node.func)
        if binding:
            if len(self.calls) >= MAX_BOUND_CALLS:
                raise MatchTimeoutError("source binding call limit exceeded")
            start = self._offset(node.func.end_lineno or node.lineno, node.func.end_col_offset or 0)
            end = self._offset(node.end_lineno or node.lineno, node.end_col_offset or 0)
            self.calls.append(_Call(binding, self.text[start:min(end, start + MAX_CALL_TEXT)], node.lineno,
                                    node=node))
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

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default:
                self.visit(default)
        if not isinstance(node, ast.Lambda):
            for decorator in node.decorator_list:
                self.visit(decorator)
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
        for statement in body:
            self.visit(statement)
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
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.scope_kinds.pop()

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._store(node.target)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._store(item.optional_vars, self._resolve(item.context_expr))
        for statement in node.body:
            self.visit(statement)

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
        for statement in node.body:
            self.visit(statement)

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
            for statement in case.body:
                self.visit(statement)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            for statement in node.body if node.test.value else node.orelse:
                self.visit(statement)
            return
        # Neither branch is assumed to execute. Only bindings identical after
        # both branches survive into subsequent code.
        before = self.scopes[-1].copy()
        outcomes = []
        for branch in (node.body, node.orelse):
            self.scopes[-1] = before.copy()
            for statement in branch:
                self.visit(statement)
            outcomes.append(self.scopes[-1])
        self.scopes[-1] = {name: outcomes[0].get(name) if outcomes[0].get(name) == outcomes[1].get(name) else None
                           for name in set(outcomes[0]) | set(outcomes[1])}


def _python_bindings(text: str) -> tuple[list[_Call], list[tuple[_Binding, int]], ast.Module]:
    tree = ast.parse(text)
    for count, _ in enumerate(ast.walk(tree)):
        if count >= MAX_AST_NODES:
            raise MatchTimeoutError("source binding AST limit exceeded")
    visitor = _PythonBindings(text)
    visitor.visit(tree)
    return visitor.calls, visitor.imports, tree


def _same_scope_nodes(node: ast.AST):
    """Walk one loop without borrowing evidence from a nested function/class."""
    pending = [node]
    while pending:
        current = pending.pop()
        if current is not node and isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield current
        if isinstance(current, ast.If) and isinstance(current.test, ast.Constant):
            pending.extend(current.body if current.test.value else current.orelse)
            continue
        pending.extend(ast.iter_child_nodes(current))


def _member(node: ast.AST | None, owner: str, name: str) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == name and
            isinstance(node.value, ast.Name) and node.value.id == owner)


def _assigned_call(node: ast.AST) -> tuple[str, ast.Call] | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        name = node.targets[0].id
        value: ast.expr | None = node.value
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        name, value = node.target.id, node.value
    else:
        return None
    if isinstance(value, ast.Await):
        value = value.value
    return (name, value) if isinstance(value, ast.Call) else None


def _tool_output_dict(node: ast.AST, item: str, results: set[str]) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    fields = {key.value: value for key, value in zip(node.keys, node.values, strict=True)
              if isinstance(key, ast.Constant) and isinstance(key.value, str)}
    output = fields.get("output")
    kind = fields.get("type")
    return (isinstance(kind, ast.Constant) and kind.value == "function_call_output"
            and _member(fields.get("call_id"), item, "call_id")
            and output is not None and any(isinstance(part, ast.Name) and part.id in results
                                           for part in ast.walk(output)))


def _function_call_filter(node: ast.AST, item: str) -> bool:
    return (isinstance(node, ast.Compare) and
            len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq) and
            any(_member(part, item, "type") for part in [node.left, *node.comparators]) and
            any(isinstance(part, ast.Constant) and part.value == "function_call"
                for part in [node.left, *node.comparators]))


def _item_type_condition(node: ast.AST, item: str) -> bool | None:
    """Evaluate a simple type guard assuming a selected function_call item."""
    if not (isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1):
        return None
    left, right = node.left, node.comparators[0]
    if _member(right, item, "type"):
        left, right = right, left
    if not (_member(left, item, "type") and isinstance(right, ast.Constant) and isinstance(right.value, str)):
        return None
    if isinstance(node.ops[0], ast.Eq):
        return right.value == "function_call"
    if isinstance(node.ops[0], ast.NotEq):
        return right.value != "function_call"
    return None


def _selected_paths(statements: list[ast.stmt], item: str, consume: Callable[[int], None]) -> list[list[ast.AST]]:
    """Keep evidence on reachable branches for an item known to be function_call."""
    paths: list[list[ast.AST]] = [[]]
    for statement in statements:
        if isinstance(statement, ast.If):
            outcome = (bool(statement.test.value) if isinstance(statement.test, ast.Constant)
                       else _item_type_condition(statement.test, item))
            branches = [statement.body] if outcome is True else [statement.orelse] if outcome is False else [statement.body, statement.orelse]
            alternatives = [path for branch in branches for path in _selected_paths(branch, item, consume)]
            if len(paths) * len(alternatives) > 64:
                raise MatchTimeoutError("OpenAI Responses tool path limit exceeded")
            paths = [prior + alternative for prior in paths for alternative in alternatives]
        elif isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            return []
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            # Nested loops have independent control flow; do not merge their
            # tool result with an enclosing branch's feedback.
            continue
        else:
            nodes = list(_same_scope_nodes(statement))
            consume(len(nodes) * len(paths))
            paths = [prior + nodes for prior in paths]
    return paths


def _declared_tool_names(tree: ast.Module, tools: ast.AST) -> set[str]:
    if isinstance(tools, ast.Name):
        definitions = [statement.value for statement in tree.body
                       if isinstance(statement, ast.Assign) and
                       any(isinstance(target, ast.Name) and target.id == tools.id for target in statement.targets)]
        if len(definitions) != 1:
            return set()
        tools = definitions[0]
    if not isinstance(tools, (ast.List, ast.Tuple)):
        return set()
    names: set[str] = set()
    for definition in tools.elts:
        if not isinstance(definition, ast.Dict):
            continue
        fields = {key.value: value for key, value in zip(definition.keys, definition.values, strict=True)
                  if isinstance(key, ast.Constant) and isinstance(key.value, str)}
        name, kind = fields.get("name"), fields.get("type")
        if (isinstance(name, ast.Constant) and isinstance(name.value, str) and
                isinstance(kind, ast.Constant) and kind.value == "function"):
            names.add(name.value)
    return names


def _resets_input(nodes: list[ast.AST], input_name: str) -> bool:
    for node in nodes:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == input_name
                                                for target in node.targets):
            return True
        if isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name) and node.target.id == input_name:
            return True
        if isinstance(node, ast.Call) and _member(node.func, input_name, "clear"):
            return True
    return False


def _has_tool_feedback(nodes: list[ast.AST], item: str, input_name: str, static_tools: set[str]) -> bool:
    dynamic_tools: set[str] = set()
    for child in nodes:
        assignment = _assigned_call(child)
        if assignment and isinstance(assignment[1].func, ast.Attribute) and assignment[1].func.attr == "get":
            if any(_member(arg, item, "name") for arg in assignment[1].args):
                dynamic_tools.add(assignment[0])
        elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
            if isinstance(child.value, ast.Subscript) and _member(child.value.slice, item, "name"):
                dynamic_tools.add(child.targets[0].id)
    results: set[str] = set()
    for child in nodes:
        assignment = _assigned_call(child)
        if assignment is None:
            continue
        result, tool_call = assignment
        if (isinstance(tool_call.func, ast.Name) and tool_call.func.id in dynamic_tools or
                isinstance(tool_call.func, ast.Name) and tool_call.func.id in static_tools and
                any(_member(part, item, "arguments") for part in ast.walk(tool_call))):
            results.add(result)
    if not results:
        return False
    output_dicts = {id(child) for child in nodes if _tool_output_dict(child, item, results)}
    if not output_dicts:
        return False
    output_names = {
        child.targets[0].id for child in nodes
        if isinstance(child, ast.Assign) and len(child.targets) == 1 and
        isinstance(child.targets[0], ast.Name) and id(child.value) in output_dicts
    }
    return any(
        isinstance(child, ast.Call) and
        (_member(child.func, input_name, "append") and
         any(id(arg) in output_dicts or isinstance(arg, ast.Name) and arg.id in output_names
             for arg in child.args) or
         _member(child.func, input_name, "extend") and
         any(isinstance(arg, (ast.List, ast.Tuple)) and
             any(isinstance(part, ast.Name) and part.id == item for part in arg.elts) and
             any(id(part) in output_dicts or isinstance(part, ast.Name) and part.id in output_names
                 for part in arg.elts)
             for arg in child.args))
        for child in nodes
    )


def _can_repeat(loop: ast.For | ast.AsyncFor | ast.While) -> bool:
    if isinstance(loop, ast.While):
        return not (isinstance(loop.test, ast.Constant) and not loop.test.value)
    source = loop.iter
    if isinstance(source, (ast.List, ast.Tuple, ast.Set)):
        return len(source.elts) > 1
    if (isinstance(source, ast.Call) and isinstance(source.func, ast.Name) and source.func.id == "range" and
            not source.keywords and 1 <= len(source.args) <= 3 and
            all(isinstance(arg, ast.Constant) and type(arg.value) is int for arg in source.args)):
        try:
            return len(range(*(arg.value for arg in source.args))) > 1  # type: ignore[attr-defined]
        except (OverflowError, ValueError):
            return True
    return True


def _openai_tool_loop_calls(tree: ast.Module, calls: list[_Call]) -> list[_Call]:
    """Find a complete, iterative Responses function dispatch and feedback path.

    Import binding proves the model call; the AST requires its output to drive
    execution and return a tool result to the input of that same loop. A single
    function call, merely configured tools, or independent source idioms cannot
    promote an SDK import to an agent.
    """
    model_calls = [call for call in calls if call.node is not None and
                   call.binding.module == "openai" and call.binding.symbol.endswith(".responses.create")]
    if not model_calls:
        return []
    bound = {id(call.node): call for call in model_calls if call.node is not None}
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    # A static handler counts only when the same named function is declared
    # in the schema actually passed to this model call.
    local_functions = {node.name for node in tree.body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    loops: dict[int, ast.For | ast.AsyncFor | ast.While] = {}
    for call in model_calls:
        ancestor = parents.get(id(call.node))
        while ancestor is not None:
            if isinstance(ancestor, (ast.For, ast.AsyncFor, ast.While)):
                loops[id(ancestor)] = ancestor
                break
            if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                break
            ancestor = parents.get(id(ancestor))
    verified: list[_Call] = []
    work = 0

    def consume(amount: int) -> None:
        nonlocal work
        work += amount
        if work > MAX_TOOL_LOOP_AST_WORK:
            raise MatchTimeoutError("OpenAI Responses loop AST work limit exceeded")

    for loop in loops.values():
        if not _can_repeat(loop):
            continue
        nodes = list(_same_scope_nodes(loop))
        consume(len(nodes))
        for statement in nodes:
            assignment = _assigned_call(statement)
            if assignment is None:
                continue
            response, model_call = assignment
            sdk_call = bound.get(id(model_call))
            if not (sdk_call and sdk_call.binding.module == "openai" and
                    sdk_call.binding.symbol.endswith(".responses.create")):
                continue
            options = {keyword.arg: keyword.value for keyword in model_call.keywords if keyword.arg}
            input_arg = options.get("input")
            if not (isinstance(input_arg, ast.Name) and options.get("tools") is not None):
                continue
            if _resets_input(nodes, input_arg.id) or any(
                isinstance(child, (ast.Break, ast.Return, ast.Raise)) for child in loop.body
            ):
                continue
            static_tools = local_functions & _declared_tool_names(tree, options["tools"])
            # The function-call item and the feedback must be inside the same
            # repeated model call, and the result must feed the next input.
            selected_lists: set[str] = set()
            for child in nodes:
                if not (isinstance(child, ast.Assign) and len(child.targets) == 1 and
                        isinstance(child.targets[0], ast.Name) and isinstance(child.value, ast.ListComp) and
                        len(child.value.generators) == 1):
                    continue
                comprehension = child.value.generators[0]
                if (isinstance(comprehension.target, ast.Name) and
                        _member(comprehension.iter, response, "output") and
                        any(_function_call_filter(condition, comprehension.target.id)
                            for condition in comprehension.ifs)):
                    selected_lists.add(child.targets[0].id)
            consume(len(nodes))
            for selection in nodes:
                if not (isinstance(selection, (ast.For, ast.AsyncFor)) and
                        isinstance(selection.target, ast.Name) and
                        (_member(selection.iter, response, "output") or
                         isinstance(selection.iter, ast.Name) and selection.iter.id in selected_lists)):
                    continue
                item = selection.target.id
                has_function_filter = (isinstance(selection.iter, ast.Name) and
                                       selection.iter.id in selected_lists or
                                       any(_item_type_condition(child.test, item) is not None
                                           for child in ast.walk(selection)
                                           if isinstance(child, ast.If)))
                if not has_function_filter:
                    continue
                if any(_has_tool_feedback(path, item, input_arg.id, static_tools)
                       for path in _selected_paths(selection.body, item, consume)):
                    verified.append(sdk_call)
                    break
    return list(dict.fromkeys(verified))


def _javascript_bindings(text: str, ignored: list[tuple[int, int]]) -> tuple[list[_Call], list[tuple[_Binding, int]]]:
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

    rx = regex.compile(r"\b(?:const|let|var)\s+([\w$]+|\{[^}\r\n]{1,1000}\})\s*=\s*require\s*\(\s*(['\"])([^'\"\r\n]{1,240})\2\s*\)")
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
        if any(regex.search(pattern, rest, timeout=pattern_timeout(), concurrent=False) for pattern in patterns):
            del bindings[name]

    calls: list[_Call] = []
    rx = regex.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(?:<[^;(){}]{1,1000}>)?\s*\(")
    for match in rx.finditer(masked, timeout=pattern_timeout(), concurrent=False):
        parts = re.split(r"\s*\.\s*", match.group(1))
        binding = bindings.get(parts[0])
        if binding is None:
            continue
        if len(calls) >= MAX_BOUND_CALLS:
            raise MatchTimeoutError("source binding call limit exceeded")
        opening = match.end() - 1
        depth, end = 1, opening + 1
        while end < min(len(masked), opening + MAX_CALL_TEXT) and depth:
            depth += (masked[end] == "(") - (masked[end] == ")")
            end += 1
        if depth:
            continue
        symbol = ".".join(filter(None, (binding.symbol, *parts[1:])))
        calls.append(_Call(_Binding(binding.module, symbol), text[opening:end], text.count("\n", 0, match.start()) + 1,
                           masked[opening:end]))
    return calls, imports


def bound_source_matches(index: SignatureIndex, text: str, language: str, ignored: list[tuple[int, int]],
                         is_local_python_module: Callable[[str], bool] | None = None) -> list[Match]:
    """Return import and call evidence whose module provenance is resolved.

    Invalid Python cannot establish bound constructions. The caller already
    retains lexical import/supporting evidence and reports lexical ambiguity.
    """
    try:
        if language == "python":
            calls, imports, tree = _python_bindings(text)
        else:
            calls, imports = _javascript_bindings(text, ignored)
            tree = None
    except RecursionError as exc:
        raise MatchTimeoutError("source binding recursion limit exceeded") from exc
    except (SyntaxError, ValueError):
        return []
    found: list[Match] = []
    module_cache: dict[_Binding, list[Match]] = {}

    def module_matches(binding: _Binding) -> list[Match]:
        if binding not in module_cache:
            if language == "python":
                if is_local_python_module and is_local_python_module(binding.module):
                    # A checkout-local module can shadow the third-party SDK.
                    # The AST proves a name binding, not its package origin.
                    matches = []
                else:
                    statement = f"from {binding.module} import {binding.symbol.split('.')[0]}" if binding.symbol else f"import {binding.module}"
                    matches = index.match_imports(statement, language)
            else:
                matches = index.match_imports(f"import {{ example }} from '{binding.module}'", language)
                matches += index.match_dependency("npm", binding.module)
                if binding.module.startswith("@langchain/langgraph"):
                    matches = [m for m in matches if m.signature_id != "framework.langchain"]
            module_cache[binding] = matches
        return module_cache[binding]

    for binding, line in imports:
        for match in module_matches(binding):
            found.append(Match(match.signature, Signal(type="import", weight=match.weight),
                               sanitize_text(binding.module), match.weight, line=line,
                               extra={"verified_agent": False}))
        # Some signatures describe capabilities conveyed by a particular
        # imported tool. Retain those as supporting evidence, never an agent.
        if language == "python" and not (is_local_python_module and is_local_python_module(binding.module)):
            statement = f"from {binding.module} import {binding.symbol}" if binding.symbol else f"import {binding.module}"
            for match in index.match_code(statement, language):
                if match.signature_id in {m.signature_id for m in module_matches(binding)}:
                    match.line = line
                    match.extra["verified_agent"] = False
                    found.append(match)
    for call in calls:
        signatures = {m.signature_id: m.signature for m in module_matches(call.binding)}
        symbol = _symbol_tail(call.binding.symbol)
        canonical = symbol + call.arguments
        for signature in signatures.values():
            factory = _FACTORIES.get(signature.id)
            verified = bool(factory and re.fullmatch(factory, symbol))
            if signature.id == "framework.vercel-ai-sdk" and symbol in {"generateText", "streamText"}:
                # Options belong to a resolved SDK call, not unrelated config.
                verified = bool(re.search(r"\btools\s*:\s*\{", call.structural_arguments))
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
                    found.append(Match(signature, signal, sanitize_text(canonical[:len(symbol) + 1]), signal.weight,
                                       line=call.line, extra={"verified_agent": indicator}))
                    break
            if verified:
                found.append(Match(signature, Signal(type="code", weight=0.9, agent_indicator=True,
                                                     description="import-bound agent construction"),
                                   sanitize_text(f"{call.binding.module}:{symbol}("), 0.9, line=call.line,
                                   extra={"verified_agent": True}))
    if tree is not None:
        provider = index.get("provider.openai")
        if provider is not None:
            for call in _openai_tool_loop_calls(tree, calls):
                # The resolved module must match the provider signature. A
                # checkout-local openai.py may shadow the third-party SDK.
                if not any(m.signature_id == provider.id for m in module_matches(call.binding)):
                    continue
                found.append(Match(provider, Signal(type="code", weight=0.9, agent_indicator=True,
                                                    capabilities=["tool-use", "autonomous"],
                                                    description="iterative Responses tool dispatch and feedback"),
                                   "OpenAI Responses function call loop", 0.9, line=call.line,
                                   extra={"verified_agent": True}))
    return found
