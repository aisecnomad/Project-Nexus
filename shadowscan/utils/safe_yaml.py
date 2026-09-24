"""Bounded YAML construction for untrusted repository and inventory inputs.

SafeLoader prevents object construction, but does not bound alias expansion,
merge flattening, or downstream serialization. Validate the composed graph
before constructing any Python objects and account for its *expanded* size.
"""

from __future__ import annotations

from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class YAMLResourceLimitError(yaml.YAMLError):
    """The YAML input exceeds a fixed safety limit; its scan is incomplete."""


class BoundedSafeLoader(yaml.SafeLoader):
    """SafeLoader with stream, node, alias, depth and expanded-work budgets.

    Custom mapping constructors (e.g. duplicate-key validation) should inherit
    this loader. Limits apply across all documents in one stream. Small aliases
    and ordinary YAML merge keys remain supported; cyclic aliases are rejected.
    """

    MAX_INPUT_SIZE = 64 * 1024 * 1024
    MAX_NODES = 100_000
    MAX_ALIASES = 1_000
    MAX_DEPTH = 64
    MAX_EXPANDED_NODES = 100_000
    MAX_EXPANDED_CHARS = 64 * 1024 * 1024

    def __init__(self, stream: Any) -> None:
        if hasattr(stream, "read"):
            stream = stream.read(self.MAX_INPUT_SIZE + 1)
        if not isinstance(stream, (str, bytes)):
            raise TypeError("YAML input must be text, bytes, or a readable stream")
        if len(stream) > self.MAX_INPUT_SIZE:
            raise YAMLResourceLimitError("YAML input size limit exceeded")
        self._nodes_seen = 0
        self._aliases_seen = 0
        self._compose_depth = 0
        self._expanded_nodes = 0
        self._expanded_chars = 0
        self._flattened: set[Node] = set()
        self._merge_work = 0
        super().__init__(stream)

    def compose_node(self, parent: Any, index: Any) -> Node:
        self._nodes_seen += 1
        if self._nodes_seen > self.MAX_NODES:
            raise YAMLResourceLimitError("YAML node limit exceeded")
        if self.check_event(AliasEvent):
            self._aliases_seen += 1
            if self._aliases_seen > self.MAX_ALIASES:
                raise YAMLResourceLimitError("YAML alias limit exceeded")
        self._compose_depth += 1
        try:
            if self._compose_depth > self.MAX_DEPTH:
                raise YAMLResourceLimitError("YAML nesting limit exceeded")
            node = super().compose_node(parent, index)
            assert node is not None
            return node
        finally:
            self._compose_depth -= 1

    def compose_document(self) -> Node:
        node = super().compose_document()
        assert node is not None
        self._check_expansion(node)
        # Nodes from earlier documents cannot be referenced by later documents.
        self._flattened.clear()
        return node

    def _check_expansion(self, root: Node) -> None:
        memo: dict[Node, tuple[int, int, int]] = {}
        active: set[Node] = set()

        def cost(node: Node) -> tuple[int, int, int]:
            if node in active:
                raise YAMLResourceLimitError("YAML cyclic alias is not supported")
            if node in memo:
                return memo[node]
            if len(active) >= self.MAX_DEPTH:
                raise YAMLResourceLimitError("YAML expanded nesting limit exceeded")
            active.add(node)
            count, chars, height = 1, 0, 1
            if isinstance(node, ScalarNode):
                chars = len(node.value)
                children: list[Node] = []
            elif isinstance(node, MappingNode):
                children = [child for pair in node.value for child in pair]
            elif isinstance(node, SequenceNode):
                children = node.value
            else:
                children = []
            for child in children:
                child_count, child_chars, child_height = cost(child)
                count += child_count
                chars += child_chars
                height = max(height, child_height + 1)
                if count > self.MAX_EXPANDED_NODES or chars > self.MAX_EXPANDED_CHARS:
                    raise YAMLResourceLimitError("YAML alias expansion limit exceeded")
                if height > self.MAX_DEPTH:
                    raise YAMLResourceLimitError("YAML expanded nesting limit exceeded")
            active.remove(node)
            memo[node] = (count, chars, height)
            return memo[node]

        nodes, chars, _ = cost(root)
        self._expanded_nodes += nodes
        self._expanded_chars += chars
        if self._expanded_nodes > self.MAX_EXPANDED_NODES or self._expanded_chars > self.MAX_EXPANDED_CHARS:
            raise YAMLResourceLimitError("YAML expanded stream limit exceeded")

    def flatten_mapping(self, node: MappingNode) -> None:
        if node in self._flattened:
            return
        # Expansion was checked before construction, so each merge copy is
        # bounded. Memoization also prevents re-flattening shared mapping nodes.
        super().flatten_mapping(node)
        self._merge_work += len(node.value)
        if self._merge_work > self.MAX_EXPANDED_NODES:
            raise YAMLResourceLimitError("YAML merge work limit exceeded")
        self._flattened.add(node)


def bounded_safe_load(stream: Any) -> Any:
    """Load one bounded YAML document, retaining PyYAML's safe type semantics."""
    return yaml.load(stream, Loader=BoundedSafeLoader)
