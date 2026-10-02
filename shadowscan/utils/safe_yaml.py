"""Bounded YAML construction for untrusted repository and inventory inputs.

SafeLoader prevents object construction, but does not bound alias expansion,
merge flattening, or downstream serialization. Validate the composed graph
before constructing any Python objects and account for its *expanded* size.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any, ClassVar

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class YAMLResourceLimitError(yaml.YAMLError):
    """The YAML input exceeds a fixed safety limit; its scan is incomplete."""


class YAMLConstructionError(yaml.constructor.ConstructorError):
    """A scalar is invalid for its explicit or implicit tag; the message gives its position only.

    PyYAML's SafeConstructor converts scalars with ``int()``, ``float()``,
    ``datetime`` and table lookups and lets the builtin exception escape:
    ``!!bool x`` raises ``KeyError``, ``!!int ''`` ``IndexError``,
    ``!!timestamp ---`` ``AttributeError`` and ``2024-02-30`` ``ValueError``.
    Handlers written for ``yaml.YAMLError`` miss them, and their text echoes
    the scalar, which can be a credential.
    """


# Tags whose scalars SafeConstructor converts arithmetically. A YAML 1.1 sexagesimal
# integer (``1:1:1:...``) is built by repeated big-integer multiplication, which is
# quadratic in its length: 80 KB takes about 0.5 s and 1 MB about a minute, and the
# input limit alone would allow hours.
_NUMBER_TAGS: frozenset[str] = frozenset({"tag:yaml.org,2002:int", "tag:yaml.org,2002:float"})

# The exact builtin types SafeConstructor leaks for a malformed scalar.
# Subclasses are deliberate diagnostics of a loader subclass (for example the
# configuration loader's ConfigValidationError, a ValueError) and pass through.
_CONSTRUCTOR_LEAKS: frozenset[type[Exception]] = frozenset(
    {AttributeError, IndexError, KeyError, OverflowError, TypeError, ValueError}
)


def _construction_failure(exc: Exception, node: Node) -> yaml.YAMLError | None:
    """Return the value-free YAMLError for an exception leaked by construction, or None to re-raise it."""
    if isinstance(exc, RecursionError):
        return YAMLResourceLimitError("YAML nesting limit exceeded")
    if type(exc) not in _CONSTRUCTOR_LEAKS:
        return None
    mark = getattr(node, "start_mark", None)
    # A mark without its buffer renders as a position, never a source excerpt.
    position = None if mark is None else yaml.Mark(mark.name, mark.index, mark.line, mark.column, None, 0)
    return YAMLConstructionError(problem="YAML value is invalid for its type", problem_mark=position)


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
    # Longest integer or float scalar converted. A real number is far shorter than this.
    # Python itself refuses a decimal integer beyond 4300 digits, which is reported as an
    # invalid scalar; this bound is above that and covers the sexagesimal form, whose
    # conversion is quadratic (10,000 characters cost about 15 ms).
    MAX_NUMBER_CHARS = 10_000

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

    def construct_object(self, node: Node, deep: bool = False) -> Any:
        if (
            node.tag in _NUMBER_TAGS
            and isinstance(node, ScalarNode)
            and len(node.value) > self.MAX_NUMBER_CHARS
        ):
            raise YAMLResourceLimitError("YAML number length limit exceeded")
        # The innermost node that fails supplies the reported position.
        try:
            return super().construct_object(node, deep=deep)
        except Exception as exc:
            error = _construction_failure(exc, node)
            if error is None:
                raise
            raise error from None

    def construct_document(self, node: Node) -> Any:
        # Also covers generator-based constructors drained after construct_object returned.
        try:
            return super().construct_document(node)
        except Exception as exc:
            error = _construction_failure(exc, node)
            if error is None:
                raise
            raise error from None


def bounded_safe_load(stream: Any) -> Any:
    """Load one bounded YAML document, retaining PyYAML's safe type semantics."""
    return yaml.load(stream, Loader=BoundedSafeLoader)


def bounded_safe_load_all(stream: Any) -> list[Any]:
    """Load a bounded stream of YAML documents with the same limits as ``bounded_safe_load``."""
    return list(yaml.load_all(stream, Loader=BoundedSafeLoader))


class YAMLIntegrityError(yaml.YAMLError):
    """An offline mapping has ambiguous or unsupported keys, without source text."""


_MERGE_KEY = object()


class StrictBoundedSafeLoader(BoundedSafeLoader):
    """Bounded offline YAML with unique string keys in every source mapping.

    Validate before merge flattening: ordinary YAML merge inheritance and an
    explicit override remain supported, but repeated keys in a source mapping
    (including a merged anchor) cannot silently discard earlier observations.
    """

    REQUIRE_STRING_KEYS: ClassVar[bool] = True

    def flatten_mapping(self, node: MappingNode) -> None:
        if node not in self._flattened:
            keys: set[Any] = set()
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    key = _MERGE_KEY
                else:
                    key = self.construct_object(key_node)
                    if self.REQUIRE_STRING_KEYS and not isinstance(key, str):
                        raise YAMLIntegrityError("Offline YAML mapping keys must be strings")
                    try:
                        hash(key)
                    except TypeError:
                        raise YAMLIntegrityError("YAML mapping keys must be scalar") from None
                if key in keys:
                    raise YAMLIntegrityError("Duplicate YAML field")
                keys.add(key)
        super().flatten_mapping(node)


class StrictBoundedConfigLoader(StrictBoundedSafeLoader):
    """Strict repository YAML retaining SafeLoader's standard typed keys.

    PyYAML follows YAML 1.1 and resolves common configuration keys such as
    unquoted ``on`` to booleans. Repository formats such as GitHub Actions use
    that spelling as a key, so code scanning must accept it while still
    rejecting fields that collide after construction.
    """

    REQUIRE_STRING_KEYS: ClassVar[bool] = False


def _validate_strict_yaml_values(values: list[Any], *, max_depth: int) -> None:
    """Reject non-finite values in one already bounded YAML stream."""
    remaining = 100_000
    active: set[int] = set()

    def validate(item: Any, depth: int = 0) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > max_depth:
            raise YAMLResourceLimitError("YAML validation limit exceeded")
        if isinstance(item, float) and not math.isfinite(item):
            raise YAMLIntegrityError("Nonfinite YAML number")
        if not isinstance(item, (dict, list, tuple, set, frozenset)):
            return
        identity = id(item)
        if identity in active:
            raise YAMLResourceLimitError("YAML cyclic alias is not supported")
        active.add(identity)
        try:
            children: Iterable[Any]
            if isinstance(item, dict):
                children = (child for pair in item.items() for child in pair)
            else:
                children = item
            for child in children:
                validate(child, depth + 1)
        finally:
            active.remove(identity)

    for value in values:
        validate(value)


def strict_bounded_safe_load(stream: Any, *, require_string_keys: bool = True) -> Any:
    """Load bounded offline YAML without ambiguous or non-finite values.

    PyYAML deliberately accepts ``.nan`` and infinities, but those values have
    no interoperable JSON representation and can poison later risk arithmetic.
    Validate the fully constructed graph here so aliases receive the same rule.
    """
    loader = StrictBoundedSafeLoader if require_string_keys else StrictBoundedConfigLoader
    value = yaml.load(stream, Loader=loader)
    _validate_strict_yaml_values([value], max_depth=loader.MAX_DEPTH)
    return value


def strict_bounded_safe_load_all(stream: Any, *, require_string_keys: bool = True) -> list[Any]:
    """Load a bounded YAML stream with strict integrity checks on every document."""
    loader = StrictBoundedSafeLoader if require_string_keys else StrictBoundedConfigLoader
    values = list(yaml.load_all(stream, Loader=loader))
    _validate_strict_yaml_values(values, max_depth=loader.MAX_DEPTH)
    return values
