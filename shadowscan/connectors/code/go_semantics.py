"""Import-bound LangChainGo constructors, without loading scanned Go code.

Only exact imports of the agents package and unshadowed receivers qualify.
Dot/blank imports and uncertain local declarations remain framework evidence.
"""

from __future__ import annotations

from shadowscan.connectors.code.polyglot_bindings import (
    IDENTIFIER,
    MAX_CALLS,
    SourceTokens,
    source_tokens,
)
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import Signal
from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

_PACKAGE = "github.com/tmc/langchaingo/agents"
_FACTORIES = {"NewExecutor", "NewOneShotAgent", "NewConversationalAgent"}
# Keywords that never end a line; break, continue, fallthrough and return do.
_OPEN_KEYWORDS = frozenset(
    {
        "case",
        "chan",
        "const",
        "default",
        "defer",
        "else",
        "for",
        "func",
        "go",
        "goto",
        "if",
        "import",
        "interface",
        "map",
        "package",
        "range",
        "select",
        "struct",
        "switch",
        "type",
        "var",
    }
)


def _ends_line(source: SourceTokens, position: int) -> bool:
    """Whether Go inserts a semicolon after this token (the spec's lexical rule)."""
    word = source.words[position]
    if position + 1 >= len(source.words):
        return False
    if "\n" not in source.text[source.starts[position] + len(word) : source.starts[position + 1]]:
        return False
    return word not in _OPEN_KEYWORDS and (word[-1].isalnum() or word[-1] in "_)]}\"`'")


def _imports(source: SourceTokens) -> dict[str, bool]:
    words = source.words
    bindings: dict[str, bool] = {}
    for i, word in enumerate(words):
        if word != "import":
            continue
        start = i + 1
        end = source.pairs.get(start, start + 2) if words[start : start + 1] == ["("] else start + 2
        for j in range(start, min(end + 1, len(words))):
            value = words[j]
            if not value.startswith(('"', "`")):
                continue
            path = value[1:-1]
            alias = (
                words[j - 1] if j > start and IDENTIFIER.fullmatch(words[j - 1]) else path.rsplit("/", 1)[-1]
            )
            if j > start and words[j - 1] == ".":
                continue
            if alias == "_":
                continue
            bindings[alias] = path == _PACKAGE and alias not in bindings
    return bindings


def _parameter_names(source: SourceTokens, opening: int, names: set[str]) -> set[str]:
    words = source.words
    # Scalar, pointer and tuple return signatures can lie between parameters
    # and the body. Find the func header, then its argument list; never mistake
    # the tuple return list for the shadowing parameter declarations.
    cursor = opening - 1
    floor = max(0, opening - 256)
    header = None
    while cursor >= floor:
        if words[cursor] == "}" and cursor in source.reverse:
            start = source.reverse[cursor]
            if start and words[start - 1] in {"struct", "interface"}:
                cursor = start - 1
                continue
        # A newline that ends the previous line is a statement boundary too:
        # `type Option func(...)` before this header is not its declaration.
        if words[cursor] in {";", "{", "}"} or _ends_line(source, cursor):
            break
        if words[cursor] == "func":
            header = cursor
        cursor -= 1
    if cursor < floor and header is None and floor > 0:
        return names.copy()  # an unread long header cannot preserve package proof
    if header is None:
        return set()
    parameters = header + 1
    lists: list[tuple[int, int]] = []
    if words[parameters : parameters + 1] == ["("]:
        close = source.pairs.get(parameters, parameters)
        if close + 2 < opening and IDENTIFIER.fullmatch(words[close + 1]) and words[close + 2] in {"(", "["}:
            lists.append((parameters + 1, close))
            parameters = close + 2  # method receiver precedes its declared name
    elif parameters < opening and IDENTIFIER.fullmatch(words[parameters]):
        parameters += 1
    if words[parameters : parameters + 1] == ["["]:
        parameters = source.pairs.get(parameters, parameters) + 1
    if words[parameters : parameters + 1] != ["("]:
        return names.copy()
    close = source.pairs.get(parameters, parameters)
    lists.append((parameters + 1, close))
    if words[close + 1 : close + 2] == ["("]:
        lists.append((close + 2, source.pairs.get(close + 1, close + 1)))
    return {
        words[j]
        for start, stop in lists
        for j in range(start, stop)
        if words[j] in names and words[j + 1 : j + 2] != ["."]
    }


def langchaingo_agent_matches(
    index: SignatureIndex, text: str, ignored: list[tuple[int, int]]
) -> list[Match]:
    signature = index.signatures.get("framework.langchaingo")
    if signature is None or _PACKAGE not in text:
        return []
    source = source_tokens(text, ignored, "Go")
    words = source.words
    imports = _imports(source)
    scopes: list[dict[str, bool]] = [imports]
    names = set(imports)
    result: list[Match] = []
    for i, word in enumerate(words):
        if not i % 256:
            pattern_timeout()
        if word == "{":
            scopes.append(dict.fromkeys(_parameter_names(source, i, names), False))
            continue
        if word == "}":
            if len(scopes) > 1:
                scopes.pop()
            continue
        if word in {"var", "const", "type", "func"} and i + 1 < len(words) and words[i + 1] in names:
            scopes[-1][words[i + 1]] = False
        if word == ":=":
            # The lhs ends at a statement/newline boundary; multi-name short
            # declarations shadow each package alias they introduce.
            j = i - 1
            while j >= 0 and words[j] not in {";", "{", "}"}:
                if j + 1 < i and "\n" in text[source.starts[j] : source.starts[j + 1]]:
                    break
                if words[j] in names:
                    scopes[-1][words[j]] = False
                j -= 1
        if word in {"var", "const"} and words[i + 1 : i + 2] == ["("]:
            end = source.pairs.get(i + 1, i + 1)
            for j in range(i + 2, end):
                if words[j] in names and words[j + 1 : j + 2] != ["."]:
                    scopes[-1][words[j]] = False
        if (
            word not in names
            or i
            and words[i - 1] == "."
            or words[i + 1 : i + 2] != ["."]
            or i + 3 >= len(words)
            or words[i + 2] not in _FACTORIES
            or words[i + 3] != "("
        ):
            continue
        bound = next((scope[word] for scope in reversed(scopes) if word in scope), False)
        if not bound:
            continue
        if len(result) >= MAX_CALLS:
            raise MatchTimeoutError("Go import proof call budget exceeded")
        result.append(
            Match(
                signature,
                Signal(type="code", weight=0.9, agent_indicator=True, capabilities=["tool-use"]),
                f"{_PACKAGE}:{words[i + 2]}(",
                0.9,
                line=source.line(i),
                extra={"verified_agent": True, "source_capabilities": ["tool-use"]},
            )
        )
    return result
