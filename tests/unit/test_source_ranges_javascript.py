"""JavaScript and TypeScript source ranges: JSX text is masked and TSX generics are not JSX."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind

VALID_TSX = {
    "type-arguments-on-child": (
        "export const A = () => (\n  <Box>\n    <Select<Option> value={v} onChange={set} />\n  </Box>\n);\n"
    ),
    "literal-type-arguments": (
        "export const B = () => (\n  <Box>\n    <Picker<'day' | 'hour'> value={u}>\n"
        "      <Item />\n    </Picker>\n  </Box>\n);\n"
    ),
    "object-type-arguments-at-expression": (
        "export const C = () => (\n  <Form<{ email: string; name: string }> onSubmit={go}>\n"
        "    <input />\n  </Form>\n);\n"
    ),
    "line-comment-with-apostrophe": (
        "export const D = () => (\n  <ul\n    // the browser's default list role\n"
        '    role="list"\n  >\n    <li>x</li>\n  </ul>\n);\n'
    ),
    "commented-out-attribute-expression": (
        "export const E = () => (\n  <input\n    // style={{\n    //   width: 1,\n    // }}\n"
        "    size={3}\n  />\n);\n"
    ),
    "block-comment-in-tag": "export const F = () => <input /* it's fine */ size={3} />;\n",
    "child-text-starting-with-parenthesis": "export const G = ({ n }: { n: number }) => <Text>({n})</Text>;\n",
}


@pytest.mark.parametrize("source", VALID_TSX.values(), ids=VALID_TSX.keys())
def test_valid_tsx_constructs_are_lexed_completely(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


def test_jsx_text_after_typed_element_stays_masked() -> None:
    source = (
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const View = () => (\n  <Box>\n    <Select<Option>\n"
        "      // the user's choice\n      value={v}\n    />\n"
        "    <Text>(createReactAgent( is documented here)</Text>\n  </Box>\n);\n"
        "const graph = createReactAgent({});\n"
    )
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    prose = source.index("createReactAgent( is")
    code = source.rindex("createReactAgent(")
    assert any(start <= prose < end for start, end in ignored)
    assert not any(start <= code < end for start, end in ignored)


@pytest.mark.parametrize(
    "source",
    [
        "const identity = <T>(value: T): T => value;\n",
        "const identity = <T>(value: T) => value;\n",
        "const constrained = <T extends object>(value: T): T => value;\n",
    ],
)
def test_generic_arrow_functions_are_not_jsx(source: str) -> None:
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert not any(start <= source.index("value") < end for start, end in ignored)


def test_unbalanced_type_arguments_still_fail_closed() -> None:
    _, ambiguous = noncode_ranges(
        "const v = (\n  <Box>\n    <Select<Option value={v} />\n", "javascript", ".tsx", jsx=True
    )
    assert ambiguous


def test_typed_jsx_component_file_scans_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "Agent.tsx").write_text(
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const Panel = () => (\n  <Box>\n    <Select<Option> value={v} />\n"
        "    <Text>({count})</Text>\n  </Box>\n);\n"
        "export const graph = createReactAgent({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "const a = <div /* note */>{x}</div>;\n",
        "const a = <div\n  // note\n>{x}</div>;\n",
        'const a = <div title="a/" /* note */>{x}</div>;\n',
    ],
)
def test_comment_before_tag_end_does_not_self_close(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


def test_self_closing_tag_after_comment_still_closes() -> None:
    source = "const a = <Box>\n  <input /* note */ />\n</Box>;\nconst b = run();\n"
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert not any(start <= source.index("run()") < end for start, end in ignored)
