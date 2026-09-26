"""The JavaScript dispatch recognizer requires one ordered, bound source flow."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import javascript_dispatch
from shadowscan.connectors.code.source_ranges import noncode_ranges

SOURCE = '''import OpenAI from "openai";
const client = new OpenAI();
const response = await client.responses.create({model: "gpt-4o", tools: TOOLS, input: "query"});
for (const item of response.output) {
  if (item.type === "function_call") {
    const result = TOOLS[item.name](item.arguments);
  }
}
'''


def _recognize(source: str, constructor_lines: set[int] | None = None) -> list[int]:
    ignored, ambiguous = noncode_ranges(source, "javascript")
    assert not ambiguous
    if constructor_lines is None:
        constructor_lines = {line for line, text in enumerate(source.splitlines(), 1) if "new " in text}
    return javascript_dispatch.javascript_responses_dispatch_lines(source, ignored, constructor_lines)


def test_bound_single_dispatch_is_recognized():
    assert _recognize(SOURCE) == [3]


@pytest.mark.parametrize("source", [
    SOURCE.replace('import OpenAI from "openai";', 'import { OpenAI } from "openai";'),
    SOURCE.replace('import OpenAI from "openai";', 'import { OpenAI as OpenAI } from "openai";'),
    SOURCE.replace('import OpenAI from "openai";', 'import OpenAI, { helper } from "openai";'),
    SOURCE.replace('import OpenAI from "openai";', 'import OpenAI from "openai"; import { TOOLS } from "./tools";'),
    SOURCE.replace('import OpenAI from "openai";', 'import OpenAI from "openai"; import { lookup as helper, } from "./tools";'),
    SOURCE.replace("new OpenAI()", 'new OpenAI({apiKey: "example"})'),
    SOURCE.replace("new OpenAI()", "new OpenAI({maxRetries: 2, timeout: 1.5,})"),
    SOURCE.replace("new OpenAI()", "new OpenAI({flag: true, value: null, extra: undefined})"),
    SOURCE.replace('input: "query"', 'input: "query",'),
    SOURCE.replace("const result = TOOLS", "await TOOLS"),
    SOURCE.replace("TOOLS[item.name]", "handlers[item.name]"),
    SOURCE.replace("===", "=="),
    SOURCE.replace('"function_call"', "'function_call'"),
    SOURCE.replace("const client", "/* a comment with for (const item ...) */ const client"),
    SOURCE + "// extra inert content\n",
])
def test_supported_alias_options_comments_and_dispatch_variants(source):
    assert _recognize(source) == [3]


@pytest.mark.parametrize("source", [
    SOURCE.replace('"openai"', '"./openai"'),
    SOURCE.replace('import OpenAI from "openai";', 'import { Other as OpenAI } from "openai";'),
    SOURCE.replace('import OpenAI from "openai";', 'import OpenAI from "openai"; import OpenAI from "fake";'),
    SOURCE.replace('import OpenAI from "openai";', 'import { OpenAI, OpenAI } from "openai";'),
    SOURCE.replace("new OpenAI", "new LocalClient"),
    SOURCE.replace("new OpenAI", "OpenAI"),
    SOURCE.replace("const response", "client.responses.create = fake; const response"),
    SOURCE.replace("const response", "function unrelated() { const response") + "}\n",
    SOURCE.replace("const response", "if (false) { const response") + "}\n",
    SOURCE.replace("const response", "throw Error(); const response"),
    SOURCE.replace("for (const item", "function consume() { for (const item") + "}\n",
    SOURCE.replace("for (const item", "response = queue.take(); for (const item"),
    SOURCE.replace("for (const item", "if (false) { for (const item") + "}\n",
    SOURCE.replace("await client", "await unrelated"),
    SOURCE.replace("await client", "client"),
    SOURCE.replace("response.output", "differentResponse.output"),
    SOURCE.replace('item.type === "function_call"', 'item.type === "message"'),
    SOURCE.replace('item.type === "function_call"', 'other.type === "function_call"'),
    SOURCE.replace("const result =", "continue; const result ="),
    SOURCE.replace("const result =", "if (false) { const result =").replace("  }\n}", "  }}\n}"),
    SOURCE.replace("item.name", "other.name"),
    SOURCE.replace("item.arguments", "other.arguments"),
    SOURCE.replace("TOOLS[item.name](item.arguments)", "log(item.arguments)"),
    SOURCE.replace("tools: TOOLS", "tools: []"),
    SOURCE.replace("tools: TOOLS", "tools: null"),
    SOURCE.replace("tools: TOOLS", "tools: 'TOOLS'"),
    SOURCE.replace("tools: TOOLS", "inputTools: TOOLS"),
    SOURCE.replace("tools: TOOLS", "tools: TOOLS, tools: other"),
    SOURCE.replace("tools: TOOLS", "tools: factory()"),
    SOURCE.replace("tools: TOOLS", "tools: return"),
    SOURCE.replace("tools: TOOLS", "tools: {}"),
    SOURCE.replace("new OpenAI()", "new OpenAI(options)"),
    SOURCE.replace("const client", "const OpenAI"),
    SOURCE.replace("const result", "const item"),
    SOURCE.replace("const result", "const response"),
    SOURCE.replace("const result", "const TOOLS"),
    SOURCE.replace("const result", "const return"),
    SOURCE.replace("const result", "const 'result'"),
    SOURCE.replace("const result", "const 123"),
    SOURCE.replace("const response", "const client"),
    SOURCE.replace("for (const item", "for (let item"),
    SOURCE.replace("const result =", "const result = () =>"),
    SOURCE.replace('"function_call"', "`function_call`"),
    SOURCE.replace('"function_call"', '"function_\\u0063all"'),
    "/*\n" + SOURCE + "*/",
    "`" + SOURCE + "`",
    SOURCE.replace("for (const item", "// for (const item"),
    SOURCE.replace("item.arguments", "item.arguments + payload"),
    SOURCE + "sideEffect();\n",
    SOURCE.replace('import OpenAI from "openai";', 'import OpenAI from openai;'),
    SOURCE.replace('import OpenAI from "openai";', 'import { default as OpenAI } from "openai";'),
    SOURCE.replace('"function_call"', "function_call"),
])
def test_unsupported_or_unrelated_source_cannot_establish_dispatch(source):
    assert _recognize(source) == []


def test_import_binding_must_be_confirmed_by_caller():
    assert _recognize(SOURCE, set()) == []
    assert _recognize(SOURCE, {1}) == []
    # A multiline declaration still needs the constructor's precise line.
    assert _recognize(SOURCE.replace("const client", "const\nclient"), {2}) == []
    assert _recognize(SOURCE.replace("const client", "const\nclient"), {3}) == [4]


@pytest.mark.parametrize("length", [0, 1, 2, 20, 45, 80, 150, 200, 250, len(SOURCE) - 3])
def test_truncation_cannot_crash_or_supply_dispatch(length):
    text = SOURCE[:length]
    ignored, _ = noncode_ranges(text, "javascript")
    assert javascript_dispatch.javascript_responses_dispatch_lines(text, ignored, {2}) == []


def test_file_longer_than_the_grammar_is_a_plain_non_match(monkeypatch):
    # Only a small, complete program can match, so a longer file is an
    # unsupported shape: no dispatch evidence, and no incomplete scan.
    monkeypatch.setattr(javascript_dispatch, "MAX_TOKENS", 5)
    assert _recognize(SOURCE) == []


def test_mid_size_javascript_file_stays_complete_with_its_evidence(tmp_path, run_connector):
    # A file far larger than the dispatch grammar is an unsupported shape, not
    # an analysis gap: its ordinary SDK evidence is kept and the scan completes.
    (tmp_path / "package.json").write_text('{"name": "demo", "dependencies": {"openai": "^5.0.0"}}')
    (tmp_path / "app.js").write_text(SOURCE + "".join(f"const v{n} = compute({n}, other{n});\n" for n in range(6_000)))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any("provider.openai" in finding.model_providers for finding in findings)
