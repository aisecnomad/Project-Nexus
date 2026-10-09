"""CommonJS and dynamic module loads are import evidence wherever they run.

In the real-world benchmark, a server loaded the Claude Agent SDK only through
`import("@anthropic-ai/claude-agent-sdk")` and through `require` calls inside
functions and `try` blocks, and no source evidence named the SDK. The import
signals describe ES `import ... from` statements; a load call is matched as that
statement would be, at the call's line.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SDK = "framework.claude-agent-sdk"


def _scan(tmp_path: Path, run_connector, name: str, source: str):
    (tmp_path / name).write_text(source)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False)


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "adapter.js",
            'let sdk;\nfunction load() {\n  if (!sdk) sdk = import("@anthropic-ai/claude-agent-sdk");\n  return sdk;\n}\n',
        ),
        (
            "proxy.js",
            "function start() {\n  try { var sdk = require('@anthropic-ai/claude-agent-sdk'); } catch (e) {}\n}\n",
        ),
        ("index.mjs", 'const { query } = await import("@anthropic-ai/claude-agent-sdk");\n'),
    ],
    ids=["lazy-dynamic-import", "require-in-try", "top-level-await-import"],
)
def test_module_loads_are_import_evidence(tmp_path: Path, run_connector, name: str, source: str) -> None:
    findings, ctx = _scan(tmp_path, run_connector, name, source)
    assert not ctx.stats.incomplete
    (project,) = [f for f in findings if f.resource_type == "project"]
    assert SDK in project.frameworks
    line = source[: source.index("claude-agent-sdk")].count("\n") + 1
    assert any(e.signal == f"import:{SDK}" and e.location == f"{name}:{line}" for e in project.evidence)


@pytest.mark.parametrize(
    "source",
    [
        '// const sdk = require("@anthropic-ai/claude-agent-sdk");\nconsole.log(1);\n',
        'const help = "run require(\\"@anthropic-ai/claude-agent-sdk\\") to start";\n',
        'const sdk = loader.require("@anthropic-ai/claude-agent-sdk");\n',
        'type Sdk = typeof import("@anthropic-ai/claude-agent-sdk");\n',
    ],
    ids=["comment", "string", "member-call", "type-query"],
)
def test_module_loads_in_comments_and_strings_are_not_evidence(
    tmp_path: Path, run_connector, source: str
) -> None:
    findings, _ = _scan(tmp_path, run_connector, "index.js", source)
    assert not any(SDK in f.frameworks for f in findings)
