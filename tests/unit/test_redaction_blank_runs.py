"""Long runs of blanks are tokenized in linear time.

Python 3.11's pure-Python tokenizer rescans a run of spaces, tabs or form
feeds once per character when a character it cannot tokenize ('$', '?', a
control character, a lone quote) ends the run. The assignment pass tokenizes
from each sensitive candidate ('Authorization:', '${API_KEY:-',
'credentials = {') to the end of its statement, so a 60 KB run took minutes
and the file ran into the connector deadline: the scan was incomplete and
every finding was discarded. The tokenizer now reads long runs shortened,
which yields the same tokens, and positions are mapped back to the text.
"""

from __future__ import annotations

import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.utils import redaction
from shadowscan.utils.redaction import SanitizationLimitError, sanitize_text

ROOT = Path(__file__).resolve().parents[2]


def _bounded_process(script: str, *args: str) -> None:
    # A generous bound: linear work takes well under a second, while Python
    # 3.11 took minutes for each of these inputs before runs were shortened.
    result = subprocess.run(
        [sys.executable, "-c", script, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_long_blank_runs_are_redacted_in_linear_time():
    _bounded_process(r"""
import time
from shadowscan.utils.redaction import REDACTED, sanitize_text
key = '9f3c2a7b1d4e8f60a5b2c9d7e1f4a3b8'
blanks = ' ' * 60_000
cases = [
    # Header values that are references, then a credential the file still withholds.
    "curl -H 'Authorization: Bearer " + blanks + "$TOKEN'\napi_key = '" + key + "'\n",
    "Authorization: Token " + blanks + "?\npassword = '" + key + "'\n",
    "echo ${OPENAI_API_KEY:-" + blanks + "\x01}\ntoken = '" + key + "'\n",
    # Unfinished credential expressions are withheld through the end.
    "credentials = {" + ' \t' * 30_000 + "\x01 'token': '" + key + "'}\n",
    "password = (\n" + blanks + "$x, '" + key + "')\n",
    "password = \\\n" + '\t' * 60_000 + "?'" + key + "'\n",
]
for source in cases:
    started = time.perf_counter()
    safe = sanitize_text(source)
    elapsed = time.perf_counter() - started
    assert elapsed < 5, (source[:30], elapsed)
    assert key not in safe and REDACTED in safe, (source[:30], safe[-80:])
    assert safe.count('\n') == source.count('\n')
""")


def test_a_long_blank_run_leaves_a_full_scan_complete(tmp_path):
    # The security review's sample: on Python 3.11 the scan ran into the
    # connector deadline and discarded the LangChain agent finding.
    service = tmp_path / "svc"
    service.mkdir()
    (service / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\nexecutor = AgentExecutor(agent=None, tools=[])\n",
        encoding="utf-8",
    )
    (service / "deploy.py").write_text(
        "from langchain_openai import ChatOpenAI\n# curl -H 'Authorization: Bearer "
        + " " * 60_000
        + "$TOKEN'\n",
        encoding="utf-8",
    )
    _bounded_process(
        """
import sys
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.signatures import get_index
ctx = ConnectorContext(config={'path': sys.argv[1], 'use_git': False}, index=get_index())
findings = FilesystemConnector(ctx).run()
assert ctx.stats.objects_examined == 2, ctx.stats
assert not ctx.stats.errors, ctx.stats.errors
assert any('framework.langchain' in finding.frameworks for finding in findings), findings
""",
        str(tmp_path),
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # Positions after a shortened run map back to the text exactly.
        (
            'password = "a"' + " " * 40 + '; model = "gpt-4o"',
            'password = "[REDACTED]"; model = "gpt-4o"',
        ),
        (
            "f(api_key=" + "\t" * 30 + '"a",' + " " * 30 + 'model="gpt-4o")',
            "f(api_key=" + "\t" * 30 + '"[REDACTED]",' + " " * 30 + 'model="gpt-4o")',
        ),
        (
            'token: str = "a"' + " " * 20 + "# rotated" + " " * 20 + "\nimport openai\n",
            'token: "[REDACTED]"\nimport openai\n',
        ),
        # Continued lines inside brackets: their leading blanks are shortened.
        (
            "credentials = {\n" + " " * 30 + '"a": "b",\n' + " " * 30 + "}\nimport openai\n",
            'credentials = "[REDACTED]"\n\n\nimport openai\n',
        ),
    ],
)
def test_positions_after_shortened_runs_are_exact(source, expected):
    assert sanitize_text(source) == expected
    assert sanitize_text(expected) == expected


# Pieces of sensitive statements, and characters the Python 3.11 tokenizer
# cannot match ('$', '?', '!', '`', control and Unicode blanks).
_PIECES = [
    "password = ",
    "token: ",
    "api_key=",
    "credentials = {",
    'config["password"] = ',
    "x(api_key=",
    "${API_KEY:-",
    "Authorization: Bearer ",
    "token: str = ",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ";",
    ":",
    "=",
    "+",
    ".",
    '"v"',
    "'v'",
    '"',
    "'",
    '"""',
    "# note",
    "\\\n",
    "\n",
    "\n    ",
    "\n\t",
    "$",
    "?",
    "!",
    "`",
    "\x0b",
    "\x1c",
    "\xa0",
    "\x01",
    "a",
    "1",
    " ",
    "\t",
]


def _blank_run(rng: random.Random) -> str:
    return "".join(rng.choice(" \t\f") if rng.random() < 0.3 else " " for _ in range(rng.randint(9, 40)))


def test_shortened_blank_runs_match_whole_runs(monkeypatch):
    rng = random.Random(20261001)
    sources = [
        "".join(
            _blank_run(rng) if rng.random() < 0.25 else rng.choice(_PIECES) for _ in range(rng.randint(2, 40))
        )
        for _ in range(1500)
    ]
    shortened = []
    shorten = redaction._LineReader._shorten

    def counting(self: redaction._LineReader, line: str, row: int) -> str:
        result = shorten(self, line, row)
        shortened.append(result is not line)
        return result

    def redact(source: str) -> str:
        try:
            return redaction._redact_python_assignments(source)
        except SanitizationLimitError as exc:
            return f"limit: {exc}"

    blank_run = redaction._LONG_BLANK_RUN
    monkeypatch.setattr(redaction._LineReader, "_shorten", counting)
    # The default line limit, and one that cuts lines inside and around runs.
    for limit in (redaction._SCAN_LINE_LIMIT, 9):
        monkeypatch.setattr(redaction, "_SCAN_LINE_LIMIT", limit)
        monkeypatch.setattr(redaction, "_LONG_BLANK_RUN", re.compile(r"(?!)"))
        whole = [redact(source) for source in sources]
        monkeypatch.setattr(redaction, "_LONG_BLANK_RUN", blank_run)
        assert [redact(source) for source in sources] == whole, limit
    assert sum(shortened) > 1000  # runs were shortened, not merely shortenable
