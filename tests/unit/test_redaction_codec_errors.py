"""Assignment redaction survives the codec errors of Python 3.12+ tokenizers.

The C tokenizer of Python 3.12 and later raises UnicodeDecodeError for a
non-ASCII character right after a lone carriage return (a classic Mac line
ending, even inside a comment) and UnicodeEncodeError for a lone surrogate,
which a JSON export can carry. The assignment pass let both escape, so the
text could not be sanitized: a file with such a line made the scan
incomplete, and its findings were lost. The pass now reads such text as
source the tokenizer cannot finish, as it reads any other tokenizer error.
Python 3.11's tokenizer reads both; there these tests guard the same results.
"""

from __future__ import annotations

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.reporters.json_ import render_json
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

SECRET = "hunter2-opaque-value"


@pytest.mark.parametrize(
    "source",
    [
        f'password = "{SECRET}"\r\xa0\n',
        f"token: {SECRET}\rété\nmodel = 'gpt-4o'\n",
        # A classic Mac file is one physical line; here one of its lines starts with 'é'.
        f'import openai\rpassword = "{SECRET}"\rétape = 1\r',
        f'api_key = ("{SECRET}"  # note\r中\n)\nimport openai\n',
        f"credentials = {{\n    'token': '{SECRET}',  # \r\U0001f511\n}}\nimport openai\n",
        f'secret = "\ud800{SECRET}"\nimport openai\n',
    ],
)
def test_tokenizer_codec_errors_still_withhold_the_value(source):
    safe = sanitize_text(source)
    assert SECRET not in safe and REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


def test_metadata_with_a_lone_surrogate_is_sanitized():
    record = {"description": f'password = "\udcff{SECRET}"', "model": "gpt-4o"}
    assert sanitize(record) == {"description": f'password = "{REDACTED}"', "model": "gpt-4o"}


def test_a_carriage_return_before_non_ascii_text_leaves_the_scan_complete(tmp_path, index):
    (tmp_path / "app.py").write_bytes(
        f'import openai\nclient = openai.OpenAI()\npassword = "{SECRET}"\r \n'.encode()
    )
    config = ScanConfig(
        connectors=[ConnectorSpec(name="code.filesystem", config={"path": str(tmp_path), "use_git": False})]
    )
    result = Engine(config, index).run()
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    assert any("OpenAI" in finding.title for finding in result.findings)
    assert SECRET not in render_json(result)
