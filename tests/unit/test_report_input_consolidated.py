"""Bound hostile diagnostic streams and restrict self-contained report scripts."""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser

import pytest

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters.html import _JS, render_html


class _Probe(BaseConnector):
    name = "test.offline"

    def collect(self):
        return []

    def analyze(self, records):
        return []


@pytest.mark.parametrize("suffix", [".jsonl", ".json"])
def test_corrupt_record_flood_preserves_later_valid_record(tmp_path, index, suffix):
    source = tmp_path / f"export{suffix}"
    source.write_text("invalid\n" * 100 + '{"id":"survivor"}\n')
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    records = list(_Probe(ctx).load_offline(str(source)))
    assert records == [{"id": "survivor"}]
    assert ctx.stats.incomplete
    assert len(ctx.stats.errors) == BaseConnector._MAX_INVALID_LINE_ERRORS + 1
    assert "not listed individually" in ctx.stats.errors[-1]


def test_context_diagnostic_limits_preserve_failure_status(monkeypatch, index, caplog):
    monkeypatch.setattr(ConnectorContext, "_MAX_DIAGNOSTICS", 2)
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    for _ in range(10):
        ctx.warn("optional", incomplete=False)
    assert not ctx.stats.incomplete
    # A suppressed diagnostic must still mark missing required coverage.
    ctx.warn("required", incomplete=True)
    for _ in range(10):
        ctx.error("invalid record")
    assert ctx.stats.incomplete
    assert len(ctx.stats.errors) == len(ctx.stats.warnings) == 3
    assert len(caplog.records) == 6
    assert "diagnostic limit" in ctx.stats.errors[-1]


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.metas = []
        self.scripts = 0
        self.images = 0

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            self.metas.append(dict(attrs))
        self.scripts += tag == "script"
        self.images += tag == "img"


def test_report_csp_only_authorizes_shipped_script_and_escapes_numeric_slots():
    finding = Finding(surface=Surface.CODE, connector="test", kind=Kind.AGENT,
                      title="</script><script>alert(1)</script>", resource="agent", resource_type="test")
    # Direct library callers do not go through Finding.from_dict validation.
    finding.risk.score = "'><img src=x onerror=alert(1)>"  # type: ignore[assignment]
    result = ScanResult(version="test", findings=[finding])
    page = _Page()
    html = render_html(result)
    page.feed(html)
    policy = next(m["content"] for m in page.metas if m.get("http-equiv") == "Content-Security-Policy")
    expected = base64.b64encode(hashlib.sha256(_JS.encode()).digest()).decode()
    assert f"script-src 'sha256-{expected}'" in policy
    assert "script-src 'unsafe-inline'" not in policy
    assert "default-src 'none'" in policy and "base-uri 'none'" in policy and "form-action 'none'" in policy
    assert page.scripts == 1 and page.images == 0
    assert {"name": "referrer", "content": "no-referrer"} in page.metas
