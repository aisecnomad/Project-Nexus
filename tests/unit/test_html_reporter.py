"""The self-contained HTML report authorizes only its shipped script."""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser

from shadowscan.models import Finding, Kind, ScanResult, Surface
from shadowscan.reporters.html import _JS, render_html


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
