"""The self-contained HTML report authorizes only its shipped script."""

from __future__ import annotations

import base64
import hashlib
import html as html_lib
from html.parser import HTMLParser

from shadowscan.models import Evidence, Finding, Kind, RiskFactor, ScanResult, ScanStats, Surface
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
    finding = Finding(
        surface=Surface.CODE,
        connector="test",
        kind=Kind.AGENT,
        title="</script><script>alert(1)</script>",
        resource="agent",
        resource_type="test",
    )
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


def _hostile(name: str) -> str:
    # Markup, both quote characters and an ampersand: enough to break out of a text node,
    # a single-quoted attribute or a double-quoted one if it were written raw.
    return f"<u>{name}</u>'\"&"


def test_every_untrusted_field_is_escaped_where_it_is_rendered():
    """One hostile marker per field: a field written without ``_e`` leaves a raw ``<u>`` in the page."""
    fields = {
        "connector": "connector",
        "title": "title",
        "resource": "resource",
        "resource-type": "resource_type",
        "provider": "provider",
        "account": "account",
        "region": "region",
        "owner": "owner",
        "first-seen": "first_seen",
        "last-seen": "last_seen",
        "registry-match": "registry_match",
    }
    finding = Finding(
        surface=Surface.CODE,
        kind=Kind.AGENT,
        models=[_hostile("model")],
        permissions=[_hostile("permission")],
        evidence=[
            Evidence(
                signal="test",
                description=_hostile("evidence-description"),
                location=_hostile("evidence-location"),
                snippet=_hostile("evidence-snippet"),
            )
        ],
        shadow=False,
        metadata={"note": _hostile("metadata")},
        **{attribute: _hostile(name) for name, attribute in fields.items()},
    )
    finding.risk.factors.append(RiskFactor("test", _hostile("risk-factor"), 5))
    stats = ScanStats(
        connector=_hostile("stats-connector"),
        started_at="2026-10-02T00:00:00Z",
        errors=[_hostile("diagnostic-error")],
        warnings=[_hostile("diagnostic-warning")],
    )
    result = ScanResult(version=_hostile("version"), findings=[finding], stats=[stats])
    page = render_html(result)
    assert "<u>" not in page, "a field was written without escaping"
    names = [*fields, "model", "permission", "evidence-description", "evidence-location", "evidence-snippet"]
    names += [
        "risk-factor",
        "metadata",
        "stats-connector",
        "diagnostic-error",
        "diagnostic-warning",
        "version",
    ]
    for name in names:
        assert html_lib.escape(f"<u>{name}</u>") in page, f"{name} is not rendered"
    # The attribute copy of the title cannot be closed early by its own quote characters.
    assert f"data-title='{html_lib.escape(_hostile('title'))}'" in page
