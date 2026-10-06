"""Self-contained HTML report (no external assets) with filtering and evidence drill-down."""

from __future__ import annotations

import base64
import hashlib
import html
import json

from shadowscan.compliance import compliance_references
from shadowscan.models import ScanResult
from shadowscan.reporters._publication import publication_stats, related_finding_ids, visible_controls

_CSS = (
    "\n"
    ":root{--bg:#0f1117;--card:#171a23;--fg:#e6e6e6;--muted:#9aa0ad;--line:#262a36;--critical:#ff4d4f;"
    "--critical-text:#ff4d4f;--high:#ff9c2b;--medium:#f5d90a;--low:#3ddc84;--info:#8c8c8c;--accent:#7aa2f7}\n"
    "@media (prefers-color-scheme: light){:root{--bg:#fafafa;--card:#fff;--fg:#1a1a1a;--muted:#5f6670;"
    "--line:#e3e5ea;--accent:#2a55b8;--critical-text:#c8161c}}\n"
    "*{box-sizing:border-box}body{margin:0;"
    "font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);"
    "color:var(--fg)}\n"
    "header{padding:24px 32px;border-bottom:1px solid var(--line)}h1{margin:0 0 4px;font-size:22px}"
    "h1 span{color:var(--muted);font-weight:400;font-size:14px;margin-left:8px}\n"
    ".stats{display:flex;flex-wrap:wrap;gap:12px;padding:16px 32px}.stat{background:var(--card);"
    "border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px}"
    ".stat b{display:block;font-size:20px}\n"
    ".controls{display:flex;flex-wrap:wrap;gap:8px;padding:0 32px 12px}"
    ".controls input,.controls select{background:var(--card);color:var(--fg);border:1px solid var(--line);"
    "border-radius:6px;padding:6px 8px}\n"
    "table{width:calc(100% - 64px);margin:0 32px 32px;border-collapse:collapse;background:var(--card);"
    "border:1px solid var(--line);border-radius:8px;overflow:hidden}\n"
    "th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}"
    "th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}"
    "th button,td button.toggle{all:unset;cursor:pointer}th button{color:inherit;font:inherit;"
    "text-transform:inherit;letter-spacing:inherit}"
    "th button:focus-visible,td button.toggle:focus-visible{outline:2px solid var(--accent);"
    "outline-offset:2px}\n"
    "tr.row{cursor:pointer}tr.row:hover{background:rgba(122,162,247,.08)}tr.detail{display:none}"
    "tr.detail.open{display:table-row}tr.detail td{background:var(--bg);padding:14px 18px}\n"
    ".pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;"
    "color:#000}.critical{background:var(--critical)}.high{background:var(--high)}"
    ".medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}\n"
    ".tag{display:inline-block;background:rgba(122,162,247,.15);color:var(--accent);border-radius:4px;"
    "padding:1px 6px;margin:1px 2px;font-size:12px}.shadow{color:var(--critical-text);font-weight:700}\n"
    ".muted{color:var(--muted)}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;"
    "background:rgba(127,127,127,.12);padding:1px 4px;border-radius:3px}\n"
    "ul{margin:6px 0 10px 18px;padding:0}li{margin:2px 0}.ev{margin:4px 0}.ev .w{color:var(--muted);"
    "font-size:12px;margin-right:6px}pre{white-space:pre-wrap;background:rgba(127,127,127,.12);"
    "padding:6px 8px;border-radius:4px;font-size:12px;margin:4px 0}\n"
    "footer{padding:16px 32px;color:var(--muted);font-size:12px}\n"
)

_JS = (
    "\n"
    "const rows=[...document.querySelectorAll('tr.row')];\n"
    "function apply(){const q=document.getElementById('q').value.toLowerCase();"
    "const lvl=document.getElementById('lvl').value;const sf=document.getElementById('sf').value;"
    "const sh=document.getElementById('sh').value;\n"
    "rows.forEach(r=>{const d=r.nextElementSibling;const ok=(!q||r.dataset.text.includes(q))&&"
    "(!lvl||r.dataset.level===lvl)&&(!sf||r.dataset.surface===sf)&&(!sh||r.dataset.shadow===sh);"
    "r.style.display=ok?'':'none';if(!ok)d.classList.remove('open');});\n"
    "document.getElementById('shown').textContent=rows.filter(r=>r.style.display!=='none').length;}\n"
    "['q','lvl','sf','sh'].forEach(id=>document.getElementById(id).addEventListener('input',apply));\n"
    "function toggle(r){const d=r.nextElementSibling;const open=d.classList.toggle('open');"
    "const b=r.querySelector('button.toggle');if(b)b.setAttribute('aria-expanded',open?'true':'false');}\n"
    "rows.forEach(r=>{r.addEventListener('click',()=>toggle(r));const b=r.querySelector('button.toggle');"
    "if(b)b.addEventListener('click',e=>{e.stopPropagation();toggle(r);});});\n"
    "document.querySelectorAll('th[data-k]').forEach(th=>th.querySelector('button').addEventListener('click',"
    "()=>{const k=th.dataset.k;const tb=th.closest('table').querySelector('tbody');"
    "const pairs=rows.map(r=>[r,r.nextElementSibling]);const dir=th.dataset.dir==='asc'?'desc':'asc';"
    "th.dataset.dir=dir;"
    "document.querySelectorAll('th[data-k]').forEach(o=>o.setAttribute('aria-sort','none'));"
    "th.setAttribute('aria-sort',dir==='asc'?'ascending':'descending');\n"
    "pairs.sort((a,b)=>{const x=a[0].dataset[k],y=b[0].dataset[k];const nx=parseFloat(x),ny=parseFloat(y);"
    "const c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:String(x).localeCompare(String(y));return dir==='asc'?c:-c;});"
    "pairs.forEach(p=>{tb.appendChild(p[0]);tb.appendChild(p[1]);});}));\n"
    "apply();\n"
)


def _e(s: object) -> str:
    """Escape markup and show terminal controls, so ``cat report.html`` cannot run escape sequences."""
    text = "" if s is None else str(s).replace("\r\n", "\n")
    return html.escape(visible_controls(text, keep="\t\n"))


def _tags(values: list[str]) -> str:
    return "".join(f"<span class=tag>{_e(value)}</span>" for value in values)


_LEVELS = ("critical", "high", "medium", "low", "info")
_COLUMNS = (
    ("score", "Risk"),
    ("shadow", "Shadow"),
    ("surface", "Surface"),
    ("kind", "Kind"),
    ("title", "Title"),
    ("owner", "Owner"),
    ("confidence", "Conf."),
)


def render_html(result: ScanResult) -> str:
    for finding in result.findings:
        finding.sanitize()
    s = result.summary()
    parts: list[str] = []
    script_hash = base64.b64encode(hashlib.sha256(_JS.encode("utf-8")).digest()).decode("ascii")
    # Permit only the shipped filter/sort script. Finding text cannot authorize
    # another script or trigger outbound resource loads if escaping regresses.
    parts.append(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        f"script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'\">"
        "<meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>ShadowScan report</title><style>" + _CSS + "</style></head><body>"
    )
    parts.append(
        f"<header><h1>ShadowScan report <span>v{_e(result.version)} · "
        f"{_e(result.finished_at or result.started_at)}</span></h1>"
        "<div class='muted'>Shadow AI agent discovery across code, identity, gateways, low-code,"
        " SaaS and cloud.</div></header>"
    )
    if not result.complete:
        parts.append(
            "<div class='controls'><strong class='shadow'>INCOMPLETE SCAN — some required inputs"
            " could not be assessed. Review connector statistics.</strong></div>"
        )
    parts.append("<div class='stats'>")
    parts.append(f"<div class='stat'><b>{s['total']}</b>findings</div>")
    if result.inventory_size:
        parts.append(
            f"<div class='stat'><b class='shadow'>{s['shadow']}</b>shadow (unregistered)</div>"
            f"<div class='stat'><b>{_e(result.inventory_size)}</b>registered agents</div>"
        )
    for lvl in _LEVELS:
        count = s["by_risk_level"].get(lvl, 0)
        parts.append(f"<div class='stat'><b><span class='pill {lvl}'>{count}</span></b>{lvl}</div>")
    for k, v in sorted(s["by_surface"].items()):
        parts.append(f"<div class='stat'><b>{v}</b>{_e(k)}</div>")
    parts.append("</div>")
    surfaces = sorted(s["by_surface"])
    parts.append(
        "<div class='controls'><input id='q' aria-label='Filter findings' placeholder='filter…' size='40'>"
    )
    parts.append(
        "<select id='lvl' aria-label='Risk level'><option value=''>all risk levels</option>"
        + "".join(f"<option value='{level}'>{level}</option>" for level in _LEVELS)
        + "</select>"
    )
    parts.append(
        "<select id='sf' aria-label='Surface'><option value=''>all surfaces</option>"
        + "".join(f"<option value='{_e(x)}'>{_e(x)}</option>" for x in surfaces)
        + "</select>"
    )
    parts.append(
        "<select id='sh' aria-label='Shadow status'><option value=''>shadow: any</option>"
        "<option value='yes'>shadow only</option><option value='no'>registered only</option></select>"
    )
    parts.append(
        "<span class='muted' role='status' style='align-self:center'>"
        "showing <span id='shown'></span> findings</span></div>"
    )
    parts.append(
        "<table><thead><tr>"
        + "".join(
            f"<th data-k='{k}' aria-sort='none'><button type='button'>{label}</button></th>"
            for k, label in _COLUMNS
        )
        + "<th>Technologies</th></tr></thead><tbody>"
    )
    for n, f in enumerate(result.findings):
        shadow = "" if f.shadow is None else ("yes" if f.shadow else "no")
        level = f.risk.level.value
        labels = " ".join(f.frameworks + f.model_providers + f.tags + f.capabilities)
        text = " ".join(
            [
                f.title,
                f.resource,
                f.owner or "",
                labels,
                f.kind.value,
                f.surface.value,
                f.provider or "",
            ]
        ).lower()
        parts.append(
            f"<tr class='row' data-score='{_e(f.risk.score)}' data-level='{level}' data-shadow='{shadow}'"
            f" data-surface='{_e(f.surface.value)}' data-kind='{_e(f.kind.value)}' data-title='{_e(f.title)}'"
            f" data-owner='{_e(f.owner or '')}' data-confidence='{_e(f.confidence)}' data-text='{_e(text)}'>"
        )
        shadow_cell = "<span class=shadow>SHADOW</span>" if f.shadow else _e(f.registry_match or shadow)
        parts.append(
            f"<td><span class='pill {level}'>{level} {_e(f.risk.score)}</span></td><td>{shadow_cell}</td>"
            f"<td>{_e(f.surface.value)}</td><td>{_e(f.kind.value)}</td>"
            f"<td><button type='button' class='toggle' aria-expanded='false' aria-controls='d{n}'>"
            f"{_e(f.title)}</button><br><code>{_e(f.resource)}</code></td><td>{_e(f.owner or '—')}</td>"
            f"<td>{f.confidence:.2f}</td><td>{_tags((f.frameworks + f.model_providers)[:6])}</td></tr>"
        )
        parts.append(f"<tr class='detail' id='d{n}'><td colspan='8'>")
        parts.append(
            f"<div><b>Id</b> <code>{_e(f.id)}</code> · <b>connector</b> <code>{_e(f.connector)}</code>"
            f" · <b>type</b> {_e(f.resource_type)} · <b>where</b> {_e(f.provider or '')}"
            f" {_e(f.account or '')} {_e(f.region or '')} · <b>seen</b> {_e(f.first_seen or '?')}"
            f" → {_e(f.last_seen or '?')}</div>"
        )
        if f.capabilities:
            parts.append("<div><b>Capabilities</b> " + _tags(f.capabilities) + "</div>")
        if f.tags:
            parts.append("<div><b>Tags</b> " + _tags(f.tags) + "</div>")
        compliance = compliance_references(f.tags)
        if compliance:
            parts.append("<div><b>Compliance</b> " + _tags(compliance) + "</div>")
        if f.models:
            parts.append(f"<div><b>Models</b> {_e(', '.join(f.models[:8]))}</div>")
        if f.permissions:
            more = " …" if len(f.permissions) > 20 else ""
            parts.append(f"<div><b>Permissions</b> {_e(', '.join(f.permissions[:20]))}{more}</div>")
        related = related_finding_ids(f.metadata)
        if related:
            codes = " ".join(f"<code>{_e(r)}</code>" for r in related)
            parts.append("<div><b>Related</b> " + codes + "</div>")
        activity = f.metadata.get("runtime_activity")
        if isinstance(activity, dict):
            parts.append(
                f"<div><b>Gateway activity</b> {_e(activity.get('status'))};"
                f" matching events: {_e(activity.get('events', 0))};"
                f" production observed: {_e(activity.get('production_observed', False))}</div>"
            )
            parts.append(f"<div class='muted'>{_e(activity.get('limitations', ''))}</div>")
        factors = [x for x in f.risk.factors if x.weight]
        if factors:
            items = "".join(
                f"<li>{'+' if x.weight > 0 else ''}{x.weight} {_e(x.description)}</li>" for x in factors
            )
            parts.append("<div><b>Risk factors</b><ul>" + items + "</ul></div>")
        parts.append("<div><b>Evidence</b>")
        for e in sorted(f.evidence, key=lambda e: -e.weight)[:20]:
            location = (" — <code>" + _e(e.location) + "</code>") if e.location else ""
            snippet = ("<pre>" + _e(e.snippet) + "</pre>") if e.snippet else ""
            parts.append(
                f"<div class='ev'><span class='w'>{e.weight:.2f}</span>"
                f"{_e(e.description)}{location}{snippet}</div>"
            )
        if len(f.evidence) > 20:
            parts.append(f"<div class='muted'>… {len(f.evidence) - 20} more</div>")
        parts.append("</div>")
        hidden = {"related", "technologies", "evidence_counts", "agent_indicators", "scan_root"}
        meta = {k: v for k, v in f.metadata.items() if k not in hidden}
        if meta:
            dumped = _e(json.dumps(meta, indent=2, default=str)[:6000])
            parts.append(f"<details><summary class='muted'>metadata</summary><pre>{dumped}</pre></details>")
        parts.append("</td></tr>")
    parts.append("</tbody></table>")
    parts.append("<footer><b>Connector statistics</b><ul>")
    for st in publication_stats(result):
        if st["skipped"]:
            status = "skipped"
        else:
            status = (
                "incomplete" if st["incomplete"] or st["errors"] else "cached" if st["cached"] else "complete"
            )
        parts.append(
            f"<li>{_e(st['connector'])}: {_e(status)}, {_e(st['objects_examined'])} examined,"
            f" {_e(st['findings'])} findings"
        )
        diagnostics = [
            *st["errors"],
            *st["warnings"],
            *([st["skip_reason"]] if st["skip_reason"] else []),
        ]
        if diagnostics:
            parts.append("<ul>" + "".join(f"<li>{_e(message)}</li>" for message in diagnostics) + "</ul>")
        parts.append("</li>")
    parts.append("</ul></footer>")
    parts.append("<script>" + _JS + "</script></body></html>")
    return "".join(parts)
