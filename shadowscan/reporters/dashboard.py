"""Static, self-contained fleet dashboard rendered from a ``shadowscan.inventory/v1`` document.

Every table is rendered here, so the page reads completely without JavaScript; one hashed
script only filters, sorts and pages the AI systems table. The page loads nothing: its
Content Security Policy allows that script and inline styles, and no other source. Every
value from the document is escaped, because reports are untrusted input. The coverage panel
comes first, and missing data reads "not collected", "unknown", "no inventory" or "not
classified", never 0.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from shadowscan.dashboard import (
    INVENTORY_STATUSES,
    MAX_HISTORY,
    NOT_COLLECTED,
    PRIORITY_FLOOR,
    REFERENCE_NOTE,
    UNKNOWN,
    coverage_cell,
    is_priority,
)
from shadowscan.reporters.html import _CSS, _e

# Rows written to the page; the inventory JSON always holds every record.
MAX_AGENT_ROWS = 5_000
MAX_PRIORITY_ROWS = 1_000
MAX_SOURCE_ROWS = 1_000
# Connector columns of the coverage table; built-in connectors number a few dozen.
MAX_CONNECTOR_COLUMNS = 100
MAX_VALUE_ROWS = 25
MAX_REFERENCE_ROWS = 50
MAX_DRIFT_ROWS = 100
PAGE_SIZE = 100
_LEVELS = ("critical", "high", "medium", "low", "info")
_STATUS_LABELS = {"shadow": "shadow", "sanctioned": "sanctioned", "no-inventory": "no inventory"}
_CELL_LABELS = {NOT_COLLECTED: "not collected", UNKNOWN: "unknown"}
_RECONCILIATION_COLUMNS = (
    ("registered-and-observed", "Registered and observed"),
    ("registered-not-observed", "Registered, not observed"),
    ("observed-not-registered", "Observed, not registered"),
    ("not-comparable", "Not comparable"),
    ("unreconciled", "Unreconciled"),
)
_AGENT_COLUMNS = (
    ("score", "Risk (heuristic)"),
    ("status", "Inventory"),
    ("floor", "Autonomy floor"),
    ("surface", "Surface"),
    ("kind", "Kind"),
    ("title", "Title and resource"),
    ("owner", "Owner"),
)

_DASH_CSS = (
    # The controls are flex boxes; hidden must still hide them (and paged rows) until the script runs.
    "[hidden]{display:none!important}main{padding-bottom:16px}h2{font-size:17px;margin:28px 32px 8px}\n"
    "nav{margin-top:8px;font-size:13px}nav a,td a{color:var(--accent)}"
    "nav a:focus-visible,td a:focus-visible,.controls button:focus-visible{outline:2px solid var(--accent);"
    "outline-offset:2px}\n"
    ".note{margin:0;padding:0 32px 10px;color:var(--muted);font-size:13px}.warn{color:var(--critical-text);"
    "font-weight:600}\n"
    "caption{caption-side:top;text-align:left;padding:8px 10px;color:var(--muted);font-size:12px}"
    "td.num,th.num{text-align:right}\n"
    ".st-complete{color:var(--fg)}.st-cached{color:var(--accent)}.st-incomplete,.st-skipped,.st-not-collected"
    "{color:var(--critical-text);font-weight:600}.st-unknown{color:var(--muted);font-style:italic}\n"
    "td.priority{outline:2px solid var(--critical);outline-offset:-2px;font-weight:700}"
    ".gap{color:var(--muted);font-style:italic}\n"
    ".scroll{overflow-x:auto;margin:0 32px 32px}.scroll table{width:100%;margin:0}\n"
    ".grid{display:flex;flex-wrap:wrap;gap:16px;padding:0 32px 16px}.grid table{width:auto;min-width:240px;"
    "margin:0}\n"
    ".controls button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;"
    "padding:6px 10px}.controls button:disabled{opacity:.5}\n"
    "svg.spark{display:block;margin:0 32px 12px;max-width:calc(100% - 64px);height:auto;"
    "background:var(--card);border:1px solid var(--line);border-radius:8px}"
    "svg.spark polyline{fill:none;stroke:var(--accent);stroke-width:2}"
    "svg.spark circle{stroke:var(--accent);stroke-width:2;fill:var(--accent)}"
    "svg.spark circle.incomplete{fill:var(--bg)}svg.spark text{fill:var(--muted);font-size:11px}\n"
)

_DASH_JS = (
    "\n"
    "const table=document.getElementById('agents-table');\n"
    "const rows=[...table.querySelectorAll('tbody tr.agent')];const size=" + str(PAGE_SIZE) + ";let page=0;\n"
    "const q=document.getElementById('q'),lvl=document.getElementById('lvl'),"
    "sf=document.getElementById('sf'),st=document.getElementById('st');\n"
    "function keep(r){const t=q.value.toLowerCase();return (!t||r.dataset.text.includes(t))&&"
    "(!lvl.value||r.dataset.level===lvl.value)&&(!sf.value||r.dataset.surface===sf.value)&&"
    "(!st.value||r.dataset.status===st.value);}\n"
    "function show(){const kept=rows.filter(keep);const pages=Math.max(1,Math.ceil(kept.length/size));"
    "if(page>=pages)page=pages-1;rows.forEach(r=>{r.hidden=true;});"
    "kept.slice(page*size,(page+1)*size).forEach(r=>{r.hidden=false;});"
    "document.getElementById('shown').textContent=kept.length;"
    "document.getElementById('page').textContent=(page+1)+' / '+pages;"
    "document.getElementById('prev').disabled=page===0;"
    "document.getElementById('next').disabled=page>=pages-1;}\n"
    "[q,lvl,sf,st].forEach(e=>e.addEventListener('input',()=>{page=0;show();}));\n"
    "document.getElementById('prev').addEventListener('click',()=>{if(page>0){page--;show();}});\n"
    "document.getElementById('next').addEventListener('click',()=>{page++;show();});\n"
    "const heads=[...table.querySelectorAll('th[data-k]')];\n"
    "heads.forEach(th=>th.querySelector('button').addEventListener('click',()=>{const k=th.dataset.k;"
    "const dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';"
    "heads.forEach(o=>o.setAttribute('aria-sort','none'));th.setAttribute('aria-sort',dir);\n"
    "rows.sort((a,b)=>{const x=a.dataset[k],y=b.dataset[k];const nx=parseFloat(x),ny=parseFloat(y);"
    "const c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:String(x).localeCompare(String(y));"
    "return dir==='ascending'?c:-c;});\n"
    "const body=table.querySelector('tbody');rows.forEach(r=>body.appendChild(r));page=0;show();}));\n"
    "document.getElementById('agent-controls').hidden=false;show();\n"
)


def _num(value: Any) -> str:
    return "unknown" if value is None else _e(value)


def _label(value: Any) -> str:
    """A value, or "not recorded" for a missing one, escaped."""
    return "<span class='muted'>not recorded</span>" if value is None or value == "" else _e(value)


def _status_cell(status: str) -> str:
    label = _CELL_LABELS.get(status, status)
    return f"<td class='st-{_e(status)}'>{_e(label)}</td>"


def _caption(text: str) -> str:
    return f"<caption>{_e(text)}</caption>"


def _header(columns: list[str], *, numeric: frozenset[int] = frozenset()) -> str:
    cells = "".join(
        f"<th scope='col'{' class=num' if index in numeric else ''}>{_e(name)}</th>"
        for index, name in enumerate(columns)
    )
    return f"<thead><tr>{cells}</tr></thead>"


def _more(count: int, columns: int, what: str) -> str:
    if count <= 0:
        return ""
    return (
        f"<tfoot><tr><td colspan='{columns}' class='muted'>{_e(count)} more {_e(what)}"
        " in inventory.json</td></tr></tfoot>"
    )


def _values_table(caption: str, column: str, rows: list[dict[str, Any]]) -> str:
    body = "".join(
        f"<tr><th scope='row'>{_label(row['value'])}</th><td class='num'>{_e(row['count'])}</td></tr>"
        for row in rows[:MAX_VALUE_ROWS]
    )
    return (
        f"<table>{_caption(caption)}{_header([column, 'AI systems'], numeric=frozenset({1}))}"
        f"<tbody>{body}</tbody>{_more(len(rows) - MAX_VALUE_ROWS, 2, 'values')}</table>"
    )


def _where(agent: dict[str, Any]) -> str:
    parts = [agent[key] for key in ("provider", "account", "region") if agent[key]]
    return _e(" · ".join(str(part) for part in parts)) if parts else "<span class='muted'>—</span>"


def _inventory_cell(agent: dict[str, Any]) -> str:
    status = agent["inventory_status"]
    if status == "shadow":
        note = " (matched to different agents)" if agent["ambiguous_registration"] else ""
        return f"<span class='shadow'>SHADOW</span>{_e(note)}"
    if status == "sanctioned":
        match = f": {_e(agent['registry_match'])}" if agent["registry_match"] else ""
        return f"sanctioned{match}"
    return "<span class='muted'>no inventory</span>"


def _floor_label(agent: dict[str, Any]) -> str:
    autonomy = agent["autonomy"]
    if autonomy:
        return _e(autonomy["floor_label"])
    if agent["autonomy_status"] == "not-classified":
        return "<span class='warn'>not classified</span>"
    return "<span class='muted'>not applicable</span>"


def _risk(agent: dict[str, Any]) -> str:
    level = agent["risk"]["level"]
    pill = level if level in _LEVELS else "info"
    return f"<span class='pill {pill}'>{_e(level)} {_e(agent['risk']['score'])}</span>"


def _sources(agent: dict[str, Any]) -> str:
    return _e(len(agent["merged_from"])) if agent["merged_from"] else "<span class='muted'>—</span>"


def _agent_table(agents: list[dict[str, Any]], table_id: str, caption: str) -> str:
    rows = []
    for agent in agents:
        rows.append(
            f"<tr><td>{_risk(agent)}</td><td>{_inventory_cell(agent)}</td><td>{_floor_label(agent)}</td>"
            f"<td>{_e(agent['title'])}<br><code>{_e(agent['resource'])}</code></td>"
            f"<td>{_label(agent['owner'])}</td><td>{_where(agent)}</td>"
            f"<td class='num'>{_sources(agent)}</td></tr>"
        )
    columns = [
        "Risk (heuristic)",
        "Inventory",
        "Autonomy floor",
        "Title and resource",
        "Owner",
        "Where",
        "Sources",
    ]
    return (
        f"<div class='scroll'><table id='{table_id}'>{_caption(caption)}"
        f"{_header(columns, numeric=frozenset({6}))}<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _legacy_fleet_note() -> str:
    return (
        "<p class='note warn'>This fleet report was merged by an earlier version (before"
        " shadowscan.fleet-merge/v2), which counted an AI system that any source did not reconcile,"
        " including one from a source without an inventory, as shadow, and recorded no inventory"
        " reconciliation. Its AI systems therefore read as no inventory here; merge the source"
        " reports again with this version to see their shadow status.</p>"
    )


def _coverage(inv: dict[str, Any]) -> list[str]:
    coverage, sources = inv["coverage"], inv["sources"]
    connectors = coverage["connectors"][:MAX_CONNECTOR_COLUMNS]
    parts = ["<section id='coverage' aria-labelledby='coverage-h'><h2 id='coverage-h'>Coverage</h2>"]
    summary = (
        f"{_e(coverage['sources'])} source(s): {_e(coverage['complete_sources'])} complete,"
        f" {_e(coverage['incomplete_sources'])} incomplete"
    )
    if coverage["unknown_coverage_sources"]:
        summary += (
            f"; {_e(coverage['unknown_coverage_sources'])} from an older fleet report, whose connector"
            " coverage is unknown"
        )
    as_of = f" Staleness is in whole days before {_e(inv['as_of'])}." if inv["as_of"] else ""
    parts.append(
        f"<p class='note'>{summary}.{as_of} A connector a source did not run reads not collected.</p>"
    )
    hidden_columns = len(coverage["connectors"]) - len(connectors)
    if hidden_columns > 0:
        parts.append(
            f"<p class='note warn'>{_e(hidden_columns)} more connector column(s) are not shown; each"
            " source's coverage of them is in inventory.json.</p>"
        )
    if inv["legacy_fleet"]:
        parts.append(_legacy_fleet_note())

    def order(source: dict[str, Any]) -> tuple[Any, ...]:
        stale = source["staleness_days"]
        return (
            source["complete"],
            source["connectors"] is not None,
            stale is not None,
            -(stale or 0),
            source["name"],
        )

    shown = sorted(sources, key=order)[:MAX_SOURCE_ROWS]
    columns = ["Source", "Status", "Last scanned", "Staleness (days)", "Findings", "Inventory", *connectors]
    rows = []
    for source in shown:
        status = "complete" if source["complete"] else "incomplete"
        inventory = source["inventory_present"]
        inventory_text = "unknown" if inventory is None else "supplied" if inventory else "none"
        cells = "".join(_status_cell(coverage_cell(source, name)) for name in connectors)
        rows.append(
            f"<tr><th scope='row'>{_e(source['name'])}</th>{_status_cell(status)}"
            f"<td>{_num(source['finished_at'] or source['started_at'])}</td>"
            f"<td class='num'>{_num(source['staleness_days'])}</td>"
            f"<td class='num'>{_num(source['findings'])}</td><td>{_e(inventory_text)}</td>{cells}</tr>"
        )
    caption = _caption("Completeness per source and connector, incomplete and stalest sources first")
    parts.append(
        f"<div class='scroll'><table>{caption}{_header(columns, numeric=frozenset({3, 4}))}"
        f"<tbody>{''.join(rows)}</tbody>{_more(len(sources) - len(shown), len(columns), 'sources')}"
        "</table></div>"
    )
    if inv["reasons"]:
        reasons = "".join(f"<li>{_e(reason)}</li>" for reason in inv["reasons"])
        parts.append(
            f"<p class='note'>Collection scope is not comparable:</p><ul class='note'>{reasons}</ul>"
        )
    if inv["diagnostics"]:
        opened = "" if inv["complete"] else " open"
        items: list[str] = []
        for entry in inv["diagnostics"]:
            messages = [
                *entry["errors"],
                *entry["warnings"],
                *([entry["skip_reason"]] if entry["skip_reason"] else []),
            ]
            hidden = (
                entry["errors_total"]
                + entry["warnings_total"]
                - len(entry["errors"])
                - len(entry["warnings"])
            )
            more = f"<li class='muted'>{_e(hidden)} more</li>" if hidden > 0 else ""
            listed = "".join(f"<li>{_e(message)}</li>" for message in messages)
            items.append(f"<li>{_e(entry['connector'])}: {_e(entry['status'])}<ul>{listed}{more}</ul></li>")
        omitted = inv["diagnostics_omitted"]
        tail = f"<p class='note'>{_e(omitted)} more connector runs in inventory.json.</p>" if omitted else ""
        parts.append(
            f"<details class='note'{opened}><summary>Connector diagnostics ({_e(len(inv['diagnostics']))})"
            f"</summary><ul>{''.join(items)}</ul>{tail}</details>"
        )
    parts.append("</section>")
    return parts


def _overview(inv: dict[str, Any]) -> list[str]:
    counts = inv["counts"]
    statuses = counts["inventory_status"]
    cards = [
        (counts["ai_systems"], "AI systems"),
        (statuses["shadow"], "shadow"),
        (statuses["sanctioned"], "sanctioned"),
        (statuses["no-inventory"], "no inventory"),
        (counts["unowned"], "unowned"),
        (inv["autonomy"]["priority"], f"shadow at L{PRIORITY_FLOOR} or above"),
        (counts["excluded_credentials"], "credential findings left out"),
    ]
    if counts["ambiguous_registration"]:
        cards.append((counts["ambiguous_registration"], "shadow, matched to different agents"))
    if inv["autonomy"]["not_classified"]:
        cards.append((inv["autonomy"]["not_classified"], "autonomy not classified (unknown)"))
    parts = [
        "<section id='overview' aria-labelledby='overview-h'><h2 id='overview-h'>Overview</h2>"
        "<p class='note'>An AI system here is any finding except a credential: an agent, workflow, app,"
        " MCP server, identity, grant or other kind the scanner reports.</p><div class='stats'>",
        *(f"<div class='stat'><b>{_e(value)}</b>{_e(label)}</div>" for value, label in cards),
        "</div><div class='grid'>",
    ]
    status_rows = [{"value": _STATUS_LABELS[name], "count": statuses[name]} for name in INVENTORY_STATUSES]
    for caption, column, rows in (
        ("AI systems by inventory status", "Status", status_rows),
        ("AI systems by risk level", "Risk level", counts["by_risk_level"]),
        ("AI systems by surface", "Surface", counts["by_surface"]),
        ("AI systems by kind", "Kind", counts["by_kind"]),
        ("AI systems by provider", "Provider", counts["by_provider"]),
        ("AI systems by account", "Account", counts["by_account"]),
        ("AI systems by owner", "Owner", counts["by_owner"]),
    ):
        parts.append(_values_table(caption, column, rows))
    parts.append("</div></section>")
    return parts


def _autonomy(inv: dict[str, Any]) -> list[str]:
    matrix = inv["autonomy"]
    rows = []
    for row in matrix["rows"]:
        cells = []
        for status in INVENTORY_STATUSES:
            count = _e(row[status])
            tier = row["tier"]
            if status == "shadow" and tier is not None and tier >= PRIORITY_FLOOR:
                # Emphasized by an outline and a text label, never by color alone.
                cells.append(f"<td class='num priority'><a href='#priority'>{count} · priority</a></td>")
            else:
                cells.append(f"<td class='num'>{count}</td>")
        rows.append(
            f"<tr><th scope='row'>{_e(row['label'])}</th>{''.join(cells)}"
            f"<td class='num'>{_e(row['total'])}</td></tr>"
        )
    columns = ["Autonomy floor", "Shadow", "Sanctioned", "No inventory", "Total"]
    return [
        "<section id='autonomy' aria-labelledby='autonomy-h'>"
        "<h2 id='autonomy-h'>Autonomy and shadow status</h2>",
        "<p class='note'>The floor is the lowest tier the evidence proves. A finding of a kind the scale"
        " describes that carries no valid interval is not classified: its tier is unknown. A finding the"
        f" scale does not describe is not applicable. Shadow systems at L{PRIORITY_FLOOR} and L5 are the"
        " priority quadrant.</p>",
        f"<table>{_caption('AI systems by autonomy floor and inventory status')}"
        f"{_header(columns, numeric=frozenset({1, 2, 3, 4}))}<tbody>{''.join(rows)}</tbody></table>",
        "</section>",
    ]


def _priority(inv: dict[str, Any]) -> list[str]:
    agents = [agent for agent in inv["agents"] if is_priority(agent)]
    parts = [
        "<section id='priority' aria-labelledby='priority-h'>"
        f"<h2 id='priority-h'>Priority: shadow AI systems at L{PRIORITY_FLOOR} or above</h2>"
    ]
    unknown = inv["counts"]["inventory_status"]["no-inventory"]
    if unknown:
        parts.append(
            f"<p class='note warn'>{_e(unknown)} AI system(s) have no inventory to reconcile against;"
            " their shadow status is unknown and they are not listed here.</p>"
        )
    unclassified = inv["autonomy"]["not_classified"]
    if unclassified:
        parts.append(
            f"<p class='note warn'>{_e(unclassified)} AI system(s) carry no valid autonomy interval;"
            f" their tier is unknown, any of them could be at L{PRIORITY_FLOOR} or above, and they are not"
            " listed here.</p>"
        )
    if inv["legacy_fleet"]:
        parts.append(_legacy_fleet_note())
    if agents:
        shown = agents[:MAX_PRIORITY_ROWS]
        parts.append(
            _agent_table(shown, "priority-table", "Shadow AI systems at L4 or above, highest risk first")
        )
        if len(agents) > len(shown):
            parts.append(f"<p class='note'>{_e(len(agents) - len(shown))} more in inventory.json.</p>")
    elif unknown or unclassified:
        parts.append(
            "<p class='note'>No shadow AI system whose status and tier are known has an autonomy floor"
            f" of L{PRIORITY_FLOOR} or above; the AI systems above are unknown, not absent.</p>"
        )
    else:
        parts.append(
            "<p class='note'>No shadow AI system in these reports has an autonomy floor of L4 or above.</p>"
        )
    parts.append("</section>")
    return parts


def _registries(inv: dict[str, Any]) -> list[str]:
    summary = inv["registries"]
    parts = [
        "<section id='registries' aria-labelledby='registries-h'>"
        "<h2 id='registries-h'>Vendor registry reconciliation</h2>"
    ]
    if summary["malformed_records"]:
        parts.append(
            f"<p class='note warn'>{_e(summary['malformed_records'])} registry record(s) were malformed"
            " and not reconciled.</p>"
        )
    if not summary["registries"]:
        parts.append("<p class='note'>No vendor registry records in these reports.</p></section>")
        return parts
    columns = [
        "Registry",
        "Registry id",
        "Records",
        *(label for _, label in _RECONCILIATION_COLUMNS),
        "Approved",
        "Not approved",
        "Auto-approved",
        "Listing complete",
    ]
    rows = []
    for row in summary["registries"]:
        numbers = [row["records"], *(row[key] for key, _ in _RECONCILIATION_COLUMNS)]
        numbers += [row["approved"], row["not_approved"], row["auto_approved"]]
        cells = "".join(f"<td class='num'>{_e(value)}</td>" for value in numbers)
        listing = "yes" if row["listing_complete"] else "no"
        rows.append(
            f"<tr><th scope='row'>{_e(row['registry'])}</th>"
            f"<td><code>{_label(row['registry_id'])}</code></td>{cells}<td>{listing}</td></tr>"
        )
    parts.append(
        f"<div class='scroll'><table>{_caption('Registry records and observed AI systems per registry')}"
        f"{_header(columns, numeric=frozenset(range(2, 11)))}<tbody>{''.join(rows)}</tbody></table></div>"
        "<p class='note'>A record is a registration claim, not proof that the system runs. Observed, not"
        " registered counts observed systems in a registry's scope whose every listing was complete.</p>"
        "</section>"
    )
    return parts


def _reference_table(caption: str, rows: list[dict[str, Any]]) -> str:
    body = "".join(
        f"<tr><th scope='row'><code>{_e(row['ref'])}</code></th><td>{_label(row['title'])}</td>"
        f"<td>{_label(row['framework'])}</td><td class='num'>{_e(row['count'])}</td></tr>"
        for row in rows[:MAX_REFERENCE_ROWS]
    )
    columns = ["Reference", "Title", "Framework", "AI systems"]
    return (
        f"<table>{_caption(caption)}{_header(columns, numeric=frozenset({3}))}<tbody>{body}</tbody>"
        f"{_more(len(rows) - MAX_REFERENCE_ROWS, 4, 'references')}</table>"
    )


def _references(inv: dict[str, Any]) -> list[str]:
    references = inv["references"]
    return [
        "<section id='references' aria-labelledby='references-h'>"
        "<h2 id='references-h'>Threat and control references</h2>",
        f"<p class='note'>{_e(references['note'])} Author mappings, not independently reviewed.</p>",
        _reference_table("Threat references by AI systems relevant to them", references["threats"]),
        _reference_table("Control references by AI systems relevant to them", references["controls"]),
        "</section>",
    ]


def _drift(inv: dict[str, Any]) -> list[str]:
    drift = inv["drift"]
    parts = ["<section id='drift' aria-labelledby='drift-h'><h2 id='drift-h'>Drift against the baseline</h2>"]
    if not drift["comparable"]:
        items = "".join(f"<li>{_e(reason)}</li>" for reason in drift["reasons"])
        parts.append(
            "<p class='note warn'>Not comparable with the baseline: findings missing from these reports are"
            f" unknown, not resolved.</p><ul class='note'>{items}</ul>"
        )
    started = drift["baseline_started_at"]
    if started:
        age = drift["baseline_age_days"]
        aged = f", {_e(age)} day(s) before {_e(inv['as_of'])}" if age is not None else ""
        parts.append(f"<p class='note'>Baseline started {_e(started)}{aged}.</p>")
    counts = drift["counts"]
    keys = ("new", "resolved", "unknown", "changed", "not_comparable")
    labels = ["New", "Resolved", "Unknown", "Changed", "Not comparable"]
    cells = "".join(f"<td class='num'>{_e(counts[key])}</td>" for key in keys)
    parts.append(
        f"<div class='grid'><table>{_caption('Findings compared with the baseline')}"
        f"{_header(labels, numeric=frozenset(range(5)))}<tbody><tr>{cells}</tr></tbody></table>"
    )
    rows = "".join(
        f"<tr><th scope='row'>{_e(name)}</th>"
        # Coverage drift is the comparison itself: its count is of reasons, not findings.
        f"<td class='num'>{_e(count)}{' reason(s)' if name == 'coverage' else ''}</td>"
        f"<td>{'adverse' if drift['adverse'].get(name) else 'none adverse'}</td></tr>"
        for name, count in drift["classes"].items()
    )
    parts.append(
        f"<table>{_caption('Findings with drift of each class; coverage counts reasons, not findings')}"
        f"{_header(['Drift class', 'Count', 'Adverse'], numeric=frozenset({1}))}<tbody>{rows}</tbody>"
        "</table></div>"
    )
    by_id = {agent["id"]: agent for agent in inv["agents"]}
    new = [by_id[identifier] for identifier in drift["new"] if identifier in by_id]
    if new:
        parts.append(_agent_table(new[:MAX_DRIFT_ROWS], "drift-new", "New AI systems since the baseline"))
        if len(new) > MAX_DRIFT_ROWS:
            parts.append(f"<p class='note'>{_e(len(new) - MAX_DRIFT_ROWS)} more in inventory.json.</p>")
    parts.append("</section>")
    return parts


def _sparkline(points: list[dict[str, Any]], pairs: list[dict[str, Any]]) -> str:
    """AI systems per report; a line joins two reports only when their comparison was comparable."""
    width, height, pad = 640, 80, 12
    values = [point["ai_systems"] for point in points]
    top = max(values, default=0) or 1
    step = (width - 2 * pad) / max(len(points) - 1, 1)

    def xy(index: int) -> tuple[float, float]:
        return pad + index * step, height - pad - (values[index] / top) * (height - 2 * pad)

    lines = []
    for index, pair in enumerate(pairs):
        if pair["comparable"]:
            (x1, y1), (x2, y2) = xy(index), xy(index + 1)
            lines.append(f"<polyline points='{x1:.1f},{y1:.1f} {x2:.1f},{y2:.1f}'/>")
    dots = []
    for index, point in enumerate(points):
        x, y = xy(index)
        state = "complete" if point["complete"] else "incomplete"
        dots.append(
            f"<circle class='{state}' cx='{x:.1f}' cy='{y:.1f}' r='3'><title>{_e(point['name'])}:"
            f" {_e(point['ai_systems'])} AI systems ({state})</title></circle>"
        )
    return (
        f"<svg class='spark' viewBox='0 0 {width} {height}' width='{width}' height='{height}' role='img'"
        " aria-labelledby='spark-title'><title id='spark-title'>AI systems per history report; breaks mark"
        f" pairs that are not comparable</title>{''.join(lines)}{''.join(dots)}"
        f"<text x='{pad}' y='{pad}'>max {_e(top if values else 0)}</text></svg>"
    )


def _change(pair: dict[str, Any] | None) -> str:
    if pair is None:
        return "<span class='muted'>—</span>"
    if not pair["comparable"]:
        return f"<span class='gap'>not comparable: {_e(pair['reasons'])} reason(s)</span>"
    counts = ", ".join(f"{_e(key)} {_e(value)}" for key, value in pair["counts"].items())
    classes = ", ".join(
        f"{_e(key)} {_e(value)}" for key, value in pair["classes"].items() if key != "coverage"
    )
    return f"{counts}; {classes}"


def _history(inv: dict[str, Any]) -> list[str]:
    history = inv["history"]
    points, pairs = history["points"], history["pairs"]
    parts = [
        "<section id='history' aria-labelledby='history-h'><h2 id='history-h'>History</h2>",
        f"<p class='note'>{_e(history['shown'])} of {_e(history['reports'])} report(s), ordered by start"
        " time. Drift is counted only between comparable consecutive reports; any other pair is a gap.</p>",
    ]
    if history["omitted"]:
        parts.append(
            f"<p class='note warn'>{_e(history['omitted'])} older report(s) left out: the history shows at"
            f" most the newest {_e(MAX_HISTORY)}.</p>"
        )
    if history["undated"]:
        names = ", ".join(_e(name) for name in history["undated"])
        parts.append(f"<p class='note warn'>Not placed in the series (no valid start time): {names}.</p>")
    if not points:
        parts.append("<p class='note'>No dated reports in the history directory.</p></section>")
        return parts
    parts.append(_sparkline(points, pairs))
    rows = []
    for index, point in enumerate(points):
        shadow = point["shadow"]
        floor = point["l4_plus"]
        status = "complete" if point["complete"] else "incomplete"
        rows.append(
            f"<tr><th scope='row'>{_e(point['name'])}</th><td>{_e(point['started_at'])}</td>"
            f"{_status_cell(status)}<td class='num'>{_e(point['ai_systems'])}</td>"
            f"<td class='num'>{'unknown (no inventory)' if shadow is None else _e(shadow)}</td>"
            f"<td class='num'>{'not classified' if floor is None else _e(floor)}</td>"
            f"<td>{_change(pairs[index - 1] if index else None)}</td></tr>"
        )
    columns = [
        "Report",
        "Started",
        "Status",
        "AI systems",
        "Shadow",
        f"L{PRIORITY_FLOOR}+ floor",
        "Since previous",
    ]
    parts.append(
        f"<div class='scroll'><table>{_caption('Totals per report and drift since the previous report')}"
        f"{_header(columns, numeric=frozenset({3, 4, 5}))}<tbody>{''.join(rows)}</tbody></table></div>"
        "</section>"
    )
    return parts


def _agents(inv: dict[str, Any]) -> list[str]:
    agents = inv["agents"]
    shown = agents[:MAX_AGENT_ROWS]
    surfaces = sorted({agent["surface"] for agent in agents})
    parts = [
        "<section id='agents' aria-labelledby='agents-h'><h2 id='agents-h'>AI systems</h2>",
        "<div class='controls' id='agent-controls' hidden>"
        "<input id='q' aria-label='Filter AI systems' placeholder='filter…' size='32'>"
        "<select id='lvl' aria-label='Risk level'><option value=''>all risk levels</option>"
        + "".join(f"<option value='{level}'>{level}</option>" for level in _LEVELS)
        + "</select><select id='sf' aria-label='Surface'><option value=''>all surfaces</option>"
        + "".join(f"<option value='{_e(surface)}'>{_e(surface)}</option>" for surface in surfaces)
        + "</select><select id='st' aria-label='Inventory status'>"
        "<option value=''>any inventory status</option>"
        + "".join(f"<option value='{name}'>{_STATUS_LABELS[name]}</option>" for name in INVENTORY_STATUSES)
        + "</select><button type='button' id='prev'>Previous page</button>"
        "<button type='button' id='next'>Next page</button>"
        "<span class='muted' role='status' style='align-self:center'><span id='shown'></span> match;"
        " page <span id='page'></span></span></div>",
    ]
    if len(agents) > len(shown):
        parts.append(
            f"<p class='note warn'>Showing the {_e(len(shown))} highest-risk of {_e(len(agents))} AI systems;"
            " every record is in inventory.json.</p>"
        )
    heads = "".join(
        f"<th scope='col' data-k='{key}' aria-sort='{'descending' if key == 'score' else 'none'}'>"
        f"<button type='button'>{label}</button></th>"
        for key, label in _AGENT_COLUMNS
    )
    rows = []
    for agent in shown:
        floor = agent["autonomy"]["floor"] if agent["autonomy"] else -1
        text = " ".join(
            str(value)
            for value in (
                agent["title"],
                agent["resource"],
                agent["owner"] or "",
                agent["provider"] or "",
                agent["account"] or "",
                agent["kind"],
                agent["surface"],
                *agent["tags"],
                *agent["frameworks"],
            )
        ).lower()
        reconciliation = (agent["registry_reconciliation"] or {}).get("status", "—")
        rows.append(
            f"<tr class='agent' data-score='{_e(agent['risk']['score'])}'"
            f" data-level='{_e(agent['risk']['level'])}' data-status='{_e(agent['inventory_status'])}'"
            f" data-floor='{_e(floor)}' data-surface='{_e(agent['surface'])}' data-kind='{_e(agent['kind'])}'"
            f" data-title='{_e(agent['title'])}' data-owner='{_e(agent['owner'] or '')}'"
            f" data-text='{_e(text)}'>"
            f"<td>{_risk(agent)}</td><td>{_inventory_cell(agent)}</td><td>{_floor_label(agent)}</td>"
            f"<td>{_e(agent['surface'])}</td><td>{_e(agent['kind'])}</td>"
            f"<td>{_e(agent['title'])}<br><code>{_e(agent['resource'])}</code></td>"
            f"<td>{_label(agent['owner'])}</td><td>{_where(agent)}</td><td>{_e(reconciliation)}</td>"
            f"<td class='num'>{_sources(agent)}</td></tr>"
        )
    caption = _caption("AI systems, highest risk first; credential findings are left out")
    parts.append(
        f"<div class='scroll'><table id='agents-table'>{caption}<thead><tr>{heads}<th scope='col'>Where</th>"
        "<th scope='col'>Registry</th><th scope='col' class='num'>Sources</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></section>"
    )
    return parts


def render_dashboard(inventory: dict[str, Any]) -> str:
    """The dashboard page for a :func:`shadowscan.dashboard.build_inventory` document."""
    script_hash = base64.b64encode(hashlib.sha256(_DASH_JS.encode("utf-8")).digest()).decode("ascii")
    version = inventory["report_version"] or inventory["generator"]["version"]
    stamp = inventory["generated_at"] or "undated"
    sections = [("coverage", "Coverage"), ("overview", "Overview"), ("autonomy", "Autonomy")]
    sections += [("priority", "Priority"), ("registries", "Registries"), ("references", "References")]
    if inventory["drift"] is not None:
        sections.append(("drift", "Drift"))
    if inventory["history"] is not None:
        sections.append(("history", "History"))
    sections.append(("agents", "AI systems"))
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        f"script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'\">"
        "<meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>ShadowScan dashboard</title><style>" + _CSS + _DASH_CSS + "</style></head><body>",
        f"<header><h1>ShadowScan dashboard <span>v{_e(version)} · {_e(stamp)}</span></h1>"
        "<div class='muted'>A static inventory of the AI systems in these reports. It holds resource"
        " identifiers, owners and accounts: keep it as private as the reports.</div>"
        "<nav aria-label='Sections'>"
        + " · ".join(f"<a href='#{anchor}'>{label}</a>" for anchor, label in sections)
        + "</nav></header>",
    ]
    if not inventory["complete"]:
        parts.append(
            "<div class='controls'><strong class='shadow'>INCOMPLETE SCAN — some required inputs could not be"
            " assessed. Counts cover only what was collected; review the coverage panel.</strong></div>"
        )
    if inventory["drift"] is not None and not inventory["drift"]["comparable"]:
        parts.append(
            "<div class='controls'><strong class='shadow'>BASELINE NOT COMPARABLE — findings missing from"
            " these reports are unknown, not resolved, and the command exits 3; see the drift section."
            "</strong></div>"
        )
    parts.append("<main>")
    parts += _coverage(inventory)
    parts += _overview(inventory)
    parts += _autonomy(inventory)
    parts += _priority(inventory)
    parts += _registries(inventory)
    parts += _references(inventory)
    if inventory["drift"] is not None:
        parts += _drift(inventory)
    if inventory["history"] is not None:
        parts += _history(inventory)
    parts += _agents(inventory)
    parts.append(
        "</main><footer><p><b>Threats and controls.</b> "
        + _e(REFERENCE_NOTE)
        + " Author mappings, not independently reviewed. Risk is a discovery heuristic, not a vulnerability"
        " severity. Shadow means unmatched against the supplied inventory.</p>"
        f"<p>Generated by ShadowScan {_e(inventory['generator']['version'])} from reports, not from live"
        " systems; schema <code>" + _e(inventory["schema"]) + "</code>.</p></footer>"
    )
    parts.append("<script>" + _DASH_JS + "</script></body></html>")
    return "".join(parts)
