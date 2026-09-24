"""Markdown report (suitable for tickets, PR comments, wiki pages)."""

from __future__ import annotations

import html

from shadowscan.models import Finding, ScanResult

_LEVEL_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}


def _md_text(s: object) -> str:
    """Flatten untrusted finding text so it cannot inject Markdown or HTML structure."""
    text = html.escape("" if s is None else str(s), quote=True)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("`", "&#96;")
    text = text.replace("[", "\\[").replace("]", "\\]")
    return " ".join(text.split())


def _md_cell(s: object) -> str:
    return _md_text(s).replace("|", "\\|")


def _md_heading(s: object) -> str:
    return _md_text(s).lstrip("#").strip()


def _md_fence(snippet: str) -> str:
    fence = "```"
    while fence in snippet:
        fence += "`"
    body = snippet.replace("\r\n", "\n").replace("\r", "\n")
    return f"\n{fence}\n{body}\n{fence}"


def render_markdown(result: ScanResult) -> str:
    for finding in result.findings:
        finding.sanitize()
    s = result.summary()
    lines: list[str] = []
    lines.append("# ShadowScan report")
    lines.append("")
    lines.append(f"_Generated {_md_text(result.finished_at or result.started_at)} by ShadowScan {_md_text(result.version)}_")
    lines.append("")
    if not result.complete:
        lines.extend(["**INCOMPLETE SCAN:** some required inputs could not be assessed. Review connector statistics.", ""])
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Findings:** {s['total']}" + (f" (**{s['shadow']} shadow** — not in the inventory of {result.inventory_size} registered agents)" if result.inventory_size else ""))
    lines.append("- **By risk:** " + ", ".join(f"{_LEVEL_ICON.get(k, '')} {k}: {v}" for k, v in sorted(s["by_risk_level"].items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))))
    lines.append("- **By surface:** " + ", ".join(f"{_md_cell(k)}: {v}" for k, v in sorted(s["by_surface"].items())))
    lines.append("- **By kind:** " + ", ".join(f"{_md_cell(k)}: {v}" for k, v in sorted(s["by_kind"].items())))
    if s["frameworks"]:
        lines.append("- **Top technologies:** " + ", ".join(f"{_md_cell(k)} ({v})" for k, v in list(s["frameworks"].items())[:12]))
    if s["model_providers"]:
        lines.append("- **Model providers:** " + ", ".join(f"{_md_cell(k)} ({v})" for k, v in list(s["model_providers"].items())[:10]))
    if s["errors"]:
        lines.append(f"- **Connector errors:** {s['errors']} (see stats)")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Risk | Shadow | Surface | Kind | Title | Owner | Confidence | Technologies |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for f in result.findings:
        shadow = "" if f.shadow is None else ("**yes**" if f.shadow else "no")
        lines.append(
            f"| {_LEVEL_ICON.get(f.risk.level.value, '')} {f.risk.level.value} ({f.risk.score}) | {shadow} | {_md_cell(f.surface.value)} | {_md_cell(f.kind.value)} | {_md_cell(f.title)} | {_md_cell(f.owner or '—')} | {f.confidence:.2f} | {_md_cell(', '.join((f.frameworks + f.model_providers)[:4]))} |"
        )
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for f in result.findings:
        lines.extend(_finding_section(f))
    lines.append("## Connector statistics")
    lines.append("")
    lines.append("| Connector | Objects examined | Findings | Errors | Warnings | Status |")
    lines.append("|---|---|---|---|---|---|")
    for st in result.stats:
        status = f"skipped: {st.skip_reason}" if st.skipped else "incomplete" if st.incomplete or st.errors else "cached" if st.cached else "ok"
        lines.append(f"| {_md_cell(st.connector)} | {st.objects_examined} | {st.findings} | {len(st.errors)} | {len(st.warnings)} | {_md_cell(status)} |")
    lines.append("")
    for st in result.stats:
        for diagnostic in [*st.errors, *st.warnings]:
            lines.append(f"- **{_md_cell(st.connector)}:** {_md_text(diagnostic)}")
    lines.append("")
    return "\n".join(lines)


def _finding_section(f: Finding) -> list[str]:
    out: list[str] = []
    out.append(f"### {_LEVEL_ICON.get(f.risk.level.value, '')} {_md_heading(f.title)}")
    out.append("")
    out.append(f"- **Id:** `{_md_text(f.id)}`  ")
    out.append(f"- **Resource:** `{_md_text(f.resource)}` ({_md_text(f.resource_type)}) on **{_md_text(f.surface.value)}** via `{_md_text(f.connector)}`  ")
    if f.provider or f.account or f.region:
        out.append(f"- **Where:** {_md_text(f.provider or '')} {_md_text(f.account or '')} {_md_text(f.region or '')}  ")
    shadow = "n/a" if f.shadow is None else ("yes" if f.shadow else f"no ({_md_text(f.registry_match)})")
    out.append(f"- **Risk:** {f.risk.level.value} ({f.risk.score}) · **Confidence:** {f.confidence:.2f} ({f.likelihood.value}) · **Shadow:** {shadow}  ")
    if f.owner:
        out.append(f"- **Owner:** {_md_text(f.owner)}  ")
    if f.frameworks or f.model_providers:
        out.append(f"- **Technologies:** {_md_text(', '.join(f.frameworks))}{' · ' if f.frameworks and f.model_providers else ''}{_md_text(', '.join(f.model_providers))}  ")
    if f.models:
        out.append(f"- **Models:** {_md_text(', '.join(f.models[:8]))}  ")
    if f.capabilities:
        out.append(f"- **Capabilities:** {_md_text(', '.join(f.capabilities))}  ")
    if f.tags:
        out.append(f"- **Tags:** {_md_text(', '.join(f.tags))}  ")
    if f.permissions:
        out.append(f"- **Permissions:** {_md_text(', '.join(f.permissions[:15]))}{' …' if len(f.permissions) > 15 else ''}  ")
    if f.first_seen or f.last_seen:
        out.append(f"- **Seen:** {_md_text(f.first_seen or '?')} → {_md_text(f.last_seen or '?')}  ")
    activity = f.metadata.get("runtime_activity")
    if isinstance(activity, dict):
        out.append(f"- **Gateway activity:** {_md_text(activity.get('status'))}; matching events: {activity.get('events', 0)}; production observed: {activity.get('production_observed', False)}  ")
        if activity.get("window"):
            out.append(f"- **Observation window:** {_md_text(activity['window'].get('start'))} → {_md_text(activity['window'].get('end'))}  ")
        out.append(f"- **Activity limits:** {_md_text(activity.get('limitations', ''))}  ")
    related = f.metadata.get("related")
    if related:
        out.append("- **Related findings:** " + ", ".join(f"`{_md_text(r)}`" for r in related[:8]) + "  ")
    factors = [x for x in f.risk.factors if x.weight]
    if factors:
        out.append("")
        out.append("**Risk factors**")
        out.append("")
        for x in factors:
            out.append(f"- {'+' if x.weight > 0 else ''}{x.weight} {_md_text(x.description)}")
    out.append("")
    out.append("**Evidence**")
    out.append("")
    for e in sorted(f.evidence, key=lambda e: -e.weight)[:12]:
        loc = f" — `{_md_text(e.location)}`" if e.location else ""
        snip = _md_fence(e.snippet) if e.snippet else ""
        out.append(f"- ({e.weight:.2f}) {_md_text(e.description)}{loc}{snip}")
    if len(f.evidence) > 12:
        out.append(f"- … {len(f.evidence) - 12} more")
    out.append("")
    return out
