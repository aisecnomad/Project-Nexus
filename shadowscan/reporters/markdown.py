"""Markdown report (suitable for tickets, PR comments, wiki pages)."""

from __future__ import annotations

from shadowscan.models import Finding, ScanResult

_LEVEL_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}


def _esc(s: object) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    for finding in result.findings:
        finding.sanitize()
    s = result.summary()
    lines: list[str] = []
    lines.append("# ShadowScan report")
    lines.append("")
    lines.append(f"_Generated {result.finished_at or result.started_at} by ShadowScan {result.version}_")
    lines.append("")
    if not result.complete:
        lines.extend(["**INCOMPLETE SCAN:** some required inputs could not be assessed. Review connector statistics.", ""])
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Findings:** {s['total']}" + (f" (**{s['shadow']} shadow** — not in the inventory of {result.inventory_size} registered agents)" if result.inventory_size else ""))
    lines.append("- **By risk:** " + ", ".join(f"{_LEVEL_ICON.get(k, '')} {k}: {v}" for k, v in sorted(s["by_risk_level"].items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))))
    lines.append("- **By surface:** " + ", ".join(f"{k}: {v}" for k, v in sorted(s["by_surface"].items())))
    lines.append("- **By kind:** " + ", ".join(f"{k}: {v}" for k, v in sorted(s["by_kind"].items())))
    if s["frameworks"]:
        lines.append("- **Top technologies:** " + ", ".join(f"{k} ({v})" for k, v in list(s["frameworks"].items())[:12]))
    if s["model_providers"]:
        lines.append("- **Model providers:** " + ", ".join(f"{k} ({v})" for k, v in list(s["model_providers"].items())[:10]))
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
            f"| {_LEVEL_ICON.get(f.risk.level.value, '')} {f.risk.level.value} ({f.risk.score}) | {shadow} | {f.surface.value} | {f.kind.value} | {_esc(f.title)} | {_esc(f.owner or '—')} | {f.confidence:.2f} | {_esc(', '.join((f.frameworks + f.model_providers)[:4]))} |"
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
        lines.append(f"| {st.connector} | {st.objects_examined} | {st.findings} | {len(st.errors)} | {len(st.warnings)} | {_esc(status)} |")
    lines.append("")
    for st in result.stats:
        for diagnostic in [*st.errors, *st.warnings]:
            lines.append(f"- **{_esc(st.connector)}:** {_esc(diagnostic)}")
    lines.append("")
    return "\n".join(lines)


def _finding_section(f: Finding) -> list[str]:
    out: list[str] = []
    out.append(f"### {_LEVEL_ICON.get(f.risk.level.value, '')} {f.title}")
    out.append("")
    out.append(f"- **Id:** `{f.id}`  ")
    out.append(f"- **Resource:** `{f.resource}` ({f.resource_type}) on **{f.surface.value}** via `{f.connector}`  ")
    if f.provider or f.account or f.region:
        out.append(f"- **Where:** {f.provider or ''} {f.account or ''} {f.region or ''}  ".replace("  ", " "))
    out.append(f"- **Risk:** {f.risk.level.value} ({f.risk.score}) · **Confidence:** {f.confidence:.2f} ({f.likelihood.value}) · **Shadow:** {'n/a' if f.shadow is None else ('yes' if f.shadow else f'no ({f.registry_match})')}  ")
    if f.owner:
        out.append(f"- **Owner:** {f.owner}  ")
    if f.frameworks or f.model_providers:
        out.append(f"- **Technologies:** {', '.join(f.frameworks)}{' · ' if f.frameworks and f.model_providers else ''}{', '.join(f.model_providers)}  ")
    if f.models:
        out.append(f"- **Models:** {', '.join(f.models[:8])}  ")
    if f.capabilities:
        out.append(f"- **Capabilities:** {', '.join(f.capabilities)}  ")
    if f.tags:
        out.append(f"- **Tags:** {', '.join(f.tags)}  ")
    if f.permissions:
        out.append(f"- **Permissions:** {', '.join(f.permissions[:15])}{' …' if len(f.permissions) > 15 else ''}  ")
    if f.first_seen or f.last_seen:
        out.append(f"- **Seen:** {f.first_seen or '?'} → {f.last_seen or '?'}  ")
    activity = f.metadata.get("runtime_activity")
    if isinstance(activity, dict):
        out.append(f"- **Gateway activity:** {_esc(activity.get('status'))}; matching events: {activity.get('events', 0)}; production observed: {activity.get('production_observed', False)}  ")
        if activity.get("window"):
            out.append(f"- **Observation window:** {_esc(activity['window'].get('start'))} → {_esc(activity['window'].get('end'))}  ")
        out.append(f"- **Activity limits:** {_esc(activity.get('limitations', ''))}  ")
    related = f.metadata.get("related")
    if related:
        out.append(f"- **Related findings:** {', '.join(f'`{r}`' for r in related[:8])}  ")
    factors = [x for x in f.risk.factors if x.weight]
    if factors:
        out.append("")
        out.append("**Risk factors**")
        out.append("")
        for x in factors:
            out.append(f"- {'+' if x.weight > 0 else ''}{x.weight} {x.description}")
    out.append("")
    out.append("**Evidence**")
    out.append("")
    for e in sorted(f.evidence, key=lambda e: -e.weight)[:12]:
        loc = f" — `{e.location}`" if e.location else ""
        snip = f"\n  ```\n  {e.snippet}\n  ```" if e.snippet else ""
        out.append(f"- ({e.weight:.2f}) {e.description}{loc}{snip}")
    if len(f.evidence) > 12:
        out.append(f"- … {len(f.evidence) - 12} more")
    out.append("")
    return out
