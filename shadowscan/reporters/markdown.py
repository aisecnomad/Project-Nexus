"""Markdown report (suitable for tickets, PR comments, wiki pages)."""

from __future__ import annotations

import html
import re

from shadowscan.mappings import describe, finding_references
from shadowscan.models import Finding, ScanResult
from shadowscan.reporters._publication import (
    has_inventory,
    publication_stats,
    related_finding_ids,
    unassessed_count,
    without_connector_prefix,
)
from shadowscan.utils.output import terminal_text

_LEVEL_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
_LEVEL_ORDER = ["critical", "high", "medium", "low", "info"]
_MARKDOWN_META = re.compile(r"([\\`*_\[\]~|])")
_BACKTICKS = re.compile(r"`+")
# GFM links 'http://', 'https://' and 'ftp://' after any character that is not a letter (a
# digit, '_' or '-' before the scheme does not stop it: '_https://host', '0http://host')
# and 'www.' after anything that is not a letter or digit ('_www.host'). A '\b' would miss
# the cases that follow a word character.
_AUTOLINK = re.compile(r"(?i)(?:(?<![a-z])(https?|ftp)://|(?<![a-z0-9])(www)\.)")
_LINE_BREAKS = {
    "\r": r"\r",
    "\n": r"\n",
    "\t": r"\t",
    "\f": r"\f",
    "\v": r"\v",
    "\x85": r"\u0085",
    "\u2028": r"\u2028",
    "\u2029": r"\u2029",
}
_LINE_BREAK_TRANSLATION = str.maketrans(_LINE_BREAKS)


def _one_line(value: object) -> str:
    """Keep untrusted fields on a single Markdown line, visibly retaining breaks."""
    return terminal_text(str(value).translate(_LINE_BREAK_TRANSLATION))


def _text(value: object) -> str:
    """Escape data in headings, list items and table cells (including raw HTML)."""
    content = _one_line(value)
    # GFM autolinks bare URLs even when the surrounding Markdown is escaped.
    # Reports include attacker-controlled names and diagnostics, so keep these
    # strings readable without making an exported report a link-launch surface.
    # A single alternation handles both forms in one pass over the input.
    content = _AUTOLINK.sub(_defang_autolink, content)
    # For the same reason, "@user" and "@org/team" notify people when a report
    # is pasted into a pull request or issue, and GFM autolinks bare e-mail
    # addresses. Defang every "@" like the "[.]" of a defanged host; the
    # brackets are escaped below and render as "[@]". Code spans need neither.
    content = content.replace("@", "[@]")
    return _MARKDOWN_META.sub(r"\\\1", html.escape(content, quote=False))


def _defang_autolink(match: re.Match[str]) -> str:
    scheme = match.group(1)
    if scheme:
        return {"https": "hxxps://", "http": "hxxp://"}.get(scheme.lower(), "fxp://")
    return "www[.]"


def _code(value: object) -> str:
    """Use a delimiter longer than any backtick sequence in an untrusted id."""
    content = _one_line(value)
    fence = "`" * (1 + max((len(match.group()) for match in _BACKTICKS.finditer(content)), default=0))
    if content.startswith(("`", " ")) or content.endswith(("`", " ")):
        content = f" {content} "
    return f"{fence}{content}{fence}"


def _snippet_block(value: object) -> list[str]:
    """Nest a code fence inside an evidence bullet without allowing a closing fence."""
    raw = str(value).replace("\r\n", "\n").replace("\r", "\n")
    content = "\n".join(_one_line(line) for line in raw.split("\n"))
    fence = "`" * max(3, 1 + max((len(match.group()) for match in _BACKTICKS.finditer(content)), default=0))
    return ["", f"  {fence}text", *(f"  {line}" for line in content.split("\n")), f"  {fence}"]


def _counts(counts: dict[str, int], limit: int | None = None, *, parenthesized: bool = False) -> str:
    """Join escaped ``name: count`` (or ``name (count)``) summary entries."""
    items = list(counts.items())[:limit]
    if parenthesized:
        return ", ".join(f"{_text(k)} ({v})" for k, v in items)
    return ", ".join(f"{_text(k)}: {v}" for k, v in items)


def render_markdown(result: ScanResult) -> str:
    for finding in result.findings:
        finding.sanitize()
    s = result.summary()
    lines: list[str] = []
    lines.append("# ShadowScan report")
    lines.append("")
    generated = _text(result.finished_at or result.started_at)
    lines.append(f"_Generated {generated} by ShadowScan {_text(result.version)}_")
    lines.append("")
    if not result.complete:
        lines.extend(
            [
                "**INCOMPLETE SCAN:** some required inputs could not be assessed. Review connector "
                "statistics.",
                "",
            ]
        )
    lines.append("## Summary")
    lines.append("")
    shadow_note = ""
    if has_inventory(result):
        shadow_note = (
            f" (**{s['shadow']} shadow** — not in the inventory of {result.inventory_size} registered agents)"
        )
        if unassessed := unassessed_count(result):
            shadow_note += (
                f"; **{unassessed} unassessed** (reported only by sources scanned without an inventory)"
            )
    lines.append(f"- **Findings:** {s['total']}" + shadow_note)
    by_risk = sorted(s["by_risk_level"].items(), key=lambda kv: _LEVEL_ORDER.index(kv[0]))
    lines.append("- **By risk:** " + ", ".join(f"{_LEVEL_ICON.get(k, '')} {k}: {v}" for k, v in by_risk))
    lines.append("- **By surface:** " + _counts(dict(sorted(s["by_surface"].items()))))
    lines.append("- **By kind:** " + _counts(dict(sorted(s["by_kind"].items()))))
    if s["frameworks"]:
        lines.append("- **Top technologies:** " + _counts(s["frameworks"], 12, parenthesized=True))
    if s["model_providers"]:
        lines.append("- **Model providers:** " + _counts(s["model_providers"], 10, parenthesized=True))
    if s["errors"]:
        lines.append(f"- **Connector errors:** {s['errors']} (see stats)")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    inventory = has_inventory(result)
    lines.append("| Risk | Shadow | Surface | Kind | Title | Owner | Confidence | Technologies |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for f in result.findings:
        if f.shadow is None:
            shadow = "unassessed" if inventory else ""
        else:
            shadow = "**yes**" if f.shadow else "no"
        level = f.risk.level.value
        technologies = _text(", ".join((f.frameworks + f.model_providers)[:4]))
        lines.append(
            f"| {_LEVEL_ICON.get(level, '')} {level} ({f.risk.score}) | {shadow} | {f.surface.value}"
            f" | {f.kind.value} | {_text(f.title)} | {_text(f.owner or '—')} | {f.confidence:.2f}"
            f" | {technologies} |"
        )
    lines.append("")
    lines.append("## Details")
    lines.append("")
    if any(any(finding_references(f)) for f in result.findings):
        lines.append(
            "_Threats and controls are evidence references, not compliance determinations;"
            " they are author mappings, not independently reviewed._"
        )
        lines.append("")
    for f in result.findings:
        lines.extend(_finding_section(f))
    lines.append("## Connector statistics")
    lines.append("")
    lines.append("| Connector | Objects examined | Findings | Errors | Warnings | Status |")
    lines.append("|---|---|---|---|---|---|")
    stats = publication_stats(result)
    for st in stats:
        if st["skipped"]:
            status = f"skipped: {st['skip_reason']}"
        else:
            status = "incomplete" if st["incomplete"] or st["errors"] else "cached" if st["cached"] else "ok"
        lines.append(
            f"| {_text(st['connector'])} | {st['objects_examined']} | {st['findings']} | {len(st['errors'])}"
            f" | {len(st['warnings'])} | {_text(status)} |"
        )
    lines.append("")
    for st in stats:
        for diagnostic in [*st["errors"], *st["warnings"]]:
            lines.append(
                f"- **{_text(st['connector'])}:** "
                f"{_text(without_connector_prefix(st['connector'], diagnostic))}"
            )
    lines.append("")
    return "\n".join(lines)


def _references(refs: list[str]) -> str:
    """Edition-qualified references as code spans, each followed by its catalog title."""
    items = []
    for ref in refs:
        entry = describe(ref)
        items.append(_code(ref) + (f" {_text(entry.title)}" if entry else ""))
    return "; ".join(items)


def _finding_section(f: Finding) -> list[str]:
    out: list[str] = []
    level = f.risk.level.value
    out.append(f"### {_LEVEL_ICON.get(level, '')} {_text(f.title)}")
    out.append("")
    out.append(f"- **Id:** {_code(f.id)}  ")
    out.append(
        f"- **Resource:** {_code(f.resource)} ({_text(f.resource_type)}) on **{f.surface.value}**"
        f" via {_code(f.connector)}  "
    )
    if f.provider or f.account or f.region:
        where = " ".join(_text(value) for value in (f.provider, f.account, f.region) if value)
        out.append(f"- **Where:** {where}  ")
    shadow = "n/a" if f.shadow is None else "yes" if f.shadow else f"no ({_text(f.registry_match)})"
    out.append(
        f"- **Risk:** {level} ({f.risk.score}) · **Confidence:** {f.confidence:.2f}"
        f" ({f.likelihood.value}) · **Shadow:** {shadow}  "
    )
    if f.owner:
        out.append(f"- **Owner:** {_text(f.owner)}  ")
    if f.frameworks or f.model_providers:
        separator = " · " if f.frameworks and f.model_providers else ""
        frameworks = ", ".join(map(_text, f.frameworks))
        providers = ", ".join(map(_text, f.model_providers))
        out.append(f"- **Technologies:** {frameworks}{separator}{providers}  ")
    if f.models:
        out.append(f"- **Models:** {', '.join(map(_text, f.models[:8]))}  ")
    if f.capabilities:
        out.append(f"- **Capabilities:** {', '.join(map(_text, f.capabilities))}  ")
    if f.tags:
        out.append(f"- **Tags:** {', '.join(map(_text, f.tags))}  ")
    threats, controls = finding_references(f)
    if threats:
        out.append(f"- **Threats:** {_references(threats)}  ")
    if controls:
        out.append(f"- **Controls:** {_references(controls)}  ")
    if f.permissions:
        more = " …" if len(f.permissions) > 15 else ""
        out.append(f"- **Permissions:** {', '.join(map(_text, f.permissions[:15]))}{more}  ")
    if f.first_seen or f.last_seen:
        out.append(f"- **Seen:** {_text(f.first_seen or '?')} → {_text(f.last_seen or '?')}  ")
    activity = f.metadata.get("runtime_activity")
    if isinstance(activity, dict):
        out.append(
            f"- **Gateway activity:** {_text(activity.get('status'))};"
            f" matching events: {_text(activity.get('events', 0))};"
            f" production observed: {_text(activity.get('production_observed', False))}  "
        )
        window = activity.get("window")
        if isinstance(window, dict):
            start, end = _text(window.get("start")), _text(window.get("end"))
            out.append(f"- **Observation window:** {start} → {end}  ")
        out.append(f"- **Activity limits:** {_text(activity.get('limitations', ''))}  ")
    related = related_finding_ids(f.metadata)
    if related:
        out.append(f"- **Related findings:** {', '.join(_code(r) for r in related)}  ")
    factors = [x for x in f.risk.factors if x.weight]
    if factors:
        out.append("")
        out.append("**Risk factors**")
        out.append("")
        for x in factors:
            out.append(f"- {'+' if x.weight > 0 else ''}{x.weight} {_text(x.description)}")
    out.append("")
    out.append("**Evidence**")
    out.append("")
    for e in sorted(f.evidence, key=lambda e: -e.weight)[:12]:
        loc = f" — {_code(e.location)}" if e.location else ""
        out.append(f"- ({e.weight:.2f}) {_text(e.description)}{loc}")
        if e.snippet:
            out.extend(_snippet_block(e.snippet))
    if len(f.evidence) > 12:
        out.append(f"- … {len(f.evidence) - 12} more")
    out.append("")
    return out
