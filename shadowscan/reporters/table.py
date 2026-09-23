"""Rich terminal output."""

from __future__ import annotations

from rich.console import Console, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shadowscan.models import Finding, ScanResult

_LEVEL_STYLE = {"critical": "bold white on red", "high": "bold black on dark_orange", "medium": "black on yellow", "low": "black on green", "info": "dim"}


def _level(f: Finding) -> Text:
    return Text(f" {f.risk.level.value.upper()} {f.risk.score:>3} ", style=_LEVEL_STYLE.get(f.risk.level.value, ""))


def print_table(result: ScanResult, console: Console | None = None, verbose: bool = False, max_rows: int | None = None) -> None:
    for finding in result.findings:
        finding.sanitize()
    console = console or Console()
    if not console.is_terminal and console.width < 140:
        console = Console(width=160, file=console.file, force_terminal=False, color_system=None)
    s = result.summary()
    header = Text()
    if not result.complete:
        header.append("INCOMPLETE SCAN  •  ", style="bold red")
    header.append(f"{s['total']} findings", style="bold")
    if result.inventory_size:
        header.append(f"  •  {s['shadow']} shadow", style="bold red")
        header.append(f" (inventory: {result.inventory_size} registered agents)", style="dim")
    header.append("  •  ")
    for lvl in ("critical", "high", "medium", "low", "info"):
        n = s["by_risk_level"].get(lvl, 0)
        if n:
            header.append(f" {lvl} {n} ", style=_LEVEL_STYLE[lvl])
            header.append(" ")
    header.append("  •  surfaces: " + ", ".join(f"{k} {v}" for k, v in sorted(s["by_surface"].items())), style="dim")
    console.print(Panel(header, title="ShadowScan", subtitle=f"v{result.version} · {result.finished_at or ''}", expand=False))

    table = Table(show_lines=True, expand=True, header_style="bold", pad_edge=False)
    table.add_column("Risk", no_wrap=True, min_width=13)
    if result.inventory_size:
        table.add_column("Shadow", no_wrap=True, min_width=7)
    table.add_column("Surface", no_wrap=True, min_width=8)
    table.add_column("Kind", no_wrap=True, min_width=12, overflow="fold")
    table.add_column("Finding", ratio=4, min_width=30, overflow="fold")
    table.add_column("Owner", ratio=1, min_width=8, overflow="fold")
    table.add_column("Conf", justify="right", min_width=4)
    table.add_column("Technologies", ratio=2, min_width=12, overflow="fold")
    rows = result.findings if max_rows is None else result.findings[:max_rows]
    for f in rows:
        tech = ", ".join(t.split(".", 1)[-1] for t in (f.frameworks + f.model_providers)[:5])
        finding_cell = Text(f.title, style="bold")
        finding_cell.append(f"\n{f.resource}", style="dim")
        activity = f.metadata.get("runtime_activity")
        if isinstance(activity, dict):
            suffix = "; production observed" if activity.get("production_observed") else ""
            finding_cell.append(f"\ngateway: {activity.get('status', 'unknown')}{suffix}", style="cyan")
        if verbose:
            caps = ", ".join(f.capabilities)
            if caps:
                finding_cell.append(f"\ncapabilities: {caps}", style="cyan")
            factors = "; ".join(x.description for x in f.risk.factors if x.weight > 0)
            if factors:
                finding_cell.append(f"\nrisk: {factors}", style="yellow")
            for e in sorted(f.evidence, key=lambda e: -e.weight)[:3]:
                finding_cell.append(f"\n  • {e.description}" + (f" ({e.location})" if e.location else ""), style="dim")
        cells: list[RenderableType] = [_level(f)]
        if result.inventory_size:
            cells.append(Text("SHADOW", style="bold red") if f.shadow else Text(f.registry_match or "", style="green"))
        cells += [f.surface.value, f.kind.value, finding_cell, Text(f.owner or "—"), f"{f.confidence:.2f}", Text(tech)]
        table.add_row(*cells)
    console.print(table)
    if max_rows is not None and len(result.findings) > max_rows:
        console.print(f"[dim]… {len(result.findings) - max_rows} more findings (use --output to export all)[/dim]")
    errs = [(st.connector, e) for st in result.stats for e in st.errors]
    if errs:
        console.print("[bold red]Connector errors:[/bold red]")
        for c, error in errs[:20]:
            console.print(Text(f"  {c}: {error}", style="red"))
    warns = [(st.connector, w) for st in result.stats for w in st.warnings]
    if warns and (verbose or not result.complete):
        console.print("[bold yellow]Warnings:[/bold yellow]")
        for c, w in warns[:30]:
            console.print(Text(f"  {c}: {w}", style="yellow"))
    console.print(Text(" · ".join(f"{st.connector}: {st.objects_examined} objects, {st.findings} findings" + (" (skipped)" if st.skipped else " (incomplete)" if st.incomplete or st.errors else " (cached)" if st.cached else "") for st in result.stats), style="dim"))
