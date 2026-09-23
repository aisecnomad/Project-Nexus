"""ShadowScan command line interface."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from shadowscan import __version__
from shadowscan.config import ConnectorSpec, ScanConfig, parse_set_options
from shadowscan.connectors import available_connectors, connectors_for_surface, get_connector_class
from shadowscan.engine import Engine
from shadowscan.models import Finding, ScanResult, Surface
from shadowscan.registry import Inventory, card_stub_for
from shadowscan.reporters import FORMATS, render
from shadowscan.reporters.table import print_table
from shadowscan.signatures import get_index

console = Console(width=None if sys.stdout.isatty() else 200)
err_console = Console(stderr=True)
LEVELS = ["critical", "high", "medium", "low", "info"]


def _setup_logging(verbose: int, quiet: bool) -> None:
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(message)s", handlers=[RichHandler(console=err_console, show_path=False, show_time=verbose >= 2, rich_tracebacks=False)], force=True)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)


def _emit(result: ScanResult, fmt: str, output: str | None, verbose: bool, max_rows: int | None) -> None:
    if fmt == "table" and not output:
        print_table(result, console=console, verbose=verbose, max_rows=max_rows)
        return
    text = render(result, "json" if fmt == "table" else fmt)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        err_console.print(f"[green]wrote {fmt if fmt != 'table' else 'json'} report to {output}[/green]")
        if fmt == "table":
            print_table(result, console=console, verbose=verbose, max_rows=max_rows)
    else:
        click.echo(text)


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = LEVELS.index(fail_on)
    worst = min((LEVELS.index(f.risk.level.value) for f in result.findings), default=len(LEVELS))
    return 2 if worst <= threshold else 0


def _run_and_emit(cfg: ScanConfig, fmt: str, output: str | None, verbose: int, max_rows: int | None, only: list[str] | None = None) -> None:
    def progress(cid: str, msg: str) -> None:
        err_console.print(f"[dim]{cid}: {msg}[/dim]")

    engine = Engine(cfg, progress=progress if verbose else None)
    result = engine.run(only=only)
    _emit(result, fmt, output, verbose=bool(verbose), max_rows=max_rows)
    sys.exit(_exit_code(result, cfg.fail_on))


output_options = [
    click.option("--format", "-f", "fmt", type=click.Choice(FORMATS), default="table", show_default=True, help="output format"),
    click.option("--output", "-o", type=click.Path(dir_okay=False), help="write the report to a file (table format also prints to the terminal)"),
    click.option("--inventory", "-i", multiple=True, help="sanctioned inventory: Agent Capability Cards dir/file, agents.yaml or CSV (repeatable)"),
    click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory (repeatable)"),
    click.option("--min-confidence", type=float, default=0.0, show_default=True, help="drop findings below this confidence"),
    click.option("--fail-on", type=click.Choice(LEVELS), help="exit 2 if any finding reaches this risk level"),
    click.option("--max-rows", type=int, default=None, help="limit rows printed in table mode"),
    click.option("--dump-records", type=click.Path(file_okay=False), help="directory to save raw connector records (JSONL) for offline re-analysis"),
]


def add_options(options):
    def _wrap(fn):
        for opt in reversed(options):
            fn = opt(fn)
        return fn

    return _wrap


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="shadowscan")
@click.option("-v", "--verbose", count=True, help="-v info, -vv debug")
@click.option("-q", "--quiet", is_flag=True, help="errors only")
def main(verbose: int, quiet: bool) -> None:
    """ShadowScan — discover shadow AI agents across code, identity, gateways, low-code, SaaS and cloud."""
    _setup_logging(verbose, quiet)
    main.verbose = verbose  # type: ignore[attr-defined]


# ---------------------------------------------------------------------- scan
@main.command()
@click.option("--config", "-c", "config_path", type=click.Path(exists=True, dir_okay=False), required=True, help="shadowscan.yaml")
@click.option("--only", multiple=True, help="run only these connector names / labels (repeatable)")
@add_options(output_options)
def scan(config_path: str, only: tuple[str, ...], fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None) -> None:
    """Run every connector defined in a config file."""
    cfg = ScanConfig.from_yaml(config_path)
    cfg.inventory.extend(inventory)
    cfg.signature_dirs.extend(signature_dirs)
    cfg.min_confidence = max(cfg.min_confidence, min_confidence)
    cfg.fail_on = fail_on or cfg.fail_on
    cfg.dump_records = dump_records or cfg.dump_records
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows, only=list(only) or None)  # type: ignore[attr-defined]


# ----------------------------------------------------------------------- run
@main.command()
@click.argument("connector")
@click.option("--input", "input_path", type=click.Path(exists=True), help="offline export (file or directory) instead of the live API")
@click.option("--set", "-S", "settings", multiple=True, help="connector option key=value (repeatable; lists as a,b,c)")
@add_options(output_options)
def run(connector: str, input_path: str | None, settings: tuple[str, ...], fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None) -> None:
    """Run a single connector, e.g. `shadowscan run identity.okta --set org_url=https://acme.okta.com`."""
    if connector not in available_connectors():
        raise click.BadParameter(f"unknown connector {connector!r}; see `shadowscan connectors`")
    conf = parse_set_options(list(settings))
    if input_path:
        conf["input"] = input_path
    cfg = ScanConfig(connectors=[ConnectorSpec(name=connector, config=conf)], inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------- code
@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--github-org", help="scan every repository of a GitHub organisation (GITHUB_TOKEN)")
@click.option("--github-repo", multiple=True, help="owner/name (repeatable)")
@click.option("--gitlab-group", help="scan every project of a GitLab group (GITLAB_TOKEN)")
@click.option("--mode", type=click.Choice(["clone", "api"]), default=None, help="remote fetch mode")
@click.option("--exclude", multiple=True, help="extra directory names / globs to skip")
@click.option("--no-secrets", is_flag=True, help="skip credential detection")
@add_options(output_options)
def code(paths: tuple[str, ...], github_org: str | None, github_repo: tuple[str, ...], gitlab_group: str | None, mode: str | None, exclude: tuple[str, ...], no_secrets: bool, fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None) -> None:
    """Scan local directories and/or remote repositories for agent code, MCP, coding agents, IaC and secrets."""
    specs: list[ConnectorSpec] = []
    common: dict[str, Any] = {"exclude": list(exclude), "scan_secrets": not no_secrets}
    if paths:
        specs.append(ConnectorSpec(name="code.filesystem", config={"paths": list(paths), **common}))
    if github_org or github_repo:
        gh: dict[str, Any] = {**common}
        if github_org:
            gh["org"] = github_org
        if github_repo:
            gh["repos"] = list(github_repo)
        if mode:
            gh["mode"] = mode
        specs.append(ConnectorSpec(name="code.github", config=gh))
    if gitlab_group:
        gl: dict[str, Any] = {"group": gitlab_group, **common}
        if mode:
            gl["mode"] = mode
        specs.append(ConnectorSpec(name="code.gitlab", config=gl))
    if not specs:
        raise click.UsageError("give at least one PATH, --github-org/--github-repo or --gitlab-group")
    cfg = ScanConfig(connectors=specs, inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ------------------------------------------------------------------- gateway
@main.command()
@click.argument("logs", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--log-format", type=click.Choice(["auto", "litellm", "portkey", "kong", "cloudflare", "helicone", "langfuse", "bedrock", "azure-openai", "vertex", "openai-usage", "anthropic-usage", "access-log", "generic"]), default="auto", show_default=True)
@click.option("--min-events", type=int, default=1, show_default=True, help="ignore callers with fewer requests")
@click.option("--all-hosts", is_flag=True, help="for access logs, keep traffic to every host (default: LLM/agent hosts only)")
@click.option("--label", help="gateway name used as the findings' account/provider")
@add_options(output_options)
def gateway(logs: tuple[str, ...], log_format: str, min_events: int, all_hosts: bool, label: str | None, fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None) -> None:
    """Analyse LLM gateway / provider / proxy logs and reconstruct the callers."""
    specs = []
    for i, path in enumerate(logs):
        conf: dict[str, Any] = {"input": path, "min_events": min_events, "llm_hosts_only": not all_hosts}
        if log_format != "auto":
            conf["format"] = log_format
        if label:
            conf["label"] = label
        specs.append(ConnectorSpec(name="gateway.logs", config=conf, label=f"gateway.logs#{i + 1}" if len(logs) > 1 else None))
    cfg = ScanConfig(connectors=specs, inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ----------------------------------------------------------------------- jwt
@main.command()
@click.argument("tokens", nargs=-1)
@click.option("--file", "-F", "token_file", type=click.Path(exists=True, dir_okay=False), help="file with one JWT per line or a JSON list")
@click.option("--jwks-url", help="verify signatures against this JWKS endpoint")
@add_options(output_options)
def jwt(tokens: tuple[str, ...], token_file: str | None, jwks_url: str | None, fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None) -> None:
    """Classify JWTs as human / service / delegated-agent identities and assess their privileges."""
    conf: dict[str, Any] = {}
    if tokens:
        conf["tokens"] = [t.strip().removeprefix("Bearer ").strip() for t in tokens]
    if token_file:
        conf["input"] = token_file
    if jwks_url:
        conf["jwks_url"] = jwks_url
    if not conf.get("tokens") and not conf.get("input"):
        if not sys.stdin.isatty():
            conf["tokens"] = [line.strip() for line in sys.stdin if line.strip()]
        else:
            raise click.UsageError("give tokens as arguments, --file, or on stdin")
    cfg = ScanConfig(connectors=[ConnectorSpec(name="identity.jwt", config=conf)], inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ---------------------------------------------------------------- connectors
@main.command("connectors")
@click.option("--surface", type=click.Choice([s.value for s in Surface]), help="filter by surface")
@click.option("--json", "as_json", is_flag=True)
def list_connectors(surface: str | None, as_json: bool) -> None:
    """List available connectors and their configuration keys."""
    names = connectors_for_surface(surface) if surface else sorted(available_connectors())
    rows = []
    for n in names:
        try:
            cls = get_connector_class(n)
        except Exception as exc:  # noqa: BLE001
            rows.append({"name": n, "error": str(exc)})
            continue
        rows.append({"name": n, "surface": cls.surface.value, "description": cls.description, "config": cls.config_keys, "requires": cls.requires, "offline": cls.offline_formats})
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    table = Table(title="ShadowScan connectors", header_style="bold")
    table.add_column("Connector", no_wrap=True)
    table.add_column("Surface", no_wrap=True)
    table.add_column("Description", ratio=2)
    table.add_column("Config keys", ratio=2)
    for r in rows:
        if "error" in r:
            table.add_row(r["name"], "?", f"[red]{r['error']}[/red]", "")
            continue
        keys = "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in r["config"].items())
        extra = f"\n[dim]requires: {', '.join(r['requires'])}[/dim]" if r["requires"] else ""
        table.add_row(r["name"], r["surface"], r["description"] + extra, keys)
    console.print(table)


# ---------------------------------------------------------------- signatures
@main.group()
def signatures() -> None:
    """Inspect and test the detection signature packs."""


@signatures.command("list")
@click.option("--category", help="framework | provider | protocol | coding-agent | platform | cloud-service | observability | memory | sandbox | identity-app | heuristic | policy")
@click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory")
@click.option("--json", "as_json", is_flag=True)
def signatures_list(category: str | None, signature_dirs: tuple[str, ...], as_json: bool) -> None:
    """List loaded signatures."""
    idx = get_index(extra_dirs=list(signature_dirs) or None)
    sigs = sorted(idx.signatures.values(), key=lambda s: (s.category, s.id))
    if category:
        sigs = [s for s in sigs if s.category == category]
    if as_json:
        click.echo(json.dumps([{"id": s.id, "name": s.name, "category": s.category, "vendor": s.vendor, "signals": len(s.signals), "agent_indicator": s.agent_indicator, "capabilities": s.capabilities} for s in sigs], indent=2))
        return
    table = Table(title=f"{len(sigs)} signatures", header_style="bold")
    table.add_column("Id", no_wrap=True)
    table.add_column("Name")
    table.add_column("Category", no_wrap=True)
    table.add_column("Vendor")
    table.add_column("Signals", justify="right")
    table.add_column("Agent?", justify="center")
    for s in sigs:
        table.add_row(s.id, s.name, s.category, s.vendor or "", str(len(s.signals)), "✓" if s.agent_indicator else "")
    console.print(table)


@signatures.command("show")
@click.argument("signature_id")
@click.option("--signatures", "-s", "signature_dirs", multiple=True)
def signatures_show(signature_id: str, signature_dirs: tuple[str, ...]) -> None:
    """Print one signature as YAML."""
    idx = get_index(extra_dirs=list(signature_dirs) or None)
    sig = idx.get(signature_id)
    if not sig:
        raise click.BadParameter(f"unknown signature {signature_id!r}")
    data = {"id": sig.id, "name": sig.name, "category": sig.category, "vendor": sig.vendor, "homepage": sig.homepage, "description": sig.description, "capabilities": sig.capabilities, "agent_indicator": sig.agent_indicator, "risk_notes": sig.risk_notes, "source": sig.source, "signals": [{k: v for k, v in {"type": s.type, "weight": s.weight, "ecosystem": s.ecosystem, "languages": s.languages, "names": s.names, "prefixes": s.prefixes, "patterns": s.patterns, "globs": s.globs, "values": s.values, "capabilities": s.capabilities, "agent_indicator": s.agent_indicator}.items() if v not in (None, [], False)} for s in sig.signals]}
    click.echo(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


@signatures.command("test")
@click.argument("value")
@click.option("--kind", type=click.Choice(["auto", "dependency", "domain", "user-agent", "model", "name", "env", "scope", "image", "iac", "file", "text", "secret"]), default="auto", show_default=True)
@click.option("--ecosystem", default="any", show_default=True, help="for dependency: pypi | npm | go | cargo | maven | nuget | rubygems | composer")
@click.option("--signatures", "-s", "signature_dirs", multiple=True)
def signatures_test(value: str, kind: str, ecosystem: str, signature_dirs: tuple[str, ...]) -> None:
    """Test what a value matches, e.g. `shadowscan signatures test langchain-openai --kind dependency`."""
    idx = get_index(extra_dirs=list(signature_dirs) or None)
    kinds = [kind] if kind != "auto" else ["dependency", "domain", "user-agent", "model", "name", "env", "scope", "image", "iac", "file", "text", "secret"]
    matchers = {
        "dependency": lambda v: idx.match_dependency(ecosystem, v),
        "domain": idx.match_domain,
        "user-agent": idx.match_user_agent,
        "model": idx.match_model,
        "name": idx.match_name,
        "env": idx.match_env,
        "scope": idx.match_scope,
        "image": idx.match_image,
        "iac": idx.match_iac,
        "file": idx.match_file,
        "text": lambda v: idx.match_code(v) + idx.match_imports(v, None) + idx.match_domains_in_text(v) + idx.match_envs_in_text(v),
        "secret": idx.match_secrets,
    }
    found = False
    for k in kinds:
        for m in matchers[k](value):
            found = True
            console.print(f"[bold]{k:11}[/bold] {m.signature_id:40} weight={m.weight:.2f} agent={'yes' if m.agent_indicator else 'no '} caps={','.join(m.capabilities()) or '-'}  ← {m.value[:80]}")
    if not found:
        console.print("[dim]no match[/dim]")


# ----------------------------------------------------------------- inventory
@main.group()
def inventory() -> None:
    """Work with the sanctioned agent inventory (Agent Capability Cards)."""


@inventory.command("check")
@click.argument("paths", nargs=-1, required=True)
def inventory_check(paths: tuple[str, ...]) -> None:
    """Validate inventory files and list the registered agents."""
    inv = Inventory.load(list(paths))
    table = Table(title=f"{len(inv)} registered agents", header_style="bold")
    table.add_column("Agent id")
    table.add_column("Name")
    table.add_column("Owner")
    table.add_column("Resources")
    table.add_column("Source")
    for e in inv.entries:
        table.add_row(e.agent_id, e.name or "", e.owner or "", "\n".join(e.resources) or "[dim]none (matched by id/name)[/dim]", e.source or "")
    console.print(table)


@inventory.command("stubs")
@click.argument("findings_json", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "-o", "out_dir", type=click.Path(file_okay=False), required=True, help="directory to write one capability-card YAML per shadow agent")
@click.option("--kinds", default="agent,mcp-server,workflow,bot-app,agent-config", show_default=True, help="finding kinds to register")
@click.option("--min-risk", type=click.Choice(LEVELS), default="low", show_default=True)
def inventory_stubs(findings_json: str, out_dir: str, kinds: str, min_risk: str) -> None:
    """Generate Agent Capability Card stubs for shadow findings so they can be reviewed and registered."""
    data = json.loads(Path(findings_json).read_text(encoding="utf-8"))
    wanted = {k.strip() for k in kinds.split(",")}
    threshold = LEVELS.index(min_risk)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    n = 0
    for d in data.get("findings", []):
        f = Finding.from_dict(d)
        if f.kind.value not in wanted or f.shadow is False or LEVELS.index(f.risk.level.value) > threshold:
            continue
        card = card_stub_for(f)
        path = out / f"{card['metadata']['agent_id']}-{f.id[-6:]}.yaml"
        path.write_text(yaml.safe_dump(card, sort_keys=False, allow_unicode=True), encoding="utf-8")
        n += 1
    console.print(f"[green]wrote {n} capability card stub(s) to {out}[/green]")


# ---------------------------------------------------------------------- diff
@main.command()
@click.argument("baseline", type=click.Path(exists=True, dir_okay=False))
@click.argument("current", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True)
def diff(baseline: str, current: str, as_json: bool) -> None:
    """Compare two JSON reports: new, resolved and changed-risk findings."""
    b = {d["id"]: d for d in json.loads(Path(baseline).read_text(encoding="utf-8")).get("findings", [])}
    c = {d["id"]: d for d in json.loads(Path(current).read_text(encoding="utf-8")).get("findings", [])}
    new = [c[i] for i in c.keys() - b.keys()]
    resolved = [b[i] for i in b.keys() - c.keys()]
    changed = [(b[i], c[i]) for i in b.keys() & c.keys() if b[i]["risk"]["level"] != c[i]["risk"]["level"]]
    if as_json:
        click.echo(json.dumps({"new": new, "resolved": resolved, "changed": [{"before": x, "after": y} for x, y in changed]}, indent=2, default=str))
        return
    console.print(f"[bold]{len(new)} new[/bold], [bold]{len(resolved)} resolved[/bold], [bold]{len(changed)} changed risk[/bold]")
    for d in sorted(new, key=lambda d: -d["risk"]["score"]):
        console.print(f"  [green]+[/green] {d['risk']['level']:8} {d['title']}  [dim]{d['resource']}[/dim]")
    for d in resolved:
        console.print(f"  [red]-[/red] {d['risk']['level']:8} {d['title']}  [dim]{d['resource']}[/dim]")
    for x, y in changed:
        console.print(f"  [yellow]~[/yellow] {x['risk']['level']} → {y['risk']['level']} {y['title']}")


if __name__ == "__main__":  # pragma: no cover
    main()
