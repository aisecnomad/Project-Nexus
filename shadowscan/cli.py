"""ShadowScan command line interface."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from typing import Any

import click
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from shadowscan import __version__
from shadowscan.comparison import MAX_REPORT_BYTES, compare_reports, load_report
from shadowscan.config import (
    ConfigValidationError,
    ConnectorSpec,
    ScanConfig,
    parse_set_options,
    validate_connector_timeout,
    validate_min_confidence,
)
from shadowscan.connectors import (
    available_connectors,
    builtin_connector_names,
    connectors_for_surface,
    get_connector_class,
)
from shadowscan.engine import Engine
from shadowscan.models import Finding, ScanResult, Surface
from shadowscan.registry import Inventory, InventoryValidationError, card_stub_for
from shadowscan.reporters import FORMATS, render
from shadowscan.reporters.table import print_table
from shadowscan.signatures import get_index
from shadowscan.utils.output import prepare_private_directory, write_private_text
from shadowscan.utils.redaction import REDACTED, sanitize_text

console = Console(width=None if sys.stdout.isatty() else 200)
err_console = Console(stderr=True)
LEVELS = ["critical", "high", "medium", "low", "info"]


def _load_report(path: str) -> dict[str, Any]:
    """Turn strict, bounded report import failures into a CLI usage error."""
    try:
        return load_report(path)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise click.ClickException(
            f"could not read a ShadowScan JSON report (regular file, at most {MAX_REPORT_BYTES // (1024 * 1024)} MiB)"
        ) from None


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
        try:
            write_private_text(output, text)
        except (OSError, ValueError):
            raise click.ClickException("could not write report; check output path and permissions") from None
        err_console.print(f"[green]wrote {fmt if fmt != 'table' else 'json'} report to {output}[/green]")
        if fmt == "table":
            print_table(result, console=console, verbose=verbose, max_rows=max_rows)
    else:
        click.echo(text)


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not result.complete:
        return 3
    if not fail_on:
        return 0
    threshold = LEVELS.index(fail_on)
    worst = min((LEVELS.index(f.risk.level.value) for f in result.findings), default=len(LEVELS))
    return 2 if worst <= threshold else 0


def _run_and_emit(cfg: ScanConfig, fmt: str, output: str | None, verbose: int, max_rows: int | None, only: list[str] | None = None) -> None:
    def progress(cid: str, msg: str) -> None:
        err_console.print(f"[dim]{escape(cid)}: {escape(msg)}[/dim]")

    try:
        engine = Engine(cfg, progress=progress if verbose else None)
        result = engine.run(only=only)
    except InventoryValidationError as exc:
        raise click.ClickException(str(exc)) from None
    except (ValueError, TypeError, OSError, yaml.YAMLError):
        raise click.ClickException("scan setup failed; check connector configuration, signature packs and inventory") from None
    try:
        _emit(result, fmt, output, verbose=bool(verbose), max_rows=max_rows)
    except Exception:  # noqa: BLE001 - any emission failure must still release an abandoned CLI worker
        if engine.abandoned_workers:
            err_console.print("[red]could not emit the incomplete report; exiting without waiting for timed-out workers[/red]")
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(1)
        raise
    code = _exit_code(result, cfg.fail_on)
    if engine.abandoned_workers:
        # A timed-out connector's thread may still be blocked in an SDK call.
        # Python joins worker threads at interpreter exit, which would hold the
        # process (and its CI job) open indefinitely. The report is written.
        err_console.print(
            f"[yellow]exiting without waiting for {len(engine.abandoned_workers)} timed-out connector worker(s)[/yellow]"
        )
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    sys.exit(code)


def _min_confidence_option(ctx: click.Context, param: click.Parameter, value: float) -> float:
    try:
        return validate_min_confidence(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


def _apply_security_options(cfg: ScanConfig, allow_plugin: tuple[str, ...], allow_signature_override: bool | None, allow_private_origin: bool | None, allow_instance_credentials: bool | None, allow_credential_mixing: bool | None, connector_timeout_seconds: float | None) -> None:
    cfg.plugins = list(dict.fromkeys([*cfg.plugins, *allow_plugin]))
    if allow_signature_override is not None:
        cfg.allow_signature_override = allow_signature_override
    if allow_private_origin is not None:
        cfg.allow_private_origin = allow_private_origin
    if allow_instance_credentials is not None:
        cfg.allow_instance_credentials = allow_instance_credentials
    if allow_credential_mixing is not None:
        cfg.allow_credential_mixing = allow_credential_mixing
    if connector_timeout_seconds is not None:
        cfg.connector_timeout_seconds = connector_timeout_seconds


def _connector_timeout_option(ctx: click.Context, param: click.Parameter, value: float | None) -> float | None:
    if value is None:
        return None
    try:
        return validate_connector_timeout(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


output_options = [
    click.option("--allow-instance-credentials/--deny-instance-credentials", default=None, help="explicitly allow cloud instance or managed-identity credentials"),
    click.option("--allow-credential-mixing/--deny-credential-mixing", default=None, help="allow reviewed source inputs alongside live credentialed connectors"),
    click.option("--connector-timeout-seconds", "--connector-timeout", "connector_timeout_seconds", type=float, callback=_connector_timeout_option, help="per-connector completion deadline in seconds (default: 120); --connector-timeout is a deprecated alias; blocking calls cannot be forcibly stopped"),
    click.option("--allow-plugin", multiple=True, help="allow one reviewed third-party connector name (repeatable)"),
    click.option("--allow-signature-override/--deny-signature-override", default=None, help="explicitly allow a reviewed custom pack to replace built-in signatures"),
    click.option("--allow-private-origin/--deny-private-origin", default=None, help="allow private HTTPS endpoints for this scan; origin restrictions still apply"),
    click.option("--incremental/--no-incremental", default=None, help="reuse completed scans when input content and signatures are unchanged"),
    click.option("--state-dir", type=click.Path(file_okay=False), help="private incremental state directory, outside scanned repositories"),
    click.option("--format", "-f", "fmt", type=click.Choice(FORMATS), default="table", show_default=True, help="output format"),
    click.option("--output", "-o", type=click.Path(dir_okay=False), help="write the report to a file (table format also prints to the terminal)"),
    click.option("--inventory", "-i", multiple=True, help="sanctioned inventory: Agent Capability Cards dir/file, agents.yaml or CSV (repeatable)"),
    click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory (repeatable)"),
    click.option("--min-confidence", type=float, default=0.0, show_default=True, callback=_min_confidence_option, help="drop findings below this confidence (finite 0–1)"),
    click.option("--fail-on", type=click.Choice(LEVELS), help="exit 2 if any finding reaches this risk level"),
    click.option("--max-rows", type=int, default=None, help="limit rows printed in table mode"),
    click.option("--dump-records", type=click.Path(file_okay=False), help="directory for sanitized connector records (JWTs are never exported)"),
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
def scan(config_path: str, only: tuple[str, ...], fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None, incremental: bool | None, state_dir: str | None, allow_plugin: tuple[str, ...], allow_signature_override: bool | None, allow_private_origin: bool | None, allow_instance_credentials: bool | None, allow_credential_mixing: bool | None, connector_timeout_seconds: float | None) -> None:
    """Run every connector defined in a config file."""
    try:
        cfg = ScanConfig.from_yaml(config_path)
    except ConfigValidationError as exc:
        raise click.ClickException(f"invalid scan configuration: {exc}") from None
    except ValueError as exc:
        if str(exc) == "min_confidence must be a finite number between 0 and 1":
            raise click.BadParameter(str(exc), param_hint="--config") from None
        raise click.ClickException("invalid scan configuration; check YAML structure and option types") from None
    except (TypeError, AttributeError, OSError, yaml.YAMLError):
        raise click.ClickException("invalid scan configuration; check YAML structure and option types") from None
    cfg.inventory.extend(inventory)
    cfg.signature_dirs.extend(signature_dirs)
    cfg.min_confidence = max(cfg.min_confidence, min_confidence)
    cfg.fail_on = fail_on or cfg.fail_on
    cfg.dump_records = dump_records or cfg.dump_records
    if incremental is not None:
        cfg.incremental = incremental
    if state_dir is not None:
        cfg.state_dir = state_dir
    _apply_security_options(cfg, allow_plugin, allow_signature_override, allow_private_origin, allow_instance_credentials, allow_credential_mixing, connector_timeout_seconds)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows, only=list(only) or None)  # type: ignore[attr-defined]


# ----------------------------------------------------------------------- run
@main.command()
@click.argument("connector")
@click.option("--input", "input_path", type=click.Path(exists=True), help="offline export (file or directory) instead of the live API")
@click.option("--set", "-S", "settings", multiple=True, help="connector option key=value (repeatable; lists as a,b,c)")
@add_options(output_options)
def run(connector: str, input_path: str | None, settings: tuple[str, ...], fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None, incremental: bool | None, state_dir: str | None, allow_plugin: tuple[str, ...], allow_signature_override: bool | None, allow_private_origin: bool | None, allow_instance_credentials: bool | None, allow_credential_mixing: bool | None, connector_timeout_seconds: float | None) -> None:
    """Run a single connector, e.g. `shadowscan run identity.okta --set org_url=https://acme.okta.com`."""
    if connector not in available_connectors():
        raise click.BadParameter(f"unknown connector {connector!r}; see `shadowscan connectors`")
    try:
        conf = parse_set_options(list(settings))
    except (ValueError, TypeError):
        raise click.BadParameter("--set expects key=value pairs") from None
    if input_path:
        conf["input"] = input_path
    cfg = ScanConfig(connectors=[ConnectorSpec(name=connector, config=conf)], inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records, incremental=bool(incremental), state_dir=state_dir)
    _apply_security_options(cfg, allow_plugin, allow_signature_override, allow_private_origin, allow_instance_credentials, allow_credential_mixing, connector_timeout_seconds)
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
def code(paths: tuple[str, ...], github_org: str | None, github_repo: tuple[str, ...], gitlab_group: str | None, mode: str | None, exclude: tuple[str, ...], no_secrets: bool, fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None, incremental: bool | None, state_dir: str | None, allow_plugin: tuple[str, ...], allow_signature_override: bool | None, allow_private_origin: bool | None, allow_instance_credentials: bool | None, allow_credential_mixing: bool | None, connector_timeout_seconds: float | None) -> None:
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
    cfg = ScanConfig(connectors=specs, inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records, incremental=bool(incremental), state_dir=state_dir)
    _apply_security_options(cfg, allow_plugin, allow_signature_override, allow_private_origin, allow_instance_credentials, allow_credential_mixing, connector_timeout_seconds)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ------------------------------------------------------------------- gateway
@main.command()
@click.argument("logs", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--log-format", type=click.Choice(["auto", "litellm", "portkey", "kong", "cloudflare", "helicone", "langfuse", "bedrock", "azure-openai", "vertex", "openai-usage", "anthropic-usage", "access-log", "generic"]), default="auto", show_default=True)
@click.option("--min-events", type=int, default=1, show_default=True, help="ignore callers with fewer requests")
@click.option("--all-hosts", is_flag=True, help="for access logs, keep traffic to every host (default: LLM/agent hosts only)")
@click.option("--label", help="gateway name used as the findings' account/provider")
@add_options(output_options)
def gateway(logs: tuple[str, ...], log_format: str, min_events: int, all_hosts: bool, label: str | None, fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None, incremental: bool | None, state_dir: str | None, allow_plugin: tuple[str, ...], allow_signature_override: bool | None, allow_private_origin: bool | None, allow_instance_credentials: bool | None, allow_credential_mixing: bool | None, connector_timeout_seconds: float | None) -> None:
    """Analyse LLM gateway / provider / proxy logs and reconstruct the callers."""
    specs = []
    for i, path in enumerate(logs):
        conf: dict[str, Any] = {"input": path, "min_events": min_events, "llm_hosts_only": not all_hosts}
        if log_format != "auto":
            conf["format"] = log_format
        if label:
            conf["label"] = label
        specs.append(ConnectorSpec(name="gateway.logs", config=conf, label=f"gateway.logs#{i + 1}" if len(logs) > 1 else None))
    cfg = ScanConfig(connectors=specs, inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records, incremental=bool(incremental), state_dir=state_dir)
    _apply_security_options(cfg, allow_plugin, allow_signature_override, allow_private_origin, allow_instance_credentials, allow_credential_mixing, connector_timeout_seconds)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ----------------------------------------------------------------------- jwt
@main.command()
@click.argument("tokens", nargs=-1)
@click.option("--file", "-F", "token_file", type=click.Path(exists=True, dir_okay=False), help="file with one JWT per line or a JSON list")
@click.option("--jwks-url", help="verify signatures against this trusted JWKS endpoint")
@click.option("--expected-issuer", help="require this exact issuer when checking a JWT signature")
@click.option("--jwt-algorithm", multiple=True, type=click.Choice(["RS256", "ES256", "EdDSA", "PS256"]), help="narrow allowed signature algorithms (repeatable)")
@add_options(output_options)
def jwt(tokens: tuple[str, ...], token_file: str | None, jwks_url: str | None, expected_issuer: str | None, jwt_algorithm: tuple[str, ...], fmt: str, output: str | None, inventory: tuple[str, ...], signature_dirs: tuple[str, ...], min_confidence: float, fail_on: str | None, max_rows: int | None, dump_records: str | None, incremental: bool | None, state_dir: str | None, allow_plugin: tuple[str, ...], allow_signature_override: bool | None, allow_private_origin: bool | None, allow_instance_credentials: bool | None, allow_credential_mixing: bool | None, connector_timeout_seconds: float | None) -> None:
    """Classify JWTs as human / service / delegated-agent identities and assess their privileges."""
    conf: dict[str, Any] = {}
    if tokens:
        conf["tokens"] = [t.strip().removeprefix("Bearer ").strip() for t in tokens]
    if token_file:
        conf["input"] = token_file
    if expected_issuer or jwt_algorithm:
        if not jwks_url:
            raise click.UsageError("--expected-issuer and --jwt-algorithm require --jwks-url")
    if jwks_url:
        conf["jwks_url"] = jwks_url
    if expected_issuer:
        conf["expected_issuer"] = expected_issuer
    if jwt_algorithm:
        conf["allowed_algorithms"] = list(jwt_algorithm)
    if not conf.get("tokens") and not conf.get("input"):
        if not sys.stdin.isatty():
            conf["tokens"] = [line.strip() for line in sys.stdin if line.strip()]
        else:
            raise click.UsageError("give tokens as arguments, --file, or on stdin")
    cfg = ScanConfig(connectors=[ConnectorSpec(name="identity.jwt", config=conf)], inventory=list(inventory), signature_dirs=list(signature_dirs), min_confidence=min_confidence, fail_on=fail_on, dump_records=dump_records, incremental=bool(incremental), state_dir=state_dir)
    _apply_security_options(cfg, allow_plugin, allow_signature_override, allow_private_origin, allow_instance_credentials, allow_credential_mixing, connector_timeout_seconds)
    _run_and_emit(cfg, fmt, output, main.verbose, max_rows)  # type: ignore[attr-defined]


# ---------------------------------------------------------------- connectors
@main.command("connectors")
@click.option("--surface", type=click.Choice([s.value for s in Surface]), help="filter by surface")
@click.option("--json", "as_json", is_flag=True)
def list_connectors(surface: str | None, as_json: bool) -> None:
    """List available connectors and their configuration keys."""
    names = connectors_for_surface(surface) if surface else sorted(available_connectors())
    rows: list[dict[str, Any]] = []
    for n in names:
        if n not in builtin_connector_names():
            rows.append({"name": n, "surface": n.split(".")[0], "description": "Third-party plugin (not loaded; explicitly allow before use)", "config": {}, "requires": [], "offline": "unknown", "enabled": False})
            continue
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
            table.add_row(Text(r["name"]), "?", Text(r["error"], style="red"), "")
            continue
        keys = "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in r["config"].items())
        extra = f"\n[dim]requires: {', '.join(r['requires'])}[/dim]" if r["requires"] else ""
        table.add_row(Text(r["name"]), Text(str(r["surface"])), Text(r["description"] + extra), Text(keys))
    console.print(table)


# ---------------------------------------------------------------- signatures
@main.group()
def signatures() -> None:
    """Inspect and test the detection signature packs."""


@signatures.command("list")
@click.option("--category", help="framework | provider | protocol | coding-agent | platform | cloud-service | observability | memory | sandbox | identity-app | heuristic | policy")
@click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory")
@click.option("--json", "as_json", is_flag=True)
@click.option("--allow-signature-override", is_flag=True, help="allow a reviewed pack to replace built-in signatures")
def signatures_list(category: str | None, signature_dirs: tuple[str, ...], as_json: bool, allow_signature_override: bool) -> None:
    """List loaded signatures."""
    idx = get_index(extra_dirs=list(signature_dirs) or None, allow_override=allow_signature_override)
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
        table.add_row(Text(s.id), Text(s.name), Text(s.category), Text(s.vendor or ""), str(len(s.signals)), "✓" if s.agent_indicator else "")
    console.print(table)


@signatures.command("show")
@click.argument("signature_id")
@click.option("--signatures", "-s", "signature_dirs", multiple=True)
@click.option("--allow-signature-override", is_flag=True, help="allow a reviewed pack to replace built-in signatures")
def signatures_show(signature_id: str, signature_dirs: tuple[str, ...], allow_signature_override: bool) -> None:
    """Print one signature as YAML."""
    idx = get_index(extra_dirs=list(signature_dirs) or None, allow_override=allow_signature_override)
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
@click.option("--allow-signature-override", is_flag=True, help="allow a reviewed pack to replace built-in signatures")
def signatures_test(value: str, kind: str, ecosystem: str, signature_dirs: tuple[str, ...], allow_signature_override: bool) -> None:
    """Test what a value matches, e.g. `shadowscan signatures test langchain-openai --kind dependency`."""
    idx = get_index(extra_dirs=list(signature_dirs) or None, allow_override=allow_signature_override)
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
            # Secret signatures keep raw match values so the scanner can
            # fingerprint them before producing sanitized findings. Never
            # reflect those values in terminal output or captured CI logs.
            shown = REDACTED if k == "secret" else sanitize_text(m.value)[:80]
            console.print(f"[bold]{k:11}[/bold] {m.signature_id:40} weight={m.weight:.2f} agent={'yes' if m.agent_indicator else 'no '} caps={','.join(m.capabilities()) or '-'}  ← {escape(shown)}")
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
    try:
        inv = Inventory.load(list(paths))
    except InventoryValidationError as exc:
        raise click.ClickException(str(exc)) from None
    except (ValueError, TypeError, OSError, yaml.YAMLError):
        raise click.ClickException("could not load inventory; check file access and document structure") from None
    table = Table(title=f"{len(inv)} registered agents", header_style="bold")
    table.add_column("Agent id")
    table.add_column("Name")
    table.add_column("Owner")
    table.add_column("Resources")
    table.add_column("Source")
    for e in inv.entries:
        resources = Text("\n".join(e.resources)) if e.resources else Text("none (suggestions only)", style="dim")
        table.add_row(Text(e.agent_id), Text(e.name or ""), Text(e.owner or ""), resources, Text(e.source or ""))
    console.print(table)


@inventory.command("stubs")
@click.argument("findings_json", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "-o", "out_dir", type=click.Path(file_okay=False), required=True, help="directory to write one capability-card YAML per shadow agent")
@click.option("--kinds", default="agent,mcp-server,workflow,bot-app,agent-config", show_default=True, help="finding kinds to register")
@click.option("--min-risk", type=click.Choice(LEVELS), default="low", show_default=True)
def inventory_stubs(findings_json: str, out_dir: str, kinds: str, min_risk: str) -> None:
    """Generate Agent Capability Card stubs for shadow findings so they can be reviewed and registered."""
    wanted = {k.strip() for k in kinds.split(",")}
    threshold = LEVELS.index(min_risk)
    # Finish validation and card generation before writing any approval stubs.
    # A bad later record must not leave an apparently successful partial import.
    data = _load_report(findings_json)
    try:
        cards = []
        for record in data["findings"]:
            finding = Finding.from_dict(record)
            if finding.kind.value not in wanted or finding.shadow is False or LEVELS.index(finding.risk.level.value) > threshold:
                continue
            cards.append((finding.id, card_stub_for(finding)))
    except (ValueError, TypeError, OSError, KeyError, AttributeError, RecursionError):
        raise click.ClickException("report contains a malformed finding; no inventory stubs were written") from None
    try:
        out = prepare_private_directory(out_dir)
    except (OSError, ValueError):
        raise click.ClickException("inventory output requires a private directory with mode 0700 and no symlinks") from None
    n = 0
    for finding_id, card in cards:
        suffix = hashlib.sha256(finding_id.encode()).hexdigest()[:8]
        path = out / f"{card['metadata']['agent_id']}-{suffix}.yaml"
        try:
            write_private_text(path, yaml.safe_dump(card, sort_keys=False, allow_unicode=True))
        except (OSError, ValueError):
            raise click.ClickException("could not write inventory stub; check output path and permissions") from None
        n += 1
    console.print(f"[green]wrote {n} capability card stub(s) to {out}[/green]")


# ---------------------------------------------------------------------- diff
@main.command()
@click.argument("baseline", type=click.Path(exists=True, dir_okay=False))
@click.argument("current", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True)
def diff(baseline: str, current: str, as_json: bool) -> None:
    """Compare reports; missing findings require complete, comparable scans to resolve."""
    try:
        comparison = compare_reports(
            load_report(baseline),
            load_report(current),
        )
    except (ValueError, TypeError, OSError):
        raise click.ClickException("invalid comparison input; expected two ShadowScan JSON reports") from None
    if as_json:
        click.echo(json.dumps(comparison, indent=2, default=str))
    else:
        new, resolved, unknown, changed = (comparison[key] for key in ("new", "resolved", "unknown", "changed"))
        console.print(f"[bold]{len(new)} new[/bold], [bold]{len(resolved)} resolved[/bold], [bold]{len(unknown)} unknown[/bold], [bold]{len(changed)} changed[/bold]")
        for reason in comparison["reasons"]:
            console.print(f"Comparison incomplete: {reason}", markup=False)
        for marker, records in (("+", new), ("-", resolved), ("?", unknown)):
            for d in sorted(records, key=lambda d: -d["risk"]["score"]):
                console.print(f"  {marker} {d['risk']['level']:8} {d['title']}  {d['resource']}", markup=False)
        for change in changed:
            x, y = change["before"], change["after"]
            fields = ", ".join(change["changed_fields"])
            console.print(f"  ~ {y['title']}: {fields} (risk {x['risk']['score']} → {y['risk']['score']})", markup=False)
    if not comparison["comparable"]:
        raise click.exceptions.Exit(3)


if __name__ == "__main__":  # pragma: no cover
    main()
