"""Exercise audited collectors against pre-existing controls; never provision resources.

Replay checks analysis contracts only. A live pass requires authenticated scope,
complete collection, observed control records and the expected classifications.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from shadowscan import __version__
from shadowscan.config import ConnectorSpec, ScanConfig, expand_env
from shadowscan.connectors.cloud.aws import KNOWN_SERVICES
from shadowscan.engine import Engine
from shadowscan.models import Kind, ScanResult, now_iso
from shadowscan.signatures import get_index
from shadowscan.utils.files import read_policy_text
from shadowscan.utils.git import metadata_git_argv_prefix, metadata_git_env
from shadowscan.utils.output import write_private_text
from shadowscan.utils.redaction import sanitize
from shadowscan.utils.safe_yaml import BoundedSafeLoader

SCHEMA = "shadowscan.tenant-canary/v1"
REPORT_SCHEMA = "shadowscan.tenant-canary-report/v1"
ROOT = Path(__file__).resolve().parents[2]
_ENV = re.compile(r"\$\{[A-Z][A-Z0-9_]*\}")
_CONTROL_IDENTITIES = {
    "cloud.aws": {"lambda": "FunctionArn", "bedrock-agent": "agentArn", "agentcore-runtime": "agentRuntimeArn",
                  "ecs-task-definition": "taskDefinitionArn", "sagemaker-endpoint": "EndpointArn", "state-machine": "stateMachineArn"},
    "saas.slack": {"approved_app": "app.id", "restricted_app": "app.id", "app_request": "app.id",
                   "bot_user": "profile.api_app_id"},
}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}")
_DENIED = re.compile(
    r"(?:cloud\.aws: [a-z_]+ collection failed \(access denied "
    r"\((?:AccessDenied|AccessDeniedException|UnauthorizedOperation)\)\)"
    r"|saas\.slack: /[A-Za-z.]+: (?:missing_scope|restricted_action); coverage unknown)"
)


class _CanaryLoader(BoundedSafeLoader):
    """Reject ambiguous duplicate fields in operator acceptance policy."""

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        self.flatten_mapping(node)
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if any(not isinstance(key, str) for key in keys) or len(keys) != len(set(keys)):
            raise ValueError("canary mapping keys must be unique strings")
        return super().construct_mapping(node, deep=deep)


class CanaryConfigError(ValueError):
    """Configuration rejection without reflecting potentially sensitive values."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CanaryConfigError(message)


def _keys(value: Any, allowed: set[str], required: set[str], label: str) -> None:
    _require(isinstance(value, dict), f"{label} must be a mapping")
    _require(set(value) <= allowed and required <= set(value), f"{label} has missing or unsupported fields")


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 2048


def _strings(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_text(item) for item in value)


def validate(config: dict[str, Any]) -> None:
    _keys(config, {"schema", "mode", "expectation", "connector", "scope", "ground_truth", "controls"},
          {"schema", "mode", "expectation", "connector", "scope", "ground_truth", "controls"}, "canary")
    _require(config["schema"] == SCHEMA, "unsupported canary schema")
    _require(isinstance(config["mode"], str) and config["mode"] in {"live", "replay"}, "mode must be live or replay")
    _require(isinstance(config["expectation"], str) and config["expectation"] in {"complete", "permission-denied"}, "unsupported expectation")
    _require(config["mode"] == "live" or config["expectation"] == "complete",
             "permission denial requires live transport; replay cannot establish IAM behavior")
    truth = config["ground_truth"]
    _keys(truth, {"owner", "reviewed_at", "source", "independent_of_scanner"},
          {"owner", "reviewed_at", "source", "independent_of_scanner"}, "ground truth")
    _require(all(_text(truth[key]) for key in ("owner", "reviewed_at", "source"))
             and truth["independent_of_scanner"] is True, "ground truth requires independent operator review")
    connector = config["connector"]
    _keys(connector, {"name", "input", "token", "regions", "services", "account_id", "team_id"},
          {"name"}, "connector")
    name = connector["name"]
    _require(isinstance(name, str) and name in {"cloud.aws", "saas.slack"}, "only audited AWS and Slack collectors are enabled")
    scope = config["scope"]
    if name == "cloud.aws":
        _keys(scope, {"account_id", "regions", "services"}, {"account_id", "regions", "services"}, "AWS scope")
        _require(isinstance(scope["account_id"], str) and bool(re.fullmatch(r"[0-9]{12}", scope["account_id"])),
                 "AWS account must be an explicit 12-digit string")
        _require(_strings(scope["regions"]) and all(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", r) for r in scope["regions"]),
                 "AWS regions must be explicit; all-region discovery is disabled")
        _require(_strings(scope["services"]) and set(scope["services"]) <= KNOWN_SERVICES, "AWS services must be explicit")
        _require(set(connector) <= {"name", "input", "account_id", "regions", "services"}, "unsupported AWS connector settings")
        for key in ("account_id", "regions", "services"):
            _require(connector.get(key) == scope[key], "connector and approved AWS scope must agree")
    else:
        _keys(scope, {"team_id"}, {"team_id"}, "Slack scope")
        _require(isinstance(scope["team_id"], str) and bool(re.fullmatch(r"T[A-Z0-9]+", scope["team_id"])),
                 "Slack workspace ID must be explicit")
        _require(set(connector) <= {"name", "input", "token", "team_id"}, "unsupported Slack connector settings")
        _require(connector.get("team_id") == scope["team_id"], "connector and approved Slack workspace must agree")
    if config["mode"] == "live":
        _require("input" not in connector, "live canaries forbid replay inputs")
        if name == "saas.slack":
            _require(isinstance(connector.get("token"), str) and bool(_ENV.fullmatch(connector["token"])),
                     "Slack token must be a required environment reference; literals and fallbacks are forbidden")
    else:
        _require(_text(connector.get("input")) and "token" not in connector, "replay requires an input and forbids tokens")
    controls = config["controls"]
    _require(isinstance(controls, list) and len(controls) <= 1000, "controls must be a bounded list")
    ids: set[str] = set()
    resources: set[str] = set()
    for control in controls:
        _keys(control, {"id", "record", "finding", "rationale"}, {"id", "record", "finding", "rationale"}, "control")
        _require(isinstance(control["id"], str) and bool(_ID.fullmatch(control["id"])) and control["id"] not in ids,
                 "control IDs must be unique safe identifiers")
        ids.add(control["id"])
        _require(_text(control["rationale"]), "controls require an independent labeling rationale")
        record = control["record"]
        _require(isinstance(record, dict) and 1 <= len(record) <= 20 and all(
            isinstance(k, str) and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", k)) and _text(v)
            for k, v in record.items()), "record selectors must be nonempty exact string field matches")
        finding = control["finding"]
        _keys(finding, {"resource", "kind", "present"}, {"resource", "present"}, "finding expectation")
        _require(_text(finding["resource"]) and isinstance(finding["present"], bool), "invalid finding expectation")
        identity_key = _CONTROL_IDENTITIES[name].get(record.get("_kind", ""))
        _require(identity_key is not None and identity_key in record,
                 "control requires a supported object kind and its exact canonical identity field")
        expected_resource = record[identity_key] if name == "cloud.aws" else f"slack:app:{record[identity_key]}"
        _require(finding["resource"] == expected_resource,
                 "record selector identity and expected finding resource must identify the same object")
        _require(finding["resource"] not in resources, "control resources must be unique")
        resources.add(finding["resource"])
        if name == "cloud.aws":
            arn = expected_resource.split(":", 5)
            _require(len(arn) == 6 and arn[0] == "arn" and arn[1] in {"aws", "aws-cn", "aws-us-gov"}
                     and arn[4] == scope["account_id"] and arn[3] in scope["regions"],
                     "AWS control must be a canonical ARN within approved account and regions")
        if finding["present"]:
            _require(isinstance(finding.get("kind"), str) and finding.get("kind") in {kind.value for kind in Kind}, "positive controls require a known finding kind")
        else:
            _require("kind" not in finding, "negative controls must reject every finding kind for the known resource")
    if config["expectation"] == "complete":
        _require(any(c["finding"]["present"] for c in controls) and any(not c["finding"]["present"] for c in controls),
                 "complete canaries require observed positive and benign negative controls")
    else:
        _require(not controls, "permission-denied runs use scope and classified denial rather than missing objects as evidence")


def _sanitized(report: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = sanitize(report)
    return clean


def load_config(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.load(read_policy_text(path, max_bytes=1024 * 1024), Loader=_CanaryLoader)
    validate(data)
    if data["mode"] == "replay":
        source = Path(data["connector"]["input"])
        data["connector"]["input"] = str(source if source.is_absolute() else path.parent / source)
    return data


def _preflight(config: dict[str, Any]) -> str | None:
    if config["mode"] != "live":
        return None
    if config["connector"]["name"] == "cloud.aws":
        # Avoid profiles (which can execute credential_process), implicit default
        # tenants and metadata providers. Dedicated temporary environment keys
        # support both full-read and already-restricted audit identities.
        if any(os.environ.get(key) for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_DATA_PATH")):
            return "ambient_profile_or_web_identity_forbidden"
        if any(key.startswith("AWS_ENDPOINT_URL") and value for key, value in os.environ.items()):
            return "ambient_endpoint_override_forbidden"
        if not all(os.environ.get(key) for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")):
            return "explicit_aws_credentials_missing"
    else:
        name = config["connector"]["token"][2:-1]
        if not os.environ.get(name):
            return "explicit_slack_credential_missing"
    return None


def _path_value(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _match(record: dict[str, Any], selector: dict[str, Any]) -> bool:
    return all(_path_value(record, key) == value for key, value in selector.items())


def evaluate(config: dict[str, Any], result: ScanResult, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Assertions are identical for replay and live; provenance remains distinct."""
    scope = config["scope"]
    aws = config["connector"]["name"] == "cloud.aws"
    identity = [r for r in records if r.get("_kind") == ("account" if aws else "team")]
    expected_id = scope["account_id"] if aws else scope["team_id"]
    observed_ids = [r.get("account" if aws else "id") for r in identity]
    scope_ok = bool(identity) and all(identifier == expected_id for identifier in observed_ids)
    if aws:
        scope_ok = scope_ok and all(_strings(r.get("regions")) and set(r["regions"]) == set(scope["regions"]) for r in identity)
        scope_ok = scope_ok and all(f.account == expected_id for f in result.findings)
        scope_ok = scope_ok and all(not f.region or f.region in scope["regions"] for f in result.findings)
    control_reports = []
    for control in config["controls"]:
        expected = control["finding"]
        identity_key = _CONTROL_IDENTITIES[config["connector"]["name"]][control["record"]["_kind"]]
        observations = [record for record in records if _match(record, control["record"]) and (
            _path_value(record, identity_key) if aws else f"slack:app:{_path_value(record, identity_key)}"
        ) == expected["resource"]]
        findings = [f for f in result.findings if f.resource == expected["resource"]]
        matched = [f for f in findings if f.kind.value == expected.get("kind")]
        passed = bool(observations) and (bool(matched) if expected["present"] else not findings)
        control_reports.append({
            "id": control["id"], "rationale": control["rationale"], "expected": expected, "collected_records": len(observations),
            "observed_kinds": sorted({f.kind.value for f in findings}), "passed": passed,
        })
    diagnostics = [message for stats in result.stats for message in (*stats.errors, *stats.warnings)]
    denied = any(_DENIED.fullmatch(message) for message in diagnostics)
    if config["expectation"] == "permission-denied":
        # Every failure must be a classified permission denial. A wrong token,
        # timeout, malformed response or unrelated error cannot satisfy this.
        valid_denial = bool(diagnostics) and all(_DENIED.fullmatch(message) for message in diagnostics)
        passed = scope_ok and not result.complete and denied and valid_denial
    else:
        passed = scope_ok and result.complete and all(c["passed"] for c in control_reports)
    return {
        "passed": passed, "scope_verified": scope_ok, "observed_scope_ids": observed_ids,
        "collection_complete": result.complete, "classified_permission_denial": denied,
        "objects_examined": sum(stats.objects_examined for stats in result.stats),
        "diagnostic_count": len(diagnostics), "controls": control_reports,
    }


def _source_provenance() -> dict[str, Any]:
    files = sorted([*ROOT.joinpath("shadowscan").rglob("*.py"), *ROOT.joinpath("tools/canaries").glob("*.py")])
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    provenance: dict[str, Any] = {"version": __version__, "source_sha256": digest.hexdigest(), "commit": None, "dirty": None}
    try:
        git_env = {key: value for key, value in metadata_git_env().items()
                   if key.startswith("GIT_") or key in {"PATH", "LANG", "LC_ALL", "SYSTEMROOT"}}
        prefix = [*metadata_git_argv_prefix(), "-C", str(ROOT)]
        commit = subprocess.run([*prefix, "rev-parse", "HEAD"], capture_output=True, text=True,
                                check=True, timeout=5, env=git_env).stdout.strip()
        status = subprocess.run([*prefix, "status", "--porcelain", "--", "shadowscan", "tools/canaries"],
                                capture_output=True, text=True, check=True, timeout=5, env=git_env).stdout
        provenance.update(commit=commit if re.fullmatch(r"[0-9a-f]{40,64}", commit) else None, dirty=bool(status))
    except (OSError, subprocess.SubprocessError):
        pass
    return provenance


def run(config: dict[str, Any]) -> dict[str, Any]:
    validate(config)
    index = get_index(reload=True)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA, "mode": config["mode"], "expectation": config["expectation"],
        "status": "LIVE_NOT_RUN" if config["mode"] == "live" else "REPLAY_FAIL", "live_acceptance": False,
        "started_at": now_iso(), "scanner": _source_provenance(), "signature_sha256": index.fingerprint(),
        "connector": config["connector"]["name"], "expected_scope": config["scope"],
        "ground_truth": config["ground_truth"],
        "limitations": "A canary validates named controls in selected scope, not estate-wide recall or effective IAM permissions.",
    }
    missing = _preflight(config)
    if missing:
        report.update(reason=missing, finished_at=now_iso())
        return _sanitized(report)
    settings = expand_env(dict(config["connector"]))
    name = settings.pop("name")
    # Engine and built-in connector safety options cannot be overridden by input.
    with tempfile.TemporaryDirectory(prefix="shadowscan-canary-") as temporary:
        engine = Engine(ScanConfig(connectors=[ConnectorSpec(name, settings)], parallel=1,
                                   dump_records=temporary, connector_timeout_seconds=120.0), index=index)
        result = engine.run()
        report["abandoned_workers"] = len(engine.abandoned_workers)
        records: list[dict[str, Any]] = []
        for path in sorted(Path(temporary).glob("*.jsonl")):
            # Engine already bounds and sanitizes dumps; cap total verification
            # input so a very large tenant does not exhaust the canary process.
            if path.stat().st_size > 64 * 1024 * 1024:
                report.update(status="LIVE_FAIL" if config["mode"] == "live" else "REPLAY_FAIL",
                              reason="record_verification_budget_exceeded", finished_at=now_iso())
                return _sanitized(report)
            for line in path.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
        verification = evaluate(config, result, records)
        report.update(verification)
        report["status"] = f"{config['mode'].upper()}_{'PASS' if verification['passed'] else 'FAIL'}"
        report["live_acceptance"] = config["mode"] == "live" and config["expectation"] == "complete" and verification["passed"]
        report["finished_at"] = now_iso()
        report["collection_started_at"] = result.started_at
        report["collection_finished_at"] = result.finished_at
    return _sanitized(report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="atomic private JSON report (parent must exist)")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        report = run(config)
        write_private_text(args.output, json.dumps(report, indent=2, allow_nan=False) + "\n")
    except (ValueError, OSError, yaml.YAMLError):
        # Never echo provider/config exceptions, which can contain credentials.
        print("CANARY_ERROR: configuration, input or output rejected; no acceptance recorded")
        return 2
    print(report["status"], flush=True)
    if report.get("abandoned_workers"):
        # The private receipt is durable; do not let a stuck SDK thread hold
        # this isolated canary process open after its collection deadline.
        os._exit(1)
    if report["status"] == "LIVE_NOT_RUN":
        return 3
    return 0 if report.get("passed") else 1
