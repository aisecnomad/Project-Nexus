"""Session-scoped cloud credential policy helpers.

Cloud SDKs use transports outside ``HttpClient``. These helpers keep instance
metadata and private Google ADC discovery from being used unless the operator
opted in with ``options.allow_instance_credentials``.
"""

from __future__ import annotations

import os
from pathlib import Path

from shadowscan.connectors.base import ConnectorError

_ADC_FILENAME = "application_default_credentials.json"


def allow_instance_credentials(value: object) -> bool:
    return value is True


def application_default_credentials_path(explicit: str | None = None) -> Path | None:
    """Resolve a local ADC file without using google.auth private APIs.

    Order: explicit path or ``GOOGLE_APPLICATION_CREDENTIALS``, then the
    documented well-known gcloud user-credential files.
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(Path.home() / ".config" / "gcloud" / _ADC_FILENAME)
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "gcloud" / _ADC_FILENAME)
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path if path.is_absolute() else path
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            if resolved.is_file() and not resolved.is_symlink():
                return resolved
        except OSError:
            continue
    return None


def require_local_adc(explicit: str | None = None) -> str:
    path = application_default_credentials_path(explicit)
    if path is None:
        raise ConnectorError(
            "cloud.gcp: provide access_token or local ADC; "
            "instance credentials require options.allow_instance_credentials=true"
        )
    return str(path)


def configure_aws_session(sdk_session: object, *, allow_instance: bool) -> None:
    """Bound IMDS probes on a botocore session without mutating process env.

    Process-wide ``AWS_EC2_METADATA_DISABLED`` races with concurrent connectors.
    Session config is scoped to this AWS client. When instance credentials are
    denied, metadata attempts are disabled and IAM/container providers removed.
    """
    set_config = getattr(sdk_session, "set_config_variable", None)
    if callable(set_config):
        set_config("metadata_service_timeout", 3)
        set_config("metadata_service_num_attempts", 1 if allow_instance else 0)
    if allow_instance:
        return
    get_component = getattr(sdk_session, "get_component", None)
    if not callable(get_component):
        return
    try:
        resolver = get_component("credential_provider")
    except Exception:
        return
    remove = getattr(resolver, "remove", None)
    if callable(remove):
        for name in ("iam-role", "container-role"):
            try:
                remove(name)
            except Exception:
                continue


def reject_instance_profile_sources(sdk_session: object, profile: str | None) -> None:
    """Fail closed when a named profile points at IMDS or ECS credentials."""
    full_config = getattr(sdk_session, "full_config", {}) or {}
    profiles = full_config.get("profiles", {}) if isinstance(full_config, dict) else {}
    get_var = getattr(sdk_session, "get_config_variable", None)
    source = profile or (get_var("profile") if callable(get_var) else None) or "default"
    visited: set[str] = set()
    while source and source not in visited:
        visited.add(source)
        details = profiles.get(source, {}) if isinstance(profiles, dict) else {}
        if not isinstance(details, dict):
            break
        if details.get("credential_source") in {"Ec2InstanceMetadata", "EcsContainer"}:
            raise ConnectorError(
                "cloud.aws: instance credentials require options.allow_instance_credentials=true"
            )
        source = details.get("source_profile")
