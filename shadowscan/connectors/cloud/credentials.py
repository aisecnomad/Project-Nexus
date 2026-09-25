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

    Precedence: explicit path, ``GOOGLE_APPLICATION_CREDENTIALS``, then the
    documented well-known gcloud user-credential files. An invalid explicit
    path or environment setting does not fall through to another identity.
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    else:
        env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if env:
            candidates.append(Path(env).expanduser())
        else:
            candidates.append(Path.home() / ".config" / "gcloud" / _ADC_FILENAME)
            appdata = os.environ.get("APPDATA")
            if appdata:
                candidates.append(Path(appdata) / "gcloud" / _ADC_FILENAME)
    seen: set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        try:
            if path.is_file() and not path.is_symlink():
                return path
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
    if not callable(set_config):
        raise ConnectorError("cloud.aws: cannot enforce instance credential policy")
    set_config("metadata_service_timeout", 3)
    set_config("metadata_service_num_attempts", 1 if allow_instance else 0)
    if allow_instance:
        return
    get_component = getattr(sdk_session, "get_component", None)
    if not callable(get_component):
        raise ConnectorError("cloud.aws: cannot enforce instance credential policy")
    try:
        resolver = get_component("credential_provider")
    except Exception as exc:
        raise ConnectorError("cloud.aws: cannot enforce instance credential policy") from exc
    remove = getattr(resolver, "remove", None)
    if not callable(remove):
        raise ConnectorError("cloud.aws: cannot enforce instance credential policy")
    for name in ("iam-role", "container-role"):
        try:
            remove(name)
        except Exception as exc:
            raise ConnectorError("cloud.aws: cannot enforce instance credential policy") from exc


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
