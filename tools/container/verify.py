"""Reject stale, incomplete or mismatched Trivy container evidence; never publish."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_MAX_REPORT_BYTES = 64 * 1024 * 1024
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
# Report text is printed into CI logs: keep it to one printable line per field.
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_MAX_LISTED = 200


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate evidence key")
        result[key] = value
    return result


def _invalid_number(value: str) -> Any:
    raise ValueError(f"invalid JSON number: {value}")


def _read_json(directory: Path, filename: str) -> Any:
    path = directory / filename
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_REPORT_BYTES:
        raise ValueError(f"missing or oversized evidence: {filename}")
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_number
    )


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("database timestamp is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("database timestamp requires a timezone")
    return parsed.astimezone(UTC)


def _finding(entry: dict[str, Any], result: dict[str, Any]) -> dict[str, str]:
    """The identifying fields of one reported vulnerability, as bounded printable text."""

    def text(source: dict[str, Any], key: str) -> str:
        value = source.get(key)
        return _UNPRINTABLE.sub("?", value)[:200] if isinstance(value, str) else ""

    return {
        "vulnerability": text(entry, "VulnerabilityID"),
        "severity": text(entry, "Severity"),
        "package": text(entry, "PkgName"),
        "installed_version": text(entry, "InstalledVersion"),
        "fixed_version": text(entry, "FixedVersion"),
        "status": text(entry, "Status"),
        "package_type": text(result, "Type"),
    }


def verify_database(directory: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Require a newly acquired schema-2 database updated within 48 hours."""
    current = now or datetime.now(UTC)
    metadata = _read_json(directory, "database-metadata.json")
    if not isinstance(metadata, dict) or type(metadata.get("Version")) is not int or metadata["Version"] != 2:
        raise ValueError("unsupported vulnerability database schema")
    updated = _timestamp(metadata.get("UpdatedAt"))
    downloaded = _timestamp(metadata.get("DownloadedAt"))
    if not -timedelta(minutes=5) <= current - updated <= timedelta(hours=48):
        raise ValueError("vulnerability database update is stale or in the future")
    if not -timedelta(minutes=5) <= current - downloaded <= timedelta(hours=1):
        raise ValueError("vulnerability database was not freshly acquired")
    digest_path = directory / "database-sha256.txt"
    if digest_path.is_symlink() or not digest_path.is_file() or digest_path.stat().st_size > 128:
        raise ValueError("missing database digest")
    digest = digest_path.read_text(encoding="utf-8").strip()
    if not _DIGEST.fullmatch(digest):
        raise ValueError("invalid database digest")
    return {"metadata": metadata, "sha256": digest}


def verify_bundle(
    directory: Path,
    *,
    image_id: str,
    source_sha: str,
    scanner_version: str,
    scanner_sha256: str,
    scan_exit: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate inventory and report contracts before accepting a scan result."""
    if (
        not _IMAGE_ID.fullmatch(image_id)
        or not _SHA.fullmatch(source_sha)
        or not _DIGEST.fullmatch(scanner_sha256)
    ):
        raise ValueError("invalid image, source or scanner identity")
    if scan_exit not in (0, 1):
        raise ValueError(f"container vulnerability scan failed (exit {scan_exit})")
    database = verify_database(directory, now=now)
    inspection = _read_json(directory, "image-inspect.json")
    if (
        not isinstance(inspection, list)
        or len(inspection) != 1
        or not isinstance(inspection[0], dict)
        or inspection[0].get("Id") != image_id
    ):
        raise ValueError("inspected image does not match the scan input")
    config = inspection[0].get("Config")
    if (
        not isinstance(config, dict)
        or not isinstance(config.get("Labels"), dict)
        or config["Labels"].get("org.opencontainers.image.revision") != source_sha
    ):
        raise ValueError("built image revision does not match the reviewed source")
    version = _read_json(directory, "trivy-version.json")
    if not isinstance(version, dict) or version.get("Version") != scanner_version:
        raise ValueError("scanner version does not match the reviewed tool")
    sbom = _read_json(directory, "container-sbom.cdx.json")
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("container inventory must be CycloneDX")
    metadata = sbom.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    properties = root.get("properties") if isinstance(root, dict) else None
    if not isinstance(properties, list) or any(not isinstance(prop, dict) for prop in properties):
        raise ValueError("container inventory is missing image identity")
    for name, expected in (
        ("aquasecurity:trivy:ImageID", image_id),
        ("aquasecurity:trivy:Labels:org.opencontainers.image.revision", source_sha),
    ):
        values = [prop.get("value") for prop in properties if prop.get("name") == name]
        if values != [expected]:
            raise ValueError("container inventory does not match the built image and source")
    components = sbom.get("components")
    if not isinstance(components, list) or any(not isinstance(component, dict) for component in components):
        raise ValueError("container inventory is missing components")
    purls = [component.get("purl", "") for component in components]
    if not any(isinstance(purl, str) and purl.startswith("pkg:deb/") for purl in purls):
        raise ValueError("container inventory is missing Debian packages")
    if not any(
        isinstance(purl, str) and purl.startswith("pkg:pypi/project-nexus-shadowscan@") for purl in purls
    ):
        raise ValueError("container inventory is missing the installed scanner Python package")
    report = _read_json(directory, "container-vulnerabilities.json")
    if (
        not isinstance(report, dict)
        or report.get("ArtifactType") != "container_image"
        or not isinstance(report.get("Metadata"), dict)
        or report["Metadata"].get("ImageID") != image_id
    ):
        raise ValueError("vulnerability report does not match the built image")
    results = report.get("Results")
    if not isinstance(results, list) or any(not isinstance(result, dict) for result in results):
        raise ValueError("vulnerability report is missing package results")
    for expected_class, expected_type in (("os-pkgs", "debian"), ("lang-pkgs", "python-pkg")):
        if not any(
            result.get("Class") == expected_class
            and result.get("Type") == expected_type
            and isinstance(result.get("Packages"), list)
            and result["Packages"]
            for result in results
        ):
            raise ValueError(f"vulnerability report is missing {expected_type} inventory")
    vulnerabilities: list[dict[str, str]] = []
    for result in results:
        entries = result.get("Vulnerabilities", [])
        if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
            raise ValueError("malformed vulnerability entries")
        if any(entry.get("Severity") not in {"HIGH", "CRITICAL"} for entry in entries):
            raise ValueError("vulnerability severity does not match the gate policy")
        vulnerabilities.extend(_finding(entry, result) for entry in entries)
    vulnerabilities.sort(key=lambda finding: (finding["vulnerability"], finding["package"]))
    if (scan_exit == 1) != bool(vulnerabilities):
        raise ValueError("scanner exit does not match reported vulnerabilities")
    required = (
        "image-inspect.json",
        "database-metadata.json",
        "database-sha256.txt",
        "trivy-version.json",
        "container-sbom.cdx.json",
        "container-vulnerabilities.json",
    )
    return {
        "schema_version": 1,
        "source_commit": source_sha,
        "image_id": image_id,
        "image_identity_scope": (
            "local Docker config digest and referenced layers; not a registry manifest digest"
        ),
        "scanner": {"version": scanner_version, "archive_sha256": scanner_sha256},
        "database": database,
        "policy": {"severity": ["HIGH", "CRITICAL"], "ignore_unfixed": False, "max_database_age_hours": 48},
        "scan_exit": scan_exit,
        "high_critical_vulnerabilities": len(vulnerabilities),
        "blocking_vulnerabilities": vulnerabilities,
        "status": "blocked" if vulnerabilities else "passed",
        "scope": "detected Debian and Python packages; no production acceptance or reproducible-build claim",
        "files": [
            {"name": filename, "sha256": hashlib.sha256((directory / filename).read_bytes()).hexdigest()}
            for filename in required
        ],
    }


def _blocked_summary(findings: list[dict[str, str]]) -> str:
    """Name every blocking finding so a failed job explains itself without its artifact."""
    lines = [f"container scan blocked by {len(findings)} HIGH/CRITICAL vulnerabilities:"]
    for finding in findings[:_MAX_LISTED]:
        package = f"{finding['package_type']}:{finding['package']}"
        lines.append(
            f"  {finding['vulnerability']} {finding['severity']} {package} {finding['installed_version']} "
            f"status={finding['status'] or '-'} fixed={finding['fixed_version'] or '-'}"
        )
    if len(findings) > _MAX_LISTED:
        lines.append(f"  ... {len(findings) - _MAX_LISTED} more in container-evidence.json")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    database = commands.add_parser("database")
    database.add_argument("directory", type=Path)
    bundle = commands.add_parser("bundle")
    bundle.add_argument("directory", type=Path)
    bundle.add_argument("--image-id", required=True)
    bundle.add_argument("--source-sha", required=True)
    bundle.add_argument("--scanner-version", required=True)
    bundle.add_argument("--scanner-sha256", required=True)
    bundle.add_argument("--scan-exit", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "database":
            verify_database(args.directory)
            return
        manifest = verify_bundle(
            args.directory,
            image_id=args.image_id,
            source_sha=args.source_sha,
            scanner_version=args.scanner_version,
            scanner_sha256=args.scanner_sha256,
            scan_exit=args.scan_exit,
        )
        with (args.directory / "container-evidence.json").open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        if manifest["status"] != "passed":
            parser.exit(1, _blocked_summary(manifest["blocking_vulnerabilities"]))
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
