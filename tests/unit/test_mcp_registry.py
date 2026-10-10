"""options.mcp_registries: pinned MCP Registry snapshots, matching, the approved-catalog factor and the producer."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
from click.testing import CliRunner

import shadowscan.engine as engine_module
import shadowscan.mcp_registry as registry_module
from shadowscan.cli import main
from shadowscan.comparison import build_collection_scope
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine
from shadowscan.mcp_registry import (
    GOVERNANCE_FACTOR,
    MATCHES_KEY,
    METADATA_KEY,
    REGISTRY_TAGS,
    SERVER_KEY,
    LoadedRegistries,
    McpRegistrySource,
    SnapshotError,
    enrich_mcp_findings,
    fetch_snapshot,
    load_registries,
    load_snapshot,
    normalize_remote,
)
from shadowscan.models import Evidence, Finding, Kind, ScanResult, Surface
from shadowscan.risk import RiskPolicy, assess
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.http import HttpClient, HttpError

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mcp" / "registry_snapshot.json"
OFFICIAL = "io.modelcontextprotocol.registry/official"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source(path: Path = FIXTURE, *, id: str = "official", approved: bool = False, sha: str | None = None):
    return McpRegistrySource(id=id, snapshot=str(path), sha256=sha or _sha(path), approved=approved)


def _entry(
    name: str,
    version: str = "1.0.0",
    *,
    status: str = "active",
    latest: bool = True,
    packages: list[dict[str, Any]] | None = None,
    remotes: list[str] | None = None,
) -> dict[str, Any]:
    server: dict[str, Any] = {"name": name, "description": "synthetic", "version": version}
    if packages is not None:
        server["packages"] = packages
    if remotes is not None:
        server["remotes"] = [{"type": "streamable-http", "url": url} for url in remotes]
    meta = {"status": status, "publishedAt": "2026-01-01T00:00:00Z", "isLatest": latest}
    return {"server": server, "_meta": {OFFICIAL: meta}}


def _document(*entries: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    document = {
        "schema": "shadowscan.mcp-registry-snapshot/v1",
        "registry": "https://registry.example.com",
        "api": "v0.1",
        "fetched_at": "2026-10-10T00:00:00Z",
        "complete": True,
        "servers": list(entries),
    }
    document.update(overrides)
    return document


def _write(tmp_path: Path, document: Any, name: str = "snapshot.json", **source: Any) -> McpRegistrySource:
    path = tmp_path / name
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    return _source(path, **source)


def _server(name: str, **fields: Any) -> dict[str, Any]:
    server: dict[str, Any] = {
        "name": name,
        "transport": "stdio",
        "command": None,
        "args": [],
        "url": None,
        "urls": [],
        "env_names": [],
        "headers": [],
        "auto_approve": None,
        "secrets_inline": False,
        "disabled": False,
    }
    server.update(fields)
    if fields.get("url") and "urls" not in fields:
        server["urls"] = [fields["url"]]
    return server


def _npx(name: str, spec: str, **fields: Any) -> dict[str, Any]:
    return _server(name, command="npx", args=["-y", spec], **fields)


def _mcp_finding(*servers: dict[str, Any], client: str = "Claude Code", resource: str = "repo/.mcp.json"):
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.MCP_SERVER,
        title="MCP configuration",
        resource=resource,
        resource_type="mcp-config",
        evidence=[Evidence("file:protocol.mcp", "MCP configuration", weight=0.95)],
        metadata={"servers": [copy.deepcopy(server) for server in servers], "client": client},
    )


def _enriched(*servers: dict[str, Any], registries: LoadedRegistries | None = None, **kwargs: Any) -> Finding:
    finding = _mcp_finding(*servers, **kwargs)
    assert enrich_mcp_findings([finding], registries or load_registries([_source()])) == []
    return finding


def _blocks(finding: Finding, position: int = 0) -> list[dict[str, Any]]:
    return finding.metadata["servers"][position][SERVER_KEY]


def _registry_tags(finding: Finding) -> set[str]:
    return set(finding.tags) & set(REGISTRY_TAGS)


# ------------------------------------------------------------------ loading


def test_fixture_loads_under_its_pin_and_indexes_packages_remotes_and_names():
    snapshot = load_snapshot(_source())
    assert snapshot.fetched_at == "2026-10-10T00:00:00Z"
    assert ("npm", "@acme/mcp-files") in snapshot.by_package
    # PyPI names are compared as PEP 503 normalizes them; OCI tags are versions, not identity.
    assert ("pypi", "acme-legacy-mcp") in snapshot.by_package
    assert ("oci", "ghcr.io/acme/gone-mcp") in snapshot.by_package
    assert snapshot.by_remote["https://mcp.example.com/mcp"] == {"com.example/remote"}
    # A templated remote URL can never match a configured one.
    assert not any("{" in url for url in snapshot.by_remote)
    assert snapshot.latest["io.github.acme/files"].version == "1.1.0"


def test_a_digest_mismatch_leaves_the_registry_unused_without_quoting_content(tmp_path):
    loaded = load_registries([_source(sha="0" * 64)])
    assert loaded.snapshots == () and not loaded.complete
    assert loaded.errors == (
        "MCP registry official: snapshot SHA-256 does not match the pinned sha256; registry not used",
    )


def test_a_symbolic_link_is_never_followed(tmp_path):
    link = tmp_path / "link.json"
    link.symlink_to(FIXTURE)
    with pytest.raises(SnapshotError, match="symbolic link"):
        load_snapshot(_source(link, sha=_sha(FIXTURE)))
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "snapshot.json").write_bytes(FIXTURE.read_bytes())
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(folder)
    with pytest.raises(SnapshotError, match="symbolic link"):
        load_snapshot(_source(linked_dir / "snapshot.json", sha=_sha(FIXTURE)))


def test_a_missing_file_or_a_directory_is_reported(tmp_path):
    with pytest.raises(SnapshotError, match="could not be read"):
        load_snapshot(_source(tmp_path / "absent.json", sha="0" * 64))
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(SnapshotError, match="not a regular file"):
        load_snapshot(_source(fifo, sha="0" * 64))


def test_an_oversized_snapshot_is_refused_before_hashing(tmp_path):
    source = _write(tmp_path, _document(_entry("io.github.acme/a")))
    with pytest.raises(SnapshotError, match="byte limit"):
        load_snapshot(source, max_bytes=64)


def test_a_snapshot_that_grows_while_read_is_refused(tmp_path, monkeypatch):
    source = _write(tmp_path, _document(_entry("io.github.acme/a")))
    monkeypatch.setattr(registry_module, "changed_since", lambda before, fd: True)
    with pytest.raises(SnapshotError, match="changed while"):
        load_snapshot(source)


@pytest.mark.parametrize(
    "text,message",
    [
        ('{"schema": 1, "schema": 2}', "duplicate field"),
        ('{"servers": [NaN]}', "nonfinite"),
        ("{not json", "not valid JSON"),
        ("[" * 100_000, "not valid JSON"),
    ],
)
def test_ambiguous_or_invalid_json_is_refused(tmp_path, text, message):
    with pytest.raises(SnapshotError, match=message):
        load_snapshot(_write(tmp_path, text))


@pytest.mark.parametrize(
    "document,message",
    [
        (["not", "an", "object"], "exactly the fields"),
        ({**_document(), "extra": 1}, "exactly the fields"),
        (_document(schema="shadowscan.mcp-registry-snapshot/v2"), "unknown schema"),
        (_document(api="v1"), "registry API v0.1"),
        (_document(complete=False), "not complete"),
        (_document(complete="true"), "not complete"),
        (_document(fetched_at=""), "fetched_at"),
        (_document(registry=7), "fetched_at"),
        (_document(servers={}), "must be a list"),
        (_document(["not an object"]), "server entry 1 must have"),
        (_document({"server": {"name": "io.github.acme/a", "version": "1"}}), "server entry 1 must have"),
        (_document(_entry("no-namespace")), "invalid name"),
        (_document(_entry("io.github.acme/" + "a" * 200)), "invalid name"),
        (_document(_entry("io.github.acme/a", " ")), "invalid version"),
        (_document(_entry("io.github.acme/a", status="retired")), "unknown status"),
        (_document(_entry("io.github.acme/a", status=["active"])), "unknown status"),
        (_document({**_entry("io.github.acme/a"), "_meta": {OFFICIAL: {"status": "active"}}}), "isLatest"),
        (
            _document(
                {
                    **_entry("io.github.acme/a"),
                    "_meta": {OFFICIAL: {"status": "active", "isLatest": True, "publishedAt": 5}},
                }
            ),
            "publishedAt",
        ),
        (_document(_entry("io.github.acme/a", packages={"npm": "x"})), "invalid packages list"),
        (_document(_entry("io.github.acme/a", packages=[{"registryType": "npm"}])), "invalid package"),
        (
            _document(
                _entry(
                    "io.github.acme/a", packages=[{"registryType": "npm", "identifier": "x", "version": 1}]
                )
            ),
            "invalid package",
        ),
        (
            _document(
                {
                    **_entry("io.github.acme/a"),
                    "server": {**_entry("io.github.acme/a")["server"], "remotes": "x"},
                }
            ),
            "remotes list",
        ),
        (_document(_entry("io.github.acme/a", remotes=[""])), "invalid remote"),
        (_document(_entry("io.github.acme/a"), _entry("io.github.acme/a")), "server entry 2 repeats"),
    ],
)
def test_malformed_snapshots_are_refused_with_a_located_message(tmp_path, document, message):
    with pytest.raises(SnapshotError, match=message):
        load_snapshot(_write(tmp_path, document))


def test_too_many_entries_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(registry_module, "MAX_SNAPSHOT_SERVERS", 1)
    source = _write(tmp_path, _document(_entry("io.github.acme/a"), _entry("io.github.acme/b")))
    with pytest.raises(SnapshotError, match="more than 1 server versions"):
        load_snapshot(source)


def test_a_name_with_several_latest_versions_has_no_latest(tmp_path):
    source = _write(
        tmp_path, _document(_entry("io.github.acme/a", "1.0.0"), _entry("io.github.acme/a", "2.0.0"))
    )
    assert load_snapshot(source).latest["io.github.acme/a"] is None


@pytest.mark.parametrize(
    "url,expected",
    [
        ("HTTPS://MCP.Example.com:443/mcp/", "https://mcp.example.com/mcp"),
        ("https://mcp.example.com/mcp?token=abc#frag", "https://mcp.example.com/mcp"),
        ("https://operator@mcp.example.com:8443/mcp", "https://mcp.example.com:8443/mcp"),
        ("http://mcp.example.com:80", "http://mcp.example.com"),
        ("https://[2001:db8::1]/mcp", "https://[2001:db8::1]/mcp"),
        ("https://mcp.example.com/{tenant}/mcp", None),
        ("ws://mcp.example.com/mcp", None),
        ("https://mcp.example.com:99999/mcp", None),
        ("not a url", None),
        (None, None),
    ],
)
def test_remote_urls_are_compared_in_a_normalized_form(url, expected):
    assert normalize_remote(url) == expected


# ------------------------------------------------------------------ matching


def test_an_older_pinned_npm_version_is_published_but_outdated():
    finding = _enriched(_npx("files", "@acme/mcp-files@1.0.0"))
    assert _blocks(finding) == [
        {
            "registry": "official",
            "name": "io.github.acme/files",
            "namespace": "io.github.acme",
            "match": "package",
            "configured_version": "1.0.0",
            "version_published": True,
            "latest_version": "1.1.0",
            "is_latest": False,
            "status": "active",
            "published_at": "2026-01-10T10:00:00Z",
            "ambiguous": False,
        }
    ]
    assert _registry_tags(finding) == {"mcp-registry-published", "mcp-registry-outdated"}
    signals = {ev.signal: ev for ev in finding.evidence if ev.signal.startswith("mcp-registry:")}
    assert set(signals) == {"mcp-registry:mcp-registry-published", "mcp-registry:mcp-registry-outdated"}
    # Review hints never change confidence.
    assert all(ev.weight == 0.0 for ev in signals.values())
    assert finding.metadata[METADATA_KEY] == {
        "registries": [
            {
                "id": "official",
                "sha256": _sha(FIXTURE),
                "fetched_at": "2026-10-10T00:00:00Z",
                "approved": False,
            }
        ],
        "approved_checked": False,
        "not_in_approved": 0,
    }


def test_the_latest_version_and_an_unpinned_package_are_only_published():
    latest = _enriched(_npx("files", "@ACME/mcp-files@v1.1.0"))
    assert _blocks(latest)[0]["is_latest"] is True and _blocks(latest)[0]["configured_version"] == "1.1.0"
    assert _registry_tags(latest) == {"mcp-registry-published"}
    unpinned = _enriched(_npx("files", "@acme/mcp-files"))
    block = _blocks(unpinned)[0]
    assert (block["configured_version"], block["version_published"], block["is_latest"]) == (None, None, None)
    assert block["latest_version"] == "1.1.0" and block["status"] == "active"
    assert _registry_tags(unpinned) == {"mcp-registry-published"}


def test_an_unpinned_launch_takes_the_latest_status_even_when_older_entries_list_no_version(tmp_path):
    source = _write(
        tmp_path,
        _document(
            _entry(
                "io.github.acme/a",
                "1.0.0",
                status="deprecated",
                latest=False,
                packages=[{"registryType": "npm", "identifier": "a"}],
            ),
            _entry(
                "io.github.acme/a",
                "2.0.0",
                packages=[{"registryType": "npm", "identifier": "a", "version": "2.0.0"}],
            ),
        ),
    )
    finding = _enriched(_npx("a", "a"), registries=load_registries([source]))
    block = _blocks(finding)[0]
    assert (block["status"], block["version_published"], block["latest_version"]) == ("active", None, "2.0.0")
    assert _registry_tags(finding) == {"mcp-registry-published"}
    # A pinned version among versions the registry never recorded cannot be judged.
    unknown = _enriched(
        _npx("a", "a@1.0.0"),
        registries=load_registries(
            [
                _write(
                    tmp_path,
                    _document(
                        _entry("io.github.acme/a", packages=[{"registryType": "npm", "identifier": "a"}])
                    ),
                    name="unversioned.json",
                )
            ]
        ),
    )
    assert _blocks(unknown)[0]["version_published"] is None and _blocks(unknown)[0]["is_latest"] is None


def test_a_version_the_registry_does_not_list_is_flagged():
    finding = _enriched(_npx("files", "@acme/mcp-files@9.9.9"))
    block = _blocks(finding)[0]
    assert block["version_published"] is False and block["is_latest"] is False
    # The status shown is the latest version's.
    assert block["published_at"] == "2026-03-02T10:00:00Z"
    assert _registry_tags(finding) == {"mcp-registry-published", "mcp-registry-version-unpublished"}


def test_pypi_names_match_after_pep_503_normalization_and_deprecation_is_flagged():
    finding = _enriched(_server("legacy", command="uvx", args=["acme-legacy-mcp==0.9.0"]))
    block = _blocks(finding)[0]
    assert (block["name"], block["status"], block["is_latest"]) == (
        "io.github.acme/legacy",
        "deprecated",
        True,
    )
    assert _registry_tags(finding) == {"mcp-registry-published", "mcp-registry-deprecated"}


def test_oci_images_match_without_their_tag_and_deletion_is_flagged():
    finding = _enriched(
        _server("gone", command="docker", args=["run", "-i", "--rm", "GHCR.io/acme/gone-mcp:2.0.0"])
    )
    block = _blocks(finding)[0]
    assert (block["configured_version"], block["version_published"], block["status"]) == (
        "2.0.0",
        True,
        "deleted",
    )
    assert _registry_tags(finding) == {"mcp-registry-published", "mcp-registry-deleted"}


def test_remote_urls_match_and_an_endpoint_the_latest_version_dropped_is_outdated():
    current = _enriched(_server("remote", transport="http", url="https://MCP.example.com/mcp/?session=1"))
    block = _blocks(current)[0]
    assert (block["match"], block["is_latest"], block["latest_version"]) == ("remote", True, "2.0.0")
    assert block["configured_version"] is None and block["version_published"] is None
    assert _registry_tags(current) == {"mcp-registry-published"}
    old = _enriched(_server("remote", transport="sse", url="https://old.example.com/sse"))
    assert _blocks(old)[0]["is_latest"] is False and _blocks(old)[0]["published_at"] == "2026-02-01T00:00:00Z"
    assert _registry_tags(old) == {"mcp-registry-published", "mcp-registry-outdated"}


def test_a_name_matches_only_for_a_server_manifest():
    manifest = _server("io.github.acme/manifest-tool", transport="unknown", command=None)
    listed = _enriched(manifest, client="MCP server manifest", resource="repo/server.json")
    block = _blocks(listed)[0]
    assert (block["match"], block["latest_version"], block["status"]) == ("name", "3.0.0", "active")
    # A client configuration names servers freely: a matching name proves nothing there.
    client = _mcp_finding(dict(manifest, command="node", args=["server.js"]))
    assert enrich_mcp_findings([client], load_registries([_source()])) == []
    assert SERVER_KEY not in client.metadata["servers"][0] and not _registry_tags(client)


def test_a_package_several_registry_names_list_is_ambiguous_and_claims_no_status():
    finding = _enriched(_npx("shared", "@acme/shared-mcp@1.0.0"))
    block = _blocks(finding)[0]
    assert block["ambiguous"] is True and block["name"] == "io.github.acme/shared-a"
    assert all(block[key] is None for key in ("version_published", "latest_version", "is_latest", "status"))
    # One of the names is deleted, but which one the server is cannot be told.
    assert _registry_tags(finding) == {"mcp-registry-published"}


def test_an_identifiable_server_no_registry_lists_is_unpublished_and_others_are_skipped():
    finding = _enriched(
        _npx("unknown", "@other/mcp-tool@1.0.0"),
        _server("local", command="node", args=["./server.js"]),
        _server("shell", command="sh", args=["-c", "npx @acme/mcp-files"]),
    )
    servers = finding.metadata["servers"]
    assert servers[0][SERVER_KEY] == []
    assert SERVER_KEY not in servers[1] and SERVER_KEY not in servers[2]
    assert _registry_tags(finding) == {"mcp-unpublished"}
    evidence = next(ev for ev in finding.evidence if ev.signal == "mcp-registry:mcp-unpublished")
    assert evidence.description == "1 enabled MCP server(s) listed in no configured MCP registry"


def test_disabled_servers_are_matched_but_add_no_tags():
    finding = _enriched(
        _npx("off", "@other/mcp-tool@1.0.0", disabled=True),
        _npx("gone", "@acme/mcp-files@0.1.0", disabled=True),
    )
    assert _blocks(finding, 0) == [] and _blocks(finding, 1)[0]["version_published"] is False
    assert not _registry_tags(finding)


def test_an_mcp_tool_finding_matches_by_its_server_url():
    finding = Finding(
        surface=Surface.ENDPOINT,
        connector="endpoint.mcp",
        kind=Kind.MCP_SERVER,
        title="MCP tool search",
        resource="https://mcp.example.com/mcp/search",
        resource_type="mcp-tool",
        metadata={"server": "https://mcp.example.com/mcp", "tool": "search"},
    )
    assert enrich_mcp_findings([finding], load_registries([_source()])) == []
    assert finding.metadata[METADATA_KEY][MATCHES_KEY][0]["name"] == "com.example/remote"
    named = Finding(
        surface=Surface.ENDPOINT,
        connector="endpoint.mcp",
        kind=Kind.MCP_SERVER,
        title="MCP tool search",
        resource="github/search",
        resource_type="mcp-tool",
        metadata={"server": "github", "tool": "search"},
    )
    enrich_mcp_findings([named], load_registries([_source()]))
    # A bare server name identifies nothing; no unpublished claim is made.
    assert MATCHES_KEY not in named.metadata[METADATA_KEY] and not _registry_tags(named)


def test_other_kinds_and_shapes_are_left_alone(make_finding):
    agent = make_finding(metadata={"servers": [_npx("x", "@acme/mcp-files")]})
    shapeless = _mcp_finding()
    shapeless.metadata = {"servers": "not a list"}
    odd = _mcp_finding()
    odd.metadata = {"client": "x"}
    assert enrich_mcp_findings([agent, shapeless, odd], load_registries([_source()])) == []
    assert SERVER_KEY not in agent.metadata["servers"][0] and METADATA_KEY not in agent.metadata
    assert METADATA_KEY not in shapeless.metadata and METADATA_KEY not in odd.metadata


def test_the_pass_is_idempotent_and_removes_forged_or_stale_results():
    finding = _mcp_finding(_npx("files", "@acme/mcp-files@1.0.0"), _npx("unknown", "@other/x@1.0.0"))
    loaded = load_registries([_source()])
    enrich_mcp_findings([finding], loaded)
    first = (copy.deepcopy(finding.metadata), list(finding.tags), [ev.signal for ev in finding.evidence])
    enrich_mcp_findings([finding], loaded)
    assert (finding.metadata, finding.tags, [ev.signal for ev in finding.evidence]) == first
    # Without configured registries the pass only clears: nothing forged survives into scoring.
    finding.metadata[METADATA_KEY] = {"approved_checked": True, "not_in_approved": 9}
    enrich_mcp_findings([finding], LoadedRegistries())
    assert METADATA_KEY not in finding.metadata and SERVER_KEY not in finding.metadata["servers"][0]
    assert not _registry_tags(finding) and not any(
        ev.signal.startswith("mcp-registry:") for ev in finding.evidence
    )


def test_a_finding_that_cannot_be_matched_is_reported(monkeypatch):
    def broken(server: dict[str, Any]) -> None:
        raise TypeError("unexpected record shape")

    monkeypatch.setattr(registry_module, "server_package", broken)
    finding = _mcp_finding(_npx("files", "@acme/mcp-files@1.0.0"))
    assert enrich_mcp_findings([finding], load_registries([_source()])) == [
        "MCP registry matching failed on 1 finding(s)"
    ]
    assert METADATA_KEY not in finding.metadata


def test_registries_that_failed_to_load_withhold_the_unpublished_claim(tmp_path):
    loaded = load_registries([_source(), _source(tmp_path / "absent.json", id="corp", sha="0" * 64)])
    finding = _enriched(
        _npx("unknown", "@other/x@1.0.0"), _npx("files", "@acme/mcp-files@1.1.0"), registries=loaded
    )
    assert _registry_tags(finding) == {"mcp-registry-published"}
    assert finding.metadata[METADATA_KEY]["registries"][0]["id"] == "official"
    nothing = _enriched(
        _npx("files", "@acme/mcp-files@1.1.0"), registries=load_registries([_source(sha="0" * 64)])
    )
    assert SERVER_KEY not in nothing.metadata["servers"][0]
    assert nothing.metadata[METADATA_KEY] == {
        "registries": [],
        "approved_checked": False,
        "not_in_approved": 0,
    }


# ------------------------------------------------------- approved catalogs and risk


def _catalog(tmp_path: Path, *, approved: bool = True) -> McpRegistrySource:
    document = _document(
        _entry(
            "com.acme.internal/files", packages=[{"registryType": "npm", "identifier": "@acme/mcp-files"}]
        ),
        _entry("com.acme.internal/retired", status="deleted", remotes=["https://retired.acme.example/mcp"]),
    )
    return _write(tmp_path, document, name="catalog.json", id="corp", approved=approved)


def test_an_approved_catalog_counts_enabled_servers_it_does_not_list(tmp_path):
    loaded = load_registries([_source(), _catalog(tmp_path)])
    assert loaded.approved_checked
    finding = _enriched(
        _npx("files", "@acme/mcp-files@1.0.0"),
        _npx("legacy", "@other/x@1.0.0"),
        _server("retired", transport="http", url="https://retired.acme.example/mcp"),
        _npx("off", "@other/y@1.0.0", disabled=True),
        _server("local", command="node", args=["server.js"]),
        registries=loaded,
    )
    # Unlisted, and listed only as deleted, count; disabled and unidentifiable servers do not.
    assert finding.metadata[METADATA_KEY]["approved_checked"] is True
    assert finding.metadata[METADATA_KEY]["not_in_approved"] == 2
    assert [block["registry"] for block in _blocks(finding)] == ["corp", "official"]
    risk = assess(finding)
    factor = next(f for f in risk.factors if f.id == GOVERNANCE_FACTOR)
    assert factor.weight == 15
    assert factor.description == "2 enabled MCP server(s) not listed in an approved MCP registry"
    # A governance factor: excluded from the danger score.
    without = assess(_enriched(_npx("files", "@acme/mcp-files@1.0.0"), registries=loaded))
    assert GOVERNANCE_FACTOR not in {f.id for f in without.factors}
    assert risk.danger_score == without.danger_score


def test_the_factor_needs_a_loaded_approved_registry(tmp_path):
    servers = (_npx("legacy", "@other/x@1.0.0"),)
    public_only = _enriched(*servers, registries=load_registries([_source()]))
    assert public_only.metadata[METADATA_KEY]["approved_checked"] is False
    assert GOVERNANCE_FACTOR not in {f.id for f in assess(public_only).factors}
    catalog = _catalog(tmp_path)
    failed = McpRegistrySource(catalog.id, catalog.snapshot, "f" * 64, approved=True)
    for loaded in (
        load_registries([_source(), failed]),
        load_registries([_source(), _catalog(tmp_path), failed]),
    ):
        finding = _enriched(*servers, registries=loaded)
        assert finding.metadata[METADATA_KEY] | {"registries": None} == {
            "registries": None,
            "approved_checked": False,
            "not_in_approved": 0,
        }
        assert GOVERNANCE_FACTOR not in {f.id for f in assess(finding).factors}


def test_the_factor_follows_the_risk_policy(tmp_path):
    finding = _enriched(_npx("legacy", "@other/x@1.0.0"), registries=load_registries([_catalog(tmp_path)]))
    assert GOVERNANCE_FACTOR not in {f.id for f in assess(finding, policy=RiskPolicy(basis="danger")).factors}
    tuned = RiskPolicy.from_options({"governance": {GOVERNANCE_FACTOR: 40}})
    assert next(f for f in assess(finding, policy=tuned).factors if f.id == GOVERNANCE_FACTOR).weight == 40
    off = RiskPolicy.from_options({"governance": {GOVERNANCE_FACTOR: 0}})
    assert GOVERNANCE_FACTOR not in {f.id for f in assess(finding, policy=off).factors}


@pytest.mark.parametrize(
    "block",
    [
        {"approved_checked": False, "not_in_approved": 3},
        {"approved_checked": "true", "not_in_approved": 3},
        {"approved_checked": True, "not_in_approved": 0},
        {"approved_checked": True, "not_in_approved": "many"},
        "not a mapping",
    ],
)
def test_the_factor_ignores_malformed_or_unchecked_metadata(block):
    finding = _mcp_finding()
    finding.metadata[METADATA_KEY] = block
    assert GOVERNANCE_FACTOR not in {f.id for f in assess(finding).factors}


def test_the_factor_applies_only_to_mcp_server_findings(make_finding):
    finding = make_finding(metadata={METADATA_KEY: {"approved_checked": True, "not_in_approved": 2}})
    assert GOVERNANCE_FACTOR not in {f.id for f in assess(finding).factors}


# ------------------------------------------------------------------ engine


def _engine(monkeypatch: pytest.MonkeyPatch, findings: Callable[[], list[Finding]], **options: Any) -> Engine:
    class Fake(BaseConnector):
        name: ClassVar[str] = "test.mcp"
        surface: ClassVar[Surface] = Surface.CODE

        def collect(self) -> Iterator[dict[str, Any]]:
            yield {}

        def analyze(self, items: Any) -> list[Finding]:
            list(items)
            return findings()

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: Fake)
    monkeypatch.setattr(engine_module, "builtin_connector_names", lambda: frozenset({"test.mcp"}))
    return Engine(ScanConfig(connectors=[ConnectorSpec("test.mcp")], **options), SignatureIndex([]))


def _stats(result: ScanResult, connector: str):
    return next((stats for stats in result.stats if stats.connector == connector), None)


def test_the_engine_enriches_before_scoring_and_stays_complete(monkeypatch, tmp_path):
    def findings() -> list[Finding]:
        return [_mcp_finding(_npx("files", "@acme/mcp-files@1.0.0"), _npx("legacy", "@other/x@1.0.0"))]

    result = _engine(monkeypatch, findings, mcp_registries=[_source(), _catalog(tmp_path)]).run()
    assert result.complete and _stats(result, "engine.mcp-registry") is None
    finding = result.findings[0]
    assert finding.metadata[METADATA_KEY]["not_in_approved"] == 1
    assert {"mcp-registry-published", "mcp-registry-outdated", "mcp-unpublished"} <= set(finding.tags)
    assert GOVERNANCE_FACTOR in {f.id for f in finding.risk.factors}
    # Without the option nothing is matched and the score is the old one.
    plain = _engine(monkeypatch, findings).run()
    assert plain.complete and METADATA_KEY not in plain.findings[0].metadata
    factors = {f.id: f.weight for f in finding.risk.factors if f.id != "confidence-scaling"}
    assert factors.pop(GOVERNANCE_FACTOR) == 15
    assert factors == {f.id: f.weight for f in plain.findings[0].risk.factors if f.id != "confidence-scaling"}
    assert plain.findings[0].risk.danger_score == finding.risk.danger_score


def test_a_snapshot_that_fails_makes_the_scan_incomplete(monkeypatch, tmp_path):
    catalog = _catalog(tmp_path)
    catalog = McpRegistrySource(catalog.id, catalog.snapshot, "e" * 64, approved=True)

    def findings() -> list[Finding]:
        return [_mcp_finding(_npx("legacy", "@other/x@1.0.0"))]

    result = _engine(monkeypatch, findings, mcp_registries=[catalog]).run()
    assert not result.complete
    stats = _stats(result, "engine.mcp-registry")
    assert stats is not None and stats.incomplete
    assert stats.errors == [
        "MCP registry corp: snapshot SHA-256 does not match the pinned sha256; registry not used"
    ]
    finding = result.findings[0]
    assert finding.metadata[METADATA_KEY]["approved_checked"] is False
    assert GOVERNANCE_FACTOR not in {f.id for f in finding.risk.factors}


def test_snapshots_are_read_again_for_every_run(monkeypatch, tmp_path):
    source = _write(
        tmp_path, _document(_entry("io.github.acme/a", packages=[{"registryType": "npm", "identifier": "a"}]))
    )
    engine = _engine(monkeypatch, lambda: [_mcp_finding(_npx("a", "a@1.0.0"))], mcp_registries=[source])
    assert engine.run().complete
    # A replaced snapshot no longer matches its pin: the next run reports it instead of reusing the old one.
    Path(source.snapshot).write_text(json.dumps(_document()))
    second = engine.run()
    assert not second.complete and _stats(second, "engine.mcp-registry") is not None


def test_postprocess_loads_snapshots_when_called_without_a_run(monkeypatch):
    engine = _engine(monkeypatch, list, mcp_registries=[_source()])
    findings, errors = engine._postprocess([_mcp_finding(_npx("files", "@acme/mcp-files@1.1.0"))])
    assert errors == [] and findings[0].metadata[METADATA_KEY]["registries"][0]["id"] == "official"


def test_collection_scope_changes_only_when_registries_are_configured(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    specs = [ConnectorSpec("code.filesystem", {"path": str(repo)})]
    index = SignatureIndex([])
    plain = build_collection_scope(ScanConfig(connectors=specs), index, specs)
    assert plain["comparable"] is True
    pinned = build_collection_scope(ScanConfig(connectors=specs, mcp_registries=[_source()]), index, specs)
    approved = build_collection_scope(
        ScanConfig(connectors=specs, mcp_registries=[_source(approved=True)]), index, specs
    )
    assert len({plain["fingerprint"], pinned["fingerprint"], approved["fingerprint"]}) == 3
    moved = McpRegistrySource("official", str(tmp_path / "elsewhere.json"), _sha(FIXTURE))
    # The snapshot's location is not part of the scope; its id, pin and approval are.
    assert (
        build_collection_scope(ScanConfig(connectors=specs, mcp_registries=[moved]), index, specs) == pinned
    )


# ------------------------------------------------------------------ producer


def _page(*entries: dict[str, Any], cursor: str | None = None, count: int | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"count": len(entries) if count is None else count}
    if cursor is not None:
        metadata["nextCursor"] = cursor
    return {"servers": list(entries), "metadata": metadata}


def _listing(monkeypatch: pytest.MonkeyPatch, pages: list[Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def get_json(self: HttpClient, path: str, **kwargs: Any) -> Any:
        calls.append({"base": self.base_url, "path": path, **kwargs["params"]})
        page = pages[len(calls) - 1]
        if isinstance(page, Exception):
            raise page
        return page

    monkeypatch.setattr(HttpClient, "get_json", get_json)
    return calls


def test_the_producer_follows_cursors_and_keeps_only_matched_fields(monkeypatch):
    full = json.loads(FIXTURE.read_text())["servers"]
    calls = _listing(
        monkeypatch, [_page(*full[:4], cursor="io.github.acme/gone:2.0.0"), _page(*full[4:], cursor="")]
    )
    text = fetch_snapshot("https://registry.example.com/")
    assert calls == [
        {
            "base": "https://registry.example.com",
            "path": "v0.1/servers",
            "limit": "100",
            "include_deleted": "true",
        },
        {
            "base": "https://registry.example.com",
            "path": "v0.1/servers",
            "limit": "100",
            "include_deleted": "true",
            "cursor": "io.github.acme/gone:2.0.0",
        },
    ]
    document = json.loads(text)
    assert document["complete"] is True and document["registry"] == "https://registry.example.com"
    assert len(document["servers"]) == len(full) and text.isascii() and text.endswith("\n")
    first = document["servers"][0]
    assert first == {
        "server": {
            "name": "io.github.acme/files",
            "version": "1.0.0",
            "packages": [{"registryType": "npm", "identifier": "@acme/mcp-files", "version": "1.0.0"}],
        },
        "_meta": {OFFICIAL: {"status": "active", "isLatest": False, "publishedAt": "2026-01-10T10:00:00Z"}},
    }


@pytest.mark.parametrize(
    "pages,message",
    [
        (
            [_page(_entry("io.github.acme/a"), cursor="c1"), _page(cursor="c1")],
            "repeated a pagination cursor",
        ),
        ([_page(cursor="c1"), _page(cursor="c2"), _page(cursor="c3")], "more than 2 page"),
        ([_page(_entry("io.github.acme/a"), count=2)], "count does not match"),
        ([{"servers": [], "metadata": {"count": 0}, "error": "x"}], "invalid page"),
        ([{"servers": ["x"], "metadata": {"count": 1}}], "invalid page"),
        ([_page(cursor=" ")], "invalid pagination cursor"),
        ([HttpError(429, "https://registry.example.com/v0.1/servers")], r"HTTP 429"),
        ([ValueError("Invalid JSON response with private detail")], r"\(ValueError\)"),
        ([_page(_entry("io.github.acme/a", status="retired"))], "unknown status"),
    ],
)
def test_the_producer_fails_closed(monkeypatch, pages, message):
    _listing(monkeypatch, pages)
    with pytest.raises(SnapshotError, match=message) as caught:
        fetch_snapshot("https://registry.example.com", max_pages=2)
    assert "private detail" not in str(caught.value)


def test_the_producer_enforces_its_size_limits(monkeypatch):
    _listing(monkeypatch, [_page(_entry("io.github.acme/a"), _entry("io.github.acme/b"))] * 2)
    monkeypatch.setattr(registry_module, "MAX_SNAPSHOT_SERVERS", 1)
    with pytest.raises(SnapshotError, match="more than 1 server versions"):
        fetch_snapshot("https://registry.example.com")
    monkeypatch.setattr(registry_module, "MAX_SNAPSHOT_BYTES", 100)
    with pytest.raises(SnapshotError, match="byte limit"):
        fetch_snapshot("https://registry.example.com")


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.example.com",
        "https://registry.example.com/?x=1",
        "https://user@registry.example.com",
        "https://127.0.0.1",
    ],
)
def test_the_producer_refuses_unsafe_registry_urls(url):
    with pytest.raises(SnapshotError, match="registry URL"):
        fetch_snapshot(url)


def test_snapshot_command_writes_a_private_file_and_prints_its_pin(monkeypatch, tmp_path):
    _listing(monkeypatch, [_page(*json.loads(FIXTURE.read_text())["servers"])])
    output = tmp_path / "official.json"
    result = CliRunner().invoke(main, ["mcp-registry", "snapshot", "--output", str(output)])
    assert result.exit_code == 0, result.output
    digest = _sha(output)
    assert result.stdout.strip() == digest
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    snapshot = load_snapshot(McpRegistrySource("official", str(output), digest))
    assert snapshot.registry == "https://registry.modelcontextprotocol.io"


def test_snapshot_command_exits_3_and_writes_nothing_on_failure(monkeypatch, tmp_path):
    _listing(monkeypatch, [_page(cursor="c1"), _page(cursor="c1")])
    output = tmp_path / "official.json"
    result = CliRunner().invoke(
        main, ["mcp-registry", "snapshot", "--url", "https://registry.example.com", "-o", str(output)]
    )
    assert result.exit_code == 3 and not output.exists()
    assert "repeated a pagination cursor; no snapshot written" in result.output


def test_snapshot_command_rejects_an_unsafe_url_as_a_usage_error(tmp_path):
    output = tmp_path / "official.json"
    result = CliRunner().invoke(
        main, ["mcp-registry", "snapshot", "--url", "http://registry.example.com", "-o", str(output)]
    )
    assert result.exit_code not in (0, 3) and not output.exists()
    assert "--url" in result.output
