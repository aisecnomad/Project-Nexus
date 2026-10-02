"""Shared clone, API snapshot and offline plumbing of the GitHub and GitLab connectors."""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
from pathlib import Path
from threading import Event, Lock
from time import monotonic
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import responses

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code import remote
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector, _GitLabMetadata
from shadowscan.connectors.code.remote import (
    API_MAX_BLOB_BYTES,
    API_MODE_MAX_FILES,
    SOURCE_SAMPLE,
    OfflineRepository,
    RemoteRepositoryConnector,
    repository_blob_matches,
    select_api_paths,
)
from shadowscan.models import Kind, ScanStats
from shadowscan.utils import git as git_module
from shadowscan.utils.git import checkout_has_lfs_pointers, safe_git_env
from shadowscan.utils.http import HttpError

COMMIT = "a" * 40
PROVIDERS = [GitHubConnector, GitLabConnector]


def _sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def _connector(index, cls, **config):
    ctx = ConnectorContext(config={"use_git": False, **config}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-09-27T00:00:00Z")
    return cls(ctx)


def _fetch_name(cls) -> str:
    return "_fetch_repo" if cls is GitHubConnector else "_fetch"


def _record(**extra):
    return {"full_name": "acme/app", "path_with_namespace": "acme/app", "id": 7, **extra}


# ------------------------------------------------------------ shared code
@pytest.mark.parametrize(
    "method",
    [
        "load_offline",
        "_analyze_repository",
        "_scan_local",
        "_fetch",
        "_clone",
        "_set_clone_snapshot",
        "_api_ref",
        "_write_api_snapshot",
    ],
)
def test_providers_run_one_shared_implementation(method):
    shared = getattr(RemoteRepositoryConnector, method)
    assert getattr(GitHubConnector, method) is shared
    assert getattr(GitLabConnector, method) is shared


def test_github_fetch_repo_is_the_shared_fetch():
    assert GitHubConnector._fetch_repo is RemoteRepositoryConnector._fetch


def test_api_selection_keeps_high_signal_files_before_shallow_sources():
    paths = [
        "src/pkg/sub/deep/agent.py",
        "README.md",
        "app.py",
        "pkg/mod.ts",
        "docs/notes.txt",
        ".github/workflows/ci.yml",
        "sub/CLAUDE.md",
        "infra/main.tf",
        "requirements.txt",
        "tools/.cursor/rules.mdc",
    ]
    assert select_api_paths(paths) == [
        ".github/workflows/ci.yml",
        "sub/CLAUDE.md",
        "infra/main.tf",
        "requirements.txt",
        "tools/.cursor/rules.mdc",
        "app.py",
        "pkg/mod.ts",
    ]


def test_api_selection_is_bounded():
    must = [f"cfg/{n}.yaml" for n in range(API_MODE_MAX_FILES + 5)]
    sources = [f"s{n}.py" for n in range(SOURCE_SAMPLE + 5)]
    assert select_api_paths(must + sources) == must[:API_MODE_MAX_FILES]
    assert select_api_paths(sources) == sorted(sources, key=lambda p: (p.count("/"), len(p)))[:SOURCE_SAMPLE]


@pytest.mark.parametrize("object_id", ["zz", "A" * 40, None, 12])
def test_blob_verification_rejects_invalid_object_ids(object_id):
    assert not repository_blob_matches(object_id, b"")
    assert repository_blob_matches(_sha(b"x"), b"x")


# ---------------------------------------------------------------- offline
def test_offline_records_carry_provider_identity(tmp_path, index):
    (tmp_path / "acme__app").mkdir()
    (tmp_path / "solo").mkdir()
    github = list(_connector(index, GitHubConnector).load_offline(str(tmp_path)))
    gitlab = list(_connector(index, GitLabConnector).load_offline(str(tmp_path)))
    assert github == [
        {"full_name": "acme__app", "owner": {"login": "acme"}},
        {"full_name": "solo", "owner": {"login": "solo"}},
    ]
    assert gitlab == [{"path_with_namespace": "acme__app"}, {"path_with_namespace": "solo"}]
    assert all(isinstance(record, OfflineRepository) for record in github + gitlab)
    assert [Path(record.local_path).name for record in gitlab] == ["acme__app", "solo"]


@pytest.mark.parametrize("cls", PROVIDERS)
def test_offline_input_must_be_a_directory(tmp_path, index, cls):
    export = tmp_path / "export.json"
    export.write_text("{}")
    with pytest.raises(ConnectorError, match="directory of clones"):
        list(_connector(index, cls).load_offline(str(export)))


@pytest.mark.parametrize("cls", PROVIDERS)
def test_offline_enumeration_failure_marks_scan_incomplete(tmp_path, index, monkeypatch, cls):
    def denied(self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "iterdir", denied)
    connector = _connector(index, cls)
    assert list(connector.load_offline(str(tmp_path))) == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings == [f"{cls.name}: could not enumerate offline clones"]


@pytest.mark.parametrize("cls", PROVIDERS)
def test_offline_clone_escaping_its_input_is_skipped(tmp_path, index, monkeypatch, cls):
    (tmp_path / "moved").mkdir()

    def escaped(self, *other):
        raise ValueError("outside")

    monkeypatch.setattr(Path, "relative_to", escaped)
    connector = _connector(index, cls)
    assert list(connector.load_offline(str(tmp_path))) == []
    assert connector.ctx.stats.incomplete
    assert f"{cls.name}: offline clone path escaped its input directory" in connector.ctx.stats.warnings


# ---------------------------------------------------------------- analyze
@pytest.mark.parametrize("cls", PROVIDERS)
def test_repository_http_failure_is_a_warning_and_cleans_up(tmp_path, index, monkeypatch, cls):
    connector = _connector(index, cls)
    connector.ctx.workdir = str(tmp_path)
    fetched = []

    def fetch(record, destination):
        fetched.append(Path(destination))
        raise HttpError(502, "https://api.example.test/repository")

    monkeypatch.setattr(connector, _fetch_name(cls), fetch)
    assert list(connector.analyze([_record()])) == []
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors
    assert connector.ctx.stats.warnings == [
        f"{cls.name}: acme/app: HTTP 502 for https://api.example.test/repository",
    ]
    assert fetched and not fetched[0].exists()


@pytest.mark.parametrize("cls", PROVIDERS)
def test_unfetched_repository_reports_nothing_further(index, monkeypatch, cls):
    connector = _connector(index, cls)
    remote_level = Mock(side_effect=AssertionError("no repository-level requests without content"))
    monkeypatch.setattr(connector, _fetch_name(cls), lambda record, destination: None)
    remote_level_name = "_repo_level_findings" if cls is GitHubConnector else "_project_level"
    monkeypatch.setattr(connector, remote_level_name, remote_level)
    assert list(connector.analyze([_record()])) == []
    assert connector.ctx.stats.objects_examined == 1
    remote_level.assert_not_called()


def test_checkout_findings_carry_provider_metadata_and_timestamps(tmp_path, index):
    (tmp_path / "requirements.txt").write_text("langchain\n")
    record = _record(
        owner={"login": "acme"},
        namespace={"full_path": "acme"},
        private=True,
        pushed_at="2026-09-01T00:00:00Z",
        created_at="2026-01-01T00:00:00Z",
    )
    github = list(_connector(index, GitHubConnector)._scan_local(record, str(tmp_path)))
    assert github and all(f.connector == "code.github" and f.provider == "github" for f in github)
    assert all(f.first_seen == "2026-01-01T00:00:00Z" and f.account == "acme" for f in github)
    assert all(f.metadata["repository"] == "acme/app" for f in github)
    assert all(f.metadata["visibility"] == "private" for f in github)
    gitlab_connector = _connector(index, GitLabConnector)
    gitlab = list(gitlab_connector._scan_local({"path_with_namespace": "acme/app"}, str(tmp_path)))
    assert gitlab and all(f.connector == "code.gitlab" and f.provider == "gitlab" for f in gitlab)
    # GitLab findings describe the project's creation time, unknown here.
    assert all(f.first_seen is None and f.account == "acme" for f in gitlab)
    assert all(f.metadata["project"] == "acme/app" for f in gitlab)


# ---------------------------------------------------------------- cloning
@pytest.mark.parametrize("cls", PROVIDERS)
def test_unknown_clone_revision_marks_provenance_incomplete(tmp_path, index, monkeypatch, cls):
    monkeypatch.setattr(remote, "read_git_snapshot", lambda path, timeout: None)
    connector = _connector(index, cls)
    record = _record()
    connector._set_clone_snapshot(record, str(tmp_path))
    assert "source_snapshot" not in record
    assert connector.ctx.stats.incomplete
    assert "source provenance unknown" in connector.ctx.stats.warnings[0]


def test_gitlab_project_without_clone_url_is_not_cloned(tmp_path, index, monkeypatch):
    run = Mock(side_effect=AssertionError("no clone without a URL"))
    monkeypatch.setattr(remote, "run_bounded_clone", run)
    assert not _connector(index, GitLabConnector)._clone({"path_with_namespace": "acme/app"}, str(tmp_path))
    run.assert_not_called()


@pytest.mark.parametrize("cls", PROVIDERS)
def test_clone_launch_failure_falls_back(tmp_path, index, monkeypatch, cls):
    monkeypatch.setattr(remote, "run_bounded_clone", Mock(side_effect=OSError("git missing")))
    record = _record(
        clone_url="https://github.com/acme/app.git",
        http_url_to_repo="https://gitlab.com/acme/app.git",
    )
    assert not _connector(index, cls)._clone(record, str(tmp_path / "repo"))


def test_github_enterprise_clone_stays_on_the_api_origin(tmp_path, index, monkeypatch):
    run = Mock(return_value=True)
    monkeypatch.setattr(remote, "run_bounded_clone", run)
    connector = _connector(
        index,
        GitHubConnector,
        api_url="https://ghe.example.com/api/v3",
        token="synthetic",
    )
    assert connector._clone({"full_name": "acme/app"}, str(tmp_path / "repo"))
    cmd, env = run.call_args.args[:2]
    assert cmd[-3:] == ["--", "https://ghe.example.com/acme/app.git", str(tmp_path / "repo")]
    keys = [env[f"GIT_CONFIG_KEY_{n}"] for n in range(int(env["GIT_CONFIG_COUNT"]))]
    assert "http.https://ghe.example.com/.extraheader" in keys


# ------------------------------------------------------------ GitHub API
def _github_api(index, tree, blobs=None):
    connector = _connector(index, GitHubConnector, mode="api")
    connector.http = Mock()

    def get(path, **kwargs):
        if "/git/trees/" in path:
            return tree
        return (blobs or {}).get(path.rsplit("/", 1)[-1])

    connector.http.try_get_json.side_effect = get
    return connector


def test_github_unreadable_tree_skips_content(tmp_path, index):
    connector = _github_api(index, {"message": "Not Found"})
    assert connector._fetch_via_api(_record(), str(tmp_path)) is None
    assert connector.ctx.stats.warnings == ["code.github: cannot read tree of acme/app"]


def test_github_malformed_tree_metadata_is_partial_coverage(tmp_path, index):
    good = b"from crewai import Agent\n"
    tree = {
        "sha": COMMIT,
        "tree": [
            "not-an-entry",
            {"path": "agent.py", "type": "blob", "sha": _sha(good), "size": len(good)},
            {"path": "big.py", "type": "blob", "sha": _sha(b"big"), "size": -1},
        ],
    }
    blobs = {_sha(good): {"encoding": "base64", "content": base64.b64encode(good).decode()}}
    connector = _github_api(index, tree, blobs)
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == good
    assert not (Path(dest) / "big.py").exists()
    warnings = connector.ctx.stats.warnings
    assert "code.github: malformed tree entries in acme/app; source coverage partial" in warnings
    assert "code.github: invalid blob size metadata in acme/app; source coverage partial" in warnings


@pytest.mark.parametrize(
    "blob,warning",
    [
        (None, "code.github: cannot read content in acme/app"),
        ({"encoding": "utf-8", "content": "x"}, "code.github: cannot read content in acme/app"),
        (
            {"encoding": "base64", "content": base64.b64encode(b"x" * (API_MAX_BLOB_BYTES + 1)).decode()},
            "code.github: oversized API content in acme/app",
        ),
    ],
)
def test_github_unusable_blob_is_skipped(tmp_path, index, blob, warning):
    object_id = _sha(b"x")
    tree = {"sha": COMMIT, "tree": [{"path": "agent.py", "type": "blob", "sha": object_id, "size": 1}]}
    connector = _github_api(index, tree, {object_id: blob})
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert not (Path(dest) / "agent.py").exists()
    assert connector.ctx.stats.warnings == [warning]


@pytest.mark.parametrize("name", ["", "UNRELATED_SETTING"])
def test_github_repository_without_provider_secret_names_has_no_finding(index, name):
    connector = _connector(index, GitHubConnector)
    connector.http = Mock()
    connector.http.paginate_link.return_value = [{"name": name}]
    assert list(connector._repo_level_findings(_record())) == []
    assert [call.args[0] for call in connector.http.paginate_link.call_args_list] == [
        "/repos/acme/app/actions/secrets",
        "/repos/acme/app/actions/variables",
        "/repos/acme/app/codespaces/secrets",
        "/repos/acme/app/dependabot/secrets",
    ]
    assert [call.kwargs["item_key"] for call in connector.http.paginate_link.call_args_list] == [
        "secrets",
        "variables",
        "secrets",
        "secrets",
    ]


# ------------------------------------------------------------ GitLab API
def _gitlab_api(index, tree, content=b""):
    connector = _connector(index, GitLabConnector, mode="api")
    connector.http = Mock()
    connector.http.try_get_json.return_value = {"id": COMMIT}
    connector.http.paginate_link.return_value = tree
    connector.http.read_response_bytes.return_value = content
    return connector


def test_gitlab_malformed_and_unselected_tree_entries_are_partial_coverage(tmp_path, index):
    good = b"from crewai import Agent\n"
    connector = _gitlab_api(
        index,
        [
            {"type": "blob"},
            {"path": "agent.py", "type": "blob", "id": _sha(good)},
            {"path": "notes.txt", "type": "blob", "id": _sha(b"notes")},
            {"path": "src", "type": "tree", "id": COMMIT},
        ],
        good,
    )
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == good
    assert not (Path(dest) / "notes.txt").exists()
    assert connector.ctx.stats.warnings == [
        "code.gitlab: malformed tree entry; source coverage partial",
        "code.gitlab: API mode samples repository; source coverage partial",
    ]


@pytest.mark.parametrize(
    "failure,warning",
    [
        (
            HttpError(404, "https://gitlab.com/api/v4/projects/7"),
            "code.gitlab: repository content HTTP 404; coverage partial",
        ),
        (ValueError("oversized"), "code.gitlab: oversized or invalid API content skipped"),
    ],
)
def test_gitlab_blob_download_failure_keeps_neighbours(tmp_path, index, failure, warning):
    good = b"from crewai import Agent\n"
    connector = _gitlab_api(
        index,
        [
            {"path": "bad.py", "type": "blob", "id": _sha(b"bad")},
            {"path": "good.py", "type": "blob", "id": _sha(good)},
        ],
    )
    connector.http.read_response_bytes.side_effect = [failure, good]
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert not (Path(dest) / "bad.py").exists()
    assert (Path(dest) / "good.py").read_bytes() == good
    assert connector.ctx.stats.warnings == [warning]


def test_gitlab_unusual_tree_path_costs_only_that_file(tmp_path, index):
    good = b"from crewai import Agent\n"
    connector = _gitlab_api(
        index,
        [
            {"path": "C:/agent.py", "type": "blob", "id": _sha(good)},
            {"path": "agent.py", "type": "blob", "id": _sha(good)},
        ],
        good,
    )
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert [p.name for p in Path(dest).iterdir()] == ["agent.py"]
    assert connector.ctx.stats.warnings == [
        "code.gitlab: unusual repository tree path skipped; source coverage partial",
    ]


def test_gitlab_project_level_reports_variables_tokens_and_bots_without_values(index):
    connector = _connector(index, GitLabConnector)
    listings = {
        "/projects/7/variables": [
            {"key": "OPENAI_API_KEY", "masked": False, "value": "synthetic-secret-value"},
        ],
        "/projects/7/access_tokens": [{"id": 3, "name": "deploy", "scopes": ["api"]}],
        "/projects/7/members": [
            {"id": 4, "username": "project_7_bot_1a2b"},
            {"id": 5, "username": "alice"},
            {"id": 6, "username": "helper", "bot": True},
        ],
    }
    connector.http = Mock()
    connector.http.paginate_link.side_effect = lambda path, **_: listings[path]
    findings = list(connector._project_level({"id": 7, "path_with_namespace": "acme/app"}))
    assert [f.resource_type for f in findings] == [
        "ci-variables",
        "project_access_token",
        "project_bot",
        "project_bot",
    ]
    assert "unmasked-ci-variable" in findings[0].tags
    assert findings[1].permissions == ["api"]
    assert "synthetic-secret-value" not in repr(findings)
    assert [call.args[0] for call in connector.http.paginate_link.call_args_list] == list(listings)


def test_gitlab_variables_without_provider_names_have_no_finding(index):
    connector = _connector(index, GitLabConnector)
    assert connector._variables_finding("acme/app", [{"key": "UNRELATED_SETTING"}], scope="project") is None


# ---------------------------------------------------------------- collect
@pytest.mark.parametrize("cls", PROVIDERS)
def test_collect_without_targets_is_a_configuration_error(index, cls, monkeypatch):
    for variable in ("GITHUB_ORG", "GITLAB_GROUP"):
        monkeypatch.delenv(variable, raising=False)
    with pytest.raises(ConnectorError, match="set '"):
        list(_connector(index, cls).collect())


def test_github_collect_filters_deduplicates_and_caps_listings(index):
    connector = _connector(
        index,
        GitHubConnector,
        repos=["acme/one", "acme/one", "acme/gone"],
        user="octo",
        max_repos=3,
    )
    connector.http = Mock()
    connector.http.try_get_json.side_effect = [{"full_name": "acme/one"}, None]
    connector.http.paginate_link.return_value = [
        {"full_name": "acme/one"},
        {"full_name": "octo/archived", "archived": True},
        {"full_name": "octo/fork", "fork": True},
        {"full_name": "octo/tool", "topics": ["ai"]},
        {"full_name": "octo/extra"},
    ]
    records = list(connector.collect())
    assert [record["full_name"] for record in records] == ["acme/one", "octo/tool", "octo/extra"]
    assert connector.http.paginate_link.call_args.args[0] == "/users/octo/repos"
    assert connector.ctx.stats.warnings == ["code.github: cannot access acme/gone"]

    capped = _connector(index, GitHubConnector, user="octo", max_repos=1, topics=["ai"])
    capped.http = Mock()
    capped.http.paginate_link.return_value = [
        {"full_name": "octo/a", "topics": ["ai"]},
        {"full_name": "octo/b"},
        {"full_name": "octo/c", "topics": ["ai"]},
    ]
    assert [record["full_name"] for record in capped.collect()] == ["octo/a"]
    assert capped.ctx.stats.warnings == ["code.github: max_repos (1) reached"]


def test_gitlab_collect_deduplicates_and_caps_group_listing(index):
    connector = _connector(
        index,
        GitLabConnector,
        projects=["acme/one", "acme/one"],
        group="acme",
        max_projects=2,
    )
    connector.http = Mock()
    connector.http.try_get_json.side_effect = [{"id": 1, "path_with_namespace": "acme/one"}, {}]
    listings = {
        "/groups/acme/projects": [
            {"id": 1, "path_with_namespace": "acme/one"},
            {"id": 2, "path_with_namespace": "acme/two"},
            {"id": 3, "path_with_namespace": "acme/three"},
        ]
    }
    connector.http.paginate_link.side_effect = lambda path, **_: listings.get(path, [])
    records = list(connector.collect())
    assert [record["id"] for record in records] == [1, 2]
    assert connector.http.try_get_json.call_count == 2  # one explicit project, then the group details
    assert connector.ctx.stats.warnings == ["code.gitlab: max_projects (2) reached"]


def test_gitlab_denied_optional_metadata_is_partial_coverage(index):
    connector = _connector(index, GitLabConnector)
    connector.http = Mock()
    denied = HttpError(403, "https://gitlab.com/api/v4/groups/acme/variables")
    connector.http.paginate_link.side_effect = denied
    assert list(connector._optional_list("/groups/acme/variables")) == []
    assert connector.ctx.stats.warnings == [
        "code.gitlab: metadata HTTP 403 for /groups/acme/variables; coverage unknown",
    ]


def test_gitlab_duo_setting_becomes_an_agent_config_finding(index):
    connector = _connector(index, GitLabConnector)
    connector.http = Mock()
    connector.http.paginate_link.return_value = []
    connector.http.try_get_json.return_value = {
        "full_path": "acme",
        "duo_features_enabled": True,
        "lock_duo_features_enabled": False,
    }
    records = list(connector._group_identities("acme"))
    assert [record.kind for record in records] == ["duo"]
    disabled = _GitLabMetadata("duo", {"group": "other", "duo_features_enabled": False})
    findings = list(connector.analyze([*records, disabled]))
    assert [f.resource for f in findings] == ["gitlab:acme/duo"]
    assert findings[0].kind is Kind.AGENT_CONFIG and "code-exec" in findings[0].capabilities


@pytest.mark.parametrize(
    "cls, fetch_method, metadata_method",
    [
        (GitHubConnector, "_fetch_repo", "_repo_level_findings"),
        (GitLabConnector, "_fetch", "_project_level"),
    ],
)
def test_live_download_under_symlinked_temp_parent_is_scanned(
    tmp_path, index, monkeypatch, cls, fetch_method, metadata_method
):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    context = ConnectorContext(config={"use_git": False}, index=index, workdir=str(alias))
    connector = cls(context)
    record = {"full_name": "org/agent", "path_with_namespace": "org/agent"}
    monkeypatch.setattr(connector, "collect", lambda: iter([record]))
    downloaded = []

    def fetch(_record, destination):
        root = Path(destination)
        downloaded.append(root)
        (root / "agent.py").write_text("from crewai import Agent\n")
        return destination

    monkeypatch.setattr(connector, fetch_method, fetch)
    monkeypatch.setattr(connector, metadata_method, lambda _record: iter([]))
    findings = connector.run()
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert not context.stats.errors
    assert downloaded and downloaded[0].parent == actual
    assert not downloaded[0].exists()  # temporary source remains cleaned up


@pytest.mark.parametrize("cls", [GitHubConnector, GitLabConnector])
def test_nested_repository_scan_inherits_cancellation_and_publication_fence(
    tmp_path, index, monkeypatch, cls
):
    cancelled, publication_lock = Event(), Lock()
    parent = ConnectorContext(
        config={"use_git": False},
        index=index,
        workdir=str(tmp_path),
        deadline=monotonic() + 30,
        cancelled=cancelled,
        publication_lock=publication_lock,
    )
    child_contexts = []

    class CaptureFilesystem:
        def __init__(self, ctx):
            self.ctx = ctx
            child_contexts.append(ctx)

        def analyze(self, records):
            self.ctx.check_deadline()
            return []

    monkeypatch.setattr("shadowscan.connectors.code.remote.FilesystemConnector", CaptureFilesystem)
    connector = cls(parent)
    record = {"full_name": "org/repo", "path_with_namespace": "org/repo"}
    assert list(connector._scan_local(record, str(tmp_path))) == []
    child = child_contexts[0]
    assert child.deadline == parent.deadline
    assert child.cancelled is cancelled and child.publication_lock is publication_lock
    assert child.workdir == str(tmp_path)
    cancelled.set()
    with pytest.raises(ConnectorError, match="deadline"):
        child.check_deadline()


@pytest.mark.parametrize(
    "cls, record",
    [
        (GitHubConnector, {"full_name": "org/repo", "clone_url": "https://github.com/org/repo.git"}),
        (GitLabConnector, {"http_url_to_repo": "https://gitlab.com/org/repo.git"}),
    ],
)
def test_clone_process_is_bounded_by_connector_deadline(tmp_path, index, monkeypatch, cls, record):
    timeouts = []

    class FakeProc:
        def wait(self, timeout):
            timeouts.append(timeout)
            return 0

    monkeypatch.setattr("shadowscan.utils.git.subprocess.Popen", lambda *args, **kwargs: FakeProc())
    context = ConnectorContext(index=index, deadline=monotonic() + 2)
    assert cls(context)._clone(record, str(tmp_path / "repo"))
    assert len(timeouts) == 1 and 0 < timeouts[0] <= 2


@pytest.mark.parametrize(
    "cls,key,records,identity",
    [
        (GitHubConnector, "repos", ["acme/one", "acme/two"], "full_name"),
        (GitLabConnector, "projects", ["acme/one", "acme/two"], "id"),
    ],
)
def test_explicit_repository_caps_are_enforced(cls, key, records, identity, index):
    limit = "max_repos" if cls is GitHubConnector else "max_projects"
    ctx = ConnectorContext(config={key: records, limit: 1}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    connector.http = Mock()
    connector.http.try_get_json.return_value = (
        {identity: "acme/one"} if cls is GitHubConnector else {identity: 1, "path_with_namespace": "acme/one"}
    )
    assert len(list(connector.collect())) == 1
    assert connector.http.try_get_json.call_count == 1
    assert ctx.stats.incomplete and any(limit in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("cls,key", [(GitHubConnector, "max_repos"), (GitLabConnector, "max_projects")])
def test_invalid_repository_caps_rejected(cls, key, index):
    from shadowscan.connectors.base import ConnectorError

    with pytest.raises(ConnectorError, match=key):
        cls(ConnectorContext(config={key: 0}, index=index))


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_offline_repo_caps_mark_partial_coverage(tmp_path: Path, connector: str, run_connector):
    for name in ("one", "two"):
        repo = tmp_path / name
        repo.mkdir()
        (repo / "requirements.txt").write_text("langchain\n")
    limit = "max_repos" if connector == "code.github" else "max_projects"
    findings, ctx = run_connector(connector, input=str(tmp_path), use_git=False, **{limit: 1})
    assert len([f for f in findings if f.resource_type == "project"]) == 1
    assert ctx.stats.incomplete and any(limit in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
@pytest.mark.parametrize("file_only", [False, True], ids=["empty-root", "files-without-clones"])
def test_empty_offline_clone_input_marks_scan_incomplete(
    tmp_path: Path, connector: str, file_only: bool, run_connector
):
    if file_only:
        (tmp_path / "README.md").write_text("No checkout was exported here.\n")
    findings, ctx = run_connector(connector, input=str(tmp_path), use_git=False)

    assert findings == []
    assert ctx.stats is not None and ctx.stats.objects_examined == 0
    assert ctx.stats.incomplete
    assert any("contains no clone directories" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_nested_filesystem_respects_scan_timeout(tmp_path: Path, connector: str, run_connector):
    checkout = tmp_path / "one"
    checkout.mkdir()
    (checkout / "requirements.txt").write_text("langchain\n")
    findings, ctx = run_connector(connector, input=str(tmp_path), scan_timeout=61)
    assert not findings and ctx.stats.incomplete
    assert any("scan_timeout" in error for error in ctx.stats.errors)


def test_per_repository_contexts_share_the_diagnostic_cap(tmp_path, index):
    for name in ("acme__r1", "acme__r2", "acme__r3"):
        repo = tmp_path / name
        repo.mkdir()
        for i in range(1100):
            (repo / f"f{i}.py").write_text("ab")
    ctx = ConnectorContext(
        config={"input": str(tmp_path), "max_file_size": 1, "strict_coverage": True}, index=index
    )
    GitHubConnector(ctx).run()
    assert len(ctx.stats.errors) == ConnectorContext._MAX_DIAGNOSTICS + 1
    assert sum("diagnostic limit reached" in e for e in ctx.stats.errors) == 1


# ---------------------------------------------------- listing completeness
def _listing_connector(index, cls, **config):
    """A connector listing an org/group of eight repositories ordered by activity (most recent first)."""
    scope = {"org": "acme"} if cls is GitHubConnector else {"group": "acme"}
    connector = _connector(index, cls, **scope, **config)
    connector.http = Mock()
    return connector


def _entry(cls, name):
    if cls is GitHubConnector:
        return {"full_name": f"acme/{name}"}
    return {"id": int(name[1:]), "path_with_namespace": f"acme/{name}"}


def _identity(cls, record):
    return record["full_name"] if cls is GitHubConnector else record["path_with_namespace"]


@pytest.mark.parametrize("cls", PROVIDERS)
def test_a_push_during_the_scan_cannot_hide_a_repository_that_was_not_listed_yet(index, cls):
    """Reviewer PoC: with page N+1 fetched after page N was scanned, a push moved r7 behind the cursor."""
    names = [f"r{n}" for n in range(1, 9)]
    order = list(names)  # most recently pushed first
    connector = _listing_connector(index, cls)

    def pages(path, **_):
        if "/projects" not in path and "/repos" not in path:
            return
        for start in range(0, len(order), 3):  # three entries per page, fetched when asked for
            yield from (_entry(cls, name) for name in list(order[start : start + 3]))

    connector.http.paginate_link.side_effect = pages
    connector.http.try_get_json.return_value = {}
    seen = []
    for record in connector.collect():
        if "full_name" in record or "path_with_namespace" in record:
            seen.append(_identity(cls, record))
            if len(seen) == 1:  # somebody pushes to r7 while the scanner is busy with the first repository
                order.remove("r7")
                order.insert(0, "r7")
    assert sorted(seen) == sorted(f"acme/{name}" for name in names)
    assert connector.ctx.stats.warnings == []


@pytest.mark.parametrize("cls", PROVIDERS)
def test_listing_is_read_to_the_end_before_the_first_repository_is_handed_out(index, cls):
    connector = _listing_connector(index, cls)
    fetched = []

    def pages(path, **_):
        if "/projects" not in path and "/repos" not in path:
            return
        for page in (1, 2, 3):
            fetched.append(page)
            yield _entry(cls, f"r{page}")

    connector.http.paginate_link.side_effect = pages
    connector.http.try_get_json.return_value = {}
    records = connector.collect()
    assert fetched == []  # nothing happens until the records are consumed
    first = next(iter(records))
    assert _identity(cls, first).startswith("acme/r") and fetched == [1, 2, 3]


@pytest.mark.parametrize("cls", PROVIDERS)
def test_failed_listing_still_scans_what_was_listed_and_then_fails(index, cls):
    connector = _listing_connector(index, cls)

    def pages(path, **_):
        if "/projects" not in path and "/repos" not in path:
            return
        yield _entry(cls, "r1")
        yield _entry(cls, "r2")
        raise RuntimeError("Pagination limit reached; collection incomplete")

    connector.http.paginate_link.side_effect = pages
    connector.http.try_get_json.return_value = {}
    listed = []
    with pytest.raises(RuntimeError, match="collection incomplete"):
        for record in connector.collect():
            if "full_name" in record or "path_with_namespace" in record:
                listed.append(_identity(cls, record))
    assert listed == ["acme/r1", "acme/r2"]


def test_listings_use_an_ordering_a_push_cannot_change(index):
    github = _connector(index, GitHubConnector, org="acme", user="octo")
    github.http = Mock()
    github.http.paginate_link.return_value = []
    list(github.collect())
    calls = {call.args[0]: call.kwargs["params"] for call in github.http.paginate_link.call_args_list}
    assert calls["/orgs/acme/repos"]["sort"] == calls["/users/octo/repos"]["sort"] == "full_name"
    assert calls["/orgs/acme/repos"]["direction"] == calls["/users/octo/repos"]["direction"] == "asc"
    gitlab = _connector(index, GitLabConnector, group="acme")
    gitlab.http = Mock()
    gitlab.http.paginate_link.return_value = []
    gitlab.http.try_get_json.return_value = {}
    list(gitlab.collect())
    params = gitlab.http.paginate_link.call_args_list[-1].kwargs["params"]
    assert (params["order_by"], params["sort"]) == ("id", "asc")


GITLAB_API = "https://gitlab.example.com/api/v4"


def _gitlab_group_pages(total, *, second_total=None, pages=2):
    """Register a two-page group listing of three projects whose pages state *total* (X-Total)."""
    for suffix in ("service_accounts", "access_tokens", "variables"):
        responses.get(f"{GITLAB_API}/groups/acme/{suffix}", json=[])
    responses.get(f"{GITLAB_API}/groups/acme", json={})
    headers = {"X-Total": str(total), "X-Total-Pages": str(pages)}
    responses.get(
        f"{GITLAB_API}/groups/acme/projects",
        json=[{"id": 1, "path_with_namespace": "acme/a"}, {"id": 2, "path_with_namespace": "acme/b"}],
        headers={**headers, "Link": f'<{GITLAB_API}/groups/acme/projects?page=2>; rel="next"'},
    )
    responses.get(
        f"{GITLAB_API}/groups/acme/projects",
        json=[{"id": 3, "path_with_namespace": "acme/c"}],
        headers={**headers, "X-Total": str(second_total or total)},
    )


@responses.activate
def test_gitlab_listing_that_matches_its_reported_totals_is_complete(index):
    _gitlab_group_pages(3)
    connector = _connector(index, GitLabConnector, group="acme", api_url=GITLAB_API)
    assert [record["id"] for record in connector.collect() if "path_with_namespace" in record] == [1, 2, 3]
    assert connector.ctx.stats.warnings == [] and not connector.ctx.stats.incomplete
    first = responses.calls[-2].request.url
    assert "order_by=id" in first and "sort=asc" in first


@pytest.mark.parametrize(
    "total,second_total,pages",
    [(4, None, 2), (2, None, 2), (3, 4, 2), (3, None, 3), ("many", None, 2)],
    ids=["entries-missing", "extra-entries", "total-changed-between-pages", "wrong-page-count", "garbage"],
)
@responses.activate
def test_gitlab_listing_that_disagrees_with_its_reported_totals_is_incomplete(
    index, total, second_total, pages
):
    _gitlab_group_pages(total, second_total=second_total, pages=pages)
    connector = _connector(index, GitLabConnector, group="acme", api_url=GITLAB_API)
    records = [record for record in connector.collect() if "path_with_namespace" in record]
    assert len(records) == 3  # what was listed is still scanned
    assert connector.ctx.stats.incomplete
    assert any("does not match its reported X-Total" in w for w in connector.ctx.stats.warnings)


@responses.activate
def test_github_listing_reports_no_totals_and_requests_a_stable_order(index):
    api = "https://api.github.com"
    responses.get(
        f"{api}/orgs/acme/repos",
        json=[{"full_name": "acme/a"}, {"full_name": "acme/b"}],
        headers={"Link": f'<{api}/orgs/acme/repos?page=2>; rel="next"'},
    )
    responses.get(f"{api}/orgs/acme/repos", json=[{"full_name": "acme/c"}])
    connector = _connector(index, GitHubConnector, org="acme")
    assert [record["full_name"] for record in connector.collect()] == ["acme/a", "acme/b", "acme/c"]
    assert connector.ctx.stats.warnings == []
    query = responses.calls[0].request.url.split("?", 1)[1]
    assert "sort=full_name" in query and "direction=asc" in query


# ---------------------------------------------------- Git LFS pointer files in a clone
# Submodules (gitlinks) of a clone are reported by the filesystem scan of the checkout; see
# tests/unit/test_gitlink_coverage.py. A clone also holds LFS pointer files, not the large files.
LFS_POINTER = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 123456789\n"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _run_git(*args):
    subprocess.run(["git", *args], check=True, capture_output=True, env=safe_git_env())


def _source_repository(tmp_path, *, lfs_pointer=False):
    """A one-commit repository, optionally holding a Git LFS pointer file as `git lfs track` leaves it."""
    work = tmp_path / "origin"
    work.mkdir()
    _run_git("init", "-q", "-b", "main", str(work))
    (work / "app.py").write_text("print('hello')\n")
    (work / "assets").mkdir()
    if lfs_pointer:
        (work / "assets" / "model.bin").write_text(LFS_POINTER)
    _run_git("-C", str(work), "add", "-A")
    _run_git(
        *("-C", str(work), "-c", "user.name=Test", "-c", "user.email=test@example.test"),
        *("-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"),
    )
    return work


def _clone_of(source):
    """Stand-in for the bounded clone: a real shallow clone of a local repository."""

    def clone(cmd, env, ctx, timeout, *, destination, max_bytes):
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", f"file://{source}", destination],
            check=True,
            capture_output=True,
            env=safe_git_env({"GIT_ALLOW_PROTOCOL": "file"}),
        )
        return True

    return clone


def _clone_fetch(index, monkeypatch, tmp_path, cls, source, **config):
    connector = _connector(index, cls, **config)
    monkeypatch.setattr(remote, "run_bounded_clone", _clone_of(source))
    record = (
        {"full_name": "acme/app", "size": 1, "clone_url": "https://github.com/acme/app.git"}
        if cls is GitHubConnector
        else {
            "id": 7,
            "path_with_namespace": "acme/app",
            "statistics": {"repository_size": 1},
            "http_url_to_repo": "https://gitlab.com/acme/app.git",
        }
    )
    work = tmp_path / "work"
    work.mkdir()
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(work)) == str(work / "repo")
    return connector.ctx.stats


@needs_git
@pytest.mark.parametrize("cls", PROVIDERS)
def test_clone_with_an_lfs_pointer_is_incomplete_coverage(tmp_path, index, monkeypatch, cls):
    stats = _clone_fetch(index, monkeypatch, tmp_path, cls, _source_repository(tmp_path, lfs_pointer=True))
    assert stats.incomplete and not stats.errors
    assert stats.warnings == [
        f"{cls.name}: Git LFS pointer files in acme/app are not resolved; source coverage partial"
    ]


@needs_git
@pytest.mark.parametrize("cls", PROVIDERS)
def test_strict_coverage_makes_an_lfs_pointer_an_error(tmp_path, index, monkeypatch, cls):
    stats = _clone_fetch(
        index,
        monkeypatch,
        tmp_path,
        cls,
        _source_repository(tmp_path, lfs_pointer=True),
        strict_coverage=True,
    )
    assert stats.incomplete and not stats.warnings
    assert stats.errors == [
        f"{cls.name}: Git LFS pointer files in acme/app are not resolved; source coverage partial"
    ]


@needs_git
@pytest.mark.parametrize("cls", PROVIDERS)
def test_ordinary_clone_stays_complete(tmp_path, index, monkeypatch, cls):
    stats = _clone_fetch(index, monkeypatch, tmp_path, cls, _source_repository(tmp_path))
    assert stats.warnings == [] and not stats.incomplete


@needs_git
def test_clone_that_cannot_be_inspected_for_lfs_pointers_is_incomplete_coverage(tmp_path, index, monkeypatch):
    monkeypatch.setattr(remote, "checkout_has_lfs_pointers", lambda *args, **kwargs: None)
    stats = _clone_fetch(index, monkeypatch, tmp_path, GitHubConnector, _source_repository(tmp_path))
    assert stats.incomplete
    assert stats.warnings == [
        "code.github: could not inspect acme/app for Git LFS pointer files; source coverage unknown"
    ]


def test_lfs_pointer_scan_looks_only_at_small_regular_files_and_follows_no_link(tmp_path):
    root = tmp_path / "checkout"
    (root / ".git").mkdir(parents=True)
    (root / "src").mkdir()
    (root / ".git" / "pointer").write_text(LFS_POINTER)  # repository metadata is not content
    (root / "big.txt").write_text(LFS_POINTER + "x" * 2048)  # too large to be a pointer
    (root / "notes.txt").write_text("a version line of its own, https://git-lfs.github.com/spec/v1\n")
    outside = tmp_path / "outside.bin"
    outside.write_text(LFS_POINTER)
    (root / "src" / "link.bin").symlink_to(outside)
    assert checkout_has_lfs_pointers(root) is False
    (root / "src" / "deep").mkdir()
    (root / "src" / "deep" / "weights.bin").write_text(LFS_POINTER)
    assert checkout_has_lfs_pointers(root) is True


def test_lfs_pointer_scan_is_bounded_and_honours_the_deadline(tmp_path, monkeypatch):
    for number in range(5):
        (tmp_path / f"f{number}.txt").write_text("x\n")
    monkeypatch.setattr(git_module, "_MAX_CLONE_ENTRIES", 3)
    assert checkout_has_lfs_pointers(tmp_path) is None  # beyond the bound is "unknown", not "none"
    assert checkout_has_lfs_pointers(tmp_path / "missing") is None
    monkeypatch.undo()

    def expired() -> None:
        raise ConnectorError("scan deadline exceeded")

    for number in range(1000):
        (tmp_path / f"g{number}.txt").write_text("x\n")
    with pytest.raises(ConnectorError, match="deadline"):
        checkout_has_lfs_pointers(tmp_path, check_deadline=expired)


def _api_snapshot_with_a_pointer(tmp_path, index, monkeypatch, cls, **config):
    connector = _connector(index, cls, **config)
    pointer = LFS_POINTER.encode()
    source = b"print('hello')\n"
    monkeypatch.setattr(
        connector,
        "_download_blob",
        lambda repo, blob_id: pointer if blob_id == _sha(pointer) else source,
    )
    field = connector.blob_id_field
    blobs = {"model.bin": {field: _sha(pointer)}, "app.py": {field: _sha(source)}}
    dest, written = connector._write_api_snapshot({}, blobs, list(blobs), str(tmp_path), " in acme/app")
    assert written == 2 and Path(dest, "app.py").exists()
    return connector.ctx.stats


@pytest.mark.parametrize("cls", PROVIDERS)
def test_api_snapshot_with_an_lfs_pointer_is_incomplete_coverage(tmp_path, index, monkeypatch, cls):
    stats = _api_snapshot_with_a_pointer(tmp_path, index, monkeypatch, cls)
    assert stats.incomplete and not stats.errors
    assert stats.warnings == [
        f"{cls.name}: Git LFS pointer files in acme/app are not resolved; source coverage partial"
    ]


@pytest.mark.parametrize("cls", PROVIDERS)
def test_strict_coverage_makes_an_api_lfs_pointer_an_error(tmp_path, index, monkeypatch, cls):
    stats = _api_snapshot_with_a_pointer(tmp_path, index, monkeypatch, cls, strict_coverage=True)
    assert stats.incomplete and not stats.warnings
    assert len(stats.errors) == 1 and "Git LFS pointer files" in stats.errors[0]


# ---------------------------------------------------- option validation
LIST_OPTIONS = [(GitHubConnector, "topics"), (GitHubConnector, "repos"), (GitLabConnector, "projects")]


@pytest.mark.parametrize("cls,key", LIST_OPTIONS)
@pytest.mark.parametrize(
    "value",
    ["llm", "acme/app", "a,b", "", 7, True, {"acme/app": 1}, ["ok", ""], ["ok", "  "], ["ok", None], [["x"]]],
    ids=lambda v: repr(v),
)
def test_list_options_accept_only_a_list_of_non_empty_strings(index, cls, key, value):
    """`--set topics=llm` became the characters l, l, m: zero repositories examined, scan complete."""
    with pytest.raises(ConnectorError, match=f"^{key} must be a list of non-empty strings"):
        cls(ConnectorContext(config={key: value}, index=index))


@pytest.mark.parametrize("cls,key", LIST_OPTIONS)
def test_list_option_errors_name_the_key_not_the_value(index, cls, key):
    with pytest.raises(ConnectorError) as raised:
        cls(ConnectorContext(config={key: "synthetic-topic-value-1f3a"}, index=index))
    assert key in str(raised.value) and "synthetic-topic-value-1f3a" not in str(raised.value)


@pytest.mark.parametrize("cls,key", LIST_OPTIONS)
@pytest.mark.parametrize("value", [None, [], (), ["one"], ("one", "two")])
def test_list_options_accept_unset_empty_and_real_lists(index, cls, key, value):
    cls(ConnectorContext(config={key: value}, index=index))


def test_topics_filter_uses_whole_topic_names(index):
    connector = _connector(index, GitHubConnector, topics=["llm", "agents"])
    assert connector.topics == {"llm", "agents"}
    assert connector._wanted({"full_name": "acme/app", "topics": ["llm"]})
    assert not connector._wanted({"full_name": "acme/app", "topics": ["l", "m"]})


def test_gitlab_projects_may_name_numeric_ids_and_the_group_a_number(index):
    connector = _connector(index, GitLabConnector, projects=[42, "acme/app"], group=1234)
    assert connector.projects == ["42", "acme/app"] and connector.group == "1234"


def test_cli_run_with_a_bare_topic_is_incomplete_not_an_empty_clean_scan():
    from click.testing import CliRunner

    from shadowscan.cli import main

    result = CliRunner().invoke(
        main, ["run", "code.github", "--set", "org=acme", "--set", "topics=llm", "--format", "json"]
    )
    assert result.exit_code == 3
    assert "topics must be a list of non-empty strings" in result.output
    assert '"complete": false' in result.output


@pytest.mark.parametrize("cls,key", [(GitHubConnector, "max_repos"), (GitLabConnector, "max_projects")])
@pytest.mark.parametrize("value", [True, False, 2.5, "many", "1e3", [5], {"n": 5}, "", "12345678901"])
def test_record_caps_must_be_whole_numbers(index, cls, key, value):
    with pytest.raises(ConnectorError, match=f"^{key} must be a whole number"):
        cls(ConnectorContext(config={key: value}, index=index))


@pytest.mark.parametrize("cls,key", [(GitHubConnector, "max_repos"), (GitLabConnector, "max_projects")])
@pytest.mark.parametrize("value,expected", [(5, 5), (5.0, 5), ("25", 25), (" 7 ", 7)])
def test_record_caps_accept_whole_numbers_including_expanded_text(index, cls, key, value, expected):
    assert cls(ConnectorContext(config={key: value}, index=index)).max_records == expected


@pytest.mark.parametrize("value", [0, -1, "-3"])
def test_record_caps_must_be_positive(index, value):
    with pytest.raises(ConnectorError, match="max_repos must be positive"):
        GitHubConnector(ConnectorContext(config={"max_repos": value}, index=index))


@pytest.mark.parametrize("value", [True, 1.5, "deep", 0, -2])
def test_clone_depth_must_be_a_positive_whole_number(index, value):
    with pytest.raises(ConnectorError, match="clone_depth must be"):
        GitHubConnector(ConnectorContext(config={"clone_depth": value}, index=index))


@pytest.mark.parametrize(
    "key,cls", [("org", GitHubConnector), ("user", GitHubConnector), ("group", GitLabConnector)]
)
@pytest.mark.parametrize("value", [["acme"], {"name": "acme"}, True, 3.5])
def test_target_names_must_be_text(index, key, cls, value):
    with pytest.raises(ConnectorError, match=f"^{key} must be a string"):
        cls(ConnectorContext(config={key: value}, index=index))


def test_blank_target_names_are_unset_like_an_empty_variable(index, monkeypatch):
    monkeypatch.setenv("GITHUB_ORG", "  ")
    connector = _connector(index, GitHubConnector, user="")
    assert connector.org is None and connector.user is None
    with pytest.raises(ConnectorError, match="set 'org', 'user' or 'repos'"):
        list(connector.collect())


# ---------------------------------------------------- Git version gate
@pytest.mark.parametrize(
    "cls,record",
    [
        (GitHubConnector, {"full_name": "org/repo", "size": 1}),
        (GitLabConnector, {"path_with_namespace": "org/repo", "id": 123}),
    ],
)
@pytest.mark.parametrize("version", [(2, 30, 2), (2, 31, 9), (1, 9, 5), None], ids=str)
def test_clone_with_an_old_or_unreadable_git_uses_incomplete_api_fallback(
    tmp_path, monkeypatch, index, cls, record, version
):
    """Git before 2.32 ignores GIT_CONFIG_COUNT/GIT_CONFIG_GLOBAL: a redirect to another host was followed."""
    ctx = ConnectorContext(config={"mode": "clone"}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    monkeypatch.setattr(git_module, "git_version", lambda: version)
    clone = Mock(side_effect=AssertionError("an unsupported git must not clone"))
    monkeypatch.setattr(connector, "_clone", clone)
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == [
        f"{cls.name}: Git 2.32 or newer is required to clone org/repo; using sampled API mode"
    ]
    clone.assert_not_called()


@pytest.mark.parametrize("version", [(2, 32, 0), (2, 43, 0), (3, 0, 1)])
def test_clone_proceeds_with_a_supported_git(tmp_path, monkeypatch, index, version):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-01-01T00:00:00Z")
    connector = GitHubConnector(ctx)
    monkeypatch.setattr(git_module, "git_version", lambda: version)
    monkeypatch.setattr(connector, "_clone", lambda repo, dest: True)
    monkeypatch.setattr(
        remote, "read_git_snapshot", lambda path, timeout: {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    )
    assert connector._fetch_repo({"full_name": "org/repo", "size": 1}, str(tmp_path)) == str(
        tmp_path / "repo"
    )
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    "version,supported",
    [
        ((2, 31, 9), False),
        ((2, 32, 0), True),
        ((2, 43, 0), True),
        ((3, 0, 0), True),
        ((1, 99, 0), False),
        (None, False),
    ],
)
def test_clone_git_support_boundary(monkeypatch, version, supported):
    monkeypatch.setattr(git_module, "git_version", lambda: version)
    assert git_module.clone_git_supported() is supported


@pytest.mark.parametrize(
    "output,expected",
    [
        (b"git version 2.43.0\n", (2, 43, 0)),
        (b"git version 2.39.3 (Apple Git-146)\n", (2, 39, 3)),
        (b"git version 2.43.0.windows.1\n", (2, 43, 0)),
        (b"git version 2.32\n", (2, 32, 0)),
        (b"git version 2.45.0-rc1\n", (2, 45, 0)),
        (b"not git\n", None),
        (b"", None),
    ],
)
def test_git_version_parses_the_banner(monkeypatch, output, expected):
    monkeypatch.setattr(git_module, "_git_version_cache", None)
    monkeypatch.setattr(
        git_module.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=output)
    )
    assert git_module.git_version() == expected


def test_git_version_is_read_once_and_a_failed_probe_is_retried(monkeypatch):
    monkeypatch.setattr(git_module, "_git_version_cache", None)
    calls = []

    def probe(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise OSError("git could not be executed")
        return SimpleNamespace(returncode=0, stdout=b"git version 2.40.1\n")

    monkeypatch.setattr(git_module.subprocess, "run", probe)
    assert git_module.git_version() is None  # not remembered: cloning is not disabled for good
    assert git_module.git_version() == (2, 40, 1)
    assert git_module.git_version() == (2, 40, 1)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "result",
    [
        SimpleNamespace(returncode=1, stdout=b"git version 2.43.0\n"),
        SimpleNamespace(returncode=0, stdout="git version 2.43.0\n"),
        SimpleNamespace(returncode=0, stdout=None),
    ],
)
def test_unusable_version_probe_output_is_unknown_not_supported(monkeypatch, result):
    monkeypatch.setattr(git_module, "_git_version_cache", None)
    monkeypatch.setattr(git_module.subprocess, "run", lambda *a, **k: result)
    assert git_module.git_version() is None and not git_module.clone_git_supported()


@needs_git
def test_the_installed_git_banner_is_understood():
    # Catches a banner format the parser misses on the platform that runs the suite.
    assert git_module.git_version() is not None


# A checkout made without git-lfs (or a directory of offline clones) holds the
# pointer, not the file: read as content it looked like a complete scan.
@pytest.mark.parametrize("name", ["agent.py", "config/llm.yaml", "notebook.ipynb", "Dockerfile"])
def test_analyzable_lfs_pointer_is_a_coverage_gap_in_a_local_scan(tmp_path, index, name):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(LFS_POINTER)
    (tmp_path / "requirements.txt").write_text("langgraph\n")
    note = (
        f"code.filesystem: {name}: Git LFS pointer file, not the content it stands for; coverage incomplete"
    )
    for strict in (False, True):
        connector = FilesystemConnector(
            ConnectorContext(config={"path": str(tmp_path), "strict_coverage": strict}, index=index)
        )
        findings = connector.run()
        stats = connector.ctx.stats
        assert stats is not None and stats.incomplete and findings  # the neighbouring evidence stays
        assert (stats.errors, stats.warnings) == (([note], []) if strict else ([], [note]))


def test_lfs_pointer_of_a_file_the_scanner_never_reads_is_not_a_gap(tmp_path, index):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "model.bin").write_text(LFS_POINTER)
    (tmp_path / "requirements.txt").write_text("langgraph\n")
    connector = FilesystemConnector(ConnectorContext(config={"path": str(tmp_path)}, index=index))
    assert connector.run() and connector.ctx.stats is not None
    assert not connector.ctx.stats.incomplete and not connector.ctx.stats.warnings


@pytest.mark.parametrize("cls", PROVIDERS)
def test_offline_clone_with_an_lfs_pointer_is_incomplete(tmp_path, index, run_connector, cls):
    clone = tmp_path / "acme__app"
    clone.mkdir()
    (clone / "agent.py").write_text(LFS_POINTER)
    _, ctx = run_connector(cls.name, input=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("agent.py: Git LFS pointer file" in warning for warning in ctx.stats.warnings)
