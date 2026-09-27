"""Shared clone, API snapshot and offline plumbing of the GitHub and GitLab connectors."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code import remote
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
@pytest.mark.parametrize("method", [
    "load_offline", "_analyze_repository", "_scan_local", "_fetch", "_clone", "_set_clone_snapshot",
    "_api_ref", "_write_api_snapshot",
])
def test_providers_run_one_shared_implementation(method):
    shared = getattr(RemoteRepositoryConnector, method)
    assert getattr(GitHubConnector, method) is shared
    assert getattr(GitLabConnector, method) is shared


def test_github_fetch_repo_is_the_shared_fetch():
    assert GitHubConnector._fetch_repo is RemoteRepositoryConnector._fetch


def test_api_selection_keeps_high_signal_files_before_shallow_sources():
    paths = [
        "src/pkg/sub/deep/agent.py", "README.md", "app.py", "pkg/mod.ts", "docs/notes.txt",
        ".github/workflows/ci.yml", "sub/CLAUDE.md", "infra/main.tf", "requirements.txt",
        "tools/.cursor/rules.mdc",
    ]
    assert select_api_paths(paths) == [
        ".github/workflows/ci.yml", "sub/CLAUDE.md", "infra/main.tf", "requirements.txt",
        "tools/.cursor/rules.mdc", "app.py", "pkg/mod.ts",
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
        owner={"login": "acme"}, namespace={"full_path": "acme"}, private=True,
        pushed_at="2026-09-01T00:00:00Z", created_at="2026-01-01T00:00:00Z",
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
        clone_url="https://github.com/acme/app.git", http_url_to_repo="https://gitlab.com/acme/app.git",
    )
    assert not _connector(index, cls)._clone(record, str(tmp_path / "repo"))


def test_github_enterprise_clone_stays_on_the_api_origin(tmp_path, index, monkeypatch):
    run = Mock(return_value=True)
    monkeypatch.setattr(remote, "run_bounded_clone", run)
    connector = _connector(
        index, GitHubConnector, api_url="https://ghe.example.com/api/v3", token="synthetic",
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
    tree = {"sha": COMMIT, "tree": [
        "not-an-entry",
        {"path": "agent.py", "type": "blob", "sha": _sha(good), "size": len(good)},
        {"path": "big.py", "type": "blob", "sha": _sha(b"big"), "size": -1},
    ]}
    blobs = {_sha(good): {"encoding": "base64", "content": base64.b64encode(good).decode()}}
    connector = _github_api(index, tree, blobs)
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == good
    assert not (Path(dest) / "big.py").exists()
    warnings = connector.ctx.stats.warnings
    assert "code.github: malformed tree entries in acme/app; source coverage partial" in warnings
    assert "code.github: invalid blob size metadata in acme/app; source coverage partial" in warnings


@pytest.mark.parametrize("blob,warning", [
    (None, "code.github: cannot read content in acme/app"),
    ({"encoding": "utf-8", "content": "x"}, "code.github: cannot read content in acme/app"),
    (
        {"encoding": "base64", "content": base64.b64encode(b"x" * (API_MAX_BLOB_BYTES + 1)).decode()},
        "code.github: oversized API content in acme/app",
    ),
])
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
        "/repos/acme/app/actions/secrets", "/repos/acme/app/actions/variables",
        "/repos/acme/app/codespaces/secrets", "/repos/acme/app/dependabot/secrets",
    ]
    assert [call.kwargs["item_key"] for call in connector.http.paginate_link.call_args_list] == [
        "secrets", "variables", "secrets", "secrets",
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
    connector = _gitlab_api(index, [
        {"type": "blob"},
        {"path": "agent.py", "type": "blob", "id": _sha(good)},
        {"path": "notes.txt", "type": "blob", "id": _sha(b"notes")},
        {"path": "src", "type": "tree", "id": COMMIT},
    ], good)
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == good
    assert not (Path(dest) / "notes.txt").exists()
    assert connector.ctx.stats.warnings == [
        "code.gitlab: malformed tree entry; source coverage partial",
        "code.gitlab: API mode samples repository; source coverage partial",
    ]


@pytest.mark.parametrize("failure,warning", [
    (
        HttpError(404, "https://gitlab.com/api/v4/projects/7"),
        "code.gitlab: repository content HTTP 404; coverage partial",
    ),
    (ValueError("oversized"), "code.gitlab: oversized or invalid API content skipped"),
])
def test_gitlab_blob_download_failure_keeps_neighbours(tmp_path, index, failure, warning):
    good = b"from crewai import Agent\n"
    connector = _gitlab_api(index, [
        {"path": "bad.py", "type": "blob", "id": _sha(b"bad")},
        {"path": "good.py", "type": "blob", "id": _sha(good)},
    ])
    connector.http.read_response_bytes.side_effect = [failure, good]
    dest = connector._fetch_via_api(_record(), str(tmp_path))
    assert not (Path(dest) / "bad.py").exists()
    assert (Path(dest) / "good.py").read_bytes() == good
    assert connector.ctx.stats.warnings == [warning]


def test_gitlab_unusual_tree_path_costs_only_that_file(tmp_path, index):
    good = b"from crewai import Agent\n"
    connector = _gitlab_api(index, [
        {"path": "C:/agent.py", "type": "blob", "id": _sha(good)},
        {"path": "agent.py", "type": "blob", "id": _sha(good)},
    ], good)
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
            {"id": 4, "username": "project_7_bot_1a2b"}, {"id": 5, "username": "alice"},
            {"id": 6, "username": "helper", "bot": True},
        ],
    }
    connector.http = Mock()
    connector.http.paginate_link.side_effect = lambda path, **_: listings[path]
    findings = list(connector._project_level({"id": 7, "path_with_namespace": "acme/app"}))
    assert [f.resource_type for f in findings] == [
        "ci-variables", "project_access_token", "project_bot", "project_bot",
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
        index, GitHubConnector, repos=["acme/one", "acme/one", "acme/gone"], user="octo", max_repos=3,
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
        {"full_name": "octo/a", "topics": ["ai"]}, {"full_name": "octo/b"},
        {"full_name": "octo/c", "topics": ["ai"]},
    ]
    assert [record["full_name"] for record in capped.collect()] == ["octo/a"]
    assert capped.ctx.stats.warnings == ["code.github: max_repos (1) reached"]


def test_gitlab_collect_deduplicates_and_caps_group_listing(index):
    connector = _connector(
        index, GitLabConnector, projects=["acme/one", "acme/one"], group="acme", max_projects=2,
    )
    connector.http = Mock()
    connector.http.try_get_json.side_effect = [{"id": 1, "path_with_namespace": "acme/one"}, {}]
    listings = {"/groups/acme/projects": [
        {"id": 1, "path_with_namespace": "acme/one"}, {"id": 2, "path_with_namespace": "acme/two"},
        {"id": 3, "path_with_namespace": "acme/three"},
    ]}
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
        "full_path": "acme", "duo_features_enabled": True, "lock_duo_features_enabled": False,
    }
    records = list(connector._group_identities("acme"))
    assert [record.kind for record in records] == ["duo"]
    disabled = _GitLabMetadata("duo", {"group": "other", "duo_features_enabled": False})
    findings = list(connector.analyze([*records, disabled]))
    assert [f.resource for f in findings] == ["gitlab:acme/duo"]
    assert findings[0].kind is Kind.AGENT_CONFIG and "code-exec" in findings[0].capabilities
