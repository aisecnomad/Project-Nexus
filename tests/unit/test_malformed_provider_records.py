"""One malformed provider record costs itself, never the rest of the collection."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
import responses as responses_lib

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import _EcsInventory
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector, _GitLabMetadata
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def connector(index, cls, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-09-26")
    instance = cls(ctx)
    instance.http = Mock()
    return instance


def test_github_listing_skips_malformed_repositories_once(index):
    github = connector(index, GitHubConnector, org="acme", repos=["acme/direct"])
    github.http.try_get_json.return_value = {"name": "no-full-name"}
    github.http.paginate_link.return_value = iter([{"full_name": "acme/a"}, ["not", "a", "record"], {"id": 3}, {"full_name": "acme/b"}])
    names = [record["full_name"] for record in github.collect()]
    assert names == ["acme/a", "acme/b"]
    warnings = github.ctx.stats.warnings
    assert sum("malformed repository record in listing" in w for w in warnings) == 1
    assert any("malformed repository record for acme/direct" in w for w in warnings)
    assert github.ctx.stats.incomplete


def test_gitlab_listing_skips_projects_without_integer_ids(index):
    gitlab = connector(index, GitLabConnector, group="acme", projects=["acme/direct"])
    gitlab.http.try_get_json.return_value = {"id": "7"}
    listings = {"/groups/acme/projects": [{"id": 1, "path_with_namespace": "acme/a"}, {"id": [2]}, "junk", {"id": 3, "path_with_namespace": "acme/b"}]}
    gitlab.http.paginate_link.side_effect = lambda path, params=None: iter(listings.get(path, [None, {"name": "sa"}]))
    records = list(gitlab.collect())
    assert [r.get("id") for r in records if r.get("_kind") is None] == [1, 3]
    warnings = gitlab.ctx.stats.warnings
    assert sum("malformed project record skipped" in w for w in warnings) == 2  # the direct project and the listing
    assert any("malformed metadata record" in w for w in warnings)


def test_gitlab_reports_group_variables_already_seen_when_collection_fails(index):
    gitlab = connector(index, GitLabConnector, group="acme")
    variables = [{"key": "OPENAI_API_KEY", "masked": False, "protected": False, "variable_type": "env_var"}]

    def stream():
        yield _GitLabMetadata("group_variables", {"group": "acme", "variables": variables})
        raise HttpError(403, "https://gitlab.example/api/v4/groups/acme/projects")

    findings = []
    with pytest.raises(HttpError):
        for finding in gitlab.analyze(stream()):
            findings.append(finding)
    assert findings and "OPENAI_API_KEY" in json.dumps(findings[0].to_dict())


def test_gitlab_warns_once_per_repository_for_a_broken_tree(index, tmp_path):
    gitlab = connector(index, GitLabConnector, group="acme", mode="api")
    gitlab.http.try_get_json.return_value = {"id": "a" * 40}
    gitlab.http.paginate_link.return_value = iter([None] * 50 + [{"path": 3}] * 50)
    gitlab._fetch_via_api({"id": 1, "path_with_namespace": "acme/a", "default_branch": "main"}, str(tmp_path))
    assert sum("malformed tree entry" in w for w in gitlab.ctx.stats.warnings) == 1


def test_ecs_definitions_with_malformed_containers_keep_the_valid_parts(index):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-09-26")
    inventory = _EcsInventory.__new__(_EcsInventory)
    inventory.ctx, inventory.region = ctx, "us-east-1"
    record = inventory.definition_record({
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:1:task-definition/app:1",
        "containerDefinitions": [
            "junk",
            {"name": "app", "image": "img", "environment": [{"name": "OPENAI_API_KEY", "value": "x"}, {"value": "no-name"}, "junk"],
             "secrets": [{"name": "TOKEN"}, 5]},
            {"name": "sidecar", "environment": {"not": "a list"}},
        ],
    })
    assert [c["name"] for c in record["containers"]] == ["app", "sidecar"]
    assert record["containers"][0]["environment"] == {"OPENAI_API_KEY": "x"}
    assert record["containers"][0]["secrets"] == ["TOKEN"]
    assert any("invalid ECS container definition" in w for w in ctx.stats.warnings)


def test_cloudtrail_event_detail_that_is_not_an_object_skips_only_that_detail(index, monkeypatch):
    from shadowscan.connectors.cloud.aws import AwsConnector

    ctx = ConnectorContext(config={"input": "unused"}, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-09-26")
    aws = AwsConnector(ctx)
    events = [{"EventName": "InvokeModel", "CloudTrailEvent": "[1, 2]"},
              {"EventName": "InvokeModel", "CloudTrailEvent": json.dumps({"userIdentity": "not-an-object"})},
              {"EventName": "InvokeModel", "CloudTrailEvent": 7},
              {"EventName": "InvokeModel", "CloudTrailEvent": json.dumps({"userIdentity": {"arn": "arn:aws:iam::1:role/r"}})}]
    monkeypatch.setattr(aws, "_client", lambda *args: object())
    monkeypatch.setattr(aws, "_paginate", lambda *args, **kwargs: iter(events))
    monkeypatch.setattr("shadowscan.connectors.cloud.aws.CLOUDTRAIL_EVENTS", ["InvokeModel"])
    records = list(aws._collect_cloudtrail("us-east-1"))
    assert [r["principal"] for r in records] == [None, None, None, "arn:aws:iam::1:role/r"]
    assert any("invalid CloudTrail event detail" in w for w in ctx.stats.warnings)


def test_gcp_audit_page_that_is_not_json_warns_for_that_project(index):
    from shadowscan.connectors.cloud.gcp import GcpConnector

    ctx = ConnectorContext(config={"input": "unused"}, index=index)
    ctx.stats = ScanStats(connector="cloud.gcp", started_at="2026-09-26")
    gcp = GcpConnector(ctx)
    gcp.http = Mock()
    gcp.http.post_json.side_effect = ValueError("Invalid JSON response")
    assert list(gcp._collect_audit("proj-1")) == []
    assert any("audit logs not readable for proj-1 (ValueError)" in w for w in ctx.stats.warnings)


def test_an_explicit_empty_signature_index_is_honored(index):
    from shadowscan.signatures import SignatureIndex

    empty = SignatureIndex([])
    assert ConnectorContext(index=empty).index is empty
    assert len(ConnectorContext(index=None).index) > 0


def test_a_worker_failure_cancels_its_siblings(monkeypatch, tmp_path):
    import threading
    import time

    from shadowscan.config import ConnectorSpec, ScanConfig
    from shadowscan.engine import Engine
    from shadowscan.signatures import SignatureIndex

    started = threading.Event()
    seen_cancel = {}

    def run_job(self, scan, number, spec):
        if number == 1:  # config ordinals start at 1
            started.wait(5)
            raise RuntimeError("worker failed outside connector isolation")
        started.set()
        deadline = time.monotonic() + 5
        while not scan.states[number].cancelled.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        seen_cancel[number] = scan.states[number].cancelled.is_set()
        raise AssertionError("unreachable result")

    monkeypatch.setattr(Engine, "_run_job", run_job)
    specs = [ConnectorSpec(name="code.filesystem", config={"path": str(tmp_path)}, label=f"j{i}") for i in range(2)]
    with pytest.raises(RuntimeError, match="outside connector isolation"):
        Engine(ScanConfig(connectors=specs, parallel=2), SignatureIndex([])).run()
    deadline = time.monotonic() + 5
    while 2 not in seen_cancel and time.monotonic() < deadline:
        time.sleep(0.01)
    assert seen_cancel.get(2) is True


def test_plugin_subclass_of_a_hosted_connector_keeps_provider_diagnostics_and_ids(index, tmp_path):
    class GitHubEnterprise(GitHubConnector):
        name = "code.ghe"
        provider = "ghe"

    for repo in ("one", "two"):
        (tmp_path / repo).mkdir()
        (tmp_path / repo / "agent.py").write_text("from crewai import Agent\nagent = Agent(role='r', goal='g', backstory='b')\n")
    ghe = connector(index, GitHubEnterprise, max_repos=1)
    findings = list(ghe.analyze(ghe.load_offline(str(tmp_path))))
    assert any(w.startswith("code.github: max_repos (1) reached") for w in ghe.ctx.stats.warnings)
    assert findings and {f.provider for f in findings} == {"github"} and {f.connector for f in findings} == {"code.ghe"}


GITLAB_API = "https://gitlab.example.com/api/v4"


def _gitlab_group(responses_module, **overrides):
    endpoints = {
        "/groups/acme/service_accounts": {"json": []},
        "/groups/acme/access_tokens": {"json": []},
        "/groups/acme/variables": {"json": [{"key": "OPENAI_API_KEY", "masked": False, "protected": False}]},
        "/groups/acme": {"json": {"full_path": "acme"}},
        "/groups/acme/projects": {"json": []},
        **overrides,
    }
    for path, kwargs in endpoints.items():
        responses_module.get(GITLAB_API + path, **kwargs)


@responses_lib.activate
def test_real_client_malformed_metadata_page_keeps_the_rest_of_the_group(run_connector):
    _gitlab_group(responses_lib, **{"/groups/acme/service_accounts": {"json": [None, {"id": 5, "name": "sa-bot"}]}})
    findings, ctx = run_connector("code.gitlab", group="acme", api_url=GITLAB_API, mode="api", token="glpat-test")
    assert not ctx.stats.errors
    assert any("metadata listing failed for /groups/acme/service_accounts" in w for w in ctx.stats.warnings)
    assert any("OPENAI_API_KEY" in json.dumps(f.to_dict()) for f in findings)


@responses_lib.activate
def test_real_client_variables_read_before_an_invalid_page_are_still_reported(run_connector):
    responses_lib.get(GITLAB_API + "/groups/acme/variables?per_page=100&page=2", body="not json{")
    _gitlab_group(responses_lib, **{"/groups/acme/variables": {
        "json": [{"key": "OPENAI_API_KEY", "masked": False, "protected": False}],
        "headers": {"Link": f'<{GITLAB_API}/groups/acme/variables?per_page=100&page=2>; rel="next"'},
    }})
    findings, ctx = run_connector("code.gitlab", group="acme", api_url=GITLAB_API, mode="api", token="glpat-test")
    assert any("OPENAI_API_KEY" in json.dumps(f.to_dict()) for f in findings)
    assert ctx.stats.incomplete and not ctx.stats.errors


@responses_lib.activate
def test_real_client_invalid_repository_listing_page_keeps_earlier_repositories(run_connector, tmp_path):
    api = "https://github.example.com/api/v3"
    responses_lib.get(api + "/orgs/acme/repos?per_page=100&type=all&sort=pushed", json=[], headers={
        "Link": f'<{api}/orgs/acme/repos?per_page=100&type=all&sort=pushed&page=2>; rel="next"'})
    responses_lib.get(api + "/orgs/acme/repos?per_page=100&type=all&sort=pushed&page=2", json=[None])
    github = GitHubConnector(ConnectorContext(config={"org": "acme", "api_url": api, "token": "ghp_test_token_value_0123"}))
    github.ctx.stats = ScanStats(connector="code.github", started_at="2026-09-26")
    assert list(github.collect()) == []
    assert any("organization repository listing stopped at an invalid page" in w for w in github.ctx.stats.warnings)


def test_cloudtrail_request_parameters_that_are_not_an_object_are_dropped(index, monkeypatch):
    from shadowscan.connectors.cloud.aws import AwsConnector

    ctx = ConnectorContext(config={"input": "unused"}, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-09-26")
    aws = AwsConnector(ctx)
    events = ["junk", {"EventName": "InvokeModel", "CloudTrailEvent": json.dumps({"requestParameters": "modelId=x"})},
              {"EventName": "InvokeModel", "CloudTrailEvent": json.dumps({"requestParameters": {"modelId": "anthropic.claude"}})}]
    monkeypatch.setattr(aws, "_client", lambda *args: object())
    monkeypatch.setattr(aws, "_paginate", lambda *args, **kwargs: iter(events))
    monkeypatch.setattr("shadowscan.connectors.cloud.aws.CLOUDTRAIL_EVENTS", ["InvokeModel"])
    assert [r["modelId"] for r in aws._collect_cloudtrail("us-east-1")] == [None, "anthropic.claude"]
    assert any("invalid CloudTrail request parameters" in w for w in ctx.stats.warnings)
    assert any(w.endswith("invalid CloudTrail event") for w in ctx.stats.warnings)


def test_ecs_task_sets_that_are_not_a_list_are_reported(index):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-09-26")
    inventory = _EcsInventory.__new__(_EcsInventory)
    inventory.ctx, inventory.region = ctx, "us-east-1"
    added = []
    inventory.identifiers = lambda *args, **kwargs: iter(["arn:svc"])
    inventory.described = lambda *args: iter([{"serviceArn": "arn:svc", "status": "ACTIVE",
                                               "taskSets": {"taskDefinition": "arn:aws:ecs:us-east-1:1:task-definition/blue:3"}}])
    inventory.add_definition = lambda identifier, source, reference=None: added.append(identifier)
    inventory.reference_services("cluster")
    assert ctx.stats.incomplete
    assert any("invalid ECS service deployment" in w for w in ctx.stats.warnings)


def test_multi_root_scan_states_an_unused_cache_once(tmp_path):
    from shadowscan.config import ConnectorSpec, ScanConfig
    from shadowscan.engine import Engine

    roots = []
    for name in ("a", "b", "c"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "app.py").write_text("x = 1\n")
        roots.append(str(tmp_path / name))
    cfg = ScanConfig(connectors=[ConnectorSpec(name="code.filesystem", config={"paths": roots, "use_git": False})],
                     incremental=True, dump_records=str(tmp_path / "dumps"), state_dir=str(tmp_path / "state"))
    [stats] = Engine(cfg).run().stats
    assert sum(w.startswith("incremental: record dumps") for w in stats.warnings) == 1
