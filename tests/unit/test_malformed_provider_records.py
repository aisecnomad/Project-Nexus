"""One malformed provider record costs itself, never the rest of the collection."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

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
