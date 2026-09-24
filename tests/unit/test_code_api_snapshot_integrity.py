"""API repository snapshots must retain the exact enumerated blob contents."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import ScanStats


def _sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def _connector(index, cls):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-09-24")
    return cls(ctx)


def test_github_uses_enumerated_blob_instead_of_moving_branch(tmp_path, index):
    original = b"from crewai import Agent\n"
    digest = _sha(original)
    connector = _connector(index, GitHubConnector)
    connector.http = Mock()

    def get(path, **kwargs):
        if "/git/trees/" in path:
            return {"tree": [{"path": "agent.py", "type": "blob", "mode": "100644", "size": len(original), "sha": digest}]}
        content = original if path.endswith("/git/blobs/" + digest) else b"# changed after enumeration\n"
        return {"encoding": "base64", "content": base64.b64encode(content).decode(), "sha": _sha(content)}

    connector.http.try_get_json.side_effect = get
    dest = connector._fetch_via_api({"full_name": "org/repo", "default_branch": "main"}, str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == original
    assert not connector.ctx.stats.incomplete


def test_gitlab_uses_enumerated_blob_instead_of_moving_branch(tmp_path, index):
    original = b"from crewai import Agent\n"
    digest = _sha(original)
    connector = _connector(index, GitLabConnector)
    connector.http = Mock()
    connector.http.paginate_link.return_value = [{"path": "agent.py", "type": "blob", "mode": "100644", "id": digest}]
    connector.http.get.side_effect = lambda path, **kwargs: original if path.endswith("/repository/blobs/" + digest + "/raw") else b"# changed after enumeration\n"
    connector.http.read_response_bytes.side_effect = lambda response, **kwargs: response
    dest = connector._fetch_via_api({"id": 1, "default_branch": "main"}, str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == original
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("cls", [GitHubConnector, GitLabConnector])
@pytest.mark.parametrize("kind,mode", [("blob", "120000"), ("commit", "160000")])
def test_api_links_are_not_scanned_as_regular_source(tmp_path, index, cls, kind, mode):
    connector = _connector(index, cls)
    connector.http = Mock()
    item = {"path": "agent.py", "type": kind, "mode": mode, "size": 0, "sha": _sha(b""), "id": _sha(b"")}
    connector.http.try_get_json.side_effect = [{"tree": [item]}, {"encoding": "base64", "content": ""}]
    connector.http.paginate_link.return_value = [item]
    connector.http.read_response_bytes.return_value = b""
    dest = connector._fetch_via_api({"full_name": "org/repo", "id": 1}, str(tmp_path))
    assert not (Path(dest) / "agent.py").exists()
    assert connector.ctx.stats.incomplete
    connector.http.get.assert_not_called()
    if cls is GitHubConnector:
        assert connector.http.try_get_json.call_count == 1


@pytest.mark.parametrize("encoded", ["!!!", "aW1wb3J0\x00", None, 12])
def test_github_rejects_malformed_encoded_blobs(tmp_path, index, encoded):
    connector = _connector(index, GitHubConnector)
    connector.http = Mock()
    connector.http.try_get_json.side_effect = [
        {"tree": [{"path": "agent.py", "type": "blob", "size": 0, "sha": _sha(b"")}]},
        {"encoding": "base64", "content": encoded},
    ]
    dest = connector._fetch_via_api({"full_name": "org/repo"}, str(tmp_path))
    assert not (Path(dest) / "agent.py").exists()
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("content", [b"", b"from crewai import Agent\n"])
def test_github_valid_wrapped_and_empty_blobs_remain_supported(tmp_path, index, content):
    connector = _connector(index, GitHubConnector)
    connector.http = Mock()
    connector.http.try_get_json.side_effect = [
        {"tree": [{"path": "agent.py", "type": "blob", "size": len(content), "sha": _sha(content)}]},
        {"encoding": "base64", "content": base64.encodebytes(content).decode()},
    ]
    dest = connector._fetch_via_api({"full_name": "org/repo"}, str(tmp_path))
    assert (Path(dest) / "agent.py").read_bytes() == content
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("cls", [GitHubConnector, GitLabConnector])
@pytest.mark.parametrize("object_id", [None, "../../outside", "a" * 39, "f" * 65, 12])
def test_invalid_blob_identity_is_not_a_request_path_and_keeps_neighbors(tmp_path, index, cls, object_id):
    connector = _connector(index, cls)
    connector.http = Mock()
    content = b"from crewai import Agent\n"
    entries = [
        {"path": "bad.py", "type": "blob", "mode": "100644", "sha": object_id, "id": object_id},
        {"path": "good.py", "type": "blob", "mode": "100644", "sha": _sha(content), "id": _sha(content)},
    ]
    connector.http.try_get_json.side_effect = [
        {"tree": entries}, {"encoding": "base64", "content": base64.b64encode(content).decode()},
    ]
    connector.http.paginate_link.return_value = entries
    connector.http.read_response_bytes.return_value = content
    dest = connector._fetch_via_api({"full_name": "org/repo", "id": 1}, str(tmp_path))
    assert not (Path(dest) / "bad.py").exists()
    assert (Path(dest) / "good.py").read_bytes() == content
    assert connector.ctx.stats.incomplete
    if cls is GitHubConnector:
        assert connector.http.try_get_json.call_count == 2
        assert connector.http.try_get_json.call_args.args[0].endswith("/git/blobs/" + _sha(content))
    else:
        connector.http.get.assert_called_once_with("/projects/1/repository/blobs/" + _sha(content) + "/raw", stream=True)


def test_bad_encoded_blob_does_not_discard_valid_neighbor(tmp_path, index):
    connector = _connector(index, GitHubConnector)
    connector.http = Mock()
    content = b"from crewai import Agent\n"
    connector.http.try_get_json.side_effect = [
        {"tree": [
            {"path": "bad.py", "type": "blob", "sha": _sha(b"")},
            {"path": "good.py", "type": "blob", "sha": _sha(content)},
        ]},
        {"encoding": "base64", "content": 12},
        {"encoding": "base64", "content": base64.b64encode(content).decode()},
    ]
    dest = connector._fetch_via_api({"full_name": "org/repo"}, str(tmp_path))
    assert not (Path(dest) / "bad.py").exists()
    assert (Path(dest) / "good.py").read_bytes() == content
    assert connector.ctx.stats.incomplete
