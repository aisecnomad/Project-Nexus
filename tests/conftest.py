from __future__ import annotations

import errno
import functools
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import shadowscan.engine as engine_module
import shadowscan.signatures.matcher as matcher
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.models import Finding, Kind, Surface
from shadowscan.signatures import SignatureIndex, get_index, schema
from shadowscan.signatures.loader import signature_source_digest
from shadowscan.utils import http

FIXTURES = Path(__file__).parent / "fixtures"

# Offline git enrichment passes ``--no-lazy-fetch``, which older Git rejects
# (fail closed). Tests that run real git enrichment need this host version.
GIT_ENRICHMENT_MIN_VERSION = (2, 45)

# Names that tests do not resolve themselves map to one fixed public address
# (see hermetic_dns). It must pass the scanner's own destination policy:
# documentation ranges such as TEST-NET count as private there.
STUB_PUBLIC_ADDRESSES = {socket.AF_INET: "8.8.8.8", socket.AF_INET6: "2001:4860:4860::8888"}
for _address in STUB_PUBLIC_ADDRESSES.values():
    assert not http._blocked_ip(ipaddress.ip_address(_address)), _address
# Top-level domains that no resolver answers (RFC 2606 and RFC 6761).
UNRESOLVABLE_TLDS = frozenset({"example", "invalid", "test"})

# Signature matching runs under wall-clock and CPU budgets (100 ms per regex
# operation, two seconds per input). On a loaded CI runner a budget can expire
# and silently drop matches from a test that is not about budgets, so ordinary
# tests run with these generous values. Tests that exercise the budgets are
# marked ``production_budgets`` and keep the shipped values.
PRODUCTION_REGEX_TIMEOUT_SECONDS = matcher.REGEX_TIMEOUT_SECONDS
PRODUCTION_SCAN_BUDGET_SECONDS = matcher.DEFAULT_SCAN_BUDGET_SECONDS
TEST_REGEX_TIMEOUT_SECONDS = 5.0
TEST_SCAN_BUDGET_SECONDS = 30.0
# pattern_timeout() and SignatureIndex.scan_budget() bind these constants as
# default arguments when the module loads; their defaults are raised as well.
_BUDGET_DEFAULTS: tuple[tuple[Callable[..., Any], float, float], ...] = (
    (matcher.pattern_timeout, PRODUCTION_REGEX_TIMEOUT_SECONDS, TEST_REGEX_TIMEOUT_SECONDS),
    (
        matcher.SignatureIndex.scan_budget.__wrapped__,
        PRODUCTION_SCAN_BUDGET_SECONDS,
        TEST_SCAN_BUDGET_SECONDS,
    ),
)
for _function, _production, _ in _BUDGET_DEFAULTS:
    # Fail loudly if the matcher stops binding the constant this way, rather
    # than leaving ordinary tests on the tight production budgets.
    assert _function.__defaults__ == (_production,), _function


@functools.lru_cache(maxsize=1)
def host_git_version() -> tuple[int, int] | None:
    """Return the host ``git`` version as ``(major, minor)``, or None without a usable git.

    The result is parsed from ``git --version`` once per process. Any failure to
    locate or run git reports None so callers can skip rather than error.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        completed = subprocess.run(
            [git, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\bgit version (\d+)\.(\d+)", completed.stdout)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


# Applied by pytest_collection_modifyitems to every test marked
# ``@pytest.mark.requires_git_2_45``; the condition is fixed per host.
requires_git_2_45 = pytest.mark.skipif(
    (host_git_version() or (0, 0)) < GIT_ENRICHMENT_MIN_VERSION,
    reason="tool requires Git >= 2.45 for lazy-fetch suppression",
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_git_2_45: the test runs real git enrichment, which needs Git >= 2.45 on the host",
    )
    config.addinivalue_line(
        "markers",
        "production_budgets: the test exercises signature-matching budgets and keeps their shipped values",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if item.get_closest_marker("requires_git_2_45") is not None:
            item.add_marker(requires_git_2_45)


# --- Network isolation ---------------------------------------------------------


def _is_numeric_or_local(host: str) -> bool:
    """True for addresses the C resolver parses without DNS, and for localhost."""
    candidate = host.strip("[]").split("%", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    try:
        socket.inet_aton(candidate)  # also the short forms such as 127.1
        return True
    except OSError:
        pass
    name = host.rstrip(".").lower()
    return name == "localhost" or name.endswith(".localhost")


def _port_number(port: Any) -> int:
    if isinstance(port, int):
        return port
    if isinstance(port, bytes):
        port = port.decode("ascii")
    if not port:
        return 0
    return int(port) if port.isdigit() else socket.getservbyname(port)


@pytest.fixture(autouse=True)
def hermetic_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve hostnames to a fixed public address instead of asking the host's DNS.

    HttpClient and validate_url resolve every API hostname and refuse private,
    loopback, link-local, reserved and metadata answers. With the host resolver,
    a test naming api.github.com passes without DNS but fails behind a sinkhole
    (0.0.0.0) or split-horizon resolver. Names under the reserved example,
    invalid and test domains fail as on any real resolver. IP literals and
    localhost still use the real resolver, which answers them without DNS. A
    test that patches socket.getaddrinfo itself replaces this stub for its own
    duration.
    """
    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(
        host: Any, port: Any, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
    ) -> list[tuple[Any, ...]]:
        name = host.decode("idna") if isinstance(host, bytes) else host
        if name is None or flags & socket.AI_NUMERICHOST or _is_numeric_or_local(name):
            return real_getaddrinfo(host, port, family, type, proto, flags)
        if name.rstrip(".").rsplit(".", 1)[-1].lower() in UNRESOLVABLE_TLDS:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        family = socket.AF_INET6 if family == socket.AF_INET6 else socket.AF_INET
        address = STUB_PUBLIC_ADDRESSES[family]
        sockaddr = (address, _port_number(port)) + ((0, 0) if family == socket.AF_INET6 else ())
        if type == socket.SOCK_DGRAM:
            return [(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", sockaddr)]
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def _outbound_destination(address: Any) -> str | None:
    """Describe an IP destination that is neither loopback nor unspecified, else None."""
    if not isinstance(address, tuple) or len(address) < 2 or not isinstance(address[0], str):
        return None  # Unix sockets and other non-IP families stay local.
    host = address[0]
    if host.rstrip(".").lower() == "localhost":
        return None
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return f"{host}:{address[1]}"  # resolved inside the C library, so never local here
    mapped = getattr(ip, "ipv4_mapped", None) or ip
    if mapped.is_loopback or mapped.is_unspecified:
        return None
    return f"{host}:{address[1]}"


@pytest.fixture(autouse=True)
def blocked_connections(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Refuse and report any socket connection that would leave the host.

    Every test is offline: connector tests use fixtures and stubbed transports,
    and local servers listen on loopback. A connection to any other address
    fails with ENETUNREACH, and the test fails at teardown even when the code
    under test handled that error. A test that provokes one on purpose can
    request this fixture and clear the list after checking it.
    """
    attempts: list[str] = []

    def guard(original: Callable[..., Any]) -> Callable[..., Any]:
        def connect(sock: socket.socket, address: Any) -> Any:
            destination = _outbound_destination(address)
            if destination is not None:
                attempts.append(destination)
                raise OSError(errno.ENETUNREACH, f"tests may not connect to {destination}")
            return original(sock, address)

        return connect

    monkeypatch.setattr(socket.socket, "connect", guard(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guard(socket.socket.connect_ex))
    yield attempts
    if attempts:
        pytest.fail(f"test attempted outbound connections: {sorted(set(attempts))}", pytrace=False)


@pytest.fixture(autouse=True)
def generous_signature_budgets(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Raise signature-matching budgets unless the test is marked ``production_budgets``."""
    if request.node.get_closest_marker("production_budgets") is not None:
        return
    monkeypatch.setattr(matcher, "REGEX_TIMEOUT_SECONDS", TEST_REGEX_TIMEOUT_SECONDS)
    # The schema's empty-match check uses the matcher's timeout; keep them equal.
    monkeypatch.setattr(schema, "EMPTY_MATCH_TIMEOUT_SECONDS", TEST_REGEX_TIMEOUT_SECONDS)
    monkeypatch.setattr(matcher, "DEFAULT_SCAN_BUDGET_SECONDS", TEST_SCAN_BUDGET_SECONDS)
    for function, _, generous in _BUDGET_DEFAULTS:
        monkeypatch.setattr(function, "__defaults__", (generous,))


# --- Shared fixtures -------------------------------------------------------------


@pytest.fixture
def make_finding():
    """A Finding factory with the common code-connector defaults; tests override per call."""

    def _make(**overrides: Any) -> Finding:
        fields: dict[str, Any] = {
            "surface": Surface.CODE,
            "connector": "code.filesystem",
            "kind": Kind.AGENT,
            "title": "Agent",
            "resource": "repository",
            "resource_type": "project",
        }
        fields.update(overrides)
        return Finding(**fields)

    return _make


@pytest.fixture(scope="session")
def builtin_signature_index() -> tuple[str, SignatureIndex]:
    """The built-in packs' source digest and index, loaded before any test patches the loader."""
    return signature_source_digest(), engine_module.get_index(reload=True)


@pytest.fixture(autouse=True)
def reuse_builtin_signature_index(
    monkeypatch: pytest.MonkeyPatch, builtin_signature_index: tuple[str, SignatureIndex]
) -> None:
    """Parse the built-in signature packs once per session instead of once per Engine.

    Engine reloads the packs whenever it is constructed without an index: about
    one second of YAML parsing, three under coverage, for each of the hundreds
    of tests and CLI invocations that build one. The loader's own source digest
    covers every pack file's content and the override approval; while it is
    unchanged, Engine gets the index loaded at session start. Organization pack
    directories and override approval always load for real, and a test that
    patches engine.get_index replaces this.
    """
    digest, builtin = builtin_signature_index
    real_get_index = engine_module.get_index

    def get_index(
        extra_dirs: list[str] | None = None, reload: bool = False, *, allow_override: bool = False
    ) -> SignatureIndex:
        if not extra_dirs and not allow_override:
            try:
                unchanged = signature_source_digest() == digest
            except (OSError, ValueError):
                unchanged = False  # the real load below reports the problem
            if unchanged:
                return builtin
        return real_get_index(extra_dirs=extra_dirs, reload=reload, allow_override=allow_override)

    monkeypatch.setattr(engine_module, "get_index", get_index)


@pytest.fixture(scope="session")
def index():
    return get_index()


@pytest.fixture(scope="session")
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def run_connector(index):
    """Run a connector by name with a config dict and return its findings + context."""

    def _run(name: str, **config):
        cls = get_connector_class(name)
        ctx = ConnectorContext(config=config, index=index)
        connector = cls(ctx)
        findings = connector.run()
        return findings, ctx

    return _run


def _canonical(value):
    """An order-independent form of a report value: dicts by key, lists as sorted multisets."""
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((_canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def _materialize(source: Path, destination: Path, depth: int = 0) -> None:
    """Copy a tree as `cp -rL` does: each link holds its target's content; a dangling link is left out.

    ``shutil.copytree(ignore_dangling_symlinks=True)`` judges a relative link
    from the working directory, not from the link's own, so it is not used.
    """
    assert depth < 40, "a link cycle cannot be materialized"
    destination.mkdir()
    for entry in sorted(os.scandir(source), key=lambda item: item.name):
        path = Path(entry.path)
        if entry.is_symlink() and not os.path.exists(path):
            continue  # dangling: nothing to copy
        if path.is_dir():
            _materialize(path, destination / entry.name, depth + 1)
        else:
            shutil.copyfile(path, destination / entry.name)


@pytest.fixture
def same_as_copy(run_connector):
    """Scan a tree with symbolic links and a copy with the links materialized; both must agree.

    A link inside the scan root is analyzed as a copy of its target would be at
    the link's path. The scan with links must be complete and report what the
    materialized copy reports, apart from the scan root's name.
    """

    def _check(root: Path, *, complete: bool = True, **config):
        findings, ctx = run_connector("code.filesystem", path=str(root), use_git=False, **config)
        copy = root.parent / f"{root.name}-materialized"
        _materialize(root, copy)
        copied, copy_ctx = run_connector("code.filesystem", path=str(copy), use_git=False, **config)
        # ``complete=False``: a limit stops both scans alike (max_files), with the same findings.
        assert copy_ctx.stats.incomplete is not complete, (copy_ctx.stats.warnings, copy_ctx.stats.errors)
        assert ctx.stats.incomplete is not complete, (ctx.stats.warnings, ctx.stats.errors)

        def normalized(found, scanned: Path) -> list[str]:
            out = []
            for finding in found:
                data = finding.to_dict()
                data.pop("id", None)
                out.append(
                    json.dumps(_canonical(data), sort_keys=True, default=str).replace(str(scanned), "<root>")
                )
            return sorted(out)

        assert normalized(findings, root) == normalized(copied, copy)
        return findings, ctx

    return _check
