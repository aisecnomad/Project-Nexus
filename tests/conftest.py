from __future__ import annotations

import errno
import functools
import ipaddress
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import shadowscan.engine as engine_module
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.signatures import SignatureIndex, get_index
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


# --- Shared fixtures -------------------------------------------------------------


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
