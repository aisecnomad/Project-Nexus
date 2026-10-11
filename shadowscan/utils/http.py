"""Small HTTP helper with retries, rate-limit handling and pagination helpers.

Kept deliberately thin so connectors read like the API docs they implement.
"""

from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import json
import logging
import math
import os
import random
import re
import socket
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ChunkedEncodingError,
    ConnectionError,
    ConnectTimeout,
    ContentDecodingError,
    InvalidHeader,
    ReadTimeout,
    RequestException,
    SSLError,
    Timeout,
)
from requests.utils import check_header_validity
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError

from shadowscan import __version__
from shadowscan.utils.redaction import sanitize_text

log = logging.getLogger("shadowscan.http")

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
# A per-read socket timeout does not bound a response body: a server can send one
# byte just inside every timeout. Each body must also finish within this multiple
# of the client timeout (60 seconds by default).
READ_DEADLINE_FACTOR = 2
MAX_RETRY_DELAY = 120
RETRY_STATUSES = {429, 500, 502, 503, 504}
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")

_allow_private_origin: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "shadowscan_allow_private_origin", default=False
)
_ca_bundle: contextvars.ContextVar[str | None] = contextvars.ContextVar("shadowscan_ca_bundle", default=None)
# (monotonic deadline, cancellation event) of the connector the current worker runs.
_request_limits: contextvars.ContextVar[tuple[float | None, threading.Event | None]] = contextvars.ContextVar(
    "shadowscan_request_limits", default=(None, None)
)
_acquisition_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "shadowscan_http_acquisition_deadline", default=None
)


class _SocketDeadline:
    """Interrupt acquisition while this pool checkout still owns its socket.

    The timer never closes a descriptor or touches a returned pool connection.
    ``finish`` cancels and joins it before ``_make_request`` returns, so an
    expiring request cannot shut down a socket reused by another request.
    DNS runs in the caller: it cannot be killed safely, but a late resolution
    cannot proceed to a connection. TLS uses the remaining socket timeout.
    """

    def __init__(self, connection: Any, deadline: float):
        self.connection = connection
        self.deadline = deadline
        self.socket: socket.socket | None = None
        self.expired = threading.Event()
        self._lock = threading.Lock()
        self._finished = False
        self._timer = threading.Timer(max(0.0, deadline - time.monotonic()), self._abort)
        self._timer.name = "shadowscan-http-acquisition"
        self._timer.daemon = True
        self._timer.start()

    def _abort(self) -> None:
        with self._lock:
            if self._finished:
                return
            self.expired.set()
            # During numeric connect the socket is not yet assigned to the
            # connection. After TLS wrapping, its live SSLSocket takes priority.
            active = self.connection.sock or self.socket
            if active is not None:
                with contextlib.suppress(OSError, RuntimeError, ValueError):
                    active.shutdown(socket.SHUT_RDWR)

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if self.expired.is_set() or remaining <= 0:
            raise ValueError("HTTP request exceeds the acquisition deadline")
        return remaining

    def socket_timeout(self, timeout: Any) -> float:
        remaining = self.remaining()
        return min(float(timeout), remaining) if isinstance(timeout, (float, int)) else remaining

    def watch_socket(self, active: socket.socket) -> None:
        with self._lock:
            self.socket = active
        self.remaining()

    def finish(self) -> None:
        with self._lock:
            self._finished = True
        self._timer.cancel()
        self._timer.join()


def _validate_headers(headers: Any, *, allow_removal: bool = False) -> None:
    """Reject malformed headers without putting their names or values in errors.

    requests and the underlying HTTP transport quote invalid input in errors.
    Header names can contain credentials too, so diagnostics are deliberately
    independent of both. Per-request None retains requests' removal semantics.
    """
    if headers is None:
        return
    if not isinstance(headers, Mapping):
        raise ValueError("HTTP headers must be a mapping")
    for name, value in headers.items():
        try:
            encoded_name = name.encode("ascii") if isinstance(name, str) else name
            if not isinstance(encoded_name, bytes) or not _HEADER_NAME.fullmatch(encoded_name):
                raise ValueError
            if allow_removal and value is None:
                continue
            check_header_validity((name, value))
            encoded_value = value.encode("latin-1") if isinstance(value, str) else value
            if any(byte < 32 and byte != 9 or byte == 127 for byte in encoded_value):
                raise ValueError
        except (InvalidHeader, TypeError, ValueError, UnicodeError):
            raise ValueError("HTTP header contains invalid characters or types") from None


def _positive_byte_limit(value: int | None, default: int) -> int:
    limit = default if value is None else value
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("max_bytes must be a positive integer")
    return limit


def _validated_ca_bundle(path: Any) -> str:
    """An explicit, operator-supplied PEM bundle: an existing regular file, nothing else."""
    message = "ca_bundle must be a path to an existing regular file"
    if not isinstance(path, str) or not path or "\0" in path:
        raise ValueError(message)
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        raise ValueError(message) from None
    if not regular:
        raise ValueError(message)
    return os.path.abspath(path)


def _read_deadline(timeout: float) -> float:
    """Derive the whole-body read deadline from the per-read client timeout."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a positive finite number of seconds")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive finite number of seconds")
    return float(timeout) * READ_DEADLINE_FACTOR


def _read_watchdog(
    resp: requests.Response, seconds: float, expired: threading.Event
) -> threading.Timer | None:
    """Abort a body read that is still blocked when its deadline passes.

    urllib3 fills a whole chunk before returning it, so a server dripping bytes
    inside the socket timeout would otherwise hold the worker until the connector
    deadline abandons it. Shutting the socket down for reading wakes the blocked
    read; ``expired`` tells the reader that any end of body it then sees is not a
    complete response.

    urllib3 returns the connection to the pool during the read that ends the
    body, before the reader regains control, and its ``shutdown()`` checks for
    that without a lock. A pooled socket may already carry another request on
    this session, so a release waits for a shutdown in progress, and the
    watchdog leaves alone a body whose connection was released before it fired.
    """
    raw: Any = resp.raw
    shutdown = getattr(raw, "shutdown", None)
    if not callable(shutdown):
        return None
    lock = threading.Lock()
    released = False
    release = getattr(raw, "release_conn", None)
    if callable(release):

        def release_conn() -> None:
            nonlocal released
            with lock:
                released = True
                release()

        raw.release_conn = release_conn

    def abort() -> None:
        with lock:
            if released:
                return
            expired.set()
            # urllib3 refuses to shut down a connection that is already closed.
            with contextlib.suppress(OSError, RuntimeError, ValueError):
                shutdown()

    timer = threading.Timer(seconds, abort)
    timer.daemon = True
    timer.start()
    return timer


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Do not let duplicate fields overwrite observations or pagination state."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # API responses may reflect credentials in field names or values.
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite JSON number")
    return number


METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
METADATA_NETS = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.169.253/32"),
    ipaddress.ip_network("169.254.169.250/32"),
    # Azure's wire server and metadata endpoint: a public-looking address that is link-local to the VM.
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


def set_allow_private_origin(enabled: bool) -> contextvars.Token[bool]:
    """Set the current worker's policy; callers must reset the returned token."""
    if not isinstance(enabled, bool):
        raise TypeError("allow_private_origin must be a boolean")
    return _allow_private_origin.set(enabled)


def reset_allow_private_origin(token: contextvars.Token[bool]) -> None:
    """Restore the policy after a connector finishes, including failed scans."""
    _allow_private_origin.reset(token)


def set_ca_bundle(path: str | None) -> contextvars.Token[str | None]:
    """Trust only this PEM bundle for clients the current worker creates.

    TLS verification stays on; the bundle replaces the default CA store, so it
    suits scans of private endpoints behind internal PKI. Callers must reset
    the returned token.
    """
    return _ca_bundle.set(None if path is None else _validated_ca_bundle(path))


def reset_ca_bundle(token: contextvars.Token[str | None]) -> None:
    _ca_bundle.reset(token)


def set_request_deadline(
    deadline: float | None, cancelled: threading.Event | None
) -> contextvars.Token[tuple[float | None, threading.Event | None]]:
    """Let clients created by the current worker stop retrying once the scan is over.

    ``deadline`` is a ``time.monotonic()`` value and ``cancelled`` the
    connector's cancellation event. Callers must reset the returned token.
    """
    return _request_limits.set((deadline, cancelled))


def reset_request_deadline(token: contextvars.Token[tuple[float | None, threading.Event | None]]) -> None:
    _request_limits.reset(token)


# RFC 6052 well-known NAT64 prefix. A DNS64 resolver maps every IPv4 name into it, so
# IPv6-only runners reach public APIs only through it. The address is judged by the IPv4
# address the translator connects to. The local-use 64:ff9b:1::/48 prefix stays blocked.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def _blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address):
        if addr in _NAT64_WELL_KNOWN:
            return _blocked_ip(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
        embedded = addr.ipv4_mapped or addr.sixtofour
        if embedded is not None and _blocked_ip(embedded):
            return True
        if addr.teredo and any(_blocked_ip(part) for part in addr.teredo):
            return True
    return bool(
        not addr.is_global
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
        # Deprecated site-local fec0::/10 is still routed inside some networks; ipaddress calls it global.
        or (isinstance(addr, ipaddress.IPv6Address) and addr.is_site_local)
        or any(addr in net for net in METADATA_NETS)
    )


def _blocked_host(hostname: str) -> bool:
    host = hostname.strip("[]").rstrip(".").lower()
    if host in METADATA_HOSTS or host == "localhost" or host.endswith(".localhost"):
        return True
    if host.endswith(".internal") or host.endswith(".local"):
        return True
    try:
        return _blocked_ip(ipaddress.ip_address(host))
    except ValueError:
        return False


def validate_url(url: str, origin: str | None = None, *, allow_private: bool | None = None) -> str:
    """Require HTTPS and, for server-supplied links, the credential origin.

    Destinations that resolve to loopback, link-local, private, multicast,
    unspecified, reserved, or cloud-metadata addresses are rejected unless
    ``allow_private`` (or the current worker's policy) is true. DNS checks here
    are preflight only; HttpClient also enforces the policy at socket connection.
    External transports such as git and cloud SDKs need their own egress controls.
    """
    # urlsplit drops tabs and line breaks and strips leading blanks before parsing, while git and
    # libcurl reject them (and HTTP stacks differ on the rest). Anything the validator does not see
    # exactly as the transport will is refused, never silently cleaned up.
    if isinstance(url, str) and any(char.isspace() or not char.isprintable() for char in url):
        raise ValueError("API URL must not contain whitespace or control characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Invalid API URL") from None
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API URL must use HTTPS without embedded credentials")
    if origin:
        try:
            expected = urlsplit(origin)
            expected_origin = (expected.scheme, expected.hostname, expected.port or 443)
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("Invalid API origin") from None
        actual_origin = (parsed.scheme, parsed.hostname, port)
        if actual_origin != expected_origin:
            raise ValueError("Refusing API URL outside the configured credential origin")
    allow = _allow_private_origin.get() if allow_private is None else allow_private
    if not isinstance(allow, bool):
        raise TypeError("allow_private must be a boolean")
    host = parsed.hostname.strip("[]")
    if (_blocked_host(host) or "%" in host) and not allow:
        raise ValueError("Refusing loopback, link-local, private, or cloud-metadata destination")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            infos = []
        for info in infos:
            try:
                addr = ipaddress.ip_address(info[4][0])
            except (ValueError, TypeError, IndexError):
                continue
            if _blocked_ip(addr) and not allow:
                raise ValueError(
                    "Refusing loopback, link-local, private, or cloud-metadata destination"
                ) from None
    return url


def _join_url(origin: str, path: str) -> str:
    """Resolve a continuation without exposing malformed URL text in parser errors."""
    try:
        return urljoin(origin, path)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Invalid API URL") from None


class _PublicHTTPSConnection(HTTPSConnection):
    """Resolve once, validate every answer, then connect a numeric sockaddr.

    TLS retains the original hostname for SNI and certificate verification.
    Checking the addresses inside _new_conn avoids the DNS check/use race of
    validating a URL before handing its hostname to requests for resolution.
    """

    allow_private_origin = False
    acquisition_guard: _SocketDeadline | None = None

    def _new_conn(self) -> socket.socket:
        guard = self.acquisition_guard
        if guard is not None:
            guard.remaining()
        host = self.host.rstrip(".")
        if not self.allow_private_origin and (_blocked_host(host) or "%" in host):
            raise ValueError("Refusing private or cloud-metadata destination")
        try:
            addresses = socket.getaddrinfo(host, self.port or 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise NameResolutionError(host, self, exc) from exc
        if guard is not None:
            guard.remaining()
        if not addresses:
            raise NewConnectionError(self, "DNS returned no usable addresses")
        # Reject mixed public/private results, not just the first DNS answer.
        for _, _, _, _, address in addresses:
            if not self.allow_private_origin and _blocked_ip(ipaddress.ip_address(address[0])):
                raise ValueError("Refusing private or cloud-metadata destination")
        last_error: OSError | None = None
        for family, socktype, proto, _, address in addresses:
            connection: socket.socket | None = None
            try:
                connection = socket.socket(family, socktype, proto)
                if guard is not None:
                    guard.watch_socket(connection)
                connection.settimeout(guard.socket_timeout(self.timeout) if guard else self.timeout)
                for option in self.socket_options or ():
                    connection.setsockopt(*option)
                if self.source_address:
                    connection.bind(self.source_address)
                connection.connect(address)
                if guard is not None:
                    # TLS follows this connect; give its handshake only the
                    # remaining acquisition time, not another full timeout.
                    connection.settimeout(guard.socket_timeout(self.timeout))
                return connection
            except ValueError:
                if connection is not None:
                    connection.close()
                raise
            except OSError as exc:
                last_error = exc
                if connection is not None:
                    connection.close()
        if isinstance(last_error, TimeoutError):
            raise ConnectTimeoutError(self, "HTTPS connection timed out") from last_error
        raise NewConnectionError(self, "HTTPS connection failed") from last_error


class _PrivateHTTPSConnection(_PublicHTTPSConnection):
    allow_private_origin = True


class _AcquisitionHTTPSConnectionPool(HTTPSConnectionPool):
    def _make_request(self, conn: Any, *args: Any, **kwargs: Any) -> Any:
        deadline = _acquisition_deadline.get()
        if deadline is None:
            return super()._make_request(conn, *args, **kwargs)
        guard = _SocketDeadline(conn, deadline)
        conn.acquisition_guard = guard
        try:
            try:
                response = super()._make_request(conn, *args, **kwargs)
            except Exception:
                guard.finish()
                if guard.expired.is_set() or time.monotonic() >= deadline:
                    raise ValueError("HTTP request exceeds the acquisition deadline") from None
                raise
            guard.finish()
            if guard.expired.is_set() or time.monotonic() >= deadline:
                response.close()
                raise ValueError("HTTP request exceeds the acquisition deadline")
            return response
        finally:
            guard.finish()
            conn.acquisition_guard = None


class _PublicHTTPSConnectionPool(_AcquisitionHTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class _PrivateHTTPSConnectionPool(_AcquisitionHTTPSConnectionPool):
    ConnectionCls = _PrivateHTTPSConnection


class _DestinationPolicyAdapter(HTTPAdapter):
    def __init__(self, *, allow_private: bool):
        self.allow_private = allow_private
        super().__init__()

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **kwargs: Any) -> None:
        super().init_poolmanager(connections, maxsize, block=block, **kwargs)
        # urllib3's default mapping is shared; do not mutate another client's policy.
        self.poolmanager.pool_classes_by_scheme = dict(self.poolmanager.pool_classes_by_scheme)
        self.poolmanager.pool_classes_by_scheme["https"] = (
            _PrivateHTTPSConnectionPool if self.allow_private else _PublicHTTPSConnectionPool
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        raise ValueError("Proxies are unsupported by the destination-enforcing HTTP client")


def _rate_limited(resp: requests.Response) -> bool:
    """GitHub reports primary and secondary rate limits with 403 as well as 429."""
    return resp.status_code == 403 and (
        resp.headers.get("X-RateLimit-Remaining") == "0" or bool(resp.headers.get("Retry-After"))
    )


def _retry_delay(resp: requests.Response, attempt: int) -> float:
    """Honor server hints; otherwise back off exponentially with jitter.

    Jitter keeps parallel connectors (and scanner fleets) from retrying in
    lockstep against the same API. Every delay is capped at MAX_RETRY_DELAY.
    """
    retry_after = resp.headers.get("Retry-After")
    if retry_after and retry_after.isascii() and retry_after.isdigit():
        delay = float(retry_after) + random.uniform(0, 1)
    else:
        step = min(2**attempt, 30)
        delay = step / 2 + random.uniform(0, step / 2)
    reset = resp.headers.get("X-RateLimit-Reset")
    if resp.headers.get("X-RateLimit-Remaining") == "0" and reset and reset.isascii() and reset.isdigit():
        delay = max(delay, float(reset) - time.time() + 1)
    # Okta spells these X-Rate-Limit-* and sends no Retry-After with its 429.
    reset = resp.headers.get("X-Rate-Limit-Reset")
    if (
        (resp.status_code == 429 or resp.headers.get("X-Rate-Limit-Remaining") == "0")
        and reset
        and reset.isascii()
        and reset.isdigit()
    ):
        delay = max(delay, float(reset) - time.time() + 1)
    return max(0.0, min(delay, MAX_RETRY_DELAY))


def diagnostic_url(url: str) -> str:
    """Keep only an HTTPS origin in diagnostics, never request-controlled URL fields.

    Paths can contain opaque credentials just as queries and userinfo can.
    Lexical redaction cannot identify an arbitrary value without its credential
    context, so none of those components belongs in errors or retry logs.
    Malformed input gets a fixed label; URL parser errors can echo its values.
    """
    invalid = "<invalid HTTPS origin>"
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
        if parsed.scheme != "https" or not host or "%" in host:
            return invalid
        if ":" in host:
            # Reconstruct the authority rather than copying malformed netloc text.
            authority = f"[{ipaddress.IPv6Address(host)}]"
        else:
            host = host.encode("idna").decode("ascii")
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?", host):
                return invalid
            authority = host
        if port is not None:
            authority += f":{port}"
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return invalid
    return sanitize_text(urlunsplit(("https", authority, "", "", "")))


def _transport_error(exc: RequestException, url: str, phase: str) -> RequestException:
    """Keep useful transport categories without retaining untrusted error payloads.

    requests/urllib3 exceptions can retain full URLs, echoed response text and
    credential-bearing request objects. Construct only known exception types
    with a fixed category and origin, preserving connectors' existing catches.
    """
    categories = (
        (SSLError, "TLS failure"),
        (ConnectTimeout, "connect timeout"),
        (ReadTimeout, "read timeout"),
        (Timeout, "timeout"),
        (ConnectionError, "connection failure"),
        (ChunkedEncodingError, "invalid response framing"),
        (ContentDecodingError, "response decoding failure"),
    )
    for error_type, category in categories:
        if isinstance(exc, error_type):
            return error_type(f"HTTP {phase} {category} for {diagnostic_url(url)}")
    return RequestException(f"HTTP {phase} transport failure for {diagnostic_url(url)}")


class HttpError(RuntimeError):
    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = diagnostic_url(url)
        # Error documents can reflect opaque request credentials. Keep the old
        # attribute for connector compatibility, but never retain response text.
        self.body = ""
        super().__init__(f"HTTP {status} for {self.url}")


class HttpClient:
    """requests.Session wrapper with retries and JSON helpers."""

    def __init__(
        self,
        base_url: str = "",
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 4,
        session: requests.Session | None = None,
        auth: Any = None,
        on_warning: Callable[[str], None] | None = None,
        allow_private_origin: bool | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle: str | None = None,
        deadline: float | None = None,
        cancelled: threading.Event | None = None,
    ):
        # Validate before an injected session is modified.
        read_deadline = _read_deadline(timeout)
        self.base_url = base_url.rstrip("/")
        self.allow_private_origin = (
            _allow_private_origin.get() if allow_private_origin is None else allow_private_origin
        )
        if not isinstance(self.allow_private_origin, bool):
            raise TypeError("allow_private_origin must be a boolean")
        self.session = session or requests.Session()
        _validate_headers(self.session.headers)
        _validate_headers(headers)
        # Environment proxies can resolve destinations outside our socket policy.
        # Explicit proxies are refused by the adapter as well.
        self.session.trust_env = False
        # An explicit bundle replaces the default CA store (verification stays
        # on); ambient REQUESTS_CA_BUNDLE / SSL_CERT_FILE values stay ignored.
        bundle = _ca_bundle.get() if ca_bundle is None else _validated_ca_bundle(ca_bundle)
        if bundle is not None:
            self.session.verify = bundle
        if isinstance(self.session, requests.Session):
            # requests picks the longest matching adapter prefix. An injected
            # session may already have an origin-specific adapter that would
            # bypass connection-time DNS checks even after mounting https://.
            old_adapters = set(self.session.adapters.values())
            self.session.adapters.clear()
            for adapter in old_adapters:
                adapter.close()
        self._policy_adapter = _DestinationPolicyAdapter(allow_private=self.allow_private_origin)
        self.session.mount("https://", self._policy_adapter)
        self.session.headers.update({"User-Agent": f"shadowscan/{__version__}", "Accept": "application/json"})
        if headers:
            try:
                for header in headers.items():
                    check_header_validity(header)
            except InvalidHeader:
                raise ValueError("HTTP header name or value contains invalid characters") from None
            self.session.headers.update(headers)
        if auth is not None:
            self.session.auth = auth
        self.timeout = timeout
        self.read_deadline = read_deadline
        self.max_retries = max_retries
        self.max_response_bytes = _positive_byte_limit(max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES)
        inherited_deadline, inherited_cancelled = _request_limits.get()
        self.deadline = inherited_deadline if deadline is None else deadline
        self.cancelled = inherited_cancelled if cancelled is None else cancelled
        self.on_warning = on_warning

    def _url(self, path: str) -> str:
        try:
            absolute = bool(urlsplit(path).scheme) or path.startswith("//")
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("Invalid API URL") from None
        if absolute:
            url = _join_url(self.base_url, path)
        else:
            url = f"{self.base_url}/{path.lstrip('/')}"
        return validate_url(url, self.base_url or None, allow_private=self.allow_private_origin)

    def request(
        self, method: str, path: str, *, raise_for_status: bool = True, **kwargs: Any
    ) -> requests.Response:
        if not isinstance(raise_for_status, bool):
            raise TypeError("raise_for_status must be a boolean")
        _validate_headers(self.session.headers)
        _validate_headers(kwargs.get("headers"), allow_removal=True)
        url = self._url(path)
        # requests treats any falsy effective setting as CERT_NONE, including
        # 0, an empty CA path and a session-level None. Per-request None inherits
        # the session setting; inspect that effective value before sending.
        verify = kwargs.get("verify")
        if verify is None:
            verify = getattr(self.session, "verify", True)
        if not verify:
            raise ValueError("TLS certificate verification cannot be disabled")
        if kwargs.get("proxies") or (isinstance(self.session, requests.Session) and self.session.proxies):
            raise ValueError("Proxies are unsupported by the destination-enforcing HTTP client")
        stream = kwargs.pop("stream", False)
        if not isinstance(stream, bool):
            raise ValueError("stream must be a boolean")
        kwargs["stream"] = True
        kwargs.setdefault("timeout", self.timeout)
        # requests strips Authorization for some redirects, but not custom API-key
        # headers, cookies or credential-bearing POST bodies. Validate before sending.
        kwargs.pop("allow_redirects", None)
        kwargs["allow_redirects"] = False
        attempt = 0
        redirects = 0
        origin = url
        while True:
            replaced = isinstance(self.session, requests.Session) and (
                self.session.get_adapter(url) is not self._policy_adapter
            )
            if replaced:
                raise ValueError("HTTP destination policy adapter was replaced")
            attempt += 1
            # Acquisition (connect, TLS, request, status and headers) gets the read
            # budget, and never more than the connector's remaining time.
            budget = self.read_deadline
            if self.deadline is not None:
                budget = min(budget, self.deadline - time.monotonic())
            deadline_token = _acquisition_deadline.set(time.monotonic() + budget)
            request_failure: RequestException | ValueError | None = None
            try:
                try:
                    resp = self.session.request(method, url, **kwargs)
                except InvalidHeader:
                    # Auth handlers can add headers after our preflight validation.
                    request_failure = ValueError("HTTP header contains invalid characters or types")
                except RequestException as exc:
                    request_failure = _transport_error(exc, url, "request")
            finally:
                _acquisition_deadline.reset(deadline_token)
            # Raise outside the handler so even __context__ cannot retain the
            # original request, response or diagnostic payload.
            if request_failure is not None:
                raise request_failure from None
            if resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("Location")
                resp.close()
                if not location or redirects >= 5:
                    raise HttpError(resp.status_code, url, "Invalid or excessive redirect")
                url = validate_url(_join_url(url, location), origin, allow_private=self.allow_private_origin)
                redirects += 1
                # Do not carry original query parameters onto a redirect target.
                kwargs.pop("params", None)
                if resp.status_code == 303 or (resp.status_code in {301, 302} and method.upper() == "POST"):
                    method = "GET"
                    kwargs.pop("json", None)
                    kwargs.pop("data", None)
                continue
            if (resp.status_code in RETRY_STATUSES or _rate_limited(resp)) and attempt <= self.max_retries:
                resp.close()
                delay = _retry_delay(resp, attempt)
                log.warning(
                    "HTTP %s from %s; retrying in %.0fs (attempt %d)",
                    resp.status_code,
                    diagnostic_url(url),
                    delay,
                    attempt,
                )
                self._wait_before_retry(delay)
                continue
            if resp.status_code >= 400 and raise_for_status:
                resp.close()
                raise HttpError(resp.status_code, url)
            if not stream:
                # A caller of get()/post() may access resp.content directly.
                # Buffer only within the decoded-byte limit and keep the
                # familiar Response API after the transport is closed.
                resp._content = self.read_response_bytes(resp)
                resp._content_consumed = True  # type: ignore[attr-defined]
            return resp

    def _scan_over(self, pending: float = 0.0) -> bool:
        """Whether the connector was cancelled or ``pending`` seconds would pass its deadline."""
        return (self.cancelled is not None and self.cancelled.is_set()) or (
            self.deadline is not None and time.monotonic() + pending >= self.deadline
        )

    def _wait_before_retry(self, delay: float) -> None:
        """Sleep between attempts, but never past a cancelled scan or its deadline."""
        if self._scan_over(delay):
            raise TimeoutError("HTTP retry abandoned: connector deadline exceeded")
        if self.cancelled is None:
            time.sleep(delay)
        elif self.cancelled.wait(delay):
            raise TimeoutError("HTTP retry abandoned: connector deadline exceeded")

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", path, **kwargs)

    def read_response_bytes(self, resp: requests.Response, *, max_bytes: int | None = None) -> bytes:
        """Read a streamed response within the configured decoded-byte and time limits.

        Iteration counts bytes after HTTP content decoding, so compressed
        responses cannot expand past the limit unnoticed. The whole body must
        arrive within ``read_deadline`` seconds; a body cut short by that
        deadline is an error, never a truncated result. The response is closed
        on success and on every parse, transport, size, or deadline error.
        """
        watchdog: threading.Timer | None = None
        expired = threading.Event()
        try:
            limit = _positive_byte_limit(max_bytes, self.max_response_bytes)
            length = resp.headers.get("Content-Length")
            if length is not None:
                if not isinstance(length, str) or not length.isascii() or not length.isdecimal():
                    raise ValueError("Invalid Content-Length on HTTP response")
                # Compare decimal strings before conversion so arbitrarily
                # padded headers never reach Python's big-integer parser.
                digits = length.lstrip("0") or "0"
                maximum = str(limit)
                if len(digits) > len(maximum) or (len(digits) == len(maximum) and digits > maximum):
                    raise ValueError("HTTP response exceeds the byte limit")
            # The whole body must finish within the read deadline, and never past
            # the connector's own deadline or after its cancellation.
            budget = self.read_deadline
            if self.deadline is not None:
                budget = min(budget, self.deadline - time.monotonic())
            if budget <= 0 or self._scan_over():
                raise TimeoutError("HTTP response not read: connector deadline exceeded")
            deadline = time.monotonic() + budget
            watchdog = _read_watchdog(resp, budget, expired)
            body = bytearray()
            transport_failure: RequestException | None = None
            try:
                for chunk in resp.iter_content(chunk_size=min(65536, limit + 1)):
                    if time.monotonic() >= deadline:
                        expired.set()
                        break
                    if not isinstance(chunk, bytes):
                        raise ValueError("Invalid HTTP response chunk")
                    if len(body) + len(chunk) > limit:
                        raise ValueError("HTTP response exceeds the byte limit")
                    body.extend(chunk)
            except Exception as exc:  # re-raised unless the deadline shut the read down
                # The watchdog's shutdown surfaces as a transport or framing
                # error; report the deadline instead, without transport text.
                if not expired.is_set():
                    if isinstance(exc, RequestException):
                        transport_failure = _transport_error(exc, resp.url, "response")
                    else:
                        raise
            if expired.is_set():
                # A close-delimited body also ends cleanly after the shutdown.
                raise ValueError("HTTP response exceeds the read deadline")
            if transport_failure is not None:
                raise transport_failure from None
            return bytes(body)
        finally:
            if watchdog is not None:
                watchdog.cancel()
                watchdog.join()
            resp.close()

    def read_json_response(self, resp: requests.Response, *, max_bytes: int | None = None) -> Any:
        """Decode bounded, unambiguous JSON before trusting provider fields.

        Repeated keys can otherwise replace populated collections with empty
        ones, hide pagination continuations, or change JWK selection fields.
        Reject nonfinite values, including numeric overflow, before analysis.
        """
        body = self.read_response_bytes(resp, max_bytes=max_bytes)
        if not body:
            return None
        try:
            return json.loads(
                body,
                object_pairs_hook=_unique_json_object,
                parse_float=_finite_json_float,
                parse_constant=_finite_json_float,
            )
        except (ValueError, RecursionError):
            raise ValueError("Invalid JSON response") from None

    def get_json(
        self,
        path: str,
        *,
        max_bytes: int | None = None,
        on_response: Callable[[requests.Response], None] | None = None,
        **kwargs: Any,
    ) -> Any:
        """GET and decode JSON. *on_response* receives the response (headers only; the
        body is consumed) once the body is decoded, so a caller can read headers such
        as a total count; it never sees a rejected response."""
        limit = _positive_byte_limit(max_bytes, self.max_response_bytes)
        kwargs["stream"] = True
        resp = self.get(path, **kwargs)
        data = self.read_json_response(resp, max_bytes=limit)
        if on_response is not None:
            on_response(resp)
        return data

    def post_json(self, path: str, *, max_bytes: int | None = None, **kwargs: Any) -> Any:
        limit = _positive_byte_limit(max_bytes, self.max_response_bytes)
        kwargs["stream"] = True
        resp = self.post(path, **kwargs)
        return self.read_json_response(resp, max_bytes=limit)

    def try_get_json(
        self, path: str, default: Any = None, ok_statuses: set[int] | None = None, **kwargs: Any
    ) -> Any:
        """Optional GET; denied or unknown coverage is never silently discarded.

        Callers may explicitly allow a missing optional feature (e.g. 404).
        Otherwise a warning callback must record incomplete coverage, or the
        exception propagates to the connector's failure handling.
        """
        try:
            return self.get_json(path, **kwargs)
        except HttpError as exc:
            if exc.status in (ok_statuses or set()) and exc.status not in {401, 403}:
                return default
            if self.on_warning and exc.status in {401, 403, 404, 405, 422}:
                self.on_warning(f"Collection incomplete: HTTP {exc.status} for {exc.url}")
                return default
            raise

    # ------------------------------------------------------------ paginators
    @staticmethod
    def _require_page_items(data: Any, key: str | None, paginator: str) -> list[dict[str, Any]]:
        if isinstance(data, dict) and ("error" in data or data.get("ok") is False):
            # Error documents can reflect credentials, so never echo fields.
            raise RuntimeError(f"{paginator} API collection failed; collection incomplete")
        if key is None:
            items = data
        elif not isinstance(data, dict) or key not in data:
            raise RuntimeError(f"{paginator} response is missing collection '{key}'; collection incomplete")
        else:
            items = data[key]
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise RuntimeError(f"{paginator} response has an invalid collection; collection incomplete")
        return items

    @staticmethod
    def _continuation(value: Any) -> str | None:
        if value is None or value == "":
            return None
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError("Invalid pagination continuation; collection incomplete")
        return value

    def paginate_link(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        item_key: str | None = None,
        max_pages: int = 1000,
        on_page: Callable[[requests.Response], None] | None = None,
    ) -> Iterator[Any]:
        """RFC 5988 Link-header pagination for GitHub and GitLab.

        *on_page* receives each page's response (headers only; the body is
        consumed) once its items are validated, before they are yielded, so a
        caller can check header totals such as GitLab's ``X-Total``.
        """
        origin = self._url(path)
        url: str | None = origin
        pages = 0
        seen: set[str] = set()
        while url and pages < max_pages:
            url = validate_url(_join_url(origin, url), origin, allow_private=self.allow_private_origin)
            if url in seen:
                raise RuntimeError("Repeated pagination link; collection incomplete")
            seen.add(url)
            resp = self.get(url, params=params if pages == 0 else None, stream=True)
            data = self.read_json_response(resp)
            items = self._require_page_items(data, item_key, "Link pagination")
            next_url = self._continuation(resp.links.get("next", {}).get("url"))
            if on_page is not None:
                on_page(resp)
            yield from items
            url = next_url
            pages += 1
        if url:
            raise RuntimeError("Pagination limit reached; collection incomplete")

    def paginate_odata(
        self, path: str, params: dict[str, Any] | None = None, max_pages: int = 1000
    ) -> Iterator[dict[str, Any]]:
        """Microsoft Graph and OData next-link pagination."""
        origin = self._url(path)
        url: str | None = origin
        pages = 0
        seen: set[str] = set()
        while url and pages < max_pages:
            url = validate_url(_join_url(origin, url), origin, allow_private=self.allow_private_origin)
            if url in seen:
                raise RuntimeError("Repeated pagination link; collection incomplete")
            seen.add(url)
            data = self.get_json(url, params=params if pages == 0 else None)
            if not isinstance(data, dict):
                raise RuntimeError("Invalid paginated API response; collection incomplete")
            items = self._require_page_items(data, "value", "OData pagination")
            # Validate both fields before selecting; falsy malformed values
            # must not silently terminate collection or hide behind a fallback.
            odata_link = self._continuation(data.get("@odata.nextLink"))
            legacy_link = self._continuation(data.get("nextLink"))
            next_url = odata_link or legacy_link
            yield from items
            url = next_url or None
            pages += 1
        if url:
            raise RuntimeError("Pagination limit reached; collection incomplete")

    def paginate_token(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        items_key: str = "items",
        token_key: str = "nextPageToken",
        token_param: str = "pageToken",
        max_pages: int = 1000,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        expected_empty_kind: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Google / AWS style page-token pagination.

        An omitted empty collection is accepted only when an operator-supplied
        documented response kind matches and the envelope has no continuation
        or error. Ordinary missing collection fields remain incomplete scans.
        """
        params = dict(params or {})
        pages = 0
        seen: set[str] = set()
        while pages < max_pages:
            if method == "POST":
                payload = dict(body or {})
                if params.get(token_param):
                    payload[token_param] = params[token_param]
                data = self.post_json(path, json=payload)
            else:
                data = self.get_json(path, params=params)
            if not isinstance(data, dict):
                raise RuntimeError("Invalid paginated API response; collection incomplete")
            if (
                expected_empty_kind
                and data.get("kind") == expected_empty_kind
                and items_key not in data
                and "error" not in data
                and data.get("ok") is not False
                and self._continuation(data.get(token_key)) is None
            ):
                return
            items = self._require_page_items(data, items_key, "Token pagination")
            token = self._continuation(data.get(token_key))
            yield from items
            if not token:
                return
            if token in seen:
                raise RuntimeError("Repeated pagination token; collection incomplete")
            seen.add(token)
            params[token_param] = token
            pages += 1
        raise RuntimeError("Pagination limit reached; collection incomplete")
