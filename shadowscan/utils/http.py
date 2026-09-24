"""Small HTTP helper with retries, rate-limit handling and pagination helpers.

Kept deliberately thin so connectors read like the API docs they implement.
"""

from __future__ import annotations

import contextvars
import ipaddress
import json
import logging
import socket
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError

from shadowscan import __version__
from shadowscan.utils.redaction import sanitize_text

log = logging.getLogger("shadowscan.http")

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RETRY_DELAY = 120
RETRY_STATUSES = {429, 500, 502, 503, 504}

_allow_private_origin: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "shadowscan_allow_private_origin", default=False
)


def _positive_byte_limit(value: int | None, default: int) -> int:
    limit = default if value is None else value
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("max_bytes must be a positive integer")
    return limit


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


def _blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address):
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
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API URL must use HTTPS without embedded credentials")
    if origin:
        expected = urlsplit(origin)
        if (parsed.scheme, parsed.hostname, parsed.port or 443) != (expected.scheme, expected.hostname, expected.port or 443):
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
            infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            infos = []
        for info in infos:
            try:
                addr = ipaddress.ip_address(info[4][0])
            except (ValueError, TypeError, IndexError):
                continue
            if _blocked_ip(addr) and not allow:
                raise ValueError("Refusing loopback, link-local, private, or cloud-metadata destination")
    return url


class _PublicHTTPSConnection(HTTPSConnection):
    """Resolve once, validate every answer, then connect a numeric sockaddr.

    TLS retains the original hostname for SNI and certificate verification.
    Checking the addresses inside _new_conn avoids the DNS check/use race of
    validating a URL before handing its hostname to requests for resolution.
    """

    allow_private_origin = False

    def _new_conn(self) -> socket.socket:
        host = self.host.rstrip(".")
        if not self.allow_private_origin and (_blocked_host(host) or "%" in host):
            raise ValueError("Refusing private or cloud-metadata destination")
        try:
            addresses = socket.getaddrinfo(host, self.port or 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise NameResolutionError(host, self, exc) from exc
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
                connection.settimeout(self.timeout)
                for option in self.socket_options or ():
                    connection.setsockopt(*option)
                if self.source_address:
                    connection.bind(self.source_address)
                connection.connect(address)
                return connection
            except OSError as exc:
                last_error = exc
                if connection is not None:
                    connection.close()
        if isinstance(last_error, TimeoutError):
            raise ConnectTimeoutError(self, "HTTPS connection timed out") from last_error
        raise NewConnectionError(self, "HTTPS connection failed") from last_error


class _PrivateHTTPSConnection(_PublicHTTPSConnection):
    allow_private_origin = True

class _PublicHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class _PrivateHTTPSConnectionPool(HTTPSConnectionPool):
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


def diagnostic_url(url: str) -> str:
    """Drop query/fragment and userinfo before URLs enter errors or logs."""
    parsed = urlsplit(url)
    return sanitize_text(urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "")))


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
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = 4,
        session: requests.Session | None = None,
        auth: Any = None,
        on_warning: Callable[[str], None] | None = None,
        allow_private_origin: bool | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ):
        self.base_url = base_url.rstrip("/")
        self.allow_private_origin = _allow_private_origin.get() if allow_private_origin is None else allow_private_origin
        if not isinstance(self.allow_private_origin, bool):
            raise TypeError("allow_private_origin must be a boolean")
        self.session = session or requests.Session()
        # Environment proxies can resolve destinations outside our socket policy.
        # Explicit proxies are refused by the adapter as well.
        self.session.trust_env = False
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
            self.session.headers.update(headers)
        if auth is not None:
            self.session.auth = auth
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_response_bytes = _positive_byte_limit(max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES)
        self.requests_made = 0
        self.on_warning = on_warning

    def _url(self, path: str) -> str:
        if urlsplit(path).scheme or path.startswith("//"):
            url = urljoin(self.base_url, path)
        else:
            url = f"{self.base_url}/{path.lstrip('/')}"
        return validate_url(url, self.base_url or None, allow_private=self.allow_private_origin)

    def request(self, method: str, path: str, *, raise_for_status: bool = True, **kwargs: Any) -> requests.Response:
        if not isinstance(raise_for_status, bool):
            raise TypeError("raise_for_status must be a boolean")
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
            if isinstance(self.session, requests.Session) and self.session.get_adapter(url) is not self._policy_adapter:
                raise ValueError("HTTP destination policy adapter was replaced")
            attempt += 1
            self.requests_made += 1
            resp = self.session.request(method, url, **kwargs)
            if resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("Location")
                resp.close()
                if not location or redirects >= 5:
                    raise HttpError(resp.status_code, url, "Invalid or excessive redirect")
                url = validate_url(urljoin(url, location), origin, allow_private=self.allow_private_origin)
                redirects += 1
                # Do not carry original query parameters onto a redirect target.
                kwargs.pop("params", None)
                if resp.status_code == 303 or (resp.status_code in {301, 302} and method.upper() == "POST"):
                    method = "GET"
                    kwargs.pop("json", None)
                    kwargs.pop("data", None)
                continue
            if resp.status_code in RETRY_STATUSES and attempt <= self.max_retries:
                resp.close()
                retry_after = resp.headers.get("Retry-After")
                delay = min(float(retry_after), MAX_RETRY_DELAY) if retry_after and retry_after.isascii() and retry_after.isdigit() else min(2 ** attempt, 30)
                # GitHub style secondary rate limit
                reset = resp.headers.get("X-RateLimit-Reset")
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining == "0" and reset and reset.isascii() and reset.isdigit():
                    delay = max(delay, min(float(reset) - time.time() + 1, MAX_RETRY_DELAY))
                log.warning("HTTP %s from %s; retrying in %.0fs (attempt %d)", resp.status_code, diagnostic_url(url), delay, attempt)
                time.sleep(delay)
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

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", path, **kwargs)

    def read_response_bytes(self, resp: requests.Response, *, max_bytes: int | None = None) -> bytes:
        """Read a streamed response within the configured decoded-byte limit.

        Iteration counts bytes after HTTP content decoding, so compressed
        responses cannot expand past the limit unnoticed. The response is closed
        on success and on every parse, transport, or size error.
        """
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
            body = bytearray()
            for chunk in resp.iter_content(chunk_size=min(65536, limit + 1)):
                if not isinstance(chunk, bytes):
                    raise ValueError("Invalid HTTP response chunk")
                if len(body) + len(chunk) > limit:
                    raise ValueError("HTTP response exceeds the byte limit")
                body.extend(chunk)
            return bytes(body)
        finally:
            resp.close()

    def read_json_response(self, resp: requests.Response, *, max_bytes: int | None = None) -> Any:
        """Decode one JSON response while enforcing the configured body limit."""
        body = self.read_response_bytes(resp, max_bytes=max_bytes)
        if not body:
            return None
        try:
            return json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise ValueError("Invalid JSON response") from exc

    def get_json(self, path: str, *, max_bytes: int | None = None, **kwargs: Any) -> Any:
        limit = _positive_byte_limit(max_bytes, self.max_response_bytes)
        kwargs["stream"] = True
        resp = self.get(path, **kwargs)
        return self.read_json_response(resp, max_bytes=limit)

    def post_json(self, path: str, *, max_bytes: int | None = None, **kwargs: Any) -> Any:
        limit = _positive_byte_limit(max_bytes, self.max_response_bytes)
        kwargs["stream"] = True
        resp = self.post(path, **kwargs)
        return self.read_json_response(resp, max_bytes=limit)

    def try_get_json(self, path: str, default: Any = None, ok_statuses: set[int] | None = None, **kwargs: Any) -> Any:
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
                self.on_warning(f"Collection incomplete: HTTP {exc.status} for {urlsplit(exc.url).path}")
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

    def paginate_link(self, path: str, params: dict[str, Any] | None = None, item_key: str | None = None, max_pages: int = 1000) -> Iterator[Any]:
        """RFC 5988 Link-header pagination for GitHub and GitLab."""
        origin = self._url(path)
        url: str | None = origin
        pages = 0
        seen: set[str] = set()
        while url and pages < max_pages:
            url = validate_url(urljoin(origin, url), origin, allow_private=self.allow_private_origin)
            if url in seen:
                raise RuntimeError("Repeated pagination link; collection incomplete")
            seen.add(url)
            resp = self.get(url, params=params if pages == 0 else None, stream=True)
            data = self.read_json_response(resp)
            items = self._require_page_items(data, item_key, "Link pagination")
            next_url = self._continuation(resp.links.get("next", {}).get("url"))
            yield from items
            url = next_url
            pages += 1
        if url:
            raise RuntimeError("Pagination limit reached; collection incomplete")

    def paginate_odata(self, path: str, params: dict[str, Any] | None = None, max_pages: int = 1000) -> Iterator[dict[str, Any]]:
        """Microsoft Graph and OData next-link pagination."""
        origin = self._url(path)
        url: str | None = origin
        pages = 0
        seen: set[str] = set()
        while url and pages < max_pages:
            url = validate_url(urljoin(origin, url), origin, allow_private=self.allow_private_origin)
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

    def paginate_cursor(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        items_key: str = "results",
        cursor_path: Callable[[dict[str, Any]], str | None] | None = None,
        cursor_param: str = "cursor",
        max_pages: int = 1000,
    ) -> Iterator[dict[str, Any]]:
        """Slack-style response-metadata cursor pagination."""
        params = dict(params or {})
        pages = 0
        seen: set[str] = set()
        while pages < max_pages:
            data = self.get_json(path, params=params)
            if not isinstance(data, dict):
                raise RuntimeError("Invalid paginated API response; collection incomplete")
            items = self._require_page_items(data, items_key, "Cursor pagination")
            if cursor_path is None:
                metadata = data.get("response_metadata", {})
                if not isinstance(metadata, dict):
                    raise RuntimeError("Invalid pagination metadata; collection incomplete")
                cursor = self._continuation(metadata.get("next_cursor"))
            else:
                try:
                    cursor = self._continuation(cursor_path(data))
                except (AttributeError, KeyError, TypeError) as exc:
                    raise RuntimeError("Invalid pagination cursor; collection incomplete") from exc
            yield from items
            if not cursor:
                return
            if cursor in seen:
                raise RuntimeError("Repeated pagination cursor; collection incomplete")
            seen.add(cursor)
            params[cursor_param] = cursor
            pages += 1
        raise RuntimeError("Pagination limit reached; collection incomplete")
