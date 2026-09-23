"""Small HTTP helper with retries, rate-limit handling and pagination helpers.

Kept deliberately thin so connectors read like the API docs they implement.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from shadowscan import __version__
from shadowscan.utils.redaction import sanitize_text

log = logging.getLogger("shadowscan.http")

DEFAULT_TIMEOUT = 30
MAX_RETRY_DELAY = 120
RETRY_STATUSES = {429, 500, 502, 503, 504}


def validate_url(url: str, origin: str | None = None) -> str:
    """Require HTTPS and, for server-supplied links, the credential origin."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API URL must use HTTPS without embedded credentials")
    if origin:
        expected = urlsplit(origin)
        if (parsed.scheme, parsed.hostname, parsed.port or 443) != (expected.scheme, expected.hostname, expected.port or 443):
            raise ValueError("Refusing API URL outside the configured credential origin")
    return url


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
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": f"shadowscan/{__version__}", "Accept": "application/json"})
        if headers:
            self.session.headers.update(headers)
        if auth is not None:
            self.session.auth = auth
        self.timeout = timeout
        self.max_retries = max_retries
        self.requests_made = 0
        self.on_warning = on_warning

    def _url(self, path: str) -> str:
        if urlsplit(path).scheme or path.startswith("//"):
            url = urljoin(self.base_url, path)
        else:
            url = f"{self.base_url}/{path.lstrip('/')}"
        return validate_url(url, self.base_url or None)

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = self._url(path)
        kwargs.setdefault("timeout", self.timeout)
        # requests strips Authorization for some redirects, but not custom API-key
        # headers, cookies or credential-bearing POST bodies. Validate before sending.
        kwargs.pop("allow_redirects", None)
        kwargs["allow_redirects"] = False
        attempt = 0
        redirects = 0
        origin = url
        while True:
            attempt += 1
            self.requests_made += 1
            resp = self.session.request(method, url, **kwargs)
            if resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("Location")
                if not location or redirects >= 5:
                    raise HttpError(resp.status_code, url, "Invalid or excessive redirect")
                url = validate_url(urljoin(url, location), origin)
                redirects += 1
                # Do not carry original query parameters onto a redirect target.
                kwargs.pop("params", None)
                if resp.status_code == 303 or (resp.status_code in {301, 302} and method.upper() == "POST"):
                    method = "GET"
                    kwargs.pop("json", None)
                    kwargs.pop("data", None)
                continue
            if resp.status_code in RETRY_STATUSES and attempt <= self.max_retries:
                retry_after = resp.headers.get("Retry-After")
                delay = min(float(retry_after), MAX_RETRY_DELAY) if retry_after and retry_after.isdigit() else min(2**attempt, 30)
                # GitHub style secondary rate limit
                reset = resp.headers.get("X-RateLimit-Reset")
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining == "0" and reset and reset.isdigit():
                    delay = max(delay, min(int(reset) - time.time() + 1, MAX_RETRY_DELAY))
                log.warning("HTTP %s from %s; retrying in %.0fs (attempt %d)", resp.status_code, diagnostic_url(url), delay, attempt)
                time.sleep(delay)
                continue
            if resp.status_code >= 400:
                raise HttpError(resp.status_code, url)
            return resp

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", path, **kwargs)

    def get_json(self, path: str, **kwargs: Any) -> Any:
        resp = self.get(path, **kwargs)
        if not resp.content:
            return None
        return resp.json()

    def post_json(self, path: str, **kwargs: Any) -> Any:
        resp = self.post(path, **kwargs)
        if not resp.content:
            return None
        return resp.json()

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
    def paginate_link(self, path: str, params: dict[str, Any] | None = None, item_key: str | None = None, max_pages: int = 1000) -> Iterator[Any]:
        """RFC 5988 ``Link: rel=next`` pagination (GitHub, GitLab)."""
        url: str | None = self._url(path)
        origin = url
        pages = 0
        seen: set[str] = set()
        while url and pages < max_pages:
            url = validate_url(urljoin(origin, url), origin)
            if url in seen:
                raise RuntimeError("Repeated pagination link; collection incomplete")
            seen.add(url)
            resp = self.get(url, params=params if pages == 0 else None)
            data = resp.json()
            items = data.get(item_key, []) if item_key and isinstance(data, dict) else data
            if isinstance(items, list):
                yield from items
            else:
                yield items
            url = resp.links.get("next", {}).get("url")
            pages += 1
        if url:
            raise RuntimeError("Pagination limit reached; collection incomplete")

    def paginate_odata(self, path: str, params: dict[str, Any] | None = None, max_pages: int = 1000) -> Iterator[dict[str, Any]]:
        """Microsoft Graph / OData ``@odata.nextLink`` pagination."""
        url: str | None = self._url(path)
        origin = url
        pages = 0
        seen: set[str] = set()
        while url and pages < max_pages:
            url = validate_url(urljoin(origin, url), origin)
            if url in seen:
                raise RuntimeError("Repeated pagination link; collection incomplete")
            seen.add(url)
            data = self.get_json(url, params=params if pages == 0 else None)
            if not isinstance(data, dict):
                raise RuntimeError("Invalid paginated API response; collection incomplete")
            yield from data.get("value", [])
            url = data.get("@odata.nextLink") or data.get("nextLink")
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
    ) -> Iterator[dict[str, Any]]:
        """Google / AWS style page-token pagination."""
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
            yield from data.get(items_key, []) or []
            token = data.get(token_key)
            if not token:
                return
            if str(token) in seen:
                raise RuntimeError("Repeated pagination token; collection incomplete")
            seen.add(str(token))
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
        """Slack style ``response_metadata.next_cursor`` pagination (configurable)."""
        params = dict(params or {})
        pages = 0
        seen: set[str] = set()
        cursor_path = cursor_path or (lambda d: (d.get("response_metadata") or {}).get("next_cursor"))
        while pages < max_pages:
            data = self.get_json(path, params=params)
            if not isinstance(data, dict):
                raise RuntimeError("Invalid paginated API response; collection incomplete")
            if data.get("ok") is False:
                raise RuntimeError(f"API collection failed: {data.get('error', 'unknown error')}")
            yield from data.get(items_key, []) or []
            cursor = cursor_path(data)
            if not cursor:
                return
            if str(cursor) in seen:
                raise RuntimeError("Repeated pagination cursor; collection incomplete")
            seen.add(str(cursor))
            params[cursor_param] = cursor
            pages += 1
        raise RuntimeError("Pagination limit reached; collection incomplete")
