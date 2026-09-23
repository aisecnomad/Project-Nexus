"""Small HTTP helper with retries, rate-limit handling and pagination helpers.

Kept deliberately thin so connectors read like the API docs they implement.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

import requests

from shadowscan import __version__

log = logging.getLogger("shadowscan.http")

DEFAULT_TIMEOUT = 30
RETRY_STATUSES = {429, 500, 502, 503, 504}


class HttpError(RuntimeError):
    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status} for {url}: {body[:300]}")


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

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = self._url(path)
        kwargs.setdefault("timeout", self.timeout)
        attempt = 0
        while True:
            attempt += 1
            self.requests_made += 1
            resp = self.session.request(method, url, **kwargs)
            if resp.status_code in RETRY_STATUSES and attempt <= self.max_retries:
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else min(2**attempt, 30)
                # GitHub style secondary rate limit
                reset = resp.headers.get("X-RateLimit-Reset")
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining == "0" and reset and reset.isdigit():
                    delay = max(delay, min(int(reset) - time.time() + 1, 120))
                log.warning("HTTP %s from %s; retrying in %.0fs (attempt %d)", resp.status_code, url, delay, attempt)
                time.sleep(delay)
                continue
            if resp.status_code >= 400:
                raise HttpError(resp.status_code, url, resp.text)
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
        """GET that swallows 403/404 (missing permission / feature) and returns ``default``."""
        try:
            return self.get_json(path, **kwargs)
        except HttpError as exc:
            if exc.status in (ok_statuses or {401, 403, 404, 405, 422}):
                log.debug("ignoring HTTP %s for %s", exc.status, exc.url)
                return default
            raise

    # ------------------------------------------------------------ paginators
    def paginate_link(self, path: str, params: dict[str, Any] | None = None, item_key: str | None = None, max_pages: int = 1000) -> Iterator[Any]:
        """RFC 5988 ``Link: rel=next`` pagination (GitHub, GitLab)."""
        url: str | None = self._url(path)
        pages = 0
        while url and pages < max_pages:
            resp = self.get(url, params=params if pages == 0 else None)
            data = resp.json()
            items = data.get(item_key, []) if item_key and isinstance(data, dict) else data
            if isinstance(items, list):
                yield from items
            else:
                yield items
            url = resp.links.get("next", {}).get("url")
            pages += 1

    def paginate_odata(self, path: str, params: dict[str, Any] | None = None, max_pages: int = 1000) -> Iterator[dict[str, Any]]:
        """Microsoft Graph / OData ``@odata.nextLink`` pagination."""
        url: str | None = self._url(path)
        pages = 0
        while url and pages < max_pages:
            data = self.get_json(url, params=params if pages == 0 else None)
            if not isinstance(data, dict):
                return
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")
            pages += 1

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
        while pages < max_pages:
            if method == "POST":
                payload = dict(body or {})
                if params.get(token_param):
                    payload[token_param] = params[token_param]
                data = self.post_json(path, json=payload)
            else:
                data = self.get_json(path, params=params)
            if not isinstance(data, dict):
                return
            yield from data.get(items_key, []) or []
            token = data.get(token_key)
            if not token:
                return
            params[token_param] = token
            pages += 1

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
        cursor_path = cursor_path or (lambda d: (d.get("response_metadata") or {}).get("next_cursor"))
        while pages < max_pages:
            data = self.get_json(path, params=params)
            if not isinstance(data, dict):
                return
            yield from data.get(items_key, []) or []
            cursor = cursor_path(data)
            if not cursor:
                return
            params[cursor_param] = cursor
            pages += 1
