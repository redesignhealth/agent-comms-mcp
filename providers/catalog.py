"""``catalog_get``: read one row of Arcadia's opportunity catalog (TECH-9214).

A bot proposing a ``catalog_candidate`` needs to know whether its target already
exists (create versus upsert) and, for a concept-market pair, the version it is
editing (``base_version``). This read-only tool asks Arcadia:

    GET {ARCADIA_CATALOG_INTAKE_URL}/api/v1/catalog/v1/rows/{target_key}

with a short-lived service token the board gets by exchanging a long-lived key:

    POST {ARCADIA_CATALOG_INTAKE_URL}/api/v1/service/v1/token  {"key": "..."}
    -> {"access_token": "...", "token_type": "bearer", "expires_in": <seconds>}

OFF unless both ``ARCADIA_CATALOG_INTAKE_URL`` and ``ARCADIA_CATALOG_INTAKE_KEY``
are set (the tool then answers ``catalog_get is not configured``). The key and
token are never returned or logged. Rate-limited per bot (in memory, per process).

Returns ``{"exists", "version", "content"}``: ``content`` is the row in the
version-2 candidate payload shape (``proposals_schema`` explains it), ``version``
the current version number of a pair (``null`` for a concept or a missing row).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from collections import deque
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from providers.proposals import _require_bot_sub

logger = logging.getLogger(__name__)

catalog_server: FastMCP[Any] = FastMCP("catalog")

URL_ENV = "ARCADIA_CATALOG_INTAKE_URL"
KEY_ENV = "ARCADIA_CATALOG_INTAKE_KEY"
RATE_ENV = "CATALOG_GET_RATE_PER_MINUTE"
DEFAULT_RATE_PER_MINUTE = 30
MAX_RATE_PER_MINUTE = 600
TOKEN_PATH = "/api/v1/service/v1/token"
ROWS_PATH = "/api/v1/catalog/v1/rows/"
REFRESH_MARGIN = 120.0
MAX_EXPIRES_IN = 86400
TIMEOUT = httpx.Timeout(15.0, connect=5.0)
MAX_TARGET_LENGTH = 300
MAX_CONTENT_BYTES = 256 * 1024

_SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_TARGET_RE = re.compile(rf"concept:{_SLUG}|pair:{_SLUG}:[A-Z]{{2}}")

_NOT_CONFIGURED = "catalog_get is not configured"
_UNAVAILABLE = "catalog_unavailable: Arcadia could not be read; try again later"


def build_client() -> httpx.AsyncClient:
    """The HTTP client for Arcadia (tailnet proxy mounts when configured). Tests
    replace this."""
    from proposal_apply_http_client import tailnet_proxy_mounts

    return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, mounts=tailnet_proxy_mounts())


def _config() -> tuple[str, str] | None:
    url = os.environ.get(URL_ENV, "").strip()
    key = os.environ.get(KEY_ENV, "").strip()
    if not url or not key:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.hostname or parts.scheme not in ("https", "http"):
        return None
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        return None
    return url.rstrip("/"), key


class _TokenCache:
    """One exchanged token, refreshed ``REFRESH_MARGIN`` before it expires."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = asyncio.Lock()
        self._ident: tuple[str, str] | None = None
        self._token: str | None = None
        self._refresh_at = 0.0

    def invalidate(self, token: str) -> None:
        if self._token == token:
            self._token = None

    async def get(
        self, client: httpx.AsyncClient, url: str, key: str, *, force: bool = False
    ) -> str | None:
        async with self._lock:
            ident = (url, key)
            if (
                not force
                and self._ident == ident
                and self._token is not None
                and self._clock() < self._refresh_at
            ):
                return self._token
            self._token, self._ident = None, ident
            try:
                resp = await client.post(url + TOKEN_PATH, json={"key": key})
            except httpx.HTTPError as exc:
                logger.warning("catalog_get: token exchange failed: %s", type(exc).__name__)
                return None
            parsed = _parse_exchange(resp)
            if parsed is None:
                logger.warning("catalog_get: token exchange refused (HTTP %s)", resp.status_code)
                return None
            token, lifetime = parsed
            margin = REFRESH_MARGIN if lifetime > 2 * REFRESH_MARGIN else lifetime / 2
            self._token, self._refresh_at = token, self._clock() + lifetime - margin
            return token


def _parse_exchange(resp: httpx.Response) -> tuple[str, int] | None:
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    token, kind, expires = data.get("access_token"), data.get("token_type"), data.get("expires_in")
    if (
        not isinstance(token, str)
        or not token
        or any(c.isspace() for c in token)
        or not isinstance(kind, str)
        or kind.lower() != "bearer"
        or isinstance(expires, bool)
        or not isinstance(expires, int)
        or not 0 < expires <= MAX_EXPIRES_IN
    ):
        return None
    return token, expires


_tokens = _TokenCache()
_calls: dict[str, deque[float]] = {}


def _rate_limit() -> int:
    raw = os.environ.get(RATE_ENV, "").strip()
    try:
        value = int(raw) if raw else DEFAULT_RATE_PER_MINUTE
    except ValueError:
        return DEFAULT_RATE_PER_MINUTE
    return min(max(value, 1), MAX_RATE_PER_MINUTE)


def _check_rate(bot: str, now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    window = _calls.setdefault(bot, deque())
    while window and now - window[0] >= 60.0:
        window.popleft()
    if len(window) >= _rate_limit():
        raise ToolError("rate_limited: too many catalog_get calls; wait a minute and retry")
    window.append(now)


def project(data: Any) -> dict[str, Any] | None:
    """Only ``exists``, ``version`` and ``content`` from Arcadia's reply, checked;
    ``None`` if it is not that shape."""
    if not isinstance(data, dict):
        return None
    exists, version, content = data.get("exists"), data.get("version"), data.get("content")
    if not isinstance(exists, bool):
        return None
    if version is not None and (isinstance(version, bool) or not isinstance(version, int)):
        return None
    if content is not None and not isinstance(content, dict):
        return None
    return {"exists": exists, "version": version, "content": content}


@catalog_server.tool
async def get(target_key: str) -> dict[str, Any]:
    """Read-only: the current state of one catalog row in Arcadia, so you can
    choose ``create`` or ``upsert`` and set ``base_version`` before calling
    ``proposals_submit(kind="catalog_candidate")``.

    ``target_key`` is ``concept:<slug>`` or ``pair:<concept-slug>:<MARKET>``
    (the same form as the proposal's ``target_id``). Returns ``{"exists": bool,
    "version": int | null, "content": object | null}``: ``exists`` false means
    propose a ``create``; for a pair ``version`` is the version number to send as
    ``base_version`` on an ``upsert``; ``content`` is the row in the version-2
    candidate payload shape (see ``proposals_schema``). A deleted row reads as not
    existing. Available only when the board is configured for it (otherwise
    ``catalog_get is not configured``); rate-limited per bot.
    """
    bot = _require_bot_sub()
    if not isinstance(target_key, str) or not (
        len(target_key) <= MAX_TARGET_LENGTH and _TARGET_RE.fullmatch(target_key)
    ):
        raise ToolError(
            "invalid_request: target_key must be concept:<slug> or pair:<concept-slug>:<MARKET>"
        )
    config = _config()
    if config is None:
        raise ToolError(_NOT_CONFIGURED)
    _check_rate(bot)
    url, key = config
    try:
        async with build_client() as client, asyncio.timeout(30.0):
            token = await _tokens.get(client, url, key)
            if token is None:
                raise ToolError(_UNAVAILABLE)
            resp = await _read(client, url, token, target_key)
            if resp.status_code == 401:
                _tokens.invalidate(token)
                token = await _tokens.get(client, url, key, force=True)
                if token is None:
                    raise ToolError(_UNAVAILABLE)
                resp = await _read(client, url, token, target_key)
    except (httpx.HTTPError, TimeoutError, ValueError) as exc:
        logger.warning("catalog_get: read failed: %s", type(exc).__name__)
        raise ToolError(_UNAVAILABLE) from None
    if resp.status_code == 404:
        return {"exists": False, "version": None, "content": None}
    if resp.status_code != 200 or len(resp.content) > MAX_CONTENT_BYTES:
        logger.warning("catalog_get: Arcadia answered HTTP %s", resp.status_code)
        raise ToolError(_UNAVAILABLE)
    try:
        shaped = project(resp.json())
    except ValueError:
        shaped = None
    if shaped is None:
        logger.warning("catalog_get: Arcadia's reply was not the expected shape")
        raise ToolError(_UNAVAILABLE)
    return shaped


async def _read(client: httpx.AsyncClient, url: str, token: str, target_key: str) -> httpx.Response:
    return await client.get(
        url + ROWS_PATH + quote(target_key, safe=":"),
        headers={"Authorization": f"Bearer {token}"},
    )
