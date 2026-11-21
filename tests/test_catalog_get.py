"""TECH-9214: ``catalog_get`` -- a read-only view of one Arcadia catalog row."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from providers import catalog
from scopes import PROPOSAL_SUBMIT_SCOPE, TOOL_SCOPES
from tests.test_proposal_tools import _ENV_PATCH, _OIDC_PATCH, _import_main

URL = "https://arcadia.example.test/api/v1"
KEY = "rai_svc_fake_not_a_secret"
BOT = "catalog-agent"


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(catalog, "_tokens", catalog._TokenCache())
    monkeypatch.setattr(catalog, "_calls", {})
    monkeypatch.setenv(catalog.URL_ENV, URL)
    monkeypatch.setenv(catalog.KEY_ENV, KEY)
    monkeypatch.delenv(catalog.RATE_ENV, raising=False)


def _token(sub: str = BOT) -> MagicMock:
    token = MagicMock()
    token.claims = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": [PROPOSAL_SUBMIT_SCOPE],
        "owner_sub": "owner@example.com",
    }
    token.scopes = []
    token.client_id = sub
    return token


class Arcadia:
    """A fake Arcadia: token exchange plus the rows endpoint."""

    def __init__(
        self,
        row: Callable[[httpx.Request], httpx.Response] | None = None,
        exchange_status: int = 200,
    ) -> None:
        self.row = row or (
            lambda r: httpx.Response(
                200,
                json={
                    "target_key": "pair:a:US",
                    "target_type": "pair",
                    "exists": True,
                    "status": "active",
                    "version": 3,
                    "payload": {"slug": "a"},
                },
            )
        )
        self.exchange_status = exchange_status
        self.requests: list[httpx.Request] = []
        self.exchanges = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/api/v1" + catalog.TOKEN_PATH:
            self.exchanges += 1
            if self.exchange_status != 200:
                return httpx.Response(self.exchange_status)
            assert json.loads(request.content) == {"api_key": KEY}
            return httpx.Response(
                200,
                json={
                    "access_token": f"svc-{self.exchanges}",
                    "token_type": "bearer",
                    "expires_in": 900,
                },
            )
        return self.row(request)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


async def _call(main: Any, arcadia: Arcadia, key: Any, token: MagicMock | None = None) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(catalog, "build_client", arcadia.client),
        patch("main.get_access_token", return_value=token or _token()),
        patch("providers.proposals.get_access_token", return_value=token or _token()),
    ):
        async with Client(main.mcp) as client:
            return (await client.call_tool("catalog_get", {"target_key": key})).data


class TestRegistration:
    async def test_mounted_read_only_with_the_bot_scope(self, main: Any) -> None:
        assert "catalog_get" in {t.name for t in await main.mcp.list_tools()}
        assert TOOL_SCOPES["catalog_get"] == PROPOSAL_SUBMIT_SCOPE


class TestReads:
    async def test_returns_the_six_fields(self, main: Any) -> None:
        arcadia = Arcadia()
        out = await _call(main, arcadia, "pair:remote-patient-monitoring:US")
        assert out == {
            "target_key": "pair:a:US",
            "target_type": "pair",
            "exists": True,
            "status": "active",
            "version": 3,
            "payload": {"slug": "a"},
        }
        read = arcadia.requests[-1]
        assert str(read.url) == f"{URL}/catalog/v1/rows/pair:remote-patient-monitoring:US"
        assert read.headers["authorization"] == "Bearer svc-1"

    async def test_missing_row_is_arcadias_exists_false(self, main: Any) -> None:
        arcadia = Arcadia(
            row=lambda r: httpx.Response(
                200, json={"exists": False, "status": None, "version": None, "payload": None}
            )
        )
        out = await _call(main, arcadia, "concept:nope")
        assert out["exists"] is False
        assert (out["status"], out["version"], out["payload"]) == (None, None, None)

    async def test_a_soft_deleted_target_is_exists_true_status_deleted(self, main: Any) -> None:
        arcadia = Arcadia(
            row=lambda r: httpx.Response(
                200,
                json={
                    "target_key": "concept:old",
                    "target_type": "concept",
                    "exists": True,
                    "status": "deleted",
                    "version": None,
                    "payload": {"slug": "old"},
                },
            )
        )
        out = await _call(main, arcadia, "concept:old")
        assert (out["exists"], out["status"], out["version"]) == (True, "deleted", None)

    async def test_422_invalid_target_key_is_an_invalid_request(self, main: Any) -> None:
        arcadia = Arcadia(
            row=lambda r: httpx.Response(
                422, json={"detail": {"code": "INVALID_TARGET_KEY", "message": "bad"}}
            )
        )
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(main, arcadia, "concept:a")

    @pytest.mark.parametrize("body", [{"detail": "Not Found"}, {"exists": False}, None])
    async def test_a_404_is_an_unavailable_lookup_never_exists_false(
        self, main: Any, body: Any
    ) -> None:
        """404 means the route is not deployed; reading it as "no such row" would
        make an agent propose a create on a row that may exist."""
        arcadia = Arcadia(
            row=lambda r: httpx.Response(404, json=body) if body else httpx.Response(404)
        )
        with pytest.raises(ToolError, match="catalog_unavailable") as caught:
            await _call(main, arcadia, "concept:nope")
        assert "do not propose a create" in str(caught.value)

    async def test_only_the_three_fields_are_returned(self, main: Any) -> None:
        arcadia = Arcadia(
            row=lambda r: httpx.Response(
                200,
                json={
                    "exists": True,
                    "status": "active",
                    "version": None,
                    "payload": {},
                    "token": "leak",
                    "x": 1,
                },
            )
        )
        out = await _call(main, arcadia, "concept:a")
        assert set(out) == {
            "target_key",
            "target_type",
            "exists",
            "status",
            "version",
            "payload",
        }

    async def test_the_token_is_exchanged_once_and_cached(self, main: Any) -> None:
        arcadia = Arcadia()
        for _ in range(3):
            await _call(main, arcadia, "concept:a")
        assert arcadia.exchanges == 1

    async def test_a_401_re_exchanges_once_and_retries(self, main: Any) -> None:
        seen: list[str] = []

        def row(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["authorization"])
            if len(seen) == 1:
                return httpx.Response(401)
            return httpx.Response(
                200, json={"exists": False, "status": None, "version": None, "payload": None}
            )

        arcadia = Arcadia(row=row)
        out = await _call(main, arcadia, "concept:a")
        assert out["exists"] is False
        assert seen == ["Bearer svc-1", "Bearer svc-2"]

    async def test_a_second_401_is_unavailable(self, main: Any) -> None:
        with pytest.raises(ToolError, match="catalog_unavailable"):
            await _call(main, Arcadia(row=lambda r: httpx.Response(401)), "concept:a")


class TestFailuresAreGeneric:
    @pytest.mark.parametrize(
        "row",
        [
            lambda r: httpx.Response(500, text=f"boom {KEY}"),
            lambda r: httpx.Response(200, text="not json"),
            lambda r: httpx.Response(200, json=[1]),
            lambda r: httpx.Response(200, json={"exists": "yes"}),
            lambda r: httpx.Response(200, json={"exists": True, "version": "3"}),
            lambda r: httpx.Response(200, json={"exists": True, "payload": []}),
            lambda r: httpx.Response(200, json={"exists": True, "status": "gone"}),
            lambda r: httpx.Response(200, json={"exists": True, "target_type": "table"}),
        ],
    )
    async def test_unusable_replies(self, main: Any, row: Callable[..., httpx.Response]) -> None:
        with pytest.raises(ToolError) as caught:
            await _call(main, Arcadia(row=row), "concept:a")
        assert str(caught.value).startswith("catalog_unavailable")
        assert KEY not in str(caught.value)

    @pytest.mark.parametrize("status", [400, 401, 403, 500])
    async def test_refused_exchange(self, main: Any, status: int) -> None:
        with pytest.raises(ToolError, match="catalog_unavailable") as caught:
            await _call(main, Arcadia(exchange_status=status), "concept:a")
        assert KEY not in str(caught.value)

    async def test_transport_error(self, main: Any) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot reach {KEY}")

        with pytest.raises(ToolError) as caught:
            await _call(main, Arcadia(row=boom), "concept:a")
        assert str(caught.value).startswith("catalog_unavailable") and KEY not in str(caught.value)


class TestOffUnlessConfigured:
    async def test_a_key_without_the_service_prefix_is_not_configured(
        self, main: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(catalog.KEY_ENV, "something-else")
        with pytest.raises(ToolError, match="not configured"):
            await _call(main, Arcadia(), "concept:a")

    @pytest.mark.parametrize("unset", [catalog.URL_ENV, catalog.KEY_ENV])
    async def test_missing_config(
        self, main: Any, monkeypatch: pytest.MonkeyPatch, unset: str
    ) -> None:
        monkeypatch.delenv(unset)
        arcadia = Arcadia()
        with pytest.raises(ToolError, match="not configured"):
            await _call(main, arcadia, "concept:a")
        assert arcadia.requests == []

    @pytest.mark.parametrize("url", ["http://arcadia.example.test", "ftp://x", "nope", ""])
    async def test_unsafe_url_is_not_configured(
        self, main: Any, monkeypatch: pytest.MonkeyPatch, url: str
    ) -> None:
        monkeypatch.setenv(catalog.URL_ENV, url)
        with pytest.raises(ToolError, match="not configured"):
            await _call(main, Arcadia(), "concept:a")

    async def test_loopback_http_is_allowed(
        self, main: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(catalog.URL_ENV, "http://localhost:8000/api/v1")
        assert (await _call(main, Arcadia(), "concept:a"))["exists"] is True


class TestInput:
    @pytest.mark.parametrize(
        "key",
        [
            "",
            "concept:",
            "Concept:a",
            "concept:a b",
            "pair:a:usa",
            "pair:a",
            "../x",
            "concept:a/b",
            "x" * 400,
            5,
        ],
    )
    async def test_bad_target_keys_never_reach_arcadia(self, main: Any, key: Any) -> None:
        arcadia = Arcadia()
        with pytest.raises(ToolError):
            await _call(main, arcadia, key)
        assert arcadia.requests == []

    async def test_interactive_callers_are_refused(self, main: Any) -> None:
        token = _token()
        token.claims = {"iss": "okta", "sub": "human@example.com"}
        with pytest.raises(ToolError):
            await _call(main, Arcadia(), "concept:a", token)


class TestRateLimit:
    async def test_per_bot_limit(self, main: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(catalog.RATE_ENV, "2")
        arcadia = Arcadia()
        await _call(main, arcadia, "concept:a")
        await _call(main, arcadia, "concept:a")
        with pytest.raises(ToolError, match="rate_limited"):
            await _call(main, arcadia, "concept:a")
        # another bot has its own allowance
        assert (await _call(main, arcadia, "concept:a", _token("other-bot")))["exists"]

    def test_window_slides(self) -> None:
        catalog._calls.clear()
        for t in (0.0, 1.0):
            catalog._check_rate("b", t)
        import os

        os.environ[catalog.RATE_ENV] = "2"
        try:
            with pytest.raises(ToolError):
                catalog._check_rate("b", 30.0)
            catalog._check_rate("b", 61.0)  # the first call left the window
        finally:
            del os.environ[catalog.RATE_ENV]

    @pytest.mark.parametrize(
        ("raw", "expected"), [("", 30), ("x", 30), ("0", 1), ("9999", 600), ("5", 5)]
    )
    def test_limit_parsing(self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: int) -> None:
        monkeypatch.setenv(catalog.RATE_ENV, raw)
        assert catalog._rate_limit() == expected


class TestTokenCache:
    async def test_refreshes_two_minutes_early(self) -> None:
        now = [0.0]
        cache = catalog._TokenCache(lambda: now[0])
        arcadia = Arcadia()
        async with arcadia.client() as client:
            assert await cache.get(client, URL, KEY) == "svc-1"
            now[0] = 900 - 121
            assert await cache.get(client, URL, KEY) == "svc-1"
            now[0] = 900 - 119
            assert await cache.get(client, URL, KEY) == "svc-2"


class TestExchangeErrors:
    async def _cache_get(self, cache: Any, arcadia: Arcadia) -> str | None:
        async with arcadia.client() as client:
            return await cache.get(client, URL, KEY)

    async def test_a_rejected_key_is_not_retried_in_a_loop(self) -> None:
        now = [0.0]
        cache = catalog._TokenCache(lambda: now[0])
        arcadia = Arcadia(exchange_status=401)
        for _ in range(4):
            assert await self._cache_get(cache, arcadia) is None
        assert arcadia.exchanges == 1
        now[0] = 301.0
        await self._cache_get(cache, arcadia)
        assert arcadia.exchanges == 2

    @pytest.mark.parametrize(("status", "wait"), [(429, 30.0), (503, 15.0)])
    async def test_429_and_503_back_off(self, status: int, wait: float) -> None:
        now = [0.0]
        cache = catalog._TokenCache(lambda: now[0])
        arcadia = Arcadia(exchange_status=status)
        assert await self._cache_get(cache, arcadia) is None
        now[0] = wait - 1
        assert await self._cache_get(cache, arcadia) is None
        assert arcadia.exchanges == 1
        now[0] = wait + 1
        await self._cache_get(cache, arcadia)
        assert arcadia.exchanges == 2


class TestSchemaGuide:
    async def test_proposals_schema_guide_points_at_catalog_get(self) -> None:
        from providers import proposal_schemas

        guide = proposal_schemas.CATALOG_CANDIDATE_GUIDE
        assert "catalog_get" in guide and "base_version" in guide
        for text in ("payload", "status", "deleted", "restores", "never a create"):
            assert text in guide
