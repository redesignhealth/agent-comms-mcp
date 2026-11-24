"""BLU-31: ``catalog_capabilities`` and ``catalog_get`` for ``capability_map:<slug>`` keys."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from providers import catalog
from scopes import PROPOSAL_SUBMIT_SCOPE, TOOL_SCOPES
from tests.test_catalog_get import KEY, URL, Arcadia, _call, _fresh, _token  # noqa: F401
from tests.test_proposal_tools import _ENV_PATCH, _OIDC_PATCH, _import_main

RUBRIC = "a" * 64
LABELS = [
    {
        "capability": "11. Tools and Technology",
        "sub_capability": "Data",
        "description": "Shared data layer.",
    },
    {
        "capability": "11. Tools and Technology",
        "sub_capability": "Interoperability",
        "description": "Feeds between systems.",
    },
]


@pytest.fixture
def main() -> Any:
    return _import_main()


def _rubric(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"rubric_sha256": RUBRIC, "capabilities": LABELS})


async def _capabilities(main: Any, arcadia: Arcadia) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(catalog, "build_client", arcadia.client),
        patch("main.get_access_token", return_value=_token()),
        patch("providers.proposals.get_access_token", return_value=_token()),
    ):
        async with Client(main.mcp) as client:
            return (await client.call_tool("catalog_capabilities", {})).data


class TestCapabilities:
    async def test_mounted_read_only_with_the_bot_scope(self, main: Any) -> None:
        assert "catalog_capabilities" in {t.name for t in await main.mcp.list_tools()}
        assert TOOL_SCOPES["catalog_capabilities"] == PROPOSAL_SUBMIT_SCOPE

    async def test_returns_the_rubric_hash_and_labels(self, main: Any) -> None:
        arcadia = Arcadia(row=_rubric)
        out = await _capabilities(main, arcadia)
        assert out == {"rubric_sha256": RUBRIC, "capabilities": LABELS}
        read = arcadia.requests[-1]
        assert str(read.url) == f"{URL}/catalog/v1/capabilities"
        assert read.headers["authorization"] == "Bearer svc-1"

    async def test_extra_fields_are_dropped(self, main: Any) -> None:
        def row(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "rubric_sha256": RUBRIC,
                    "secret": "x",
                    "capabilities": [{**LABELS[0], "internal": "x"}],
                },
            )

        out = await _capabilities(main, Arcadia(row=row))
        assert out == {"rubric_sha256": RUBRIC, "capabilities": [LABELS[0]]}

    async def test_a_401_re_exchanges_once_and_retries(self, main: Any) -> None:
        calls = {"n": 0}

        def row(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(401) if calls["n"] == 1 else _rubric(request)

        arcadia = Arcadia(row=row)
        assert (await _capabilities(main, arcadia))["rubric_sha256"] == RUBRIC
        assert arcadia.exchanges == 2

    @pytest.mark.parametrize(
        "row",
        [
            lambda r: httpx.Response(404),
            lambda r: httpx.Response(503),
            lambda r: httpx.Response(200, text="not json"),
            lambda r: httpx.Response(200, json=[]),
            lambda r: httpx.Response(200, json={"rubric_sha256": "short", "capabilities": []}),
            lambda r: httpx.Response(200, json={"rubric_sha256": RUBRIC}),
            lambda r: httpx.Response(
                200, json={"rubric_sha256": RUBRIC, "capabilities": [{"capability": "x"}]}
            ),
        ],
    )
    async def test_unusable_replies_are_unavailable(self, main: Any, row: Any) -> None:
        with pytest.raises(ToolError, match="catalog_unavailable"):
            await _capabilities(main, Arcadia(row=row))

    async def test_refused_exchange_is_unavailable(self, main: Any) -> None:
        with pytest.raises(ToolError, match="catalog_unavailable"):
            await _capabilities(main, Arcadia(row=_rubric, exchange_status=401))

    async def test_not_configured(self, main: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(catalog.KEY_ENV)
        arcadia = Arcadia(row=_rubric)
        with pytest.raises(ToolError, match="not configured"):
            await _capabilities(main, arcadia)
        assert arcadia.requests == []

    async def test_shares_the_per_bot_rate_limit(
        self, main: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(catalog.RATE_ENV, "1")
        arcadia = Arcadia(row=_rubric)
        await _capabilities(main, arcadia)
        with pytest.raises(ToolError, match="rate_limited"):
            await _capabilities(main, arcadia)


class TestCapabilityMapKeys:
    async def test_catalog_get_reads_a_capability_map(self, main: Any) -> None:
        payload = {
            "schema_version": 4,
            "concept_slug": "service-line-analytics",
            "rubric_sha256": RUBRIC,
            "items": [],
        }

        def row(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "target_key": "capability_map:service-line-analytics",
                    "target_type": "capability_map",
                    "exists": True,
                    "status": "active",
                    "version": 2,
                    "payload": payload,
                },
            )

        arcadia = Arcadia(row=row)
        out = await _call(main, arcadia, "capability_map:service-line-analytics")
        assert out["target_type"] == "capability_map"
        assert (out["exists"], out["version"], out["payload"]) == (True, 2, payload)
        assert str(arcadia.requests[-1].url) == (
            f"{URL}/catalog/v1/rows/capability_map:service-line-analytics"
        )

    async def test_a_missing_map_is_exists_false(self, main: Any) -> None:
        arcadia = Arcadia(
            row=lambda r: httpx.Response(
                200,
                json={
                    "target_key": "capability_map:a",
                    "target_type": "capability_map",
                    "exists": False,
                    "status": None,
                    "version": None,
                    "payload": None,
                },
            )
        )
        out = await _call(main, arcadia, "capability_map:a")
        assert out["exists"] is False and out["target_type"] == "capability_map"

    def test_project_still_refuses_unknown_target_types(self) -> None:
        reply = {"exists": False, "status": None, "version": None, "payload": None}
        assert catalog.project({**reply, "target_type": "capability_map"}) is not None
        assert catalog.project({**reply, "target_type": "site"}) is None
