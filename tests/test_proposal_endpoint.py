"""End-to-end tests for the non-MCP proposal HTTP surface (main.py,
TECH-5872/5875): ``POST /proposals`` and ``GET /proposals/pending``.

Own file, mirroring ``tests/test_approval_endpoint.py``'s Postgres fixture
block and fake-auth-provider idiom. Auth is exercised against
``main._auth_provider`` directly (a fake standing in for FastMCP's real
``MultiAuth.verify_token``), not a real Okta/agent-jwt signing round trip
-- these tests are about main.py's OWN gate logic on these two routes.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.applications import Starlette
from starlette.routing import Route

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


def _test_database_url() -> str:
    url = os.environ.get("DATABASE_URL", _DEFAULT_TEST_DATABASE_URL)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def _can_connect(url: str) -> bool:
    try:
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def database_url() -> str:
    url = _test_database_url()
    if not asyncio.run(_can_connect(url)):
        pytest.skip(
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise the proposal-endpoint tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
    env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
    for args in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )


@pytest_asyncio.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(database_url)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE proposal_holds RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


_MOCK_OIDC_CONFIG = MagicMock()
_OIDC_PATCH = patch(
    "fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration",
    return_value=_MOCK_OIDC_CONFIG,
)
_ENV_PATCH = patch.dict(
    os.environ,
    {
        "OKTA_ISSUER_URL": "https://example.okta.com/oauth2/default",
        "OKTA_CLIENT_ID": "test-id",
        "OKTA_CLIENT_SECRET": "test-secret",
        "BASE_URL": "http://localhost:8080",
        "MCP_JWT_SECRET": "test-jwt-secret",
        "AGENT_JWT_SECRET": "test-agent-jwt-secret-long-enough-for-hs256",
    },
)


def _import_main() -> Any:
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


class _FakeAccessToken:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims


class _FakeInteractiveOnlyProvider:
    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") == "agent-jwt":
            return None
        return found


class _FakeAuthProvider:
    def __init__(self) -> None:
        self.tokens: dict[str, _FakeAccessToken] = {}
        self.server = _FakeInteractiveOnlyProvider(self)

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        return self.tokens.get(token)


def _interactive_token(owner_email: str) -> _FakeAccessToken:
    return _FakeAccessToken({"iss": "https://agent-comms.example/mcp", "email": owner_email})


def _agent_jwt_token(
    sub: str, *, scopes: list[str] | None = None, owner_sub: str | None = None
) -> _FakeAccessToken:
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else [],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    return _FakeAccessToken(claims)


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest_asyncio.fixture
async def client(
    main: Any, test_session_factory: async_sessionmaker[AsyncSession]
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    fake_provider = _FakeAuthProvider()
    app = Starlette(
        routes=[
            Route("/proposals", main.submit_proposal, methods=["POST"]),
            Route("/proposals/pending", main.list_pending_proposals, methods=["GET"]),
        ]
    )
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(main, "_auth_provider", fake_provider),
        patch.object(main, "_okta_provider", fake_provider.server),
        patch("main.get_session_factory", return_value=test_session_factory),
    ):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            yield http_client, fake_provider


_PROPOSAL_BODY = {
    "kind": "linear_progress_update",
    "action": {"action_type": "open_ticket", "target_id": "TECH-1"},
    "rationale": "because reasons",
    "confidence": "medium",
    "importance": "medium",
    "impact": "medium",
    "target_fingerprint": "fp1",
}


class TestSubmitAuthGate:
    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.post("/proposals", json=_PROPOSAL_BODY)
        assert resp.status_code == 401

    async def test_unverifiable_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer garbage"}
        )
        assert resp.status_code == 401

    async def test_interactive_token_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Opposite gate from ``/approvals/*``: proposals are submitted BY
        BOTS, not humans -- an interactive/Okta caller must be rejected."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_without_required_scope_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_with_required_scope_is_allowed(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["proposed_by_bot_id"] == "bot-1"


class TestSubmitProposal:
    async def test_missing_owner_sub_and_unregistered_bot_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token("bot-1", scopes=["comms:proposals:write"])
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "owner_sub_unresolvable"

    async def test_missing_action_target_id_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "action": {"action_type": "open_ticket"}}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422

    async def test_invalid_confidence_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "confidence": "extremely-sure"}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422

    async def test_priority_in_body_is_ignored(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {
            **_PROPOSAL_BODY,
            "action": {**_PROPOSAL_BODY["action"], "action_type": "close_ticket"},
            "priority": "low",
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        # close_ticket server-derives "high" regardless of the caller's
        # top-level "priority": "low" in the request body.
        assert resp.json()["priority"] == "high"

    async def test_rate_limit_exceeded_returns_429(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        import service

        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        for i in range(service.MAX_PROPOSALS_PER_BOT_PER_WINDOW):
            body = {
                **_PROPOSAL_BODY,
                "action": {**_PROPOSAL_BODY["action"], "target_id": f"TECH-{i}"},
            }
            resp = await http_client.post(
                "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
            )
            assert resp.status_code == 200

        body = {
            **_PROPOSAL_BODY,
            "action": {
                **_PROPOSAL_BODY["action"],
                "target_id": f"TECH-{service.MAX_PROPOSALS_PER_BOT_PER_WINDOW}",
            },
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 429


class TestListPendingAuthGate:
    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.get("/proposals/pending")
        assert resp.status_code == 401

    async def test_agent_jwt_token_returns_403_even_with_comms_admin_scope(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Same hard interactive-only gate as ``GET /approvals/pending`` --
        a bot's agent-jwt token, even with ``comms:admin``, can't list."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-bot", scopes=["comms:admin", "comms:proposals:write"]
        )
        resp = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403


class TestListPendingProposals:
    async def test_owner_filtering(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        provider.tokens["other-human-token"] = _interactive_token("owner-b@example.com")

        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200

        own = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert own.status_code == 200
        assert len(own.json()["proposals"]) == 1

        other = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer other-human-token"}
        )
        assert other.status_code == 200
        assert other.json()["proposals"] == []

    async def test_approved_proposals_excluded(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        body = {
            **_PROPOSAL_BODY,
            "action": {
                **_PROPOSAL_BODY["action"],
                "source_message_url": "https://slack.example/p1",
            },
        }
        submit_resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert submit_resp.status_code == 200
        assert submit_resp.json()["status"] == "approved"

        pending = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert pending.json()["proposals"] == []
