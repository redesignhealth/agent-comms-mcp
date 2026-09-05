"""End-to-end tests for the proposals MCP tool surface (providers/proposals.py)
-- TECH-6018 follow-up.

Mirrors ``tests/test_comms_tools.py``'s real-Postgres + in-memory
``fastmcp.Client`` idiom: every tool call goes through the REAL mounted
server (auth middleware, scope enforcement, tool dispatch), never the raw
Python function. ``providers.proposals.get_session_factory`` is patched to
the test database's session factory (the documented test-injection seam,
db.py's docstring).

Deliberately does NOT re-test business logic already covered by
``tests/test_proposal_service.py`` (dedup, rate limiting, the TECH-5877
judge) -- these tests are about the TRANSPORT layer: scope enforcement, the
new sender-only listing tools, and that a proposing bot need not be a
board-registered agent (unlike every ``comms_*`` tool).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from fastmcp import Client
from fastmcp.exceptions import ToolError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from service import decide_proposal

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"

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
    """Import a fresh ``main`` module under the OIDC/env patches."""
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


# --- Database fixtures (mirrors tests/test_comms_tools.py) ------------------------


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
            "(or set DATABASE_URL) to exercise the real-database tool tests."
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
        await conn.execute(
            text("TRUNCATE TABLE proposal_holds, audit_log RESTART IDENTITY CASCADE")
        )
    yield


@pytest.fixture
def test_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


# --- MCP client helpers -------------------------------------------------------------


def _token(sub: str, *, scopes: list[str] | None = None, owner_sub: str | None = None) -> MagicMock:
    """A minimal agent-jwt-shaped ``AccessToken`` stand-in for a proposing bot."""
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else ["comms:proposals:write"],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    token = MagicMock()
    token.claims = claims
    token.scopes = []
    token.client_id = sub
    return token


async def _call(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    tool_name: str,
    args: dict[str, Any] | None = None,
) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.proposals.get_access_token", return_value=token),
        patch("providers.proposals.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data


@pytest.fixture
def main() -> Any:
    return _import_main()


def _action(
    action_type: str = "open_ticket", target_id: str = "TECH-1234", **extra: Any
) -> dict[str, Any]:
    return {"action_type": action_type, "target_id": target_id, **extra}


async def _submit(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    *,
    bot_sub: str = "bot-1",
    owner_sub: str = "owner-a@example.com",
    action: dict[str, Any] | None = None,
    target_fingerprint: str = "deadbeef",
) -> dict[str, Any]:
    token = _token(bot_sub, owner_sub=owner_sub)
    result: dict[str, Any] = await _call(
        main,
        test_session_factory,
        token,
        "proposals_submit",
        {
            "kind": "linear_progress_update",
            "action": action if action is not None else _action(),
            "rationale": "because reasons",
            "confidence": "medium",
            "importance": "medium",
            "impact": "medium",
            "target_fingerprint": target_fingerprint,
        },
    )
    return result


# --- Registry / scope enforcement ----------------------------------------------


class TestScopeEnforcement:
    async def test_all_five_tools_are_registry_enrolled(self, main: Any) -> None:
        from scopes import TOOL_SCOPES

        tools = await main.mcp.list_tools()
        mounted = {t.name for t in tools}
        expected = {
            "proposals_submit",
            "proposals_get",
            "proposals_list_pending",
            "proposals_list_history",
            "proposals_withdraw",
        }
        assert expected <= mounted
        assert expected <= set(TOOL_SCOPES)

    async def test_missing_scope_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("scope-test-bot", scopes=[])
        with pytest.raises(ToolError, match="requires elevated permissions"):
            await _call(main, test_session_factory, token, "proposals_list_pending")

    async def test_unregistered_bot_can_still_submit(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Unlike every ``comms_*`` tool, a proposing bot need not be a
        board-registered ``Agent`` -- this is a deliberate, pre-existing
        distinction (see ``providers/proposals.py``'s module docstring)."""
        result = await _submit(main, test_session_factory, bot_sub="never-registered-bot")
        assert result["status"] in ("pending", "applied", "apply_failed")


# --- Submit / get / withdraw round-trips ----------------------------------------


class TestSubmitGetWithdraw:
    async def test_submit_then_get_round_trips(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-rt")
        token = _token("bot-rt")
        fetched = await _call(
            main,
            test_session_factory,
            token,
            "proposals_get",
            {"proposal_id": submitted["proposal_id"]},
        )
        assert fetched["proposal_id"] == submitted["proposal_id"]

    async def test_get_another_bots_proposal_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-owner")
        other_token = _token("bot-intruder")
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                other_token,
                "proposals_get",
                {"proposal_id": submitted["proposal_id"]},
            )

    async def test_withdraw_own_pending_proposal(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-withdraw")
        token = _token("bot-withdraw")
        result = await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": submitted["proposal_id"], "reason": "no longer needed"},
        )
        assert result["status"] == "withdrawn"

    async def test_withdraw_allows_empty_string_reason(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Matches ``withdraw_proposal_route``'s HTTP semantics exactly --
        an empty-string ``reason`` is explicitly permitted, unlike the
        general ``validate_proposal_string_field`` helper used elsewhere."""
        submitted = await _submit(main, test_session_factory, bot_sub="bot-empty-reason")
        token = _token("bot-empty-reason")
        result = await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": submitted["proposal_id"], "reason": ""},
        )
        assert result["status"] == "withdrawn"

    async def test_withdraw_reason_over_cap_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        import service

        submitted = await _submit(main, test_session_factory, bot_sub="bot-long-reason")
        token = _token("bot-long-reason")
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                token,
                "proposals_withdraw",
                {
                    "proposal_id": submitted["proposal_id"],
                    "reason": "x" * (service.MAX_DECISION_REASON_LENGTH + 1),
                },
            )


# --- list_pending / list_history -------------------------------------------------


class TestListPendingAndHistory:
    async def test_list_pending_scoped_to_own_bot(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _submit(main, test_session_factory, bot_sub="bot-mine", action=_action(target_id="A"))
        await _submit(
            main, test_session_factory, bot_sub="bot-other", action=_action(target_id="B")
        )

        token = _token("bot-mine")
        result = await _call(main, test_session_factory, token, "proposals_list_pending")
        subs = {p["proposed_by_bot_id"] for p in result["proposals"]}
        assert subs <= {"bot-mine"}
        assert len(result["proposals"]) >= 1

    async def test_list_history_excludes_pending(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        bot_sub = "bot-history"
        await _submit(main, test_session_factory, bot_sub=bot_sub, action=_action(target_id="C"))

        token = _token(bot_sub)
        history = await _call(main, test_session_factory, token, "proposals_list_history")
        assert history["proposals"] == []

        pending = await _call(main, test_session_factory, token, "proposals_list_pending")
        assert len(pending["proposals"]) == 1

    async def test_list_history_includes_human_decided_and_withdrawn(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        bot_sub = "bot-history-2"
        owner_sub = "owner-history-2@example.com"
        rejected = await _submit(
            main,
            test_session_factory,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            action=_action(target_id="D"),
        )
        withdrawn = await _submit(
            main,
            test_session_factory,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            action=_action(target_id="E"),
        )

        await decide_proposal(
            session,
            approver_sub=owner_sub,
            hold_id=uuid.UUID(rejected["proposal_id"]),
            decision="reject",
            decision_note="not appropriate",
        )
        token = _token(bot_sub)
        await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": withdrawn["proposal_id"]},
        )

        history = await _call(main, test_session_factory, token, "proposals_list_history")
        by_id = {p["proposal_id"]: p for p in history["proposals"]}
        assert by_id[rejected["proposal_id"]]["status"] == "rejected"
        assert by_id[withdrawn["proposal_id"]]["status"] == "withdrawn"

    async def test_list_history_redacts_human_decider(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        bot_sub = "bot-redact"
        owner_sub = "owner-redact@example.com"
        submitted = await _submit(
            main,
            test_session_factory,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            action=_action(target_id="F"),
        )
        await decide_proposal(
            session,
            approver_sub=owner_sub,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not appropriate",
        )

        token = _token(bot_sub)
        history = await _call(main, test_session_factory, token, "proposals_list_history")
        assert len(history["proposals"]) == 1
        assert "decided_by_actor_id" not in history["proposals"][0]
