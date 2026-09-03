"""End-to-end tests for the comms MCP resource surface (providers/comms.py).

Mirrors ``tests/test_comms_tools.py``'s real-Postgres idiom (module-scoped
Alembic chain, function-scoped engine/session, autouse truncate, skip the
whole module with a clear reason if Postgres is unreachable) combined with
``tests/test_main.py``'s in-memory ``fastmcp.Client`` end-to-end idiom
(fresh ``main`` import under OIDC/env patches, ``get_access_token`` mocked
per simulated caller).

Every resource read goes through the REAL mounted server (auth middleware,
scope enforcement, resource dispatch) — never the raw Python function — so
these tests exercise the full stack TECH-5903 Phase A wired up.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from fastmcp import Client
from mcp.shared.exceptions import McpError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from schemas import MESSAGE_TYPES

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


# --- Database fixtures (mirrors tests/test_comms_tools.py) -------------------------


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
            "(or set DATABASE_URL) to exercise the real-database resource tests."
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
            text(
                "TRUNCATE TABLE audit_log, messages, participants, conversations, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


@pytest.fixture
def test_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


# --- MCP client helpers -------------------------------------------------------------


def _token(
    sub: str,
    *,
    scopes: list[str] | None = None,
) -> MagicMock:
    """A minimal agent-jwt-shaped ``AccessToken`` stand-in for ``sub``."""
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else ["comms:read", "comms:write"],
    }
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
        patch("providers.comms.get_access_token", return_value=token),
        patch("providers.comms.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data


async def _read_resource(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    uri: str,
) -> dict[str, Any]:
    """Read ``uri`` through the real mounted server and parse its JSON body."""
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.comms.get_access_token", return_value=token),
        patch("providers.comms.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            contents = await client.read_resource(uri)
            assert len(contents) == 1
            text_content = contents[0]
            body: Any = json.loads(text_content.text)  # type: ignore[union-attr]
            assert isinstance(body, dict)
            return body


async def _register(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    sub: str,
    *,
    display_name: str | None = None,
) -> dict[str, Any]:
    token = _token(sub)
    args: dict[str, Any] = {
        "display_name": display_name or sub,
        "accepted_types": sorted(MESSAGE_TYPES),
    }
    result: dict[str, Any] = await _call(main, test_session_factory, token, "comms_register", args)
    return result


def _availability_request() -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "window": {"start": now.isoformat(), "end": (now + timedelta(hours=2)).isoformat()},
        "duration_min": 30,
        "modality": "video",
        "priority": "normal",
        "constraints": [],
    }


async def _start_open_conversation(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    owner_sub: str,
    target_sub: str,
) -> tuple[str, dict[str, str]]:
    """Register ``owner_sub``/``target_sub``, start an ``open`` conversation
    between them, and return ``(conversation_id, {sub: agent_id})``."""
    await _register(main, test_session_factory, owner_sub)
    await _register(main, test_session_factory, target_sub)

    token_owner = _token(owner_sub)
    list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
    ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

    started = await _call(
        main,
        test_session_factory,
        token_owner,
        "comms_start_conversation",
        {
            "conversation_type": "open",
            "target_agent_ids": [ids[target_sub]],
            "initial_message": _availability_request(),
        },
    )
    return started["conversation_id"], ids


class TestConversationResource:
    async def test_matches_get_conversation_tool_for_same_caller(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "conv-res-owner", "conv-res-member"
        )
        token_owner = _token("conv-res-owner")
        await _call(
            main,
            test_session_factory,
            _token("conv-res-member"),
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        tool_result = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_get_conversation",
            {"conversation_id": conversation_id, "since_seq": 0},
        )
        resource_result = await _read_resource(
            main,
            test_session_factory,
            token_owner,
            f"comms://comms/conversations/{conversation_id}",
        )
        assert resource_result == tool_result

    async def test_invited_caller_gets_metadata_only(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "conv-res-inv-owner", "conv-res-inv-target"
        )
        result = await _read_resource(
            main,
            test_session_factory,
            _token("conv-res-inv-target"),
            f"comms://comms/conversations/{conversation_id}",
        )
        assert result["invited"] is True
        assert result["messages"] == []
        assert result["has_more"] is False
        assert "invited_by" in result

    async def test_non_member_gets_uniform_denial(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "conv-res-nm-owner", "conv-res-nm-member"
        )
        await _register(main, test_session_factory, "conv-res-nm-stranger")

        # A resource-read denial crosses the wire as a JSON-RPC error and
        # the client reconstructs it as a generic McpError (unlike
        # call_tool, which specially reconstructs the server's ToolError) —
        # ResourceError is the server-side type only, never what the client
        # sees.
        with pytest.raises(
            McpError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _read_resource(
                main,
                test_session_factory,
                _token("conv-res-nm-stranger"),
                f"comms://comms/conversations/{conversation_id}",
            )

    async def test_unknown_conversation_id_gets_uniform_denial(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "conv-res-unknown-caller")
        unknown_id = "00000000-0000-0000-0000-000000000000"
        with pytest.raises(
            McpError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _read_resource(
                main,
                test_session_factory,
                _token("conv-res-unknown-caller"),
                f"comms://comms/conversations/{unknown_id}",
            )


class TestAgentInboxResource:
    async def test_suspended_agent_own_inbox_resource_is_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Mirrors tests/test_comms_tools.py's
        test_suspended_agent_loses_read_path_access: a suspended agent's
        still-unexpired token must not be able to read its own inbox
        through this resource, the same as it can't via comms_inbox --
        the resource handler resolves through the same
        _resolve_caller_agent suspension check, not a hand-rolled copy of
        the self-only sub match alone."""
        registered = await _register(main, test_session_factory, "inbox-res-suspended")
        agent_id = registered["agent_id"]

        admin_token = _token(
            "inbox-res-suspend-admin", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": agent_id},
        )

        with pytest.raises(McpError, match="agent_suspended"):
            await _read_resource(
                main,
                test_session_factory,
                _token("inbox-res-suspended"),
                f"comms://comms/agents/{agent_id}/inbox",
            )

    async def test_self_inbox_matches_inbox_tool(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        _conversation_id, ids = await _start_open_conversation(
            main, test_session_factory, "inbox-res-owner", "inbox-res-member"
        )
        member_token = _token("inbox-res-member")

        tool_result = await _call(main, test_session_factory, member_token, "comms_inbox")
        resource_result = await _read_resource(
            main,
            test_session_factory,
            member_token,
            f"comms://comms/agents/{ids['inbox-res-member']}/inbox",
        )
        assert resource_result == tool_result
        assert resource_result["total_count"] >= 1

    async def test_reading_another_agents_inbox_is_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        _conversation_id, ids = await _start_open_conversation(
            main, test_session_factory, "inbox-res-a", "inbox-res-b"
        )
        with pytest.raises(
            McpError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _read_resource(
                main,
                test_session_factory,
                _token("inbox-res-a"),
                f"comms://comms/agents/{ids['inbox-res-b']}/inbox",
            )

    async def test_unknown_agent_id_is_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "inbox-res-solo")
        unknown_id = "00000000-0000-0000-0000-000000000000"
        with pytest.raises(
            McpError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _read_resource(
                main,
                test_session_factory,
                _token("inbox-res-solo"),
                f"comms://comms/agents/{unknown_id}/inbox",
            )

    async def test_sibling_identity_inbox_read_succeeds(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A caller's own ``{base_sub}::agent_key`` sibling identity's inbox
        is readable by the SAME base-sub token — the sibling is "self" for
        this check, not "another agent" (TECH-5903 §1)."""
        base_sub = "inbox-res-sib-base"
        base_token = _token(base_sub)
        await _call(
            main,
            test_session_factory,
            base_token,
            "comms_register",
            {
                "display_name": "sib-primary",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "primary",
            },
        )
        await _call(
            main,
            test_session_factory,
            base_token,
            "comms_register",
            {
                "display_name": "sib-secondary",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "secondary",
                "confirm_new_identity": True,
            },
        )
        list_result = await _call(main, test_session_factory, base_token, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}
        secondary_agent_id = ids[f"{base_sub}::secondary"]

        # Reading the SECONDARY sibling's inbox using the same base-sub
        # token (no agent_key on the token itself -- resources have no
        # agent_key parameter) must succeed, since it's a sibling of the
        # caller's own identity, not a stranger's.
        result = await _read_resource(
            main,
            test_session_factory,
            base_token,
            f"comms://comms/agents/{secondary_agent_id}/inbox",
        )
        assert result["total_count"] == 0
        assert result["unread"] == []
        assert result["pending_invites"] == []


class TestAgentsDirectoryResource:
    async def test_matches_list_agents_tool_first_page(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "dir-res-a")
        await _register(main, test_session_factory, "dir-res-b")
        token = _token("dir-res-a")

        tool_result = await _call(main, test_session_factory, token, "comms_list_agents")
        resource_result = await _read_resource(
            main, test_session_factory, token, "comms://comms/agents"
        )
        assert resource_result == tool_result
        assert resource_result["total_count"] >= 2
