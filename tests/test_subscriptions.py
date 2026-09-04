"""Tests for TECH-5903 Phase B: the subscription registry (``subscriptions.py``)
and the low-level ``subscribe_resource``/``unsubscribe_resource`` handlers
wired into ``main.py``.

Two layers, mirroring the plan doc's testing strategy (§5):

- ``TestRegistry*``: DB-less unit tests of ``subscriptions.py`` in isolation
  (idempotency, recipient filtering, prune-on-dead-weakref,
  prune-on-send-failure, per-agent cap eviction) — no Postgres, no FastMCP.
- ``TestSubscribeEndToEnd``/``TestNotificationFiring``: real-Postgres,
  in-memory ``fastmcp.Client`` end-to-end tests against the REAL mounted
  server (``main.mcp``), using ``mcp.ClientSession.subscribe_resource``/
  ``unsubscribe_resource`` and a ``message_handler`` to observe
  ``notifications/resources/updated`` — mirrors
  ``tests/test_comms_resources.py``'s real-Postgres idiom combined with
  ``tests/test_main.py``'s in-memory-client idiom.
"""

from __future__ import annotations

import asyncio
import gc
import os
import re
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import mcp.types as mt
import pytest
import pytest_asyncio
from fastmcp import Client
from mcp.shared.exceptions import McpError
from pydantic import AnyUrl
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import subscriptions
from schemas import MESSAGE_TYPES

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


# --- DB-less registry unit tests ---------------------------------------------------


class _FakeSession:
    """A minimal weakref-able stand-in for ``mcp.server.session.ServerSession``."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[str] = []

    async def send_resource_updated(self, uri: str) -> None:
        if self.fail:
            raise RuntimeError("boom")
        self.calls.append(str(uri))


@pytest_asyncio.fixture(autouse=True)
async def _clear_registry() -> AsyncIterator[None]:
    subscriptions._registry.clear()
    subscriptions._agent_subscription_counts.clear()
    yield
    subscriptions._registry.clear()
    subscriptions._agent_subscription_counts.clear()


class TestRegistrySubscribeUnsubscribe:
    async def test_subscribe_is_idempotent_per_session(self) -> None:
        session = _FakeSession()
        agent_id = _new_agent_id()
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert len(subscriptions._registry["comms://x"]) == 1

    async def test_unsubscribe_is_idempotent(self) -> None:
        session = _FakeSession()
        agent_id = _new_agent_id()
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        await subscriptions.unsubscribe("comms://x", session)  # type: ignore[arg-type]
        await subscriptions.unsubscribe("comms://x", session)  # type: ignore[arg-type]
        assert "comms://x" not in subscriptions._registry

    async def test_unsubscribe_unknown_uri_is_a_noop(self) -> None:
        await subscriptions.unsubscribe("comms://never-subscribed", _FakeSession())  # type: ignore[arg-type]


def _new_agent_id() -> uuid.UUID:
    return uuid.uuid4()


class TestRegistryNotify:
    async def test_recipient_filter_narrows_delivery(self) -> None:
        agent_a, agent_b = _new_agent_id(), _new_agent_id()
        session_a, session_b = _FakeSession(), _FakeSession()
        await subscriptions.subscribe("comms://x", session_a, agent_id=agent_a, sub="a")  # type: ignore[arg-type]
        await subscriptions.subscribe("comms://x", session_b, agent_id=agent_b, sub="b")  # type: ignore[arg-type]

        await subscriptions.notify("comms://x", recipient_filter={agent_a})

        assert session_a.calls == ["comms://x"]
        assert session_b.calls == []

    async def test_no_filter_notifies_everyone(self) -> None:
        agent_a, agent_b = _new_agent_id(), _new_agent_id()
        session_a, session_b = _FakeSession(), _FakeSession()
        await subscriptions.subscribe("comms://x", session_a, agent_id=agent_a, sub="a")  # type: ignore[arg-type]
        await subscriptions.subscribe("comms://x", session_b, agent_id=agent_b, sub="b")  # type: ignore[arg-type]

        await subscriptions.notify("comms://x")

        assert session_a.calls == ["comms://x"]
        assert session_b.calls == ["comms://x"]

    async def test_notify_unknown_uri_is_a_noop(self) -> None:
        await subscriptions.notify("comms://nobody-subscribed")

    async def test_dead_weakref_is_pruned_silently(self) -> None:
        agent_id = _new_agent_id()

        async def _subscribe_a_doomed_session() -> None:
            session = _FakeSession()
            await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        await _subscribe_a_doomed_session()
        gc.collect()

        # Must not raise despite the dead weakref.
        await subscriptions.notify("comms://x")
        assert "comms://x" not in subscriptions._registry

    async def test_failed_send_prunes_the_record(self) -> None:
        agent_id = _new_agent_id()
        session = _FakeSession(fail=True)
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        await subscriptions.notify("comms://x")  # swallows the RuntimeError
        assert "comms://x" not in subscriptions._registry

        # A second notify must not attempt to call the (now-removed) session
        # again -- nothing left to prune, and no exception either way.
        await subscriptions.notify("comms://x")


class TestRegistryPerAgentCap:
    async def test_oldest_subscription_is_evicted_at_the_cap(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 2)
        agent_id = _new_agent_id()
        sessions = [_FakeSession() for _ in range(3)]
        for index, session in enumerate(sessions):
            await subscriptions.subscribe(f"comms://x{index}", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        assert subscriptions._agent_subscription_counts[agent_id] == 2
        assert "comms://x0" not in subscriptions._registry
        assert "comms://x1" in subscriptions._registry
        assert "comms://x2" in subscriptions._registry


class TestNotifyConversationEvent:
    async def test_fires_conversation_and_inbox_uris(self) -> None:
        conversation_id = uuid.uuid4()
        active_agent = uuid.uuid4()
        other_agent = uuid.uuid4()
        conv_session = _FakeSession()
        inbox_session = _FakeSession()
        await subscriptions.subscribe(
            subscriptions.conversation_uri(conversation_id),
            conv_session,  # type: ignore[arg-type]
            agent_id=active_agent,
            sub="a",
        )
        await subscriptions.subscribe(
            subscriptions.inbox_uri(other_agent),
            inbox_session,  # type: ignore[arg-type]
            agent_id=other_agent,
            sub="b",
        )

        await subscriptions.notify_conversation_event(
            conversation_id,
            active_agent_ids={active_agent},
            inbox_agent_ids=[other_agent],
        )

        assert conv_session.calls == [subscriptions.conversation_uri(conversation_id)]
        assert inbox_session.calls == [subscriptions.inbox_uri(other_agent)]

    async def test_conversation_uri_recheck_excludes_departed_subscriber(self) -> None:
        """The plan doc's "re-check membership at fire time" requirement: a
        subscriber whose agent_id is no longer in ``active_agent_ids`` (e.g.
        it left the conversation since subscribing) must not be notified,
        even though its subscription record and session are both still
        alive."""
        conversation_id = uuid.uuid4()
        departed_agent = uuid.uuid4()
        session = _FakeSession()
        await subscriptions.subscribe(
            subscriptions.conversation_uri(conversation_id),
            session,  # type: ignore[arg-type]
            agent_id=departed_agent,
            sub="a",
        )

        await subscriptions.notify_conversation_event(
            conversation_id, active_agent_ids=set(), inbox_agent_ids=[]
        )

        assert session.calls == []


# --- End-to-end (real Postgres, in-memory fastmcp.Client) ---------------------------

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
            "(or set DATABASE_URL) to exercise the real-database subscription tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
    import subprocess

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
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


def _token(sub: str, *, scopes: list[str] | None = None) -> MagicMock:
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


async def _register(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    sub: str,
) -> dict[str, Any]:
    token = _token(sub)
    args = {"display_name": sub, "accepted_types": sorted(MESSAGE_TYPES)}
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


class _NotificationCollector:
    def __init__(self) -> None:
        self.uris: list[str] = []

    async def __call__(self, message: Any) -> None:
        if isinstance(message, mt.ServerNotification) and isinstance(
            message.root, mt.ResourceUpdatedNotification
        ):
            self.uris.append(str(message.root.params.uri))


async def _wait_until(predicate: Any, *, timeout: float = 2.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met within timeout")


class TestSubscribeAuthorization:
    async def test_subscribe_requires_active_participant(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "sub-req-active-owner", "sub-req-active-target"
        )
        invited_token = _token("sub-req-active-target")
        uri = f"comms://comms/conversations/{conversation_id}"

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=invited_token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(AnyUrl(uri))

    async def test_non_member_subscribe_is_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "sub-nm-owner", "sub-nm-member"
        )
        await _register(main, test_session_factory, "sub-nm-stranger")
        stranger_token = _token("sub-nm-stranger")
        uri = f"comms://comms/conversations/{conversation_id}"

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=stranger_token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(AnyUrl(uri))

    async def test_unknown_uri_is_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "sub-unknown-uri")
        token = _token("sub-unknown-uri")

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(AnyUrl("comms://comms/nonsense"))

    async def test_successful_subscribe_writes_audit_row(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "sub-audit-owner", "sub-audit-member"
        )
        member_token = _token("sub-audit-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        uri = f"comms://comms/conversations/{conversation_id}"

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=member_token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                await client.session.subscribe_resource(AnyUrl(uri))

        row_count = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'resource.subscribe' "
                    "AND actor_sub = :actor_sub"
                ),
                {"actor_sub": "sub-audit-member"},
            )
        ).scalar_one()
        assert row_count == 1


class TestNotificationFiring:
    async def test_subscriber_receives_notification_on_post_message(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "notify-owner", "notify-member"
        )
        member_token = _token("notify-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        uri = f"comms://comms/conversations/{conversation_id}"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(uri))

            owner_token = _token("notify-owner")
            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "needs_clarification",
                    "payload": {"about_seq": 1},
                },
            )

            await _wait_until(lambda: uri in collector.uris)

    async def test_departed_subscriber_stops_receiving_conversation_notifications(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "notify-leave-owner", "notify-leave-member"
        )
        member_token = _token("notify-leave-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        uri = f"comms://comms/conversations/{conversation_id}"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(uri))

            await _call(
                main,
                test_session_factory,
                member_token,
                "comms_leave",
                {"conversation_id": conversation_id},
            )
            # `comms_leave` itself re-queries active participants AFTER
            # committing the leave, so the leaver is already excluded from
            # its own conversation-URI recheck set -- it gets no ping for
            # its own departure. The real assertion here is what follows:
            # a LATER, unrelated post must not notify it either.
            owner_token = _token("notify-leave-owner")
            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "needs_clarification",
                    "payload": {"about_seq": 1},
                },
            )
            # Give the (absent) notification a moment to NOT arrive.
            await asyncio.sleep(0.2)
            assert uri not in collector.uris

    async def test_unsubscribe_stops_notifications(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "unsub-owner", "unsub-member"
        )
        member_token = _token("unsub-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        uri = f"comms://comms/conversations/{conversation_id}"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(uri))
                await client.session.unsubscribe_resource(AnyUrl(uri))

            owner_token = _token("unsub-owner")
            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "needs_clarification",
                    "payload": {"about_seq": 1},
                },
            )
            await asyncio.sleep(0.2)
            assert uri not in collector.uris
