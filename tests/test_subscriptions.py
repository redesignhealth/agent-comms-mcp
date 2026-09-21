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
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import httpx
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
from starlette.applications import Starlette
from starlette.routing import Route

import subscriptions
from schemas import MESSAGE_TYPES

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


# --- DB-less registry unit tests ---------------------------------------------------


class _FakeSession:
    """A minimal weakref-able stand-in for ``mcp.server.session.ServerSession``."""

    def __init__(
        self,
        *,
        fail: bool = False,
        exc: BaseException | None = None,
        delay_s: float | None = None,
    ) -> None:
        self.fail = fail
        self.exc = exc
        self.delay_s = delay_s
        self.calls: list[str] = []

    async def send_resource_updated(self, uri: str) -> None:
        if self.delay_s is not None:
            await asyncio.sleep(self.delay_s)
        if self.exc is not None:
            raise self.exc
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
        # Argus round-2 BLOCKING catch: a prior revision incremented
        # `_agent_subscription_counts` unconditionally on every subscribe
        # call, including this idempotent re-subscribe, inflating the
        # agent's count even though the registry itself stayed at one
        # record.
        assert subscriptions._agent_subscription_counts[agent_id] == 1

    async def test_unsubscribe_is_idempotent(self) -> None:
        session = _FakeSession()
        agent_id = _new_agent_id()
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        await subscriptions.unsubscribe("comms://x", session)  # type: ignore[arg-type]
        await subscriptions.unsubscribe("comms://x", session)  # type: ignore[arg-type]
        assert "comms://x" not in subscriptions._registry

    async def test_unsubscribe_unknown_uri_is_a_noop(self) -> None:
        await subscriptions.unsubscribe("comms://never-subscribed", _FakeSession())  # type: ignore[arg-type]

    async def test_remove_if_current_success(self) -> None:
        session = _FakeSession()
        agent_id = _new_agent_id()
        record = await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert record is not None
        assert subscriptions._agent_subscription_counts[agent_id] == 1

        removed = await subscriptions.remove_if_current("comms://x", record)
        assert removed is True
        assert "comms://x" not in subscriptions._registry
        assert agent_id not in subscriptions._agent_subscription_counts

        # Second attempt with same record is a no-op
        removed_again = await subscriptions.remove_if_current("comms://x", record)
        assert removed_again is False

    async def test_remove_if_current_stale_record_is_noop_and_preserves_current(self) -> None:
        """Reproduce the 3-step audit-failure race:
        1. Coroutine A calls subscribe(uri, session) -> succeeds, registers record R1.
        2. Coroutine B (same uri, same session, e.g. client re-subscribe) calls
           subscribe(uri, session) -> replaces R1 with R2 (returns None).
        3. A's audit write fails and A calls remove_if_current with R1.
        Assert: returns False, R2 is kept intact, count remains 1.
        """
        session = _FakeSession()
        agent_id = _new_agent_id()

        # Step 1: Coroutine A subscribes and gets record R1
        r1 = await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert r1 is not None
        assert subscriptions._agent_subscription_counts[agent_id] == 1
        assert subscriptions._registry["comms://x"][0] is r1

        # Step 2: Coroutine B re-subscribes same session to same URI (idempotent replace)
        r2 = await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert r2 is None  # Idempotent re-subscribe
        current_record = subscriptions._registry["comms://x"][0]
        assert current_record is not r1  # R1 was replaced by a new record

        # Step 3: A's rollback fires with R1
        removed = await subscriptions.remove_if_current("comms://x", r1)
        assert removed is False
        # The newer record R2 was NOT removed
        assert len(subscriptions._registry["comms://x"]) == 1
        assert subscriptions._registry["comms://x"][0] is current_record
        assert subscriptions._agent_subscription_counts[agent_id] == 1

    async def test_remove_if_current_unknown_uri_returns_false(self) -> None:
        session = _FakeSession()
        agent_id = _new_agent_id()
        record = await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert record is not None
        removed = await subscriptions.remove_if_current("comms://other", record)
        assert removed is False


def _new_agent_id() -> uuid.UUID:
    return uuid.uuid4()


class TestIsSubscribed:
    """Argus round-2 SUGGESTION: no direct unit tests existed for the
    public ``is_subscribed`` function itself, only indirect coverage via
    ``main.py``'s unsubscribe handler."""

    async def test_unknown_uri_returns_false(self) -> None:
        result = await subscriptions.is_subscribed(
            "comms://never-subscribed",
            _FakeSession(),  # type: ignore[arg-type]
        )
        assert result is False

    async def test_different_session_returns_false(self) -> None:
        agent_id = _new_agent_id()
        subscribed_session, other_session = _FakeSession(), _FakeSession()
        await subscriptions.subscribe(
            "comms://x",
            subscribed_session,  # type: ignore[arg-type]
            agent_id=agent_id,
            sub="a",
        )
        assert await subscriptions.is_subscribed("comms://x", other_session) is False  # type: ignore[arg-type]

    async def test_subscribed_session_returns_true(self) -> None:
        agent_id = _new_agent_id()
        session = _FakeSession()
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert await subscriptions.is_subscribed("comms://x", session) is True  # type: ignore[arg-type]


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

    async def test_generic_send_failure_does_not_prune_the_record(self, caplog: Any) -> None:
        agent_id = _new_agent_id()
        session = _FakeSession(fail=True)
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        with caplog.at_level("WARNING"):
            await subscriptions.notify("comms://x")  # logs warning and retains subscription
        assert "comms://x" in subscriptions._registry
        assert subscriptions._agent_subscription_counts[agent_id] == 1
        assert "notify failed for 'comms://x'" in caplog.text
        assert "keeping subscription" in caplog.text

    @pytest.mark.parametrize("exc", [anyio.ClosedResourceError(), anyio.BrokenResourceError()])
    async def test_closed_or_broken_stream_prunes_the_record(
        self, exc: BaseException, caplog: Any
    ) -> None:
        agent_id = _new_agent_id()
        session = _FakeSession(exc=exc)
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        with caplog.at_level("WARNING"):
            await subscriptions.notify("comms://x")
        assert "comms://x" not in subscriptions._registry
        assert agent_id not in subscriptions._agent_subscription_counts
        assert "after closed/broken stream" in caplog.text

    async def test_slow_consumer_times_out_without_pruning(
        self, monkeypatch: Any, caplog: Any
    ) -> None:
        monkeypatch.setattr(subscriptions, "NOTIFY_SEND_TIMEOUT_SECONDS", 0.05)
        agent_id = _new_agent_id()
        session = _FakeSession(delay_s=0.2)
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        with caplog.at_level("WARNING"):
            await subscriptions.notify("comms://x")
        assert "comms://x" in subscriptions._registry
        assert subscriptions._agent_subscription_counts[agent_id] == 1
        assert "notify timed out after" in caplog.text
        assert "keeping subscription" in caplog.text

    async def test_dead_weakref_excluded_by_recipient_filter_is_still_pruned_and_decremented(
        self,
    ) -> None:
        """Argus round-2 SUGGESTION: a record whose session is already dead
        AND whose agent is excluded by ``recipient_filter`` (so no send is
        ever attempted for it) must still be pruned from the registry with
        its count decremented -- otherwise it would never be pruned, since
        the only other prune trigger is a failed *send*, which this path
        never attempts."""
        agent_id = _new_agent_id()
        other_agent_id = _new_agent_id()

        async def _subscribe_a_doomed_session() -> None:
            session = _FakeSession()
            await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        await _subscribe_a_doomed_session()
        gc.collect()

        assert subscriptions._agent_subscription_counts[agent_id] == 1

        # recipient_filter excludes `agent_id` entirely -- no send is ever
        # attempted for its (already-dead) record.
        await subscriptions.notify("comms://x", recipient_filter={other_agent_id})

        assert "comms://x" not in subscriptions._registry
        assert agent_id not in subscriptions._agent_subscription_counts


class TestRegistryPerAgentCap:
    async def test_subscribe_at_cap_raises_subscription_limit_error(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 2)
        agent_id = _new_agent_id()
        sessions = [_FakeSession(), _FakeSession(), _FakeSession()]
        await subscriptions.subscribe("comms://x0", sessions[0], agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        await subscriptions.subscribe("comms://x1", sessions[1], agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        with pytest.raises(
            subscriptions.SubscriptionLimitError, match="already holds 2 subscriptions"
        ):
            await subscriptions.subscribe("comms://x2", sessions[2], agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        # Both pre-existing subscriptions are untouched
        assert subscriptions._agent_subscription_counts[agent_id] == 2
        assert "comms://x0" in subscriptions._registry
        assert "comms://x1" in subscriptions._registry
        assert "comms://x2" not in subscriptions._registry

        # Pre-existing subscriptions are still deliverable
        await subscriptions.notify("comms://x0")
        assert sessions[0].calls == ["comms://x0"]

    async def test_subscribe_reclaims_dead_records_when_at_cap(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 2)
        agent_id = _new_agent_id()

        doomed_session: _FakeSession | None = _FakeSession()
        live_session = _FakeSession()
        await subscriptions.subscribe("comms://x0", doomed_session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        await subscriptions.subscribe("comms://x1", live_session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]

        # Both sessions are live, count is 2 (at cap)
        assert subscriptions._agent_subscription_counts[agent_id] == 2

        # Drop reference to doomed_session and force GC
        del doomed_session
        gc.collect()

        # Count in bookkeeping is still 2 before reclaim
        assert subscriptions._agent_subscription_counts[agent_id] == 2

        # subscribe() at cap should reclaim the dead record for comms://x0,
        # freeing capacity for the new subscription to comms://x2.
        session2 = _FakeSession()
        record = await subscriptions.subscribe("comms://x2", session2, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert record is not None
        assert subscriptions._agent_subscription_counts[agent_id] == 2
        assert "comms://x0" not in subscriptions._registry
        assert "comms://x1" in subscriptions._registry
        assert "comms://x2" in subscriptions._registry

    async def test_subscribe_recovers_from_diverged_count(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 2)
        agent_id = _new_agent_id()
        subscriptions._agent_subscription_counts[agent_id] = 2

        session = _FakeSession()
        await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert subscriptions._agent_subscription_counts[agent_id] == 1
        assert len(subscriptions._registry["comms://x"]) == 1

    async def test_reclaim_dead_records_skipped_when_under_cap(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 5)
        agent_id = _new_agent_id()
        session = _FakeSession()

        with patch("subscriptions._reclaim_dead_for_agent_locked") as mock_reclaim:
            record = await subscriptions.subscribe("comms://x", session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
            assert isinstance(record, subscriptions._Record)
            mock_reclaim.assert_not_called()

        assert subscriptions._agent_subscription_counts[agent_id] == 1

        with patch("subscriptions._reclaim_dead_for_agent_locked") as mock_reclaim:
            record2 = await subscriptions.subscribe(
                "comms://y",
                _FakeSession(),  # type: ignore[arg-type]
                agent_id=agent_id,
                sub="a",
            )
            assert isinstance(record2, subscriptions._Record)
            mock_reclaim.assert_not_called()

    async def test_concurrent_subscribes_at_cap_only_one_succeeds(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 2)

        # Force genuine interleaving: replace subscriptions._lock with a lock that
        # yields to the event loop immediately after acquisition while still holding
        # the lock. Under cooperative scheduling, this proves that concurrent callers
        # run, attempt to enter the critical section, and are correctly blocked by
        # the lock rather than succeeding due to lack of suspension points.
        class _InterleavingLock(asyncio.Lock):
            async def acquire(self) -> Literal[True]:
                acquired = await super().acquire()
                await asyncio.sleep(0)
                return acquired

        monkeypatch.setattr(subscriptions, "_lock", _InterleavingLock())

        agent_id = _new_agent_id()
        # Seed 1 subscription so the agent is sitting at cap - 1
        initial_session = _FakeSession()
        await subscriptions.subscribe("comms://x0", initial_session, agent_id=agent_id, sub="a")  # type: ignore[arg-type]
        assert subscriptions._agent_subscription_counts[agent_id] == 1

        # Fire 5 concurrent subscribe calls for different URIs
        sessions = [_FakeSession() for _ in range(5)]

        async def _do_subscribe(i: int) -> subscriptions._Record | None:
            return await subscriptions.subscribe(
                f"comms://x_race_{i}",
                sessions[i],
                agent_id=agent_id,
                sub="a",  # type: ignore[arg-type]
            )

        results = await asyncio.gather(
            *(_do_subscribe(i) for i in range(5)), return_exceptions=True
        )

        successes = [r for r in results if isinstance(r, subscriptions._Record)]
        failures = [r for r in results if isinstance(r, subscriptions.SubscriptionLimitError)]

        assert len(successes) == 1
        assert len(failures) == 4
        assert subscriptions._agent_subscription_counts[agent_id] == 2


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
        # notify_conversation_event schedules each notify() as a background
        # task (TECH-6335) rather than awaiting it inline -- yield to the
        # event loop so those tasks actually run before asserting.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

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
        # notify_conversation_event schedules each notify() as a background
        # task (TECH-6335) rather than awaiting it inline -- yield to the
        # event loop so any such task actually runs before asserting.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

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


@pytest.fixture(scope="module")
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


@pytest_asyncio.fixture
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
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met within timeout")


class TestSubscribeAuthorization:
    # Real-Postgres e2e layer (see module docstring's §5 two-layer split) --
    # `_migrated_schema`/`_clean_tables` are scoped to this class (and the
    # other real-Postgres classes below), not file-wide autouse, so the
    # DB-less `TestRegistry*`/`TestIsSubscribed`/`TestNotifyConversationEvent`/
    # `TestCapDivergenceRecovery` classes above genuinely run without
    # Postgres (Argus round-5 BLOCKING catch: a file-wide autouse fixture
    # depending on `database_url` -- which calls `pytest.skip()` when
    # Postgres is unreachable -- would cascade that skip to every test in
    # this file, defeating the whole point of having a DB-less layer).
    pytestmark = pytest.mark.usefixtures("_migrated_schema", "_clean_tables")

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

    async def test_left_participant_subscribe_is_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Direct coverage for `allow_terminal_status`'s default-False path
        (Argus round-3 SUGGESTION): a participant who left must still be
        denied SUBSCRIBE (only unsubscribe tolerates a terminal status --
        see `test_left_participant_can_unsubscribe` below)."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "left-sub-owner", "left-sub-member"
        )
        member_token = _token("left-sub-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_leave",
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
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(AnyUrl(uri))

    async def test_left_participant_can_unsubscribe(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Direct coverage for `allow_terminal_status`'s True path (Argus
        round-3 SUGGESTION): a participant who subscribed while active, then
        left, must still be able to remove their own stale subscription --
        the whole point of the round-1/round-2 unsubscribe-after-leave fix."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "left-unsub-owner", "left-unsub-member"
        )
        member_token = _token("left-unsub-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        uri = f"comms://comms/conversations/{conversation_id}"

        # Argus round-4 SUGGESTION: subscribe and unsubscribe now share ONE
        # `Client` session (an earlier revision used two separate `Client`
        # blocks -- since `subscriptions.is_subscribed`/registry lookups are
        # keyed by `ServerSession` weakref IDENTITY, the unsubscribe call
        # would silently no-op against a different session's record,
        # leaving the actual stale-subscription-removal path this test
        # claims to cover completely untested). `_call`'s own OIDC/ENV/token
        # patches (used for the `comms_leave` tool call in between) can't be
        # entered while this test's own copies of the SAME patch objects
        # (`_OIDC_PATCH`/`_ENV_PATCH` are shared, reused objects, not
        # per-call factories) are already active -- `unittest.mock` raises
        # "Patch is already started" on a double-enter -- so those patches
        # are scoped narrowly around just the two low-level calls, with
        # `_call` running (and entering its own copies) in between while
        # only the outer `Client` connection itself stays open throughout.
        async with Client(main.mcp) as client:
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

            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                # Must not raise -- this is exactly the case
                # `require_active=False` plus `allow_terminal_status=True`
                # exists to permit.
                await client.session.unsubscribe_resource(AnyUrl(uri))

    async def test_non_member_subscribe_is_uniformly_denied(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
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

        # Argus round-2 SUGGESTION: a non-member denial is a DB-layer denial
        # (reaches `service.deny_resource_subscribe`), so it must write an
        # audited row same as every other denial category in this module.
        row_count = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE actor_sub = :actor_sub "
                    "AND action LIKE 'denied.%'"
                ),
                {"actor_sub": "sub-nm-stranger"},
            )
        ).scalar_one()
        assert row_count >= 1

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

    async def test_malformed_uuid_subscribe_is_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Distinct from ``test_unknown_uri_is_uniformly_denied``: this URI
        matches the conversation TEMPLATE shape, but the UUID segment itself
        doesn't parse -- a different denial branch (``malformed_uuid``) than
        an unrecognized URI shape (``unknown_uri``), both folded into the
        same uniform, anti-enumeration ``access_denied`` message."""
        await _register(main, test_session_factory, "sub-malformed-uuid")
        token = _token("sub-malformed-uuid")

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(
                        AnyUrl("comms://comms/conversations/not-a-uuid-at-all")
                    )

    async def test_subscribe_at_cap_is_denied_with_limit_reached_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        monkeypatch: Any,
    ) -> None:
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 1)
        conversation_id1, _ids1 = await _start_open_conversation(
            main, test_session_factory, "sub-cap-owner", "sub-cap-member"
        )
        member_token = _token("sub-cap-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id1},
        )
        uri1 = f"comms://comms/conversations/{conversation_id1}"

        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            # 1st subscription succeeds
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(uri1))
            assert len(subscriptions._registry.get(uri1, [])) == 1

            # Create 2nd conversation
            conversation_id2, _ids2 = await _start_open_conversation(
                main, test_session_factory, "sub-cap-owner", "sub-cap-member"
            )
            await _call(
                main,
                test_session_factory,
                member_token,
                "comms_accept",
                {"conversation_id": conversation_id2},
            )
            uri2 = f"comms://comms/conversations/{conversation_id2}"

            # 2nd subscription must fail with subscription_limit_reached
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                with pytest.raises(McpError) as exc_info:
                    await client.session.subscribe_resource(AnyUrl(uri2))
            assert "subscription_limit_reached" in str(exc_info.value)
            assert "access_denied" not in str(exc_info.value)

            # Pre-existing subscription still works
            owner_token = _token("sub-cap-owner")
            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_post_message",
                {
                    "conversation_id": conversation_id1,
                    "message_type": "needs_clarification",
                    "payload": {"about_seq": 1},
                },
            )
            await _wait_until(lambda: uri1 in collector.uris)

        # Audit row verification: denied.subscribe_limit_reached exists
        audit_row = (
            (
                await session.execute(
                    text(
                        "SELECT action, detail FROM audit_log WHERE actor_sub = :actor_sub "
                        "AND action = 'denied.subscribe_limit_reached'"
                    ),
                    {"actor_sub": "sub-cap-member"},
                )
            )
            .mappings()
            .first()
        )
        assert audit_row is not None
        assert audit_row["action"] == "denied.subscribe_limit_reached"
        assert audit_row["detail"] == {"limit": 1}

    async def test_concurrent_subscribe_at_cap_writes_exactly_one_success_audit_and_rejections(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        monkeypatch: Any,
    ) -> None:
        """Concurrency test under asyncio's cooperative model.

        Exercises concurrent MCP client subscribe requests where handlers
        naturally yield across async DB queries (authorize_resource_subscribe,
        service.audit_resource_subscription, service.deny_resource_subscribe).
        Verifies that exactly one success audit row and N-1 denial audit rows
        are written to the database with no false successes or missed denials.
        """
        monkeypatch.setattr(subscriptions, "MAX_SUBSCRIPTIONS_PER_AGENT", 2)
        member_sub = "sub-race-member"
        member_token = _token(member_sub)

        # Create first conversation and subscribe to it (puts agent at cap - 1)
        conv1, _ = await _start_open_conversation(
            main, test_session_factory, "sub-race-owner", member_sub
        )
        await _call(
            main, test_session_factory, member_token, "comms_accept", {"conversation_id": conv1}
        )
        uri1 = f"comms://comms/conversations/{conv1}"

        # Create 4 more conversations for the race
        race_uris: list[str] = []
        for _ in range(4):
            conv_i, _ = await _start_open_conversation(
                main, test_session_factory, "sub-race-owner", member_sub
            )
            await _call(
                main,
                test_session_factory,
                member_token,
                "comms_accept",
                {"conversation_id": conv_i},
            )
            race_uris.append(f"comms://comms/conversations/{conv_i}")

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=member_token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                # 1st subscription succeeds normally
                await client.session.subscribe_resource(AnyUrl(uri1))

                # Fire 4 concurrent subscribe calls for different URIs
                results = await asyncio.gather(
                    *(client.session.subscribe_resource(AnyUrl(u)) for u in race_uris),
                    return_exceptions=True,
                )

        successes = [r for r in results if not isinstance(r, BaseException)]
        failures = [
            r for r in results if isinstance(r, McpError) and "subscription_limit_reached" in str(r)
        ]

        assert len(successes) == 1
        assert len(failures) == 3

        # Exactly 2 success audit rows in DB: 1 initial + 1 from race (NO false success audit!)
        success_audits = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE actor_sub = :actor_sub "
                    "AND action = 'resource.subscribe'"
                ),
                {"actor_sub": member_sub},
            )
        ).scalar()
        assert success_audits == 2

        # Exactly 3 denial audit rows in DB for the 3 failed calls
        denial_audits = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE actor_sub = :actor_sub "
                    "AND action = 'denied.subscribe_limit_reached'"
                ),
                {"actor_sub": member_sub},
            )
        ).scalar()
        assert denial_audits == 3

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

    async def test_noop_resubscribe_writes_no_second_audit_row(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """Argus round-6 SUGGESTION: the idempotent-resubscribe no-op gate
        (main.py's `is_subscribed()` peek before the subscribe handler's
        audit write) had no dedicated test -- every existing single-subscribe
        test still passes even if that gate were deleted entirely, since
        none of them re-subscribe the same session to the same URI twice."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "resub-audit-owner", "resub-audit-member"
        )
        member_token = _token("resub-audit-member")
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
                # Same session, same URI, again -- idempotent per
                # `subscriptions.subscribe()`'s own handling; must not write
                # a second audit row.
                await client.session.subscribe_resource(AnyUrl(uri))

        row_count = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'resource.subscribe' "
                    "AND actor_sub = :actor_sub"
                ),
                {"actor_sub": "resub-audit-member"},
            )
        ).scalar_one()
        assert row_count == 1

    async def test_successful_unsubscribe_writes_audit_row(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "unsub-audit-owner", "unsub-audit-member"
        )
        member_token = _token("unsub-audit-member")
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
                await client.session.unsubscribe_resource(AnyUrl(uri))

        row_count = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'resource.unsubscribe' "
                    "AND actor_sub = :actor_sub"
                ),
                {"actor_sub": "unsub-audit-member"},
            )
        ).scalar_one()
        assert row_count == 1

    async def test_noop_unsubscribe_writes_no_audit_row(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """Argus round-2 SUGGESTION: calling unsubscribe without ever having
        subscribed first is a no-op (``subscriptions.unsubscribe`` returns
        ``False``) -- ``main._handle_unsubscribe_resource`` must skip the
        audit write entirely in that case, not just skip the registry
        mutation."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "noop-unsub-owner", "noop-unsub-member"
        )
        member_token = _token("noop-unsub-member")
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
                # Never subscribed -- this unsubscribe call is a genuine no-op.
                await client.session.unsubscribe_resource(AnyUrl(uri))

        row_count = (
            await session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'resource.unsubscribe' "
                    "AND actor_sub = :actor_sub"
                ),
                {"actor_sub": "noop-unsub-member"},
            )
        ).scalar_one()
        assert row_count == 0

    async def test_own_inbox_subscribe_succeeds(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "inbox-self-sub")
        token = _token("inbox-self-sub")
        list_result = await _call(main, test_session_factory, token, "comms_list_agents")
        agent_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "inbox-self-sub"
        )
        uri = f"comms://comms/agents/{agent_id}/inbox"

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                await client.session.subscribe_resource(AnyUrl(uri))

    async def test_other_agent_inbox_subscribe_is_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "inbox-owner")
        await _register(main, test_session_factory, "inbox-stranger")
        owner_token = _token("inbox-owner")
        list_result = await _call(main, test_session_factory, owner_token, "comms_list_agents")
        owner_agent_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "inbox-owner"
        )
        stranger_token = _token("inbox-stranger")
        uri = f"comms://comms/agents/{owner_agent_id}/inbox"

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

    async def test_sibling_inbox_subscribe_succeeds_when_bare_unregistered(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        base_sub = "inbox-unreg-bare"
        token = _token(base_sub)
        # Register sibling ONLY (bare is never registered)
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Claude Code Sibling",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "claude-code",
            },
        )
        list_res = await _call(main, test_session_factory, token, "comms_list_agents")
        sibling_id = next(
            a["agent_id"] for a in list_res["agents"] if a["sub"] == f"{base_sub}::claude-code"
        )
        uri = f"comms://comms/agents/{sibling_id}/inbox"

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                await client.session.subscribe_resource(AnyUrl(uri))

        # Check audit row: agent_id is the target sibling (TECH-6697 revisit of Argus round-2)
        audit_row = (
            await session.execute(
                text(
                    "SELECT agent_id FROM audit_log "
                    "WHERE action = 'resource.subscribe' "
                    "AND actor_sub = :actor_sub "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {"actor_sub": base_sub},
            )
        ).scalar_one()
        assert str(audit_row) == sibling_id

    async def test_sibling_inbox_subscribe_succeeds_when_bare_suspended(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        base_sub = "inbox-susp-bare"
        token = _token(base_sub)
        registered = await _register(main, test_session_factory, base_sub)
        bare_id = registered["agent_id"]
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Active Sibling",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "worker",
                "confirm_new_identity": True,
            },
        )
        admin_token = _token("admin-operator", scopes=["comms:read", "comms:write", "comms:admin"])
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": bare_id},
        )

        list_res = await _call(main, test_session_factory, token, "comms_list_agents")
        sibling_id = next(
            a["agent_id"] for a in list_res["agents"] if a["sub"] == f"{base_sub}::worker"
        )
        uri = f"comms://comms/agents/{sibling_id}/inbox"

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                await client.session.subscribe_resource(AnyUrl(uri))

    async def test_sibling_agent_conversation_subscribe_succeeds_and_charges_sibling(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        base_sub = "conv-sub-sib-bare"
        token = _token(base_sub)
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Claude Code Sibling",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "claude-code",
            },
        )
        await _register(main, test_session_factory, "conv-sub-counter")
        counter_token = _token("conv-sub-counter")

        list_res = await _call(main, test_session_factory, token, "comms_list_agents")
        sibling_id = next(
            a["agent_id"] for a in list_res["agents"] if a["sub"] == f"{base_sub}::claude-code"
        )

        started = await _call(
            main,
            test_session_factory,
            counter_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [sibling_id],
                "initial_message": _availability_request(),
            },
        )
        conv_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            token,
            "comms_accept",
            {"conversation_id": conv_id, "agent_key": "claude-code"},
        )

        uri = f"comms://comms/agents/{sibling_id}/conversations/{conv_id}"
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                await client.session.subscribe_resource(AnyUrl(uri))

        # Check audit row: agent_id is the sibling agent (charged to sibling)
        audit_row = (
            await session.execute(
                text(
                    "SELECT agent_id FROM audit_log "
                    "WHERE action = 'resource.subscribe' "
                    "AND actor_sub = :actor_sub "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {"actor_sub": base_sub},
            )
        ).scalar_one()
        assert str(audit_row) == sibling_id

    async def test_agent_conversation_subscribe_stranger_agent_id_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conv_id, ids = await _start_open_conversation(
            main, test_session_factory, "agent-sub-owner", "agent-sub-member"
        )
        member_id = ids["agent-sub-member"]
        await _register(main, test_session_factory, "agent-sub-stranger")
        stranger_token = _token("agent-sub-stranger")

        uri = f"comms://comms/agents/{member_id}/conversations/{conv_id}"
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

    async def test_agent_conversation_subscribe_invited_sibling_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        base_sub = "conv-sub-inv-sib"
        token = _token(base_sub)
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Invited Sibling",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "worker",
            },
        )
        await _register(main, test_session_factory, "conv-sub-inv-counter")
        counter_token = _token("conv-sub-inv-counter")

        list_res = await _call(main, test_session_factory, token, "comms_list_agents")
        sibling_id = next(
            a["agent_id"] for a in list_res["agents"] if a["sub"] == f"{base_sub}::worker"
        )

        started = await _call(
            main,
            test_session_factory,
            counter_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [sibling_id],
                "initial_message": _availability_request(),
            },
        )
        conv_id = started["conversation_id"]
        # Do NOT accept invite -- sibling is invited only

        uri = f"comms://comms/agents/{sibling_id}/conversations/{conv_id}"
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(AnyUrl(uri))

    async def test_plain_conversation_subscribe_does_not_fallback_to_sibling(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Regression guard: bare comms://comms/conversations/{conv_id} strictly
        requires bare base_sub to be registered/active, no fallback."""
        base_sub = "conv-sub-nf-bare"
        token = _token(base_sub)
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Active Sibling",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "worker",
            },
        )
        await _register(main, test_session_factory, "conv-sub-nf-counter")
        counter_token = _token("conv-sub-nf-counter")

        list_res = await _call(main, test_session_factory, token, "comms_list_agents")
        sibling_id = next(
            a["agent_id"] for a in list_res["agents"] if a["sub"] == f"{base_sub}::worker"
        )

        started = await _call(
            main,
            test_session_factory,
            counter_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [sibling_id],
                "initial_message": _availability_request(),
            },
        )
        conv_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            token,
            "comms_accept",
            {"conversation_id": conv_id, "agent_key": "worker"},
        )

        # Plain conversation subscribe fails because bare identity is not registered
        uri = f"comms://comms/conversations/{conv_id}"
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(McpError, match=re.escape("access_denied")):
                    await client.session.subscribe_resource(AnyUrl(uri))

        # Explicit agent-qualified subscribe succeeds
        agent_uri = f"comms://comms/agents/{sibling_id}/conversations/{conv_id}"
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                await client.session.subscribe_resource(AnyUrl(agent_uri))


class TestNotificationFiring:
    # See TestSubscribeAuthorization's comment on why this is scoped here
    # rather than file-wide autouse.
    pytestmark = pytest.mark.usefixtures("_migrated_schema", "_clean_tables")

    async def test_restart_simulation_catchup_read_recovers_missed_messages(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Simulate a restart (clearing the in-memory registry) and verify that
        the subscriber recovers missed messages via catch-up read (TECH-6335)."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "notify-restart-owner", "notify-restart-member"
        )
        member_token = _token("notify-restart-member")
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
                # 1. Initial subscribe
                await client.session.subscribe_resource(AnyUrl(uri))

            # 2. Initial catch-up read recording cursor
            initial_read = await _call(
                main,
                test_session_factory,
                member_token,
                "comms_get_conversation",
                {"conversation_id": conversation_id},
            )
            cursor = initial_read["page_max_seq"]
            assert cursor == 1

            # 3. Simulate restart by clearing in-memory subscription registry
            subscriptions._registry.clear()
            subscriptions._agent_subscription_counts.clear()

            # 4. Another agent posts 2 messages while server has no subscription record
            owner_token = _token("notify-restart-owner")
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

            # 5. Assert subscriber received nothing while registry was cleared
            await asyncio.sleep(0.1)
            assert uri not in collector.uris

            # 6. Re-subscribe (idempotent)
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(uri))

            # 7. Catch-up read using the recorded cursor returns both missed messages
            catchup = await _call(
                main,
                test_session_factory,
                member_token,
                "comms_get_conversation",
                {"conversation_id": conversation_id, "since_seq": cursor},
            )
            assert len(catchup["messages"]) == 2
            assert [m["seq"] for m in catchup["messages"]] == [2, 3]

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

    async def test_agent_conversation_subscriber_receives_notification_on_post_message(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Load-bearing test: proves identity-qualified conversation subscription
        canonicalizes to the canonical conversation URI and charges the sibling agent_id,
        so notify_conversation_event's recipient_filter (active participant agent_ids)
        allows notification delivery and the ping arrives."""
        base_sub = "notify-agent-sub"
        token = _token(base_sub)
        # Register sibling ONLY (bare is unregistered)
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Agent Subscriber",
                "accepted_types": sorted(MESSAGE_TYPES),
                "agent_key": "worker",
            },
        )
        await _register(main, test_session_factory, "notify-agent-owner")
        owner_token = _token("notify-agent-owner")

        list_res = await _call(main, test_session_factory, token, "comms_list_agents")
        sibling_id = next(
            a["agent_id"] for a in list_res["agents"] if a["sub"] == f"{base_sub}::worker"
        )

        started = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [sibling_id],
                "initial_message": _availability_request(),
            },
        )
        conv_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            token,
            "comms_accept",
            {"conversation_id": conv_id, "agent_key": "worker"},
        )

        sub_uri = f"comms://comms/agents/{sibling_id}/conversations/{conv_id}"
        canonical_uri = f"comms://comms/conversations/{conv_id}"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(sub_uri))

            # Counterparty posts a message
            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_post_message",
                {
                    "conversation_id": conv_id,
                    "message_type": "needs_clarification",
                    "payload": {"about_seq": 1},
                },
            )

            await _wait_until(lambda: canonical_uri in collector.uris)

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

    async def test_start_conversation_notifies_invitee_inbox(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "sc-notify-owner")
        await _register(main, test_session_factory, "sc-notify-target")
        owner_token = _token("sc-notify-owner")
        list_result = await _call(main, test_session_factory, owner_token, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "sc-notify-target"
        )
        inbox_uri = f"comms://comms/agents/{target_id}/inbox"
        target_token = _token("sc-notify-target")
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=target_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(inbox_uri))

            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [target_id],
                    "initial_message": _availability_request(),
                },
            )

            await _wait_until(lambda: inbox_uri in collector.uris)

    async def test_invite_notifies_target_inbox_and_conversation(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "inv-notify-owner", "inv-notify-member"
        )
        member_token = _token("inv-notify-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        await _register(main, test_session_factory, "inv-notify-target")
        owner_token = _token("inv-notify-owner")
        list_result = await _call(main, test_session_factory, owner_token, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "inv-notify-target"
        )
        conv_uri = f"comms://comms/conversations/{conversation_id}"
        inbox_uri = f"comms://comms/agents/{target_id}/inbox"
        target_token = _token("inv-notify-target")
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(conv_uri))
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=target_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(inbox_uri))

            await _call(
                main,
                test_session_factory,
                owner_token,
                "comms_invite",
                {"conversation_id": conversation_id, "target_agent_id": target_id},
            )

            await _wait_until(lambda: conv_uri in collector.uris and inbox_uri in collector.uris)

    async def test_accept_notifies_conversation_and_actor_inbox(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, ids = await _start_open_conversation(
            main, test_session_factory, "acc-notify-owner", "acc-notify-target"
        )
        owner_token = _token("acc-notify-owner")
        target_token = _token("acc-notify-target")
        conv_uri = f"comms://comms/conversations/{conversation_id}"
        inbox_uri = f"comms://comms/agents/{ids['acc-notify-target']}/inbox"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=owner_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(conv_uri))
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=target_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                # Inbox subscribe is self-scoped, no active-participant gate
                # -- allowed even while the target is still `invited`.
                await client.session.subscribe_resource(AnyUrl(inbox_uri))

            await _call(
                main,
                test_session_factory,
                target_token,
                "comms_accept",
                {"conversation_id": conversation_id},
            )

            await _wait_until(lambda: conv_uri in collector.uris and inbox_uri in collector.uris)

    async def test_decline_invite_notifies_conversation_and_actor_inbox(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, ids = await _start_open_conversation(
            main, test_session_factory, "dec-notify-owner", "dec-notify-target"
        )
        owner_token = _token("dec-notify-owner")
        target_token = _token("dec-notify-target")
        conv_uri = f"comms://comms/conversations/{conversation_id}"
        inbox_uri = f"comms://comms/agents/{ids['dec-notify-target']}/inbox"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=owner_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(conv_uri))
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=target_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(inbox_uri))

            await _call(
                main,
                test_session_factory,
                target_token,
                "comms_decline_invite",
                {"conversation_id": conversation_id},
            )

            await _wait_until(lambda: conv_uri in collector.uris and inbox_uri in collector.uris)

    async def test_archive_conversation_notifies_conversation_uri(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Argus round-6 SUGGESTION: `comms_archive_conversation` (wired
        into notify_conversation_event as a round-5 BLOCKING fix) was the
        only write path in the DESIGN.md §7 notification table with zero
        test coverage -- a regression silently dropping its
        `notify_conversation_event` call would not have been caught."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "archive-notify-owner", "archive-notify-member"
        )
        owner_token = _token("archive-notify-owner")
        member_token = _token("archive-notify-member")
        conv_uri = f"comms://comms/conversations/{conversation_id}"
        collector = _NotificationCollector()

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=owner_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(conv_uri))

            await _call(
                main,
                test_session_factory,
                member_token,
                "comms_accept",
                {"conversation_id": conversation_id},
            )
            await _call(
                main,
                test_session_factory,
                member_token,
                "comms_archive_conversation",
                {"conversation_id": conversation_id},
            )

            await _wait_until(lambda: conv_uri in collector.uris)


class _FakeApprovalAccessToken:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims


class _FakeApprovalAuthProvider:
    """Minimal stand-in for ``main._auth_provider``/``main._okta_provider``,
    mirroring ``tests/test_approval_endpoint.py``'s own fake -- only the
    interactive-token verification path is exercised here."""

    def __init__(self) -> None:
        self.tokens: dict[str, _FakeApprovalAccessToken] = {}
        self.server = self

    async def verify_token(self, token: str) -> _FakeApprovalAccessToken | None:
        return self.tokens.get(token)


class TestApprovalHttpNotification:
    # See TestSubscribeAuthorization's comment on why this is scoped here
    # rather than file-wide autouse.
    pytestmark = pytest.mark.usefixtures("_migrated_schema", "_clean_tables")

    async def test_approve_notifies_conversation_and_participant_inboxes(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, ids = await _start_open_conversation(
            main, test_session_factory, "approve-notify-owner", "approve-notify-member"
        )
        member_token = _token("approve-notify-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        owner_token = _token("approve-notify-owner")
        # A `note` under an `open` conversation always crosses the
        # ownership boundary -> held for human approval (see
        # comms_post_message's docstring).
        held = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "note",
                "payload": {"text": "hello"},
            },
        )
        assert held["held_for_approval"] is True
        hold_id = held["hold_id"]

        conv_uri = f"comms://comms/conversations/{conversation_id}"
        inbox_uri = f"comms://comms/agents/{ids['approve-notify-member']}/inbox"
        collector = _NotificationCollector()

        fake_provider = _FakeApprovalAuthProvider()
        fake_provider.tokens["human-token"] = _FakeApprovalAccessToken(
            {"iss": "https://agent-comms.example/mcp", "email": "approve-notify-owner"}
        )
        app = Starlette(
            routes=[Route("/approvals/{hold_id}/decide", main.decide_approval, methods=["POST"])]
        )

        async with Client(main.mcp, message_handler=collector) as client:
            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch("providers.comms.get_access_token", return_value=member_token),
                patch("providers.comms.get_session_factory", return_value=test_session_factory),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                await client.session.subscribe_resource(AnyUrl(conv_uri))
                # Argus round-2 SUGGESTION: this test's name promises
                # coverage of the inbox-notification behavior too, but a
                # prior revision never subscribed to any inbox URI, so it
                # never actually observed it -- the message-hold approve
                # branch pings every active participant's inbox (see
                # `service.decide_hold`'s `_notify_inbox_agent_ids`), so
                # subscribe here and assert delivery below.
                await client.session.subscribe_resource(AnyUrl(inbox_uri))

            with (
                _OIDC_PATCH,
                _ENV_PATCH,
                patch.object(main, "_auth_provider", fake_provider),
                patch.object(main, "_okta_provider", fake_provider.server),
                patch("main.get_session_factory", return_value=test_session_factory),
            ):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://test"
                ) as http_client:
                    resp = await http_client.post(
                        f"/approvals/{hold_id}/decide",
                        headers={"Authorization": "Bearer human-token"},
                        json={"decision": "approve"},
                    )
            assert resp.status_code == 200

            await _wait_until(lambda: conv_uri in collector.uris and inbox_uri in collector.uris)


class TestRollbackSafety:
    # See TestSubscribeAuthorization's comment on why this is scoped here
    # rather than file-wide autouse.
    pytestmark = pytest.mark.usefixtures("_migrated_schema", "_clean_tables")

    async def test_failed_write_triggers_zero_notifications(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Call-ordering test, not a true rollback-after-partial-write test
        (Argus round-2 SUGGESTION): this forces ``service.post_message`` to
        raise BEFORE any DB work runs, and verifies
        ``subscriptions.notify_conversation_event`` is never invoked when
        the service call fails that way. It does NOT exercise a genuine
        mid-transaction failure after some DB writes but before commit --
        constructing that correctly would need to force a failure partway
        through a transaction without corrupting the test DB session for
        other tests, which is out of scope here."""
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "rollback-owner", "rollback-member"
        )
        member_token = _token("rollback-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        owner_token = _token("rollback-owner")
        with (
            patch(
                "service.post_message",
                AsyncMock(side_effect=RuntimeError("simulated mid-service failure")),
            ),
            patch("subscriptions.notify_conversation_event", AsyncMock()) as notify_mock,
            pytest.raises(Exception),  # noqa: B017 -- any client-side surfacing is fine
        ):
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

        notify_mock.assert_not_called()


class TestAuditBeforeMutationOrdering:
    """Argus round-4 SUGGESTION: the happy-path and no-op tests elsewhere in
    this file pass identically whether the audit write happens before or
    after the registry mutation -- neither pins the actual ordering
    guarantee the round-3/round-4 fixes exist to enforce. These tests
    inject a failure into ``service.audit_resource_subscription`` itself
    and assert the registry was never mutated when that happens.
    """

    # See TestSubscribeAuthorization's comment on why this is scoped here
    # rather than file-wide autouse.
    pytestmark = pytest.mark.usefixtures("_migrated_schema", "_clean_tables")

    async def test_failed_audit_leaves_subscribe_registry_unmutated(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "audit-fail-sub-owner", "audit-fail-sub-member"
        )
        member_token = _token("audit-fail-sub-member")
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
            patch(
                "service.audit_resource_subscription",
                AsyncMock(side_effect=RuntimeError("simulated audit-write failure")),
            ),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(Exception):  # noqa: B017 -- any client-side surfacing is fine
                    await client.session.subscribe_resource(AnyUrl(uri))
                # The failed audit write must have triggered rollback of the
                # in-memory registration via remove_if_current -- so the
                # registry must be untouched.
                # `client.session` is the CLIENT-side `mcp.ClientSession`,
                # not the server-side `ServerSession` object the registry
                # stores weakrefs to (those two are distinct objects
                # connected over the in-memory transport, and the
                # server-side one isn't directly reachable from test code)
                # -- verify via the registry's own shape instead of a
                # session-identity check.
                assert uri not in subscriptions._registry

    async def test_cancelled_audit_rolls_back_subscribe_registry_and_reraises(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "audit-cancel-sub-owner", "audit-cancel-sub-member"
        )
        member_token = _token("audit-cancel-sub-member")
        await _call(
            main,
            test_session_factory,
            member_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        uri = f"comms://comms/conversations/{conversation_id}"

        mock_audit = AsyncMock(side_effect=asyncio.CancelledError())
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("providers.comms.get_access_token", return_value=member_token),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
            patch("main.get_session_factory", return_value=test_session_factory),
            patch("service.audit_resource_subscription", mock_audit),
        ):
            async with Client(main.mcp) as client:
                # CancelledError is a BaseException, not an Exception -- a bare
                # `pytest.raises(Exception)` would fail to catch it and let it
                # propagate uncaught.
                with pytest.raises(BaseException):  # noqa: B017 -- any client-side surfacing is fine
                    await client.session.subscribe_resource(AnyUrl(uri))
                assert uri not in subscriptions._registry
                # Verify the rollback path was genuinely exercised (audit write
                # was attempted) rather than the assertion above passing for
                # some unrelated reason.
                mock_audit.assert_awaited_once()

    async def test_failed_audit_leaves_unsubscribe_registry_unmutated(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await _start_open_conversation(
            main, test_session_factory, "audit-fail-unsub-owner", "audit-fail-unsub-member"
        )
        member_token = _token("audit-fail-unsub-member")
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
                # See test_failed_audit_leaves_subscribe_registry_unmutated's
                # comment on why this checks the registry's own shape rather
                # than `is_subscribed(uri, client.session)`.
                assert len(subscriptions._registry.get(uri, [])) == 1

                with patch(
                    "service.audit_resource_subscription",
                    AsyncMock(side_effect=RuntimeError("simulated audit-write failure")),
                ):
                    with pytest.raises(Exception):  # noqa: B017
                        await client.session.unsubscribe_resource(AnyUrl(uri))

                # The failed audit write must have happened BEFORE
                # `subscriptions.unsubscribe()` ran -- so the subscription
                # must still be live.
                assert len(subscriptions._registry.get(uri, [])) == 1
