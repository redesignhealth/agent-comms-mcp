"""Tests for TECH-9883: the wake loop guard.

Real Postgres (shared fixtures in ``tests/conftest.py``). Two agents that answer
each other through the real tools must stop being woken at the limit, with the
reason visible and every message still readable.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import wake_events
from models import WakeEvent, WakeSession, WakeTarget
from tests.test_comms_tools import _availability_request, _call, _import_main, _register, _token

pytestmark = pytest.mark.usefixtures("_migrated_schema")

CONV_LIMIT = "WAKE_CONVERSATION_EVENT_LIMIT"
CONV_WINDOW = "WAKE_CONVERSATION_LIMIT_WINDOW_SECONDS"
AGENT_CAP = "WAKE_AGENT_HOURLY_EVENT_CAP"


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE wake_targets, wake_events, wake_sessions, wake_rules, "
                "audit_log, messages, participants, conversations, agents RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest.fixture
def factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


class _Agent:
    def __init__(self, main: Any, factory: Any, sub: str, agent_id: str) -> None:
        self.main, self.factory, self.sub, self.id = main, factory, sub, agent_id

    async def call(self, tool: str, args: dict[str, Any] | None = None) -> Any:
        return await _call(self.main, self.factory, _token(self.sub), tool, args)


async def _pair(main: Any, factory: Any) -> tuple[_Agent, _Agent, str]:
    """Two agents with wake targets and one accepted conversation."""
    agents = []
    for sub in ("a", "b"):
        agents.append(
            _Agent(main, factory, sub, str((await _register(main, factory, sub))["agent_id"]))
        )
    a, b = agents
    async with factory() as s:
        for agent in (a, b):
            s.add(
                WakeTarget(
                    agent_id=uuid.UUID(agent.id),
                    url="https://x.example/wake",
                    secret_ciphertext=b"s",
                    system_label="test",
                )
            )
        await s.commit()
    started = await a.call(
        "comms_start_conversation",
        {
            "conversation_type": "open",
            "target_agent_ids": [b.id],
            "initial_message": _availability_request(),
        },
    )
    conv = str(started["conversation_id"])
    await b.call("comms_accept", {"conversation_id": conv})
    async with factory() as s:
        await s.execute(text("DELETE FROM wake_events"))
        await s.commit()
    return a, b, conv


async def _reply(agent: _Agent, conv: str) -> int:
    result = await agent.call(
        "comms_post_message",
        {
            "conversation_id": conv,
            "message_type": "availability_request",
            "payload": _availability_request(),
        },
    )
    return int(result["seq"])


async def _events(factory: Any, agent: _Agent | None = None) -> list[WakeEvent]:
    async with factory() as s:
        stmt = select(WakeEvent).order_by(WakeEvent.created_at, WakeEvent.id)
        if agent is not None:
            stmt = stmt.where(WakeEvent.recipient_agent_id == uuid.UUID(agent.id))
        return list((await s.execute(stmt)).scalars())


async def _old_events(
    factory: Any, agent: _Agent, sender: _Agent, conv: str, count: int, *, age: timedelta
) -> None:
    async with factory() as s:
        for i in range(count):
            s.add(
                WakeEvent(
                    recipient_agent_id=uuid.UUID(agent.id),
                    conversation_id=uuid.UUID(conv),
                    kind="message",
                    seq=1000 + i,
                    message_type="task_assign",
                    sender_agent_id=uuid.UUID(sender.id),
                    reason="rule",
                    status="delivered",
                    created_at=datetime.now(UTC) - age,
                )
            )
        await s.commit()


class TestConversationLimit:
    async def test_two_agents_answering_each_other_stop_at_the_limit(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONV_LIMIT, "4")
        a, b, conv = await _pair(main, factory)
        seqs = []
        for i in range(10):
            seqs.append(await _reply(a if i % 2 == 0 else b, conv))

        statuses = [e.status for e in await _events(factory)]
        assert statuses.count("pending") == 8  # 4 for each side, then the guard holds
        assert statuses.count("suppressed") == 2
        assert any(e.status == "suppressed" for e in await _events(factory))

        # Every message is still on the board for polling.
        conversation = await a.call("comms_get_conversation", {"conversation_id": conv})
        assert [m["seq"] for m in conversation["messages"]][-10:] == sorted(seqs)

    async def test_suppressed_event_says_why_and_is_not_delivered_or_requeueable(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONV_LIMIT, "1")
        a, b, conv = await _pair(main, factory)
        await _reply(a, conv)
        await _reply(a, conv)
        events = await _events(factory, b)
        assert [e.status for e in events] == ["pending", "suppressed"]
        guarded = events[1]
        assert guarded.last_error is not None
        assert "conversation" in guarded.last_error
        assert guarded.next_attempt_at is None
        assert guarded.attempt_count == 0

        admin = _token("wake-admin", scopes=["comms:read", "comms:write", "comms:admin"])
        listed = await _call(
            main, factory, admin, "comms_admin_wake_events_list", {"status": "suppressed"}
        )
        assert [e["event_id"] for e in listed["events"]] == [str(guarded.id)]
        assert listed["events"][0]["last_error"] == guarded.last_error

        from fastmcp.exceptions import ToolError

        with pytest.raises(ToolError, match="only a failed or dead"):
            await _call(
                main,
                factory,
                admin,
                "comms_admin_wake_event_requeue",
                {"event_id": str(guarded.id)},
            )

    async def test_a_suppressed_event_does_not_extend_the_session(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONV_LIMIT, "1")
        a, b, conv = await _pair(main, factory)
        await _reply(a, conv)
        async with factory() as s:
            before = (
                await s.execute(
                    select(WakeSession.last_activity_at).where(
                        WakeSession.agent_id == uuid.UUID(b.id)
                    )
                )
            ).scalar_one()
        await _reply(a, conv)
        async with factory() as s:
            after = (
                await s.execute(
                    select(WakeSession.last_activity_at).where(
                        WakeSession.agent_id == uuid.UUID(b.id)
                    )
                )
            ).scalar_one()
        assert after == before

    async def test_events_older_than_the_window_do_not_count(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONV_LIMIT, "3")
        monkeypatch.setenv(CONV_WINDOW, "600")
        a, b, conv = await _pair(main, factory)
        await _old_events(factory, b, a, conv, 5, age=timedelta(minutes=30))
        await _reply(a, conv)
        assert [
            e.status for e in await _events(factory, b) if e.seq is not None and e.seq < 1000
        ] == ["pending"]

    async def test_suppressed_events_do_not_count_toward_the_limit(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONV_LIMIT, "2")
        a, b, conv = await _pair(main, factory)
        for _ in range(5):
            await _reply(a, conv)
        statuses = [e.status for e in await _events(factory, b)]
        assert statuses.count("pending") == 2
        assert statuses.count("suppressed") == 3


class TestAgentCap:
    async def test_per_agent_hourly_cap_across_conversations(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(AGENT_CAP, "3")
        a, b, conv = await _pair(main, factory)
        await _old_events(factory, b, a, conv, 3, age=timedelta(minutes=5))
        await _reply(a, conv)
        events = [e for e in await _events(factory, b) if e.seq is not None and e.seq < 1000]
        assert [e.status for e in events] == ["suppressed"]
        assert events[0].last_error is not None
        assert "agent" in events[0].last_error


class TestNormalUse:
    async def test_a_ten_message_exchange_never_hits_either_limit(
        self, main: Any, factory: Any
    ) -> None:
        a, b, conv = await _pair(main, factory)
        for i in range(10):
            await _reply(a if i % 2 == 0 else b, conv)
        events = await _events(factory)
        assert len(events) == 10
        assert {e.status for e in events} == {"pending"}

    def test_default_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (CONV_LIMIT, CONV_WINDOW, AGENT_CAP):
            monkeypatch.delenv(name, raising=False)
        assert wake_events.wake_limits() == (250, 600, 2500)

    def test_defaults_are_the_documented_constants(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (CONV_LIMIT, CONV_WINDOW, AGENT_CAP):
            monkeypatch.delenv(name, raising=False)
        assert wake_events.wake_limits() == (
            wake_events.WAKE_CONVERSATION_EVENT_LIMIT,
            wake_events.WAKE_CONVERSATION_LIMIT_WINDOW_SECONDS,
            wake_events.WAKE_AGENT_HOURLY_EVENT_CAP,
        )

    def test_bad_settings_fall_back_to_the_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (CONV_LIMIT, CONV_WINDOW, AGENT_CAP):
            monkeypatch.setenv(name, "banana")
        assert wake_events.wake_limits()[0] == wake_events.WAKE_CONVERSATION_EVENT_LIMIT
        monkeypatch.setenv(CONV_LIMIT, "0")
        assert wake_events.wake_limits()[0] == wake_events.WAKE_CONVERSATION_EVENT_LIMIT


class TestVisibleToTheAgent:
    async def test_sessions_list_shows_the_limit_that_fired(
        self, main: Any, factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONV_LIMIT, "1")
        a, b, conv = await _pair(main, factory)
        assert (await b.call("comms_wake_sessions_list"))["limits"] == []
        await _reply(a, conv)
        await _reply(a, conv)
        await _reply(a, conv)
        limits = (await b.call("comms_wake_sessions_list"))["limits"]
        assert len(limits) == 1
        assert limits[0]["conversation_id"] == conv
        assert limits[0]["limit"] == "conversation"
        assert limits[0]["suppressed_count"] == 2
        assert limits[0]["last_suppressed_at"]
        # Only the caller's own.
        assert (await a.call("comms_wake_sessions_list"))["limits"] == []
