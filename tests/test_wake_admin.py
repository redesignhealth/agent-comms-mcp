"""Tests for TECH-9913: admin tools to list and requeue wake events.

Real Postgres (shared fixtures in ``tests/conftest.py``). Tool calls go through
the real mounted server; the requeue-then-deliver tests run a real
``WakeDelivery`` against a mock receiver.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastmcp.exceptions import ToolError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import wake_secrets
import wake_targets
from models import AuditLog
from tests.test_comms_tools import _call, _import_main, _token
from tests.test_wake_delivery import ACCEPTED, _event, _fresh_room, _get
from wake_delivery import WakeDelivery

pytestmark = pytest.mark.usefixtures("_migrated_schema")

DENIED = re.escape("access_denied: not authorized for this resource")
ADMIN_SCOPES = ["comms:read", "comms:write", "comms:admin"]


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


@pytest.fixture(autouse=True)
def _operator_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, "*.ts.net")
    monkeypatch.setenv(wake_secrets.WAKE_TARGET_SECRET_KEY_ENV_VAR, Fernet.generate_key().decode())
    yield


@pytest.fixture
def factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


def _admin() -> Any:
    return _token("wake-admin", scopes=ADMIN_SCOPES)


def _plain() -> Any:
    return _token("not-admin", scopes=["comms:read", "comms:write"])


async def _list(main: Any, factory: Any, token: Any = None, **args: Any) -> Any:
    return await _call(main, factory, token or _admin(), "comms_admin_wake_events_list", args)


async def _requeue(main: Any, factory: Any, event_id: Any, token: Any = None) -> Any:
    return await _call(
        main,
        factory,
        token or _admin(),
        "comms_admin_wake_event_requeue",
        {"event_id": str(event_id)},
    )


class TestList:
    async def test_filters_order_and_limit(self, main: Any, factory: Any) -> None:
        async with factory() as s:
            room = await _fresh_room(s)
            dead = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="dead", last_error="http 503; retries exhausted", attempt_count=6,
                age=timedelta(minutes=3),
            )  # fmt: skip
            await _event(
                s, room.active, room.conversation_id, room.sender, 2,
                status="retry", age=timedelta(minutes=2),
            )  # fmt: skip
            await _event(
                s, room.invited, room.conversation_id, room.sender, 1,
                status="failed", age=timedelta(minutes=1),
            )  # fmt: skip

        everything = await _list(main, factory)
        assert [e["status"] for e in everything["events"]] == ["failed", "retry", "dead"]
        assert everything["has_more"] is False

        only_dead = await _list(main, factory, agent_id=str(room.active.id), status="dead")
        assert [e["event_id"] for e in only_dead["events"]] == [str(dead)]
        event = only_dead["events"][0]
        assert event["last_error"] == "http 503; retries exhausted"
        assert event["attempt_count"] == 6
        assert event["recipient_agent_id"] == str(room.active.id)
        assert event["seq"] == 1

        by_agent = await _list(main, factory, agent_id=str(room.active.id))
        assert len(by_agent["events"]) == 2
        by_conversation = await _list(main, factory, conversation_id=str(room.conversation_id))
        assert len(by_conversation["events"]) == 3
        other = await _list(main, factory, conversation_id=str(uuid.uuid4()))
        assert other["events"] == []

        page = await _list(main, factory, limit=2)
        assert len(page["events"]) == 2
        assert page["has_more"] is True

    async def test_output_has_no_secret_signature_session_ref_or_body(
        self, main: Any, factory: Any
    ) -> None:
        async with factory() as s:
            room = await _fresh_room(s)
            await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="dead", last_error="http 401", session_ref_sent="run-secret-ref",
            )  # fmt: skip
        result = await _list(main, factory)
        dumped = json.dumps(result)
        assert "run-secret-ref" not in dumped
        assert "whsec_" not in dumped
        assert set(result["events"][0]) == {
            "event_id", "recipient_agent_id", "conversation_id", "sender_agent_id", "kind",
            "seq", "message_type", "reason", "status", "attempt_count", "next_attempt_at",
            "last_error", "created_at", "delivered_at",
        }  # fmt: skip

    async def test_bad_input(self, main: Any, factory: Any) -> None:
        for args in (
            {"status": "bogus"},
            {"limit": 0},
            {"limit": 201},
            {"agent_id": "nope"},
            {"conversation_id": "nope"},
        ):
            with pytest.raises(ToolError, match="invalid_request"):
                await _list(main, factory, **args)

    async def test_non_admin_refused(self, main: Any, factory: Any) -> None:
        with pytest.raises(ToolError, match=DENIED):
            await _list(main, factory, _plain())
        read_only = _token("reader", scopes=["comms:read"])
        with pytest.raises(ToolError, match=DENIED):
            await _list(main, factory, read_only)


class TestRequeue:
    async def test_dead_event_is_requeued_and_delivered(self, main: Any, factory: Any) -> None:
        calls: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json=ACCEPTED)

        async with factory() as s:
            room = await _fresh_room(s)
            event_id = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="dead", last_error="http 503; retries exhausted", attempt_count=6,
            )  # fmt: skip
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        delivery = WakeDelivery(session_factory=lambda: factory, client=client, send_timeout=1.0)

        assert await delivery.tick() == 0  # dead: nothing to send
        result = await _requeue(main, factory, event_id)
        assert result["event_id"] == str(event_id)
        assert result["status"] == "retry"

        assert await delivery.tick() == 1
        await delivery.drain()
        await client.aclose()
        assert len(calls) == 1
        assert json.loads(calls[0].content)["eventId"] == str(event_id)
        async with factory() as s:
            row = await _get(s, event_id)
        assert row.status == "delivered"
        assert row.attempt_count == 1
        assert row.last_error is None

    async def test_event_dead_of_age_is_not_dead_lettered_again(
        self, main: Any, factory: Any
    ) -> None:
        async with factory() as s:
            room = await _fresh_room(s)
            event_id = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="dead", last_error="not delivered within 24 hours",
                age=timedelta(hours=30),
            )  # fmt: skip
            original = (await _get(s, event_id)).created_at
        await _requeue(main, factory, event_id)
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json=ACCEPTED))
        )
        delivery = WakeDelivery(session_factory=lambda: factory, client=client, send_timeout=1.0)
        assert await delivery.tick() == 1
        await delivery.drain()
        await client.aclose()
        async with factory() as s:
            row = await _get(s, event_id)
            audit = (
                await s.execute(select(AuditLog).where(AuditLog.action == "wake_event.requeued"))
            ).scalar_one()
        assert row.status == "delivered"
        assert audit.detail["original_created_at"] == original.isoformat()

    async def test_failed_event_can_be_requeued(self, main: Any, factory: Any) -> None:
        async with factory() as s:
            room = await _fresh_room(s)
            event_id = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="failed", last_error="no wake target registered",
            )  # fmt: skip
        await _requeue(main, factory, event_id)
        async with factory() as s:
            row = await _get(s, event_id)
        assert (row.status, row.attempt_count, row.last_error) == ("retry", 0, None)

    async def test_requeue_is_audited_with_what_it_replaced(self, main: Any, factory: Any) -> None:
        async with factory() as s:
            room = await _fresh_room(s)
            event_id = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="dead", last_error="http 503; retries exhausted", attempt_count=6,
            )  # fmt: skip
        await _requeue(main, factory, event_id)
        async with factory() as s:
            audit = (
                await s.execute(select(AuditLog).where(AuditLog.action == "wake_event.requeued"))
            ).scalar_one()
        assert audit.actor_sub == "wake-admin"
        assert audit.agent_id == room.active.id
        assert audit.conversation_id == room.conversation_id
        assert audit.detail["event_id"] == str(event_id)
        assert audit.detail["previous_status"] == "dead"
        assert audit.detail["previous_attempt_count"] == 6
        assert audit.detail["previous_last_error"] == "http 503; retries exhausted"

    @pytest.mark.parametrize("status", ["pending", "retry", "retry_later", "delivered"])
    async def test_other_statuses_are_rejected_and_untouched(
        self, main: Any, factory: Any, status: str
    ) -> None:
        lease = datetime.now(UTC) + timedelta(seconds=60)
        async with factory() as s:
            room = await _fresh_room(s)
            event_id = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status=status, attempt_count=1, next_attempt_at=lease,
            )  # fmt: skip
        with pytest.raises(ToolError, match=f"invalid_request: .*this one is {status}"):
            await _requeue(main, factory, event_id)
        async with factory() as s:
            row = await _get(s, event_id)
            audits = (
                (await s.execute(select(AuditLog).where(AuditLog.action == "wake_event.requeued")))
                .scalars()
                .all()
            )
        assert (row.status, row.attempt_count, row.next_attempt_at) == (status, 1, lease)
        assert audits == []

    async def test_a_requeued_event_still_goes_before_later_unfinished_ones(
        self, main: Any, factory: Any
    ) -> None:
        sent: list[int] = []

        def respond(request: httpx.Request) -> httpx.Response:
            sent.append(json.loads(request.content)["data"]["seq"])
            return httpx.Response(200, json=ACCEPTED)

        async with factory() as s:
            room = await _fresh_room(s)
            first = await _event(
                s, room.active, room.conversation_id, room.sender, 1,
                status="dead", age=timedelta(minutes=5),
            )  # fmt: skip
            await _event(
                s, room.active, room.conversation_id, room.sender, 2,
                status="pending", age=timedelta(minutes=4),
            )  # fmt: skip
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        delivery = WakeDelivery(session_factory=lambda: factory, client=client, send_timeout=1.0)
        await _requeue(main, factory, first)
        for _ in range(2):
            await delivery.tick()
            await delivery.drain()
        await client.aclose()
        assert sent == [1, 2]

    async def test_unknown_event_and_bad_id(self, main: Any, factory: Any) -> None:
        with pytest.raises(ToolError, match="invalid_request: no such wake event"):
            await _requeue(main, factory, uuid.uuid4())
        with pytest.raises(ToolError, match="invalid_request"):
            await _requeue(main, factory, "not-a-uuid")

    async def test_non_admin_refused_and_event_untouched(self, main: Any, factory: Any) -> None:
        async with factory() as s:
            room = await _fresh_room(s)
            event_id = await _event(
                s, room.active, room.conversation_id, room.sender, 1, status="dead"
            )
        with pytest.raises(ToolError, match=DENIED):
            await _requeue(main, factory, event_id, _plain())
        async with factory() as s:
            row = await _get(s, event_id)
            denials = (
                (await s.execute(select(AuditLog.action).where(AuditLog.action.like("denied.%"))))
                .scalars()
                .all()
            )
        assert row.status == "dead"
        assert denials == ["denied.wake_events_require_elevated_scope"]
