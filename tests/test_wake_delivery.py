"""Tests for TECH-9911: the background task that signs, posts and retries wake events.

Real Postgres (shared fixtures in ``tests/conftest.py``); the receiver is an
httpx ``MockTransport``. The signature is checked with an independent
implementation (``hmac`` here, not ``wake_delivery.sign``).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import wake_delivery
import wake_secrets
import wake_targets
from models import Agent, AuditLog, WakeEvent, WakeSession, WakeTarget
from tests.test_wake_events import _agent, _post, _Room, _room, _start
from wake_delivery import (
    ALLOWLIST_MISCONFIGURED_RETRY_SECONDS,
    BACKOFF_SCHEDULE_SECONDS,
    LEASE_SECONDS,
    MAX_RETRY_AFTER_SECONDS,
    RETRY_LATER_SECONDS,
    WakeDelivery,
)
from wake_events import WAKE_SESSION_WINDOW_SECONDS

pytestmark = pytest.mark.usefixtures("_migrated_schema")

SECRET = "whsec_" + base64.b64encode(bytes(range(32))).decode()
URL = "https://wake.example.ts.net/hooks/wake?token=query-secret-value"
RESPONSE_MARKER = "RESPONSE-BODY-MARKER-9911"
ACCEPTED = {"status": "accepted", "sessionRef": None}


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


class Clock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


class Receiver:
    """Records every request; ``respond`` decides the answer (replace it per test)."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.respond: Callable[[httpx.Request], Awaitable[httpx.Response] | httpx.Response] = (
            lambda request: httpx.Response(200, json=ACCEPTED)
        )

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        result = self.respond(request)
        return await result if isinstance(result, Awaitable) else result

    def body(self, index: int = -1) -> dict[str, Any]:
        parsed: dict[str, Any] = json.loads(self.calls[index].content)
        return parsed


@pytest.fixture
def receiver() -> Receiver:
    return Receiver()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest_asyncio.fixture
async def delivery(
    factory: async_sessionmaker[AsyncSession], receiver: Receiver, clock: Clock
) -> AsyncIterator[WakeDelivery]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(receiver), follow_redirects=False)
    yield WakeDelivery(
        session_factory=lambda: factory, client=client, clock=clock, send_timeout=1.0
    )
    await client.aclose()


async def _run(delivery: WakeDelivery) -> int:
    claimed = await delivery.tick()
    await delivery.drain()
    return claimed


async def _targets(session: AsyncSession, *agents: Agent, url: str = URL) -> None:
    for agent in agents:
        await session.execute(delete(WakeTarget).where(WakeTarget.agent_id == agent.id))
        session.add(
            WakeTarget(
                agent_id=agent.id,
                url=url,
                secret_ciphertext=wake_secrets.encrypt_secret(SECRET),
                system_label="test",
            )
        )
    await session.commit()


async def _fresh_room(session: AsyncSession) -> _Room:
    room = await _room(session)
    # Start from no events/sessions; tests insert exactly what they need.
    await session.execute(delete(WakeEvent))
    await session.execute(delete(WakeSession))
    await session.commit()
    await _targets(session, room.active, room.invited, room.sender)
    return room


async def _event(
    session: AsyncSession,
    recipient: Agent,
    conversation_id: uuid.UUID,
    sender: Agent,
    seq: int | None,
    *,
    age: timedelta = timedelta(seconds=1),
    **kw: Any,
) -> uuid.UUID:
    kind = kw.pop("kind", "message" if seq is not None else "invite")
    event = WakeEvent(
        recipient_agent_id=recipient.id,
        conversation_id=conversation_id,
        kind=kind,
        seq=seq,
        message_type="task_assign" if kind == "message" else None,
        sender_agent_id=sender.id,
        reason="rule",
        created_at=datetime.now(UTC) - age,
        **kw,
    )
    session.add(event)
    await session.commit()
    return event.id


async def _get(session: AsyncSession, event_id: uuid.UUID) -> WakeEvent:
    return (
        await session.execute(
            select(WakeEvent)
            .where(WakeEvent.id == event_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


def _expected_signature(request: httpx.Request) -> str:
    """Independent Standard Webhooks signature of what was actually sent."""
    key = base64.b64decode(SECRET.removeprefix("whsec_"))
    message = (
        request.headers["webhook-id"].encode()
        + b"."
        + request.headers["webhook-timestamp"].encode()
        + b"."
        + request.content
    )
    return "v1," + base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()).decode()


# --- the request ----------------------------------------------------------


async def test_posted_message_makes_one_signed_post_with_contract_body(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _room(session)
    await _targets(session, room.active, room.invited, room.sender)
    await _post(session, room.sender, room.conversation_id)
    events = list((await session.execute(select(WakeEvent))).scalars())
    assert events

    await _run(delivery)

    assert len(receiver.calls) == len(events)
    for request in receiver.calls:
        assert request.method == "POST"
        assert str(request.url) == URL
        assert request.headers["content-type"] == "application/json"
        assert request.headers["webhook-signature"] == _expected_signature(request)
        assert abs(int(request.headers["webhook-timestamp"]) - time.time()) < 60
    for event in events:
        sent = next(c for c in receiver.calls if c.headers["webhook-id"] == str(event.id))
        body = json.loads(sent.content)
        created = await _get(session, event.id)
        assert body == {
            "eventId": str(event.id),
            "name": "comms.wake",
            "timestamp": created.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "data": {
                "kind": "message",
                "recipientAgentId": str(event.recipient_agent_id),
                "conversationId": str(room.conversation_id),
                "seq": event.seq,
                "messageType": event.message_type,
                "senderAgentId": str(room.sender.id),
                "sessionRef": None,
                "reason": event.reason,
            },
            "cursor": None,
        }
        assert created.status == "delivered"
        assert created.delivered_at is not None
        assert created.attempt_count == 1


async def test_invite_event_has_null_seq_and_message_type(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.invited, room.conversation_id, room.sender, None)
    await _run(delivery)
    data = receiver.body()["data"]
    assert (data["kind"], data["seq"], data["messageType"]) == ("invite", None, None)


async def test_every_attempt_is_resigned_with_a_fresh_timestamp(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = lambda r: httpx.Response(503)
    await _run(delivery)
    clock.advance(seconds=BACKOFF_SCHEDULE_SECONDS[0])
    await _run(delivery)
    first, second = receiver.calls
    assert first.headers["webhook-id"] == second.headers["webhook-id"]
    assert int(second.headers["webhook-timestamp"]) - int(first.headers["webhook-timestamp"]) == 5
    assert second.headers["webhook-signature"] == _expected_signature(second)
    assert first.headers["webhook-signature"] != second.headers["webhook-signature"]


# --- sessionRef, ordering --------------------------------------------------------


async def test_session_ref_returned_is_stored_and_sent_on_the_next_event(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    session.add(WakeSession(agent_id=room.active.id, conversation_id=room.conversation_id))
    await session.commit()
    e1 = await _event(
        session, room.active, room.conversation_id, room.sender, 1, age=timedelta(seconds=2)
    )
    e2 = await _event(session, room.active, room.conversation_id, room.sender, 2)
    receiver.respond = lambda r: httpx.Response(
        200, json={"status": "accepted", "sessionRef": "run-42"}
    )

    await _run(delivery)
    assert len(receiver.calls) == 1  # e2 waits for e1
    assert receiver.body()["data"]["sessionRef"] is None
    stored = (await session.execute(select(WakeSession.session_ref))).scalar_one()
    assert stored == "run-42"

    await _run(delivery)
    assert receiver.body()["eventId"] == str(e2)
    assert receiver.body()["data"]["sessionRef"] == "run-42"
    assert (await _get(session, e1)).session_ref_sent is None
    assert (await _get(session, e2)).session_ref_sent == "run-42"


async def test_session_ref_longer_than_255_is_an_invalid_body(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    e1 = await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = lambda r: httpx.Response(
        200, json={"status": "accepted", "sessionRef": "x" * 256}
    )
    await _run(delivery)
    assert (await _get(session, e1)).status == "retry"


async def test_oldest_unfinished_event_of_a_pair_blocks_later_ones_but_not_other_pairs(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    a1 = await _event(
        session, room.active, room.conversation_id, room.sender, 1, age=timedelta(seconds=3)
    )
    a2 = await _event(
        session, room.active, room.conversation_id, room.sender, 2, age=timedelta(seconds=2)
    )
    b1 = await _event(session, room.invited, room.conversation_id, room.sender, 1)

    def respond(request: httpx.Request) -> httpx.Response:
        recipient = json.loads(request.content)["data"]["recipientAgentId"]
        return (
            httpx.Response(503)
            if recipient == str(room.active.id)
            else httpx.Response(200, json=ACCEPTED)
        )

    receiver.respond = respond
    await _run(delivery)
    assert {c.headers["webhook-id"] for c in receiver.calls} == {str(a1), str(b1)}
    assert (await _get(session, a2)).status == "pending"
    assert (await _get(session, a2)).attempt_count == 0

    # a1 backs off: a2 still waits, even once a2 itself would be due.
    clock.advance(seconds=1)
    await _run(delivery)
    assert len(receiver.calls) == 2

    receiver.respond = lambda r: httpx.Response(200, json=ACCEPTED)
    clock.advance(seconds=10)
    await _run(delivery)
    await _run(delivery)
    assert [c.headers["webhook-id"] for c in receiver.calls[2:]] == [str(a1), str(a2)]


async def test_seq_decides_order_not_created_at(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    # seq 2 was recorded "earlier" (e.g. its transaction began first) than seq 1.
    await _event(
        session, room.active, room.conversation_id, room.sender, 2, age=timedelta(seconds=5)
    )
    e1 = await _event(
        session, room.active, room.conversation_id, room.sender, 1, age=timedelta(seconds=1)
    )
    await _run(delivery)
    assert [c.headers["webhook-id"] for c in receiver.calls] == [str(e1)]


@pytest.mark.parametrize(
    ("closed", "idle", "sent"),
    [
        (False, timedelta(minutes=1), "run-1"),
        (False, timedelta(minutes=11), None),  # went quiet: a new period starts
        (True, timedelta(minutes=1), None),  # closed explicitly
    ],
)
async def test_session_ref_is_sent_only_while_the_conversation_is_open(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    closed: bool,
    idle: timedelta,
    sent: str | None,
) -> None:
    room = await _fresh_room(session)
    at = datetime.now(UTC) - idle
    session.add(
        WakeSession(
            agent_id=room.active.id,
            conversation_id=room.conversation_id,
            last_activity_at=at,
            closed_at=at if closed else None,
            closed_reason="agent_closed" if closed else None,
            session_ref="run-1",
        )
    )
    await session.commit()
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    await _run(delivery)
    assert receiver.body()["data"]["sessionRef"] == sent
    assert (await _get(session, event_id)).session_ref_sent == sent


async def test_accepted_null_session_ref_clears_the_stored_one_but_not_on_a_closed_session(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    session.add(
        WakeSession(
            agent_id=room.active.id, conversation_id=room.conversation_id, session_ref="run-1"
        )
    )
    session.add(
        WakeSession(
            agent_id=room.invited.id,
            conversation_id=room.conversation_id,
            session_ref="run-9",
            closed_at=datetime.now(UTC),
            closed_reason="agent_closed",
        )
    )
    await session.commit()
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    await _event(session, room.invited, room.conversation_id, room.sender, 1)
    receiver.respond = lambda r: httpx.Response(
        200, json={"status": "accepted", "sessionRef": "run-2"}
    )
    await _run(delivery)
    refs = {
        row.agent_id: row.session_ref
        for row in (
            await session.execute(select(WakeSession).execution_options(populate_existing=True))
        ).scalars()
    }
    assert refs[room.active.id] == "run-2"
    assert refs[room.invited.id] == "run-9"  # closed: untouched
    receiver.respond = lambda r: httpx.Response(
        200, json={"status": "accepted", "sessionRef": None}
    )
    await _event(session, room.active, room.conversation_id, room.sender, 2)
    await _run(delivery)
    row = (
        await session.execute(
            select(WakeSession)
            .where(WakeSession.agent_id == room.active.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert row.session_ref is None


@pytest.mark.parametrize("status", ["accepted", "duplicate"])
async def test_an_answer_without_a_session_ref_key_leaves_the_stored_ref(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, status: str
) -> None:
    room = await _fresh_room(session)
    session.add(
        WakeSession(
            agent_id=room.active.id, conversation_id=room.conversation_id, session_ref="run-1"
        )
    )
    await session.commit()
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = lambda r: httpx.Response(200, json={"status": status})
    await _run(delivery)
    row = (
        await session.execute(select(WakeSession).execution_options(populate_existing=True))
    ).scalar_one()
    assert row.session_ref == "run-1"


async def test_a_late_answer_does_not_touch_a_session_that_went_quiet(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    at = datetime.now(UTC) - timedelta(minutes=11)
    session.add(
        WakeSession(
            agent_id=room.active.id,
            conversation_id=room.conversation_id,
            last_activity_at=at,
            session_ref="run-1",
        )
    )
    await session.commit()
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = lambda r: httpx.Response(200, json={"status": "accepted", "sessionRef": "x"})
    await _run(delivery)
    row = (
        await session.execute(select(WakeSession).execution_options(populate_existing=True))
    ).scalar_one()
    assert row.session_ref == "run-1"


async def test_first_event_after_a_quiet_period_carries_no_session_ref_end_to_end(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    """Recorder then delivery: the event recorded by a real post reopens a quiet session."""
    room = await _room(session)
    await _targets(session, room.active, room.invited, room.sender)
    quiet = datetime.now(UTC) - timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS + 60)
    session.add(
        WakeSession(
            agent_id=room.active.id,
            conversation_id=room.conversation_id,
            opened_at=quiet,
            last_activity_at=quiet,
            session_ref="run-1",
        )
    )
    await session.commit()
    await _post(session, room.sender, room.conversation_id)
    await _run(delivery)
    to_active = [
        json.loads(c.content)
        for c in receiver.calls
        if json.loads(c.content)["data"]["recipientAgentId"] == str(room.active.id)
    ]
    assert len(to_active) == 1
    assert to_active[0]["data"]["sessionRef"] is None


async def test_a_stale_outcome_cannot_overwrite_a_newer_claim_even_if_the_count_matches(
    session: AsyncSession, delivery: WakeDelivery, clock: Clock
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    (claim_a,) = await delivery._claim(5, clock())
    clock.advance(seconds=LEASE_SECONDS + 1)
    (claim_b,) = await delivery._claim(5, clock())
    assert (claim_a.attempt, claim_b.attempt) == (1, 2)
    # B is answered retry_later: the attempt is given back, so the count is 1 again.
    await delivery._record(
        claim_b,
        wake_delivery._Outcome(
            "retry_later", "retry_later", delay_seconds=300, refund_attempt=True
        ),
    )
    before = await _get(session, event_id)
    assert (before.status, before.attempt_count) == ("retry_later", 1)
    # A's late answer carries attempt 1 as well, but not B's lease: it is dropped.
    await delivery._record(claim_a, wake_delivery._Outcome("delivered", "delivered"))
    after = await _get(session, event_id)
    assert (after.status, after.delivered_at) == ("retry_later", None)


# --- the response table ---------------------------------------------------


def _resp(status: int, **kw: Any) -> Callable[[httpx.Request], httpx.Response]:
    return lambda r: httpx.Response(status, **kw)


@pytest.mark.parametrize(
    ("respond", "status", "delay_seconds", "attempt_count", "target_kept"),
    [
        (_resp(200, json={"status": "accepted", "sessionRef": None}), "delivered", None, 1, True),
        (_resp(200, json={"status": "duplicate", "sessionRef": None}), "delivered", None, 1, True),
        (_resp(200, json={"status": "weird"}), "retry", 5, 1, True),
        (_resp(200, text="not json"), "retry", 5, 1, True),
        (_resp(200, json=["accepted"]), "retry", 5, 1, True),
        (
            _resp(409, json={"status": "retry_later", "reason": "paused"}),
            "retry_later",
            300,
            0,
            True,
        ),
        (_resp(409, json={"status": "other"}), "failed", None, 1, True),
        (_resp(410), "failed", None, 1, False),
        (_resp(401), "dead", None, 1, True),
        (_resp(429), "retry", 5, 1, True),
        (_resp(500), "retry", 5, 1, True),
        (_resp(503), "retry", 5, 1, True),
        (
            _resp(302, headers={"location": "https://wake.example.ts.net/elsewhere"}),
            "failed",
            None,
            1,
            True,
        ),
        (_resp(400), "failed", None, 1, True),
        (_resp(404), "failed", None, 1, True),
    ],
)
async def test_response_table(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    clock: Clock,
    respond: Callable[[httpx.Request], httpx.Response],
    status: str,
    delay_seconds: int | None,
    attempt_count: int,
    target_kept: bool,
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = respond
    await _run(delivery)
    event = await _get(session, event_id)
    assert event.status == status
    assert event.attempt_count == attempt_count
    if delay_seconds is None:
        assert event.next_attempt_at is None
    else:
        assert event.next_attempt_at == clock.now + timedelta(seconds=delay_seconds)
    assert (event.status == "delivered") == (event.delivered_at is not None)
    targets = (
        await session.execute(select(WakeTarget).where(WakeTarget.agent_id == room.active.id))
    ).all()
    assert bool(targets) == target_kept
    assert len(receiver.calls) == 1


async def test_redirect_is_not_followed(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = _resp(307, headers={"location": "https://elsewhere.example.ts.net/x"})
    await _run(delivery)
    assert [str(c.url.host) for c in receiver.calls] == ["wake.example.ts.net"]


async def test_410_removes_the_target_and_audits_it(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = _resp(410)
    await _run(delivery)
    rows = list(
        (
            await session.execute(select(AuditLog).where(AuditLog.action == "wake_target.removed"))
        ).scalars()
    )
    assert len(rows) == 1
    assert rows[0].agent_id == room.active.id
    assert rows[0].actor_sub == wake_delivery.SYSTEM_ACTOR
    assert rows[0].detail is not None
    assert "query-secret-value" not in json.dumps(rows[0].detail)


async def test_410_does_not_remove_a_target_replaced_since_the_claim(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.active, room.conversation_id, room.sender, 1)

    async def respond(request: httpx.Request) -> httpx.Response:
        await session.execute(
            update(WakeTarget)
            .where(WakeTarget.agent_id == room.active.id)
            .values(url="https://new.example.ts.net/wake")
        )
        await session.commit()
        return httpx.Response(410)

    receiver.respond = respond
    await _run(delivery)
    assert (await session.execute(select(WakeTarget.url))).scalars().all().count(
        "https://new.example.ts.net/wake"
    ) == 1


# --- transient failures ---------------------------------------------------


async def test_transient_backoff_schedule_then_dead(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = _resp(503)
    delays = []
    for _ in range(len(BACKOFF_SCHEDULE_SECONDS)):
        await _run(delivery)
        event = await _get(session, event_id)
        assert event.status == "retry"
        assert event.next_attempt_at is not None
        delays.append((event.next_attempt_at - clock.now).total_seconds())
        # Not due one second early.
        clock.advance(seconds=delays[-1] - 1)
        before = len(receiver.calls)
        await _run(delivery)
        assert len(receiver.calls) == before
        clock.advance(seconds=1)
    assert delays == [5, 30, 120, 600, 1800]
    await _run(delivery)  # the sixth attempt
    event = await _get(session, event_id)
    assert (event.status, event.attempt_count, event.next_attempt_at) == ("dead", 6, None)
    assert len(receiver.calls) == 6
    await _run(delivery)
    assert len(receiver.calls) == 6


async def test_timeout_and_network_error_are_transient(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    e1 = await _event(session, room.active, room.conversation_id, room.sender, 1)

    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        return httpx.Response(200, json=ACCEPTED)

    receiver.respond = hang
    await _run(delivery)
    event = await _get(session, e1)
    assert (event.status, event.last_error) == ("retry", "timeout")

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    receiver.respond = boom
    clock.advance(seconds=5)
    await _run(delivery)
    event = await _get(session, e1)
    assert (event.status, event.attempt_count) == ("retry", 2)
    assert event.last_error == "network error (ConnectError)"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("120", 120),
        ("0", 0),
        ("999999", MAX_RETRY_AFTER_SECONDS),
        ("garbage", 5),
        (None, 5),
    ],
)
async def test_429_retry_after_is_honoured_and_capped(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    clock: Clock,
    header: str | None,
    expected: int,
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = _resp(429, headers={"retry-after": header} if header else {})
    await _run(delivery)
    event = await _get(session, event_id)
    assert event.status == "retry"
    assert event.attempt_count == 1  # counts in the backoff sequence
    assert event.next_attempt_at == clock.now + timedelta(seconds=expected)


async def test_429_retry_after_http_date(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    from email.utils import format_datetime

    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    receiver.respond = _resp(
        429,
        headers={"retry-after": format_datetime(clock.now + timedelta(seconds=90), usegmt=True)},
    )
    await _run(delivery)
    event = await _get(session, event_id)
    assert event.next_attempt_at is not None
    assert 88 <= (event.next_attempt_at - clock.now).total_seconds() <= 91


async def test_429_counts_toward_dead_letter(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(
        session, room.active, room.conversation_id, room.sender, 1, status="retry", attempt_count=5
    )
    receiver.respond = _resp(429, headers={"retry-after": "10"})
    await _run(delivery)
    assert (await _get(session, event_id)).status == "dead"


# --- retry_later -------------------------------------------------------------------------


async def test_retry_later_pauses_the_recipient_to_one_probe_per_five_minutes(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    clock: Clock,
    factory: async_sessionmaker[AsyncSession],
) -> None:
    room = await _fresh_room(session)
    second = await _start(
        session,
        actor_sub=room.sender.sub,
        initiator_agent_id=room.sender.id,
        conversation_type="open",
        target_agent_ids=[room.active.id],
        initial_message={"action": "report_status"},
        message_type="task_assign",
    )
    await session.execute(delete(WakeEvent))
    await session.commit()
    a1 = await _event(
        session, room.active, room.conversation_id, room.sender, 1, age=timedelta(seconds=9)
    )
    a2 = await _event(
        session, room.active, room.conversation_id, room.sender, 2, age=timedelta(seconds=8)
    )
    b1 = await _event(session, room.active, second.id, room.sender, 1, age=timedelta(seconds=7))
    other = await _event(
        session, room.invited, room.conversation_id, room.sender, 1, age=timedelta(seconds=6)
    )

    def respond(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content)["data"]["recipientAgentId"] == str(room.active.id):
            return httpx.Response(409, json={"status": "retry_later", "reason": "spend limit"})
        return httpx.Response(200, json=ACCEPTED)

    receiver.respond = respond
    await _run(delivery)
    # a1, b1 (heads of their pairs) and the other recipient's event went out together.
    assert {c.headers["webhook-id"] for c in receiver.calls} == {str(a1), str(b1), str(other)}
    assert (await _get(session, a1)).status == "retry_later"
    assert (await _get(session, b1)).status == "retry_later"
    assert (await _get(session, a1)).attempt_count == 0  # retry_later does not consume the sequence

    # Paused: nothing for `active` before the 5 minutes pass; other recipients unaffected.
    third = await _event(session, room.invited, room.conversation_id, room.sender, 2)
    clock.advance(seconds=RETRY_LATER_SECONDS - 1)
    calls = len(receiver.calls)
    await _run(delivery)
    assert [c.headers["webhook-id"] for c in receiver.calls[calls:]] == [str(third)]

    # Due: exactly one probe, although two events of this recipient are due.
    clock.advance(seconds=1)
    calls = len(receiver.calls)
    await _run(delivery)
    assert [c.headers["webhook-id"] for c in receiver.calls[calls:]] == [str(a1)]
    assert (await _get(session, a1)).next_attempt_at == clock.now + timedelta(
        seconds=RETRY_LATER_SECONDS
    )
    await _run(delivery)
    assert len(receiver.calls) == calls + 1

    # Accepted probe: events flow again, each pair in order.
    receiver.respond = lambda r: httpx.Response(200, json=ACCEPTED)
    clock.advance(seconds=RETRY_LATER_SECONDS)
    calls = len(receiver.calls)
    await _run(delivery)
    assert [c.headers["webhook-id"] for c in receiver.calls[calls:]] == [str(a1)]
    await _run(delivery)
    await _run(delivery)
    sent = [c.headers["webhook-id"] for c in receiver.calls[calls:]]
    assert sorted(sent) == sorted([str(a1), str(a2), str(b1)])
    assert sent.index(str(a1)) < sent.index(str(a2))
    for event_id in (a1, a2, b1):
        assert (await _get(session, event_id)).status == "delivered"


async def test_retry_later_event_is_dead_lettered_after_24_hours(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    e1 = await _event(
        session,
        room.active,
        room.conversation_id,
        room.sender,
        1,
        age=timedelta(hours=23, minutes=58),
    )
    receiver.respond = _resp(409, json={"status": "retry_later"})
    await _run(delivery)
    assert (await _get(session, e1)).status == "retry_later"
    clock.advance(minutes=3)
    await _run(delivery)
    assert (await _get(session, e1)).status == "dead"
    assert len(receiver.calls) == 1


# --- 24 hours, no target, allowlist -----------------------------------------------------------


@pytest.mark.parametrize("status", ["pending", "retry", "retry_later"])
async def test_events_undelivered_after_24_hours_are_dead_whatever_their_state(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, status: str
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(
        session,
        room.active,
        room.conversation_id,
        room.sender,
        1,
        age=timedelta(hours=24, seconds=1),
        status=status,
    )
    await _run(delivery)
    event = await _get(session, event_id)
    assert (event.status, event.next_attempt_at) == ("dead", None)
    assert receiver.calls == []


async def test_no_target_fails_with_a_clear_error(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    room = await _fresh_room(session)
    await session.execute(delete(WakeTarget).where(WakeTarget.agent_id == room.active.id))
    await session.commit()
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    await _run(delivery)
    event = await _get(session, event_id)
    assert (event.status, event.last_error) == ("failed", "no wake target registered")
    assert receiver.calls == []


async def test_host_no_longer_on_the_allowlist_fails_the_event(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, "*.other.net")
    await _run(delivery)
    event = await _get(session, event_id)
    assert (event.status, event.last_error) == (
        "failed",
        "wake target host is not on the allowed host list",
    )
    assert receiver.calls == []


async def test_real_invite_row_is_delivered_before_the_messages_that_follow_it(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver
) -> None:
    sender = await _agent(session, "inv-sender")
    invitee = await _agent(session, "inv-invitee")
    await _targets(session, sender, invitee)
    conversation = await _start(
        session,
        actor_sub=sender.sub,
        initiator_agent_id=sender.id,
        conversation_type="open",
        target_agent_ids=[invitee.id],
        initial_message={"action": "report_status"},
        message_type="task_assign",
    )
    invite = (
        await session.execute(
            select(WakeEvent).where(
                WakeEvent.recipient_agent_id == invitee.id, WakeEvent.kind == "invite"
            )
        )
    ).scalar_one()
    assert (invite.seq, invite.message_type) == (None, None)
    # A message event for the same pair recorded later, and one recorded "earlier".
    later = await _event(session, invitee, conversation.id, sender, 5, age=timedelta(seconds=0))
    earlier = await _event(session, invitee, conversation.id, sender, 6, age=timedelta(hours=1))

    sent: list[str] = []
    for _ in range(3):
        await _run(delivery)
    sent = [c.headers["webhook-id"] for c in receiver.calls]
    assert sent == [str(invite.id), str(later), str(earlier)]
    body = json.loads(receiver.calls[0].content)
    assert body["data"]["kind"] == "invite"
    assert body["data"]["seq"] is None
    assert body["data"]["messageType"] is None
    assert body["data"]["senderAgentId"] == str(sender.id)
    assert receiver.calls[0].headers["webhook-signature"] == _expected_signature(receiver.calls[0])
    assert (await _get(session, invite.id)).status == "delivered"


@pytest.mark.parametrize("setting", ["", " , ", "*", "*.,foo*,.bad..host"])
async def test_misconfigured_allowlist_sends_nothing_and_loses_no_event(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, setting)
    for _ in range(10):  # far more passes than the backoff schedule has steps
        await _run(delivery)
        clock.advance(seconds=ALLOWLIST_MISCONFIGURED_RETRY_SECONDS)
    event = await _get(session, event_id)
    assert (event.status, event.attempt_count) == ("retry", 0)
    assert event.last_error == "host allowlist is empty or invalid"
    assert receiver.calls == []

    # The operator fixes the setting: the same event goes out.
    monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, "*.ts.net")
    await _run(delivery)
    assert (await _get(session, event_id)).status == "delivered"
    assert len(receiver.calls) == 1


async def test_misconfigured_allowlist_unset_does_not_crash_the_loop(
    session: AsyncSession, delivery: WakeDelivery, monkeypatch: pytest.MonkeyPatch
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    monkeypatch.delenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR)
    await delivery.start()
    try:
        await asyncio.sleep(0.3)
        assert delivery._loop_task is not None and not delivery._loop_task.done()
    finally:
        await delivery.stop()


# --- isolation and leases -------------------------------------------------


async def test_hanging_receiver_does_not_block_a_concurrent_post_message(
    session: AsyncSession,
    engine: AsyncEngine,
    factory: async_sessionmaker[AsyncSession],
    receiver: Receiver,
    clock: Clock,
) -> None:
    room = await _fresh_room(session)
    await _event(session, room.active, room.conversation_id, room.sender, 1)
    release = asyncio.Event()

    async def hang(request: httpx.Request) -> httpx.Response:
        await release.wait()
        return httpx.Response(200, json=ACCEPTED)

    receiver.respond = hang
    client = httpx.AsyncClient(transport=httpx.MockTransport(receiver))
    delivery = WakeDelivery(
        session_factory=lambda: factory, client=client, clock=clock, send_timeout=30
    )
    try:
        started = time.monotonic()
        await delivery.tick()
        assert time.monotonic() - started < 2  # tick starts the send; it does not wait for it
        for _ in range(100):
            if receiver.calls:
                break
            await asyncio.sleep(0.02)
        assert len(receiver.calls) == 1 and delivery._in_flight

        async with factory() as other_session:
            started = time.monotonic()
            await _post(other_session, room.sender, room.conversation_id)
            assert time.monotonic() - started < 5
        assert delivery._in_flight  # still hanging
    finally:
        release.set()
        await delivery.drain()
        await client.aclose()


async def test_claim_whose_process_died_is_resent_after_the_lease_expires(
    session: AsyncSession, delivery: WakeDelivery, receiver: Receiver, clock: Clock
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    # A process claims the event and dies before sending.
    claims = await delivery._claim(5, clock())
    assert len(claims) == 1
    event = await _get(session, event_id)
    assert event.attempt_count == 1
    assert event.next_attempt_at == clock.now + timedelta(seconds=LEASE_SECONDS)

    clock.advance(seconds=LEASE_SECONDS - 1)
    await _run(delivery)
    assert receiver.calls == []  # leased: not sent twice concurrently

    clock.advance(seconds=1)
    await _run(delivery)
    assert [c.headers["webhook-id"] for c in receiver.calls] == [str(event_id)]
    event = await _get(session, event_id)
    assert (event.status, event.attempt_count) == ("delivered", 2)


async def test_no_row_lock_is_held_during_the_http_call(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    factory: async_sessionmaker[AsyncSession],
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)
    seen: dict[str, Any] = {}

    async def respond(request: httpx.Request) -> httpx.Response:
        async with factory() as other:
            await other.execute(text("SET LOCAL lock_timeout = '500ms'"))
            row = (
                await other.execute(
                    select(WakeEvent.id)
                    .where(WakeEvent.id == event_id)
                    .with_for_update(nowait=True)
                )
            ).scalar_one()
            seen["locked_ok"] = row
            activity = (
                await other.execute(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' "
                        "AND pid <> pg_backend_pid()"
                    )
                )
            ).scalar_one()
            seen["idle_in_tx"] = activity
        return httpx.Response(200, json=ACCEPTED)

    receiver.respond = respond
    await _run(delivery)
    assert seen["locked_ok"] == event_id
    # The test's own `session` may be idle in a transaction; the delivery task holds none.
    assert seen["idle_in_tx"] <= 1


# --- logs and errors ------------------------------------------------------


async def test_no_secret_signature_or_body_in_logs_or_last_error(
    session: AsyncSession,
    delivery: WakeDelivery,
    receiver: Receiver,
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    room = await _fresh_room(session)
    ids = [
        await _event(session, room.active, room.conversation_id, room.sender, 1),
        await _event(session, room.invited, room.conversation_id, room.sender, 1),
    ]
    answers = iter(
        [
            httpx.Response(503, text=RESPONSE_MARKER),
            httpx.Response(200, text=RESPONSE_MARKER),
            httpx.Response(401, text=RESPONSE_MARKER),
        ]
    )
    receiver.respond = lambda r: next(answers)
    await _run(delivery)
    clock.advance(seconds=5)
    await _run(delivery)

    forbidden = {
        SECRET,
        SECRET.removeprefix("whsec_"),
        RESPONSE_MARKER,
        "query-secret-value",
        *(c.headers["webhook-signature"] for c in receiver.calls),
        *(c.content.decode() for c in receiver.calls),
    }
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "wake delivery event=" in log_text
    for item in forbidden:
        assert item not in log_text
    for event_id in ids:
        event = await _get(session, event_id)
        for item in forbidden:
            assert item not in (event.last_error or "")


# --- lifecycle ------------------------------------------------------------


async def test_started_client_uses_tailnet_mounts_and_never_follows_redirects(
    factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TAILNET_HTTP_PROXY", "http://127.0.0.1:1055")
    task = WakeDelivery(session_factory=lambda: factory)
    await task.start()
    try:
        client = task._client
        assert client is not None
        assert client.follow_redirects is False
        assert client.timeout == httpx.Timeout(wake_delivery.SEND_TIMEOUT_SECONDS)
        assert [m.pattern for m in client._mounts] == ["all://*.ts.net"]
    finally:
        await task.stop()
    assert client.is_closed


async def test_task_starts_and_stops_with_the_server(
    factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_comms_tools import _import_main

    created: list[WakeDelivery] = []

    class Spy(WakeDelivery):
        def __init__(self) -> None:
            super().__init__()
            created.append(self)

    monkeypatch.setattr(wake_delivery, "WakeDelivery", Spy)
    monkeypatch.setattr(wake_delivery, "get_session_factory", lambda: factory)
    main = _import_main()
    # The streamable-http app enters exactly this manager at startup and leaves it at shutdown.
    async with main.mcp._lifespan_manager():
        assert len(created) == 1
        loop_task = created[0]._loop_task
        client = created[0]._client
        assert loop_task is not None and not loop_task.done()
        assert client is not None and not client.is_closed
    assert loop_task.done()
    assert client.is_closed
    assert created[0]._loop_task is None


async def test_stop_cancels_sends_in_flight_and_leaves_the_lease(
    session: AsyncSession,
    factory: async_sessionmaker[AsyncSession],
    receiver: Receiver,
    clock: Clock,
) -> None:
    room = await _fresh_room(session)
    event_id = await _event(session, room.active, room.conversation_id, room.sender, 1)

    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        return httpx.Response(200, json=ACCEPTED)

    receiver.respond = hang
    client = httpx.AsyncClient(transport=httpx.MockTransport(receiver))
    task = WakeDelivery(
        session_factory=lambda: factory, client=client, clock=clock, send_timeout=30
    )
    await task.tick()
    for _ in range(100):
        if receiver.calls:
            break
        await asyncio.sleep(0.02)
    await asyncio.wait_for(task.stop(), timeout=5)
    await client.aclose()
    event = await _get(session, event_id)
    assert (event.status, event.attempt_count) == ("pending", 1)
    assert event.next_attempt_at == clock.now + timedelta(seconds=LEASE_SECONDS)
