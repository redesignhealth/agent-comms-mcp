"""Tests for TECH-9907: wake events recorded on post, and open-conversation tracking.

Real Postgres only (shared fixtures in ``tests/conftest.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import delete, event, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import plugins
import service as _service
from models import Agent, ApprovalHold, WakeEvent, WakeRule, WakeSession, WakeTarget
from schemas import MESSAGE_TYPES, PayloadValidationError
from service import (
    AgentTableOwnershipClient,
    accept_invite,
    archive_conversation,
    register_agent,
)
from wake_events import WAKE_SESSION_WINDOW_SECONDS, record_message_wake_events
from wake_rules import ensure_catch_all, update_wake_rule

pytestmark = pytest.mark.usefixtures("_migrated_schema")


class _AllowAllDocsVerifier:
    async def verify(self, ctx: plugins.DocsVerificationContext) -> plugins.DocsVerificationResult:
        return plugins.DocsVerificationResult(verified=True, reason=None, detail=None)


class _AlwaysHighRiskScorer:
    async def score(self, ctx: plugins.MessageRiskContext) -> plugins.RiskVerdict:
        return plugins.RiskVerdict(high_risk=True, reason="boundary_crossing", detail=None)


async def _start(session: AsyncSession, **kwargs: Any) -> Any:
    risk_scorer = kwargs.pop("risk_scorer", None)
    return await _service.start_conversation(
        session,
        ownership_client=AgentTableOwnershipClient(session),
        risk_scorer=risk_scorer or plugins.BoundaryCrossingScorer(),
        auto_approver=plugins.EscalateAllAutoApprover(),
        notifier=plugins.LogOnlyNotifier(),
        active_checker=plugins.AlwaysActiveChecker(),
        docs_verifier=_AllowAllDocsVerifier(),
        **kwargs,
    )


async def _post(session: AsyncSession, sender: Agent, conversation_id: uuid.UUID, **kw: Any) -> Any:
    kw.setdefault("message_type", "task_assign")
    kw.setdefault("payload", {"action": "report_status", "priority": "high"})
    return await _service.post_message(
        session,
        actor_sub=sender.sub,
        sender_agent_id=sender.id,
        conversation_id=conversation_id,
        ownership_client=AgentTableOwnershipClient(session),
        risk_scorer=plugins.BoundaryCrossingScorer(),
        auto_approver=plugins.EscalateAllAutoApprover(),
        notifier=plugins.LogOnlyNotifier(),
        docs_verifier=_AllowAllDocsVerifier(),
        **kw,
    )


def _opener() -> dict[str, Any]:
    return {"action": "report_status"}


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


async def _agent(session: AsyncSession, sub: str, *, target: bool = True) -> Agent:
    agent = await register_agent(
        session,
        sub=sub,
        base_sub=sub,
        owner_sub=f"owner-{sub}",
        owner_email=f"{sub}@example.com",
        display_name=sub,
        accepted_types=sorted(MESSAGE_TYPES),
        is_shared_authorized=True,
    )
    if target:
        session.add(
            WakeTarget(
                agent_id=agent.id,
                url="https://x.example/wake",
                secret_ciphertext=b"s",
                system_label="test",
            )
        )
        await session.commit()
    return agent


class _Room:
    """sender (target) + active (target) + active_no_target + invited (target)."""

    sender: Agent
    active: Agent
    active_no_target: Agent
    invited: Agent
    conversation_id: uuid.UUID


async def _room(session: AsyncSession) -> _Room:
    room = _Room()
    room.sender = await _agent(session, "wk-sender")
    room.active = await _agent(session, "wk-active")
    room.active_no_target = await _agent(session, "wk-notarget", target=False)
    room.invited = await _agent(session, "wk-invited")
    conversation = await _start(
        session,
        actor_sub=room.sender.sub,
        initiator_agent_id=room.sender.id,
        conversation_type="open",
        target_agent_ids=[room.active.id, room.active_no_target.id, room.invited.id],
        initial_message=_opener(),
        message_type="task_assign",
    )
    room.conversation_id = conversation.id
    for agent in (room.active, room.active_no_target):
        await accept_invite(
            session, actor_sub=agent.sub, agent_id=agent.id, conversation_id=conversation.id
        )
    # Starting the conversation recorded invite events and sessions for the
    # invitees (TECH-9910, covered in test_wake_events_invites_holds.py). These
    # tests are about message events, so start them from a clean slate; the
    # sender's own session, opened by the opener, is kept.
    await session.execute(delete(WakeEvent))
    await session.execute(delete(WakeRule))  # catch-alls are created lazily
    await session.execute(delete(WakeSession).where(WakeSession.agent_id != room.sender.id))
    await session.commit()
    return room


async def _events(session: AsyncSession) -> list[WakeEvent]:
    return list(
        (
            await session.execute(
                select(WakeEvent)
                .order_by(WakeEvent.created_at)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )


async def _wake_session(
    session: AsyncSession, agent: Agent, conversation_id: uuid.UUID
) -> WakeSession | None:
    return (
        await session.execute(
            select(WakeSession)
            .where(WakeSession.agent_id == agent.id, WakeSession.conversation_id == conversation_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _set_catch_all(session: AsyncSession, agent: Agent, action: str) -> None:
    rule = await ensure_catch_all(session, agent_id=agent.id)
    await update_wake_rule(
        session, actor_sub=agent.sub, agent_id=agent.id, rule_id=rule.id, action=action
    )


async def _set_session(
    session: AsyncSession,
    agent: Agent,
    conversation_id: uuid.UUID,
    *,
    age: timedelta,
    closed: bool = False,
) -> None:
    at = datetime.now(UTC) - age
    session.add(
        WakeSession(
            agent_id=agent.id,
            conversation_id=conversation_id,
            opened_at=at,
            last_activity_at=at,
            closed_at=at if closed else None,
            closed_reason="agent_closed" if closed else None,
            session_ref="run-1",
        )
    )
    await session.commit()


async def test_post_records_one_pending_event_per_active_recipient_with_target(
    session: AsyncSession,
) -> None:
    room = await _room(session)
    assert await _events(session) == []  # the opener has only invited recipients

    message = await _post(session, room.sender, room.conversation_id)

    events = await _events(session)
    assert len(events) == 1  # not the sender, the target-less agent or the invited agent
    e = events[0]
    assert (e.recipient_agent_id, e.conversation_id, e.kind) == (
        room.active.id,
        room.conversation_id,
        "message",
    )
    assert (e.seq, e.message_type, e.sender_agent_id) == (
        message.seq,
        "task_assign",
        room.sender.id,
    )
    assert (e.reason, e.status, e.attempt_count) == ("rule", "pending", 0)
    assert await _wake_session(session, room.active_no_target, room.conversation_id) is None
    assert await _wake_session(session, room.invited, room.conversation_id) is None


async def test_opener_opens_senders_session_and_records_no_event(session: AsyncSession) -> None:
    room = await _room(session)
    assert await _events(session) == []
    own = await _wake_session(session, room.sender, room.conversation_id)
    assert own is not None and own.closed_at is None


async def test_poster_without_target_gets_no_session(session: AsyncSession) -> None:
    room = await _room(session)
    await _post(session, room.active_no_target, room.conversation_id)
    assert await _wake_session(session, room.active_no_target, room.conversation_id) is None


async def test_posters_own_session_opens_and_keeps_session_ref(session: AsyncSession) -> None:
    room = await _room(session)
    await _set_session(session, room.active, room.conversation_id, age=timedelta(minutes=30))
    await _post(session, room.active, room.conversation_id)
    own = await _wake_session(session, room.active, room.conversation_id)
    assert own is not None and own.closed_at is None and own.session_ref == "run-1"
    assert (datetime.now(UTC) - own.last_activity_at) < timedelta(minutes=1)


async def test_poll_rule_records_nothing(session: AsyncSession) -> None:
    room = await _room(session)
    await _set_catch_all(session, room.active, "poll")
    await _post(session, room.sender, room.conversation_id)
    assert await _events(session) == []
    assert await _wake_session(session, room.active, room.conversation_id) is None


async def test_specific_rule_matches_payload_fields(session: AsyncSession) -> None:
    room = await _room(session)
    from wake_rules import add_wake_rule

    await _set_catch_all(session, room.active, "poll")
    await add_wake_rule(
        session,
        actor_sub="a",
        agent_id=room.active.id,
        action="wake",
        match_task_action="report_status",
        match_message_priority="high",
    )
    await _post(session, room.sender, room.conversation_id)
    assert [e.reason for e in await _events(session)] == ["rule"]


async def test_open_session_overrides_poll_rule(session: AsyncSession) -> None:
    room = await _room(session)
    await _set_catch_all(session, room.active, "poll")
    await _set_session(session, room.active, room.conversation_id, age=timedelta(minutes=1))
    await _post(session, room.sender, room.conversation_id)
    events = await _events(session)
    assert [e.reason for e in events] == ["open_conversation"]


async def test_quiet_session_closes_and_rules_apply_again(session: AsyncSession) -> None:
    room = await _room(session)
    quiet = timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS + 60)
    await _set_catch_all(session, room.active, "poll")
    await _set_session(session, room.active, room.conversation_id, age=quiet)
    await _post(session, room.sender, room.conversation_id)
    assert await _events(session) == []
    closed = await _wake_session(session, room.active, room.conversation_id)
    assert closed is not None
    assert closed.closed_reason == "quiet" and closed.closed_at is not None
    assert closed.session_ref == "run-1"

    # Rules say wake: the session reopens as a new period, without the old session_ref.
    await _set_catch_all(session, room.active, "wake")
    await _post(session, room.sender, room.conversation_id)
    assert [e.reason for e in await _events(session)] == ["rule"]
    reopened = await _wake_session(session, room.active, room.conversation_id)
    assert reopened is not None
    assert reopened.closed_at is None and reopened.closed_reason is None
    assert reopened.session_ref is None


async def test_quiet_session_woken_by_rule_restarts_without_old_session_ref(
    session: AsyncSession,
) -> None:
    room = await _room(session)
    quiet = timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS + 60)
    await _set_session(session, room.active, room.conversation_id, age=quiet)  # catch-all wakes
    await _post(session, room.sender, room.conversation_id)
    assert [e.reason for e in await _events(session)] == ["rule"]
    restarted = await _wake_session(session, room.active, room.conversation_id)
    assert restarted is not None and restarted.closed_at is None
    assert restarted.session_ref is None


async def test_open_session_keeps_its_session_ref(session: AsyncSession) -> None:
    room = await _room(session)
    await _set_session(session, room.active, room.conversation_id, age=timedelta(minutes=1))
    await _post(session, room.sender, room.conversation_id)
    kept = await _wake_session(session, room.active, room.conversation_id)
    assert kept is not None and kept.session_ref == "run-1"


async def test_explicitly_closed_session_does_not_override_rules(session: AsyncSession) -> None:
    room = await _room(session)
    await _set_catch_all(session, room.active, "poll")
    await _set_session(
        session, room.active, room.conversation_id, age=timedelta(minutes=1), closed=True
    )
    await _post(session, room.sender, room.conversation_id)
    assert await _events(session) == []


async def test_denied_message_leaves_no_wake_rows(session: AsyncSession) -> None:
    room = await _room(session)
    with pytest.raises(PayloadValidationError):  # about_seq does not exist: the last gate
        await _post(
            session,
            room.sender,
            room.conversation_id,
            message_type="needs_clarification",
            payload={"about_seq": 999},
        )
    assert await _events(session) == []
    assert await _wake_session(session, room.active, room.conversation_id) is None


async def test_held_message_leaves_no_wake_rows(session: AsyncSession) -> None:
    room = await _room(session)
    result = await _post(session, room.sender, room.conversation_id, review_reason="check")
    assert isinstance(result, ApprovalHold)
    assert await _events(session) == []
    assert await _wake_session(session, room.active, room.conversation_id) is None


async def test_held_opener_marker_leaves_no_event_or_session(session: AsyncSession) -> None:
    sender = await _agent(session, "wk-h-sender")
    target = await _agent(session, "wk-h-target")
    conversation = await _start(
        session,
        actor_sub=sender.sub,
        initiator_agent_id=sender.id,
        conversation_type="open",
        target_agent_ids=[target.id],
        initial_message=_opener(),
        message_type="task_assign",
        risk_scorer=_AlwaysHighRiskScorer(),
    )
    assert conversation.pending_hold is not None
    # Only the invitee's invite event: the marker records nothing.
    assert [(e.kind, e.recipient_agent_id) for e in await _events(session)] == [
        ("invite", target.id)
    ]
    assert await _wake_session(session, sender, conversation.id) is None


async def test_archive_closes_open_sessions(session: AsyncSession) -> None:
    room = await _room(session)
    await _post(session, room.sender, room.conversation_id)
    await archive_conversation(
        session,
        actor_sub=room.sender.sub,
        agent_id=room.sender.id,
        conversation_id=room.conversation_id,
    )
    for agent in (room.sender, room.active):
        s = await _wake_session(session, agent, room.conversation_id)
        assert s is not None
        assert (s.closed_reason, s.closed_at is not None) == ("conversation_ended", True)


async def test_query_count_does_not_grow_with_recipient_count(
    session: AsyncSession, engine: AsyncEngine
) -> None:
    sender = await _agent(session, "wk-q-sender")
    conversation = await _start(
        session,
        actor_sub=sender.sub,
        initiator_agent_id=sender.id,
        conversation_type="open",
        target_agent_ids=[(await _agent(session, "wk-q-seed")).id],
        initial_message=_opener(),
        message_type="task_assign",
    )

    async def statements(recipients: list[Agent], seq: int) -> int:
        count = 0

        def _count(*_args: Any) -> None:
            nonlocal count
            count += 1

        event.listen(engine.sync_engine, "before_cursor_execute", _count)
        try:
            await record_message_wake_events(
                session,
                conversation_id=conversation.id,
                seq=seq,
                message_type="task_assign",
                payload={"action": "report_status"},
                sender_agent_id=sender.id,
                recipient_agent_ids=[r.id for r in recipients],
                now=datetime.now(UTC),
            )
            await session.flush()
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", _count)
        return count

    small = [await _agent(session, f"wk-q-a{i}") for i in range(2)]
    large = [await _agent(session, f"wk-q-b{i}") for i in range(8)]
    few = await statements(small, 10)
    many = await statements(large, 11)
    assert many == few
    assert len([e for e in await _events(session) if e.kind == "message"]) == 10


async def test_hook_never_commits_so_rollback_leaves_no_wake_rows(
    session: AsyncSession, engine: AsyncEngine
) -> None:
    room = await _room(session)
    active_id, conversation_id = room.active.id, room.conversation_id
    await record_message_wake_events(
        session,
        conversation_id=conversation_id,
        seq=50,
        message_type="task_assign",
        payload={"action": "report_status"},
        sender_agent_id=room.sender.id,
        recipient_agent_ids=[active_id],
        now=datetime.now(UTC),
    )
    await session.flush()
    await session.rollback()  # e.g. a denial raised after the hook ran

    async with engine.connect() as conn:
        for table in ("wake_events", "wake_rules"):
            count = (await conn.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()
            assert count == 0, table
        sessions = (
            await conn.execute(
                text("SELECT count(*) FROM wake_sessions WHERE agent_id = :a"),
                {"a": active_id},
            )
        ).scalar_one()
        assert sessions == 0


async def test_sender_listed_as_recipient_gets_no_event(session: AsyncSession) -> None:
    room = await _room(session)
    await record_message_wake_events(
        session,
        conversation_id=room.conversation_id,
        seq=60,
        message_type="task_assign",
        payload={"action": "report_status"},
        sender_agent_id=room.sender.id,
        recipient_agent_ids=[room.sender.id, room.active.id],
        now=datetime.now(UTC),
    )
    await session.flush()
    assert [e.recipient_agent_id for e in await _events(session)] == [room.active.id]


async def test_naive_now_is_rejected(session: AsyncSession) -> None:
    room = await _room(session)
    with pytest.raises(ValueError, match="timezone-aware"):
        await record_message_wake_events(
            session,
            conversation_id=room.conversation_id,
            seq=61,
            message_type="task_assign",
            payload={},
            sender_agent_id=room.sender.id,
            recipient_agent_ids=[room.active.id],
            now=datetime.now(),
        )
