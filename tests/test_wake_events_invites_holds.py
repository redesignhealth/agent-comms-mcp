"""Tests for TECH-9910: wake events for invites, and for messages and invites
released from a hold.

Real Postgres only (shared fixtures in ``tests/conftest.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import plugins
import service as _service
from models import Agent, ApprovalHold, Message, WakeEvent
from service import AgentTableOwnershipClient, accept_invite
from tests.test_wake_events import (
    _agent,
    _AllowAllDocsVerifier,
    _AlwaysHighRiskScorer,
    _events,
    _opener,
    _start,
    _wake_session,
)
from wake_events import record_invite_wake_events
from wake_rules import add_wake_rule

pytestmark = pytest.mark.usefixtures("_migrated_schema")


class _ClearAllApprover:
    async def review(self, ctx: plugins.HoldContext) -> plugins.AutoDecision:
        return plugins.AutoDecision(cleared=True, detail={"stub": "clear"})


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables_9910(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE wake_targets, wake_events, wake_sessions, wake_rules, "
                "approval_holds, audit_log, messages, participants, conversations, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


async def _invite(
    session: AsyncSession,
    inviter: Agent,
    conversation_id: uuid.UUID,
    target: Agent,
    *,
    auto_approver: plugins.AutoApprover | None = None,
) -> Any:
    return await _service.invite(
        session,
        actor_sub=inviter.sub,
        inviter_agent_id=inviter.id,
        conversation_id=conversation_id,
        target_agent_id=target.id,
        ownership_client=AgentTableOwnershipClient(session),
        active_checker=plugins.AlwaysActiveChecker(),
        auto_approver=auto_approver or plugins.EscalateAllAutoApprover(),
        notifier=plugins.LogOnlyNotifier(),
    )


async def _post(
    session: AsyncSession,
    sender: Agent,
    conversation_id: uuid.UUID,
    *,
    risk_scorer: plugins.RiskScorer | None = None,
    auto_approver: plugins.AutoApprover | None = None,
    **kw: Any,
) -> Any:
    kw.setdefault("message_type", "task_assign")
    kw.setdefault("payload", {"action": "report_status", "priority": "high"})
    return await _service.post_message(
        session,
        actor_sub=sender.sub,
        sender_agent_id=sender.id,
        conversation_id=conversation_id,
        ownership_client=AgentTableOwnershipClient(session),
        risk_scorer=risk_scorer or plugins.BoundaryCrossingScorer(),
        auto_approver=auto_approver or plugins.EscalateAllAutoApprover(),
        notifier=plugins.LogOnlyNotifier(),
        docs_verifier=_AllowAllDocsVerifier(),
        **kw,
    )


async def _decide(session: AsyncSession, hold: ApprovalHold, owner: Agent, decision: str) -> Any:
    return await _service.decide_hold(
        session,
        approver_sub=owner.owner_sub,
        hold_id=hold.id,
        decision=decision,
        reason=None,
        ownership_client=AgentTableOwnershipClient(session),
        active_checker=plugins.AlwaysActiveChecker(),
    )


async def _open_conversation(
    session: AsyncSession, inviter: Agent, targets: list[Agent], **kw: Any
) -> Any:
    return await _start(
        session,
        actor_sub=inviter.sub,
        initiator_agent_id=inviter.id,
        conversation_type="open",
        target_agent_ids=[t.id for t in targets],
        initial_message=_opener(),
        message_type="task_assign",
        **kw,
    )


async def _with_note_history(session: AsyncSession, conversation_id: uuid.UUID) -> None:
    """Make later invites subject to the note-history hold (TECH-5735)."""
    first = (
        (await session.execute(select(Message).where(Message.conversation_id == conversation_id)))
        .scalars()
        .first()
    )
    assert first is not None
    session.add(
        Message(
            conversation_id=conversation_id,
            seq=99,
            sender_id=first.sender_id,
            type="note",
            schema_version=1,
            payload={"text": "hello"},
        )
    )
    await session.commit()


def _invite_event_shape(event: WakeEvent, recipient: Agent, inviter: Agent) -> None:
    assert event.kind == "invite"
    assert event.seq is None
    assert event.message_type is None
    assert event.recipient_agent_id == recipient.id
    assert event.sender_agent_id == inviter.id
    assert event.status == "pending"
    assert event.reason == "rule"


# --- invites ---------------------------------------------------------------------


async def test_start_conversation_wakes_each_invitee_with_a_target(session: AsyncSession) -> None:
    inviter = await _agent(session, "i-inviter")
    a = await _agent(session, "i-a")
    b = await _agent(session, "i-b", target=False)
    conversation = await _open_conversation(session, inviter, [a, b])

    events = await _events(session)
    assert len(events) == 1
    _invite_event_shape(events[0], a, inviter)
    assert events[0].conversation_id == conversation.id
    assert await _wake_session(session, a, conversation.id) is not None
    assert await _wake_session(session, b, conversation.id) is None


async def test_direct_invite_wakes_the_invitee(session: AsyncSession) -> None:
    inviter = await _agent(session, "d-inviter")
    first = await _agent(session, "d-first")
    new = await _agent(session, "d-new")
    conversation = await _open_conversation(session, inviter, [first])
    before = len(await _events(session))

    result = await _invite(session, inviter, conversation.id, new)
    assert not isinstance(result, ApprovalHold)

    events = await _events(session)
    assert len(events) == before + 1
    _invite_event_shape(events[-1], new, inviter)
    assert await _wake_session(session, new, conversation.id) is not None


async def test_invitee_without_wake_target_gets_nothing(session: AsyncSession) -> None:
    inviter = await _agent(session, "n-inviter")
    first = await _agent(session, "n-first")
    new = await _agent(session, "n-new", target=False)
    conversation = await _open_conversation(session, inviter, [first])
    before = len(await _events(session))
    await _invite(session, inviter, conversation.id, new)
    assert len(await _events(session)) == before
    assert await _wake_session(session, new, conversation.id) is None


async def test_held_invite_records_nothing_then_auto_clear_records_once(
    session: AsyncSession,
) -> None:
    inviter = await _agent(session, "ac-inviter")
    first = await _agent(session, "ac-first")
    new = await _agent(session, "ac-new")
    conversation = await _open_conversation(session, inviter, [first])
    await _with_note_history(session, conversation.id)
    before = len(await _events(session))

    held = await _invite(session, inviter, conversation.id, new)
    assert isinstance(held, ApprovalHold)
    assert len(await _events(session)) == before  # nothing while held

    new2 = await _agent(session, "ac-new2")
    cleared = await _invite(
        session, inviter, conversation.id, new2, auto_approver=_ClearAllApprover()
    )
    assert not isinstance(cleared, ApprovalHold)
    events = await _events(session)
    assert len(events) == before + 1  # exactly one: no double recording
    _invite_event_shape(events[-1], new2, inviter)


async def test_human_approved_invite_hold_records_once_and_rejected_records_none(
    session: AsyncSession,
) -> None:
    inviter = await _agent(session, "h-inviter")
    first = await _agent(session, "h-first")
    approved = await _agent(session, "h-approved")
    rejected = await _agent(session, "h-rejected")
    conversation = await _open_conversation(session, inviter, [first])
    await _with_note_history(session, conversation.id)
    before = len(await _events(session))

    hold_ok = await _invite(session, inviter, conversation.id, approved)
    hold_no = await _invite(session, inviter, conversation.id, rejected)
    assert isinstance(hold_ok, ApprovalHold) and isinstance(hold_no, ApprovalHold)
    assert len(await _events(session)) == before

    await _decide(session, hold_no, inviter, "reject")
    assert len(await _events(session)) == before

    await _decide(session, hold_ok, inviter, "approve")
    events = await _events(session)
    assert len(events) == before + 1
    _invite_event_shape(events[-1], approved, inviter)


async def test_invite_poll_rule_suppresses_invite_but_messages_still_wake(
    session: AsyncSession,
) -> None:
    inviter = await _agent(session, "p-inviter")
    first = await _agent(session, "p-first")
    invitee = await _agent(session, "p-invitee")
    await add_wake_rule(
        session,
        actor_sub=invitee.sub,
        agent_id=invitee.id,
        action="poll",
        match_message_type="invite",
    )
    conversation = await _open_conversation(session, inviter, [first])
    before = len(await _events(session))

    await _invite(session, inviter, conversation.id, invitee)
    assert len(await _events(session)) == before
    assert await _wake_session(session, invitee, conversation.id) is None

    await accept_invite(
        session, actor_sub=invitee.sub, agent_id=invitee.id, conversation_id=conversation.id
    )
    await _post(session, inviter, conversation.id)
    events = await _events(session)
    assert [e.kind for e in events[before:]] == ["message"]
    assert events[-1].recipient_agent_id == invitee.id


async def test_reinvite_records_a_second_event(session: AsyncSession) -> None:
    # `invite` itself refuses an agent that already has a participant row, so
    # a re-invite is exercised on the recording function directly: nothing
    # may dedupe a legitimate second invite.
    inviter = await _agent(session, "r-inviter")
    invitee = await _agent(session, "r-invitee")
    conversation = await _open_conversation(session, inviter, [invitee])
    # The start already recorded the first invite event; this is the second.
    await record_invite_wake_events(
        session,
        conversation_id=conversation.id,
        inviter_agent_id=inviter.id,
        invitee_agent_ids=[invitee.id],
        now=datetime.now(UTC),
    )
    await session.commit()
    events = [e for e in await _events(session) if e.kind == "invite"]
    assert len(events) == 2
    assert all(e.recipient_agent_id == invitee.id for e in events)


async def test_invite_recording_never_commits(session: AsyncSession, engine: AsyncEngine) -> None:
    inviter = await _agent(session, "rb-inviter")
    invitee = await _agent(session, "rb-invitee")
    invitee_id = invitee.id
    conversation = await _open_conversation(session, inviter, [await _agent(session, "rb-first")])
    await record_invite_wake_events(
        session,
        conversation_id=conversation.id,
        inviter_agent_id=inviter.id,
        invitee_agent_ids=[invitee.id],
        now=datetime.now(UTC),
    )
    await session.flush()
    await session.rollback()
    async with engine.connect() as conn:
        count = (
            await conn.execute(
                text("SELECT count(*) FROM wake_events WHERE recipient_agent_id = :a"),
                {"a": invitee_id},
            )
        ).scalar_one()
        assert count == 0


# --- messages released from a hold ------------------------------------------------


async def _active_pair(session: AsyncSession, tag: str) -> tuple[Agent, Agent, Any]:
    sender = await _agent(session, f"{tag}-sender")
    recipient = await _agent(session, f"{tag}-recipient")
    conversation = await _open_conversation(session, sender, [recipient])
    await accept_invite(
        session, actor_sub=recipient.sub, agent_id=recipient.id, conversation_id=conversation.id
    )
    return sender, recipient, conversation


async def test_auto_approved_held_message_wakes_recipient_once(session: AsyncSession) -> None:
    sender, recipient, conversation = await _active_pair(session, "am")
    before = len(await _events(session))

    result = await _post(
        session,
        sender,
        conversation.id,
        risk_scorer=_AlwaysHighRiskScorer(),
        auto_approver=_ClearAllApprover(),
    )
    assert isinstance(result, Message)

    events = await _events(session)
    assert len(events) == before + 1  # one, not one from each path
    event = events[-1]
    assert (event.kind, event.seq, event.message_type) == ("message", result.seq, "task_assign")
    assert event.recipient_agent_id == recipient.id
    assert event.sender_agent_id == sender.id


async def test_human_approved_held_message_wakes_recipient_once(session: AsyncSession) -> None:
    sender, recipient, conversation = await _active_pair(session, "hm")
    before = len(await _events(session))

    hold = await _post(session, sender, conversation.id, review_reason="check")
    assert isinstance(hold, ApprovalHold)
    assert len(await _events(session)) == before  # nothing while held

    await _decide(session, hold, sender, "approve")
    events = await _events(session)
    assert len(events) == before + 1
    held_message = (
        await session.execute(select(Message).where(Message.id == hold.message_id))
    ).scalar_one()
    assert events[-1].seq == held_message.seq
    assert events[-1].recipient_agent_id == recipient.id
    assert events[-1].sender_agent_id == sender.id


async def test_rejected_held_message_records_nothing(session: AsyncSession) -> None:
    sender, _recipient, conversation = await _active_pair(session, "rm")
    before = len(await _events(session))
    hold = await _post(session, sender, conversation.id, review_reason="check")
    await _decide(session, hold, sender, "reject")
    assert len(await _events(session)) == before


async def test_held_opener_released_wakes_only_those_who_can_read(session: AsyncSession) -> None:
    sender = await _agent(session, "ho-sender")
    reader = await _agent(session, "ho-reader")
    waiting = await _agent(session, "ho-waiting")
    conversation = await _open_conversation(
        session, sender, [reader, waiting], risk_scorer=_AlwaysHighRiskScorer()
    )
    assert conversation.pending_hold is not None
    # Only the two invite events: the synthesized marker records nothing.
    events = await _events(session)
    assert sorted(e.kind for e in events) == ["invite", "invite"]
    assert {e.recipient_agent_id for e in events} == {reader.id, waiting.id}

    await accept_invite(
        session, actor_sub=reader.sub, agent_id=reader.id, conversation_id=conversation.id
    )
    await _decide(session, conversation.pending_hold, sender, "approve")

    events = await _events(session)
    message_events = [e for e in events if e.kind == "message"]
    assert len(message_events) == 1
    assert message_events[0].recipient_agent_id == reader.id
    assert message_events[0].seq == 2  # seq 1 is the marker


async def test_invite_recording_rejects_naive_now(session: AsyncSession) -> None:
    inviter = await _agent(session, "nv-inviter")
    invitee = await _agent(session, "nv-invitee")
    with pytest.raises(ValueError, match="timezone-aware"):
        await record_invite_wake_events(
            session,
            conversation_id=uuid.uuid4(),
            inviter_agent_id=inviter.id,
            invitee_agent_ids=[invitee.id],
            now=datetime.now(),  # deliberately naive
        )
