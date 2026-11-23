"""Record wake events and track open conversations (TECH-9907, TECH-9910).

``record_message_wake_events`` runs inside the posting transaction, after
every gate that can deny, and only stages rows: it never commits, so the
message, its wake events and the session changes land or roll back
together. Delivery of the events is separate work.

The number of queries is fixed regardless of the recipient count: one
each for targets, sessions, rules, plus one write per table touched.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import and_, case, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog, WakeEvent, WakeSession, WakeTarget
from wake_rules import WakeMessage, evaluate_wake_rules, list_wake_rules_for_agents

# A wake session ("open conversation") is open while it is not closed and its
# last activity is at most this many seconds old (docs/WAKE-EVENTS.md section 7).
WAKE_SESSION_WINDOW_SECONDS: Final = 600


def _is_open(wake_session: WakeSession, now: datetime) -> bool:
    return wake_session.closed_at is None and wake_session.last_activity_at >= now - timedelta(
        seconds=WAKE_SESSION_WINDOW_SECONDS
    )


async def record_message_wake_events(
    session: AsyncSession,
    *,
    conversation_id: uuid.UUID,
    seq: int,
    message_type: str,
    payload: dict[str, Any],
    sender_agent_id: uuid.UUID,
    recipient_agent_ids: Collection[uuid.UUID],
    now: datetime,
) -> None:
    """Decide and stage wake rows for one newly posted, visible message.

    ``recipient_agent_ids`` are the conversation's active participants other
    than the sender (the sender is removed here if listed). ``now`` must be
    timezone-aware. Only agents with a ``wake_targets`` row are considered.
    A recipient with an open session gets an ``open_conversation`` event;
    otherwise its rules decide (``wake`` -> a ``rule`` event, ``poll`` ->
    nothing). Recording an event opens or extends that recipient's session.
    The sender's own session is opened or extended too, if it has a target.
    """
    await _record_wake_events(
        session,
        conversation_id=conversation_id,
        kind="message",
        seq=seq,
        event_message_type=message_type,
        wake_message=WakeMessage(
            conversation_id=conversation_id,
            sender_agent_id=sender_agent_id,
            message_type=message_type,
            task_action=payload.get("action") if isinstance(payload.get("action"), str) else None,
            message_priority=(
                payload.get("priority") if isinstance(payload.get("priority"), str) else None
            ),
        ),
        recipient_agent_ids=recipient_agent_ids,
        touch_sender=True,
        now=now,
    )


async def record_invite_wake_events(
    session: AsyncSession,
    *,
    conversation_id: uuid.UUID,
    inviter_agent_id: uuid.UUID,
    invitee_agent_ids: Collection[uuid.UUID],
    now: datetime,
) -> None:
    """Decide and stage ``kind='invite'`` wake rows for newly visible invites.

    Call once per batch of ``invited`` participant rows, at the moment each
    becomes visible to its invitee (never while the invite is held). Same
    decision order as a message (docs/WAKE-EVENTS.md section 8); for rule
    matching an invite is message type ``invite`` with no task action and no
    message priority. The row has ``seq`` and ``message_type`` NULL. There is
    no unique index for invites, so the caller must call this exactly once
    per invite becoming visible. The inviter's own session is not touched.
    ``now`` must be timezone-aware.
    """
    await _record_wake_events(
        session,
        conversation_id=conversation_id,
        kind="invite",
        seq=None,
        event_message_type=None,
        wake_message=WakeMessage(
            conversation_id=conversation_id,
            sender_agent_id=inviter_agent_id,
            message_type="invite",
            task_action=None,
            message_priority=None,
        ),
        recipient_agent_ids=invitee_agent_ids,
        touch_sender=False,
        now=now,
    )


async def _record_wake_events(
    session: AsyncSession,
    *,
    conversation_id: uuid.UUID,
    kind: str,
    seq: int | None,
    event_message_type: str | None,
    wake_message: WakeMessage,
    recipient_agent_ids: Collection[uuid.UUID],
    touch_sender: bool,
    now: datetime,
) -> None:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    sender_agent_id = wake_message.sender_agent_id
    candidate_ids = {*recipient_agent_ids, sender_agent_id} - (
        set() if touch_sender else {sender_agent_id}
    )
    target_ids = set(
        (
            await session.execute(
                select(WakeTarget.agent_id).where(WakeTarget.agent_id.in_(candidate_ids))
            )
        ).scalars()
    )
    if not target_ids:
        return
    recipients = sorted((target_ids & set(recipient_agent_ids)) - {sender_agent_id})

    sessions = {
        s.agent_id: s
        for s in (
            await session.execute(
                select(WakeSession).where(
                    WakeSession.conversation_id == conversation_id,
                    WakeSession.agent_id.in_(recipients),
                )
            )
        ).scalars()
    }
    open_ids = {a for a, s in sessions.items() if _is_open(s, now)}
    # Found stale (never closed, but quiet past the window): closed as "quiet".
    stale_ids = {a for a, s in sessions.items() if a not in open_ids and s.closed_at is None}

    rule_ids = [a for a in recipients if a not in open_ids]
    rules_by_agent = (
        await list_wake_rules_for_agents(session, agent_ids=rule_ids) if rule_ids else {}
    )

    reasons: dict[uuid.UUID, str] = {a: "open_conversation" for a in open_ids}
    for agent_id in rule_ids:
        if evaluate_wake_rules(rules_by_agent[agent_id], wake_message).action == "wake":
            reasons[agent_id] = "rule"

    if reasons:
        await session.execute(
            pg_insert(WakeEvent).values(
                [
                    {
                        "recipient_agent_id": agent_id,
                        "conversation_id": conversation_id,
                        "kind": kind,
                        "seq": seq,
                        "message_type": event_message_type,
                        "sender_agent_id": sender_agent_id,
                        "reason": reasons[agent_id],
                        "status": "pending",
                        "attempt_count": 0,
                    }
                    for agent_id in sorted(reasons)
                ]
            )
        )

    quiet_ids = stale_ids - reasons.keys()
    if quiet_ids:
        await session.execute(
            update(WakeSession)
            .where(
                WakeSession.conversation_id == conversation_id,
                WakeSession.agent_id.in_(quiet_ids),
            )
            .values(closed_at=now, closed_reason="quiet")
        )

    # Open or extend. A woken recipient's session_ref is kept only while its session
    # was really open: one that was closed or went quiet starts a new period without
    # the old ref (docs/WAKE-EVENTS.md sections 3.1 and 7). The sender's own session is
    # the agent still running, so its ref is left as it is.
    wake_sessions = WakeSession.__table__
    keep_ref = and_(
        wake_sessions.c.closed_at.is_(None),
        wake_sessions.c.last_activity_at >= now - timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS),
    )
    reopen: dict[str, Any] = {"last_activity_at": now, "closed_at": None, "closed_reason": None}
    groups = [
        (
            set(reasons),
            {**reopen, "session_ref": case((keep_ref, wake_sessions.c.session_ref), else_=None)},
        ),
        ({sender_agent_id} if touch_sender and sender_agent_id in target_ids else set(), reopen),
    ]
    for agents, set_ in groups:
        if not agents:
            continue
        insert = pg_insert(WakeSession).values(
            [
                {
                    "agent_id": a,
                    "conversation_id": conversation_id,
                    "opened_at": now,
                    "last_activity_at": now,
                }
                for a in sorted(agents)
            ]
        )
        await session.execute(
            insert.on_conflict_do_update(
                constraint="uq_wake_sessions_agent_id_conversation_id", set_=set_
            )
        )


async def close_wake_sessions_for_conversation(
    session: AsyncSession, *, conversation_id: uuid.UUID, now: datetime
) -> None:
    """Close the conversation's still-open sessions with reason ``conversation_ended``."""
    await session.execute(
        update(WakeSession)
        .where(WakeSession.conversation_id == conversation_id, WakeSession.closed_at.is_(None))
        .values(closed_at=now, closed_reason="conversation_ended")
    )


async def list_open_wake_sessions(
    session: AsyncSession, *, agent_id: uuid.UUID, now: datetime
) -> list[WakeSession]:
    """The agent's open conversations, most recently active first. Read-only."""
    return list(
        (
            await session.execute(
                select(WakeSession)
                .where(
                    WakeSession.agent_id == agent_id,
                    WakeSession.closed_at.is_(None),
                    WakeSession.last_activity_at
                    >= now - timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS),
                )
                .order_by(WakeSession.last_activity_at.desc(), WakeSession.id)
            )
        ).scalars()
    )


async def close_wake_session(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    now: datetime,
) -> bool:
    """Close the agent's open session for one conversation (``agent_closed``).

    Returns ``False`` and writes nothing when the agent has no open session
    there (already closed, quiet past the window, or never opened), so the
    call is idempotent and says nothing about conversations the agent is not
    in. Otherwise writes a ``wake_session.close`` audit row. COMMITS.
    """
    closed = (
        await session.execute(
            update(WakeSession)
            .where(
                WakeSession.agent_id == agent_id,
                WakeSession.conversation_id == conversation_id,
                WakeSession.closed_at.is_(None),
                WakeSession.last_activity_at
                >= now - timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS),
            )
            .values(closed_at=now, closed_reason="agent_closed")
            .returning(WakeSession.id)
        )
    ).scalar_one_or_none()
    if closed is None:
        await session.rollback()
        return False
    session.add(
        AuditLog(
            actor_sub=actor_sub,
            action="wake_session.close",
            agent_id=agent_id,
            conversation_id=conversation_id,
            detail={"reason": "agent_closed"},
        )
    )
    await session.commit()
    return True


__all__ = [
    "WAKE_SESSION_WINDOW_SECONDS",
    "close_wake_session",
    "close_wake_sessions_for_conversation",
    "list_open_wake_sessions",
    "record_invite_wake_events",
    "record_message_wake_events",
]
