"""Admin list and requeue of wake events (TECH-9913).

Behind ``comms_admin_wake_events_list`` and ``comms_admin_wake_event_requeue``.
An operator uses them to see which events failed or were dead-lettered, and why,
and to send one again once the cause is fixed (docs/WAKE-EVENTS.md section 11).

Nothing here returns a secret, a signature, a session reference, a request body
or a response body. ``last_error`` is the short fixed phrase the delivery task
wrote.

Requeue is one conditional UPDATE on a ``failed`` or ``dead`` row. The delivery
task only claims and records events in an open status (pending, retry,
retry_later), so it cannot hold a lease on, or overwrite, a row in either
terminal status. The update turns the row back into an open ``retry`` event due
now, and the task then treats it like any other: the ordering rule (the oldest
unfinished event of a recipient and conversation goes first) applies to it as it
does to every other event.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import InvalidWakeEventError
from models import WAKE_EVENT_STATUSES, WakeEvent
from service import _audit, _deny

DEFAULT_LIMIT: Final = 50
MAX_LIMIT: Final = 200
REQUEUEABLE_STATUSES: Final = ("failed", "dead")


def _view(event: WakeEvent) -> dict[str, Any]:
    def _iso(value: datetime | None) -> str | None:
        return None if value is None else value.isoformat()

    return {
        "event_id": str(event.id),
        "recipient_agent_id": str(event.recipient_agent_id),
        "conversation_id": str(event.conversation_id),
        "sender_agent_id": str(event.sender_agent_id),
        "kind": event.kind,
        "seq": event.seq,
        "message_type": event.message_type,
        "reason": event.reason,
        "status": event.status,
        "attempt_count": event.attempt_count,
        "next_attempt_at": _iso(event.next_attempt_at),
        "last_error": event.last_error,
        "created_at": _iso(event.created_at),
        "delivered_at": _iso(event.delivered_at),
    }


async def _require_admin(
    session: AsyncSession, *, actor_sub: str, admin_authorized: bool, action: str
) -> None:
    if not admin_authorized:
        await _deny(session, actor_sub=actor_sub, action=action)


async def list_wake_events(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    agent_id: uuid.UUID | None,
    conversation_id: uuid.UUID | None,
    status: str | None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """List wake events, newest first, filtered by recipient, conversation and status."""
    await _require_admin(
        session,
        actor_sub=actor_sub,
        admin_authorized=admin_authorized,
        action="denied.wake_events_require_elevated_scope",
    )
    if status is not None and status not in WAKE_EVENT_STATUSES:
        raise InvalidWakeEventError(f"status must be one of {', '.join(WAKE_EVENT_STATUSES)}")
    if not 1 <= limit <= MAX_LIMIT:
        raise InvalidWakeEventError(f"limit must be between 1 and {MAX_LIMIT}")
    stmt = select(WakeEvent).order_by(WakeEvent.created_at.desc(), WakeEvent.id).limit(limit + 1)
    if agent_id is not None:
        stmt = stmt.where(WakeEvent.recipient_agent_id == agent_id)
    if conversation_id is not None:
        stmt = stmt.where(WakeEvent.conversation_id == conversation_id)
    if status is not None:
        stmt = stmt.where(WakeEvent.status == status)
    rows = list((await session.execute(stmt)).scalars())
    return {"events": [_view(e) for e in rows[:limit]], "has_more": len(rows) > limit}


async def requeue_wake_event(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    event_id: uuid.UUID,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Turn a ``failed`` or ``dead`` event back into a ``retry`` event due now.

    The attempt count restarts at 0, ``last_error`` is cleared and ``created_at``
    is set to now. The last matters: the delivery task dead-letters an open event
    24 hours after ``created_at``, so an event that died of age would otherwise
    die again on the next tick. The values it replaces go to the audit row.
    """
    await _require_admin(
        session,
        actor_sub=actor_sub,
        admin_authorized=admin_authorized,
        action="denied.wake_events_require_elevated_scope",
    )
    now = now or datetime.now(UTC)
    before = (
        await session.execute(select(WakeEvent).where(WakeEvent.id == event_id))
    ).scalar_one_or_none()
    if before is None:
        raise InvalidWakeEventError("no such wake event")
    previous = {
        "previous_status": before.status,
        "previous_attempt_count": before.attempt_count,
        "previous_last_error": before.last_error,
        "original_created_at": before.created_at.isoformat(),
    }
    # The status test is in the UPDATE itself, so a row that moved on since the
    # read above is not touched.
    result = await session.execute(
        update(WakeEvent)
        .where(WakeEvent.id == event_id, WakeEvent.status.in_(REQUEUEABLE_STATUSES))
        .values(
            status="retry",
            attempt_count=0,
            next_attempt_at=now,
            last_error=None,
            created_at=now,
            delivered_at=None,
        )
        .returning(WakeEvent.recipient_agent_id, WakeEvent.conversation_id)
    )
    row = result.one_or_none()
    if row is None:
        raise InvalidWakeEventError(
            f"only a failed or dead wake event can be requeued; this one is {before.status}"
        )
    _audit(
        session,
        actor_sub=actor_sub,
        action="wake_event.requeued",
        agent_id=row.recipient_agent_id,
        conversation_id=row.conversation_id,
        detail={"event_id": str(event_id), **previous},
        at=now,
    )
    await session.commit()
    return {"event_id": str(event_id), "status": "retry", "next_attempt_at": now.isoformat()}


__all__ = ["list_wake_events", "requeue_wake_event"]
