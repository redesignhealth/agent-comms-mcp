"""The wake delivery pause switch (TECH-9890).

One row in ``wake_delivery_state`` (``id`` always 1). While ``paused`` is true the
delivery task claims and sends nothing; events keep being recorded and keep their
24 hour life (the task still dead-letters expired ones). On resume the backlog
goes out in the normal order. No row means not paused, which is how it ships.

Behind ``comms_admin_wake_delivery_pause``, ``_resume`` and ``_status``
(docs/WAKE-EVENTS.md section 11). Pause and resume are idempotent and audited.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import InvalidWakeEventError
from models import WakeDeliveryState
from service import _audit, _deny

MAX_REASON_LENGTH: Final = 200


def _view(state: WakeDeliveryState | None) -> dict[str, Any]:
    if state is None:
        return {"paused": False, "paused_at": None, "paused_by": None, "reason": None}
    return {
        "paused": state.paused,
        "paused_at": None if state.paused_at is None else state.paused_at.isoformat(),
        "paused_by": state.paused_by,
        "reason": state.reason,
    }


async def _read(session: AsyncSession) -> WakeDeliveryState | None:
    return (
        await session.execute(
            select(WakeDeliveryState)
            .where(WakeDeliveryState.id == 1)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def is_delivery_paused(session: AsyncSession) -> bool:
    """True only if the row exists and is paused (a missing row is not paused)."""
    state = await _read(session)
    return state is not None and state.paused


async def _require_admin(session: AsyncSession, *, actor_sub: str, admin_authorized: bool) -> None:
    if not admin_authorized:
        await _deny(
            session, actor_sub=actor_sub, action="denied.wake_delivery_require_elevated_scope"
        )


async def get_status(
    session: AsyncSession, *, actor_sub: str, admin_authorized: bool
) -> dict[str, Any]:
    await _require_admin(session, actor_sub=actor_sub, admin_authorized=admin_authorized)
    return _view(await _read(session))


async def _set(
    session: AsyncSession,
    *,
    actor_sub: str,
    paused: bool,
    reason: str | None,
    at: datetime,
    action: str,
) -> dict[str, Any]:
    previous = _view(await _read(session))
    values: dict[str, Any] = {
        "paused": paused,
        "paused_at": at if paused else None,
        "paused_by": actor_sub if paused else None,
        "reason": reason if paused else None,
    }
    # Pausing an already paused switch keeps the original who/when/why.
    if paused and previous["paused"]:
        values = {}
    if values:
        await session.execute(
            pg_insert(WakeDeliveryState)
            .values(id=1, **values)
            .on_conflict_do_update(index_elements=[WakeDeliveryState.id], set_=values)
        )
    _audit(
        session,
        actor_sub=actor_sub,
        action=action,
        detail={"previous": previous, "reason": reason, "changed": bool(values)},
        at=at,
    )
    await session.commit()
    return _view(await _read(session))


async def pause_delivery(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    reason: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    await _require_admin(session, actor_sub=actor_sub, admin_authorized=admin_authorized)
    reason = (reason or "").strip() or None
    if reason is not None and len(reason) > MAX_REASON_LENGTH:
        raise InvalidWakeEventError(f"reason must be at most {MAX_REASON_LENGTH} characters")
    return await _set(
        session,
        actor_sub=actor_sub,
        paused=True,
        reason=reason,
        at=now or datetime.now(UTC),
        action="wake_delivery.paused",
    )


async def resume_delivery(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    await _require_admin(session, actor_sub=actor_sub, admin_authorized=admin_authorized)
    return await _set(
        session,
        actor_sub=actor_sub,
        paused=False,
        reason=None,
        at=now or datetime.now(UTC),
        action="wake_delivery.resumed",
    )


__all__ = ["get_status", "is_delivery_paused", "pause_delivery", "resume_delivery"]
