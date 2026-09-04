"""Process-local, in-memory registry for MCP resource subscriptions (TECH-5903 Phase B).

Backs the low-level ``subscribe_resource``/``unsubscribe_resource`` handlers
registered in ``main.py`` and the post-commit notification firing wired into
``providers/comms.py``'s write-path tools (and ``main.decide_approval``).

Deliberately has NO dependency on ``db``/``service`` — every notify call is
handed an already-resolved recipient set by its caller, computed from that
caller's own just-committed transaction (see ``notify_conversation_event``'s
docstring for why this satisfies the "re-check membership at fire time"
requirement without a second query here).

Deployment fit (plan doc §6): this repo runs one ECS Fargate task
(``desired_count = 1``) with no shared pub/sub — a process-local registry is
correct-by-deployment for v1. Sessions and subscriptions are ephemeral: any
deploy/restart drops the registry and every client must re-subscribe after
re-initializing.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
import weakref
from collections.abc import Collection, Iterable
from dataclasses import dataclass

from mcp.server.session import ServerSession

logger = logging.getLogger(__name__)

# Bounds leakage between prune-on-send-failure opportunities (see
# ``subscribe``'s docstring) — a departed agent that never triggers a failed
# send (e.g. its session is still open but it stopped calling tools) would
# otherwise be able to accumulate unbounded stale records.
MAX_SUBSCRIPTIONS_PER_AGENT = 100

_CONVERSATION_URI_TEMPLATE = "comms://comms/conversations/{conversation_id}"
_INBOX_URI_TEMPLATE = "comms://comms/agents/{agent_id}/inbox"


def conversation_uri(conversation_id: uuid.UUID) -> str:
    return _CONVERSATION_URI_TEMPLATE.format(conversation_id=conversation_id)


def inbox_uri(agent_id: uuid.UUID) -> str:
    return _INBOX_URI_TEMPLATE.format(agent_id=agent_id)


@dataclass(frozen=True)
class _Record:
    session_ref: weakref.ReferenceType[ServerSession]
    agent_id: uuid.UUID
    sub: str


_registry: dict[str, list[_Record]] = {}
_agent_subscription_counts: dict[uuid.UUID, int] = {}
_lock = asyncio.Lock()


def _dec_count(agent_id: uuid.UUID) -> None:
    remaining = _agent_subscription_counts.get(agent_id, 0) - 1
    if remaining > 0:
        _agent_subscription_counts[agent_id] = remaining
    else:
        _agent_subscription_counts.pop(agent_id, None)


async def subscribe(uri: str, session: ServerSession, *, agent_id: uuid.UUID, sub: str) -> None:
    """Register ``session`` as a subscriber of ``uri``.

    Idempotent per ``(uri, session)`` — re-subscribing the same session to
    the same URI replaces its record rather than duplicating it. If
    ``agent_id`` is already at ``MAX_SUBSCRIPTIONS_PER_AGENT`` (across every
    URI), the oldest of its existing records is evicted first — a bound on
    leakage between prune-on-send-failure opportunities (weakrefs are GC'd
    automatically, but a still-open, still-connected session that just
    stopped being useful — e.g. its owning agent went idle — leaks nothing
    until its next failed send).
    """
    async with _lock:
        records = _registry.setdefault(uri, [])
        records[:] = [r for r in records if r.session_ref() is not session]

        total_for_agent = _agent_subscription_counts.get(agent_id, 0)
        if total_for_agent >= MAX_SUBSCRIPTIONS_PER_AGENT:
            _evict_oldest_for_agent_locked(agent_id)
            logger.warning(
                "agent %s hit the %d-subscription cap; evicted its oldest subscription",
                agent_id,
                MAX_SUBSCRIPTIONS_PER_AGENT,
            )

        records.append(_Record(weakref.ref(session), agent_id, sub))
        _agent_subscription_counts[agent_id] = _agent_subscription_counts.get(agent_id, 0) + 1


def _evict_oldest_for_agent_locked(agent_id: uuid.UUID) -> None:
    """Drop the single oldest record belonging to ``agent_id``, across every
    URI. Caller must hold ``_lock``."""
    for uri, records in _registry.items():
        for index, record in enumerate(records):
            if record.agent_id == agent_id:
                del records[index]
                _dec_count(agent_id)
                if not records:
                    del _registry[uri]
                return


async def unsubscribe(uri: str, session: ServerSession) -> None:
    """Remove ``session``'s subscription to ``uri``, if any. Idempotent."""
    async with _lock:
        records = _registry.get(uri)
        if not records:
            return
        remaining = []
        for record in records:
            if record.session_ref() is session:
                _dec_count(record.agent_id)
                continue
            remaining.append(record)
        if remaining:
            _registry[uri] = remaining
        else:
            del _registry[uri]


async def notify(uri: str, *, recipient_filter: Collection[uuid.UUID] | None = None) -> None:
    """Best-effort fan-out of a ``notifications/resources/updated`` for ``uri``.

    Never raises: a dead weakref or a failed ``send_resource_updated`` call
    is pruned and logged, never propagated — matching
    ``service._fire_approval_notifier``'s "never fails the request" posture.
    ``recipient_filter``, when given, narrows delivery to subscriptions whose
    ``agent_id`` is a member (the caller's own fresh, post-commit view of
    who is still entitled to this ping); ``None`` delivers to every current
    subscriber of ``uri`` unfiltered.
    """
    async with _lock:
        records = list(_registry.get(uri, ()))

    live: list[_Record] = []
    dead_or_failed: list[_Record] = []
    for record in records:
        if recipient_filter is not None and record.agent_id not in recipient_filter:
            live.append(record)
            continue
        session = record.session_ref()
        if session is None:
            dead_or_failed.append(record)
            continue
        try:
            await session.send_resource_updated(uri)  # type: ignore[arg-type]
        except Exception as exc:
            logger.warning(
                "dropping subscription to %r for agent %s after failed notify: %s",
                uri,
                record.agent_id,
                type(exc).__name__,
                exc_info=True,
            )
            dead_or_failed.append(record)
        else:
            live.append(record)

    if dead_or_failed:
        async with _lock:
            current = _registry.get(uri)
            if current is not None:
                dead_ids = {id(r) for r in dead_or_failed}
                remaining = [r for r in current if id(r) not in dead_ids]
                for record in dead_or_failed:
                    _dec_count(record.agent_id)
                if remaining:
                    _registry[uri] = remaining
                else:
                    _registry.pop(uri, None)


async def notify_conversation_event(
    conversation_id: uuid.UUID,
    *,
    active_agent_ids: Collection[uuid.UUID],
    inbox_agent_ids: Iterable[uuid.UUID] = (),
) -> None:
    """Post-commit, best-effort notification that ``conversation_id`` changed.

    Caller MUST have already committed the transaction that made the
    change — mirrors ``service._fire_approval_notifier``'s contract. Never
    raises.

    ``active_agent_ids`` is the caller's own fresh, just-queried-post-commit
    set of currently-active participants: passing it as ``notify``'s
    ``recipient_filter`` for the conversation URI IS the "re-check the
    subscriber is still an admitted participant" requirement (plan doc
    §3.1) — every call site queries this fresh from the DB state as of its
    own commit, so a subscriber who left in an EARLIER, unrelated
    transaction is excluded here without ``subscriptions.py`` itself ever
    touching the database. ``inbox_agent_ids`` are pinged unconditionally
    (an inbox URI is already agent-specific, so there is nothing to filter
    by) — callers choose which agents belong in this set per plan doc §4's
    per-write-path table (e.g. "active participants other than the
    sender").
    """
    await notify(conversation_uri(conversation_id), recipient_filter=set(active_agent_ids))
    for agent_id in inbox_agent_ids:
        await notify(inbox_uri(agent_id))
