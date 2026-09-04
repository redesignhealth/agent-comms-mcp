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
    # Monotonically increasing creation order (Argus round-2 BLOCKING catch):
    # `_evict_oldest_for_agent_locked` must evict the record an agent
    # actually registered longest ago, not merely the first one encountered
    # via `_registry`'s dict/URI iteration order (which reflects URI
    # registration order, not per-agent subscription recency) -- without
    # this field, eviction could drop a subscription registered moments ago
    # while an actually-older one for the same agent survives.
    seq: int


_registry: dict[str, list[_Record]] = {}
_agent_subscription_counts: dict[uuid.UUID, int] = {}
_lock = asyncio.Lock()
_seq_counter = 0


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
    global _seq_counter
    async with _lock:
        records = _registry.setdefault(uri, [])
        before = len(records)
        records[:] = [r for r in records if r.session_ref() is not session]
        # Idempotent re-subscribe (same uri, same session): the filter above
        # just dropped this session's existing record. Without decrementing
        # here, the unconditional increment below double-counts it against
        # `agent_id` -- Argus round-2 BLOCKING catch (a caller re-subscribing
        # to the same URI N times would inflate its count by N, eventually
        # tripping the cap on a genuinely idempotent no-op).
        removed_existing = len(records) < before
        if removed_existing:
            _dec_count(agent_id)

        total_for_agent = _agent_subscription_counts.get(agent_id, 0)
        if total_for_agent >= MAX_SUBSCRIPTIONS_PER_AGENT:
            _evict_oldest_for_agent_locked(agent_id)
            logger.warning(
                "agent %s hit the %d-subscription cap; evicted its oldest subscription",
                agent_id,
                MAX_SUBSCRIPTIONS_PER_AGENT,
            )

        # Re-fetched AFTER eviction, not reused from above (Argus round-2
        # BLOCKING catch): eviction can delete `_registry[uri]`'s own list
        # entry entirely (e.g. this agent's oldest subscription happens to
        # be to this very `uri`) -- appending to the pre-eviction `records`
        # object in that case would append to a list no longer reachable
        # from `_registry`, silently dropping this subscription from the
        # live registry while `_agent_subscription_counts` still counts it
        # as registered.
        records = _registry.setdefault(uri, [])
        _seq_counter += 1
        records.append(_Record(weakref.ref(session), agent_id, sub, _seq_counter))
        _agent_subscription_counts[agent_id] = _agent_subscription_counts.get(agent_id, 0) + 1


def _evict_oldest_for_agent_locked(agent_id: uuid.UUID) -> None:
    """Drop the single TRULY oldest record belonging to ``agent_id``, across
    every URI, by creation order (``_Record.seq``) -- not by ``_registry``'s
    own dict/URI iteration order, which reflects URI registration order, not
    this agent's own subscription recency (Argus round-2 BLOCKING catch: the
    prior first-match-wins scan over `_registry.items()` could evict a
    subscription this agent registered moments ago while an actually older
    one for the same agent survived, whenever the older one happened to live
    under a later-inserted URI key). Caller must hold ``_lock``.
    """
    oldest_uri: str | None = None
    oldest_index: int | None = None
    oldest_seq: int | None = None
    for uri, records in _registry.items():
        for index, record in enumerate(records):
            if record.agent_id == agent_id and (oldest_seq is None or record.seq < oldest_seq):
                oldest_uri = uri
                oldest_index = index
                oldest_seq = record.seq
    if oldest_uri is None or oldest_index is None:
        # Argus round-3 SUGGESTION: this is only ever called when the count
        # already says `agent_id` is at cap, so finding zero of its records
        # here means `_registry`/`_agent_subscription_counts` have diverged
        # -- silently returning would let `subscribe()`'s caller append a
        # new record right past the cap with no signal that the invariant
        # broke.
        logger.error(
            "cap eviction found no records for agent %s despite being at "
            "the %d-subscription cap -- registry/count state has diverged",
            agent_id,
            MAX_SUBSCRIPTIONS_PER_AGENT,
        )
        return
    records = _registry[oldest_uri]
    del records[oldest_index]
    _dec_count(agent_id)
    if not records:
        del _registry[oldest_uri]


async def is_subscribed(uri: str, session: ServerSession) -> bool:
    """Non-mutating check: is ``session`` currently subscribed to ``uri``?

    Used by ``main.py``'s unsubscribe handler to decide, BEFORE writing the
    audit row, whether this call will actually change anything (Argus
    round-2: reconciling the "audit before mutation" ordering fix with the
    "skip the audit row for a no-op unsubscribe" fix means the no-op check
    has to happen before either the audit write or the registry mutation).
    """
    async with _lock:
        records = _registry.get(uri)
        if not records:
            return False
        return any(r.session_ref() is session for r in records)


async def unsubscribe(uri: str, session: ServerSession) -> bool:
    """Remove ``session``'s subscription to ``uri``, if any. Idempotent.

    Returns ``True`` if a record was actually removed, ``False`` if this was
    a no-op (nothing was registered for this ``(uri, session)`` pair) --
    callers (``main.py``'s low-level handler) use this to skip writing an
    audit row for a no-op unsubscribe (Argus round-2 SUGGESTION).
    """
    async with _lock:
        records = _registry.get(uri)
        if not records:
            return False
        remaining = []
        removed = False
        for record in records:
            if record.session_ref() is session:
                _dec_count(record.agent_id)
                removed = True
                continue
            remaining.append(record)
        if remaining:
            _registry[uri] = remaining
        else:
            del _registry[uri]
        return removed


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
            # Argus round-2 SUGGESTION: still prune a dead weakref even
            # though no send is attempted for a filtered-out agent -- without
            # this, a record whose owning agent never again appears in a
            # `recipient_filter` (e.g. it permanently left every
            # conversation it's subscribed to) would never be pruned, since
            # the only other prune trigger is a failed *send*, which this
            # path never attempts.
            if record.session_ref() is None:
                dead_or_failed.append(record)
            else:
                live.append(record)
            continue
        session = record.session_ref()
        if session is None:
            dead_or_failed.append(record)
            continue
        try:
            await session.send_resource_updated(uri)  # type: ignore[arg-type]
        except asyncio.CancelledError:
            # BaseException, not Exception -- already excluded from the
            # guard below under Python's actual exception hierarchy, but
            # re-raised explicitly (matching service._fire_approval_notifier's
            # established pattern) so this stays correct even if the
            # `except Exception` below is ever accidentally broadened to
            # `except BaseException`.
            raise
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
                # Argus round-2 BLOCKING catch: decrement only for records
                # still actually present in this freshly re-locked snapshot,
                # not unconditionally for every record in `dead_or_failed` --
                # a concurrent `unsubscribe()` may have already removed (and
                # decremented) one of these between the unlocked send loop
                # above and this re-lock, and double-decrementing it here
                # would under-count `agent_id`'s subscriptions.
                dead_ids = {id(r) for r in dead_or_failed}
                remaining = []
                for record in current:
                    if id(record) in dead_ids:
                        _dec_count(record.agent_id)
                    else:
                        remaining.append(record)
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
