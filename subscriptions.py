"""Process-local, in-memory registry for MCP resource subscriptions (TECH-5903 Phase B).

Backs the low-level ``subscribe_resource``/``unsubscribe_resource`` handlers
registered in ``main.py`` and the post-commit notification firing wired into
``providers/comms.py``'s write-path tools (and ``main.decide_approval``).

Deliberately has NO dependency on ``db``/``service`` — every notify call is
handed an already-resolved recipient set by its caller, computed from that
caller's own just-committed transaction (see ``notify_conversation_event``'s
docstring for why this satisfies the "re-check membership at fire time"
requirement without a second query here).

Deployment fit and delivery semantics (TECH-6335): this repo runs one ECS
Fargate task (``desired_count = 1``) with no shared pub/sub — a process-local
registry is correct-by-deployment for v1. Sessions and subscriptions are
ephemeral: any deploy/restart drops the registry and every client must
re-subscribe after re-initializing. A notification push is strictly an
at-most-once, best-effort hint carrying only a URI, with no payload, ordering,
or delivery guarantee. Crucially, a successful ``send_resource_updated`` call
does NOT imply delivery: the MCP SDK silently drops notifications with no
exception when no GET/SSE stream is attached to the session. The real delivery
contract is the client's catch-up read via
``comms_get_conversation(since_seq=...)`` (for conversations, paging while
``has_more`` is true) or ``comms_inbox`` (for inboxes, best-effort current-state
snapshot capped at 100 items).

Cap and prune bookkeeping: the per-agent subscription cap
(``MAX_SUBSCRIPTIONS_PER_AGENT``) now rejects with ``SubscriptionLimitError``
rather than silently evicting. Pruning is restricted to definitive session death
(``anyio.ClosedResourceError``, ``anyio.BrokenResourceError``) or dead weakrefs;
transient send errors or slow consumer timeouts do not prune the subscription.
No audit row is written for pruning — it is system-driven cleanup of stale
bookkeeping, not a caller-initiated action, so there is no actor to attribute an
audit row to, and giving this module a DB dependency would cut against its
deliberate DB-less design.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
import weakref
from collections.abc import Collection, Iterable
from dataclasses import dataclass

import anyio
from mcp.server.session import ServerSession

logger = logging.getLogger(__name__)

# Bounds leakage between prune-on-send-failure opportunities (see
# ``subscribe``'s docstring) — a departed agent that never triggers a failed
# send (e.g. its session is still open but it stopped calling tools) would
# otherwise be able to accumulate unbounded stale records.
MAX_SUBSCRIPTIONS_PER_AGENT = 100
NOTIFY_SEND_TIMEOUT_SECONDS = 2.0


class SubscriptionLimitError(Exception):
    """``agent_id`` already holds ``MAX_SUBSCRIPTIONS_PER_AGENT`` live subscriptions."""


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
    # Set only when this record replaced a same-``(uri, session)`` record
    # that was registered under a DIFFERENT ``agent_id`` (TECH-6697
    # identity-replacement fix) -- i.e. the identity this session acts as
    # for this subscription slot just switched from ``replaced_agent_id``
    # to this record's own ``agent_id``. ``None`` for a brand-new
    # subscription or an idempotent same-identity re-subscribe.
    replaced_agent_id: uuid.UUID | None = None


_registry: dict[str, list[_Record]] = {}
_agent_subscription_counts: dict[uuid.UUID, int] = {}
_lock = asyncio.Lock()

# Holds a strong reference to each background `notify()` task scheduled by
# `notify_conversation_event()` (TECH-6335) so it isn't garbage-collected
# before it completes; each task discards itself once done.
_background_notify_tasks: set[asyncio.Task[None]] = set()


def _dec_count(agent_id: uuid.UUID) -> None:
    remaining = _agent_subscription_counts.get(agent_id, 0) - 1
    if remaining > 0:
        _agent_subscription_counts[agent_id] = remaining
    else:
        _agent_subscription_counts.pop(agent_id, None)


def _reclaim_dead_for_agent_locked(agent_id: uuid.UUID) -> None:
    """Remove dead weakref records for ``agent_id`` and recompute its count.

    Caller must hold ``_lock``. Scans ``_registry``, removes every record
    belonging to ``agent_id`` whose ``session_ref()`` is ``None``, and
    recomputes ``_agent_subscription_counts[agent_id]`` from the surviving
    records (popping the key entirely if count reaches 0). Recomputing from
    ground truth also self-heals any count/registry divergence.
    """
    empty_uris: list[str] = []
    for uri, records in _registry.items():
        surviving = [r for r in records if not (r.agent_id == agent_id and r.session_ref() is None)]
        if len(surviving) != len(records):
            records[:] = surviving
        if not records:
            empty_uris.append(uri)
    for uri in empty_uris:
        _registry.pop(uri, None)

    count = sum(1 for records in _registry.values() for r in records if r.agent_id == agent_id)
    if count > 0:
        _agent_subscription_counts[agent_id] = count
    else:
        _agent_subscription_counts.pop(agent_id, None)


async def subscribe(
    uri: str, session: ServerSession, *, agent_id: uuid.UUID, sub: str
) -> _Record | None:
    """Register ``session`` as a subscriber of ``uri``.

    Idempotent per ``(uri, session)`` — re-subscribing the same session to
    the same URI replaces its record rather than duplicating it. Returns
    the created ``_Record`` instance if a new subscription was added, or
    ``None`` if this was an idempotent re-subscription for an existing
    ``(uri, session)`` under the SAME ``agent_id`` as before.

    TECH-6697 identity-replacement fix: a caller-supplied ``agent_id`` need
    not match the ``agent_id`` recorded for this exact ``(uri, session)``
    on a prior call -- this happens when the same underlying session
    re-subscribes to a CANONICALIZED URI it already holds a record for
    (e.g. ``conversation_uri()`` is agent-agnostic, so subscribing via
    ``comms://comms/agents/{sibling_A}/conversations/{conv_id}`` and later
    via ``comms://comms/agents/{sibling_B}/conversations/{conv_id}``
    canonicalize to the identical registry key). Two cases:

    - Same identity (``agent_id`` unchanged): idempotent, as documented
      above -- the existing record's count is decremented then immediately
      re-incremented below (net no-op), and this returns ``None``.
    - Different identity (``agent_id`` changed): this is an identity
      REPLACEMENT, not a routine idempotent re-subscribe. The OLD record's
      own ``agent_id`` (the one actually being replaced) is decremented --
      never the new, caller-supplied ``agent_id`` -- so per-agent cap
      bookkeeping stays correct for both identities. The cap check and
      increment below still apply to the NEW ``agent_id`` being charged.
      This returns the new ``_Record``, with its ``replaced_agent_id``
      field set to the old identity, so callers (``main.py``) can audit
      the switch as a distinct, security-relevant event rather than
      silently dropping it as an idempotent no-op.

    If ``agent_id`` already holds ``MAX_SUBSCRIPTIONS_PER_AGENT`` live
    subscriptions after reclaiming any dead sessions, raises
    ``SubscriptionLimitError`` — the cap now rejects rather than evicting.
    """
    async with _lock:
        records = _registry.setdefault(uri, [])
        before = len(records)
        existing_for_session = next((r for r in records if r.session_ref() is session), None)
        records[:] = [r for r in records if r.session_ref() is not session]
        # Idempotent re-subscribe (same uri, same session): the filter above
        # just dropped this session's existing record. Without decrementing
        # here, the unconditional increment below double-counts it against
        # `agent_id` -- Argus round-2 BLOCKING catch (a caller re-subscribing
        # to the same URI N times would inflate its count by N, eventually
        # tripping the cap on a genuinely idempotent no-op).
        #
        # TECH-6697 BLOCKING catch: decrement the REMOVED record's own
        # `agent_id` (`existing_for_session.agent_id`), not the new,
        # caller-supplied `agent_id` parameter -- those two can now differ
        # (identity replacement, see docstring above). Decrementing the
        # wrong identity here either leaks a stale count on the identity
        # actually being replaced (it's never decremented) or corrupts an
        # unrelated identity's count (if the new `agent_id` happens to have
        # its own real subscriptions elsewhere), letting a caller bypass
        # the cap by alternating sibling identities on the same session.
        removed_existing = len(records) < before
        replaced_agent_id: uuid.UUID | None = None
        if removed_existing:
            assert existing_for_session is not None
            _dec_count(existing_for_session.agent_id)
            if existing_for_session.agent_id != agent_id:
                replaced_agent_id = existing_for_session.agent_id

        # Optimization (TECH-6335): only perform the full O(total subscriptions)
        # scan when the agent's tracked count is actually at or above the cap.
        # When strictly below cap, trust the tracked count and skip the scan.
        if _agent_subscription_counts.get(agent_id, 0) >= MAX_SUBSCRIPTIONS_PER_AGENT:
            _reclaim_dead_for_agent_locked(agent_id)

        if _agent_subscription_counts.get(agent_id, 0) >= MAX_SUBSCRIPTIONS_PER_AGENT:
            if not records:
                _registry.pop(uri, None)
            raise SubscriptionLimitError(
                f"agent {agent_id} already holds {MAX_SUBSCRIPTIONS_PER_AGENT} subscriptions"
            )

        records = _registry.setdefault(uri, [])
        new_record = _Record(weakref.ref(session), agent_id, sub, replaced_agent_id)
        records.append(new_record)
        _agent_subscription_counts[agent_id] = _agent_subscription_counts.get(agent_id, 0) + 1
        if removed_existing and replaced_agent_id is None:
            return None
        return new_record


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
    a no-op (nothing was registered for this ``(uri, session)`` pair).

    This return value is informational/currently unused by ``main.py``
    (Argus round-4 SUGGESTION: an earlier revision had the caller branch on
    it to decide whether to write an audit row, but that ordering had to be
    reverted -- see ``main.py``'s unsubscribe handler for why -- back to a
    non-mutating ``is_subscribed()`` peek as the no-op gate, called BEFORE
    the audit write, with this function's own mutation happening only
    after). Kept (rather than reverted to returning ``None``) since it's
    cheap to compute and may be useful to a future caller.
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


async def remove_if_current(uri: str, record: _Record) -> bool:
    """Remove ``record`` from ``uri``'s subscribers only if it is still the current record.

    Used by ``main.py``'s subscribe rollback on audit failure (TECH-6335): if
    another coroutine or client re-subscribe has since replaced or removed this
    exact record, this is a no-op returning ``False``, avoiding accidentally
    destroying a newer, valid subscription.

    Note on known residual race: if two concurrent subscribe requests for the
    same ``(uri, session)`` race, the second may replace the first with a new
    record instance and return ``None`` (treated as an unaudited re-subscribe).
    If the first request's audit write then fails, its rollback will no-op here,
    leaving the second's replacement record live without an audit row. This narrow
    race is documented and accepted in ``main.py`` to avoid auditing routine re-subscribes.

    Returns ``True`` if ``record`` was still registered and removed, ``False`` otherwise.
    """
    async with _lock:
        records = _registry.get(uri)
        if not records:
            return False
        remaining = []
        removed = False
        for r in records:
            if r is record:
                _dec_count(r.agent_id)
                removed = True
                continue
            remaining.append(r)
        if remaining:
            _registry[uri] = remaining
        else:
            _registry.pop(uri, None)
        return removed


async def notify(uri: str, *, recipient_filter: Collection[uuid.UUID] | None = None) -> None:
    """Best-effort fan-out of a ``notifications/resources/updated`` for ``uri``.

    Never raises: a dead weakref or definitive session death
    (``anyio.ClosedResourceError``, ``anyio.BrokenResourceError``) is pruned and
    logged, never propagated — matching ``service._fire_approval_notifier``'s
    "never fails the request" posture. A slow consumer timing out
    (``TimeoutError`` after ``NOTIFY_SEND_TIMEOUT_SECONDS``) or an unknown/transient
    exception logs a warning and keeps the subscription alive (its periodic catch-up
    read covers the missed ping).

    Serial worst-case cost: ``notify()`` sends sequentially per subscriber, so a
    URI with N stalled subscribers costs up to ``N * NOTIFY_SEND_TIMEOUT_SECONDS``
    before this call itself returns — ``notify()`` remains synchronous/blocking
    on its own for whoever awaits it directly. ``notify_conversation_event``
    (TECH-6335) decouples the post-commit write path from this cost by
    scheduling each ``notify()`` call as a background task rather than
    awaiting it inline; a caller awaiting ``notify()`` directly would still
    block for the full serial cost. This is an accepted tradeoff (documented,
    not fixed here) — do not attempt to parallelize sends.

    ``recipient_filter``, when given, narrows delivery to subscriptions whose
    ``agent_id`` is a member (the caller's own fresh, post-commit view of
    who is still entitled to this ping); ``None`` delivers to every current
    subscriber of ``uri`` unfiltered.
    """
    async with _lock:
        records = list(_registry.get(uri, ()))

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
            continue
        session = record.session_ref()
        if session is None:
            dead_or_failed.append(record)
            continue
        try:
            async with asyncio.timeout(NOTIFY_SEND_TIMEOUT_SECONDS):
                await session.send_resource_updated(uri)  # type: ignore[arg-type]
        except asyncio.CancelledError:
            # BaseException, not Exception -- already excluded from the
            # guard below under Python's actual exception hierarchy, but
            # re-raised explicitly (matching service._fire_approval_notifier's
            # established pattern) so this stays correct even if the
            # `except Exception` below is ever accidentally broadened to
            # `except BaseException`.
            raise
        except (anyio.ClosedResourceError, anyio.BrokenResourceError) as exc:
            logger.warning(
                "dropping subscription to %r for agent %s after closed/broken stream: %s",
                uri,
                record.agent_id,
                type(exc).__name__,
            )
            dead_or_failed.append(record)
        except TimeoutError:
            logger.warning(
                "notify timed out after %.1fs for %r (agent %s); keeping subscription",
                NOTIFY_SEND_TIMEOUT_SECONDS,
                uri,
                record.agent_id,
            )
        except Exception as exc:
            logger.warning(
                "notify failed for %r (agent %s): %s; keeping subscription",
                uri,
                record.agent_id,
                type(exc).__name__,
                exc_info=True,
            )

    if dead_or_failed:
        async with _lock:
            current = _registry.get(uri)
            # `current` can be `None` here: a concurrent operation (e.g.
            # another `unsubscribe()` racing this same re-lock) may have
            # already removed `_registry[uri]`'s entire entry between the
            # unlocked send loop above and this re-lock -- there is nothing
            # left to prune or decrement against in that case, so skip the
            # block entirely rather than resurrecting a deleted `uri` key.
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
    raises and never blocks on the actual send: each ``notify()`` call is
    scheduled as a background ``asyncio.Task`` (TECH-6335) rather than
    awaited inline, so this function returns as soon as the tasks are
    scheduled, without waiting for any subscriber's send (or its up-to
    ``NOTIFY_SEND_TIMEOUT_SECONDS`` timeout) to complete. This decouples the
    write path from a stalled/slow subscriber's cost — see ``notify()``'s
    own docstring for that cost. The scheduled tasks are held in
    ``_background_notify_tasks`` so they aren't garbage-collected before
    they finish; each discards itself from that set once done.

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
    coros = [notify(conversation_uri(conversation_id), recipient_filter=set(active_agent_ids))]
    coros.extend(notify(inbox_uri(agent_id)) for agent_id in inbox_agent_ids)
    for coro in coros:
        task = asyncio.create_task(coro)
        _background_notify_tasks.add(task)
        task.add_done_callback(_background_notify_tasks.discard)
