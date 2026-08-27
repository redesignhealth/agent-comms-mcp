"""Comms domain service layer — all access rules live here, not in tools.

Every function in this module takes an ``AsyncSession`` plus primitive/typed
arguments (UUIDs, strings, dicts) — never a FastMCP ``AccessToken`` or other
request object. The (not-yet-built) MCP tools layer
is responsible for:

1. Verifying the caller's token and extracting identity claims.
2. Resolving the caller's ``sub`` to a board ``Agent.id`` (for every
   function below except ``register_agent``, which establishes that
   mapping in the first place).
3. Calling exactly one function here per tool invocation and mapping the
   three exception shapes in ``exceptions.py`` to ``ToolError`` messages.

This split keeps token verification out of the domain layer entirely (this
module never imports ``fastmcp``) and keeps every authorization/state-
machine/rate-limit/audit rule in one place so it cannot drift between
tools.

Identity threading (``actor_sub``)
-----------------------------------
Every function that can deny or mutate takes an explicit ``actor_sub``
keyword: the caller's VERIFIED raw token subject, sourced by the tools
layer from token claims — never re-derived here. It is threaded through
separately from any resolved ``*_agent_id`` because the two can fail
independently: a garbage/spoofed ``agent_id`` must still produce an
audit row attributable to the real ``actor_sub`` that presented it. Only
``register_agent`` accepts ``sub`` instead of a resolved ``agent_id``,
since establishing that mapping is exactly what it does.

Access model (v1, internal trust domain)
-----------------------------------------
- Board admission is the permission: an ``Agent`` row (created by
  ``register_agent``) is what lets a ``sub`` participate. No pairwise
  grants (DESIGN.md §4, §10 — the seam for one is
  ``_authorize_conversation_open``).
- Membership = visibility. An ``invited`` participant sees only minimal
  conversation metadata (no messages) until they call ``accept_invite``;
  an ``active`` participant sees full history; a ``left``/``declined``
  participant sees nothing further — identical to a non-member.
- Every conversation-scoped authorization failure raises the single
  uniform ``AccessDeniedError`` (see ``exceptions.py``) — identical message
  whether the conversation does not exist, the caller was never invited,
  is still ``invited`` and trying to read content or post, or
  left/declined. The audit trail distinguishes causes via the ``action``
  column even though the client-visible message never does.
- Conversation-open authorization routes through
  ``_authorize_conversation_open`` (whole-participant-set predicate) and
  invites through ``may_invite`` — the seams DESIGN.md §10 names for a
  future grants/consent layer.

Judgment calls made in this module (documented once, here, rather than
scattered as inline comments):

- **Expiry vs. history access**: lazy expiry (``expires_at`` in the past)
  flips an ``active`` conversation to ``expired`` on next touch and then
  treats it exactly like ``completed``/``canceled`` for *write* legality
  (``is_message_legal`` already rejects all message types outside
  ``active``). For *reads*, membership is still visibility: a participant
  who was ``active`` before expiry keeps read access to full history
  afterward — expiry ends the negotiation, it does not retroactively
  revoke a member's own record of it. This mirrors how ``completed`` and
  ``canceled`` conversations already remain readable by their members.
- **Unknown agent / type-not-accepted uniformity**: see
  ``exceptions.AccessDeniedError``'s docstring — folded into the uniform denial
  rather than given a leakier, more specific message.
- **Board-level ``Agent.status`` gating**: checked (uniform denial) on the
  *initiating* side of a write — starting a conversation, inviting, and
  posting all require the actor's own agent to be board-``active``, and
  ``invite``/``start_conversation`` require the same of every target. It
  is deliberately NOT re-checked on ``accept_invite``/``decline_invite``/
  ``leave``: those are a participant exiting or resolving their own
  already-granted membership, and a participant should always be able to
  do that even if ops suspends their agent mid-negotiation.

Audit contract
--------------
Every mutation AND every authorization/validation/rate-limit denial writes
an ``audit_log`` row, committed together with (or in place of) the
operation it describes. Denial actions are namespaced ``denied.*``:
``denied.not_member`` (no participant row at all), ``denied.wrong_state.
<status>`` (the participant OR the conversation itself is in the wrong
state for this operation — keeps each of a participant's "already
active"/"declined"/"left", and a conversation's "completed"/"canceled"
zombie-invite case, distinguishable in the trail even though the client
sees one uniform message), ``denied.unknown_agent``,
``denied.already_participant``, ``denied.bad_state`` (state-machine
violation), ``denied.bad_schema`` (payload validation),
``denied.rate_limited`` (limit names: ``conversation_starts_per_hour``,
``messages_per_conversation_per_hour``, ``messages_per_sender_per_hour``,
and — TECH-5389 PR2 — ``approval_holds_per_hour``),
``denied.ownership_unverified`` (Axis 1 admission — conversation open,
invite owner-freeze — lookup failed; fail closed), ``denied.not_same_owner``/
``denied.no_owner_overlap`` (conversation-open admission failed for
``internal``/``asymmetric``), ``denied.owner_set_frozen`` (an invite would
expand a frozen owner set), ``denied.wrong_sender_role`` (DESIGN.md §9
Axis 2's per-message sender-role check), ``denied.message_type_not_accepted``
(a recipient hasn't declared ``message_type`` in their own
``accepted_types`` — a capability gate, not a trust boundary, so it applies
universally, even to ``internal`` traffic that Axis 2 itself always
allows), ``denied.is_shared_requires_elevated_scope`` (a caller without
``comms:admin`` tried to self-declare ``is_shared=True`` at first
registration), and ``denied.set_shared_requires_elevated_scope`` (a caller
without ``comms:admin`` tried to use the ``set_agent_shared`` admin
override).

TECH-5703's ``denied.target_agent_retired`` is the one denial that is
audited under ``_deny_agent_retired`` rather than the uniform ``_deny``
above -- it raises the specific, client-visible ``AgentRetiredError``
instead of ``AccessDeniedError`` (see that exception's own docstring for
why this one case gets a specific message).

TECH-5389 PR2's approval-holds pipeline (DESIGN.md §9 Axis 2) retired the
per-message ``denied.boundary_crossing`` denial: a genuine high-risk
verdict now DIVERTS to an ``approval_holds`` row instead of denying (see
``approval.*`` below), and only a scorer INFRASTRUCTURE failure still
denies -- via ``denied.risk_unscored``, folding the former per-message
``denied.ownership_unverified``/``denied.unknown_conversation_type`` causes
into one action, keyed by ``exc.cause`` in the audit detail. New PR2
denials: ``denied.system_message_type`` (an agent tried to post the
service-synthesized ``conversation_opened`` marker directly);
``denied.unknown_hold``/``denied.hold_not_sender`` (uniform,
``comms_get_hold_status``); ``denied.hold_not_owner`` (uniform, the decide
endpoint).

New PR2 mutation actions: ``approval.hold`` (a high-risk verdict created a
hold), ``approval.escalate``/``approval.auto_approve`` (the auto-approver's
inline decision), ``approval.approve``/``approval.reject`` (a human's
decide-endpoint decision), ``approval.expire`` (lazy TTL expiry on touch).

Bypass/best-effort-observability actions are a third category, neither a
mutation nor a denial: they record that a privileged or fire-and-forget
code path was taken, not that anything was created or refused.
``risk.shared_sender_bypass`` (renamed from PR1's still-unrenamed
``agent.boundary_check_bypassed_shared`` — no backwards compatibility,
ratified)/``agent.conversation_open_bypassed_shared`` (a
``comms:admin``-authorized shared sender/initiator skipped the
ownership-boundary check for a message/conversation-open respectively --
DESIGN.md §9), ``agent.reregister_is_shared_ignored`` (a re-registration's
requested ``is_shared`` value diverged from the already-frozen row value
and was silently ignored, per ``is_shared``'s freeze-at-first-registration
rule), and ``approval.notify_failed`` (the post-commit approval notifier
raised — logged, never fails the triggering call).
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import uuid
from collections.abc import Callable, Sequence
from collections.abc import Set as AbstractSet
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn, Protocol

from sqlalchemy import func, literal, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import (
    AccessDeniedError,
    AgentRetiredError,
    HoldAlreadyDecidedError,
    HoldAwaitingAutoReviewError,
    HoldExpiredError,
    InvalidConversationStateError,
    RateLimitExceededError,
    SchemaVersionMismatchError,
    UnknownConversationTypeError,
)
from models import Agent, ApprovalHold, AuditLog, Conversation, Message, Participant
from plugins import (
    ActiveChecker,
    ApprovalNotification,
    ApprovalNotifier,
    AutoApprover,
    HoldContext,
    MessageRiskContext,
    RiskScorer,
    RiskScoringInfraError,
    resolve_plugin,
)
from plugins import (
    auto_approver_name as _auto_approver_name,
)
from plugins import (
    notifier_name as _notifier_name,
)
from plugins import (
    risk_scorer_name as _risk_scorer_name,
)
from schemas import (
    CONVERSATION_TYPES,
    MAX_ACCEPTED_TYPE_LENGTH,
    MAX_ACCEPTED_TYPES,
    MAX_DISPLAY_NAME_LENGTH,
    MAX_REGISTERED_SCHEMA_VERSION,
    MESSAGE_TYPES,
    PayloadValidationError,
    validate_payload,
)
from state_machine import (
    is_message_legal,
    resulting_conversation_state,
)

# Plain stdlib logging, not structlog/observability.py's event-schema
# helpers: this module's own docstring commits to
# never importing fastmcp, and observability.py's log_* helpers exist for
# the tools-layer request lifecycle (tool_call/auth_flow/scope_denial),
# not an arbitrary service-layer diagnostic. This logger exists solely so
# an ownership-lookup failure's full exception (never persisted to the
# audit_log itself -- see the except block below) still lands somewhere
# (CloudWatch, via the ECS log driver) instead of being silently discarded.
logger = logging.getLogger(__name__)

# Module-level invariant check, not an in-function guard:
# invite()'s schema-version-mismatch denial path (see the comment at its
# _deny_schema_version_mismatch call) computes its audit-detail fields
# ("required_min"/"available_max") correctly only for the direction
# reachable while MAX_REGISTERED_SCHEMA_VERSION == 1. An in-function check
# placed inside that one denial branch would fire only on that one
# authorization path -- writing no audit row and emitting no log for what
# would be a security-relevant deny event, since
# _deny_schema_version_mismatch (which does both) is never reached if this
# check raises first. Checking it here instead means a deploy that ships a
# second schema version without revisiting that comment crash-loops at
# import time, loudly, rather than silently mislabeling an audit row deep
# inside a request. A plain `if`/`raise`, not a bare `assert` -- this
# module already avoids `assert` for invariant checks elsewhere (see the
# "stripped under python -O" comment on the migration-context bind check)
# since an assert would silently vanish under -O, making this check itself
# as fragile as the thing it guards against.
if MAX_REGISTERED_SCHEMA_VERSION != 1:
    raise RuntimeError(
        "invite()'s schema-mismatch audit semantics (service.py) assume "
        "MAX_REGISTERED_SCHEMA_VERSION == 1 -- revisit that call site's audit-field "
        "comment before shipping a second schema version"
    )

# --- Policy constants --------------------------------------------------------

# Default conversation TTL by conversation type.
# Applied when a caller doesn't supply an explicit ``expires_at`` to
# ``start_conversation``. Values chosen to match typical use:
#   open       — scheduling negotiations; a week is already stale
#   asymmetric — cross-owner task delegation; two weeks gives room to breathe
#   internal   — same-owner coordination; a month for longer-running tasks
# The explicit-override parameter exists so tests can construct already-expired
# conversations without sleeping.
CONVERSATION_TTL: dict[str, timedelta] = {
    "open": timedelta(days=7),
    "asymmetric": timedelta(days=14),
    "internal": timedelta(days=30),
}

# Absolute ceiling on a caller-supplied ``expires_at`` override in
# ``start_conversation`` (TECH-5377). Nothing previously bounded how far in
# the future a caller could push this -- an explicit override with no upper
# bound defeats the whole point of a per-type default TTL. 90 days is 3x the
# longest default (``internal``'s 30 days): generous headroom for a
# legitimate long-running override, while still capping the worst case for a
# conversation that's abandoned right after creation and never touched again
# (expiry stays lazy either way -- see ``_maybe_expire`` -- this only bounds
# how long "lazy" can mean). Deliberately NOT a floor: tests construct
# already-expired conversations via an explicit past ``expires_at`` (see
# CONVERSATION_TTL's docstring above), which is intentional test tooling, not
# something this ceiling should reject.
MAX_CONVERSATION_TTL = timedelta(days=90)

# Per-sender rate limits, counted from the messages/conversations tables
# directly (no Redis — DESIGN.md §5: "No Redis until it matters").
MAX_MESSAGES_PER_CONVERSATION_PER_HOUR = 30
MAX_CONVERSATION_STARTS_PER_HOUR = 10
# Board-level, cross-conversation defense-in-depth: the two
# limits above are each scoped to a single conversation (or to opening new
# ones), so a sender could still flood MANY DIFFERENT conversations, each
# comfortably under MAX_MESSAGES_PER_CONVERSATION_PER_HOUR, and disclose or
# probe at a much higher aggregate rate than either limit alone suggests.
# This caps a sender's TOTAL message volume across every conversation
# combined. 120 is deliberately generous relative to the per-conversation
# cap: an agent legitimately juggling several concurrent negotiations at up
# to 30 msgs/hour each in 3-4 conversations stays comfortably under this;
# it exists to catch a sender spraying messages across many conversations
# to evade the per-conversation cap, not to constrain normal multi-
# negotiation traffic.
MAX_MESSAGES_PER_SENDER_PER_HOUR = 120

# Read-path page caps (TECH-5377): previously unbounded -- a long-lived
# conversation's ``get_conversation`` call, or an agent with many unread
# conversations, had no ceiling on rows returned in one response. Both use
# the same "fetch one extra row, trim, report has_more" pattern list_agents
# already established. get_conversation's cap is intentionally far above
# the per-hour message-volume limits above: it bounds one page of a single
# read, not a sender's write rate, and a caller behind by many pages
# (multiple concurrent negotiations, or a long since_seq gap) should still
# get a decently large page rather than needing dozens of round trips.
MAX_MESSAGES_PER_GET_CONVERSATION = 500
MAX_UNREAD_CONVERSATIONS_PER_INBOX = 100
MAX_PENDING_INVITES_PER_INBOX = 100

# Approval-holds pipeline (TECH-5389 PR2). TTL/rate-limit values confirmed
# in the plan doc §5. The rate limit is counted from approval_holds.created_at
# per sender -- same table-count pattern as every other rate limit in this
# module (no Redis).
APPROVAL_HOLD_TTL = timedelta(days=7)
MAX_APPROVAL_HOLDS_PER_HOUR = 10

# The one message type the SERVICE itself synthesizes (the seq-1 marker for
# a diverted conversation opener, schemas.ConversationOpenedV1) -- never
# legal as a caller-supplied message_type (denied.system_message_type,
# below) and exempt from the accepted_types capability gate by construction
# (no code path ever calls _enforce_message_type_accepted against it).
_SYSTEM_MESSAGE_TYPES: frozenset[str] = frozenset({"conversation_opened"})


def _now() -> datetime:
    return datetime.now(UTC)


# --- Audit helpers ------------------------------------------------------------


def _audit(
    session: AsyncSession,
    *,
    actor_sub: str,
    action: str,
    agent_id: uuid.UUID | None = None,
    conversation_id: uuid.UUID | None = None,
    message_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Stage an append-only audit row (committed by the caller)."""
    session.add(
        AuditLog(
            actor_sub=actor_sub,
            action=action,
            agent_id=agent_id,
            conversation_id=conversation_id,
            message_id=message_id,
            detail=detail,
        )
    )


async def _deny(
    session: AsyncSession,
    *,
    actor_sub: str,
    action: str,
    agent_id: uuid.UUID | None = None,
    conversation_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> NoReturn:
    """Audit a denial, COMMIT it, and raise the uniform ``AccessDeniedError``.

    The commit persists the denial row (and any state already staged on
    the session, e.g. a lazy expiry flip) even though the caller's
    operation fails.
    """
    _audit(
        session,
        actor_sub=actor_sub,
        action=action,
        agent_id=agent_id,
        conversation_id=conversation_id,
        detail=detail,
    )
    await session.commit()
    raise AccessDeniedError(reason=action)


_DENIED_TARGET_AGENT_RETIRED = "denied.target_agent_retired"


async def _deny_agent_retired(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    target_agent_id: uuid.UUID,
) -> NoReturn:
    """Same audit/commit shape as ``_deny``, but for the one case
    (TECH-5703) that gets its own specific, non-uniform error --
    see ``exceptions.AgentRetiredError``'s docstring for why."""
    _audit(
        session,
        actor_sub=actor_sub,
        action=_DENIED_TARGET_AGENT_RETIRED,
        agent_id=agent_id,
        conversation_id=conversation_id,
        detail={"target_agent_id": str(target_agent_id)},
    )
    await session.commit()
    raise AgentRetiredError(reason=_DENIED_TARGET_AGENT_RETIRED)


async def _deny_bad_state(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    current_state: str,
    message_type: str,
) -> NoReturn:
    """Audit + raise the specific (non-uniform) state-machine violation."""
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.bad_state",
        agent_id=agent_id,
        conversation_id=conversation_id,
        detail={"state": current_state, "message_type": message_type},
    )
    await session.commit()
    raise InvalidConversationStateError(
        f"message type '{message_type}' is not legal while the conversation is '{current_state}'"
    )


async def _deny_rate_limited(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    limit_name: str,
    message: str,
) -> NoReturn:
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.rate_limited",
        agent_id=agent_id,
        conversation_id=conversation_id,
        detail={"limit": limit_name},
    )
    await session.commit()
    raise RateLimitExceededError(message, reason=limit_name)


async def _deny_schema_version_mismatch(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    participant_ids: list[uuid.UUID],
    required_min: int,
    available_max: int,
) -> NoReturn:
    """Audit + raise the schema-version-mismatch denial.

    ``required_min``/``available_max`` carry different underlying
    computations at this function's two call sites —
    ``start_conversation`` passes the negotiated-set's
    ``max(min_schema_version)``/clamped-``min(max_schema_version)``
    (see ``_negotiate_schema_version``), while ``invite`` passes a single
    new target's own ``min_schema_version``/the conversation's already-
    pinned version (see ``_conversation_pinned_schema_version``). Both are
    still "the floor that was required" vs. "the ceiling that was
    available" in the audit record, which is why one field pair covers
    both — but the two call sites are NOT computing the same thing, so
    don't assume ``required_min``/``available_max`` are directly
    comparable in the audit trail across a start-vs-invite denial without
    checking which call site produced the row.

    The exact values are recorded in the audit detail (server-side only)
    but deliberately NOT included in the raised message: unlike
    ``UnknownConversationTypeError``'s fixed ``CONVERSATION_TYPES`` vocabulary,
    an agent's registered ``[min, max]``
    range is its own per-agent state -- an initiator could otherwise
    recover a target's exact range by varying its own declared range
    across repeated ``start_conversation``/``invite`` calls and bisecting
    on which side of the mismatch it lands.
    """
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.schema_version_mismatch",
        agent_id=agent_id,
        conversation_id=conversation_id,
        detail={
            "participant_agent_ids": [str(p) for p in participant_ids],
            "required_min": required_min,
            "available_max": available_max,
        },
    )
    await session.commit()
    raise SchemaVersionMismatchError(
        "schema_version_mismatch: no wire schema version is supported by "
        "every participant in this conversation"
    )


async def _negotiate_schema_version(
    session: AsyncSession, *, actor_sub: str, initiator: Agent, targets: list[Agent]
) -> int:
    """Compute the highest wire schema version every participant mutually
    supports, refusing to open the conversation if no such version exists.

    Schema-version capability negotiation, evaluated once at ``start_conversation``
    (a fresh participant set is only ever assembled here, not on every later
    message — a message's own per-message ``schema_version`` field is the
    sibling agent-local defense-in-depth layer's concern, not this one's).

    Combined refuse-vs-degrade rule: the candidate version is the lowest
    common denominator (``min`` of every participant's declared
    ``max_schema_version``), clamped down to
    ``schemas.MAX_REGISTERED_SCHEMA_VERSION`` — the highest version this
    board's own code actually implements. Without that clamp, two agents
    that both legitimately declare a ``max_schema_version`` above what the
    board supports would negotiate to a version nothing can validate
    payloads against, turning a board capability limit into a confusing
    ``PayloadValidationError`` on the very next line. If
    the clamped candidate is still >= every participant's declared
    ``min_schema_version`` (i.e. it falls inside every participant's
    ``[min, max]`` range), the conversation degrades to it. Otherwise there
    is no version at all that every participant can correctly interpret
    (or that the board itself supports), and opening is refused entirely
    (``SchemaVersionMismatchError``).
    """
    participants = [initiator, *targets]
    negotiated_version = min(
        min(p.max_schema_version for p in participants), MAX_REGISTERED_SCHEMA_VERSION
    )
    required_floor = max(p.min_schema_version for p in participants)
    if required_floor > negotiated_version:
        await _deny_schema_version_mismatch(
            session,
            actor_sub=actor_sub,
            agent_id=initiator.id,
            conversation_id=None,
            participant_ids=[p.id for p in participants],
            required_min=required_floor,
            available_max=negotiated_version,
        )
    return negotiated_version


async def _deny_bad_schema(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    message_type: str,
    exc: PayloadValidationError,
) -> NoReturn:
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.bad_schema",
        agent_id=agent_id,
        conversation_id=conversation_id,
        detail={"message_type": message_type},
    )
    await session.commit()
    raise exc


async def _deny_if_system_message_type(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    message_type: str,
) -> None:
    """Deny a caller-supplied ``message_type`` that is service-synthesized-only.

    Without this, an agent could forge the board's own
    ``conversation_opened`` "opened pending approval" marker (TECH-5389
    PR2 §6) -- a deliberately tiny resurrection of an earlier plan's
    mint-gate mechanic, scoped to this one system marker type.
    """
    if message_type in _SYSTEM_MESSAGE_TYPES:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.system_message_type",
            agent_id=agent_id,
            conversation_id=conversation_id,
            detail={"message_type": message_type},
        )


async def _deny_rate_limited_holds(
    session: AsyncSession, *, actor_sub: str, sender_agent_id: uuid.UUID
) -> None:
    """Hold-creation rate limit (TECH-5389 PR2) -- distinct from every
    other rate limit in this module: it counts ``approval_holds`` rows, not
    ``messages``/``conversations`` rows. Never part of the divert-don't-deny
    reversal -- a sender flooding the human approval queue is still capped."""
    one_hour_ago = _now() - timedelta(hours=1)
    count = (
        await session.execute(
            select(func.count())
            .select_from(ApprovalHold)
            .where(
                ApprovalHold.sender_agent_id == sender_agent_id,
                ApprovalHold.created_at > one_hour_ago,
            )
        )
    ).scalar_one()
    if count >= MAX_APPROVAL_HOLDS_PER_HOUR:
        await _deny_rate_limited(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=None,
            limit_name="approval_holds_per_hour",
            message=f"rate_limited: at most {MAX_APPROVAL_HOLDS_PER_HOUR} approval holds per hour",
        )


# --- Lookups -------------------------------------------------------------------


async def _find_agent_by_id(session: AsyncSession, agent_id: uuid.UUID) -> Agent | None:
    return (await session.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()


async def get_agent_by_sub(session: AsyncSession, sub: str) -> Agent | None:
    """Resolve a caller's verified ``sub`` to their board ``Agent`` row, or ``None``.

    The tools layer (stage 3) calls this on every tool except
    ``register_agent`` to turn the caller's raw token subject into the
    ``agent_id`` every other function in this module expects. Read-only,
    no denial/audit path, and no board-``status`` gating here — "this sub
    has never registered" is not a conversation-authorization decision (it
    is folded into the uniform ``AccessDeniedError`` nowhere else in this
    module), so the tools layer is expected to surface it as its own
    explicit "call comms_register first" error rather than the uniform
    denial, which is about conversation access, not board admission.
    """
    return (await session.execute(select(Agent).where(Agent.sub == sub))).scalar_one_or_none()


async def _fk_safe_agent_id(session: AsyncSession, agent_id: uuid.UUID) -> uuid.UUID | None:
    """Return ``agent_id`` iff it references a real ``Agent`` row, else ``None``.

    ``audit_log.agent_id`` is FK-constrained to ``agents.id``. Most denial
    paths only ever see an ``agent_id`` that already passed through
    ``_require_active_agent`` (so it is always FK-safe by construction),
    but the "not a participant at all" branches below can be reached with
    a caller-presented ``agent_id`` that was never resolved against the
    ``agents`` table at all (e.g. a spoofed/garbage id) — inserting THAT
    into ``audit_log.agent_id`` would raise a ``ForeignKeyViolationError``
    and turn a graceful denial into a crash. This check keeps the denial
    graceful; the raw attempted id is still captured in ``detail`` by the
    caller so the audit trail doesn't lose it.
    """
    exists = (
        await session.execute(select(Agent.id).where(Agent.id == agent_id))
    ).scalar_one_or_none()
    return exists


async def _find_conversation(
    session: AsyncSession, conversation_id: uuid.UUID, *, for_update: bool = False
) -> Conversation | None:
    stmt = select(Conversation).where(Conversation.id == conversation_id)
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


async def _find_participant(
    session: AsyncSession, conversation_id: uuid.UUID, agent_id: uuid.UUID
) -> Participant | None:
    return (
        await session.execute(
            select(Participant).where(
                Participant.conversation_id == conversation_id,
                Participant.agent_id == agent_id,
            )
        )
    ).scalar_one_or_none()


async def _conversation_pinned_schema_version(
    session: AsyncSession, conversation_id: uuid.UUID
) -> int:
    """The wire schema version this conversation was negotiated/pinned to.

    Schema-version capability negotiation: rather than a separate persisted
    ``Conversation`` column, the pin is durably recoverable from the
    conversation's own append-only seq-1 ``Message.schema_version`` —
    ``start_conversation`` always writes the negotiated version there (see
    its own docstring), and that row is never updated/deleted. Used by
    ``invite`` to re-check a new participant against the already-pinned
    version, closing the gap where inviting could otherwise admit a
    participant whose declared range excludes it.

    Raises ``RuntimeError`` (an internal invariant violation, mapped to
    the generic ToolError at the tools boundary — see
    ``_map_service_errors``'s docstring) if the seq-1 row is somehow
    missing — every conversation this function is ever called on already
    passed ``_load_participant_for_transition``, which requires the
    conversation to exist, and ``start_conversation`` always writes seq-1
    atomically with the conversation row itself. Prefer
    this explicit, diagnosable failure over ``scalar_one()``'s
    ``NoResultFound`` leaking out as an unmapped internal error).
    """
    result = (
        await session.execute(
            select(Message.schema_version).where(
                Message.conversation_id == conversation_id, Message.seq == 1
            )
        )
    ).scalar_one_or_none()
    if result is None:
        raise RuntimeError(
            f"invariant violation: conversation {conversation_id} has no seq-1 message"
        )
    return result


def _maybe_expire(session: AsyncSession, actor_sub: str, conversation: Conversation) -> None:
    """Lazily flip an over-deadline 'active' conversation to 'expired'.

    Persisted by whatever commit the caller performs next (a denial's
    commit, or the operation's own success commit).
    """
    if conversation.state == "active" and conversation.expires_at <= _now():
        conversation.state = "expired"
        _audit(
            session,
            actor_sub=actor_sub,
            action="conversation.expire",
            conversation_id=conversation.id,
        )


async def _find_hold(
    session: AsyncSession, hold_id: uuid.UUID, *, for_update: bool = False
) -> ApprovalHold | None:
    stmt = select(ApprovalHold).where(ApprovalHold.id == hold_id)
    if for_update:
        # Argus round-1 BLOCKING catch (TOCTOU in decide_hold): without this
        # lock, two concurrent decide requests for the same hold can both
        # read status='pending_human' before either acquires the
        # conversation lock further down, both pass the status guard, and
        # both insert a message. Locking the hold row itself at fetch time
        # serializes concurrent decisions on the SAME hold.
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


def _maybe_expire_hold(session: AsyncSession, actor_sub: str, hold: ApprovalHold) -> None:
    """Lazily flip an over-TTL ``pending_auto``/``pending_human`` hold to
    ``expired`` on next touch (``comms_get_hold_status``, the decide
    endpoint, or ``GET /approvals/pending`` -- mirrors
    ``_maybe_expire``'s conversation-level lazy-expiry pattern). No
    scheduler/sweep exists in this codebase (TECH-5378) -- expiry is only
    ever observed by whichever caller happens to touch the row next."""
    if hold.status in ("pending_auto", "pending_human") and hold.expires_at <= _now():
        hold.status = "expired"
        _audit(
            session,
            actor_sub=actor_sub,
            action="approval.expire",
            conversation_id=hold.conversation_id,
            detail={"hold_id": str(hold.id)},
        )


def _hold_dict(hold: ApprovalHold) -> dict[str, Any]:
    result: dict[str, Any] = {
        "hold_id": str(hold.id),
        "conversation_id": str(hold.conversation_id),
        "status": hold.status,
        "risk_reason": hold.risk_reason,
        "created_at": _iso(hold.created_at),
        "expires_at": _iso(hold.expires_at),
    }
    if hold.decided_at is not None:
        result["decided_at"] = _iso(hold.decided_at)
    if hold.decision_reason is not None:
        result["decision_reason"] = hold.decision_reason
    if hold.message_id is not None:
        result["message_id"] = str(hold.message_id)
    return result


async def _require_active_agent(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
) -> Agent:
    """Resolve ``agent_id`` to its board-ACTIVE ``Agent``, or deny (uniform).

    Used on the *initiating* side of writes (starting a conversation,
    inviting, posting) — see the module docstring's judgment-call note on
    why this check is deliberately skipped for accept/decline/leave.
    """
    agent = await _find_agent_by_id(session, agent_id)
    if agent is None or agent.status != "active":
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_agent",
            agent_id=agent.id if agent else None,
        )
    return agent


async def _load_participant_for_transition(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    required_status: str,
    for_update: bool = False,
) -> tuple[Conversation, Participant]:
    """Load a conversation + the caller's participant row, requiring an
    EXACT current participant status; apply lazy expiry; deny (uniform)
    on every other outcome.

    Every failure — no such conversation, no participant row, or a
    participant row in any status other than ``required_status`` —
    raises the identical ``AccessDeniedError``. The audit ``action`` still
    distinguishes "not a participant at all" (``denied.not_member``) from
    "participant, but in the wrong status" (``denied.wrong_state.
    <current_status>``), per the module docstring's audit contract.
    """
    conversation = await _find_conversation(session, conversation_id, for_update=for_update)
    participant = (
        await _find_participant(session, conversation_id, agent_id) if conversation else None
    )
    if conversation is None or participant is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.not_member",
            agent_id=await _fk_safe_agent_id(session, agent_id),
            conversation_id=conversation.id if conversation else None,
            detail={"attempted_agent_id": str(agent_id)},
        )
    _maybe_expire(session, actor_sub, conversation)
    if participant.status != required_status:
        await _deny(
            session,
            actor_sub=actor_sub,
            action=f"denied.wrong_state.{participant.status}",
            agent_id=agent_id,
            conversation_id=conversation.id,
            detail={"required_status": required_status, "current_status": participant.status},
        )
    return conversation, participant


async def _load_participant_for_read(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
) -> tuple[Conversation, Participant]:
    """Load a conversation + participant for ``get_conversation``.

    Unlike ``_load_participant_for_transition``, an ``invited`` participant
    is NOT denied here — ``get_conversation`` itself decides what an
    ``invited`` caller may see (metadata only). Only "no participant row"
    and "left"/"declined" are denied, identically to non-membership.
    """
    conversation = await _find_conversation(session, conversation_id)
    participant = (
        await _find_participant(session, conversation_id, agent_id) if conversation else None
    )
    if conversation is None or participant is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.not_member",
            agent_id=await _fk_safe_agent_id(session, agent_id),
            conversation_id=conversation.id if conversation else None,
            detail={"attempted_agent_id": str(agent_id)},
        )
    if participant.status in ("left", "declined"):
        await _deny(
            session,
            actor_sub=actor_sub,
            action=f"denied.wrong_state.{participant.status}",
            agent_id=agent_id,
            conversation_id=conversation.id,
            detail={"current_status": participant.status},
        )
    _maybe_expire(session, actor_sub, conversation)
    return conversation, participant


# --- Policy seams --------------------------------------------------------------


async def _owner_sets_for(
    agents: list[Agent], ownership_client: OwnershipClient
) -> tuple[dict[uuid.UUID, frozenset[str]], dict[uuid.UUID, bool]]:
    """Resolve each agent's verified owner set and ``is_shared`` flag, one
    lookup at a time.

    Sequential, not concurrent (e.g. via ``asyncio.gather``):
    ``AgentTableOwnershipClient.get_agent_owners`` shares this call's
    ``AsyncSession``, which SQLAlchemy's ``AsyncSession`` does not support
    across concurrent coroutines.

    Returns ``(owner_sets, is_shared_by_id)`` so callers needing an
    individual participant's ``is_shared`` flag (e.g. the initiator) can
    reuse this single pass instead of issuing a second lookup.

    Callers MUST fail closed on any exception raised here (see
    ``OwnershipClient``'s docstring) - this helper does not catch.
    """
    owner_sets: dict[uuid.UUID, frozenset[str]] = {}
    is_shared_by_id: dict[uuid.UUID, bool] = {}
    for agent in agents:
        info = await ownership_client.get_agent_owners(agent.id)
        owner_sets[agent.id] = frozenset(info.get("owners") or [])
        is_shared_by_id[agent.id] = bool(info.get("is_shared"))
    return owner_sets, is_shared_by_id


def _pairwise_admitted(
    conversation_type: str,
    participants: list[Agent],
    owner_sets: dict[uuid.UUID, frozenset[str]],
) -> bool:
    """Pure pairwise decision given already-resolved owner sets — every pair
    must independently satisfy the type's predicate (no star-topology
    exception: A-B and B-C admitted doesn't imply A-C is).
    """
    pairs = itertools.combinations(participants, 2)
    if conversation_type == "internal":
        return all(owner_sets[a.id] == owner_sets[b.id] for a, b in pairs)
    # asymmetric: exactly may_assign's owner-set-intersection predicate,
    # applied pairwise (this is the reuse the ticket calls out — one
    # predicate, not two independently-drifting implementations of
    # "do these owner sets intersect").
    return all(may_assign(owner_sets[a.id], owner_sets[b.id]) for a, b in pairs)


def may_invite(inviter_participant_status: str) -> bool:
    """v1 invite policy: any ACTIVE member may invite.

    Deliberately a plain predicate over just the inviter's participant
    status (not the whole ``Participant``/``Conversation`` objects) so it
    stays trivial to unit-test and to tighten later (e.g. owner-only
    invites) as a policy change, not a migration — DESIGN.md §4/§10.
    """
    return inviter_participant_status == "active"


# --- Serialization helpers ------------------------------------------------------


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _agent_public(agent: Agent) -> dict[str, Any]:
    """Directory projection — compact AXI fields, no ``owner_sub`` leak."""
    return {
        "agent_id": str(agent.id),
        "sub": agent.sub,
        "display_name": agent.display_name,
        "owner_email": agent.owner_email,
        "accepted_types": list(agent.accepted_types),
        "status": agent.status,
        "is_shared": agent.is_shared,
    }


def _conversation_dict(conversation: Conversation) -> dict[str, Any]:
    # Project the reconciled logical state, not necessarily the raw
    # column: a conversation past expires_at stays stored as "active"
    # until the next lazy-expiry touch (_maybe_expire), and read-only
    # paths (list_conversations, inbox) never make that touch themselves.
    # This is read-only display, not a mutation -- no audit row, no
    # commit, no change to the ORM object itself. A no-op for any caller
    # that already ran _maybe_expire (get_conversation, post_message,
    # etc.), since conversation.state is already "expired" there.
    state = conversation.state
    if state == "active" and conversation.expires_at <= _now():
        state = "expired"
    return {
        "conversation_id": str(conversation.id),
        "type": conversation.type,
        "state": state,
        "created_by": str(conversation.created_by),
        "expires_at": _iso(conversation.expires_at),
        "created_at": _iso(conversation.created_at),
    }


def _message_dict(message: Message, sender_sub: str) -> dict[str, Any]:
    return {
        "seq": message.seq,
        "sender_agent_id": str(message.sender_id),
        "sender_sub": sender_sub,
        "type": message.type,
        "schema_version": message.schema_version,
        "payload": message.payload,
        "created_at": _iso(message.created_at),
    }


# --- Board admission -----------------------------------------------------------


def validate_schema_version_range(min_schema_version: int, max_schema_version: int) -> None:
    """Shared schema-version-range validation for a declared range.

    Called from BOTH ``register_agent`` (below) and the ``comms_register``
    tool layer (``providers/comms.py``) so tightening this rule in one
    place tightens it everywhere, rather than the two independent guards
    silently drifting apart. Raises ``ValueError`` — a
    plain input-validation failure, not an authorization decision.
    """
    if min_schema_version < 1:
        raise ValueError("min_schema_version must be >= 1")
    if min_schema_version > max_schema_version:
        raise ValueError("min_schema_version must be <= max_schema_version")


async def register_agent(
    session: AsyncSession,
    *,
    sub: str,
    owner_sub: str,
    owner_email: str,
    display_name: str,
    accepted_types: list[str],
    min_schema_version: int = 1,
    max_schema_version: int = 1,
    is_shared: bool = False,
    is_shared_authorized: bool = False,
) -> Agent:
    """Idempotently create or re-bind the board ``Agent`` row for ``sub``.

    SECURITY: ``owner_sub``/``owner_email`` MUST be sourced by the caller
    (the MCP tools layer) from verified OAuth token claims — DESIGN.md §4:
    "Owner identity ... is always derived from verified token claims: never
    accepted as a parameter." This function performs NO token
    verification of its own; it persists exactly what it is given. Never
    call it with owner_sub/owner_email taken from untrusted tool arguments.

    SECURITY: ``is_shared_authorized`` gates ``is_shared=True`` on FIRST
    registration only (a re-registration can never change the already-frozen
    ``is_shared`` value, so the gate is a no-op there). ``is_shared`` is an
    admission-decision input — it lets its holder skip the pairwise
    ownership-boundary check in ``_authorize_conversation_open`` and the
    risk scorer's ownership lookups (``_score_message_risk``) — so
    self-declaring it at registration
    with only the baseline write scope would be a privilege escalation.
    Callers MUST compute this from the caller's own verified token (e.g. an
    elevated ``comms:admin`` scope or platform-provisioning identity) and
    pass ``True`` only when that check passes. Defaults to ``False``
    (fail-closed): an admission-decision-input gate must never silently
    grant its privilege to a caller that forgets the kwarg. Direct
    service-layer callers that need the convenience of a permissive
    default (e.g. tests) should set it in their own helper, not rely on
    this signature's default.

    Idempotent: calling again with the same ``sub`` updates
    ``display_name``/``accepted_types``/``owner_email`` in place (unique on
    ``agents.sub``) rather than creating a duplicate row, and re-marks the
    agent ``active`` + refreshes ``bound_at``. ``owner_sub`` is the
    exception: THIS function never overwrites it on a later call, even one
    presenting a different ``owner_sub`` — see the inline comment on the
    re-registration branch below: once ``add_task``'s ``may_assign`` started
    reading ``owner_sub`` as an admission-decision input, allowing a
    re-register to change it became a forgeable privilege-escalation path,
    not just an unmodeled edge case. ``write_through_ownership`` (TECH-5593)
    is a DELIBERATE, narrower exception to this freeze — see its own
    docstring for why it's safe: it's reachable only with claims the caller
    has already confirmed came from a trusted, registry-backed verifier,
    never from this function's own untrusted-by-default parameters.

    Raises ``ValueError`` (not ``AccessDeniedError``) for malformed input --
    this is a data-validation failure, not an authorization decision (the
    caller has not claimed a resource yet). In validation order: empty ``sub``;
    empty or over-length (``schemas.MAX_DISPLAY_NAME_LENGTH``) ``display_name``;
    empty ``accepted_types``; over-count (``schemas.MAX_ACCEPTED_TYPES``)
    ``accepted_types``; or any entry over-length
    (``schemas.MAX_ACCEPTED_TYPE_LENGTH``) within ``accepted_types``. NOTE: an
    empty ``accepted_types`` previously raised ``UnknownConversationTypeError``
    with an empty "got unknown" list; it now raises this plain ``ValueError``
    instead (a deliberate breaking change to the ToolError shape for that one
    input -- there is no unknown value to usefully name for an empty list).
    An ``accepted_types`` containing a value outside ``MESSAGE_TYPES``
    instead raises ``UnknownConversationTypeError`` (exceptions.py) --
    specific and client-safe by design, unlike the cases above.

    ``min_schema_version``/``max_schema_version`` (both default
    to ``1``, today's only version) declare the wire-schema version range
    this agent's own code can correctly interpret. ``start_conversation``
    negotiates down to the highest version every participant in a new
    conversation mutually supports, refusing to open at all if no version
    is inside every participant's range — see
    ``service._negotiate_schema_version``. Raises ``ValueError`` (via
    ``validate_schema_version_range``) if ``min_schema_version < 1`` or
    ``min_schema_version > max_schema_version`` (checked alongside the
    other input-validation failures above, not as an authorization
    decision).

    Omitting both range parameters on a RE-registration resets an existing
    agent's declared range to ``1``/``1`` — the same "both absent" default
    every fresh registration gets — even if that agent had previously
    declared a wider range. There is deliberately no "leave unchanged if
    omitted" behavior here, unlike ``owner_sub``: unlike that field (whose
    silent-overwrite would be a forgeable privilege escalation, see above),
    accepting a client's stated capability range at face value on every
    call is the correct posture, and unlike ``owner_email``, an
    accidentally-narrowed range is safe by construction — it can only make
    negotiation MORE conservative, never admit a version this agent can't
    handle.
    """
    validate_schema_version_range(min_schema_version, max_schema_version)
    sub = sub.strip()
    if not sub:
        raise ValueError("sub must be non-empty")
    display_name = display_name.strip()
    if not display_name:
        raise ValueError("display_name must be non-empty")
    if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
        raise ValueError(f"display_name exceeds {MAX_DISPLAY_NAME_LENGTH} characters")
    # Cap check runs FIRST, before computing unknown_types -- for security:
    # the old order let a caller submit an arbitrarily large
    # list of unknown-type strings and get every one of them echoed back
    # verbatim in the error message, silently bypassing the declared
    # MAX_ACCEPTED_TYPES cap for this input shape. Bounding the input size
    # up front means unknown_types is now computed over an already-capped
    # list, whatever the values.
    if len(accepted_types) > MAX_ACCEPTED_TYPES:
        raise ValueError(f"accepted_types exceeds {MAX_ACCEPTED_TYPES} entries")
    # Empty list is a distinct failure from "contains an unknown type" --
    # it's not client-safe/specific in the same way (there's no unknown
    # value to usefully enumerate), so it stays a bare ValueError rather
    # than UnknownConversationTypeError. Splitting these
    # avoids the confusing prior message "... (got unknown: [])" for an
    # empty list, which named zero unknown values while still claiming
    # something was unknown.
    if not accepted_types:
        raise ValueError("accepted_types must be non-empty")
    # Per-entry length cap, for security: the count cap above
    # bounds how many entries there are, not how long any one entry is --
    # without this, 20 arbitrarily large strings would all pass the count
    # check, then get echoed back verbatim in UnknownConversationTypeError
    # below. Checked before computing unknown_types for the same
    # echo-bounding reason as the count check.  Every real MESSAGE_TYPES
    # value is under 30 characters; 100 is a generous margin.
    if any(len(t) > MAX_ACCEPTED_TYPE_LENGTH for t in accepted_types):
        raise ValueError(
            f"accepted_types entries must not exceed {MAX_ACCEPTED_TYPE_LENGTH} characters"
        )
    unknown_types = sorted(set(accepted_types) - MESSAGE_TYPES)
    if unknown_types:
        raise UnknownConversationTypeError(
            "accepted_types must be a non-empty subset of "
            f"{sorted(MESSAGE_TYPES)} (got unknown: {unknown_types})"
        )
    normalized_types = sorted(set(accepted_types))

    existing = (await session.execute(select(Agent).where(Agent.sub == sub))).scalar_one_or_none()
    now = _now()
    created = existing is None
    if created and is_shared and not is_shared_authorized:
        # First-registration self-escalation: `is_shared` is frozen after
        # this point (see the re-registration branch below), so this is the
        # only moment a caller could ever mint a permanently privileged
        # agent. Deny before the row is created — audited the same as every
        # other fail-closed denial in this module.
        await _deny(
            session,
            actor_sub=sub,
            action="denied.is_shared_requires_elevated_scope",
            detail={"display_name": display_name},
        )
    if existing is None:
        agent = Agent(
            sub=sub,
            owner_sub=owner_sub,
            owner_email=owner_email,
            display_name=display_name,
            accepted_types=normalized_types,
            status="active",
            is_shared=is_shared,
            bound_at=now,
            min_schema_version=min_schema_version,
            max_schema_version=max_schema_version,
        )
        session.add(agent)
    else:
        agent = existing
        if is_shared != agent.is_shared:
            # Re-registration can never change the already-frozen `is_shared`
            # value (see the comment below), so this has no effect on the
            # row -- but leaving it unaudited would let repeated probing of
            # this escalation vector (or an accidental downgrade attempt) go
            # unnoticed. Note only, not a `_deny()` call: nothing is
            # actually being denied here.
            _audit(
                session,
                actor_sub=sub,
                action="agent.reregister_is_shared_ignored",
                agent_id=agent.id,
                detail={
                    "is_shared_requested": is_shared,
                    "is_shared_effective": agent.is_shared,
                    "is_shared_authorized": is_shared_authorized,
                },
            )
        # owner_sub and is_shared are deliberately NOT overwritten by THIS
        # function on re-registration. owner_sub is read by
        # AgentTableOwnershipClient as the input to may_assign's admission
        # decision, and agent-jwt extra claims (including owner_sub) are
        # caller-supplied and unverified (providers/comms.py). Allowing a
        # re-register to overwrite it would let a caller forge a victim's
        # owner_sub, re-register their own agent under it, and be admitted
        # into that victim's tasks. is_shared is frozen for the same
        # reason: it's an admission-decision input (shared senders bypass
        # the boundary-crossing check) and must not be escalatable
        # post-registration -- register_agent has NO exception to this one
        # (unlike owner_sub's write_through_ownership carve-out below,
        # is_shared's only other mutation path is the separately
        # comms:admin-gated set_agent_shared). Freezing both at first
        # registration closes those paths; owner_email is NOT similarly
        # frozen here. Unlike owner_sub, owner_email now does carry
        # admission-decision weight (since lookup_agent_by_email resolves
        # callers by this field), but it remains a caller-supplied,
        # unverified claim rather than a proven mailbox ownership fact --
        # see lookup_agent_by_email's docstring for the resulting
        # trust-model gap this re-write permits.
        #
        # NOTE (TECH-5593): "never overwritten" above describes THIS
        # function only. write_through_ownership -- called from
        # providers.comms._resolve_caller_agent on later, UNRELATED tool
        # calls, never from here -- IS a sanctioned exception to owner_sub's
        # freeze, but only when the caller has already confirmed the value
        # came from a trusted, registry-backed AGENT_TOKEN_VERIFIERS plugin
        # (scopes.is_registry_backed_agent_token), never from the same
        # caller-supplied, unverified claim this comment is about.
        agent.owner_email = owner_email
        agent.display_name = display_name
        agent.accepted_types = normalized_types
        agent.status = "active"
        agent.bound_at = now
        agent.min_schema_version = min_schema_version
        agent.max_schema_version = max_schema_version
    await session.flush()
    _audit(
        session,
        actor_sub=sub,
        action="agent.register",
        agent_id=agent.id,
        # `is_shared` is the effective/persisted row value (agent.is_shared);
        # `is_shared_requested` is the caller-supplied value. These can
        # diverge on re-registration, since is_shared is frozen -- do not
        # conflate them.
        detail={"created": created, "is_shared": agent.is_shared, "is_shared_requested": is_shared},
    )
    await session.commit()
    return agent


async def write_through_ownership(
    session: AsyncSession,
    agent: Agent,
    *,
    owner_sub: str | None,
    owner_email: str | None,
) -> None:
    """Bounded-staleness ownership write-through (TECH-5593).

    ``agents.owner_sub``/``owner_email`` are a deliberately-kept cache of
    the platform's real ownership registry (decision log #9 of the
    cross-repo target-state plan): ``register_agent`` freezes ``owner_sub``
    at first registration and never overwrites it on re-registration
    (see that function's docstring) because agent-jwt ``owner_sub`` claims
    are, in general, caller-supplied and unverified. This function is the
    ONE sanctioned exception to that freeze, and it exists specifically to
    bound the cache's staleness to whatever cache TTL the configured
    agent-token verifier itself uses (e.g. an HTTP-backed registry client's
    in-process TTL cache) instead of leaving it frozen forever.

    SECURITY: the caller MUST have already confirmed ``owner_sub``/
    ``owner_email`` came from a registry-backed verifier --
    ``scopes.is_registry_backed_agent_token`` -- before calling this
    function. This module deliberately stays free of any FastMCP/token
    dependency (see the module docstring), so it cannot make that check
    itself; it trusts its caller (``providers.comms._resolve_caller_agent``)
    the same way every other function here trusts ``actor_sub``. Calling
    this with a legacy agent-jwt token's self-asserted claims would reopen
    exactly the forgery hole ``register_agent``'s freeze exists to close.

    A no-op (no DB write, no audit row) when neither value differs from
    the stored row, or when both are ``None`` (nothing to write through --
    the configured verifier didn't supply an owner claim for this
    request).
    """
    changed: dict[str, dict[str, str]] = {}
    if owner_sub is not None and owner_sub != agent.owner_sub:
        changed["owner_sub"] = {"old": agent.owner_sub, "new": owner_sub}
        agent.owner_sub = owner_sub
    if owner_email is not None and owner_email != agent.owner_email:
        changed["owner_email"] = {"old": agent.owner_email, "new": owner_email}
        agent.owner_email = owner_email
    if not changed:
        return
    _audit(
        session,
        actor_sub=agent.sub,
        action="agent.ownership_write_through",
        agent_id=agent.id,
        detail=changed,
    )
    await session.commit()


async def set_agent_shared(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    is_shared: bool,
    is_shared_authorized: bool,
) -> Agent:
    """Admin override of an existing agent's ``is_shared`` value.

    ``register_agent`` freezes ``is_shared`` at first registration on
    purpose (see its docstring) — this function is the one supported way to
    correct it afterwards, for the case where an agent self-declared the
    wrong value at registration. Mirrors ``register_agent``'s
    ``is_shared_authorized`` gate exactly: the caller (tools layer) MUST
    compute this from the actor's own verified token (elevated
    ``comms:admin`` scope, or an interactive/Okta caller) and pass ``True``
    only when that check passes. Defaults are not provided (unlike
    ``register_agent``'s fail-closed ``False`` default) since this
    function's entire purpose is the privileged mutation — there is no
    unprivileged call site for it to protect.

    Raises ``AccessDeniedError`` with reason
    ``denied.set_shared_requires_elevated_scope`` if ``is_shared_authorized``
    is ``False`` (checked FIRST, before the existence lookup below, so an
    unauthorized caller's audit trail always records the authorization
    failure -- not ``denied.unknown_agent`` -- regardless of whether
    ``agent_id`` happens to be valid), or ``denied.unknown_agent`` if
    ``agent_id`` does not match any agent (uniform with every other
    unknown-agent-id denial in this module).
    """
    if not is_shared_authorized:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.set_shared_requires_elevated_scope",
            detail={"target_agent_id": str(agent_id), "requested_is_shared": is_shared},
        )
    agent = await _find_agent_by_id(session, agent_id)
    if agent is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_agent",
            detail={"target_agent_id": str(agent_id)},
        )
    previous = agent.is_shared
    agent.is_shared = is_shared
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="agent.set_shared",
        agent_id=agent.id,
        detail={"is_shared": is_shared, "previous": previous},
    )
    await session.commit()
    return agent


async def list_agents(
    session: AsyncSession,
    *,
    active_checker: ActiveChecker,
    limit: int = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Paginated board directory, ordered by ``sub`` (keyset pagination).

    ``cursor`` is the ``sub`` of the last agent from a previous page;
    passing it back returns the next page. Not authorization-gated at this
    layer (internal trust domain, DESIGN.md §10 flags directory enumeration
    as acceptable today and as the seam that tightens once external
    counterparties exist) — no denial paths, so no audit rows.

    TECH-5703: a registry-retired agent (``active_checker.is_active`` false)
    is dropped from ``agents`` -- filtered AFTER pagination/cursor
    computation, which are still based on the raw DB rows, so a retired
    agent's ``sub`` still occupies its position in keyset order and paging
    never skips the row immediately after it. ``total_count`` deliberately
    still counts every row regardless of retirement (it reflects the table,
    not this listing's visibility -- the agent row itself is never deleted,
    per this ticket's audit-trail requirement).
    """
    limit = max(1, min(limit, 200))
    stmt = select(Agent).order_by(Agent.sub).limit(limit + 1)
    if cursor:
        stmt = stmt.where(Agent.sub > cursor)
    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    total_count = (await session.execute(select(func.count()).select_from(Agent))).scalar_one()
    visible_agents = [_agent_public(a) for a in rows if await active_checker.is_active(a.sub)]
    return {
        "agents": visible_agents,
        "total_count": total_count,
        "has_more": has_more,
        "next_cursor": rows[-1].sub if has_more and rows else None,
    }


MAX_LOOKUP_EMAIL_LENGTH = 254  # RFC 5321 4.5.3.1.3 total-address cap


async def lookup_agent_by_email(
    session: AsyncSession, *, owner_email: str, active_checker: ActiveChecker
) -> dict[str, Any] | None:
    """Directory lookup: is ``owner_email`` bound to a board-active agent?

    This realizes the "handshake registry" concept -- answering "does this
    email belong to a registered EA" -- directly on the existing ``Agent``
    table rather than a separate store: ``owner_email``/``sub`` already
    carry exactly what a caller needs (which email, which board-wide
    identity), so there is nothing left to duplicate. Formerly its own
    module (``registry/directory.py``) inside the negotiation
    library; folded in here once each EA agent started
    holding its own calendar and that library stopped needing a copy of
    this lookup for itself -- the comms board is the one place every agent
    can already reach, so this is where the lookup belongs. See
    ``docs/DESIGN.md`` §10 for this endpoint's anti-enumeration posture.

    Comparison is case-insensitive (``func.lower``) since OAuth-sourced
    email claims are not guaranteed to arrive in one canonical case, but
    does not attempt the fuller NFKC-normalization ``rh_maiea.canonical``
    applies -- this service has no dependency on that library (by design:
    the negotiation library and the comms board stay
    decoupled) and plain case-folding covers the realistic input space for
    values sourced from Okta/Google identity claims. Python's ``str.lower()``
    (used on the input) and Postgres's ``lower()`` (used on the stored
    value) can disagree on case-folding for some non-ASCII characters under
    a non-UTF-8 database collation -- not addressed here,
    since real input is Okta/Google email claims, which are ASCII.

    Fail-closed by construction, matching the retired module's contract:
    a non-string, empty/whitespace-only, or over-length (see
    ``MAX_LOOKUP_EMAIL_LENGTH``) ``owner_email`` returns ``None`` rather
    than raising or querying -- there is no legitimate email this could
    ever match, and the dangerous failure mode here is a false positive
    (treating an unregistered counterparty as EA-represented), not a
    missed match. This validation intentionally lives here rather than at
    the ``comms_lookup_agent_by_email`` tool boundary: it
    mirrors the retired module's own contract, which lived on the type
    doing the lookup, not its caller.

    This validation is one-sided: ``register_agent`` (the write path) does
    not strip, lower-case, or length-cap ``owner_email`` before storing it
    -- including the JWT ``sub``-fallback path (``providers/comms.py``),
    which can write a non-email URI as ``owner_email`` for a token with no
    ``email``/``owner_email`` claim. An agent whose stored ``owner_email``
    has incidental leading/trailing whitespace, or came from that fallback
    path, will not be found here -- indistinguishable from "not
    registered". Not fixed in this pass: normalizing at
    write time is a broader change to ``register_agent`` than this lookup
    feature's scope.

    This is a claims lookup, not a verified-ownership lookup: ``owner_email``
    is caller-supplied at registration (an agent-jwt caller can pass any
    string, and ``register_agent`` overwrites it on every re-registration,
    see that function's docstring) and is never checked against the actual
    mailbox. A match here means "some agent currently *claims* to be
    represented by this ``owner_email``", not "this ``owner_email`` *is*
    EA-represented by this specific agent" -- i.e. this answers "who
    currently claims this email", not "who is verified to own it". A
    malicious caller can register under a victim's email and, because the
    tiebreak below is ``bound_at`` DESC, a later spoofing re-registration
    can outrank the legitimate agent in this lookup's result.

    ``owner_email`` is NOT a unique column: ``register_agent`` never
    demotes another agent's status when a new ``sub`` registers under the
    same ``owner_email`` (the ``agent_key`` mechanism -- see that
    function's docstring -- deliberately allows one owner to run multiple
    board-active agents under the same email). So multiple active rows
    for one ``owner_email`` is an expected, not exceptional, state, and
    this function deterministically returns whichever is most recently
    (re)bound. Ties break, in order: ``bound_at`` DESC, then ``created_at``
    DESC (two rows can share the same ``bound_at``/``created_at`` down to
    the microsecond -- ``created_at`` in particular freezes to transaction
    start time via ``server_default=text("now()")``, so two agents
    registered in the same transaction get an identical value), then
    ``id`` (the UUID primary key, the only column here actually guaranteed
    unique) as the final, always-deterministic tiebreaker. This is NOT
    "the" registered EA in any stronger sense. Do not read the
    ``status == "active"`` filter as "a deregistered agent is
    never returned": nothing in this codebase currently transitions an
    agent to ``"suspended"`` (the only other value ``AGENT_STATUSES``
    allows), so today that filter is inert, future-proofing for
    deregistration rather than an enforced guarantee. TECH-5703's
    ``active_checker`` filter below is the actual enforcement mechanism for
    retirement today -- a registry-retired agent is excluded here the same
    way an unregistered email is (``None``, not a distinguishable error),
    matching this lookup's existing anti-enumeration posture.
    """
    if not isinstance(owner_email, str):
        return None
    normalized = owner_email.strip().lower()
    if not normalized or len(normalized) > MAX_LOOKUP_EMAIL_LENGTH:
        return None
    stmt = (
        select(Agent)
        .where(func.lower(Agent.owner_email) == normalized, Agent.status == "active")
        .order_by(Agent.bound_at.desc().nullslast(), Agent.created_at.desc(), Agent.id.asc())
        .limit(1)
    )
    agent = (await session.execute(stmt)).scalar_one_or_none()
    if agent is None:
        return None
    if not await active_checker.is_active(agent.sub):
        return None
    return _agent_public(agent)


async def list_conversations(
    session: AsyncSession,
    *,
    caller_agent_id: uuid.UUID,
    role: str | None = None,
    conversation_type: str | None = None,
    state: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Paginated list of conversations the caller participates in.

    Filters (all optional, combinable):
    - ``role``: ``"owner"``, ``"member"``, or ``None`` for any role.
    - ``conversation_type``: one of ``CONVERSATION_TYPES`` or ``None`` for any.
    - ``state``: one of ``"active"``, ``"completed"``, ``"canceled"``,
      ``"expired"``, or ``None`` for any.

    Keyset-paginated over ``(created_at DESC, id DESC)`` — pass back the
    ``next_cursor`` value from a prior response to get the next page.
    Visibility is scoped to conversations where the caller has a non-declined,
    non-left participant row (``invited`` and ``active`` both visible).
    """
    limit = max(1, min(limit, 200))

    # Base join: conversations the caller participates in (any non-exit status)
    stmt = (
        select(Conversation)
        .join(
            Participant,
            (Participant.conversation_id == Conversation.id)
            & (Participant.agent_id == caller_agent_id)
            & (Participant.status.in_(["invited", "active"])),
        )
        .order_by(Conversation.created_at.desc(), Conversation.id.desc())
        .limit(limit + 1)
    )

    if role is not None:
        stmt = stmt.where(Participant.role == role)
    if conversation_type is not None:
        stmt = stmt.where(Conversation.type == conversation_type)
    if state is not None:
        # Conversations past expires_at stay stored as "active" until the
        # next lazy-expiry touch (_maybe_expire) — filtering on the raw
        # column alone would return stale-expired rows for "active" and
        # match almost nothing for "expired". Reconcile against
        # expires_at directly rather than eagerly expiring every row this
        # query would otherwise touch.
        if state == "active":
            stmt = stmt.where(Conversation.state == "active", Conversation.expires_at > _now())
        elif state == "expired":
            stmt = stmt.where(
                or_(
                    Conversation.state == "expired",
                    (Conversation.state == "active") & (Conversation.expires_at <= _now()),
                )
            )
        else:
            stmt = stmt.where(Conversation.state == state)

    if cursor:
        # cursor = "<created_at_iso>|<id>"
        try:
            ts_part, id_part = cursor.rsplit("|", 1)
            cursor_ts = datetime.fromisoformat(ts_part)
            cursor_id = uuid.UUID(id_part)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"malformed cursor: {cursor!r}") from exc
        stmt = stmt.where(
            tuple_(Conversation.created_at, Conversation.id)
            < tuple_(literal(cursor_ts), literal(cursor_id))
        )

    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]

    next_cursor = f"{rows[-1].created_at.isoformat()}|{rows[-1].id}" if has_more and rows else None
    return {
        "conversations": [_conversation_dict(c) for c in rows],
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


# --- Conversation lifecycle -----------------------------------------------------


async def _enforce_start_rate_limit(
    session: AsyncSession, *, actor_sub: str, initiator: Agent
) -> None:
    one_hour_ago = _now() - timedelta(hours=1)
    count = (
        await session.execute(
            select(func.count())
            .select_from(Conversation)
            .where(
                Conversation.created_by == initiator.id,
                Conversation.created_at > one_hour_ago,
            )
        )
    ).scalar_one()
    if count >= MAX_CONVERSATION_STARTS_PER_HOUR:
        await _deny_rate_limited(
            session,
            actor_sub=actor_sub,
            agent_id=initiator.id,
            conversation_id=None,
            limit_name="conversation_starts_per_hour",
            message=(
                f"rate_limited: at most {MAX_CONVERSATION_STARTS_PER_HOUR} "
                "conversation starts per hour"
            ),
        )


async def _resolve_targets(
    session: AsyncSession,
    *,
    actor_sub: str,
    initiator: Agent,
    target_ids: list[uuid.UUID],
    active_checker: ActiveChecker,
) -> list[Agent]:
    """Resolve every named target, requiring it to exist and be board-active.

    Ownership/ownership-boundary admission across the WHOLE participant
    set (initiator + targets) is a separate step (``_authorize_conversation_open``)
    — this function only rules out missing/inactive targets, uniformly
    denied as ``denied.unknown_agent``. TECH-5703: a target that DOES exist
    and is board-active, but whose registry reports it retired, gets the
    specific ``AgentRetiredError`` instead (see that exception's docstring
    for why this one case is deliberately not folded into the uniform
    denial above) -- checked only after the existence/board-active gate, so
    a genuinely unknown target still gets the uniform denial first.
    """
    rows = (await session.execute(select(Agent).where(Agent.id.in_(target_ids)))).scalars().all()
    by_id = {a.id: a for a in rows}
    for target_id in target_ids:
        target = by_id.get(target_id)
        if target is None or target.status != "active":
            await _deny(
                session,
                actor_sub=actor_sub,
                action="denied.unknown_agent",
                agent_id=initiator.id,
                detail={"target_agent_id": str(target_id)},
            )
        if not await active_checker.is_active(target.sub):
            await _deny_agent_retired(
                session,
                actor_sub=actor_sub,
                agent_id=initiator.id,
                conversation_id=None,
                target_agent_id=target_id,
            )
    return [by_id[target_id] for target_id in target_ids]


async def _authorize_conversation_open(
    session: AsyncSession,
    *,
    actor_sub: str,
    initiator: Agent,
    targets: list[Agent],
    conversation_type: str,
    ownership_client: OwnershipClient,
) -> dict[str, Any] | None:
    """Admit or deny opening ``conversation_type`` with this participant set.

    Returns the owner-set snapshot to persist on ``Conversation.owner_snapshot``
    on success (``None`` for ``open``, which has no ownership concept).
    Raises via ``_deny``/``_deny``-family helpers (``NoReturn``) otherwise —
    this function's return type omits that case because every ``_deny*``
    call always raises.

    Fails closed (``denied.ownership_unverified``) on any ownership-lookup
    exception, same posture ``add_task`` used.
    """
    participants = [initiator, *targets]
    if conversation_type == "open":
        return None
    owner_sets: dict[uuid.UUID, frozenset[str]] = {}
    is_shared_by_id: dict[uuid.UUID, bool] = {}
    try:
        owner_sets, is_shared_by_id = await _owner_sets_for(participants, ownership_client)
    except Exception as exc:
        logger.warning(
            "ownership lookup failed opening a conversation: %s",
            type(exc).__name__,
            exc_info=True,
        )
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.ownership_unverified",
            agent_id=initiator.id,
            detail={"conversation_type": conversation_type},
        )
    if any(not owners for owners in owner_sets.values()):
        # Fail closed on an empty owner set, same posture the deleted
        # add_task used — an ownership_client that soft-fails to {"owners": []}
        # instead of raising must not silently admit an unverified agent
        # (internal's set-equality check would otherwise treat two empty
        # sets as "identical" and admit them).
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.ownership_unverified",
            agent_id=initiator.id,
            detail={"conversation_type": conversation_type},
        )
    # The shared-initiator bypass only applies to `asymmetric` — the type
    # `is_shared` exists to bridge (DESIGN.md §9). `internal` requires every
    # participant to share one owner set BY CONSTRUCTION; letting a shared
    # initiator skip that check would let it open an `internal` conversation
    # across disjoint owners, defeating the type's invariant entirely.
    shared_bypass = conversation_type == "asymmetric" and is_shared_by_id.get(initiator.id, False)
    if shared_bypass:
        # Mirrors _score_message_risk's risk.shared_sender_bypass
        # audit: staged, not committed, for consistency
        # with that sibling bypass-observability event -- both are
        # persisted by the caller's own enclosing commit along with the
        # rest of the operation, exactly like every other non-`_deny`
        # audit call in this module. (An earlier round committed this one
        # immediately, since start_conversation holds no row lock here
        # unlike post_message; that asymmetry in durability between two
        # events DESIGN.md documents as the same category was itself the
        # bug -- consistency trumps the now-moot durability advantage.)
        _audit(
            session,
            actor_sub=actor_sub,
            action="agent.conversation_open_bypassed_shared",
            agent_id=initiator.id,
            detail={"conversation_type": conversation_type},
        )
    if not shared_bypass and not _pairwise_admitted(conversation_type, participants, owner_sets):
        await _deny(
            session,
            actor_sub=actor_sub,
            action=(
                "denied.not_same_owner"
                if conversation_type == "internal"
                else "denied.no_owner_overlap"
            ),
            agent_id=initiator.id,
            detail={"conversation_type": conversation_type},
        )
    snapshot_owners = sorted(set().union(*owner_sets.values()))
    return {"owners": snapshot_owners}


async def start_conversation(
    session: AsyncSession,
    *,
    actor_sub: str,
    initiator_agent_id: uuid.UUID,
    conversation_type: str,
    target_agent_ids: list[uuid.UUID],
    initial_message: dict[str, Any],
    ownership_client: OwnershipClient,
    risk_scorer: RiskScorer,
    auto_approver: AutoApprover,
    notifier: ApprovalNotifier,
    active_checker: ActiveChecker,
    message_type: str = "availability_request",
    schema_version: int = 1,
    expires_at: datetime | None = None,
    owner_sub_claim: str | None = None,
) -> Conversation:
    """Open a conversation with N other agents; post the seq-1 message.

    The initiator becomes an ``active`` participant with ``role='owner'``;
    every named target becomes an ``invited`` participant (DESIGN.md §4's
    invite/accept revision — "Named targets are added as invited, never
    active on creation"). ``initial_message``/``message_type`` are
    validated via ``schemas.validate_payload`` against
    ``(message_type, schema_version)`` before anything is persisted.

    Admission (``_authorize_conversation_open``) is evaluated over the
    FULL participant set at once — ``internal``
    requires identical verified owner sets, ``asymmetric`` requires every
    pair to intersect, ``open`` is unrestricted. The resulting owner-set
    snapshot is persisted on ``Conversation.owner_snapshot`` (``None`` for
    ``open``) so ``invite`` can later reject an invite that would expand
    the frozen set.

    Raises ``ValueError`` for a malformed ``conversation_type`` or an empty
    target list (input-validation, not authorization); ``AccessDeniedError``
    (uniform) if any target is unknown/inactive, or the participant set
    fails admission; ``AgentRetiredError`` (TECH-5703, specific -- not
    folded into the uniform denial above) if a target exists and is
    board-active but its registry reports it retired;
    ``RateLimitExceededError`` past the per-initiator
    conversation-start hourly cap OR the board-level per-sender-across-all-
    conversations hourly cap; ``SchemaVersionMismatchError`` if
    no wire schema version falls inside every participant's declared
    ``[min_schema_version, max_schema_version]`` range;
    ``schemas.PayloadValidationError`` if ``initial_message`` fails schema
    validation.
    """
    initiator = await _require_active_agent(
        session, actor_sub=actor_sub, agent_id=initiator_agent_id
    )
    # An agent may never post the service-synthesized marker type directly
    # as its own opener (TECH-5389 PR2 §6) -- checked early, before rate
    # limits, so forging an attempt doesn't consume rate-limit budget.
    await _deny_if_system_message_type(
        session,
        actor_sub=actor_sub,
        agent_id=initiator.id,
        conversation_id=None,
        message_type=message_type,
    )
    if len(conversation_type) > MAX_ACCEPTED_TYPE_LENGTH:
        raise ValueError(f"conversation_type exceeds {MAX_ACCEPTED_TYPE_LENGTH} characters")
    if conversation_type not in CONVERSATION_TYPES:
        raise UnknownConversationTypeError(
            f"unknown conversation_type {conversation_type!r} — supported: "
            f"{sorted(CONVERSATION_TYPES)}"
        )
    target_ids = sorted({t for t in target_agent_ids if t != initiator.id}, key=str)
    if not target_ids:
        raise ValueError("target_agent_ids must name at least one other agent")
    # Ceiling only, deliberately no floor: an already-past expires_at is
    # valid test tooling (see CONVERSATION_TTL's docstring), so this rejects
    # only the unbounded-future case, not the already-expired one. Checked
    # against a validation-time timestamp, not the later insert-time ``now``
    # below (several async calls -- admission, rate limits -- separate the
    # two; reusing this one there would understate the actual creation time).
    if expires_at is not None:
        # A naive datetime would otherwise raise a raw TypeError from the
        # subtraction below (Argus round-1 SUGGESTION) -- a poor validation
        # experience that leaks an internal arithmetic failure instead of a
        # clear rejection. providers/comms.py's own _parse_expires_at
        # already rejects a naive datetime at the tool layer, but this
        # service function has other direct callers (tests, and any future
        # non-MCP caller), so it needs its own guard rather than relying on
        # that layer above it.
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        if expires_at - _now() > MAX_CONVERSATION_TTL:
            raise ValueError(f"expires_at may not be more than {MAX_CONVERSATION_TTL} from now")

    await _enforce_start_rate_limit(session, actor_sub=actor_sub, initiator=initiator)
    # start_conversation inserts its seq-1 message directly (below), rather
    # than delegating to post_message — so the board-level global rate
    # limit has to be enforced here too, or opening many new conversations
    # would be an easy way to route around it (post_message's own call
    # never sees the opening message). See _enforce_sender_global_rate_limit.
    await _enforce_sender_global_rate_limit(
        session, actor_sub=actor_sub, sender_agent_id=initiator.id
    )
    targets = await _resolve_targets(
        session,
        actor_sub=actor_sub,
        initiator=initiator,
        target_ids=target_ids,
        active_checker=active_checker,
    )

    # Schema-version capability negotiation: the caller-supplied schema_version
    # is NOT trusted as the actual wire version — it is overridden by the
    # highest version every participant (initiator + all targets) mutually
    # supports, refusing outright if no such version exists at all. See
    # _negotiate_schema_version's docstring for the combined refuse-vs-
    # degrade rule. Deliberately checked BEFORE _authorize_conversation_open:
    # negotiation is pure in-memory computation over
    # already-loaded Agent rows, while _authorize_conversation_open makes an
    # external ownership-service call for internal/asymmetric conversations
    # — running the cheap, purely local check first avoids that round-trip
    # on a mismatch that would refuse the conversation anyway.
    schema_version = await _negotiate_schema_version(
        session, actor_sub=actor_sub, initiator=initiator, targets=targets
    )

    owner_snapshot = await _authorize_conversation_open(
        session,
        actor_sub=actor_sub,
        initiator=initiator,
        targets=targets,
        conversation_type=conversation_type,
        ownership_client=ownership_client,
    )

    try:
        payload = validate_payload(message_type, schema_version, initial_message)
    except PayloadValidationError as exc:
        await _deny_bad_schema(
            session,
            actor_sub=actor_sub,
            agent_id=initiator.id,
            conversation_id=None,
            message_type=message_type,
            exc=exc,
        )

    # DESIGN.md §9 Axis 2 and the sender-role restriction apply to the
    # seq-1 message exactly like every later one. Checked here, before any
    # row is created: ``_deny`` commits whatever is already staged on the
    # session, so running these after ``session.add(conversation)`` would
    # persist an orphaned conversation/participant pair with no message on
    # a denial. The initiator's role in a freshly-opened conversation is
    # always "owner", passed directly rather than queried; the target list
    # is already in memory, so no conversation row is needed to know the
    # "other side" for the boundary check either.
    await _require_message_sender_role(
        session,
        actor_sub=actor_sub,
        sender_agent_id=initiator.id,
        conversation_id=None,
        message_type=message_type,
        sender_role="owner",
    )
    await _enforce_message_type_accepted(
        session,
        actor_sub=actor_sub,
        sender_agent_id=initiator.id,
        conversation_id=None,
        other_agents=[(t.id, t.accepted_types) for t in targets],
        message_type=message_type,
    )
    risk_reason = await _score_message_risk(
        session,
        actor_sub=actor_sub,
        sender_agent_id=initiator.id,
        conversation_type=conversation_type,
        conversation_id=None,
        other_agent_ids=[t.id for t in targets],
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
        risk_scorer=risk_scorer,
    )

    if risk_reason is not None:
        # Checked BEFORE any insert/flush below (not just before the divert
        # call) -- Argus round-1 BLOCKING catch: a rate-limit denial commits
        # via `_deny_rate_limited`, which would otherwise permanently
        # persist an orphaned Conversation+Participant rows (no message, no
        # hold) if this ran after they were flushed.
        await _deny_rate_limited_holds(session, actor_sub=actor_sub, sender_agent_id=initiator.id)

    now = _now()
    conversation = Conversation(
        type=conversation_type,
        state="active",
        created_by=initiator.id,
        expires_at=expires_at or (now + CONVERSATION_TTL[conversation_type]),
        owner_snapshot=owner_snapshot,
    )
    session.add(conversation)
    await session.flush()

    session.add(
        Participant(
            conversation_id=conversation.id,
            agent_id=initiator.id,
            role="owner",
            status="active",
            invited_by=None,
            joined_at=now,
        )
    )
    for target in targets:
        session.add(
            Participant(
                conversation_id=conversation.id,
                agent_id=target.id,
                role="member",
                status="invited",
                invited_by=initiator.id,
                joined_at=None,
            )
        )
    await session.flush()

    if risk_reason is not None:
        # Diverted opener (TECH-5389 PR2 §6, ratified decision 1): the
        # conversation is created anyway, with a service-synthesized safe
        # seq-1 marker (`conversation_opened`) taking the opener's slot;
        # the caller's actual content is diverted into a hold exactly like
        # any other high-risk post -- no denial. Hold rate limit was
        # already checked above, before the Conversation/Participant rows
        # were inserted.
        marker_payload = validate_payload("conversation_opened", schema_version, {})
        marker = Message(
            conversation_id=conversation.id,
            seq=1,
            sender_id=initiator.id,
            type="conversation_opened",
            schema_version=schema_version,
            payload=marker_payload,
        )
        session.add(marker)
        await session.flush()
        _audit(
            session,
            actor_sub=actor_sub,
            action="conversation.start",
            agent_id=initiator.id,
            conversation_id=conversation.id,
            detail={
                "type": conversation_type,
                "target_agent_ids": [str(t) for t in target_ids],
                "owner_snapshot": owner_snapshot,
            },
        )
        result = await _divert_high_risk_message(
            session,
            actor_sub=actor_sub,
            conversation=conversation,
            sender_agent_id=initiator.id,
            owner_sub_claim=owner_sub_claim,
            owner_sub_fallback=initiator.owner_sub,
            message_type=message_type,
            schema_version=schema_version,
            payload=payload,
            risk_reason=risk_reason,
            risk_scorer=risk_scorer,
            auto_approver=auto_approver,
        )
        _audit(
            session,
            actor_sub=actor_sub,
            action="message.post",
            agent_id=initiator.id,
            conversation_id=conversation.id,
            message_id=marker.id,
            detail={
                "seq": 1,
                "message_type": "conversation_opened",
                "system_synthesized": True,
                "hold_id": str(result.id) if isinstance(result, ApprovalHold) else None,
            },
        )
        if isinstance(result, Message):
            # Cleared inline: the real content posts as seq 2 in the SAME
            # transaction -- apply the same terminal-type state transition
            # post_message would apply for any other message insert.
            new_state = resulting_conversation_state(message_type)
            if new_state is not None:
                conversation.state = new_state
                _audit(
                    session,
                    actor_sub=actor_sub,
                    action="conversation.close",
                    agent_id=initiator.id,
                    conversation_id=conversation.id,
                    detail={"new_state": new_state, "via": message_type},
                )
        await session.commit()
        if isinstance(result, ApprovalHold):
            await _fire_approval_notifier(
                session, hold=result, conversation=conversation, sender=initiator, notifier=notifier
            )
        conversation.negotiated_schema_version = schema_version  # type: ignore[attr-defined]
        conversation.pending_hold = result if isinstance(result, ApprovalHold) else None  # type: ignore[attr-defined]
        return conversation

    message = Message(
        conversation_id=conversation.id,
        seq=1,
        sender_id=initiator.id,
        type=message_type,
        schema_version=schema_version,
        payload=payload,
    )
    session.add(message)
    await session.flush()

    _audit(
        session,
        actor_sub=actor_sub,
        action="conversation.start",
        agent_id=initiator.id,
        conversation_id=conversation.id,
        detail={
            "type": conversation_type,
            "target_agent_ids": [str(t) for t in target_ids],
            "owner_snapshot": owner_snapshot,
        },
    )
    _audit(
        session,
        actor_sub=actor_sub,
        action="message.post",
        agent_id=initiator.id,
        conversation_id=conversation.id,
        message_id=message.id,
        detail={"seq": 1, "message_type": message_type},
    )

    # A terminal type as the OPENING message must apply the same
    # state-transition post_message applies for every later message --
    # otherwise the conversation is left "active" forever while its only
    # message is already terminal. Calling resulting_conversation_state
    # directly (rather than a hardcoded terminal-type tuple) keeps this in
    # sync with post_message's own equivalent branch by construction --
    # "decline"'s all_non_owners_declined-gated cascade is the one type
    # this intentionally can't reach here (it needs the kwarg this call
    # omits), which is fine: at creation zero participants have declined
    # yet, so it would always resolve to a no-op transition regardless.
    new_state = resulting_conversation_state(message_type)
    if new_state is not None:
        conversation.state = new_state
        _audit(
            session,
            actor_sub=actor_sub,
            action="conversation.close",
            agent_id=initiator.id,
            conversation_id=conversation.id,
            detail={"new_state": new_state, "via": message_type},
        )

    await session.commit()
    # Not a mapped column (no migration/persistence needed for this,
    # unlike a new Conversation column): the negotiated version
    # is durably discoverable via this conversation's own seq-1
    # Message.schema_version (see _conversation_pinned_schema_version,
    # used by invite's re-check below), which already exists and is
    # append-only. This transient attribute exists only so the
    # SAME in-memory object this call returns can hand the negotiated
    # value straight to the tools-layer response without a second query
    # in the common case — it does not survive a fresh fetch of this
    # conversation from a later call.
    conversation.negotiated_schema_version = schema_version  # type: ignore[attr-defined]
    conversation.pending_hold = None  # type: ignore[attr-defined]
    return conversation


async def accept_invite(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
) -> Participant:
    """Flip the caller's participant status ``invited`` -> ``active``.

    Requires the caller to currently be an ``invited`` participant on this
    conversation; any other state (not a participant at all, already
    ``active``, ``left``, or ``declined``) raises the uniform
    ``AccessDeniedError`` — see the module docstring's audit contract for how
    the audit trail still distinguishes each cause. Also denied if the
    conversation has already reached a terminal state (``completed``/
    ``canceled`` — e.g. a terminal opening message closed it before this
    invite was accepted): accepting there would leave the caller
    permanently unable to post (``is_message_legal`` requires ``active``),
    a zombie state worse than the uniform denial. ``expired`` is
    deliberately NOT included here: unlike a terminal message's definitive
    close, expiry racing an in-flight accept is an ordinary, tolerated
    outcome (a participant may still accept an invite that expired after
    it was sent — they simply can't post afterward, same as any other
    already-``active`` member of an expired conversation).
    """
    conversation, participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=agent_id,
        conversation_id=conversation_id,
        required_status="invited",
    )
    if conversation.state in ("completed", "canceled"):
        await _deny(
            session,
            actor_sub=actor_sub,
            action=f"denied.wrong_state.{conversation.state}",
            agent_id=agent_id,
            conversation_id=conversation.id,
        )
    participant.status = "active"
    participant.joined_at = _now()
    _audit(
        session,
        actor_sub=actor_sub,
        action="participant.accept",
        agent_id=agent_id,
        conversation_id=conversation.id,
    )
    await session.commit()
    return participant


async def decline_invite(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
) -> None:
    """Set the caller's pending invite to ``declined``. No access is granted.

    Requires the caller to currently be ``invited``. Declining is terminal:
    it does not flip through ``active`` first, so no message content is
    ever disclosed to a declining caller (DESIGN.md §4: "Calling decline
    sets 'declined' directly: no access is ever granted").
    """
    conversation, participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=agent_id,
        conversation_id=conversation_id,
        required_status="invited",
    )
    participant.status = "declined"
    _audit(
        session,
        actor_sub=actor_sub,
        action="participant.decline_invite",
        agent_id=agent_id,
        conversation_id=conversation.id,
    )
    await session.commit()
    return None


async def _authorize_invite_owner_freeze(
    session: AsyncSession,
    *,
    actor_sub: str,
    inviter_agent_id: uuid.UUID,
    conversation: Conversation,
    target: Agent,
    ownership_client: OwnershipClient,
) -> None:
    """Reject an invite that would expand an ``internal``/``asymmetric``
    conversation's frozen owner set. No-op for ``open``.

    Fails closed (``denied.ownership_unverified``) on any lookup error,
    same posture as conversation-open admission.
    """
    if conversation.type == "open":
        return
    try:
        target_owners = frozenset(
            (await ownership_client.get_agent_owners(target.id)).get("owners") or []
        )
    except Exception as exc:
        logger.warning(
            "ownership lookup failed authorizing an invite: %s",
            type(exc).__name__,
            exc_info=True,
        )
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.ownership_unverified",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target.id)},
        )
    if not target_owners:
        # Fail closed, same posture as _authorize_conversation_open and
        # the risk scorer's ownership lookups: an empty owner set (a soft-failing
        # client returning {"owners": []} instead of raising) must not be
        # treated as "subset of everything" and silently admitted.
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.ownership_unverified",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target.id)},
        )
    snapshot_owners = frozenset((conversation.owner_snapshot or {}).get("owners") or [])
    if not target_owners <= snapshot_owners:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.owner_set_frozen",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target.id)},
        )


async def invite(
    session: AsyncSession,
    *,
    actor_sub: str,
    inviter_agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    target_agent_id: uuid.UUID,
    ownership_client: OwnershipClient,
    active_checker: ActiveChecker,
) -> Participant:
    """Add ``target_agent_id`` to a conversation as a new ``invited`` row.

    ``inviter_agent_id`` must currently be an ``active`` participant
    (``may_invite`` — v1: any active member, tightenable to owner-only
    later without a migration). The target must be a board-active agent,
    must not already have a participant row in ANY status (re-inviting a
    former member is out of scope for v1 — DESIGN.md does not define
    re-invite semantics, and a ``declined`` row in particular must never
    be overridable by another member, since decline is the consent
    mechanism), and — for ``internal``/``asymmetric`` conversations — must
    not introduce an owner outside the conversation's frozen
    ``owner_snapshot`` (the owner set is frozen at creation, not
    retroactively reconciled against prior messages when it would expand).
    ``open`` conversations have no ownership concept and skip this check.

    Also re-checks the target's declared
    ``[min_schema_version, max_schema_version]`` range against the version
    this conversation was already pinned to at ``start_conversation`` time
    (``_conversation_pinned_schema_version``), raising
    ``SchemaVersionMismatchError`` if the target can't correctly interpret
    it -- closing the gap where invite could otherwise admit a participant
    incompatible with every message already in the conversation.
    """
    conversation, inviter_participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=inviter_agent_id,
        conversation_id=conversation_id,
        required_status="active",
    )
    if not may_invite(inviter_participant.status):  # pragma: no cover — v1 always True here
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.invite_not_allowed",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
        )
    if conversation.state != "active":
        await _deny_bad_state(
            session,
            actor_sub=actor_sub,
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            current_state=conversation.state,
            message_type="invite",
        )
    target = await _find_agent_by_id(session, target_agent_id)
    if target is None or target.status != "active":
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_agent",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target_agent_id)},
        )
    if not await active_checker.is_active(target.sub):
        # TECH-5703: specific, not folded into the uniform denial above --
        # see AgentRetiredError's docstring.
        await _deny_agent_retired(
            session,
            actor_sub=actor_sub,
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            target_agent_id=target_agent_id,
        )
    # Re-check the new target against the version this
    # conversation was already pinned to at open time (see
    # _conversation_pinned_schema_version) -- without this, invite could
    # silently admit a participant whose own declared range excludes the
    # version every message in this conversation is already written in.
    pinned_version = await _conversation_pinned_schema_version(session, conversation.id)
    if not (target.min_schema_version <= pinned_version <= target.max_schema_version):
        # Audit field semantics note: this "required_min/
        # available_max" pairing is directionally accurate for the case
        # that's actually reachable today (pinned_version <
        # target.min_schema_version — the target requires newer than
        # what's pinned). The OTHER direction (pinned_version >
        # target.max_schema_version — the target is too OLD for the pin)
        # would instead want target.max_schema_version as the "available"
        # ceiling, not pinned_version itself; that direction is currently
        # unreachable (MAX_REGISTERED_SCHEMA_VERSION == 1, and the DB
        # CHECK constraint already enforces every registered
        # max_schema_version >= 1), so this isn't fixed here — revisit
        # once a second schema version makes that direction reachable.
        # The invariant this comment depends on (MAX_REGISTERED_SCHEMA_VERSION
        # == 1) is mechanically enforced at IMPORT time, not here —
        # see the module-level check near this constant's
        # import above. An in-function check at this exact spot would fire
        # only inside this one denial branch, on this one authorization
        # path, writing no audit row and no log for what would be a
        # security-relevant event; failing at import time instead means a
        # deploy with an unreviewed second schema version crash-loops at
        # startup, loudly, rather than silently mislabeling this one
        # audit row's fields the first time this branch is ever hit.
        await _deny_schema_version_mismatch(
            session,
            actor_sub=actor_sub,
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            participant_ids=[inviter_agent_id, target.id],
            required_min=target.min_schema_version,
            available_max=pinned_version,
        )
    await _authorize_invite_owner_freeze(
        session,
        actor_sub=actor_sub,
        inviter_agent_id=inviter_agent_id,
        conversation=conversation,
        target=target,
        ownership_client=ownership_client,
    )
    existing = await _find_participant(session, conversation.id, target.id)
    if existing is not None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.already_participant",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target_agent_id), "current_status": existing.status},
        )
    participant = Participant(
        conversation_id=conversation.id,
        agent_id=target.id,
        role="member",
        status="invited",
        invited_by=inviter_agent_id,
        joined_at=None,
    )
    session.add(participant)
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="participant.invite",
        agent_id=target.id,
        conversation_id=conversation.id,
        detail={"invited_by_agent_id": str(inviter_agent_id)},
    )
    await session.commit()
    return participant


async def leave(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
) -> None:
    """Leave a conversation: participant status -> ``left``, access revoked.

    Requires the caller to currently be ``active``. This is pure exit
    bookkeeping — it does not affect ``conversation.state`` or trigger the
    decline cascade. To decline a negotiation (with cascade-to-``canceled``
    semantics), post a ``decline`` message via ``post_message`` instead;
    that is the consent mechanism, ``leave`` is not (DESIGN.md §4/§6).
    """
    conversation, participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=agent_id,
        conversation_id=conversation_id,
        required_status="active",
    )
    participant.status = "left"
    _audit(
        session,
        actor_sub=actor_sub,
        action="participant.leave",
        agent_id=agent_id,
        conversation_id=conversation.id,
    )
    await session.commit()
    return None


async def _enforce_message_rate_limit(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation: Conversation,
) -> None:
    one_hour_ago = _now() - timedelta(hours=1)
    count = (
        await session.execute(
            select(func.count())
            .select_from(Message)
            .where(
                Message.conversation_id == conversation.id,
                Message.sender_id == sender_agent_id,
                Message.created_at > one_hour_ago,
            )
        )
    ).scalar_one()
    if count >= MAX_MESSAGES_PER_CONVERSATION_PER_HOUR:
        await _deny_rate_limited(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            limit_name="messages_per_conversation_per_hour",
            message=(
                f"rate_limited: at most {MAX_MESSAGES_PER_CONVERSATION_PER_HOUR} "
                "messages per conversation per hour"
            ),
        )


async def _enforce_sender_global_rate_limit(
    session: AsyncSession, *, actor_sub: str, sender_agent_id: uuid.UUID
) -> None:
    """Board-level defense-in-depth: cap a sender's TOTAL
    message volume across ALL conversations combined, not just within one.

    Additive to ``_enforce_message_rate_limit``, not a replacement — both
    are always checked. This one protects the board itself even if a
    counterparty's own agent-local rate limiter has a bug or is bypassed
    entirely by a compromised agent that doesn't run the standard
    negotiation library at all. See ``MAX_MESSAGES_PER_SENDER_PER_HOUR``'s
    definition for why 120 is the chosen ceiling.
    """
    one_hour_ago = _now() - timedelta(hours=1)
    count = (
        await session.execute(
            select(func.count())
            .select_from(Message)
            .where(
                Message.sender_id == sender_agent_id,
                Message.created_at > one_hour_ago,
            )
        )
    ).scalar_one()
    if count >= MAX_MESSAGES_PER_SENDER_PER_HOUR:
        await _deny_rate_limited(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=None,
            limit_name="messages_per_sender_per_hour",
            message=(
                f"rate_limited: at most {MAX_MESSAGES_PER_SENDER_PER_HOUR} "
                "messages per sender per hour, across all conversations"
            ),
        )


async def _all_non_owners_declined(session: AsyncSession, conversation_id: uuid.UUID) -> bool:
    """Whether every ``role='member'`` participant is currently ``declined``.

    A conversation with no members at all (shouldn't happen — every
    conversation is created with at least one target) never counts as
    "all declined". A member who is ``invited``/``active``/``left`` blocks
    the cascade: only an explicit ``decline`` counts.
    """
    member_statuses = (
        (
            await session.execute(
                select(Participant.status).where(
                    Participant.conversation_id == conversation_id,
                    Participant.role == "member",
                )
            )
        )
        .scalars()
        .all()
    )
    return bool(member_statuses) and all(status == "declined" for status in member_statuses)


async def _score_message_risk(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation_type: str,
    conversation_id: uuid.UUID | None,
    other_agent_ids: list[uuid.UUID],
    message_type: str,
    schema_version: int,
    ownership_client: OwnershipClient,
    risk_scorer: RiskScorer,
) -> str | None:
    """Run the configured ``plugins.RiskScorer`` for this message and
    return its verdict (DESIGN.md §9 Axis 2) as a ``risk_reason`` string, or
    ``None`` if the message is not high-risk (including a shared-sender
    bypass, which is audited but treated as low-risk).

    TECH-5389 PR2 (the pipeline): a ``high_risk=True`` verdict no longer
    denies -- it is returned to the caller (``post_message``/
    ``start_conversation``), which diverts the message to an
    ``approval_holds`` row instead of a ``denied.boundary_crossing`` denial
    (PR1's behavior). ``other_agent_ids`` is supplied by the caller rather
    than queried here — ``_check_boundary_crossing`` (below) queries
    current participants for ``post_message``; ``start_conversation``
    already has its target list in memory and calls this directly with no
    conversation row required to exist yet.

    A scorer-raised ``RiskScoringInfraError`` still fails CLOSED via a hard
    denial: ``denied.risk_unscored``, with ``exc.cause`` (e.g.
    ``"unknown_conversation_type"``, ``"ownership_unverified"``,
    ``"empty_owner_set"``) carried in the audit detail -- one action for
    every scorer infrastructure failure, ratified (PR1 kept two separate
    actions here). Rationale (owner, ratified): an ownership-service outage
    must not flood the human approval queue with unscorable holds -- only a
    GENUINE crossing verdict diverts; an unscorable one still denies. A
    verdict whose
    ``detail`` marks a shared-sender bypass emits the ``risk.shared_sender_bypass``
    bypass-observability audit row (renamed from PR1's still-unrenamed
    ``agent.boundary_check_bypassed_shared`` -- no backwards compatibility,
    ratified, see the module docstring's audit contract).
    """
    ctx = MessageRiskContext(
        conversation_type=conversation_type,
        conversation_id=conversation_id,
        sender_agent_id=sender_agent_id,
        other_agent_ids=other_agent_ids,
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
    )
    try:
        verdict = await risk_scorer.score(ctx)
    except RiskScoringInfraError as exc:
        logger.warning("risk scorer infrastructure failure: %s", exc.cause, exc_info=True)
        # TECH-5389 PR2 (ratified): every scorer infrastructure failure --
        # an unrecognized conversation_type, a lookup error, or an empty
        # owner set -- folds into ONE action, denied.risk_unscored, with
        # exc.cause in the detail distinguishing the specific failure. PR1
        # kept two separate actions here (denied.unknown_conversation_type /
        # denied.ownership_unverified); this PR unifies them so a genuine
        # high-risk verdict (which now diverts, never denies) can't be
        # confused with an unscorable one (which still hard-denies) by
        # anyone reading only the audited action name.
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.risk_unscored",
            agent_id=sender_agent_id,
            conversation_id=conversation_id,
            detail={"message_type": message_type, "cause": exc.cause},
        )

    if verdict.detail and verdict.detail.get("bypass") == "shared_sender":
        # Outside any try/except: staging this audit inside one risked a
        # session-state error being mislabeled as an infrastructure
        # failure. Staged, not committed: the caller (post_message) holds
        # a SELECT ... FOR UPDATE lock on the Conversation row to
        # serialize seq assignment, and committing here would release that
        # lock mid-request, letting two concurrent shared senders race on
        # seq. This audit row is persisted by the caller's own enclosing
        # commit along with the rest of the operation, exactly like every
        # other non-`_deny` audit call in this module.
        _audit(
            session,
            actor_sub=actor_sub,
            action="risk.shared_sender_bypass",
            agent_id=sender_agent_id,
            conversation_id=conversation_id,
            detail={"message_type": message_type},
        )
        return None

    if verdict.high_risk:
        return verdict.reason
    return None


async def _enforce_message_type_accepted(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    other_agents: Sequence[tuple[uuid.UUID, list[str]]],
    message_type: str,
) -> None:
    """Enforce that every other participant/target has declared
    ``message_type`` in their own ``accepted_types``.

    This is a capability gate, not a trust boundary: whether a given
    agent's own implementation actually handles a message type is a fact
    about that specific running agent, unrelated to who sent it — so
    unlike ``_score_message_risk``, this check is universal and
    applies even to ``internal`` same-owner traffic. Checked per-recipient
    (each of ``other_agents`` individually), not aggregated, since
    ``accepted_types`` is a per-agent fact, not a per-owner one.

    Takes already-resolved ``(agent_id, accepted_types)`` pairs rather than
    IDs to look up itself: every caller already has this data from a query
    that's fail-closed by construction (``_resolve_targets`` for
    ``start_conversation``; the ``participants JOIN agents`` in
    ``_check_boundary_crossing``, which can't miss a row given
    ``participants.agent_id``'s FK to ``agents.id``) — so there is no
    "agent ID present but its accepted_types row missing" case to guard
    against here, and no second round-trip to fetch what the caller
    already loaded.

    Sorted by agent ID before iterating so which recipient's denial gets
    audited is deterministic across runs, not an artifact of query-plan
    ordering, when more than one recipient would reject.

    Detail intentionally omits which recipient rejected it or their
    ``accepted_types``, mirroring ``denied.boundary_crossing``'s posture of
    not leaking a target's declared state to the sender.
    """
    for _agent_id, accepted in sorted(other_agents, key=lambda pair: str(pair[0])):
        if message_type not in accepted:
            await _deny(
                session,
                actor_sub=actor_sub,
                action="denied.message_type_not_accepted",
                agent_id=sender_agent_id,
                conversation_id=conversation_id,
                detail={"message_type": message_type},
            )
            # Explicit return, not relying solely on _deny's NoReturn
            # contract -- a future refactor that weakens _deny must not
            # silently let this loop keep iterating past a recorded denial.
            return


async def _check_boundary_crossing(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation: Conversation,
    message_type: str,
    schema_version: int,
    ownership_client: OwnershipClient,
    risk_scorer: RiskScorer,
) -> str | None:
    """``_score_message_risk`` (+ the universal ``accepted_types``
    capability gate) for an existing conversation row — queries current
    (``active``/``invited``) participants for the other side rather than
    requiring the caller to already know them.

    Single join query (participants + agents), not two separate
    round-trips: covers both ``_score_message_risk``'s
    active-or-invited "other" set (queried unconditionally now, unlike the
    old asymmetric-and-unsafe-only gating this replaced — boundary
    crossing itself only needs an ownership lookup for the narrower case,
    but ``_enforce_message_type_accepted`` needs participant data on every
    send) and the capability gate's narrower active-only set below.

    The capability gate deliberately excludes ``invited`` (not yet
    accepted) participants, unlike the boundary-crossing set: an invite
    must not retroactively block existing ACTIVE members from sending
    message types they were already exchanging before the invite, just
    because the new invitee hasn't declared support for them yet. Once an
    invitee accepts and becomes ``active``, the very next send is checked
    against them normally — this only defers the check, it doesn't skip
    it forever. (Boundary-crossing's own "other" set has a different,
    already-established reason to include ``invited``: keeping it
    consistent with the owner-set-freeze snapshot taken at invite time --
    see that function's own docstring.)

    Accepted trade-off: this query now runs on every ``post_message`` call,
    including ones where the capability gate turns out to be a no-op (an
    ``open``/``internal`` conversation with every participant already
    accepting everything). Skipping it in that case would mean re-deriving
    "is this skippable" some other way -- which needs participant data
    anyway -- so it isn't actually a savings; the query is the cheapest
    correct way to answer "does anyone here need checking."
    """
    rows = (
        await session.execute(
            select(Participant.agent_id, Participant.status, Agent.accepted_types)
            .join(Agent, Agent.id == Participant.agent_id)
            .where(
                Participant.conversation_id == conversation.id,
                Participant.agent_id != sender_agent_id,
                Participant.status.in_(("active", "invited")),
            )
        )
    ).all()
    other_ids = [agent_id for agent_id, _status, _accepted in rows]
    capability_others = [
        (agent_id, accepted) for agent_id, status, accepted in rows if status == "active"
    ]
    await _enforce_message_type_accepted(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation_id=conversation.id,
        other_agents=capability_others,
        message_type=message_type,
    )
    return await _score_message_risk(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation_type=conversation.type,
        conversation_id=conversation.id,
        other_agent_ids=other_ids,
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
        risk_scorer=risk_scorer,
    )


# Message types restricted to a specific sender participant role
# ``task_cancel`` is the creator-side
# close (today's decline-cascade only counts role='member', no creator
# path — this is that path), ``task_decline`` is the assignee's consent/
# refusal mechanism, mirroring ``update_task``'s old assignee-only
# ``declined`` restriction. Every other message type is unrestricted by
# sender role (any active participant may post it).
_MESSAGE_TYPE_SENDER_ROLES: dict[str, str] = {
    "task_cancel": "owner",
    "task_decline": "member",
}


async def _require_message_sender_role(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation_id: uuid.UUID | None,
    message_type: str,
    sender_role: str,
) -> None:
    """Deny if ``message_type`` is sender-role-restricted and the sender's
    participant role doesn't match. No-op for every unrestricted type."""
    required_role = _MESSAGE_TYPE_SENDER_ROLES.get(message_type)
    if required_role is not None and sender_role != required_role:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.wrong_sender_role",
            agent_id=sender_agent_id,
            conversation_id=conversation_id,
            detail={"message_type": message_type, "required_role": required_role},
        )


# --- Approval-holds pipeline (TECH-5389 PR2) ------------------------------------


async def _insert_message_for_hold(
    session: AsyncSession, *, conversation: Conversation, hold: ApprovalHold
) -> tuple[Message, int]:
    """Insert ``hold``'s pinned type/schema_version/payload as the next
    message in ``conversation``, assigning ``seq`` under the caller's
    already-held conversation lock. Shared by the inline auto-clear path
    (``_divert_high_risk_message``) and the human decide-endpoint's
    approve path (``main.py``) — "approve and post atomically" is one
    reusable function, per the plan doc §3."""
    next_seq = (
        await session.execute(
            select(func.coalesce(func.max(Message.seq), 0)).where(
                Message.conversation_id == conversation.id
            )
        )
    ).scalar_one() + 1
    message = Message(
        conversation_id=conversation.id,
        seq=next_seq,
        sender_id=hold.sender_agent_id,
        type=hold.message_type,
        schema_version=hold.schema_version,
        payload=hold.payload,
    )
    session.add(message)
    await session.flush()
    hold.message_id = message.id
    return message, next_seq


async def _divert_high_risk_message(
    session: AsyncSession,
    *,
    actor_sub: str,
    conversation: Conversation,
    sender_agent_id: uuid.UUID,
    owner_sub_claim: str | None,
    owner_sub_fallback: str,
    message_type: str,
    schema_version: int,
    payload: dict[str, Any],
    risk_reason: str,
    risk_scorer: RiskScorer,
    auto_approver: AutoApprover,
) -> Message | ApprovalHold:
    """Create the ``approval_holds`` row for a high-risk verdict, run the
    injected ``AutoApprover`` inline, and either post the message
    atomically (cleared) or escalate to ``pending_human`` (v1's
    ``EscalateAllAutoApprover``: always).

    Caller MUST have already run every other gate (membership, state,
    sender role, payload validation, capability gate, hold rate limit) and
    hold the conversation's row lock (``post_message``'s
    ``SELECT ... FOR UPDATE``, or ``start_conversation``'s not-yet-committed
    insert transaction) so seq assignment on the cleared path is race-safe.
    Returns the inserted ``Message`` (cleared; carries a transient
    ``auto_approved_hold_id`` attribute for the tools layer, mirroring
    ``start_conversation``'s existing ``negotiated_schema_version``
    transient-attribute convention) or the ``ApprovalHold`` itself
    (escalated — the caller commits and then fires the notifier
    post-commit, per ``_fire_approval_notifier``'s docstring).
    """
    now = _now()
    scorer_name = _risk_scorer_name(risk_scorer)
    # Snapshot, not a live join: owner_sub_claim is the sender's verified
    # claim from the request that created this hold; owner_sub_fallback is
    # the (currently-frozen) agents.owner_sub, used only when the claim is
    # absent. See ApprovalHold's docstring / plan doc §15.4.
    # `is not None`, not `or` (Argus round-1 BLOCKING catch): an explicit
    # empty-string claim is present, not absent, and must not silently
    # fall back to a different identity.
    hold_owner_sub = owner_sub_claim if owner_sub_claim is not None else owner_sub_fallback
    hold = ApprovalHold(
        conversation_id=conversation.id,
        sender_agent_id=sender_agent_id,
        owner_sub=hold_owner_sub,
        message_type=message_type,
        schema_version=schema_version,
        payload=payload,
        risk_reason=risk_reason,
        risk_scorer=scorer_name,
        status="pending_auto",
        expires_at=now + APPROVAL_HOLD_TTL,
    )
    session.add(hold)
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="approval.hold",
        agent_id=sender_agent_id,
        conversation_id=conversation.id,
        detail={
            "hold_id": str(hold.id),
            "risk_reason": risk_reason,
            "risk_scorer": scorer_name,
            "message_type": message_type,
        },
    )

    approver_name = _auto_approver_name(auto_approver)
    hold.auto_approver = approver_name
    ctx = HoldContext(
        hold_id=hold.id,
        conversation_id=conversation.id,
        conversation_type=conversation.type,
        sender_agent_id=sender_agent_id,
        owner_sub=hold_owner_sub,
        message_type=message_type,
        schema_version=schema_version,
        payload=payload,
        risk_reason=risk_reason,
    )
    decision = await auto_approver.review(ctx)
    if decision.cleared:
        message, next_seq = await _insert_message_for_hold(
            session, conversation=conversation, hold=hold
        )
        hold.status = "auto_approved"
        hold.auto_decision = "cleared"
        hold.auto_decided_at = _now()
        system_actor = f"system:auto_approver/{approver_name}"
        _audit(
            session,
            actor_sub=system_actor,
            action="approval.auto_approve",
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            message_id=message.id,
            detail={"hold_id": str(hold.id)},
        )
        _audit(
            session,
            actor_sub=system_actor,
            action="message.post",
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            message_id=message.id,
            detail={"seq": next_seq, "message_type": message_type, "hold_id": str(hold.id)},
        )
        message.auto_approved_hold_id = hold.id  # type: ignore[attr-defined]
        return message

    hold.status = "pending_human"
    hold.auto_decision = "escalated"
    hold.auto_decided_at = _now()
    _audit(
        session,
        actor_sub=actor_sub,
        action="approval.escalate",
        agent_id=sender_agent_id,
        conversation_id=conversation.id,
        detail={"hold_id": str(hold.id), "auto_approver": approver_name},
    )
    return hold


async def _fire_approval_notifier(
    session: AsyncSession,
    *,
    hold: ApprovalHold,
    conversation: Conversation,
    sender: Agent,
    notifier: ApprovalNotifier,
) -> None:
    """Best-effort, post-commit notification that ``hold`` entered
    ``pending_human`` (DESIGN.md/plan doc §4). Caller MUST have already
    committed the transaction that created/escalated ``hold`` — this
    function starts a FRESH short transaction of its own for the
    ``approval.notify_failed`` audit row on failure, since the main
    commit already succeeded and must not be affected by a notifier
    outage. Never FAILS the request: a notifier failure never rolls back
    or raises past this function. It IS awaited inline before the tool
    response returns (Argus round-1 catch corrected the "never delays"
    claim this docstring used to make), so ``APPROVAL_NOTIFIER=webhook``
    can add up to ``_WEBHOOK_TIMEOUT_SECONDS`` of latency to a high-risk
    send -- ``GET /approvals/pending`` is still the source of truth;
    notification is an accelerant, not a guarantee, and delay is the
    accepted cost of keeping this synchronous rather than a background
    task with its own session-lifecycle concerns.
    """
    notification = ApprovalNotification(
        hold_id=str(hold.id),
        conversation_id=str(conversation.id),
        conversation_type=conversation.type,
        sender_agent_id=str(sender.id),
        sender_display_name=sender.display_name,
        owner_sub=hold.owner_sub,
        owner_email=sender.owner_email,
        message_type=hold.message_type,
        risk_reason=hold.risk_reason,
        expires_at=_iso(hold.expires_at) or "",
        created_at=_iso(hold.created_at) or "",
    )
    try:
        await notifier.notify_escalated(notification)
    except asyncio.CancelledError:
        # BaseException, not Exception -- already excluded from the guard
        # below under Python's actual exception hierarchy, but re-raised
        # explicitly (Argus round-1 catch) so this stays correct even if
        # the `except Exception` below is ever accidentally broadened to
        # `except BaseException`.
        raise
    except Exception as exc:
        logger.warning(
            "approval notifier failed for hold %s: %s", hold.id, type(exc).__name__, exc_info=True
        )
        _audit(
            session,
            actor_sub=sender.sub,
            action="approval.notify_failed",
            agent_id=sender.id,
            conversation_id=conversation.id,
            detail={
                "hold_id": str(hold.id),
                "notifier": _notifier_name(notifier),
                "error_type": type(exc).__name__,
            },
        )
        await session.commit()


async def audit_denied_approval_requires_interactive(
    session: AsyncSession, *, actor_sub: str
) -> None:
    """Audit + commit ``denied.approval_requires_interactive`` -- the hard
    interactive-token-only gate on ``main.py``'s decide/list-pending HTTP
    endpoints. Unlike every other denial in this module, the caller here
    (``main.py``, a non-MCP ``mcp.custom_route`` handler) has no board
    ``Agent``/conversation context at all -- there is nothing to raise
    (the HTTP handler decides its own 403 response), only an audit row to
    persist so the denial is still recorded per this module's "every
    denial is audited" invariant.
    """
    _audit(session, actor_sub=actor_sub, action="denied.approval_requires_interactive")
    await session.commit()


async def get_hold_status(
    session: AsyncSession,
    *,
    actor_sub: str,
    caller_agent_id: uuid.UUID,
    hold_id: uuid.UUID,
) -> dict[str, Any]:
    """Sender-only read of one hold's status (``comms_get_hold_status``).

    The caller's resolved agent must equal the hold's ``sender_agent_id``;
    an unknown ``hold_id`` and someone-else's hold raise the identical
    uniform ``AccessDeniedError`` (audit distinguishes ``denied.unknown_hold``
    / ``denied.hold_not_sender``). Applies lazy TTL expiry on touch.
    """
    hold = await _find_hold(session, hold_id)
    if hold is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_hold",
            agent_id=await _fk_safe_agent_id(session, caller_agent_id),
            detail={"attempted_hold_id": str(hold_id)},
        )
    if hold.sender_agent_id != caller_agent_id:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.hold_not_sender",
            agent_id=caller_agent_id,
            conversation_id=hold.conversation_id,
            detail={"attempted_hold_id": str(hold_id)},
        )
    _maybe_expire_hold(session, actor_sub, hold)
    result = _hold_dict(hold)
    if hold.message_id is not None:
        seq = (
            await session.execute(select(Message.seq).where(Message.id == hold.message_id))
        ).scalar_one_or_none()
        if seq is not None:
            result["message_seq"] = seq
    await session.commit()
    return result


async def list_pending_approval_holds(
    session: AsyncSession, *, owner_sub: str, limit: int = 50
) -> dict[str, Any]:
    """``GET /approvals/pending`` (main.py, non-MCP, interactive+owner-gated):
    every ``pending_human`` hold whose OWN ``owner_sub`` snapshot (§15.4 --
    NOT a live join to the sender agent's ``agents`` row) matches the
    caller, oldest first, INCLUDING the held payload -- this is the one
    place a human reads the actual held text (the notifier deliberately
    carries only a pointer; see ``plugins.ApprovalNotification``).
    """
    limit = max(1, min(limit, 200))
    stmt = (
        select(ApprovalHold, Agent)
        .join(Agent, Agent.id == ApprovalHold.sender_agent_id)
        .where(ApprovalHold.owner_sub == owner_sub, ApprovalHold.status == "pending_human")
        .order_by(ApprovalHold.created_at.asc())
        .limit(limit + 1)
    )
    rows = (await session.execute(stmt)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    holds: list[dict[str, Any]] = []
    for hold, sender in rows:
        _maybe_expire_hold(session, owner_sub, hold)
        if hold.status != "pending_human":
            continue
        entry = _hold_dict(hold)
        entry["sender_agent_id"] = str(sender.id)
        entry["sender_display_name"] = sender.display_name
        entry["message_type"] = hold.message_type
        entry["payload"] = hold.payload
        holds.append(entry)
    await session.commit()
    # Argus round-1 catch: `has_more` was computed from the raw row count
    # before lazy expiry ran. If every fetched row expires during the loop
    # above, that left {"holds": [], "has_more": True} -- and this API has
    # no cursor/offset to actually page past this call, so that combination
    # would trap a naive polling client into retrying forever for a "next
    # page" that doesn't exist. An empty page is never followed by more.
    # Known accepted residual (Argus round-3): if the OLDEST of the
    # overfetched rows expires here but a NEWER one within the same
    # overfetch window is still pending, this forces has_more=False and
    # transiently hides that still-pending hold from this call -- it
    # self-heals on the caller's next poll once the expired row is gone.
    has_more = has_more and len(holds) > 0
    return {"holds": holds, "has_more": has_more}


async def decide_hold(
    session: AsyncSession,
    *,
    approver_sub: str,
    hold_id: uuid.UUID,
    decision: str,
    reason: str | None,
) -> dict[str, Any]:
    """``POST /approvals/{hold_id}/decide`` (main.py, non-MCP,
    interactive+owner-gated). ``decision`` is ``"approve"`` or ``"reject"``.

    Raises ``AccessDeniedError`` (uniform, ``denied.unknown_hold`` /
    ``denied.hold_not_owner``) if the hold doesn't exist or the caller's
    verified sub doesn't match the hold's own ``owner_sub`` snapshot
    (§15.4 -- NOT a live join to the sender agent's ``agents`` row);
    ``HoldExpiredError`` if lazy expiry fires on this touch;
    ``HoldAwaitingAutoReviewError`` if the hold is still ``pending_auto``
    (unreachable in v1, specified for a future async auto-approver);
    ``HoldAlreadyDecidedError`` if it's already ``approved``/``rejected``/
    ``auto_approved``. Approve additionally raises
    ``InvalidConversationStateError`` (audited ``denied.bad_state``) if the
    conversation is no longer ``active`` -- the hold stays ``pending_human``
    in that case (the human can still reject with a reason).

    The risk scorer is deliberately NOT re-run here — the human decision
    IS the override. Approve DOES re-run the ``accepted_types`` capability
    gate against currently-active participants (closing the gap where a
    participant added after the hold was created never had a chance to
    reject the type).
    """
    hold = await _find_hold(session, hold_id, for_update=True)
    if hold is None:
        await _deny(
            session,
            actor_sub=approver_sub,
            action="denied.unknown_hold",
            detail={"attempted_hold_id": str(hold_id)},
        )
    if hold.owner_sub != approver_sub:
        await _deny(
            session,
            actor_sub=approver_sub,
            action="denied.hold_not_owner",
            conversation_id=hold.conversation_id,
            detail={"attempted_hold_id": str(hold_id)},
        )
    _maybe_expire_hold(session, approver_sub, hold)
    if hold.status == "expired":
        await session.commit()
        raise HoldExpiredError
    if hold.status == "pending_auto":
        await session.commit()
        raise HoldAwaitingAutoReviewError
    if hold.status != "pending_human":
        await session.commit()
        raise HoldAlreadyDecidedError(hold.status)

    if decision == "reject":
        hold.status = "rejected"
        hold.decided_by_sub = approver_sub
        hold.decided_at = _now()
        hold.decision_reason = reason
        _audit(
            session,
            actor_sub=approver_sub,
            action="approval.reject",
            agent_id=hold.sender_agent_id,
            conversation_id=hold.conversation_id,
            detail={"hold_id": str(hold_id), "has_reason": reason is not None},
        )
        await session.commit()
        return _hold_dict(hold)

    conversation = await _find_conversation(session, hold.conversation_id, for_update=True)
    if conversation is None:
        raise RuntimeError(f"invariant violation: hold {hold_id} references a missing conversation")
    _maybe_expire(session, approver_sub, conversation)
    if conversation.state != "active":
        await _deny_bad_state(
            session,
            actor_sub=approver_sub,
            agent_id=hold.sender_agent_id,
            conversation_id=conversation.id,
            current_state=conversation.state,
            message_type=hold.message_type,
        )

    rows = (
        await session.execute(
            select(Participant.agent_id, Agent.accepted_types)
            .join(Agent, Agent.id == Participant.agent_id)
            .where(
                Participant.conversation_id == conversation.id,
                Participant.agent_id != hold.sender_agent_id,
                Participant.status == "active",
            )
        )
    ).all()
    await _enforce_message_type_accepted(
        session,
        actor_sub=approver_sub,
        sender_agent_id=hold.sender_agent_id,
        conversation_id=conversation.id,
        other_agents=[(agent_id, accepted) for agent_id, accepted in rows],
        message_type=hold.message_type,
    )

    message, next_seq = await _insert_message_for_hold(
        session, conversation=conversation, hold=hold
    )
    hold.status = "approved"
    hold.decided_by_sub = approver_sub
    hold.decided_at = _now()
    hold.decision_reason = reason
    _audit(
        session,
        actor_sub=approver_sub,
        action="approval.approve",
        agent_id=hold.sender_agent_id,
        conversation_id=conversation.id,
        message_id=message.id,
        detail={"hold_id": str(hold_id), "has_reason": reason is not None},
    )
    _audit(
        session,
        actor_sub=approver_sub,
        action="message.post",
        agent_id=hold.sender_agent_id,
        conversation_id=conversation.id,
        message_id=message.id,
        detail={"seq": next_seq, "message_type": hold.message_type, "hold_id": str(hold_id)},
    )
    new_state = resulting_conversation_state(hold.message_type)
    if new_state is not None:
        conversation.state = new_state
        _audit(
            session,
            actor_sub=approver_sub,
            action="conversation.close",
            agent_id=hold.sender_agent_id,
            conversation_id=conversation.id,
            detail={"new_state": new_state, "via": hold.message_type},
        )
    await session.commit()
    return _hold_dict(hold)


async def post_message(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    message_type: str,
    payload: dict[str, Any],
    ownership_client: OwnershipClient,
    risk_scorer: RiskScorer,
    auto_approver: AutoApprover,
    notifier: ApprovalNotifier,
    schema_version: int = 1,
    owner_sub_claim: str | None = None,
) -> Message | ApprovalHold:
    """Append a schema-validated message; apply state-machine side effects.

    Requires ``sender_agent_id`` to be a board-active agent (uniform denial
    otherwise) AND a currently-``active`` participant on ``conversation_id``
    (same uniform denial, identical whether the conversation doesn't
    exist, the sender was never invited, is still ``invited``, or has
    ``left``/``declined`` — DESIGN.md §4/§8's anti-enumeration rule).

    ``seq`` is assigned under ``SELECT ... FOR UPDATE`` on the conversation
    row (acquired while loading the participant), so concurrent posters to
    the same conversation serialize and every seq is gapless and race-safe.

    Boundary-crossing (DESIGN.md §9 Axis 2, ``_check_boundary_crossing``,
    scored by the injected ``risk_scorer``) is checked right after payload
    validation, so an unregistered ``(message_type, schema_version)`` pair
    is denied via ``_deny_bad_schema``'s audit trail first, rather than
    scored at all: an ``asymmetric`` conversation diverts a barrier-
    sensitive message (e.g. ``note``) that would cross an ownership
    boundary for the sender into an ``approval_holds`` row, audited as
    ``approval.hold`` (or, if the scorer itself fails, denied and audited
    as ``denied.risk_unscored``).

    Side effects: ``confirm``/``task_complete`` transition the conversation
    to ``completed``; ``decline`` sets the sender's OWN participant status
    to ``declined`` and, only once every non-owner participant is now
    ``declined`` (``_all_non_owners_declined``), transitions the
    conversation to ``canceled``; ``task_decline``/``task_cancel``
    transition the conversation to ``canceled`` unconditionally (each is
    sender-role-restricted to a single role, so one post is always
    decisive — see ``_require_message_sender_role``).

    Raises ``RateLimitExceededError`` past the per-sender-per-conversation
    hourly cap OR the board-level per-sender-across-all-conversations hourly
    cap (``_enforce_sender_global_rate_limit``, board-level defense-in-depth
    against a sender spraying messages across many conversations to evade
    the per-conversation cap); ``InvalidConversationStateError`` if
    ``message_type`` is not legal in the conversation's current state
    (state-machine violation, including after lazy expiry);
    ``AccessDeniedError`` (uniform) if ``message_type`` is sender-role-
    restricted and the sender's role doesn't match;
    ``schemas.PayloadValidationError`` if ``payload`` fails schema
    validation, or if a ``needs_clarification``'s ``about_seq`` does not
    reference an existing prior message.
    """
    sender = await _require_active_agent(session, actor_sub=actor_sub, agent_id=sender_agent_id)
    conversation, participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=sender_agent_id,
        conversation_id=conversation_id,
        required_status="active",
        for_update=True,
    )

    # An agent may never post the service-synthesized marker type directly
    # (TECH-5389 PR2 §6) -- checked early, before rate limits, so forging
    # an attempt doesn't consume rate-limit budget.
    await _deny_if_system_message_type(
        session,
        actor_sub=actor_sub,
        agent_id=sender_agent_id,
        conversation_id=conversation.id,
        message_type=message_type,
    )

    await _enforce_message_rate_limit(
        session, actor_sub=actor_sub, sender_agent_id=sender_agent_id, conversation=conversation
    )
    await _enforce_sender_global_rate_limit(
        session, actor_sub=actor_sub, sender_agent_id=sender_agent_id
    )

    if not is_message_legal(conversation.state, message_type):
        await _deny_bad_state(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            current_state=conversation.state,
            message_type=message_type,
        )

    await _require_message_sender_role(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation_id=conversation.id,
        message_type=message_type,
        sender_role=participant.role,
    )

    try:
        validated = validate_payload(message_type, schema_version, payload)
    except PayloadValidationError as exc:
        await _deny_bad_schema(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            message_type=message_type,
            exc=exc,
        )

    # Validated above, not after: an unregistered (message_type,
    # schema_version) pair must go through _deny_bad_schema's audit trail
    # above, not reach the risk scorer at all -- DESIGN.md §8's "every
    # denial is audited" invariant.
    risk_reason = await _check_boundary_crossing(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation=conversation,
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
        risk_scorer=risk_scorer,
    )

    if risk_reason is not None:
        # Divert-not-deny (TECH-5389 PR2): a genuine high-risk verdict no
        # longer denies -- it is held for approval instead. The hold-
        # creation rate limit was never part of the divert-don't-deny
        # reversal, so it's still enforced here, before the hold itself
        # is created.
        await _deny_rate_limited_holds(
            session, actor_sub=actor_sub, sender_agent_id=sender_agent_id
        )
        result = await _divert_high_risk_message(
            session,
            actor_sub=actor_sub,
            conversation=conversation,
            sender_agent_id=sender_agent_id,
            owner_sub_claim=owner_sub_claim,
            owner_sub_fallback=sender.owner_sub,
            message_type=message_type,
            schema_version=schema_version,
            payload=validated,
            risk_reason=risk_reason,
            risk_scorer=risk_scorer,
            auto_approver=auto_approver,
        )
        await session.commit()
        if isinstance(result, ApprovalHold):
            await _fire_approval_notifier(
                session, hold=result, conversation=conversation, sender=sender, notifier=notifier
            )
        return result

    next_seq = (
        await session.execute(
            select(func.coalesce(func.max(Message.seq), 0)).where(
                Message.conversation_id == conversation.id
            )
        )
    ).scalar_one() + 1

    if message_type == "needs_clarification":
        about_seq = int(validated["about_seq"])
        if about_seq >= next_seq:
            await _deny_bad_schema(
                session,
                actor_sub=actor_sub,
                agent_id=sender_agent_id,
                conversation_id=conversation.id,
                message_type=message_type,
                exc=PayloadValidationError(
                    f"payload failed schema validation: about_seq: {about_seq} does not "
                    "reference a prior message in this conversation"
                ),
            )

    message = Message(
        conversation_id=conversation.id,
        seq=next_seq,
        sender_id=sender_agent_id,
        type=message_type,
        schema_version=schema_version,
        payload=validated,
    )
    session.add(message)
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="message.post",
        agent_id=sender_agent_id,
        conversation_id=conversation.id,
        message_id=message.id,
        detail={"seq": next_seq, "message_type": message_type},
    )

    if message_type == "decline":
        participant.status = "declined"
        _audit(
            session,
            actor_sub=actor_sub,
            action="participant.decline",
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            detail={"reason": validated.get("reason")},
        )
        all_declined = await _all_non_owners_declined(session, conversation.id)
        new_state = resulting_conversation_state("decline", all_non_owners_declined=all_declined)
        if new_state is not None:
            conversation.state = new_state
            _audit(
                session,
                actor_sub=actor_sub,
                action="conversation.close",
                agent_id=sender_agent_id,
                conversation_id=conversation.id,
                detail={"new_state": new_state, "via": "decline"},
            )
    elif message_type in ("confirm", "task_complete", "task_decline", "task_cancel"):
        new_state = resulting_conversation_state(message_type)
        if new_state is not None:
            conversation.state = new_state
            _audit(
                session,
                actor_sub=actor_sub,
                action="conversation.close",
                agent_id=sender_agent_id,
                conversation_id=conversation.id,
                detail={"new_state": new_state, "via": message_type},
            )

    await session.commit()
    return message


async def get_conversation(
    session: AsyncSession,
    *,
    actor_sub: str,
    caller_agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    since_seq: int = 0,
) -> dict[str, Any]:
    """Combined read: conversation + participants + messages since ``since_seq``.

    An ``invited`` (not yet accepted) caller gets METADATA ONLY: the
    returned dict has ``"invited": True``, ``"has_more": False``, and an
    empty ``"messages"`` list — never any message content — and the
    caller's ``last_read_seq`` is NOT advanced (there is nothing to mark
    read). An ``active`` caller gets up to
    ``MAX_MESSAGES_PER_GET_CONVERSATION`` messages from ``since_seq``
    onward. ``"has_more"`` signals a truncated page; continue with
    ``since_seq=page_max_seq`` (the max seq actually IN this page), NOT
    ``since_seq=last_read_seq`` (TECH-5377 follow-up) -- ``last_read_seq``
    is the caller's persisted read cursor, which can already be ahead of
    a page returned for a `since_seq` below it (e.g. a deliberate re-read
    of older history): re-calling with the persisted cursor in that case
    would skip everything between this page's actual end and that cursor.
    ``last_read_seq`` itself is advanced to the max seq actually returned
    in THIS page (only if any messages were returned, and only forward --
    never regresses on an older-history re-read). A caller who is not a
    participant, or who previously left/declined, gets the uniform
    ``AccessDeniedError`` — identical to a non-existent conversation
    (DESIGN.md §4/§8).
    """
    conversation, participant = await _load_participant_for_read(
        session,
        actor_sub=actor_sub,
        agent_id=caller_agent_id,
        conversation_id=conversation_id,
    )

    part_rows = (
        await session.execute(
            select(Participant, Agent)
            .join(Agent, Agent.id == Participant.agent_id)
            .where(Participant.conversation_id == conversation.id)
            .order_by(Agent.sub)
        )
    ).all()
    participants_view = [
        {
            "agent_id": str(a.id),
            "sub": a.sub,
            "display_name": a.display_name,
            "role": p.role,
            "status": p.status,
            "invited_by": str(p.invited_by) if p.invited_by else None,
        }
        for p, a in part_rows
    ]

    if participant.status == "invited":
        await session.commit()
        return {
            "conversation": _conversation_dict(conversation),
            "participants": participants_view,
            "messages": [],
            "invited": True,
            "has_more": False,
            "invited_by": str(participant.invited_by) if participant.invited_by else None,
        }

    msg_rows = (
        await session.execute(
            select(Message, Agent.sub)
            .join(Agent, Agent.id == Message.sender_id)
            .where(Message.conversation_id == conversation.id, Message.seq > since_seq)
            .order_by(Message.seq)
            .limit(MAX_MESSAGES_PER_GET_CONVERSATION + 1)
        )
    ).all()
    # Fetch one extra row to detect truncation, then trim -- same pattern as
    # list_agents (TECH-5377).
    has_more = len(msg_rows) > MAX_MESSAGES_PER_GET_CONVERSATION
    msg_rows = msg_rows[:MAX_MESSAGES_PER_GET_CONVERSATION]
    # The max seq actually IN this trimmed page -- distinct from
    # last_read_seq below. Argus round-1 BLOCKING catch: `since_seq` can be
    # below the caller's persisted cursor (a deliberate re-read of older
    # history), in which case this page's own max seq is LESS than that
    # cursor. Continuation must use THIS value, not last_read_seq, or a
    # caller re-calling with the (unchanged, still-ahead) persisted cursor
    # would silently skip every message between page_max_seq and that
    # cursor. Falls back to `since_seq` itself on an empty page, so
    # `since_seq=page_max_seq` is always a safe (no-op) re-call.
    page_max_seq = max((m.seq for m, _ in msg_rows), default=since_seq)
    # last_read_seq only ever advances forward, never regresses on an
    # older-history re-read (page_max_seq can be below the existing cursor
    # in exactly that case). `msg_rows and` is load-bearing, not redundant
    # (Argus round-2 BLOCKING catch): on an EMPTY page, page_max_seq falls
    # back to since_seq -- if a caller passes a since_seq ahead of their
    # own persisted cursor (e.g. since_seq=10, last_read_seq=3) with no
    # messages actually returned, `10 > 3` would otherwise fire and commit
    # last_read_seq=10, permanently hiding seqs 4-10 from inbox's `HAVING
    # max(seq) > last_read_seq` for messages that were never delivered to
    # this caller. The docstring's own contract ("only if any messages
    # were returned") requires this guard.
    if msg_rows and page_max_seq > participant.last_read_seq:
        participant.last_read_seq = page_max_seq
    await session.commit()

    return {
        "conversation": _conversation_dict(conversation),
        "participants": participants_view,
        "messages": [_message_dict(m, sender_sub) for m, sender_sub in msg_rows],
        "invited": False,
        # Page-scoped, capped at MAX_MESSAGES_PER_GET_CONVERSATION -- NOT
        # the conversation's true total message count (Argus round-1
        # SUGGESTION: the prior name was misleading for direct service
        # callers even though the tools layer already renamed it to
        # `messages_returned`).
        "messages_in_page": len(msg_rows),
        "has_more": has_more,
        "page_max_seq": page_max_seq,
        "last_read_seq": participant.last_read_seq,
    }


async def inbox(session: AsyncSession, *, caller_agent_id: uuid.UUID) -> dict[str, Any]:
    """Unread-first inbox for the caller's agent: unread + pending invites.

    ``unread``: every conversation where the caller is an ``active``
    participant and ``max(seq) > last_read_seq`` — regardless of
    conversation state, so a completion/cancelation message still
    surfaces once. ``pending_invites``: every conversation where the
    caller has a pending ``invited`` row (metadata only — no message
    peek, matching ``get_conversation``'s invited-caller behavior).

    Explicit empty state: always returns the same keys, even when both
    lists are empty, so a tools layer can render "nothing needs your
    attention" rather than reasoning about an ambiguous bare empty list
    (AXI convention, DESIGN.md §7).

    Each list is capped (``MAX_UNREAD_CONVERSATIONS_PER_INBOX``,
    ``MAX_PENDING_INVITES_PER_INBOX``; TECH-5377) with a corresponding
    ``"*_has_more"`` flag -- previously unbounded, so an agent behind on
    many conversations at once had no ceiling on a single inbox response.
    ``unread`` is ordered by most-recent activity first, so truncation
    drops the stalest conversations, not the freshest. ``total_count`` is
    always a TRUE count across both lists, never a page-capped length
    (Argus round-1 BLOCKING catch: computing it from the two, possibly
    page-capped, list lengths would silently report page size instead of
    the real backlog once either list is truncated -- the same
    established pattern ``list_agents`` already uses for its own
    ``total_count``). Each half is only a real ``COUNT(*)`` query when
    its own list was actually truncated (``*_has_more``); otherwise the
    list's own length already IS the true count, and a second round trip
    would return the same number for a real cost (Argus round-2
    SUGGESTION).

    Read-only with no denial path for a valid ``caller_agent_id`` (no
    audit rows) — the write-through mutation side of lazy expiry
    (``_maybe_expire``, which flips and commits ``conversation.state``) is
    intentionally NOT applied here (it would require touching every
    returned conversation individually); that happens on whichever
    read/write path next touches a given conversation directly
    (``get_conversation``, ``post_message``, etc.). The read-only
    *projection* side IS applied, though: ``_conversation_dict`` (used for
    both ``unread`` and ``pending_invites`` below) still reports
    ``"state": "expired"`` for a past-``expires_at`` row, since that's a
    pure display computation with no DB write.
    """
    unread_rows = (
        await session.execute(
            select(
                Conversation,
                Participant.last_read_seq,
                func.max(Message.seq).label("max_seq"),
                func.count(Message.id)
                .filter(Message.seq > Participant.last_read_seq)
                .label("unread"),
            )
            .join(Participant, Participant.conversation_id == Conversation.id)
            .join(Message, Message.conversation_id == Conversation.id)
            .where(Participant.agent_id == caller_agent_id, Participant.status == "active")
            .group_by(Conversation.id, Participant.last_read_seq)
            .having(func.max(Message.seq) > Participant.last_read_seq)
            .order_by(func.max(Message.created_at).desc())
            .limit(MAX_UNREAD_CONVERSATIONS_PER_INBOX + 1)
        )
    ).all()
    unread_has_more = len(unread_rows) > MAX_UNREAD_CONVERSATIONS_PER_INBOX
    unread_rows = unread_rows[:MAX_UNREAD_CONVERSATIONS_PER_INBOX]

    # True unread-conversation count, unaffected by the page cap above --
    # same GROUP BY/HAVING as the paginated query, wrapped and counted
    # rather than limited (Argus round-1 BLOCKING catch).
    # Only worth a second round trip when the page was actually truncated
    # (Argus round-2 SUGGESTION): when it wasn't, the true count IS the
    # returned list's length, and DESIGN.md §7 already treats "a second
    # SELECT COUNT(*) replaying the same filter predicates" as a real cost
    # worth avoiding elsewhere (why comms_list_conversations omits
    # total_count entirely) -- inbox shouldn't pay it unconditionally on
    # every call when it only matters in the truncated case.
    if unread_has_more:
        unread_total_stmt = select(func.count()).select_from(
            select(Conversation.id)
            .join(Participant, Participant.conversation_id == Conversation.id)
            .join(Message, Message.conversation_id == Conversation.id)
            .where(Participant.agent_id == caller_agent_id, Participant.status == "active")
            .group_by(Conversation.id, Participant.last_read_seq)
            .having(func.max(Message.seq) > Participant.last_read_seq)
            .subquery()
        )
        unread_total = (await session.execute(unread_total_stmt)).scalar_one()
    else:
        unread_total = len(unread_rows)

    # Fetch every unread conversation's latest message + sender sub in a
    # single round trip (instead of one SELECT per conversation in a Python
    # loop): join Message/Agent against the exact (conversation_id, max_seq)
    # pairs already computed above via a composite-tuple IN.
    latest_by_conversation_id: dict[uuid.UUID, tuple[Message, str]] = {}
    conversation_seq_pairs = [
        (conversation.id, max_seq) for conversation, _, max_seq, _ in unread_rows
    ]
    if conversation_seq_pairs:
        latest_rows = (
            await session.execute(
                select(Message, Agent.sub)
                .join(Agent, Agent.id == Message.sender_id)
                .where(tuple_(Message.conversation_id, Message.seq).in_(conversation_seq_pairs))
            )
        ).all()
        latest_by_conversation_id = {
            message.conversation_id: (message, sender_sub) for message, sender_sub in latest_rows
        }

    unread: list[dict[str, Any]] = []
    for conversation, last_read_seq, _max_seq, unread_count in unread_rows:
        latest, sender_sub = latest_by_conversation_id[conversation.id]
        unread.append(
            {
                **_conversation_dict(conversation),
                "unread_count": unread_count,
                "last_read_seq": last_read_seq,
                "latest_message": _message_dict(latest, sender_sub),
            }
        )

    pending_rows = (
        await session.execute(
            select(Conversation, Participant)
            .join(Participant, Participant.conversation_id == Conversation.id)
            .where(Participant.agent_id == caller_agent_id, Participant.status == "invited")
            .order_by(Participant.invited_at.desc())
            .limit(MAX_PENDING_INVITES_PER_INBOX + 1)
        )
    ).all()
    pending_has_more = len(pending_rows) > MAX_PENDING_INVITES_PER_INBOX
    pending_rows = pending_rows[:MAX_PENDING_INVITES_PER_INBOX]

    if pending_has_more:
        pending_total = (
            await session.execute(
                select(func.count())
                .select_from(Participant)
                .where(Participant.agent_id == caller_agent_id, Participant.status == "invited")
            )
        ).scalar_one()
    else:
        pending_total = len(pending_rows)

    pending_invites = [
        {
            **_conversation_dict(conversation),
            "invited_by": str(p.invited_by) if p.invited_by else None,
            "invited_at": _iso(p.invited_at),
        }
        for conversation, p in pending_rows
    ]

    return {
        "unread": unread,
        "unread_has_more": unread_has_more,
        "pending_invites": pending_invites,
        "pending_invites_has_more": pending_has_more,
        "total_count": unread_total + pending_total,
    }


# --- Ownership lookups -------


class OwnershipClient(Protocol):
    """Resolves a board agent's verified owner set — the seam for ``may_assign``.

    The real implementation calls the platform's ownership lookup
    (not yet built; tracked as a follow-up). Tests fake
    this protocol directly. Every caller of ``get_agent_owners`` MUST fail
    closed on any exception — never treat a lookup error as "no match" vs.
    "match", since either silently loosens or tightens admission depending
    on what the caller assumes. ``agents.owner_sub``/``owner_email`` must
    NEVER be read directly for this decision (single-valued columns a
    shared agent's row cannot faithfully represent) — this protocol is
    the only sanctioned path.

    Implementations must not hold a live DB session open across their own
    ``get_agent_owners`` call: the eventual real implementation makes an
    external HTTP call to the ownership service, and holding a checked-out
    ``AsyncSession`` (and its connection-pool slot) for the duration of
    that round trip risks pool exhaustion under concurrency
    (``db.py``'s ``pool_size``/``max_overflow`` are small). Construct a
    future HTTP-backed implementation independently of any request's
    session, not inside the ``async with get_session_factory()()`` block
    that owns it — unlike the interim ``AgentTableOwnershipClient`` below,
    which is a same-transaction DB read and has no such constraint.
    """

    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        """Return ``{"is_shared": bool, "owners": list[str]}`` for ``agent_id``.

        Raise on any lookup failure/timeout/empty result — the caller
        treats every exception as fail-closed (``denied.ownership_unverified``).
        """
        ...


class AgentTableOwnershipClient:
    """Interim ``OwnershipClient`` until the platform's real ownership
    endpoint ships.

    Wraps the existing ``agents`` columns: ``owner_sub`` as a
    single-element owner set, and ``is_shared`` from the DB. ``owner_sub``
    is frozen at first registration (see ``register_agent``) and never
    changes again. ``is_shared`` is frozen against an agent's own
    re-registration for the same reason, but -- unlike ``owner_sub`` -- IS
    mutable via the separate ``comms:admin``-gated ``set_agent_shared``
    admin override (see that function's docstring). Both remain safe as
    authorization inputs: ``owner_sub`` because it truly never changes, and
    ``is_shared`` because its only mutation path is itself gated on the
    same elevated scope required to escalate it at first registration --
    there is no path by which an unprivileged caller can move this value.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        agent = await _find_agent_by_id(self._session, agent_id)
        if agent is None:
            raise LookupError(f"unknown agent {agent_id}")
        return {"is_shared": agent.is_shared, "owners": [agent.owner_sub]}


# --- Ownership client seam (TECH-5396 open question 1) ------------------------

OWNERSHIP_CLIENT_ENV_VAR = "OWNERSHIP_CLIENT"
DEFAULT_OWNERSHIP_CLIENT = "agent_table"

# A factory takes the CURRENT request's session and returns an OwnershipClient --
# unlike plugins.py's other three seams (RiskScorer/AutoApprover/ApprovalNotifier),
# which are stateless and resolved once for the process's lifetime, the default
# OwnershipClient implementation needs a same-transaction DB read on every call (see
# AgentTableOwnershipClient's own docstring on why session lifetime matters). A
# live-resolving plugin (e.g. an HTTP-backed registry client) simply ignores the
# session argument and returns its own already-constructed, reusable instance.
OwnershipClientFactory = Callable[[AsyncSession], "OwnershipClient"]


def _agent_table_ownership_client_factory() -> OwnershipClientFactory:
    return AgentTableOwnershipClient


OWNERSHIP_CLIENTS: dict[str, Callable[[], OwnershipClientFactory]] = {
    DEFAULT_OWNERSHIP_CLIENT: _agent_table_ownership_client_factory,
}

_ownership_client_factory: OwnershipClientFactory | None = None


def get_ownership_client_factory() -> OwnershipClientFactory:
    """Return the process-wide configured ``OwnershipClientFactory``, resolving it
    on first use (mirrors ``plugins.get_risk_scorer``'s lazy-singleton pattern). A
    resolution failure is not cached -- the next call retries against the same
    (still-broken) configuration.

    Call the returned factory with the current request's session on every use:
    ``get_ownership_client_factory()(session)``. Resolved via ``OWNERSHIP_CLIENT``
    (registry name or ``pkg.module:factory`` import path, same convention as every
    other pluggable seam), default ``agent_table`` (``AgentTableOwnershipClient``,
    reading the frozen ``agents.owner_sub`` column). A live-resolving consumer (e.g.
    a consumer's own ownership registry) can point this at the SAME source its
    ``AGENT_TOKEN_VERIFIERS`` plugin already resolves ``owner_sub`` from, closing the
    gap where a re-minted/reassigned owner fixes approval *routing* immediately but
    boundary *scoring* keeps reading the frozen column until this seam is configured.
    """
    global _ownership_client_factory
    if _ownership_client_factory is None:
        _ownership_client_factory = resolve_plugin(
            OWNERSHIP_CLIENT_ENV_VAR, OWNERSHIP_CLIENTS, DEFAULT_OWNERSHIP_CLIENT
        )
    return _ownership_client_factory


def validate_ownership_client_configuration() -> None:
    """Fail fast at process start if ``OWNERSHIP_CLIENT`` doesn't resolve -- same
    posture as ``plugins.validate_configuration``'s three seams, called separately
    from ``main._cli()`` because this seam's registry lives here, not in
    ``plugins.py`` (which must stay import-free of ``service.py``).

    Also checks the resolved value is itself callable: unlike the other three
    seams (registry value = an implementation instance), this seam's registry
    value is a FACTORY-of-factories -- ``resolve_plugin`` returns whatever the
    configured factory function returns, which for this seam must be a second
    callable (``Callable[[AsyncSession], OwnershipClient]``), not an instance.
    This guards against a factory that constructs successfully but returns a
    non-callable object (e.g. ``return object()``) -- that would otherwise
    resolve "successfully" here and only fail with a bare ``TypeError`` on the
    first live request. It does NOT catch every misconfiguration shape: e.g.
    ``OWNERSHIP_CLIENT=pkg.module:MyOwnershipClient`` (a class expecting a
    session, not a factory-of-factories) already fails inside
    ``resolve_plugin_name`` with an unprefixed ``TypeError`` before this check
    ever runs, and a callable with the wrong signature (e.g.
    ``lambda session, extra: None``) passes this check and only fails at
    request time.
    """
    global _ownership_client_factory
    factory = get_ownership_client_factory()
    if not callable(factory):
        # Undo the cache-on-resolve in get_ownership_client_factory() before
        # raising: otherwise a caller that catches this RuntimeError (a test
        # harness, a health-check wrapper) leaves the non-callable value
        # cached, and every subsequent get_ownership_client_factory() call
        # returns it without re-resolving -- silently subverting fail-fast.
        _ownership_client_factory = None
        raise RuntimeError(
            f"{OWNERSHIP_CLIENT_ENV_VAR}: resolved value of type "
            f"{type(factory).__name__!r} is not callable -- expected a factory "
            "of shape Callable[[AsyncSession], OwnershipClient]"
        )


def may_assign(creator_owners: AbstractSet[str], assignee_owners: AbstractSet[str]) -> bool:
    """Symmetric verified owner-set intersection — ``owners(a) ∩ owners(b) ≠ ∅``.

    Originally the ``add_task`` admission policy; reused verbatim
    by ``_pairwise_admitted`` as the ``asymmetric`` conversation-type
    predicate. ``AbstractSet`` (not ``set``) so callers
    may pass either mutable ``set``s or the ``frozenset``s the ownership-
    lookup helpers use.

    Degenerates to an exact same-owner check for two non-shared agents
    (each owner set is a singleton); generalizes symmetrically once a
    shared agent's verified owner set has more than one entry, so a shared
    agent may be either the requester (report-back direction) or the
    target.
    """
    return not creator_owners.isdisjoint(assignee_owners)


# --- Ownership reconciliation (TECH-5593 item 4) -----------------------------

DEFAULT_RECONCILIATION_BATCH_SIZE = 500
# Hard ceiling on `limit`, independent of whatever a caller passes in
# (Argus round-1 BLOCKING catch): Postgres treats a negative LIMIT as
# LIMIT ALL, so an unclamped caller-supplied limit (e.g. an admin route
# that only rejects non-int query params) could load the entire agents
# table and fire one OwnershipClient.get_agent_owners call per row.
# `reconcile_agent_ownership` clamps unconditionally, regardless of what
# validation its own caller does or doesn't perform.
MAX_RECONCILIATION_BATCH_SIZE = 5000


async def reconcile_agent_ownership(
    session: AsyncSession,
    *,
    ownership_client: OwnershipClient,
    limit: int = DEFAULT_RECONCILIATION_BATCH_SIZE,
) -> dict[str, int]:
    """Bounded-staleness reconciliation for agents ``write_through_ownership``
    never reaches (TECH-5593 item 4): an agent that makes no further
    verified request after registration never fires the write-through path
    in ``providers.comms._resolve_caller_agent``, so its cached
    ``owner_sub`` can drift forever once its real owner is reassigned in
    the registry. This function is the out-of-band backstop — call it
    periodically (an in-process scheduled task, or an admin-triggered
    endpoint; this repo has no scheduler today, see ``main.py``'s
    ``_cli`` and the TECH-5378 comment on ``_maybe_expire`` for the same
    "no scheduler exists" gap elsewhere) against the SAME ``OwnershipClient``
    ``AGENT_TOKEN_VERIFIERS``-side registry verifiers resolve ``owner_sub``
    from (``get_ownership_client_factory``'s own docstring already
    recommends pointing this seam at that source).

    Only reconciles ``owner_sub`` -- ``OwnershipClient`` resolves verified
    owner IDENTIFIERS for the risk-scoring/task-admission seam
    (``may_assign``), not email addresses, so it has no ``owner_email`` to
    reconcile against. An idle agent's ``owner_email`` only converges the
    next time it makes a verified request, via ``write_through_ownership``.

    Excludes ``is_shared=True`` agents at the SQL level (counted separately
    in ``skipped_shared`` via a cheap, unbounded ``COUNT(*)`` -- Argus
    round-1 BLOCKING catch: an earlier version filtered them out in Python
    AFTER the ``LIMIT``, so a cluster of shared agents sorting early in
    cursor order could consume entire batches without any of them being
    actionable, starving real reconciliation): ``OwnershipClient.get_agent_owners``
    returns a SET of owners for a shared agent by design (its docstring),
    which does not map onto ``agents.owner_sub``'s single-valued column --
    deciding which of N owners a single cache column should hold is a
    design question this function does not answer on its own.

    Fails soft PER AGENT, not closed for the whole run (deliberately unlike
    every admission-decision caller of ``OwnershipClient`` elsewhere in
    this module, which fails closed by necessity -- a stale cache row here
    is this function's whole reason for existing, not a security decision
    made under uncertainty): one agent's lookup raising, timing out, or
    resolving to zero/multiple owners is counted in ``errors`` and skipped,
    so it cannot abort reconciling every other agent in the same run.

    Processes at most ``limit`` board-active, non-shared agents per call
    (clamped to ``[1, MAX_RECONCILIATION_BATCH_SIZE]`` regardless of what
    the caller passes), ordered by ``owner_reconciled_at`` ascending (NULLS
    FIRST), THEN ``id`` ascending, rather than ``bound_at`` -- and stamps
    ``owner_reconciled_at = now()`` on EVERY agent actually looked up,
    whether or not its ``owner_sub`` changed (Argus round-1 BLOCKING catch:
    ordering by ``bound_at`` alone, a value this function never writes,
    meant every call re-processed the identical oldest-N rows forever and
    any agent past the first page was never reconciled at all). A
    just-checked agent sorts to the back of the queue on the next call, so
    repeated calls make real forward progress through the whole table.

    ``id`` (Argus round-2 SUGGESTION, treated as load-bearing): every agent
    processed in ONE call shares the identical ``now`` value stamped below
    (read once per call, not once per row), so once a tie group on
    ``owner_reconciled_at`` grows past ``limit``, ordering by that column
    alone has no defined tiebreak -- Postgres could return a different
    arbitrary subset of the SAME tied group on each subsequent call,
    silently reintroducing this cursor's own starvation problem for
    exactly the rows that already share a timestamp. ``id`` carries no
    semantic meaning; it only needs to be a stable, total order, which a
    primary key already is.

    Returns ``{"checked", "updated", "skipped_shared", "errors"}`` --
    ``checked`` counts only non-shared agents actually looked up THIS CALL
    (bounded by ``limit``). ``skipped_shared`` is deliberately NOT
    batch-scoped the same way: it's the total count of board-active
    ``is_shared=True`` agents in the WHOLE table at call time, independent
    of ``limit`` -- a per-batch count would always read ``0`` now that
    shared agents are excluded before ``LIMIT`` (see above) and would
    convey nothing useful; this field's purpose is now purely "how many
    shared agents exist that this function structurally cannot reconcile,"
    not "how many did this call skip."
    """
    limit = max(1, min(limit, MAX_RECONCILIATION_BATCH_SIZE))
    skipped_shared = (
        await session.execute(
            select(func.count())
            .select_from(Agent)
            .where(Agent.status == "active", Agent.is_shared.is_(True))
        )
    ).scalar_one()
    agents = (
        (
            await session.execute(
                select(Agent)
                .where(Agent.status == "active", Agent.is_shared.is_(False))
                .order_by(Agent.owner_reconciled_at.asc().nulls_first(), Agent.id.asc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    checked = 0
    updated = 0
    errors = 0
    now = _now()
    for agent in agents:
        checked += 1
        agent.owner_reconciled_at = now
        try:
            info = await ownership_client.get_agent_owners(agent.id)
            owners = info.get("owners") or []
        except Exception:
            logger.warning("ownership reconciliation lookup failed for agent_id=%s", agent.id)
            errors += 1
            continue
        if len(owners) != 1:
            # Zero or multiple owners for a NON-shared agent is itself a
            # registry/board data inconsistency worth flagging -- not
            # something to guess an answer for.
            logger.warning(
                "ownership reconciliation got %d owners for non-shared agent_id=%s",
                len(owners),
                agent.id,
            )
            errors += 1
            continue
        current_owner_sub = owners[0]
        if current_owner_sub != agent.owner_sub:
            _audit(
                session,
                actor_sub=agent.sub,
                action="agent.ownership_reconciled",
                agent_id=agent.id,
                detail={"owner_sub": {"old": agent.owner_sub, "new": current_owner_sub}},
            )
            agent.owner_sub = current_owner_sub
            updated += 1
    await session.commit()
    return {
        "checked": checked,
        "updated": updated,
        "skipped_shared": skipped_shared,
        "errors": errors,
    }


__all__ = [
    "APPROVAL_HOLD_TTL",
    "CONVERSATION_TTL",
    "DEFAULT_OWNERSHIP_CLIENT",
    "DEFAULT_RECONCILIATION_BATCH_SIZE",
    "MAX_APPROVAL_HOLDS_PER_HOUR",
    "MAX_CONVERSATION_STARTS_PER_HOUR",
    "MAX_LOOKUP_EMAIL_LENGTH",
    "MAX_MESSAGES_PER_CONVERSATION_PER_HOUR",
    "MAX_RECONCILIATION_BATCH_SIZE",
    "OWNERSHIP_CLIENTS",
    "OWNERSHIP_CLIENT_ENV_VAR",
    "AgentTableOwnershipClient",
    "OwnershipClient",
    "OwnershipClientFactory",
    "accept_invite",
    "audit_denied_approval_requires_interactive",
    "decide_hold",
    "decline_invite",
    "get_agent_by_sub",
    "get_conversation",
    "get_hold_status",
    "get_ownership_client_factory",
    "inbox",
    "invite",
    "leave",
    "list_agents",
    "list_conversations",
    "list_pending_approval_holds",
    "lookup_agent_by_email",
    "may_assign",
    "may_invite",
    "post_message",
    "reconcile_agent_ownership",
    "register_agent",
    "start_conversation",
    "validate_ownership_client_configuration",
    "write_through_ownership",
]
