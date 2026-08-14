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
``denied.rate_limited``, ``denied.ownership_unverified`` (an ownership
lookup failed — fail closed), ``denied.not_same_owner``/
``denied.no_owner_overlap`` (conversation-open admission failed for
``internal``/``asymmetric``), ``denied.owner_set_frozen`` (an invite would
expand a frozen owner set), ``denied.unknown_conversation_type`` (a
conversation row's ``type`` isn't in ``schemas.CONVERSATION_TYPES`` — a
migration/data-integrity gap, e.g. a legacy pre-rename row — distinct from
an actual ownership-boundary crossing), ``denied.boundary_crossing``/
``denied.wrong_sender_role`` (DESIGN.md §9 Axis 2's per-message checks), and
``denied.message_type_not_accepted`` (a recipient hasn't declared
``message_type`` in their own ``accepted_types`` — a capability gate, not a
trust boundary, so it applies universally, even to ``internal`` traffic
that boundary-crossing itself always allows).
"""

from __future__ import annotations

import itertools
import logging
import uuid
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn, Protocol

from sqlalchemy import func, literal, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import (
    AccessDeniedError,
    InvalidConversationStateError,
    RateLimitExceededError,
    SchemaVersionMismatchError,
    UnknownConversationTypeError,
)
from models import Agent, AuditLog, Conversation, Message, Participant
from schemas import (
    CONVERSATION_TYPES,
    MAX_ACCEPTED_TYPE_LENGTH,
    MAX_ACCEPTED_TYPES,
    MAX_DISPLAY_NAME_LENGTH,
    MESSAGE_TYPES,
    PayloadValidationError,
    is_boundary_safe,
    validate_payload,
)
from state_machine import (
    is_boundary_crossing_safe,
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

# Per-sender rate limits, counted from the messages/conversations tables
# directly (no Redis — DESIGN.md §5: "No Redis until it matters").
MAX_MESSAGES_PER_CONVERSATION_PER_HOUR = 30
MAX_CONVERSATION_STARTS_PER_HOUR = 10
# Board-level, cross-conversation defense-in-depth (TECH-5160): the two
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
    participant_ids: list[uuid.UUID],
    common_floor: int,
    common_ceiling: int,
) -> NoReturn:
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.schema_version_mismatch",
        agent_id=agent_id,
        detail={
            "participant_agent_ids": [str(p) for p in participant_ids],
            "required_min": common_floor,
            "common_max": common_ceiling,
        },
    )
    await session.commit()
    raise SchemaVersionMismatchError(
        "schema_version_mismatch: no wire schema version is supported by every "
        f"participant (highest mutually-supported max is {common_ceiling}, but "
        f"at least one participant requires a version >= {common_floor})"
    )


async def _negotiate_schema_version(
    session: AsyncSession, *, actor_sub: str, initiator: Agent, targets: list[Agent]
) -> int:
    """Compute the highest wire schema version every participant mutually
    supports, refusing to open the conversation if no such version exists.

    TECH-5160 capability negotiation, evaluated once at ``start_conversation``
    (a fresh participant set is only ever assembled here, not on every later
    message — a message's own per-message ``schema_version`` field is the
    sibling agent-local defense-in-depth layer's concern, not this one's).

    Combined refuse-vs-degrade rule: ``negotiated_version`` is the lowest
    common denominator (``min`` of every participant's declared
    ``max_schema_version``). If that value is still >= every participant's
    declared ``min_schema_version`` (i.e. it falls inside every
    participant's ``[min, max]`` range), the conversation degrades to it.
    Otherwise there is no version at all that every participant can
    correctly interpret, and opening is refused entirely
    (``SchemaVersionMismatchError``).
    """
    participants = [initiator, *targets]
    negotiated_version = min(p.max_schema_version for p in participants)
    required_floor = max(p.min_schema_version for p in participants)
    if required_floor > negotiated_version:
        await _deny_schema_version_mismatch(
            session,
            actor_sub=actor_sub,
            agent_id=initiator.id,
            participant_ids=[p.id for p in participants],
            common_floor=required_floor,
            common_ceiling=negotiated_version,
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
) -> dict[uuid.UUID, frozenset[str]]:
    """Resolve each agent's verified owner set, one lookup at a time.

    Sequential, not concurrent (e.g. via ``asyncio.gather``):
    ``AgentTableOwnershipClient.get_agent_owners`` shares this call's
    ``AsyncSession``, which SQLAlchemy's ``AsyncSession`` does not support
    across concurrent coroutines.

    Callers MUST fail closed on any exception raised here (see
    ``OwnershipClient``'s docstring) — this helper does not catch.
    """
    owner_sets: dict[uuid.UUID, frozenset[str]] = {}
    for agent in agents:
        info = await ownership_client.get_agent_owners(agent.id)
        owner_sets[agent.id] = frozenset(info.get("owners") or [])
    return owner_sets


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
) -> Agent:
    """Idempotently create or re-bind the board ``Agent`` row for ``sub``.

    SECURITY: ``owner_sub``/``owner_email`` MUST be sourced by the caller
    (the MCP tools layer) from verified OAuth token claims — DESIGN.md §4:
    "Owner identity ... is always derived from verified token claims: never
    accepted as a parameter." This function performs NO token
    verification of its own; it persists exactly what it is given. Never
    call it with owner_sub/owner_email taken from untrusted tool arguments.

    Idempotent: calling again with the same ``sub`` updates
    ``display_name``/``accepted_types``/``owner_email`` in place (unique on
    ``agents.sub``) rather than creating a duplicate row, and re-marks the
    agent ``active`` + refreshes ``bound_at``. ``owner_sub`` is the
    exception: it is frozen at first registration and never overwritten by
    a later call, even one presenting a different ``owner_sub`` — see the
    inline comment on the re-registration branch below: once
    ``add_task``'s ``may_assign`` started reading ``owner_sub`` as an
    admission-decision input, allowing a re-register to change it became a
    forgeable privilege-escalation path, not just an unmodeled edge case.

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

    ``min_schema_version``/``max_schema_version`` (TECH-5160, both default
    to ``1``, today's only version) declare the wire-schema version range
    this agent's own code can correctly interpret. ``start_conversation``
    negotiates down to the highest version every participant in a new
    conversation mutually supports, refusing to open at all if no version
    is inside every participant's range — see
    ``service._negotiate_schema_version``. Raises ``ValueError`` if
    ``min_schema_version > max_schema_version`` (checked alongside the
    other input-validation failures above, not as an authorization
    decision).
    """
    if min_schema_version > max_schema_version:
        raise ValueError("min_schema_version must be <= max_schema_version")
    sub = sub.strip()
    if not sub:
        raise ValueError("sub must be non-empty")
    display_name = display_name.strip()
    if not display_name:
        raise ValueError("display_name must be non-empty")
    if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
        raise ValueError(f"display_name exceeds {MAX_DISPLAY_NAME_LENGTH} characters")
    # Cap check runs FIRST, before computing unknown_types (Argus round 1,
    # security): the old order let a caller submit an arbitrarily large
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
    # than UnknownConversationTypeError. Splitting these (Argus round 1)
    # avoids the confusing prior message "... (got unknown: [])" for an
    # empty list, which named zero unknown values while still claiming
    # something was unknown.
    if not accepted_types:
        raise ValueError("accepted_types must be non-empty")
    # Per-entry length cap (Argus round 2, security): the count cap above
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
    if existing is None:
        agent = Agent(
            sub=sub,
            owner_sub=owner_sub,
            owner_email=owner_email,
            display_name=display_name,
            accepted_types=normalized_types,
            status="active",
            bound_at=now,
            min_schema_version=min_schema_version,
            max_schema_version=max_schema_version,
        )
        session.add(agent)
    else:
        agent = existing
        # owner_sub is deliberately NOT overwritten on re-registration —
        # it is now read by
        # AgentTableOwnershipClient as the input to may_assign's admission
        # decision, and agent-jwt extra claims (including owner_sub) are
        # caller-supplied and unverified (providers/comms.py). Allowing a
        # re-register to overwrite it would let a caller forge a victim's
        # owner_sub, re-register their own agent under it, and be admitted
        # into that victim's tasks. Freezing it at first registration closes
        # that path; owner_email is NOT similarly frozen. Unlike owner_sub,
        # owner_email now does carry admission-decision weight (as of
        # TECH-5159's lookup_agent_by_email, which resolves callers by this
        # field), but it remains a caller-supplied, unverified claim rather
        # than a proven mailbox ownership fact -- see lookup_agent_by_email's
        # docstring for the resulting trust-model gap this re-write permits.
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
        detail={"created": created},
    )
    await session.commit()
    return agent


async def list_agents(
    session: AsyncSession,
    *,
    limit: int = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Paginated board directory, ordered by ``sub`` (keyset pagination).

    ``cursor`` is the ``sub`` of the last agent from a previous page;
    passing it back returns the next page. Not authorization-gated at this
    layer (internal trust domain, DESIGN.md §10 flags directory enumeration
    as acceptable today and as the seam that tightens once external
    counterparties exist) — no denial paths, so no audit rows.
    """
    limit = max(1, min(limit, 200))
    stmt = select(Agent).order_by(Agent.sub).limit(limit + 1)
    if cursor:
        stmt = stmt.where(Agent.sub > cursor)
    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    total_count = (await session.execute(select(func.count()).select_from(Agent))).scalar_one()
    return {
        "agents": [_agent_public(a) for a in rows],
        "total_count": total_count,
        "has_more": has_more,
        "next_cursor": rows[-1].sub if has_more and rows else None,
    }


MAX_LOOKUP_EMAIL_LENGTH = 254  # RFC 5321 4.5.3.1.3 total-address cap


async def lookup_agent_by_email(
    session: AsyncSession, *, owner_email: str
) -> dict[str, Any] | None:
    """Directory lookup: is ``owner_email`` bound to a board-active agent?

    This realizes the "handshake registry" concept -- answering "does this
    email belong to a registered EA" -- directly on the existing ``Agent``
    table rather than a separate store: ``owner_email``/``sub`` already
    carry exactly what a caller needs (which email, which board-wide
    identity), so there is nothing left to duplicate. Formerly its own
    module (``registry/directory.py``, TECH-4945) inside the negotiation
    library; folded in here per TECH-5159 once each EA agent started
    holding its own calendar and that library stopped needing a copy of
    this lookup for itself -- the comms board is the one place every agent
    can already reach, so this is where the lookup belongs. See
    ``docs/DESIGN.md`` §10 for this endpoint's anti-enumeration posture.

    Comparison is case-insensitive (``func.lower``) since OAuth-sourced
    email claims are not guaranteed to arrive in one canonical case, but
    does not attempt the fuller NFKC-normalization ``rh_maiea.canonical``
    applies -- this service has no dependency on that library (by design,
    per TECH-5158: the negotiation library and the comms board stay
    decoupled) and plain case-folding covers the realistic input space for
    values sourced from Okta/Google identity claims. Python's ``str.lower()``
    (used on the input) and Postgres's ``lower()`` (used on the stored
    value) can disagree on case-folding for some non-ASCII characters under
    a non-UTF-8 database collation (Argus round 4) -- not addressed here,
    since real input is Okta/Google email claims, which are ASCII.

    Fail-closed by construction, matching the retired module's contract:
    a non-string, empty/whitespace-only, or over-length (see
    ``MAX_LOOKUP_EMAIL_LENGTH``) ``owner_email`` returns ``None`` rather
    than raising or querying -- there is no legitimate email this could
    ever match, and the dangerous failure mode here is a false positive
    (treating an unregistered counterparty as EA-represented), not a
    missed match. This validation intentionally lives here rather than at
    the ``comms_lookup_agent_by_email`` tool boundary (Argus round 4): it
    mirrors the retired module's own contract, which lived on the type
    doing the lookup, not its caller.

    This validation is one-sided: ``register_agent`` (the write path) does
    not strip, lower-case, or length-cap ``owner_email`` before storing it
    -- including the JWT ``sub``-fallback path (``providers/comms.py``),
    which can write a non-email URI as ``owner_email`` for a token with no
    ``email``/``owner_email`` claim. An agent whose stored ``owner_email``
    has incidental leading/trailing whitespace, or came from that fallback
    path, will not be found here -- indistinguishable from "not
    registered" (Argus round 4). Not fixed in this pass: normalizing at
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
    deregistration rather than an enforced guarantee.
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
) -> list[Agent]:
    """Resolve every named target, requiring it to exist and be board-active.

    Ownership/ownership-boundary admission across the WHOLE participant
    set (initiator + targets) is a separate step (``_authorize_conversation_open``)
    — this function only rules out missing/inactive targets, uniformly
    denied as ``denied.unknown_agent``.
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
    try:
        owner_sets = await _owner_sets_for(participants, ownership_client)
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
    if not _pairwise_admitted(conversation_type, participants, owner_sets):
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
    message_type: str = "availability_request",
    schema_version: int = 1,
    expires_at: datetime | None = None,
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
    fails admission; ``RateLimitExceededError`` past the per-initiator
    conversation-start hourly cap OR the board-level per-sender-across-all-
    conversations hourly cap (TECH-5160); ``SchemaVersionMismatchError`` if
    no wire schema version falls inside every participant's declared
    ``[min_schema_version, max_schema_version]`` range;
    ``schemas.PayloadValidationError`` if ``initial_message`` fails schema
    validation.
    """
    initiator = await _require_active_agent(
        session, actor_sub=actor_sub, agent_id=initiator_agent_id
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
    )
    owner_snapshot = await _authorize_conversation_open(
        session,
        actor_sub=actor_sub,
        initiator=initiator,
        targets=targets,
        conversation_type=conversation_type,
        ownership_client=ownership_client,
    )

    # TECH-5160 capability negotiation: the caller-supplied schema_version
    # is NOT trusted as the actual wire version — it is overridden by the
    # highest version every participant (initiator + all targets) mutually
    # supports, refusing outright if no such version exists at all. See
    # _negotiate_schema_version's docstring for the combined refuse-vs-
    # degrade rule.
    schema_version = await _negotiate_schema_version(
        session, actor_sub=actor_sub, initiator=initiator, targets=targets
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
    await _enforce_boundary_crossing(
        session,
        actor_sub=actor_sub,
        sender_agent_id=initiator.id,
        conversation_type=conversation_type,
        conversation_id=None,
        other_agent_ids=[t.id for t in targets],
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
    )

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
        # _enforce_boundary_crossing: an empty owner set (a soft-failing
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
    """Board-level defense-in-depth (TECH-5160): cap a sender's TOTAL
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


async def _enforce_boundary_crossing(
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
) -> None:
    """Enforce DESIGN.md §9 Axis 2's boundary-crossing rule for this message.

    ``other_agent_ids`` is supplied by the caller rather than queried here —
    ``_check_boundary_crossing`` (below) queries current participants for
    ``post_message``; ``start_conversation`` already has its target list in
    memory and calls this directly with no conversation row required to
    exist yet.

    Only ``asymmetric`` conversations posting a non-``boundary_safe``
    message need an actual ownership lookup (``open``/``internal``, and any
    ``boundary_safe`` message, are decided by
    ``state_machine.is_boundary_crossing_safe`` from the conversation type
    alone) — avoids the external ownership-client round trip on the common
    path. Fails closed (``denied.ownership_unverified``) on any lookup
    error, or on an empty owner set for the sender or any other participant
    (an ownership_client that soft-fails to ``{"owners": []}`` instead of
    raising must not silently admit a boundary crossing).
    """
    boundary_safe = is_boundary_safe(message_type, schema_version)
    sender_owners: frozenset[str] = frozenset()
    other_owners: frozenset[str] = frozenset()
    other_owner_sets: list[frozenset[str]] = []
    if conversation_type == "asymmetric" and not boundary_safe:
        try:
            # Sequential, not asyncio.gather: AgentTableOwnershipClient's
            # get_agent_owners shares this call's AsyncSession, which
            # SQLAlchemy's AsyncSession does not support across concurrent
            # coroutines.
            sender_info = await ownership_client.get_agent_owners(sender_agent_id)
            sender_owners = frozenset(sender_info.get("owners") or [])
            for pid in other_agent_ids:
                info = await ownership_client.get_agent_owners(pid)
                other_owner_sets.append(frozenset(info.get("owners") or []))
            other_owners = frozenset().union(*other_owner_sets) if other_owner_sets else frozenset()
        except Exception as exc:
            logger.warning(
                "ownership lookup failed checking boundary crossing: %s",
                type(exc).__name__,
                exc_info=True,
            )
            await _deny(
                session,
                actor_sub=actor_sub,
                action="denied.ownership_unverified",
                agent_id=sender_agent_id,
                conversation_id=conversation_id,
                detail={"message_type": message_type},
            )
        if not sender_owners or any(not owners for owners in other_owner_sets):
            await _deny(
                session,
                actor_sub=actor_sub,
                action="denied.ownership_unverified",
                agent_id=sender_agent_id,
                conversation_id=conversation_id,
                detail={"message_type": message_type},
            )
    if not is_boundary_crossing_safe(conversation_type, boundary_safe, sender_owners, other_owners):
        # Distinct label for an unrecognized conversation_type (e.g. a
        # legacy pre-rename row) hitting is_boundary_crossing_safe's
        # default-deny path — this is a migration/data-integrity gap, not
        # an actual ownership-boundary crossing, and debugging it as the
        # latter would be misleading.
        if conversation_type not in CONVERSATION_TYPES:
            await _deny(
                session,
                actor_sub=actor_sub,
                action="denied.unknown_conversation_type",
                agent_id=sender_agent_id,
                conversation_id=conversation_id,
                detail={"message_type": message_type, "conversation_type": conversation_type},
            )
        else:
            # Explicit else, not relying on _deny's NoReturn to make the
            # two branches mutually exclusive -- a future refactor that
            # weakens _deny's contract must not silently start emitting
            # both audit rows for the same denial.
            await _deny(
                session,
                actor_sub=actor_sub,
                action="denied.boundary_crossing",
                agent_id=sender_agent_id,
                conversation_id=conversation_id,
                detail={
                    "message_type": message_type,
                    "sender_is_shared": len(sender_owners) > 1,
                    "other_owners_outside_sender": bool(other_owners - sender_owners),
                },
            )


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
    unlike ``_enforce_boundary_crossing``, this check is universal and
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
) -> None:
    """``_enforce_boundary_crossing`` (+ the universal ``accepted_types``
    capability gate) for an existing conversation row — queries current
    (``active``/``invited``) participants for the other side rather than
    requiring the caller to already know them.

    Single join query (participants + agents), not two separate
    round-trips: covers both ``_enforce_boundary_crossing``'s
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
    await _enforce_boundary_crossing(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation_type=conversation.type,
        conversation_id=conversation.id,
        other_agent_ids=other_ids,
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
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


async def post_message(
    session: AsyncSession,
    *,
    actor_sub: str,
    sender_agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    message_type: str,
    payload: dict[str, Any],
    ownership_client: OwnershipClient,
    schema_version: int = 1,
) -> Message:
    """Append a schema-validated message; apply state-machine side effects.

    Requires ``sender_agent_id`` to be a board-active agent (uniform denial
    otherwise) AND a currently-``active`` participant on ``conversation_id``
    (same uniform denial, identical whether the conversation doesn't
    exist, the sender was never invited, is still ``invited``, or has
    ``left``/``declined`` — DESIGN.md §4/§8's anti-enumeration rule).

    ``seq`` is assigned under ``SELECT ... FOR UPDATE`` on the conversation
    row (acquired while loading the participant), so concurrent posters to
    the same conversation serialize and every seq is gapless and race-safe.

    Boundary-crossing (DESIGN.md §9 Axis 2, ``_check_boundary_crossing``) is
    checked right after payload validation (which must run first here --
    ``is_boundary_safe`` itself raises ``PayloadValidationError`` for an
    unregistered schema coordinate, and that has to go through
    ``_deny_bad_schema``'s audit trail, not escape uncaught): an
    ``asymmetric`` conversation rejects a non-``boundary_safe`` message
    that would cross an ownership boundary for the sender, audited as
    ``denied.boundary_crossing``.

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
    cap (``_enforce_sender_global_rate_limit``, TECH-5160 defense-in-depth
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
    await _require_active_agent(session, actor_sub=actor_sub, agent_id=sender_agent_id)
    conversation, participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=sender_agent_id,
        conversation_id=conversation_id,
        required_status="active",
        for_update=True,
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

    # Validated above, not after: is_boundary_safe (inside
    # _check_boundary_crossing) raises PayloadValidationError itself for an
    # unregistered (message_type, schema_version) pair -- letting that
    # escape uncaught here (rather than through _deny_bad_schema) would
    # violate DESIGN.md §8's "every denial is audited" invariant.
    await _check_boundary_crossing(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation=conversation,
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
    )

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
    returned dict has ``"invited": True`` and an empty ``"messages"`` list
    — never any message content — and the caller's ``last_read_seq`` is
    NOT advanced (there is nothing to mark read). An ``active`` caller gets
    full history (respecting ``since_seq``) and their ``last_read_seq`` is
    advanced to the max seq actually returned (only if any messages were
    returned). A caller who is not a participant, or who previously
    left/declined, gets the uniform ``AccessDeniedError`` — identical to a
    non-existent conversation (DESIGN.md §4/§8).
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
            "invited_by": str(participant.invited_by) if participant.invited_by else None,
        }

    msg_rows = (
        await session.execute(
            select(Message, Agent.sub)
            .join(Agent, Agent.id == Message.sender_id)
            .where(Message.conversation_id == conversation.id, Message.seq > since_seq)
            .order_by(Message.seq)
        )
    ).all()
    max_seq = max((m.seq for m, _ in msg_rows), default=None)
    if max_seq is not None and max_seq > participant.last_read_seq:
        participant.last_read_seq = max_seq
    await session.commit()

    return {
        "conversation": _conversation_dict(conversation),
        "participants": participants_view,
        "messages": [_message_dict(m, sender_sub) for m, sender_sub in msg_rows],
        "invited": False,
        "total_count": len(msg_rows),
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

    Explicit empty state: always returns the same three keys, even when
    both lists are empty, so a tools layer can render "nothing needs your
    attention" rather than reasoning about an ambiguous bare empty list
    (AXI convention, DESIGN.md §7).

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
        )
    ).all()

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
        )
    ).all()
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
        "pending_invites": pending_invites,
        "total_count": len(unread) + len(pending_invites),
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

    Wraps the existing ``agents.owner_sub`` column as a single-element
    owner set; ``is_shared`` is always ``False`` since no shared-agent
    concept exists in this schema yet. This is exactly correct for every
    agent registered today: two agents bound to the same ``owner_sub``
    (e.g. two agents belonging to one person) intersect via ``may_assign``
    precisely as they should, and unrelated agents correctly do not. Swap
    this for a real platform-backed client the moment shared agents exist
    — the ``OwnershipClient`` protocol is the seam, not this class.

    Safe to use as an authorization input specifically because
    ``register_agent`` freezes ``owner_sub`` at first registration and
    never overwrites it on re-registration (see that function) — reading
    it here would otherwise let a caller forge a victim's ``owner_sub``
    via a re-register call.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        agent = await _find_agent_by_id(self._session, agent_id)
        if agent is None:
            raise LookupError(f"unknown agent {agent_id}")
        return {"is_shared": False, "owners": [agent.owner_sub]}


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


__all__ = [
    "CONVERSATION_TTL",
    "MAX_CONVERSATION_STARTS_PER_HOUR",
    "MAX_LOOKUP_EMAIL_LENGTH",
    "MAX_MESSAGES_PER_CONVERSATION_PER_HOUR",
    "AgentTableOwnershipClient",
    "OwnershipClient",
    "accept_invite",
    "decline_invite",
    "get_agent_by_sub",
    "get_conversation",
    "inbox",
    "invite",
    "leave",
    "list_agents",
    "list_conversations",
    "lookup_agent_by_email",
    "may_assign",
    "may_invite",
    "post_message",
    "register_agent",
    "start_conversation",
]
