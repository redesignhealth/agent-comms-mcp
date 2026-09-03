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
and — TECH-5389 PR2 — ``approval_holds_per_minute``),
``denied.ownership_unverified`` (Axis 1 admission — conversation open, or
invite owner-freeze's empty-owner-set case — fail closed) /
``denied.ownership_lookup_failed`` (invite owner-freeze ONLY, when the
lookup itself raised rather than returning an empty set — TECH-5735
distinguishes the two so ``decide_hold``'s invite re-validation can tell a
transient registry outage apart from a permanently-orphaned target),
``denied.not_same_owner``/
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
from urllib.parse import urlsplit

from sqlalchemy import and_, func, literal, or_, select, text, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import (
    AccessDeniedError,
    AgentAlreadyRegisteredError,
    AgentRetiredError,
    AgentSuspendedError,
    ConversationArchivedError,
    DisplayNameCollisionError,
    HoldAlreadyDecidedError,
    HoldAwaitingAutoReviewError,
    HoldExpiredError,
    InvalidConversationStateError,
    RateLimitExceededError,
    SchemaVersionMismatchError,
    SiblingIdentityExistsError,
    UnknownConversationTypeError,
)
from models import (
    PROPOSAL_HOLD_LEVELS,
    Agent,
    ApprovalHold,
    AuditLog,
    Conversation,
    Message,
    Participant,
    ProposalHold,
)
from plugins import (
    BARRIER_SENSITIVE_TYPES,
    ActiveChecker,
    ApprovalNotification,
    ApprovalNotifier,
    AutoApprover,
    HoldContext,
    MessageRiskContext,
    ParticipantInfo,
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
MAX_APPROVAL_HOLDS_PER_MINUTE = 2

# RFC 5321 4.5.3.1.3 total-address cap. Hoisted here (Argus round 2,
# TECH-5786 PR follow-up) rather than left as two independently-drifting
# copies -- `lookup_agent_by_email` and `admin_register_agent` both bound
# an email against this same limit, and a drift between them would make an
# `owner_email` that `admin_register_agent` accepts permanently unfindable
# via `lookup_agent_by_email` (which returns `None` for over-cap input).
MAX_LOOKUP_EMAIL_LENGTH = 254

# TECH-5735: invite-holds (ApprovalHold.kind="invite") use fixed sentinel
# values in place of a real message-schema/risk-scorer identifier, since no
# RiskScorer plugin is invoked and there is no real schemas.MessageType for
# "someone is being invited" — see ApprovalHold's class docstring and
# _divert_invite_for_approval.
INVITE_HOLD_MESSAGE_TYPE = "invite"
INVITE_HOLD_SCHEMA_VERSION = 1
# Argus round 2, TECH-5822 SUGGESTION: these two string VALUES are a
# cross-repo audit-vocabulary contract (agent-comms-approvals'
# RHAutoApprover and any consumer of ApprovalHold.risk_reason/scorer_label
# branch on the literal values, not the Python identifier names) -- renaming
# the values themselves is a breaking change requiring coordination with
# that repo, so deliberately NOT done here even though the names now read
# "note"-specific. Since _conversation_has_note_history checks
# BARRIER_SENSITIVE_TYPES (TECH-5822), these values are emitted for ANY
# barrier-sensitive free-text history (today: note or instruction_share),
# not just note history -- the historical name undersells what they cover.
INVITE_HOLD_RISK_REASON = "note_history_requires_approval"
INVITE_HOLD_RISK_SCORER_LABEL = "invite_note_history_v1"

# TECH-5786: the risk_reason a sender's own explicit `review_reason` on
# post_message forces onto the hold, overriding whatever the injected
# RiskScorer verdict was (including None, e.g. in an `internal` conversation
# where the scorer structurally never returns non-None). Distinct from every
# scorer-produced value (e.g. "boundary_crossing") on purpose: an
# AutoApprover that special-cases the scorer's own boundary-crossing reason
# (as RHAutoApprover's chief-of-staff rule does) must not accidentally treat
# an agent-requested review as that case and auto-clear it.
AGENT_REQUESTED_RISK_REASON = "agent_requested"

# Analogous to INVITE_HOLD_RISK_SCORER_LABEL above: an agent-requested hold's
# `risk_scorer` field must not read as the injected RiskScorer's own name
# (e.g. "boundary_v1"), since the scorer itself never emitted this hold --
# that would misattribute it to the scorer's false-positive rate in any
# dashboard grouping by risk_scorer. The scorer's own verdict, if any, is
# preserved separately as `scorer_risk_reason` in the audit detail.
AGENT_REQUESTED_RISK_SCORER_LABEL = "agent_requested"

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
# Argus round-4: distinct from `denied.ownership_unverified` (an empty
# owner set from a SUCCESSFUL lookup -- deterministic, will never resolve
# itself) specifically so decide_hold's invite re-validation can tell a
# transient registry outage apart from a permanently-orphaned target. Only
# `_authorize_invite_owner_freeze`'s lookup-EXCEPTION branch uses this;
# `_authorize_conversation_open`'s analogous branch does not, since that
# caller (start_conversation) has no stranded-hold concern to guard
# against -- the whole open attempt just fails and the caller retries.
_DENIED_OWNERSHIP_LOOKUP_FAILED = "denied.ownership_lookup_failed"


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


async def _deny_agent_suspended(
    session: AsyncSession, *, sub: str, agent_id: uuid.UUID
) -> NoReturn:
    """Same audit/commit shape as ``_deny``, but for
    ``exceptions.AgentSuspendedError`` (TECH-5736): a re-registration
    attempt against a suspended ``sub``. ``actor_sub`` is ``sub`` itself --
    this denial fires before any authenticated identity distinct from the
    registering caller is available, the same as every other denial inside
    ``register_agent``."""
    _audit(
        session,
        actor_sub=sub,
        action="denied.reregister_suspended_agent",
        agent_id=agent_id,
        detail={"sub": sub},
    )
    await session.commit()
    raise AgentSuspendedError(sub=sub)


def _is_constraint_violation(exc: IntegrityError, name: str) -> bool:
    """Narrow check that ``exc`` is specifically a violation of the named
    constraint/index ``name``, not merely "some IntegrityError". Postgres
    reports a unique (partial) index's name in the underlying error's
    ``constraint_name`` diagnostic field the same way it would a real named
    constraint. Under this project's driver stack (SQLAlchemy 2.0.x +
    asyncpg), ``exc.orig`` is ``AsyncAdapt_asyncpg_dbapi.IntegrityError``, a
    thin wrapper that only copies ``pgcode``/``sqlstate`` from the real
    ``asyncpg.exceptions.UniqueViolationError`` -- NOT ``constraint_name``.
    The real asyncpg exception (which does carry ``constraint_name``) is
    reachable via ``exc.orig.__cause__``. Check there first, falling back
    to ``exc.orig`` itself in case a different driver/version puts the
    attribute there directly. Deliberately not a blanket catch: any other
    IntegrityError (e.g. a genuinely unrelated constraint) must keep
    propagating as itself.

    Extracted from two near-identical copies (Argus round 2, TECH-5786 PR
    follow-up: ``_is_display_name_index_violation``/``_is_sub_unique_violation``
    differed only in the constraint-name literal) -- a future
    SQLAlchemy/asyncpg change to this extraction logic now only needs one
    fix, not two, closing the risk of one call site silently degrading to a
    bare 500 if only the other copy got updated."""
    cause = getattr(exc.orig, "__cause__", None)
    constraint_name = getattr(cause, "constraint_name", None)
    if constraint_name is None:
        constraint_name = getattr(exc.orig, "constraint_name", None)
    return constraint_name == name


async def _deny_sibling_identity_exists(
    session: AsyncSession,
    *,
    actor_sub: str,
    base_sub: str,
    sub: str,
    existing_agent_keys: list[str | None],
) -> NoReturn:
    """Same audit/commit shape as ``_deny``, but for
    ``exceptions.SiblingIdentityExistsError`` (TECH-5736): about to create a
    brand-new row for ``sub`` while ``base_sub`` already has at least one
    other active identity. DESIGN.md §8 invariant 5 requires every denial to
    be audited, the same as every other fail-closed branch in
    ``register_agent`` -- this one was missed when the check itself was
    added. ``actor_sub`` is an explicit parameter, NOT always ``sub`` itself
    (Argus round 1, TECH-5786 PR follow-up): ``register_agent``'s own call
    site passes ``actor_sub=sub`` (no authenticated identity distinct from
    the registering caller exists at that point), but
    ``admin_register_agent`` reuses this same denial for a PRIVILEGED CALLER
    registering a target ``sub`` on its behalf -- same distinction
    ``_deny_agent_already_registered`` already draws for that function."""
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.sibling_identity_exists",
        detail={"base_sub": base_sub, "sub": sub, "existing_agent_keys": existing_agent_keys},
    )
    await session.commit()
    raise SiblingIdentityExistsError(base_sub=base_sub, existing_agent_keys=existing_agent_keys)


async def _deny_display_name_collision(
    session: AsyncSession, *, actor_sub: str, display_name: str, existing_subs: list[str]
) -> NoReturn:
    """Same audit/commit shape as ``_deny``, but for
    ``exceptions.DisplayNameCollisionError`` (TECH-5736). The colliding
    ``sub``s are recorded here, server-side only -- see that exception's
    docstring for why they were removed from the client-facing message."""
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.display_name_collision",
        detail={"display_name": display_name, "colliding_subs": existing_subs},
    )
    await session.commit()
    raise DisplayNameCollisionError(display_name=display_name, existing_subs=existing_subs)


async def _is_active_safe(active_checker: ActiveChecker, sub: str) -> bool:
    """Enforce ``ActiveChecker``'s documented fail-open contract at the seam,
    since the ``Protocol`` itself cannot enforce "must never raise" on
    implementors. A registry-backed checker that raises (timeout, 5xx, bad
    auth) must not take down directory reads or conversation admission --
    worst case is a briefly-visible retired agent, not an outage."""
    try:
        return await active_checker.is_active(sub)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning(
            "active_checker.is_active raised for sub=%r; failing open", sub, exc_info=True
        )
        return True


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


async def _deny_archived(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    action: str,
) -> NoReturn:
    """Audit + raise the specific (non-uniform) archived-conversation
    denial (TECH-5887) -- see ``exceptions.ConversationArchivedError``'s
    docstring for why this gets its own message rather than the uniform
    ``AccessDeniedError`` or the state-machine's own
    ``InvalidConversationStateError``. ``action`` distinguishes the call
    site in the audit log (``denied.archived.invite`` /
    ``denied.archived.post_message`` / ``denied.archived.accept`` /
    ``denied.archived.decide_hold``) --
    unlike ``_deny_bad_state``, which records the blocked message TYPE in
    ``detail`` instead of varying the action name, there is no message type
    to vary on for ``invite``/``accept``, so the action name itself carries
    which tool was blocked.
    """
    _audit(
        session,
        actor_sub=actor_sub,
        action=action,
        agent_id=agent_id,
        conversation_id=conversation_id,
    )
    await session.commit()
    raise ConversationArchivedError(
        "conversation_archived: this conversation has been archived and no longer "
        "accepts write operations"
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
    reversal -- a sender flooding the human approval queue is still capped.

    At MAX_APPROVAL_HOLDS_PER_MINUTE=2 (Argus round-2), the sustained rate
    this permits (120/hour) equals MAX_MESSAGES_PER_SENDER_PER_HOUR exactly,
    so this cap only shapes bursts (at most 2 holds back-to-back); it no
    longer provides an independent sustained-flood ceiling below the global
    per-sender message cap."""
    one_minute_ago = _now() - timedelta(minutes=1)
    count = (
        await session.execute(
            select(func.count())
            .select_from(ApprovalHold)
            .where(
                ApprovalHold.sender_agent_id == sender_agent_id,
                ApprovalHold.created_at > one_minute_ago,
            )
        )
    ).scalar_one()
    if count >= MAX_APPROVAL_HOLDS_PER_MINUTE:
        await _deny_rate_limited(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=None,
            limit_name="approval_holds_per_minute",
            message=(
                f"rate_limited: at most {MAX_APPROVAL_HOLDS_PER_MINUTE} approval holds per minute"
            ),
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
        # Argus round-4 BLOCKING catch: this session factory sets
        # expire_on_commit=False (db.py), so re-calling this with the SAME
        # hold_id already in the identity map (e.g. decide_hold's
        # concurrent-resolution re-acquire, after an intervening commit)
        # would otherwise hand back the cached Python object UNCHANGED --
        # the `FOR UPDATE` still executes and blocks at the DB level, but
        # the row's ACTUAL current column values never make it back into
        # the object, silently defeating any "is it still pending_human"
        # check a caller does against the returned row.
        stmt = stmt.execution_options(populate_existing=True)
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
        "kind": hold.kind,
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
    if hold.target_agent_id is not None:
        result["target_agent_id"] = str(hold.target_agent_id)
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
    is_shared_by_id: dict[uuid.UUID, bool],
) -> bool:
    """Pure pairwise decision given already-resolved owner sets — every pair
    must independently satisfy the type's predicate (no star-topology
    exception: A-B and B-C admitted doesn't imply A-C is).

    For ``asymmetric``, a pair where EITHER side is ``is_shared`` is
    admitted regardless of owner-set overlap (Argus round 1, TECH-5786 PR
    follow-up): the bypass must apply PER PAIR, not to the whole
    participant set via a single ``any(is_shared_by_id.values())`` check
    at the call site -- a multi-target conversation with one shared target
    and one unrelated non-shared target (fully disjoint owners) must still
    deny that second pair, even though the first pair is legitimately
    bypassed. ``is_shared_by_id`` is ignored for ``internal`` (already
    hard-denied for any ``is_shared`` participant before this function is
    ever called), but still REQUIRED, not defaulted (Argus round 2,
    TECH-5786 PR follow-up): a future ``asymmetric`` caller that omits it
    would otherwise silently lose the per-pair bypass rather than fail
    loudly.
    """
    pairs = itertools.combinations(participants, 2)
    if conversation_type == "internal":
        return all(owner_sets[a.id] == owner_sets[b.id] for a, b in pairs)
    # asymmetric: exactly may_assign's owner-set-intersection predicate,
    # applied pairwise (this is the reuse the ticket calls out — one
    # predicate, not two independently-drifting implementations of
    # "do these owner sets intersect") — except a pair with a shared
    # participant, which bypasses the predicate entirely for that pair.
    return all(
        is_shared_by_id.get(a.id, False)
        or is_shared_by_id.get(b.id, False)
        or may_assign(owner_sets[a.id], owner_sets[b.id])
        for a, b in pairs
    )


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
        # TECH-5887: independent of `state` above -- see
        # models.Conversation.archived_at's docstring. Included in every
        # projection that uses this helper (get_conversation,
        # list_conversations, inbox), so a caller can always tell an
        # archived conversation apart from an active one without a
        # dedicated lookup.
        "archived": conversation.archived_at is not None,
        "archived_at": _iso(conversation.archived_at),
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


def _agent_key_from_sub(sub: str, base_sub: str) -> str | None:
    """Recover the ``agent_key`` half of a composed board identity.

    Inverse of ``providers.comms._compose_sub``: ``sub`` is either exactly
    ``base_sub`` (no ``agent_key`` was given) or ``f"{base_sub}::{agent_key}"``
    -- both ``base_sub`` and ``agent_key`` are validated elsewhere to never
    contain ``"::"`` themselves, so this split is unambiguous. Used only to
    render existing sibling identities back into a human-readable error
    (``SiblingIdentityExistsError``) -- never for any authorization
    decision.
    """
    if sub == base_sub:
        return None
    return sub[len(base_sub) + 2 :]


def _validate_display_name_and_accepted_types(
    display_name: str, accepted_types: list[str] | None
) -> tuple[str, list[str] | None]:
    """Shared input validation for ``display_name``/``accepted_types``,
    factored out of ``register_agent`` so ``admin_register_agent`` (the
    on-behalf-of path) enforces the identical rules rather than a
    hand-copied, driftable duplicate. Returns ``(display_name,
    normalized_types)`` -- stripped/deduped/sorted, same shape both
    callers persist. Raises ``ValueError``/``UnknownConversationTypeError``
    exactly as ``register_agent``'s docstring documents; see that
    docstring for the full validation-order rationale (cap checks run
    BEFORE computing ``unknown_types``, so an over-sized/over-long input
    can never get echoed back verbatim in the error message).

    Three distinct shapes now (TECH-5822 follow-up: opt-out
    accepted_types), not two -- this is the one place all three are
    resolved, so ``register_agent``/``admin_register_agent`` never have to
    duplicate this distinction:

    - ``None`` (the caller omitted the parameter entirely): passed straight
      through as ``None``, with NO validation performed at all. This is
      not "accept everything" by itself -- it means "no change requested",
      and it is ``register_agent``'s job (not this function's) to resolve
      that into either "use the accept-everything default" (first
      registration) or "leave the existing row's accepted_types alone"
      (re-registration). Collapsing ``None`` into ``[]`` here would erase
      that distinction before the caller who actually needs it ever sees it.
    - ``[]`` (explicitly passed empty): the opt-out "accept every message
      type" sentinel itself -- returned as-is, no per-entry/unknown-type
      checks (there is nothing to check).
    - non-empty list: goes through the full count/length/known-type
      validation and is narrowed to that explicit, restricting set,
      exactly as before this follow-up.

    See ``_enforce_message_type_accepted`` for the corresponding
    enforcement-side change, and this module's own docstring / DESIGN.md's
    "Capability gate: accepted_types" section for why empty-list-means-
    everything (rather than a wildcard string literal like ``"*"``) was
    chosen: it requires no addition to ``MESSAGE_TYPES``' vocabulary, needs
    no carve-out in the unknown-types check below, and automatically
    covers any FUTURE message type with zero code change here when one
    ships.
    """
    display_name = display_name.strip()
    if not display_name:
        raise ValueError("display_name must be non-empty")
    if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
        raise ValueError(f"display_name exceeds {MAX_DISPLAY_NAME_LENGTH} characters")
    if accepted_types is None:
        return display_name, None
    if len(accepted_types) > MAX_ACCEPTED_TYPES:
        raise ValueError(f"accepted_types exceeds {MAX_ACCEPTED_TYPES} entries")
    if not accepted_types:
        return display_name, []
    if any(len(t) > MAX_ACCEPTED_TYPE_LENGTH for t in accepted_types):
        raise ValueError(
            f"accepted_types entries must not exceed {MAX_ACCEPTED_TYPE_LENGTH} characters"
        )
    unknown_types = sorted(set(accepted_types) - MESSAGE_TYPES)
    if unknown_types:
        raise UnknownConversationTypeError(
            "accepted_types must be a subset of "
            f"{sorted(MESSAGE_TYPES)} (got unknown: {unknown_types})"
        )
    normalized_types = sorted(set(accepted_types))
    return display_name, normalized_types


async def _deny_agent_already_registered(
    session: AsyncSession, *, actor_sub: str, sub: str, existing_agent_id: uuid.UUID
) -> NoReturn:
    """Same audit/commit shape as ``_deny``, but for
    ``exceptions.AgentAlreadyRegisteredError`` (the ``comms_admin_register``
    on-behalf-of tool). ``actor_sub`` is the PRIVILEGED CALLER here, not
    ``sub`` (the target) -- unlike every denial inside ``register_agent``,
    this tool always has an authenticated actor distinct from the target
    it's registering, and the audit trail must record who attempted the
    on-behalf-of registration, not just which sub it targeted."""
    _audit(
        session,
        actor_sub=actor_sub,
        action="denied.agent_already_registered",
        agent_id=existing_agent_id,
        detail={"target_sub": sub},
    )
    await session.commit()
    raise AgentAlreadyRegisteredError(sub=sub)


# Argus round 1, TECH-5786 PR follow-up: `admin_register_agent`'s
# `sub`/`owner_sub`/`owner_email` are explicit caller-supplied parameters
# (unlike `register_agent`'s token-derived, IdP-length-constrained
# equivalents), so nothing bounds them before they're written into
# `audit_log.detail` (JSONB) -- a legitimately-credentialed admin could
# otherwise write an arbitrarily large string into the audit log.
MAX_SUB_LENGTH = 256  # generous bound for a board `sub`/`owner_sub` identifier


async def admin_register_agent(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    sub: str,
    owner_sub: str,
    owner_email: str,
    display_name: str,
    accepted_types: list[str] | None,
    is_shared: bool = False,
    min_schema_version: int = 1,
    max_schema_version: int = 1,
    confirm_new_identity: bool = False,
) -> Agent:
    """Register a NEW agent identity on behalf of an explicit target
    ``sub``, for a privileged (``comms:admin``-scoped or interactive)
    caller -- the ``comms_admin_register`` MCP tool.

    Why this exists: ``register_agent`` always derives ``sub`` from the
    CALLING token's own verified identity (``providers.comms.
    _require_identity``) -- by design, DESIGN.md §4's "owner identity is
    always derived from verified token claims, never accepted as a
    parameter" invariant means nothing can register OR claim an identity
    that isn't its own token's. That's a deliberate anti-impersonation
    property, but it leaves a real gap: a platform provisioning a new bot
    (e.g. redesign-ai minting an Arc bot's board credential) needs to set
    ``is_shared=True`` on that bot's row before the bot has ever spoken for
    itself -- and the only workarounds available without this tool are both
    bad: (a) grant the bot's own permanent credential ``comms:admin`` --
    an ordinary bot has no legitimate reason to hold a scope that lets it
    register/re-authorize OTHER agents on this board, and doing so would
    make every such bot's credential a full admin-capability leak risk --
    or (b) mint a throwaway token impersonating the
    target ``sub`` just to make one self-registration call. This function is
    the real, first-class fix: an explicit, audited, on-behalf-of
    registration capability, distinct from both ``register_agent`` (self-
    service, idempotent, ``sub`` always the caller's own) and
    ``set_agent_shared`` (corrects ``is_shared`` on an agent that ALREADY
    exists -- this function is a genuine FIRST registration for a ``sub``
    that has never registered at all).

    **Authorization**: mirrors ``set_agent_shared``/``deregister_agent``
    exactly -- ``admin_authorized`` MUST be computed by the caller (the
    tools layer) from the actor's own verified token (``comms:admin``
    scope, or an interactive/Okta caller), checked FIRST via
    ``_deny_agent_already_registered``'s sibling ``_deny`` call so an
    unauthorized attempt's audit trail always records the authorization
    failure, never ``denied.agent_already_registered``, regardless of
    whether ``sub`` happens to already exist. No default is provided (same
    reasoning as ``set_agent_shared``): this function's entire purpose is
    the privileged mutation, so there is no unprivileged call site to
    protect with a fail-closed default. Unlike ``register_agent``'s
    ``is_shared_authorized`` (a NARROWER gate on one parameter of an
    otherwise-reachable self-service tool), ``admin_authorized`` gates the
    entire call -- there is no unprivileged use of this function, so
    ``is_shared`` itself needs no separate authorization check here.

    **``owner_sub``/``owner_email`` are explicit, caller-supplied
    parameters here** -- the one deliberate exception to DESIGN.md §4's
    "never accepted as a parameter" rule, and only because this is
    fundamentally an on-behalf-of operation: there IS no verified token for
    the target to derive them from (that's the entire gap this tool closes
    -- the target hasn't authenticated to this board yet). This board's
    injected ``OwnershipClient`` seam (``_owner_sets_for`` and friends) is
    keyed by board ``agent_id`` (a UUID), which does not exist yet for a
    ``sub`` that has never registered -- it structurally cannot resolve
    ownership for a not-yet-registered identity, so there is no existing
    mechanism this function could reuse instead of trusting its caller.
    The privileged caller is expected to source these from whatever
    ownership registry it already trusts for this ``sub`` (e.g. the same
    registry that minted the target's own board credential) -- this
    function performs no verification of its own, the same trust contract
    ``register_agent`` already documents for its own (token-derived)
    ``owner_sub``/``owner_email`` parameters.

    **First-registration only, never an upsert**: raises
    ``AgentAlreadyRegisteredError`` if ``sub`` already has a board row
    (any ``status``) -- unlike ``register_agent``'s idempotent self-service
    re-bind. Correcting an EXISTING agent's ``is_shared``/``status`` goes
    through ``set_agent_shared``/``deregister_agent`` instead; there is no
    supported way to change an existing agent's ``owner_sub``/
    ``owner_email``/``display_name`` through this admin surface.

    **Sibling-identity-fork guard applies here too (Argus round 1,
    TECH-5786 PR follow-up)**: mirrors ``register_agent``'s
    ``SiblingIdentityExistsError`` check (TECH-5736) rather than silently
    omitting it. Without this, a ``comms:admin`` caller could reopen the
    exact kill-switch bypass that check exists to close: suspend every
    existing identity under a ``base_sub`` (via ``deregister_agent``), then
    admin-register a brand-new ``sub`` under that same ``base_sub`` to
    route around the suspension. ``base_sub`` here is derived from the
    TARGET ``sub`` itself (``sub.split("::", 1)[0]``), not from the
    caller's own identity the way ``register_agent`` receives it -- this
    function has no notion of "the caller's own agent_key composition"
    since the caller and the target are different identities by design.
    ``confirm_new_identity=True`` acknowledges the fork and proceeds
    anyway, same semantics as ``register_agent``'s own parameter; the
    resulting audit action (on denial) is still
    ``denied.sibling_identity_exists``, but attributed to the PRIVILEGED
    CALLER's ``actor_sub``, not the target ``sub`` -- see
    ``_deny_sibling_identity_exists``'s own docstring for why that split
    matters here specifically.

    **Interaction with later self-registration**: a row this function
    creates is, once created, ordinary -- indistinguishable from one
    ``register_agent`` created directly. If the target later calls
    ``comms_register`` itself (e.g. during its own ReClaw setup, using its
    own restricted credential), that hits ``register_agent``'s existing
    RE-registration branch (``existing is not None``) for the same ``sub``:
    ``is_shared`` and ``owner_sub`` stay frozen exactly as they would after
    any other first registration (a mismatched self-reported ``is_shared``
    is ignored and audited as ``agent.reregister_is_shared_ignored``, same
    as always) -- this function's own admin-set values are not
    retroactively escalatable by the target's own later, less-privileged
    call. ``owner_email`` is the one field ``register_agent`` DOES
    overwrite on re-registration (see its docstring) -- so a target's later
    self-registration can move ``owner_email`` away from what this
    function set, if its own token's claims (or ``base_sub`` fallback)
    disagree. This is not a new gap this function introduces: it is
    exactly ``register_agent``'s existing, already-documented
    ``owner_email`` mutability, unrelated to how the row was first
    created. Callers relying on a stable admin-set ``owner_email`` should
    ensure the target's own later credential is minted with a matching
    ``owner_email`` claim.

    Reuses ``register_agent``'s exact ``display_name``/``accepted_types``
    validation (``_validate_display_name_and_accepted_types``) and its
    display-name-collision-on-creation check, so the two registration
    paths can never silently drift apart on those rules.

    Raises ``ValueError``/``UnknownConversationTypeError`` for malformed
    input, same shapes and ordering as ``register_agent`` (see its
    docstring) -- checked BEFORE the authorization gate for ``sub``'s own
    non-emptiness (a data-shape failure, not an authorization decision),
    but the authorization gate itself still runs before the
    already-registered/display-name-collision checks below, per the
    ordering note above.
    """
    validate_schema_version_range(min_schema_version, max_schema_version)
    sub = sub.strip()
    if not sub:
        raise ValueError("sub must be non-empty")
    # Argus round 1, TECH-5786 PR follow-up: mirrors `identity.validate_sub_shape`'s
    # "@" rejection (raised here as `ValueError`, not that module's `ToolError`,
    # to match this function's own input-validation error shape rather than
    # importing an MCP-transport-layer exception into the service layer). A
    # token-derived `sub` already goes through `validate_sub_shape` via
    # `_require_identity` -- this function accepts `sub` as a plain
    # caller-supplied parameter instead, so without an equivalent check here a
    # `comms:admin` holder could pre-register `sub="victim@company.com"`,
    # squatting a real user's future Okta-derived identity with an
    # attacker-controlled `owner_sub`/`is_shared` that survives the
    # re-registration freeze once the victim actually self-registers.
    # `owner_sub` deliberately gets NO analogous "@"-rejection (Argus round
    # 2, TECH-5786 PR follow-up: an earlier revision of this fix wrongly
    # applied the same check to `owner_sub`) -- unlike `sub` (a board
    # IDENTITY, never email-shaped by spec), `owner_sub` is legitimately
    # email-shaped for any Okta/interactive-derived owner:
    # `register_agent` itself sets `owner_sub = token.claims.get("owner_sub")
    # or base_sub`, where `base_sub` resolves via `try_resolve_email` for
    # exactly that case. Rejecting it here would make it impossible to
    # admin-register a bot on behalf of an ordinary human owner, and
    # `approve_hold`/`reject_hold` gate on `hold.owner_sub == approver_sub`
    # (an email for an Okta approver) -- a worked-around non-email
    # `owner_sub` would make every hold that bot creates permanently
    # unapprovable by its real owner.
    if "@" in sub:
        raise ValueError("sub must not be email-shaped")
    if len(sub) > MAX_SUB_LENGTH:
        raise ValueError(f"sub exceeds {MAX_SUB_LENGTH} characters")
    owner_sub = owner_sub.strip()
    if not owner_sub:
        raise ValueError("owner_sub must be non-empty")
    if len(owner_sub) > MAX_SUB_LENGTH:
        raise ValueError(f"owner_sub exceeds {MAX_SUB_LENGTH} characters")
    owner_email = owner_email.strip()
    if not owner_email:
        raise ValueError("owner_email must be non-empty")
    if len(owner_email) > MAX_LOOKUP_EMAIL_LENGTH:
        raise ValueError(f"owner_email exceeds {MAX_LOOKUP_EMAIL_LENGTH} characters")
    if "@" not in owner_email:
        raise ValueError("owner_email must be email-shaped")
    display_name, normalized_types = _validate_display_name_and_accepted_types(
        display_name, accepted_types
    )
    # admin_register_agent has no re-registration path (AgentAlreadyRegisteredError
    # below denies that outright) -- every call here is a first registration,
    # so None ("no change requested") resolves the same way it does for
    # register_agent's OWN first-registration branch: the accept-everything
    # default, never "leave unset" (there is no existing row to leave alone).
    if normalized_types is None:
        normalized_types = []

    if not admin_authorized:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.admin_register_requires_elevated_scope",
            detail={"target_sub": sub, "display_name": display_name},
        )

    existing = (await session.execute(select(Agent).where(Agent.sub == sub))).scalar_one_or_none()
    if existing is not None:
        await _deny_agent_already_registered(
            session, actor_sub=actor_sub, sub=sub, existing_agent_id=existing.id
        )

    # Sibling-identity-fork guard (Argus round 1, TECH-5786 PR follow-up):
    # same check as register_agent's own (TECH-5736), deliberately not
    # omitted here -- see this function's docstring for why omitting it
    # would reopen the kill-switch bypass that check exists to close.
    # `base_sub` is derived from the TARGET `sub` itself, since this
    # function has no caller-side base_sub/agent_key composition the way
    # register_agent does. Deliberately NOT filtered to `status ==
    # "active"` -- same reasoning as register_agent's own comment: a
    # suspended sibling must still count, or `deregister_agent` followed
    # by this tool would silently bypass the suspension.
    if not confirm_new_identity:
        target_base_sub = sub.split("::", 1)[0]
        sibling_subs = (
            (
                await session.execute(
                    select(Agent.sub).where(
                        Agent.sub != sub,
                        or_(
                            Agent.sub == target_base_sub,
                            Agent.sub.startswith(f"{target_base_sub}::", autoescape=True),
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        if sibling_subs:
            await _deny_sibling_identity_exists(
                session,
                actor_sub=actor_sub,
                base_sub=target_base_sub,
                sub=sub,
                existing_agent_keys=[_agent_key_from_sub(s, target_base_sub) for s in sibling_subs],
            )

    # Same display-name-collision-on-creation guard as register_agent
    # (see that function's own comments for why this only fires on
    # creation -- always true here, since this path never re-registers).
    colliding_subs = (
        (
            await session.execute(
                select(Agent.sub).where(
                    func.lower(Agent.display_name) == display_name.lower(),
                    Agent.status == "active",
                )
            )
        )
        .scalars()
        .all()
    )
    if colliding_subs:
        await _deny_display_name_collision(
            session,
            actor_sub=actor_sub,
            display_name=display_name,
            existing_subs=list(colliding_subs),
        )

    now = _now()
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
    try:
        await session.flush()
    except IntegrityError as exc:
        # Same race-closing DB-level backstop as register_agent's own
        # flush handler -- see its comment for why this is narrowed to
        # exactly this named index rather than a blanket
        # IntegrityError->DisplayNameCollisionError mapping.
        await session.rollback()
        if _is_constraint_violation(exc, "idx_agents_lower_display_name_active"):
            colliding_subs_post_rollback = (
                (
                    await session.execute(
                        select(Agent.sub).where(
                            func.lower(Agent.display_name) == display_name.lower(),
                            Agent.status == "active",
                        )
                    )
                )
                .scalars()
                .all()
            )
            await _deny_display_name_collision(
                session,
                actor_sub=actor_sub,
                display_name=display_name,
                existing_subs=list(colliding_subs_post_rollback),
            )
        # Second race-closing backstop, specific to this function (Argus
        # round 1, TECH-5786 PR follow-up): unlike register_agent
        # (idempotent -- a concurrent duplicate is benign), this path is
        # first-registration-only, so two concurrent admin calls for the
        # same `sub` that both pass the pre-flush `scalar_one_or_none`
        # check above race for `agents_sub_key` at flush time. Without
        # this branch, the loser's IntegrityError falls through to the
        # bare `raise` below as an unmapped 500 with raw DB constraint
        # text, contradicting this function's own docstring promise of
        # `AgentAlreadyRegisteredError` for any duplicate-`sub` case.
        if _is_constraint_violation(exc, "agents_sub_key"):
            existing_post_rollback = (
                await session.execute(select(Agent).where(Agent.sub == sub))
            ).scalar_one_or_none()
            if existing_post_rollback is not None:
                await _deny_agent_already_registered(
                    session,
                    actor_sub=actor_sub,
                    sub=sub,
                    existing_agent_id=existing_post_rollback.id,
                )
            # Argus round 2, TECH-5786 PR follow-up: the constraint violation
            # confirms a row for `sub` exists, even in the vanishingly rare
            # window where it's since been deleted again before this re-read
            # (so `existing_post_rollback` came back `None`) -- raise the
            # same client-safe error directly rather than falling through to
            # the bare `raise` below, which would leak the raw `IntegrityError`
            # (including the internal `agents_sub_key` constraint name) to the
            # MCP transport as an unmapped 500. No audit write here (no agent
            # row to reference), same trade-off the display-name branch above
            # implicitly makes when it fires with an empty colliding-subs list.
            raise AgentAlreadyRegisteredError(sub=sub) from exc
        raise
    _audit(
        session,
        actor_sub=actor_sub,
        action="agent.admin_registered",
        agent_id=agent.id,
        detail={
            "target_sub": sub,
            "owner_sub": owner_sub,
            "owner_email": owner_email,
            "display_name": display_name,
            "is_shared": is_shared,
            # Argus round 2, TECH-5786 PR follow-up: before the confirm_new_identity
            # wiring existed, a bypass of the sibling-fork guard was unreachable
            # from the provider layer; now it's a first-class parameter, and a
            # forensic audit must be able to distinguish a clean first
            # registration from a kill-switch bypass of a base_sub suspension.
            "confirm_new_identity": confirm_new_identity,
        },
    )
    await session.commit()
    return agent


async def register_agent(
    session: AsyncSession,
    *,
    sub: str,
    base_sub: str,
    owner_sub: str,
    owner_email: str,
    display_name: str,
    accepted_types: list[str] | None,
    min_schema_version: int = 1,
    max_schema_version: int = 1,
    is_shared: bool = False,
    is_shared_authorized: bool = False,
    confirm_new_identity: bool = False,
) -> Agent:
    """Idempotently create or re-bind the board ``Agent`` row for ``sub``.

    ``base_sub`` (TECH-5736) is the caller's verified identity BEFORE
    ``agent_key`` composition (``providers.comms._require_identity``'s
    result) -- ``sub`` is ``base_sub`` alone or ``f"{base_sub}::{agent_key}"``.
    Passed separately, not re-derived from ``sub``, so this function can
    check for SIBLING identities under the same ``base_sub`` without
    guessing where a ``"::"`` in ``sub`` came from. Raises
    ``SiblingIdentityExistsError`` on FIRST registration (a brand new
    ``sub``) if ``base_sub`` already has at least one OTHER registered row
    and ``confirm_new_identity`` is not ``True`` -- this is the actual
    incident this check exists to prevent: a caller that omits or typos
    ``agent_key`` on a later call doesn't re-bind its existing identity,
    it silently forks a new one, and nothing before this check ever
    surfaced that as an error. Re-registration of an ALREADY-existing
    ``sub`` never triggers this (idempotent re-binding is exactly the
    safe, intended path) -- it only guards the moment a genuinely new row
    is about to be created.

    Also raises ``DisplayNameCollisionError`` on first registration if
    ``display_name`` (case-insensitively) matches an existing board-
    ``active`` agent's -- see that exception's own docstring for why this
    is checked only on creation, not on every re-registration.

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
    agent ``active`` + refreshes ``bound_at`` -- UNLESS the existing row is
    currently ``status="suspended"`` (TECH-5736), in which case this raises
    ``AgentSuspendedError`` instead of touching the row at all: silently
    reactivating on re-registration would undo every
    ``comms_deregister_agent`` call on the very next ``comms_register`` from
    the same ``sub``. ``owner_sub`` is the
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

    ``accepted_types`` (TECH-5822 follow-up) now has three distinct
    meanings, resolved by ``_validate_display_name_and_accepted_types``
    and this function together -- security-relevant, so read carefully:

    - ``[]`` (explicitly passed empty): the opt-out "accept every message
      type, including any added in the future" sentinel. Applies on BOTH
      first registration and re-registration -- a caller that explicitly
      wants to widen an existing narrower agent back to accept-everything
      passes this.
    - a non-empty list: an explicit, deliberate restriction to exactly
      that set. Applies on both first registration and re-registration,
      same as before this follow-up.
    - ``None`` (the parameter omitted entirely): the accept-everything
      default on FIRST registration (equivalent to ``[]`` there) -- but on
      RE-registration, ``None`` leaves the existing row's ``accepted_types``
      COMPLETELY UNCHANGED rather than resetting it. This is deliberately
      NOT the same "omitting resets to the default" posture
      ``min_schema_version``/``max_schema_version`` use below: those two
      have no capability-restriction meaning, so resetting them to the
      default on every omitted call is harmless, but silently resetting
      an agent's deliberately-narrowed ``accepted_types`` to
      accept-everything just because a later re-registration call omitted
      the parameter would be a real, silent capability widening for that
      agent -- not merely a convenience default. A caller that wants to
      preserve its current declared set on a routine re-registration
      (e.g. a startup health-check re-register call) should omit the
      parameter; a caller that wants to actually change it must pass
      either an explicit non-empty list or an explicit ``[]``.

    Raises ``ValueError`` (not ``AccessDeniedError``) for malformed input --
    this is a data-validation failure, not an authorization decision (the
    caller has not claimed a resource yet). In validation order: empty ``sub``;
    empty or over-length (``schemas.MAX_DISPLAY_NAME_LENGTH``) ``display_name``;
    over-count (``schemas.MAX_ACCEPTED_TYPES``) ``accepted_types``; or (for a
    non-empty ``accepted_types``) any entry over-length
    (``schemas.MAX_ACCEPTED_TYPE_LENGTH``). An ``accepted_types`` containing a
    value outside ``MESSAGE_TYPES`` raises ``UnknownConversationTypeError``
    (exceptions.py) -- specific and client-safe by design, unlike the cases
    above; this check (like the per-entry length check) is skipped entirely
    for an empty list, since there is nothing to check.

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
    display_name, normalized_types = _validate_display_name_and_accepted_types(
        display_name, accepted_types
    )

    existing = (await session.execute(select(Agent).where(Agent.sub == sub))).scalar_one_or_none()
    now = _now()
    created = existing is None
    if existing is not None and existing.status == "suspended":
        # TECH-5736 (Argus round-1 finding): without this check, this
        # idempotent re-registration branch would unconditionally reset
        # `status` back to "active" a few lines below, silently reverting
        # every `comms_deregister_agent` call the moment the same `sub`
        # (often the exact misbehaving caller a deregistration was meant to
        # stop) called `comms_register` again -- undermining the entire
        # feature this ticket added, and breaking the display_name
        # collision invariant if a different agent had since claimed the
        # suspended agent's name (display_name is only checked `if
        # created`, and this path is a re-registration). See
        # `exceptions.AgentSuspendedError` for why there is no bypass here.
        await _deny_agent_suspended(session, sub=sub, agent_id=existing.id)
    if created and not confirm_new_identity:
        # TECH-5736: about to create a brand-new row for `sub` -- check
        # whether `base_sub` already has ANY other registered identity
        # first. This is the actual incident this check exists to catch:
        # omitting/typoing `agent_key` on a later call doesn't re-bind an
        # existing row (that path never reaches here -- `existing` would
        # be non-None), it silently creates a new one. `Agent.sub != sub`
        # is redundant given `existing is None` already means no row
        # equals `sub`, but kept explicit so this query's own intent (find
        # OTHER identities under this base_sub) doesn't depend on that
        # invariant holding. Deliberately NOT filtered to `status ==
        # "active"` (Argus round-1 suggestion S3, later reverted): an
        # earlier revision scoped this to active siblings only, on the
        # theory that a SUSPENDED sibling shouldn't permanently force
        # `confirm_new_identity=True`. That reasoning turned out to be
        # wrong -- it meant `comms_deregister_agent` (the kill-switch for a
        # stray/compromised identity) could be silently bypassed: suspend
        # every sibling under a `base_sub`, then register a brand-new
        # `agent_key` with zero *active* siblings found, sailing through
        # this guard unconfirmed. A `base_sub` with ANY prior identity --
        # active or suspended -- is exactly the silent-identity-churn
        # signal this guard exists to catch, so ALL rows (regardless of
        # status) count as siblings here. This intentionally does NOT
        # affect the display_name guard below, which is a different check
        # (case-insensitive display_name collision, not identity-fork
        # detection) and correctly keeps its own `status == "active"`
        # scoping -- nor does it affect re-registration of an agent's OWN
        # existing `sub` (active or suspended), which is a separate code
        # path entirely (`existing is not None`) and never reaches here.
        #
        # Accepted race (TECH-5736 suggestion, code-level only -- the
        # display_name guard is separately getting a DB unique index; this
        # sibling check is not): this is an application-level read-then-insert
        # check with no DB constraint backing it. Two concurrent
        # `register_agent` calls for genuinely new siblings under the same
        # `base_sub` (both omitting `confirm_new_identity`) could both read
        # zero existing siblings here, both pass this check, and both insert
        # their own new row before either commits -- silently recreating the
        # exact identity-fork this guard exists to catch, just for two rows
        # created in the same instant instead of two calls spaced apart. Not
        # closed by locking/a transaction here; documenting it rather than
        # implying the check is airtight.
        sibling_subs = (
            (
                await session.execute(
                    select(Agent.sub).where(
                        Agent.sub != sub,
                        or_(
                            Agent.sub == base_sub,
                            Agent.sub.startswith(f"{base_sub}::", autoescape=True),
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        if sibling_subs:
            await _deny_sibling_identity_exists(
                session,
                actor_sub=sub,
                base_sub=base_sub,
                sub=sub,
                existing_agent_keys=[_agent_key_from_sub(s, base_sub) for s in sibling_subs],
            )
    if created:
        # TECH-5736: same "about to create a new row" moment, but this
        # check is NOT gated on `confirm_new_identity` -- that flag means
        # "I intend to register a genuinely separate identity," not "I
        # intend to collide with another active agent's display_name."
        # See DisplayNameCollisionError's docstring for why this only
        # fires on creation, not on every re-registration.
        colliding_subs = (
            (
                await session.execute(
                    select(Agent.sub).where(
                        func.lower(Agent.display_name) == display_name.lower(),
                        Agent.status == "active",
                    )
                )
            )
            .scalars()
            .all()
        )
        if colliding_subs:
            await _deny_display_name_collision(
                session,
                actor_sub=sub,
                display_name=display_name,
                existing_subs=list(colliding_subs),
            )
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
        # First registration: None ("omitted") resolves to the
        # accept-everything default here -- there is no existing row's
        # accepted_types to preserve, so "no change requested" and "use
        # the default" are the same thing (see this function's own
        # docstring for why that equivalence does NOT hold on
        # re-registration, below).
        agent = Agent(
            sub=sub,
            owner_sub=owner_sub,
            owner_email=owner_email,
            display_name=display_name,
            accepted_types=normalized_types if normalized_types is not None else [],
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
            #
            # Committed immediately, standalone, rather than left staged
            # alongside the field mutations below (Argus round-4 finding):
            # this function's later `flush()` can raise `IntegrityError` on
            # a colliding `display_name`, and the handler for that
            # unconditionally `rollback()`s -- which would silently discard
            # this row too, letting an actor pair an `is_shared=True`
            # escalation probe with a colliding display_name to suppress
            # this audit entirely. Committing it here, before that flush,
            # means it survives regardless of what happens later in this
            # call. `expire_on_commit=False` (db.py) keeps `agent` usable
            # afterward without a refresh.
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
            await session.commit()
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
        # Re-registration: unlike every other field here, `None` ("omitted")
        # is NOT resolved to a default -- it leaves the existing row's
        # accepted_types untouched (security-relevant: see this function's
        # docstring). Only an explicit `[]` (accept-everything) or explicit
        # non-empty list (a deliberate restriction) overwrites it.
        if normalized_types is not None:
            agent.accepted_types = normalized_types
        agent.status = "active"
        agent.bound_at = now
        agent.min_schema_version = min_schema_version
        agent.max_schema_version = max_schema_version
    try:
        await session.flush()
    except IntegrityError as exc:
        # TECH-5736 (Argus round-2 finding): idx_agents_lower_display_name_active
        # (migration a45f344c9c00) is a UNIQUE partial index backing the
        # app-level display_name check above -- it exists precisely to
        # catch what that racy read-then-insert check can miss: (a) two
        # concurrent first-time registrations racing past the check with
        # the same display_name, or (b) a re-registration (line ~1477)
        # renaming onto a name a DIFFERENT active agent already holds,
        # which the check above never even queries for (it only runs
        # `if created`). Without this, either case surfaces as a raw,
        # unmapped IntegrityError (a 500) instead of the intended
        # DisplayNameCollisionError. Narrowed to THIS index by name --
        # not a blanket IntegrityError->DisplayNameCollisionError mapping
        # -- so an unrelated constraint violation still propagates as
        # itself rather than being mislabeled.
        await session.rollback()
        if _is_constraint_violation(exc, "idx_agents_lower_display_name_active"):
            # Unlike the app-level check's `colliding_subs`, the
            # DB-level violation itself doesn't hand us the other row's
            # `sub` -- only that a conflict exists. But the row IS now
            # queryable post-rollback (it's what the unique index just
            # rejected our write in favor of), so look it up instead of
            # recording "sub unknown" (Argus round-4 finding): a real
            # value here makes this audit path distinguishable from a
            # bug when reviewed later. `existing_subs` remains
            # server-side-audit-only (never surfaced to the caller, see
            # DisplayNameCollisionError's docstring). Fall back to `[]`
            # if a further race means the row is already gone again by
            # the time we look.
            colliding_subs_post_rollback = (
                (
                    await session.execute(
                        select(Agent.sub).where(
                            func.lower(Agent.display_name) == display_name.lower(),
                            Agent.status == "active",
                        )
                    )
                )
                .scalars()
                .all()
            )
            await _deny_display_name_collision(
                session,
                actor_sub=sub,
                display_name=display_name,
                existing_subs=list(colliding_subs_post_rollback),
            )
        raise
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


async def deregister_agent(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    deregister_authorized: bool,
) -> Agent:
    """Admin-gated deregistration: transitions ``agent.status`` to
    ``"suspended"`` (TECH-5736).

    Closes a gap the schema has always supported but nothing ever
    exercised: ``models.AGENT_STATUSES`` has included ``"suspended"``
    since the initial schema, but before this function NOTHING in this
    codebase ever wrote it -- ``lookup_agent_by_email``'s own docstring
    used to describe the ``status == "active"`` filter as "inert,
    future-proofing for deregistration rather than an enforced guarantee."
    A live incident needed exactly this (a stray, mis-registered row with
    no way to retire it) and found it didn't exist.

    Mirrors ``set_agent_shared``'s admin-gate shape exactly:
    ``deregister_authorized`` MUST be computed by the caller (the tools
    layer) from the actor's own verified token (``comms:admin`` scope, or
    an interactive/Okta caller) -- no default is provided, since this
    function's entire purpose is the privileged mutation and there is no
    unprivileged call site to protect with a fail-closed default.

    Idempotent: deregistering an already-``suspended`` agent is a no-op
    write (still audited) rather than an error -- safe to retry.

    Raises ``AccessDeniedError`` with reason
    ``denied.deregister_requires_elevated_scope`` if
    ``deregister_authorized`` is ``False`` (checked FIRST, before the
    existence lookup, so an unauthorized caller's audit trail always
    records the authorization failure, not ``denied.unknown_agent``,
    regardless of whether ``agent_id`` happens to be valid), or
    ``denied.unknown_agent`` if ``agent_id`` does not match any agent
    (uniform with every other unknown-agent-id denial in this module).

    Deliberately one-directional (suspend only, no reactivate path) --
    this repo has no reactivation use case yet; add one as its own
    change, with its own authorization gate, if that need arises rather
    than overloading this function with a ``status`` parameter now.
    """
    if not deregister_authorized:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.deregister_requires_elevated_scope",
            detail={"target_agent_id": str(agent_id)},
        )
    agent = await _find_agent_by_id(session, agent_id)
    if agent is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_agent",
            detail={"target_agent_id": str(agent_id)},
        )
    previous = agent.status
    agent.status = "suspended"
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="agent.deregistered",
        agent_id=agent.id,
        detail={"previous_status": previous},
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
    per this ticket's audit-trail requirement). Callers MUST page until
    ``has_more`` is false, not until ``agents`` is empty -- a page can
    return fewer than ``limit`` agents (including zero) while ``has_more``
    is still true, when every row on that page happens to be retired.
    ``active_checker.is_active`` failures fail open (see
    ``_is_active_safe``): worst case a retired agent stays briefly visible,
    never a directory outage.
    """
    limit = max(1, min(limit, 200))
    stmt = select(Agent).order_by(Agent.sub).limit(limit + 1)
    if cursor:
        stmt = stmt.where(Agent.sub > cursor)
    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    total_count = (await session.execute(select(func.count()).select_from(Agent))).scalar_one()
    active_flags = await asyncio.gather(*(_is_active_safe(active_checker, a.sub) for a in rows))
    visible_agents = [
        _agent_public(a) for a, is_active in zip(rows, active_flags, strict=True) if is_active
    ]
    return {
        "agents": visible_agents,
        "total_count": total_count,
        "has_more": has_more,
        "next_cursor": rows[-1].sub if has_more and rows else None,
    }


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
    "the" registered EA in any stronger sense. The ``status == "active"``
    filter excludes agents suspended via ``deregister_agent`` (TECH-5736) --
    before that function existed, nothing in this codebase ever transitioned
    an agent to ``"suspended"``, so this filter was inert; it is now live.
    TECH-5703's
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
    if not await _is_active_safe(active_checker, agent.sub):
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
    # Two passes, not one -- closes a side channel: if this loop denied AND
    # retirement-checked each target_id in the same pass, a caller with one
    # known-retired target Z could place an unknown target X before/after Z
    # in the list to learn whether X is unknown vs. retired, purely from
    # which exception came back. `_deny()` is `-> NoReturn`, so if we reach
    # pass 2 at all, every target_id already passed the existence/board-active
    # check in pass 1 -- pass 1 raises on the FIRST bad target_id it finds
    # (it does not scan the rest), but that's fine: no retirement check has
    # run yet at that point, so there is nothing for the raise's shape to
    # reveal about any other target_id in the list.
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
    for target_id in target_ids:
        # Safe unguarded lookup: pass 1 above raises (NoReturn) for any
        # target_id not in by_id, so every target_id reaching this line is
        # guaranteed present.
        target = by_id[target_id]
        if not await _is_active_safe(active_checker, target.sub):
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
    # TECH-5735: no `is_shared` participant may EVER be admitted to
    # `internal`, full stop -- not "admitted if its roster happens to be a
    # single owner right now." A shared agent's owner set is a roster that
    # can change (a member added/removed) after this conversation opens,
    # and `internal`'s whole risk model (BoundaryCrossingScorer treats
    # `internal` as never high risk, unconditionally, forever) depends on
    # open-time equality staying true for the conversation's entire life.
    # Re-checking live on every message send does NOT fix this: the
    # exposure isn't per-message, it's per-invite -- `comms_accept` grants
    # full conversation history to whoever is invited, so the moment a
    # participant is admitted it must already be treated as though it will
    # read every message that exists or ever will. A live per-send check
    # only gates the one `note` send it runs on; it does nothing about the
    # participant's standing ability to read everything else. Excluding
    # `is_shared` here (and at invite time, below) removes the only way
    # this invariant could ever become false post-admission, which is what
    # actually makes "never high risk by construction" true again.
    if conversation_type == "internal" and any(is_shared_by_id.values()):
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.shared_agent_not_allowed_internal",
            agent_id=initiator.id,
            detail={"conversation_type": conversation_type},
        )
    # The shared-initiator/shared-target admission bypass only applies to
    # `asymmetric` — the type `is_shared` exists to bridge (DESIGN.md §9).
    # `internal` requires every participant to share one owner set BY
    # CONSTRUCTION; letting either side skip that check would let it open an
    # `internal` conversation across disjoint owners, defeating the type's
    # invariant entirely (the `internal` exclusion above already forbids any
    # `is_shared` participant there at all, so this branch never reaches
    # `internal` in practice -- this comment states the invariant, not a
    # runtime distinction).
    #
    # A shared TARGET (not just a shared INITIATOR) also admits at open time
    # now: denying a non-shared sender outright with `denied.no_owner_overlap`
    # just because a shared agent's roster doesn't happen to overlap today
    # would silently drop traffic that should instead always be flagged for
    # human/auto-approval review. That review happens downstream, in
    # `plugins.BoundaryCrossingScorer.score`'s shared-recipient check (which
    # -- unlike this admission bypass -- always forces `high_risk=True`,
    # never bypasses review, even when the sender is also shared): this
    # function only decides whether the conversation is ADMITTED, not whether
    # any given send within it is reviewed. Both the shared-initiator and
    # shared-target cases admit identically here; they diverge only in the
    # scorer.
    shared_initiator = conversation_type == "asymmetric" and is_shared_by_id.get(
        initiator.id, False
    )
    shared_target = conversation_type == "asymmetric" and any(
        is_shared_by_id.get(target.id, False) for target in targets
    )
    shared_bypass = shared_initiator or shared_target
    # NOT gated on `shared_bypass` (Argus round 1, TECH-5786 PR follow-up):
    # `shared_bypass` is a whole-conversation flag ("at least one
    # participant is shared"), which would skip this check for every pair,
    # including pairs between two NON-shared participants with disjoint
    # owner sets. The per-pair shared exemption now lives inside
    # `_pairwise_admitted` itself (via `is_shared_by_id`), so this always
    # runs. Checked BEFORE the bypass audit event below (Argus round 2,
    # TECH-5786 PR follow-up): staging that event first, unconditionally on
    # `shared_bypass`, meant a denial from THIS check still committed
    # `agent.conversation_open_bypassed_shared` alongside the denial row --
    # an analyst querying that action would see a bypass recorded for a
    # conversation that was actually rejected outright.
    if not _pairwise_admitted(conversation_type, participants, owner_sets, is_shared_by_id):
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
            detail={
                "conversation_type": conversation_type,
                # If BOTH sides happen to be shared, "shared_initiator" wins
                # here for audit-detail purposes only -- admission is
                # identical either way, and the scorer (which is what
                # actually matters for review) always treats a shared
                # target/recipient as forcing review regardless of this
                # value.
                "bypass": "shared_initiator" if shared_initiator else "shared_target",
            },
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
            # TECH-5754: `targets` are the just-inserted `role="member",
            # status="invited"` participant rows above -- no query needed.
            # Sorted by `target.sub` (Argus round-2 catch), not left in
            # `targets`' own str(uuid) order (see the sort at target_ids'
            # de-dup above) -- matches the `.order_by(Agent.sub.collate("C"))`
            # the other two producer sites use, so a downstream ordering-sensitive
            # consumer (TECH-5755's LLM judge) sees one consistent key
            # across every hold type, not two different ones.
            participants=[
                ParticipantInfo(
                    agent_id=target.id,
                    display_name=target.display_name,
                    role="member",
                    status="invited",
                    sub=target.sub,
                )
                for target in sorted(targets, key=lambda t: t.sub)
            ],
            sender_sub=initiator.sub,
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

    Also denied, with the specific ``ConversationArchivedError`` (TECH-5887),
    if the conversation has been archived (``comms_archive_conversation``)
    since this invite was sent. Judgment call, documented here rather than
    left implicit: an invite accepted after archiving would admit a brand
    new ACTIVE participant with full retroactive history read -- the exact
    outcome archiving a conversation is meant to close off, same as a fresh
    ``comms_invite`` -- so accept is blocked the same way rather than left
    as a loophole. This does leave a pending invite sent before archiving
    permanently un-acceptable (there is no path to convert it into anything
    else); ``comms_decline_invite`` remains available since declining only
    narrows access, never grants it.
    """
    conversation, participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=agent_id,
        conversation_id=conversation_id,
        required_status="invited",
    )
    if conversation.archived_at is not None:
        await _deny_archived(
            session,
            actor_sub=actor_sub,
            agent_id=agent_id,
            conversation_id=conversation.id,
            action="denied.archived.accept",
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

    TECH-5735: an ``is_shared`` target may never be invited into an
    ``internal`` conversation, full stop -- the same admission-time
    exclusion ``_authorize_conversation_open`` enforces at open. A shared
    agent's owner set is a roster that can change later, which would
    silently break `internal`'s "one owner, by construction" invariant
    for a conversation that already trusted it; excluding shared agents
    here closes the same hole at the other admission point.

    The admitted-vs-frozen-snapshot predicate matches each type's own
    admission rule (TECH-5735): ``internal`` requires the target's owner
    set to EQUAL the snapshot (mirroring ``_pairwise_admitted``'s
    equality check — the snapshot is a union of already-equal sets, so
    equality to it is equality to every existing participant); a bare
    subset let a strict-subset target into an `internal` conversation
    without ever satisfying the equality invariant `internal` is supposed
    to guarantee. ``asymmetric`` keeps the original subset check.

    Fails closed on any lookup error -- ``denied.ownership_lookup_failed``
    for a raised exception (transient: registry timeout/5xx), distinct
    from ``denied.ownership_unverified`` below for a successful lookup
    that returns an empty owner set (deterministic: an orphaned agent that
    will never resolve itself). ``decide_hold``'s invite re-validation path
    relies on this distinction to decide whether a denial here should
    strand-resolve the hold or leave it retriable.
    """
    if conversation.type == "open":
        return
    try:
        target_info = await ownership_client.get_agent_owners(target.id)
    except Exception as exc:
        logger.warning(
            "ownership lookup failed authorizing an invite: %s",
            type(exc).__name__,
            exc_info=True,
        )
        await _deny(
            session,
            actor_sub=actor_sub,
            action=_DENIED_OWNERSHIP_LOOKUP_FAILED,
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target.id)},
        )
    target_owners = frozenset(target_info.get("owners") or [])
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
    if conversation.type == "internal" and target_info.get("is_shared"):
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.shared_agent_not_allowed_internal",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target.id)},
        )
    snapshot_owners = frozenset((conversation.owner_snapshot or {}).get("owners") or [])
    # No legacy-data migration needed for this equality predicate:
    # `_pairwise_admitted` has required exact owner-set equality for every
    # pair of `internal` participants at OPEN time since `internal` was
    # introduced, not just as of this ticket. This invite-time check is
    # just applying that same, already-true-at-open invariant to a NEW
    # target -- there is no earlier era where a strict-subset target could
    # have opened an `internal` conversation for this check to now
    # retroactively conflict with.
    #
    # Deliberately NOT mirroring `_authorize_conversation_open`'s
    # shared-target admission bypass here (Argus round 1, TECH-5786 PR
    # follow-up, wording corrected in round 2): `comms_accept` grants the
    # invitee full RETROACTIVE read of every message that predates this
    # invite (see `_conversation_has_note_history`'s docstring) -- messages
    # sent from THIS invite onward ARE already covered by
    # `plugins.BoundaryCrossingScorer`'s shared-recipient check, since
    # `_check_boundary_crossing`'s "other" set includes `invited`, not just
    # `active`, participants (see that function's own docstring). The gap
    # this bypass would reopen is specifically the conversation's PRE-EXISTING
    # history, which no per-message check -- past or future -- can retroactively
    # cover. A bypass here would let an
    # `is_shared` target with a disjoint owner set read an entire existing
    # `asymmetric` conversation with no hold and no audit event, reopening
    # the exact per-invite exposure `internal`'s exclusion above (and this
    # function's own docstring) was written to close. If a shared-target
    # invite bypass is wanted later, it needs its own dedicated gate (e.g.
    # requiring an explicit hold, or checking the conversation's message
    # history), not a copy of the open-time bypass.
    admitted = (
        target_owners == snapshot_owners
        if conversation.type == "internal"
        else target_owners <= snapshot_owners
    )
    if not admitted:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.owner_set_frozen",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"target_agent_id": str(target.id)},
        )


async def _conversation_has_note_history(session: AsyncSession, conversation_id: uuid.UUID) -> bool:
    """Has any free-text message (``plugins.BARRIER_SENSITIVE_TYPES`` --
    ``note``, or ``instruction_share``'s doc-backed ``text``, TECH-5822)
    ever been posted to this conversation? Used by ``invite`` (TECH-5735)
    to decide whether admitting a new participant requires human approval
    first -- ``comms_accept`` grants full retroactive history read the
    moment a participant is admitted, and free text can't be structurally
    guaranteed safe the way ownership equality can (see
    ``_authorize_conversation_open``'s ``is_shared`` exclusion), so the
    check has to run at invite time, treating the invitee as though it
    will read every barrier-sensitive message that already exists.

    Deliberately checks ``plugins.BARRIER_SENSITIVE_TYPES`` (not a
    separately-maintained set) so this gate can never silently miss a type
    that ``BoundaryCrossingScorer`` itself already treats as free-text-risky
    -- the two lists staying in lockstep is exactly the property that broke
    when this function was still hardcoded to ``Message.type == "note"``
    and ``instruction_share`` joined ``BARRIER_SENSITIVE_TYPES`` without a
    matching update here (TECH-5822 Argus round 1 BLOCKING finding: an
    ``internal`` conversation's ``instruction_share`` history was invisible
    to this gate, so inviting a new participant into it skipped human
    approval despite exposing unreviewed free text via
    ``comms_accept``'s retroactive read).
    """
    return (
        await session.execute(
            select(Message.id)
            .where(
                Message.conversation_id == conversation_id,
                Message.type.in_(BARRIER_SENSITIVE_TYPES),
            )
            .limit(1)
        )
    ).first() is not None


async def invite(
    session: AsyncSession,
    *,
    actor_sub: str,
    inviter_agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
    target_agent_id: uuid.UUID,
    ownership_client: OwnershipClient,
    active_checker: ActiveChecker,
    auto_approver: AutoApprover,
    notifier: ApprovalNotifier,
    owner_sub_claim: str | None = None,
) -> Participant | ApprovalHold:
    """Add ``target_agent_id`` to a conversation as a new ``invited`` row —
    or, if the conversation already has free-text (``note``) history,
    divert to an ``approval_holds`` row instead (TECH-5735; see
    ``_divert_invite_for_approval``). Check ``held_for_approval``-shaped
    callers via ``isinstance(result, ApprovalHold)``, same convention as
    ``post_message``/``start_conversation``.

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

    Raises ``ConversationArchivedError`` (TECH-5887) if the conversation has
    been archived (``comms_archive_conversation``) -- checked before the
    ordinary ``state != "active"`` check, and given its own specific
    message rather than folding into ``InvalidConversationStateError``, so
    a caller can tell "this conversation is archived" apart from "this
    conversation reached a terminal state" even though both currently
    block every new invite the same way.
    """
    conversation, inviter_participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=inviter_agent_id,
        conversation_id=conversation_id,
        required_status="active",
        # TECH-5735: locks the CONVERSATION row (not the participant row --
        # `_load_participant_for_transition` only ever applies `for_update`
        # to its `_find_conversation` call) for the duration of this call,
        # so a concurrent `post_message` can't insert a `note` between the
        # `_conversation_has_note_history` check below and this invite's
        # commit -- without the lock, two concurrent invites (or an invite
        # racing a note post) could both observe "no note history yet" and
        # admit the target immediately, bypassing the approval hold.
        for_update=True,
    )
    if not may_invite(inviter_participant.status):  # pragma: no cover — v1 always True here
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.invite_not_allowed",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
        )
    if conversation.archived_at is not None:
        await _deny_archived(
            session,
            actor_sub=actor_sub,
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            action="denied.archived.invite",
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
    if not await _is_active_safe(active_checker, target.sub):
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

    # TECH-5735: admitting `target` grants it full retroactive history read
    # the moment it later calls comms_accept -- if any note (free-text)
    # message already exists in this conversation, treat the invite itself
    # as though target will read it, and require human approval first.
    if await _conversation_has_note_history(session, conversation.id):
        # Same submission-spam control post_message/start_conversation use
        # (_deny_rate_limited_holds) -- an inviter flooding the human
        # approval queue with invite-holds is still capped, same as one
        # flooding it with high-risk messages.
        await _deny_rate_limited_holds(
            session, actor_sub=actor_sub, sender_agent_id=inviter_agent_id
        )
        inviter = await _require_active_agent(
            session, actor_sub=actor_sub, agent_id=inviter_agent_id
        )
        result = await _divert_invite_for_approval(
            session,
            actor_sub=actor_sub,
            conversation=conversation,
            inviter_agent_id=inviter_agent_id,
            target_agent_id=target.id,
            target_display_name=target.display_name,
            owner_sub_claim=owner_sub_claim,
            owner_sub_fallback=inviter.owner_sub,
            auto_approver=auto_approver,
            sender_sub=inviter.sub,
        )
        await session.commit()
        if isinstance(result, ApprovalHold):
            await _fire_approval_notifier(
                session, hold=result, conversation=conversation, sender=inviter, notifier=notifier
            )
        return result

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


async def archive_conversation(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    conversation_id: uuid.UUID,
) -> Conversation:
    """Archive a conversation: sets ``archived_at``, a whole-conversation,
    symmetric-permission action (TECH-5887) -- distinct from ``leave``,
    which only ever affects the CALLING participant's own row.

    Any CURRENTLY ``active`` participant may archive the conversation, not
    just its ``owner`` role or its ``created_by`` agent -- "any agent in the
    chain" per the feature ask. Requires ``required_status="active"``, the
    same precondition ``leave``/``post_message``/``invite`` all share: an
    ``invited``-but-not-yet-accepted, ``left``, or ``declined`` participant
    (or a non-participant) gets the uniform ``AccessDeniedError``, exactly
    as any other write against this conversation would.

    Idempotent: archiving an already-archived conversation is a no-op that
    succeeds silently (returns the conversation unchanged, does NOT bump
    ``archived_at`` to now, and writes no additional
    ``conversation.archive`` audit row) rather than raising. This is a
    deliberate simplicity choice, not an oversight: archiving carries no
    parameters and has no observable side effect beyond "this conversation
    is now archived", so a second call from a different (or the same)
    participant discovering it's already archived has nothing useful to
    report as an error, and an idempotent success is what lets a client
    retry blindly on a timeout without first checking current state. A
    denial here would also be a mild enumeration/state leak for no
    corresponding safety benefit -- unlike, say, ``comms_invite``'s
    ``denied.already_participant``, there is no "wrong actor" case being
    guarded against.

    No transition out of ``archived_at`` is supported (no "unarchive" tool)
    -- v1 keeps archiving strictly one-directional, mirroring
    ``comms_deregister_agent``'s own one-directional design (see that
    tool's docstring). Add a reactivation path later, with its own
    authorization gate, if a real need for one arises. A mistaken archive
    has no in-band recovery today: every still-``invited`` participant's
    pending invite becomes permanently un-acceptable too (see
    ``accept_invite``'s own docstring) -- the only path forward is a fresh
    ``comms_start_conversation``.

    Deliberately does NOT touch ``conversation.state`` -- archiving is
    orthogonal to the state machine (see ``models.Conversation.archived_at``'s
    own docstring): an ``active`` conversation stays stored as ``active``
    after being archived (``comms_invite``/``comms_post_message`` block on
    ``archived_at`` directly, not by forcing a terminal state), and an
    already-``completed``/``canceled``/``expired`` conversation may also be
    archived (there is no precondition on ``state`` at all) since archiving
    is purely about hiding a conversation from active use, not describing
    how it ended.

    Read paths (``comms_get_conversation``, ``comms_inbox``,
    ``comms_list_conversations``) are completely unaffected by this call --
    archiving is not a delete or a redaction, every past message remains
    exactly as readable as before.
    """
    conversation, _participant = await _load_participant_for_transition(
        session,
        actor_sub=actor_sub,
        agent_id=agent_id,
        conversation_id=conversation_id,
        required_status="active",
        # TECH-5887: locks the conversation row for the duration of this
        # call so two concurrent archivers can't both observe
        # `archived_at IS NULL`, both write it, and both emit a
        # `conversation.archive` audit row -- which would violate the
        # idempotent-no-op guarantee documented above. Same pattern as
        # `invite`'s TECH-5735 lock above.
        for_update=True,
    )
    if conversation.archived_at is not None:
        # Idempotent no-op (see docstring) -- no audit row, no archived_at
        # bump, just hand back the already-archived row.
        await session.commit()
        return conversation
    conversation.archived_at = _now()
    _audit(
        session,
        actor_sub=actor_sub,
        action="conversation.archive",
        agent_id=agent_id,
        conversation_id=conversation.id,
    )
    await session.commit()
    return conversation


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

    An empty ``accepted_types`` list is the opt-out "accept everything"
    sentinel (TECH-5822 follow-up), not "accept nothing" — a recipient
    with an empty list never fails this check, for any ``message_type``,
    including one that doesn't exist yet in ``schemas.MESSAGE_TYPES`` at
    the time this recipient registered. A non-empty list still restricts
    to exactly that explicit set, same as before.

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
        if accepted and message_type not in accepted:
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
) -> tuple[str | None, list[ParticipantInfo]]:
    """``_score_message_risk`` (+ the universal ``accepted_types``
    capability gate) for an existing conversation row — queries current
    (``active``/``invited``) participants for the other side rather than
    requiring the caller to already know them.

    Returns ``(risk_reason, participants)`` -- ``participants`` (TECH-5754)
    is this same query's rows, reshaped into ``ParticipantInfo``, for the
    caller to thread into ``HoldContext`` on a diversion; it is NOT a
    second query.

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
            select(
                Participant.agent_id,
                Participant.status,
                Participant.role,
                Agent.accepted_types,
                Agent.display_name,
                Agent.sub,
            )
            .join(Agent, Agent.id == Participant.agent_id)
            .where(
                Participant.conversation_id == conversation.id,
                Participant.agent_id != sender_agent_id,
                Participant.status.in_(("active", "invited")),
            )
            # Deterministic HoldContext.participants ordering (TECH-5754
            # Argus round-1 catch) -- without this, identical holds could
            # see different participant orderings across requests, causing
            # prompt-cache misses (and potentially unstable judgments) for
            # a downstream LLM-judge AutoApprover consuming this field.
            # collate("C") (Argus round-3 catch): plain .order_by(Agent.sub)
            # sorts under Postgres's configured locale, which can order
            # mixed-case subs differently than start_conversation's Python
            # `sorted(targets, key=lambda t: t.sub)` (always codepoint
            # order) -- pinning the SQL side to byte/codepoint order keeps
            # every HoldContext.participants producer path on the exact
            # same comparator. NOTE (Argus round-4 catch): this does NOT
            # match get_hold_conversation_participants/get_conversation
            # below, which query without a COLLATE pin -- see
            # TECH-5389-APPROVAL-PIPELINE.md's participants section.
            .order_by(Agent.sub.collate("C"))
        )
    ).all()
    other_ids = [agent_id for agent_id, _status, _role, _accepted, _display_name, _sub in rows]
    capability_others = [
        (agent_id, accepted)
        for agent_id, status, _role, accepted, _display_name, _sub in rows
        if status == "active"
    ]
    participants = [
        ParticipantInfo(
            agent_id=agent_id, display_name=display_name, role=role, status=status, sub=sub
        )
        for agent_id, status, role, _accepted, display_name, sub in rows
    ]
    await _enforce_message_type_accepted(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation_id=conversation.id,
        other_agents=capability_others,
        message_type=message_type,
    )
    risk_reason = await _score_message_risk(
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
    return risk_reason, participants


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
    participants: list[ParticipantInfo],
    sender_sub: str,
    extra_audit_detail: dict[str, Any] | None = None,
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

    ``participants`` (TECH-5754) is passed straight through into
    ``HoldContext.participants`` -- the caller already resolved it (from
    ``_check_boundary_crossing``'s own participants-join for
    ``post_message``, or from the just-loaded ``targets`` for
    ``start_conversation``), so this function does not query for it itself.

    ``sender_sub`` (TECH-5755) is likewise passed straight through into
    ``HoldContext.sender_sub`` -- the caller's own already-loaded sender
    ``Agent`` row (``sender.sub``/``initiator.sub``), no extra query.

    ``extra_audit_detail`` (TECH-5786) is merged into the ``approval.hold``
    audit entry's ``detail`` dict, not stored anywhere else -- the reuse of
    one action name across every ``risk_reason`` value (this ticket's
    ``"agent_requested"`` included) is the existing, deliberate pattern per
    DESIGN.md's audit contract, so this is additive detail on that same
    entry, not a new action.
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
    # TECH-5786 Argus round-1 SUGGESTION catch: an agent-requested hold uses
    # a fixed non-plugin label, not the injected RiskScorer's own name --
    # the scorer never emitted this hold, so attributing it to the scorer
    # would misattribute it in any dashboard grouping by risk_scorer. Mirrors
    # INVITE_HOLD_RISK_SCORER_LABEL's existing precedent above. The scorer's
    # own verdict, if any, is preserved separately in extra_audit_detail.
    hold_risk_scorer = (
        AGENT_REQUESTED_RISK_SCORER_LABEL
        if risk_reason == AGENT_REQUESTED_RISK_REASON
        else scorer_name
    )
    hold = ApprovalHold(
        conversation_id=conversation.id,
        sender_agent_id=sender_agent_id,
        kind="message",
        owner_sub=hold_owner_sub,
        message_type=message_type,
        schema_version=schema_version,
        payload=payload,
        risk_reason=risk_reason,
        risk_scorer=hold_risk_scorer,
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
            # extra_audit_detail unpacked FIRST (Argus round-1 SUGGESTION
            # catch): the fixed keys below are authoritative and must win
            # over anything a caller-supplied extra_audit_detail happens to
            # collide with, not be silently overwritten by it.
            **(extra_audit_detail or {}),
            "hold_id": str(hold.id),
            "risk_reason": risk_reason,
            "risk_scorer": hold_risk_scorer,
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
        participants=participants,
        sender_sub=sender_sub,
    )
    decision = await auto_approver.review(ctx)
    if risk_reason == AGENT_REQUESTED_RISK_REASON:
        # TECH-5786 Argus round-1 BLOCKING catch: the AutoApprover still runs
        # above (for its own side effects/telemetry, same as the RiskScorer
        # running unconditionally for _enforce_message_type_accepted), but an
        # agent-requested hold's whole purpose is to reach a human -- an
        # AutoApprover that special-cases some other risk_reason (or one that
        # clears everything, e.g. a future LLM-judge approver) must not be
        # able to auto-clear this one. Enforced structurally here, not left
        # to every AutoApprover implementation to remember.
        decision = decision._replace(cleared=False)
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


async def _divert_invite_for_approval(
    session: AsyncSession,
    *,
    actor_sub: str,
    conversation: Conversation,
    inviter_agent_id: uuid.UUID,
    target_agent_id: uuid.UUID,
    target_display_name: str,
    owner_sub_claim: str | None,
    owner_sub_fallback: str,
    auto_approver: AutoApprover,
    sender_sub: str,
) -> Participant | ApprovalHold:
    """TECH-5735: create a ``kind="invite"`` ``approval_holds`` row, run the
    injected ``AutoApprover`` inline, and either create the ``Participant``
    row atomically (cleared) or escalate to ``pending_human`` (v1's
    ``EscalateAllAutoApprover``: always). Mirrors
    ``_divert_high_risk_message``'s shape exactly, but for an invite rather
    than a message — see ``ApprovalHold``'s class docstring for the field
    mapping (``sender_agent_id`` is the INVITER here, not a message sender).

    Caller MUST have already run every other invite gate (membership,
    state, target validity, retirement check, schema-version recheck,
    owner-freeze, already-participant check) — this function performs no
    authorization of its own, only the hold/participant bookkeeping.
    Returns the inserted ``Participant`` (cleared) or the ``ApprovalHold``
    itself (escalated — caller commits and then fires the notifier
    post-commit, per ``_fire_approval_notifier``'s docstring).

    ``sender_sub`` (TECH-5755) is the INVITER's own sub, not the target's --
    passed straight through into ``HoldContext.sender_sub`` from the
    caller's already-loaded ``inviter`` ``Agent`` row, no extra query.
    """
    now = _now()
    hold_owner_sub = owner_sub_claim if owner_sub_claim is not None else owner_sub_fallback
    hold = ApprovalHold(
        conversation_id=conversation.id,
        sender_agent_id=inviter_agent_id,
        target_agent_id=target_agent_id,
        kind="invite",
        owner_sub=hold_owner_sub,
        message_type=INVITE_HOLD_MESSAGE_TYPE,
        schema_version=INVITE_HOLD_SCHEMA_VERSION,
        payload={
            "target_agent_id": str(target_agent_id),
            "target_display_name": target_display_name,
        },
        risk_reason=INVITE_HOLD_RISK_REASON,
        risk_scorer=INVITE_HOLD_RISK_SCORER_LABEL,
        status="pending_auto",
        expires_at=now + APPROVAL_HOLD_TTL,
    )
    session.add(hold)
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="approval.hold",
        agent_id=inviter_agent_id,
        conversation_id=conversation.id,
        detail={
            "hold_id": str(hold.id),
            "risk_reason": INVITE_HOLD_RISK_REASON,
            "kind": "invite",
            "target_agent_id": str(target_agent_id),
        },
    )

    approver_name = _auto_approver_name(auto_approver)
    hold.auto_approver = approver_name
    # TECH-5754: unlike _divert_high_risk_message's two call sites, neither
    # caller of this function already has the conversation's current
    # participants loaded (only the not-yet-admitted `target`) -- one
    # query, same active/invited shape _check_boundary_crossing uses.
    participant_rows = (
        await session.execute(
            select(Agent.id, Participant.status, Participant.role, Agent.display_name, Agent.sub)
            .join(Agent, Agent.id == Participant.agent_id)
            .where(
                Participant.conversation_id == conversation.id,
                Participant.agent_id != inviter_agent_id,
                Participant.status.in_(("active", "invited")),
            )
            # Deterministic ordering (TECH-5754 Argus round-1 catch), pinned
            # to codepoint order (Argus round-3 catch) -- see
            # _check_boundary_crossing's matching .order_by(Agent.sub.collate("C")).
            .order_by(Agent.sub.collate("C"))
        )
    ).all()
    ctx = HoldContext(
        hold_id=hold.id,
        conversation_id=conversation.id,
        conversation_type=conversation.type,
        sender_agent_id=inviter_agent_id,
        owner_sub=hold_owner_sub,
        message_type=INVITE_HOLD_MESSAGE_TYPE,
        schema_version=INVITE_HOLD_SCHEMA_VERSION,
        payload=hold.payload,
        risk_reason=INVITE_HOLD_RISK_REASON,
        participants=[
            ParticipantInfo(
                agent_id=agent_id, display_name=display_name, role=role, status=status, sub=sub
            )
            for agent_id, status, role, display_name, sub in participant_rows
        ],
        sender_sub=sender_sub,
    )
    decision = await auto_approver.review(ctx)
    if decision.cleared:
        participant = Participant(
            conversation_id=conversation.id,
            agent_id=target_agent_id,
            role="member",
            status="invited",
            invited_by=inviter_agent_id,
            joined_at=None,
        )
        session.add(participant)
        await session.flush()
        hold.status = "auto_approved"
        hold.auto_decision = "cleared"
        hold.auto_decided_at = _now()
        system_actor = f"system:auto_approver/{approver_name}"
        _audit(
            session,
            actor_sub=system_actor,
            action="approval.auto_approve",
            agent_id=inviter_agent_id,
            conversation_id=conversation.id,
            detail={"hold_id": str(hold.id)},
        )
        _audit(
            session,
            actor_sub=system_actor,
            action="participant.invite",
            agent_id=target_agent_id,
            conversation_id=conversation.id,
            detail={"invited_by_agent_id": str(inviter_agent_id), "hold_id": str(hold.id)},
        )
        participant.auto_approved_hold_id = hold.id  # type: ignore[attr-defined]
        return participant

    hold.status = "pending_human"
    hold.auto_decision = "escalated"
    hold.auto_decided_at = _now()
    _audit(
        session,
        actor_sub=actor_sub,
        action="approval.escalate",
        agent_id=inviter_agent_id,
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
    session: AsyncSession, *, actor_sub: str, surface: str = "approval"
) -> None:
    """Audit + commit ``denied.<surface>_requires_interactive`` -- the hard
    interactive-token-only gate ``main.py`` reuses across two distinct HTTP
    surfaces: ``/approvals/*`` (``surface="approval"``, the default) and
    ``GET /proposals/pending`` (``surface="proposals"``). Argus review S6:
    both surfaces used to write the SAME action name
    (``denied.approval_requires_interactive``), making them indistinguishable
    in the audit trail even though they gate different resources -- the
    caller now threads its own surface through. Unlike every other denial
    in this module, the caller here (``main.py``, a non-MCP
    ``mcp.custom_route`` handler) has no board ``Agent``/conversation
    context at all -- there is nothing to raise (the HTTP handler decides
    its own 403 response), only an audit row to persist so the denial is
    still recorded per this module's "every denial is audited" invariant.
    """
    _audit(session, actor_sub=actor_sub, action=f"denied.{surface}_requires_interactive")
    await session.commit()


# Argus review S10: ``reason`` is interpolated directly into the audit
# action string below, and this function is exported in __all__, so an
# unchecked arbitrary str could write an arbitrary ``denied.proposal_submit_*``
# action name into the audit log. Allowlisted the same way
# ``validate_hold_level`` allowlists its own membership check --
# "not_agent_token"/"missing_scope" are the two 403 causes in
# ``main._authenticate_proposal_submitter``; "rate_limited" covers the
# rate-limit denial path for callers that route through this function.
ALLOWED_DENIAL_REASONS = frozenset({"not_agent_token", "missing_scope", "rate_limited"})


async def audit_denied_proposal_submission(
    session: AsyncSession, *, actor_sub: str, reason: str
) -> None:
    """Audit + commit a ``POST /proposals`` submission denial (TECH-5872,
    Argus review S5) -- the two 403 causes in ``main._authenticate_
    proposal_submitter`` (``reason="not_agent_token"`` for an
    interactive/unverifiable-as-agent caller, ``reason="missing_scope"`` for
    a verified agent-jwt token lacking ``PROPOSAL_SUBMIT_SCOPE``). Same "no
    board Agent/conversation context" shape as
    ``audit_denied_approval_requires_interactive`` above -- there is nothing
    to raise, only an audit row to persist.
    """
    assert reason in ALLOWED_DENIAL_REASONS, f"unexpected denial reason: {reason!r}"
    _audit(session, actor_sub=actor_sub, action=f"denied.proposal_submit_{reason}")
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
    if hold.kind == "invite" and hold.target_agent_id is not None:
        # Mirrors message_seq above -- once decided, surface the outcome
        # this hold actually produced (a Participant row, not a Message).
        participant_status = (
            await session.execute(
                select(Participant.status).where(
                    Participant.conversation_id == hold.conversation_id,
                    Participant.agent_id == hold.target_agent_id,
                )
            )
        ).scalar_one_or_none()
        if participant_status is not None:
            result["participant_status"] = participant_status
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


async def get_hold_conversation_participants(
    session: AsyncSession, *, approver_sub: str, hold_id: uuid.UUID
) -> dict[str, Any]:
    """``GET /approvals/{hold_id}/conversation`` (main.py, non-MCP,
    interactive+owner-gated): the participant list for one pending hold's
    conversation, for the decision page's "To" display (TECH-5751).

    Same ownership gate as ``decide_hold`` (uniform ``AccessDeniedError``,
    ``denied.unknown_hold`` / ``denied.hold_not_owner`` -- the caller's
    verified sub must equal the hold's own ``owner_sub`` snapshot, not a
    live join), but deliberately narrower than ``get_conversation``:
    read-only participant metadata only, no message content, and no
    ``last_read_seq`` mutation -- a human glancing at "who is this message
    to" must never advance an AGENT's own read cursor as a side effect.

    Scoped to a still-``pending_human`` hold, mirroring ``decide_hold``'s
    own status gate (and its ``for_update=True`` lock on ``_find_hold`` --
    without it, this read-then-write-status call can race a concurrent
    ``decide`` and lose-update its just-approved/rejected row back to
    ``expired``): raises ``HoldExpiredError`` if lazy TTL expiry fires on
    this touch, ``HoldAwaitingAutoReviewError`` if still ``pending_auto``
    (unreachable in v1), and ``HoldAlreadyDecidedError`` if already
    approved/rejected -- the "To" list is for a hold a human is actively
    about to decide, not a stale snapshot of one that already resolved
    (the very next ``decide`` call would 410/409/409 on it anyway). Only
    ``active``/``invited`` participants are returned -- a
    ``left``/``declined`` agent is no longer a real recipient, and showing
    one would mislead the approving human about who the message is
    actually going to.
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

    conversation = await _find_conversation(session, hold.conversation_id)
    if conversation is None:
        raise RuntimeError(f"invariant violation: hold {hold_id} references a missing conversation")

    part_rows = (
        await session.execute(
            select(Participant, Agent)
            .join(Agent, Agent.id == Participant.agent_id)
            .where(
                Participant.conversation_id == hold.conversation_id,
                Participant.status.in_(("active", "invited")),
            )
            .order_by(Agent.sub)
        )
    ).all()
    participants = [
        {
            "agent_id": str(a.id),
            "display_name": a.display_name,
            "role": p.role,
            "status": p.status,
        }
        for p, a in part_rows
    ]
    await session.commit()
    return {"conversation_id": str(hold.conversation_id), "participants": participants}


async def decide_hold(
    session: AsyncSession,
    *,
    approver_sub: str,
    hold_id: uuid.UUID,
    decision: str,
    reason: str | None,
    ownership_client: OwnershipClient,
    active_checker: ActiveChecker,
) -> dict[str, Any]:
    """``POST /approvals/{hold_id}/decide`` (main.py, non-MCP,
    interactive+owner-gated). ``decision`` is ``"approve"`` or ``"reject"``.

    ``ownership_client``/``active_checker`` are used ONLY by the
    ``kind="invite"`` approval path (below) -- a hold can sit
    ``pending_human`` for up to ``APPROVAL_HOLD_TTL`` (7 days), during
    which the target could be retired, have its ``is_shared`` flag
    flipped, or have its owner set change. Approval re-runs the target
    status/retirement check and ``_authorize_invite_owner_freeze`` --
    the two gates whose drift this ticket (TECH-5735) is specifically
    about -- so none of THAT drift can slip a target into an ``internal``
    conversation it would no longer qualify for. It does NOT re-run
    ``invite()``'s schema-version pin check (an agent could re-register
    with a narrower ``[min_schema_version, max_schema_version]`` range
    during the pending window) or re-verify that ``hold.sender_agent_id``
    is still an active participant (the inviter could have left or been
    declined in the interim) -- both accepted as out of scope for this
    ticket's fix, not silently overlooked. The ``kind="message"`` path
    takes neither parameter — it only re-runs ``accepted_types`` (see
    below), which needs neither seam.

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
    ``ConversationArchivedError`` (audited ``denied.archived.decide_hold``,
    TECH-5887) if the conversation has been archived -- checked before the
    state check above, same "hold stays pending_human" behavior.

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
    if conversation.archived_at is not None:
        # TECH-5887: a hold can sit pending_human for up to
        # APPROVAL_HOLD_TTL (7 days) -- without this check, approving a
        # message-kind hold after the conversation was archived would
        # still insert a new message via _insert_message_for_hold, and
        # approving an invite-kind hold would still admit a new
        # Participant, both directly violating archive_conversation's "no
        # new invites, no new messages" guarantee. Same pattern as the
        # state != "active" check below: the hold stays pending_human (the
        # human can still reject it with a reason), it just can't be
        # approved into an archived conversation. Applies to both
        # hold.kind == "message" and hold.kind == "invite" -- checked here,
        # before the kind-specific branches below, rather than duplicated
        # in each. Checked BEFORE the state check (matching invite/
        # post_message/accept_invite's ordering): _maybe_expire above can
        # flip conversation.state to "expired" on this same call if the
        # deadline just passed, and if the state check ran first it would
        # raise InvalidConversationStateError before this archived check
        # ever got a chance to run, surfacing the wrong error/audit row.
        # Note: a conversation that is both terminal (completed/canceled)
        # and archived surfaces conversation_archived rather than
        # conversation_not_active -- archived is the more actionable
        # signal.
        await _deny_archived(
            session,
            actor_sub=approver_sub,
            agent_id=hold.sender_agent_id,
            conversation_id=conversation.id,
            action="denied.archived.decide_hold",
        )
    if conversation.state != "active":
        await _deny_bad_state(
            session,
            actor_sub=approver_sub,
            agent_id=hold.sender_agent_id,
            conversation_id=conversation.id,
            current_state=conversation.state,
            message_type=hold.message_type,
        )

    if hold.kind == "invite":
        # TECH-5735: approving an invite-hold creates the Participant row
        # this hold diverted, not a Message -- see ApprovalHold's class
        # docstring. hold.sender_agent_id is the INVITER here.
        if hold.target_agent_id is None:
            raise RuntimeError(f"invariant violation: invite hold {hold_id} has no target_agent_id")
        existing = await _find_participant(session, conversation.id, hold.target_agent_id)
        if existing is not None:
            # Someone else already admitted this target through a
            # different path while this hold sat pending_human. Unlike
            # `invite`'s own identical check, this hold is a resolvable
            # entity in its own right -- leaving it `pending_human` after
            # this race (via the uniform `_deny`, which raises
            # AccessDeniedError -> maps to a uniform 404) would strand it
            # forever with no way for a human to close it out. Resolve it
            # as rejected instead, with a reason that explains why, and
            # raise the same 409 `decide_hold` already raises for any other
            # already-decided hold.
            hold.status = "rejected"
            hold.decided_by_sub = approver_sub
            hold.decided_at = _now()
            hold.decision_reason = "target already admitted via a different path"
            _audit(
                session,
                actor_sub=approver_sub,
                action="approval.reject",
                agent_id=hold.sender_agent_id,
                conversation_id=conversation.id,
                detail={
                    "hold_id": str(hold_id),
                    "target_agent_id": str(hold.target_agent_id),
                    "current_status": existing.status,
                    "reason": "already_participant",
                },
            )
            await session.commit()
            raise HoldAlreadyDecidedError(hold.status)
        try:
            target = await _find_agent_by_id(session, hold.target_agent_id)
            if target is None or target.status != "active":
                await _deny(
                    session,
                    actor_sub=approver_sub,
                    action="denied.unknown_agent",
                    agent_id=hold.sender_agent_id,
                    conversation_id=conversation.id,
                    detail={"target_agent_id": str(hold.target_agent_id)},
                )
            if not await _is_active_safe(active_checker, target.sub):
                # TECH-5703: specific, not folded into the uniform denial above --
                # see AgentRetiredError's docstring.
                await _deny_agent_retired(
                    session,
                    actor_sub=approver_sub,
                    agent_id=hold.sender_agent_id,
                    conversation_id=conversation.id,
                    target_agent_id=hold.target_agent_id,
                )
            # Re-run the exact gate `invite()` itself ran at hold-creation
            # time. A hold can sit `pending_human` for up to
            # APPROVAL_HOLD_TTL (7 days) -- during that window the target's
            # `is_shared` flag, owner set, or retirement status can drift.
            # Re-checking here (rather than trusting whatever was true when
            # the hold was created) is what actually closes the gap;
            # skipping it would let a target that no longer qualifies slip
            # into an `internal` conversation anyway, via the approval path
            # instead of `invite()`'s own checks.
            await _authorize_invite_owner_freeze(
                session,
                actor_sub=approver_sub,
                inviter_agent_id=hold.sender_agent_id,
                conversation=conversation,
                target=target,
                ownership_client=ownership_client,
            )
        except (AccessDeniedError, AgentRetiredError) as exc:
            if isinstance(exc, AccessDeniedError) and exc.reason == _DENIED_OWNERSHIP_LOOKUP_FAILED:
                # A transient ownership-lookup infra failure (registry
                # timeout, 5xx), not genuine target drift -- distinguished
                # from the deterministic empty-owner-set case
                # (denied.ownership_unverified, which DOES fall through to
                # the stranded-hold resolution below: an orphaned agent's
                # empty owner set won't fix itself, so leaving the hold
                # pending_human for it would recreate the exact stranding
                # this code exists to prevent), from the other
                # AccessDeniedError reasons (denied.unknown_agent /
                # denied.shared_agent_not_allowed_internal /
                # denied.owner_set_frozen), and from AgentRetiredError.
                # Leave the hold `pending_human` so a human can retry the
                # approval once the lookup succeeds again -- auto-resolving
                # it here would destroy a still-valid invite over what may
                # be a momentary outage, not a real reason to reject it.
                raise
            # Same stranded-hold concern as the already-participant branch
            # above: any of the three re-validation checks genuinely
            # failing means the target drifted out of eligibility during
            # this hold's pending_human window. `_deny`/`_deny_agent_retired`
            # already audited and committed the specific denial reason and
            # raised -- that commit released this hold row's own
            # `FOR UPDATE` lock (acquired above), opening a window for a
            # concurrent `decide_hold` call on the SAME hold to resolve it
            # first. Re-acquire the lock and only mutate if it's still
            # `pending_human`; if a concurrent call already resolved it,
            # leave that resolution alone (whatever it is) and just
            # propagate this exception without a second, conflicting
            # commit.
            refreshed = await _find_hold(session, hold_id, for_update=True)
            if refreshed is not None and refreshed.status == "pending_human":
                refreshed.status = "rejected"
                refreshed.decided_by_sub = approver_sub
                refreshed.decided_at = _now()
                refreshed.decision_reason = (
                    "target no longer eligible for admission on re-validation"
                )
                _audit(
                    session,
                    actor_sub=approver_sub,
                    action="approval.reject",
                    agent_id=refreshed.sender_agent_id,
                    conversation_id=conversation.id,
                    detail={"hold_id": str(hold_id), "reason": "revalidation_failed"},
                )
                await session.commit()
            raise
        participant = Participant(
            conversation_id=conversation.id,
            agent_id=hold.target_agent_id,
            role="member",
            status="invited",
            invited_by=hold.sender_agent_id,
            joined_at=None,
        )
        session.add(participant)
        await session.flush()
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
            detail={"hold_id": str(hold_id), "has_reason": reason is not None},
        )
        _audit(
            session,
            actor_sub=approver_sub,
            action="participant.invite",
            agent_id=hold.target_agent_id,
            conversation_id=conversation.id,
            detail={"invited_by_agent_id": str(hold.sender_agent_id), "hold_id": str(hold_id)},
        )
        await session.commit()
        result = _hold_dict(hold)
        result["participant_status"] = participant.status
        return result

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


# --- Proposal holds (TECH-5871/5872/5875/5877) --------------------------------
#
# ``proposal_holds`` generalizes the same "propose, hold for a human, decide"
# shape approval_holds already gives comms traffic, to arbitrary bot actions
# (see models.ProposalHold's class docstring). Unlike approval_holds, a
# proposer here is not necessarily a board-registered ``agents`` row --
# ``proposed_by_bot_id``/``owner_sub`` are resolved by the caller (main.py's
# non-MCP ``POST /proposals`` route) from the submitting bot's verified
# token claims, not from ``service.get_agent_by_sub``.

# TECH-5875: per-bot submission rate limit. Counts ``audit_log`` rows
# tagged ``_PROPOSAL_SUBMISSION_ATTEMPT_ACTION``, NOT ``proposal_holds``
# rows (Argus review S2 fix): a create-time dedup match (TECH-5872, B1)
# UPDATEs an existing pending row in place instead of inserting a new one,
# so counting ``proposal_holds`` rows created in the window would never
# increment for a bot repeatedly resubmitting against its own already-
# pending dedup key -- letting it call this endpoint at unlimited
# frequency. ``audit_log`` is append-only, so one row is written per
# attempt regardless of whether the attempt goes on to INSERT or UPDATE
# (see the call site in ``create_proposal``, which commits this marker
# immediately -- before the dedup lookup -- so it survives the
# rollback-and-retry ``_dedup_or_insert_proposal`` performs on the B2
# unique-index race below).
PROPOSAL_RATE_LIMIT_WINDOW = timedelta(minutes=1)
MAX_PROPOSALS_PER_BOT_PER_WINDOW = 5
_PROPOSAL_SUBMISSION_ATTEMPT_ACTION = "proposal.submission_attempt"


async def _deny_rate_limited_proposals(session: AsyncSession, *, proposed_by_bot_id: str) -> None:
    """Audit + commit a denial, then raise ``RateLimitExceededError``
    (mapped to HTTP 429 by main.py) if ``proposed_by_bot_id`` has submitted
    too many proposals in the rolling window. Unlike approval_holds' sender,
    a proposing bot is not necessarily a board ``Agent``
    (``AuditLog.agent_id`` is a real FK), so the denial audit row carries
    only ``actor_sub`` -- no ``agent_id`` (Argus review S5: this denial
    previously wasn't audited at all, only logged in main.py's route
    handler, which still happens for operational visibility).

    Argus review S6 (TOCTOU): the COUNT below and the attempt-marker INSERT
    (``create_proposal``'s caller-side ``_audit`` + ``commit`` immediately
    after this returns) happen in separate statements -- without
    serialization, N concurrent submissions from the SAME bot that all
    observe ``count == MAX - 1`` can all pass, yielding an effective burst
    cap of ``MAX + N - 1`` instead of ``MAX``. ``pg_advisory_xact_lock``,
    keyed on a hash of ``proposed_by_bot_id`` (namespaced so it can't
    collide with any other advisory-lock use, e.g. migrations/env.py's
    migration-serialization lock), is held for the rest of THIS
    transaction -- i.e. through the count-check and the attempt-marker
    commit that follows it -- so concurrent submissions from the same bot
    serialize around the rate-limit check instead of racing it. Different
    bots never contend with each other (different hash keys)."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('proposal_rate_limit:' || :bot_id))"),
        {"bot_id": proposed_by_bot_id},
    )
    window_start = _now() - PROPOSAL_RATE_LIMIT_WINDOW
    count = (
        await session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.actor_sub == proposed_by_bot_id,
                AuditLog.action == _PROPOSAL_SUBMISSION_ATTEMPT_ACTION,
                AuditLog.at > window_start,
            )
        )
    ).scalar_one()
    if count >= MAX_PROPOSALS_PER_BOT_PER_WINDOW:
        _audit(
            session,
            actor_sub=proposed_by_bot_id,
            action="denied.proposal_rate_limited",
            detail={"limit": "proposals_per_bot_per_window"},
        )
        await session.commit()
        raise RateLimitExceededError(
            f"rate_limited: at most {MAX_PROPOSALS_PER_BOT_PER_WINDOW} proposals per "
            f"{int(PROPOSAL_RATE_LIMIT_WINDOW.total_seconds())}s per bot",
            reason="proposals_per_bot_per_window",
        )


def _extract_proposal_target(action: dict[str, Any]) -> tuple[str, str]:
    """Derive ``(target_id, action_type)`` from a proposal's free-form
    ``action`` JSONB payload (TECH-5872 create-time dedup key).

    ``action``'s shape is free-form per ``kind`` (models.ProposalHold's
    docstring), but every kind is required to carry at least these two
    string fields -- ``target_id`` (what real-world thing this action
    targets, e.g. a Linear issue id) and ``action_type`` (what kind of
    mutation, e.g. ``"open_ticket"``/``"close_ticket"``) -- so dedup and the
    kind-scoped judge (see ``_PROPOSAL_JUDGES`` below) have a stable key
    without needing to understand every kind's full shape."""
    target_id = action.get("target_id")
    action_type = action.get("action_type")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError("action.target_id is required and must be a non-empty string")
    if not isinstance(action_type, str) or not action_type:
        raise ValueError("action.action_type is required and must be a non-empty string")
    return target_id, action_type


def _derive_proposal_priority(kind: str, action: dict[str, Any]) -> str:
    """Server-derive ``priority`` from ``kind``/``action`` -- NEVER trust a
    caller-supplied value (TECH-5872). Deliberately simple for the one
    ``kind`` this repo currently understands; a future kind needing a
    richer derivation adds its own branch here rather than a generic
    fallback silently misclassifying it."""
    if kind == "linear_progress_update":
        action_type = action.get("action_type")
        if action_type == "close_ticket":
            return "high"
        if action_type == "open_ticket":
            return "medium"
        return "low"
    logger.warning(
        "_derive_proposal_priority: no explicit branch for kind=%r, defaulting to medium", kind
    )
    return "medium"


# TECH-5877: exactly two auto-approval rules, scoped to
# kind="linear_progress_update" only -- a deterministic rules engine, not an
# LLM judge, because write intent must be judged outside the proposing
# agent (a bot must never self-approve its own proposal). A future kind
# needs its OWN judge function registered in ``_PROPOSAL_JUDGES`` below --
# deliberately not a shared/generic judge across kinds.
_LINEAR_OPEN_TICKET_ACTION_TYPES = frozenset({"open_ticket"})
_LINEAR_CLOSE_TICKET_ACTION_TYPES = frozenset({"close_ticket"})

# Argus review B4: presence of a non-empty string was NOT sufficient to
# treat a citation as real -- a bot could self-approve by writing ANY
# string (including whitespace-shaped junk, or a URL to a host it fully
# controls) into ``source_message_url``/``resolving_pr_url``. A citation
# must now be an http(s) URL whose host is one of these two families:
# Slack message permalinks (``*.slack.com``) and GitHub PR/commit links
# (``github.com``) -- the two citation shapes this judge is documented to
# accept.
_ALLOWED_CITATION_HOST_EXACT = frozenset({"github.com"})
_ALLOWED_CITATION_HOST_SUFFIXES = (".slack.com",)


def _is_allowed_citation_host(host: str) -> bool:
    host = host.lower()
    if host in _ALLOWED_CITATION_HOST_EXACT:
        return True
    return any(host.endswith(suffix) for suffix in _ALLOWED_CITATION_HOST_SUFFIXES)


def _is_valid_citation_url(value: Any) -> bool:
    """Argus review B4: a citation must be an http(s) URL on an allowlisted
    host (see ``_ALLOWED_CITATION_HOST_EXACT``/``_ALLOWED_CITATION_HOST_SUFFIXES``
    above), not merely a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        return False
    return parsed.hostname is not None and _is_allowed_citation_host(parsed.hostname)


def evaluate_linear_progress_update_judge(action: dict[str, Any]) -> tuple[str, str | None]:
    """Pure decision function for kind="linear_progress_update" (TECH-5877).

    Returns ``(status, decision_note)`` where ``status`` is either
    ``"approved"`` or ``"pending"`` -- never anything else, and never
    ``"rejected"`` (this judge only ever clears a proposal for auto-apply
    or leaves it for a human; it does not reject on a bot's behalf).

    Rules (self-reported ``confidence``/``importance``/``impact`` are
    advisory only and are NOT inputs here -- see models.ProposalHold's
    docstring):

    1. ``action_type`` opens a ticket: auto-approve ONLY if
       ``action["source_message_url"]`` is a valid citation URL (see
       ``_is_valid_citation_url``) citing the human message that originated
       the request. A bare confidence score, free-text rationale, or an
       unlisted-host/non-http(s) URL is never sufficient.
    2. ``action_type`` closes a ticket: auto-approve if EITHER
       ``action["source_message_url"]`` (a human confirming completion) OR
       ``action["resolving_pr_url"]`` (a merged PR that plausibly resolves
       it) is a valid citation URL.
    3. Everything else (status changes short of closing, project
       reassignment, priority changes, or open/close with no valid
       citation) stays ``"pending"``.

    Independent of the HTTP layer and the DB (takes/returns plain dicts) so
    it is unit-testable as a pure function."""
    action_type = action.get("action_type")
    has_source_message = _is_valid_citation_url(action.get("source_message_url"))
    if action_type in _LINEAR_OPEN_TICKET_ACTION_TYPES:
        if has_source_message:
            return "approved", "auto-approved: open-ticket proposal cites source_message_url"
        return "pending", None
    if action_type in _LINEAR_CLOSE_TICKET_ACTION_TYPES:
        has_resolving_pr = _is_valid_citation_url(action.get("resolving_pr_url"))
        if has_source_message or has_resolving_pr:
            return "approved", "auto-approved: close-ticket proposal cites a valid citation"
        return "pending", None
    return "pending", None


# Registry keyed by ``kind`` -- deliberately not a shared/generic judge (see
# ``evaluate_linear_progress_update_judge``'s docstring). A ``kind`` with no
# entry here is never auto-approved; it is left ``"pending"`` by
# ``create_proposal`` below.
_PROPOSAL_JUDGES: dict[str, Callable[[dict[str, Any]], tuple[str, str | None]]] = {
    "linear_progress_update": evaluate_linear_progress_update_judge,
}

_PROPOSAL_JUDGE_DECIDED_BY = "system:judge"


def _proposal_dict(hold: ProposalHold) -> dict[str, Any]:
    result: dict[str, Any] = {
        "proposal_id": str(hold.id),
        "kind": hold.kind,
        "proposed_by_bot_id": hold.proposed_by_bot_id,
        "action": hold.action,
        "rationale": hold.rationale,
        "confidence": hold.confidence,
        "importance": hold.importance,
        "impact": hold.impact,
        "priority": hold.priority,
        "status": hold.status,
        "created_at": _iso(hold.created_at),
        "updated_at": _iso(hold.updated_at),
    }
    if hold.decision_source is not None:
        result["decision_source"] = hold.decision_source
    if hold.decided_by_actor_id is not None:
        result["decided_by_actor_id"] = hold.decided_by_actor_id
    if hold.decided_at is not None:
        result["decided_at"] = _iso(hold.decided_at)
    if hold.decision_note is not None:
        result["decision_note"] = hold.decision_note
    return result


def validate_hold_level(value: str, name: str) -> str:
    """Shared ``confidence``/``importance``/``impact`` membership check
    (Argus review S14) -- ``PROPOSAL_HOLD_LEVELS`` is the single source of
    truth, and this is the only place that checks membership in it. Used by
    both ``main.py``'s HTTP-layer pre-validation (``submit_proposal``) and
    this module's own defense-in-depth re-check in ``create_proposal``, so
    the two can never drift onto different accepted vocabularies."""
    if value not in PROPOSAL_HOLD_LEVELS:
        raise ValueError(f"{name} must be one of {PROPOSAL_HOLD_LEVELS!r}")
    return value


def _proposal_dedup_where(
    *, kind: str, proposed_by_bot_id: str, target_id: str, action_type: str
) -> tuple[Any, ...]:
    """Shared create-time dedup predicate (TECH-5872, Argus review B1 fix):
    ``(kind, proposed_by_bot_id, target_id, action_type)`` against any
    currently ``status='pending'`` row. Scoped to the SAME submitting bot
    deliberately -- a different bot targeting the same ``(kind, target_id,
    action_type)`` must get its own fresh row, never silently overwrite (and
    get auto-approved under) another bot's pending proposal. This predicate
    is shared between ``_dedup_or_insert_proposal``'s app-level SELECT
    (used both for the common case and to re-query after losing the B2
    race below) and must use the SAME key as the DB-level partial unique
    index backing it, ``idx_proposal_holds_pending_dedup`` (migration
    9a1c2d3e4f5b) -- the two must never drift onto different keys, or they
    will fight each other."""
    return (
        ProposalHold.kind == kind,
        ProposalHold.proposed_by_bot_id == proposed_by_bot_id,
        ProposalHold.status == "pending",
        ProposalHold.action["target_id"].astext == target_id,
        ProposalHold.action["action_type"].astext == action_type,
    )


def _apply_proposal_resubmission(
    hold: ProposalHold,
    *,
    action: dict[str, Any],
    rationale: str,
    confidence: str,
    importance: str,
    impact: str,
    priority: str,
    target_fingerprint: str,
) -> None:
    """Mutate an existing pending ``ProposalHold`` in place for a dedup
    match. Deliberately does NOT set ``hold.updated_at`` itself (Argus
    review S3) -- ``models._updated_at()``'s ORM-managed ``onupdate`` fires
    on this same flush/commit once any column changes, so a second,
    Python-clock write here would just race the DB's own ``now()`` for no
    benefit."""
    hold.action = action
    hold.rationale = rationale
    hold.confidence = confidence
    hold.importance = importance
    hold.impact = impact
    hold.priority = priority
    hold.target_fingerprint = target_fingerprint


async def _dedup_or_insert_proposal(
    session: AsyncSession,
    *,
    kind: str,
    proposed_by_bot_id: str,
    owner_sub: str,
    action: dict[str, Any],
    rationale: str,
    confidence: str,
    importance: str,
    impact: str,
    target_id: str,
    action_type: str,
    priority: str,
    target_fingerprint: str,
) -> ProposalHold:
    """INSERT a new ``proposal_holds`` row, or UPDATE an existing pending
    dedup match in place (TECH-5872 B1/B2).

    The app-level SELECT below is the common case. ``idx_proposal_holds_
    pending_dedup`` (migration 9a1c2d3e4f5b) is the DB-level backstop for
    the race the SELECT-then-INSERT pattern can't close alone: two
    concurrent submissions for the same dedup key can both miss the SELECT
    and both attempt an INSERT. The loser's INSERT raises ``IntegrityError``
    on flush; this rolls back ONLY that failed INSERT attempt (not the
    caller's already-committed rate-limit attempt marker -- see
    ``create_proposal``) and re-queries to perform the UPDATE instead."""
    where = _proposal_dedup_where(
        kind=kind,
        proposed_by_bot_id=proposed_by_bot_id,
        target_id=target_id,
        action_type=action_type,
    )
    existing = (await session.execute(select(ProposalHold).where(*where))).scalar_one_or_none()
    if existing is not None:
        _apply_proposal_resubmission(
            existing,
            action=action,
            rationale=rationale,
            confidence=confidence,
            importance=importance,
            impact=impact,
            priority=priority,
            target_fingerprint=target_fingerprint,
        )
        return existing

    hold = ProposalHold(
        kind=kind,
        proposed_by_bot_id=proposed_by_bot_id,
        owner_sub=owner_sub,
        action=action,
        rationale=rationale,
        confidence=confidence,
        importance=importance,
        impact=impact,
        priority=priority,
        status="pending",
        target_fingerprint=target_fingerprint,
    )
    session.add(hold)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        if not _is_constraint_violation(exc, "idx_proposal_holds_pending_dedup"):
            raise
        existing_after_race = (
            await session.execute(select(ProposalHold).where(*where))
        ).scalar_one_or_none()
        if existing_after_race is None:
            # Vanishingly unlikely (the race winner's row was deleted again
            # before this re-read) -- nothing sane to update; surface the
            # original DB error rather than silently proceeding.
            raise
        _apply_proposal_resubmission(
            existing_after_race,
            action=action,
            rationale=rationale,
            confidence=confidence,
            importance=importance,
            impact=impact,
            priority=priority,
            target_fingerprint=target_fingerprint,
        )
        return existing_after_race
    return hold


async def create_proposal(
    session: AsyncSession,
    *,
    kind: str,
    proposed_by_bot_id: str,
    owner_sub: str,
    action: dict[str, Any],
    rationale: str,
    confidence: str,
    importance: str,
    impact: str,
    target_fingerprint: str,
) -> dict[str, Any]:
    """``POST /proposals`` (main.py, non-MCP, bot-submission-gated).

    Enforces the TECH-5875 per-bot rate limit (recording this attempt in
    ``audit_log`` and committing immediately -- see
    ``_deny_rate_limited_proposals``'s docstring for why this must survive
    a later rollback-and-retry), then delegates to
    ``_dedup_or_insert_proposal``, which either UPDATEs an existing
    ``status='pending'`` row matching ``(kind, proposed_by_bot_id,
    target_id, action_type)`` in place (TECH-5872 create-time dedup --
    ``target_id``/``action_type`` derived from ``action`` via
    ``_extract_proposal_target``; scoped to the submitting bot, Argus
    review B1) or INSERTs a new one. ``priority`` is always server-derived
    (``_derive_proposal_priority``) -- a caller-supplied value in ``action``
    or elsewhere is never trusted or persisted as ``priority``.

    Immediately after the row is inserted/updated, runs the TECH-5877
    kind-scoped judge (``_PROPOSAL_JUDGES``) exactly once. A ``kind`` with
    no registered judge stays ``"pending"``. The judge only ever sets
    ``status``/``decision_source``/``decided_by_actor_id``/``decided_at``/
    ``decision_note`` -- it never executes the underlying write (that is
    TECH-5873's concern, not yet built). Note: once B1 lands, a SAME-bot
    resubmission that adds a valid citation to an already-pending row is
    expected to auto-approve on this pass -- a bot progressively refining
    its own proposal, not a new escalation path (see
    ``tests/test_proposal_service.py::TestJudgeIntegration::
    test_resubmit_with_citation_auto_approves_pending_row``).
    """
    validate_hold_level(confidence, "confidence")
    validate_hold_level(importance, "importance")
    validate_hold_level(impact, "impact")
    # Argus review S3: pure validation must happen BEFORE the rate-limit
    # attempt marker is audited + committed below -- otherwise a malformed
    # (but authenticated) request that fails here still burns a rate-limit
    # slot before ever reaching a 422.
    target_id, action_type = _extract_proposal_target(action)
    priority = _derive_proposal_priority(kind, action)

    await _deny_rate_limited_proposals(session, proposed_by_bot_id=proposed_by_bot_id)
    _audit(session, actor_sub=proposed_by_bot_id, action=_PROPOSAL_SUBMISSION_ATTEMPT_ACTION)
    await session.commit()

    hold = await _dedup_or_insert_proposal(
        session,
        kind=kind,
        proposed_by_bot_id=proposed_by_bot_id,
        owner_sub=owner_sub,
        action=action,
        rationale=rationale,
        confidence=confidence,
        importance=importance,
        impact=impact,
        target_id=target_id,
        action_type=action_type,
        priority=priority,
        target_fingerprint=target_fingerprint,
    )

    judge = _PROPOSAL_JUDGES.get(kind)
    if judge is not None:
        judged_status, decision_note = judge(hold.action)
        if judged_status == "approved" and hold.status == "pending":
            hold.status = "approved"
            hold.decision_source = "auto"
            hold.decided_by_actor_id = _PROPOSAL_JUDGE_DECIDED_BY
            hold.decided_at = _now()
            hold.decision_note = decision_note

    await session.commit()
    # Refresh so server-defaulted columns (created_at/updated_at on a fresh
    # INSERT; updated_at's onupdate on the dedup UPDATE path) are populated
    # from the DB before _proposal_dict reads them -- neither is fetched
    # automatically via RETURNING on flush for this mapper, so skipping this
    # would try to lazy-load them post-commit, which asyncpg's AsyncSession
    # cannot do outside an explicit await.
    await session.refresh(hold)
    return _proposal_dict(hold)


async def list_pending_proposal_holds(
    session: AsyncSession, *, owner_sub: str, limit: int = 50
) -> dict[str, Any]:
    """``GET /proposals/pending`` (main.py, non-MCP, interactive+owner-gated):
    every ``status='pending'`` proposal whose ``owner_sub`` snapshot matches
    the caller, oldest first -- same owner_sub-scoped visibility pattern as
    ``list_pending_approval_holds``."""
    limit = max(1, min(limit, 200))
    stmt = (
        select(ProposalHold)
        .where(ProposalHold.owner_sub == owner_sub, ProposalHold.status == "pending")
        .order_by(ProposalHold.created_at.asc())
        .limit(limit + 1)
    )
    rows = (await session.execute(stmt)).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    proposals = [_proposal_dict(hold) for hold in rows]
    return {"proposals": proposals, "has_more": has_more}


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
    review_reason: str | None = None,
) -> Message | ApprovalHold:
    """Append a schema-validated message; apply state-machine side effects.

    ``review_reason`` (TECH-5786): when the sender supplies a non-empty,
    non-whitespace-only reason, the message is diverted to a hold
    unconditionally, overriding whatever the injected ``risk_scorer``
    verdict would otherwise be -- including in an ``internal`` conversation,
    where the scorer structurally never returns non-``None`` on its own. An
    empty or whitespace-only ``review_reason`` is treated the same as
    ``None`` -- it does not force a hold. The scorer still runs first (for
    its other, unconditional side effect -- ``_enforce_message_type_accepted``
    -- and so its own verdict can be recorded in the hold's audit detail for
    context), but its ``risk_reason`` return value is discarded in favor of
    ``AGENT_REQUESTED_RISK_REASON`` once a ``review_reason`` is present. The
    resulting hold's ``AutoApprover`` review always structurally escalates
    to a human regardless of the configured ``AutoApprover``'s own verdict
    -- see ``_divert_high_risk_message``'s override of ``decision.cleared``.

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
    reference an existing prior message; ``ConversationArchivedError``
    (TECH-5887) if the conversation has been archived
    (``comms_archive_conversation``) -- checked first, before every other
    gate.
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

    # TECH-5887: an archived conversation accepts no new messages at all --
    # checked before every other gate (system-message-type, rate limits,
    # state-machine legality) so a post into an archived conversation always
    # surfaces the specific, actionable ConversationArchivedError rather
    # than being folded into (or masked by) any of those other denials.
    if conversation.archived_at is not None:
        await _deny_archived(
            session,
            actor_sub=actor_sub,
            agent_id=sender_agent_id,
            conversation_id=conversation.id,
            action="denied.archived.post_message",
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
    risk_reason, boundary_participants = await _check_boundary_crossing(
        session,
        actor_sub=actor_sub,
        sender_agent_id=sender_agent_id,
        conversation=conversation,
        message_type=message_type,
        schema_version=schema_version,
        ownership_client=ownership_client,
        risk_scorer=risk_scorer,
    )

    # TECH-5786: an explicit review_reason forces a hold regardless of the
    # scorer's own verdict (captured above as `risk_reason`, which may be
    # None -- e.g. always, structurally, in an `internal` conversation).
    # Overriding after the call, not skipping the call, so
    # _enforce_message_type_accepted (inside _check_boundary_crossing) still
    # runs unconditionally, and the scorer's own verdict is still available
    # to record in the hold's audit detail below.
    scorer_risk_reason = risk_reason
    # `review_reason.strip()`, not bare `is not None` (Argus round-1
    # BLOCKING catch): an empty or whitespace-only string is not a
    # meaningful reason, and forcing a hold on one is indistinguishable
    # from a legitimate request once recorded in the audit detail.
    review_reason_requested = review_reason is not None and review_reason.strip() != ""
    if review_reason_requested:
        risk_reason = AGENT_REQUESTED_RISK_REASON

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
            participants=boundary_participants,
            sender_sub=sender.sub,
            extra_audit_detail=(
                {
                    "review_reason": review_reason,
                    # Omitted when None (Argus round-1 SUGGESTION catch),
                    # not `"scorer_risk_reason": null` -- the key's presence
                    # would otherwise imply a risk reason was found when the
                    # scorer actually returned none (e.g. always, in an
                    # `internal` conversation).
                    **(
                        {"scorer_risk_reason": scorer_risk_reason}
                        if scorer_risk_reason is not None
                        else {}
                    ),
                }
                if review_reason_requested
                else None
            ),
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


async def inbox(
    session: AsyncSession,
    *,
    caller_agent_id: uuid.UUID,
    include_own_messages: bool = False,
    include_read: bool = False,
) -> dict[str, Any]:
    """Unread-first inbox for the caller's agent: unread + pending invites.

    ``unread``: by default, every conversation where the caller is an
    ``active`` participant and at least one message from ANOTHER sender
    has ``seq > last_read_seq`` — regardless of conversation state, so a
    completion/cancelation message still surfaces once. ``pending_invites``:
    every conversation where the caller has a pending ``invited`` row
    (metadata only — no message peek, matching ``get_conversation``'s
    invited-caller behavior).

    Two default-on filters, each independently opt-outable:

    - ``include_own_messages`` (default ``False``): the caller's own
      posted messages don't, by themselves, make a conversation "unread"
      for the caller, and don't count toward ``unread_count`` or get
      chosen as ``latest_message``. Rationale: ``post_message`` never
      advances the sender's own ``last_read_seq`` (only ``get_conversation``
      does), so without this filter, posting into a conversation and then
      immediately calling ``inbox`` again would echo the caller's own
      just-sent message back as "unread" -- there is nothing new for the
      caller to act on. Pass ``True`` to restore counting/showing the
      caller's own messages (matches this tool's pre-filter behavior).
    - ``include_read`` (default ``False``): only conversations with
      qualifying unread activity (per ``include_own_messages`` above) are
      returned. Pass ``True`` to also include the caller's active
      conversations that have NO qualifying unread messages -- e.g. to see
      recent activity across every active conversation regardless of read
      state. ``unread_count`` may be ``0`` for such an entry, and
      ``latest_message`` falls back to the conversation's true latest
      message (even a self-authored or already-read one) when there is no
      qualifying unread message to show instead.

    ``include_own_messages=True`` with ``include_read=False`` (the default)
    is the faithful reproduction of this tool's original (pre-filter)
    behavior: the original unconditionally required
    ``max(seq) > last_read_seq`` (any sender), which is exactly what
    ``include_own_messages=True`` alone restores. Setting
    ``include_read=True`` as well is NOT equivalent to the original --
    it additionally surfaces already-fully-read conversations the
    original never returned, making both-``True`` a strict superset of
    the original behavior rather than identical to it.

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
    # The set of messages that count as "new" to the caller: unread by
    # cursor position, and (by default) not authored by the caller
    # themselves. `include_own_messages=True` drops the second condition,
    # restoring the original all-senders-count behavior.
    relevant_conditions = [Message.seq > Participant.last_read_seq]
    if not include_own_messages:
        relevant_conditions.append(Message.sender_id != caller_agent_id)
    relevant_filter = and_(*relevant_conditions)

    unread_query = (
        select(
            Conversation,
            Participant.last_read_seq,
            func.max(Message.seq).label("max_seq"),
            func.count(Message.id).filter(relevant_filter).label("unread"),
            func.max(Message.seq).filter(relevant_filter).label("latest_relevant_seq"),
        )
        .join(Participant, Participant.conversation_id == Conversation.id)
        .join(Message, Message.conversation_id == Conversation.id)
        .where(Participant.agent_id == caller_agent_id, Participant.status == "active")
        .group_by(Conversation.id, Participant.last_read_seq)
        .order_by(func.max(Message.created_at).desc())
    )
    if not include_read:
        unread_query = unread_query.having(func.count(Message.id).filter(relevant_filter) > 0)
    unread_query = unread_query.limit(MAX_UNREAD_CONVERSATIONS_PER_INBOX + 1)

    unread_rows = (await session.execute(unread_query)).all()
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
        unread_total_query = (
            select(Conversation.id)
            .join(Participant, Participant.conversation_id == Conversation.id)
            .join(Message, Message.conversation_id == Conversation.id)
            .where(Participant.agent_id == caller_agent_id, Participant.status == "active")
            .group_by(Conversation.id, Participant.last_read_seq)
        )
        if not include_read:
            unread_total_query = unread_total_query.having(
                func.count(Message.id).filter(relevant_filter) > 0
            )
        unread_total_stmt = select(func.count()).select_from(unread_total_query.subquery())
        unread_total = (await session.execute(unread_total_stmt)).scalar_one()
    else:
        unread_total = len(unread_rows)

    # Fetch every unread conversation's latest message + sender sub in a
    # single round trip (instead of one SELECT per conversation in a Python
    # loop): join Message/Agent against the exact (conversation_id, seq)
    # pairs already computed above via a composite-tuple IN. The seq used
    # per conversation is `latest_relevant_seq` (the latest message that
    # counts as "new" under the current filters) when one exists, falling
    # back to `max_seq` (the conversation's true latest message) when it
    # doesn't -- e.g. an `include_read=True` conversation with nothing
    # qualifying, or an all-self-authored conversation surfaced only via
    # `include_read=True`.
    latest_by_conversation_id: dict[uuid.UUID, tuple[Message, str]] = {}
    conversation_seq_pairs = [
        (conversation.id, latest_relevant_seq if latest_relevant_seq is not None else max_seq)
        for conversation, _, max_seq, _, latest_relevant_seq in unread_rows
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
    for conversation, last_read_seq, _max_seq, unread_count, _latest_relevant_seq in unread_rows:
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
        treats every exception as fail-closed (``denied.ownership_unverified``
        at conversation-open admission; ``denied.ownership_lookup_failed``
        at invite owner-freeze, TECH-5735 — see that denial's own comment
        for why the two call sites use different reason strings).
        """
        ...


class AgentTableOwnershipClient:
    """Interim ``OwnershipClient`` until the platform's real ownership
    endpoint ships.

    Wraps the existing ``agents`` columns: ``owner_sub`` as a
    single-element owner set, and ``is_shared`` from the DB.
    ``register_agent`` freezes ``owner_sub`` at first registration and
    never overwrites it on re-registration (self-asserted claims are
    untrusted) -- but ``owner_sub`` is NOT immutable for the lifetime of
    the row: ``write_through_ownership`` (TECH-5593) updates it on every
    verified request from a registry-backed agent-token verifier, and
    ``reconcile_agent_ownership`` is the periodic backstop for agents that
    make no further requests. Both are the ONE sanctioned exception to the
    freeze (see ``write_through_ownership``'s own docstring) -- an earlier
    version of this docstring claimed ``owner_sub`` "truly never changes";
    that stopped being true once those two functions shipped. TECH-5735
    does NOT address this by re-checking live on every send (an earlier,
    abandoned design did; see git history for commit c644780 on this
    ticket's branch, superseded by 8c8b318) -- it closes the ``is_shared``
    dimension of this problem STRUCTURALLY instead, by excluding any
    ``is_shared`` agent from ``internal`` at admission and invite time
    (``_authorize_conversation_open``/``_authorize_invite_owner_freeze``),
    so a shared agent's mutable roster can never be the thing that breaks
    an already-equal owner set. The narrower ``owner_sub``-reassignment
    case above (two ALREADY non-shared, already-admitted participants,
    reassigned independently after open) is a deliberately accepted
    residual gap, not one this docstring's callers close -- see
    ``docs/DESIGN.md`` §9's "Accepted residual gap (TECH-5735)" note.
    ``is_shared`` IS still frozen
    against an agent's own re-registration, but -- unlike ``owner_sub`` --
    mutable via the separate ``comms:admin``-gated ``set_agent_shared``
    admin override (see that function's docstring); its only mutation path
    is itself gated on the same elevated scope required to escalate it at
    first registration, so there is no path by which an unprivileged
    caller can move it.
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
    "ALLOWED_DENIAL_REASONS",
    "APPROVAL_HOLD_TTL",
    "CONVERSATION_TTL",
    "DEFAULT_OWNERSHIP_CLIENT",
    "DEFAULT_RECONCILIATION_BATCH_SIZE",
    "MAX_APPROVAL_HOLDS_PER_MINUTE",
    "MAX_CONVERSATION_STARTS_PER_HOUR",
    "MAX_LOOKUP_EMAIL_LENGTH",
    "MAX_MESSAGES_PER_CONVERSATION_PER_HOUR",
    "MAX_PROPOSALS_PER_BOT_PER_WINDOW",
    "MAX_RECONCILIATION_BATCH_SIZE",
    "OWNERSHIP_CLIENTS",
    "OWNERSHIP_CLIENT_ENV_VAR",
    "PROPOSAL_HOLD_LEVELS",
    "PROPOSAL_RATE_LIMIT_WINDOW",
    "AgentTableOwnershipClient",
    "OwnershipClient",
    "OwnershipClientFactory",
    "accept_invite",
    "archive_conversation",
    "audit_denied_approval_requires_interactive",
    "audit_denied_proposal_submission",
    "create_proposal",
    "decide_hold",
    "decline_invite",
    "deregister_agent",
    "evaluate_linear_progress_update_judge",
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
    "list_pending_proposal_holds",
    "lookup_agent_by_email",
    "may_assign",
    "may_invite",
    "post_message",
    "reconcile_agent_ownership",
    "register_agent",
    "start_conversation",
    "validate_hold_level",
    "validate_ownership_client_configuration",
    "write_through_ownership",
]
