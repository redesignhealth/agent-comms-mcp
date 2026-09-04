"""SQLAlchemy models for the comms domain.

Schema conventions:
snake_case plural table names, UUID primary keys, TEXT over VARCHAR,
TIMESTAMPTZ everywhere, ``created_at``/``updated_at`` on every mutable
table, explicit ``idx_{table}_{columns}`` indexes.

Domain invariants enforced at the schema level:
- ``messages`` and ``audit_log`` are append-only. No code path anywhere in
  this service updates or deletes rows in either table; the ORM models
  exist only for INSERT and SELECT.
- ``messages`` carries a per-conversation monotonic ``seq`` guarded by
  ``UNIQUE(conversation_id, seq)``; assignment is serialized via
  ``SELECT ... FOR UPDATE`` on the conversation row (see service.py).
- Closed status/state vocabularies get CHECK constraints. Open
  vocabularies (``conversations.type``, ``messages.type``) are validated
  against the versioned schema registry in schemas.py instead, so adding
  a conversation type is a code change, not a migration.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    column,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from schemas import MAX_DISPLAY_NAME_LENGTH

# Closed vocabularies (CHECK-constrained). Conversation/message *types* are
# open vocabularies owned by schemas.py.
AGENT_STATUSES = ("active", "suspended")
CONVERSATION_STATES = ("active", "completed", "canceled", "expired")
PARTICIPANT_ROLES = ("owner", "member")
PARTICIPANT_STATUSES = ("invited", "active", "left", "declined")
# approval_holds lifecycle (TECH-5389 PR2): pending_auto -> pending_human ->
# approved|rejected|expired, or pending_auto -> auto_approved. v1's
# EscalateAllAutoApprover means no committed row is ever OBSERVED at
# pending_auto (created and transitioned within one transaction), but the
# state exists in this CHECK from day one for a future async auto-approver
# (see plugins.AutoApprover's docstring).
APPROVAL_HOLD_STATUSES = (
    "pending_auto",
    "pending_human",
    "auto_approved",
    "approved",
    "rejected",
    "expired",
)
APPROVAL_HOLD_AUTO_DECISIONS = ("cleared", "escalated")
# TECH-5735: discriminates a hold's shape -- see ApprovalHold's class
# docstring. "message" is the original TECH-5389 PR2 shape (default, for
# every pre-existing row); "invite" is new.
APPROVAL_HOLD_KINDS = ("message", "invite")

# proposal_holds lifecycle (TECH-5871, transitions finalized TECH-5873
# Argus review B1, race fix Argus review round-2 B1): `pending` is the
# only persisted non-terminal status a caller can observe at rest before
# any decision. A "pending" row resolves to:
#   - `applied` | `apply_failed` | `stale`, via EITHER the TECH-5877
#     auto-judge's immediate synchronous apply at submission time
#     (service.create_proposal) OR a human's `approve` decision
#     (service.decide_proposal) -- both paths funnel through the same
#     service._apply_or_finalize_proposal_hold helper, and both first
#     claim the row by writing `applying` (below) under the initial
#     `FOR UPDATE` before releasing that lock for the ~10s external
#     Linear call.
#   - `rejected`, via a human's `reject` decision only (decide_proposal) --
#     the auto-judge never rejects on a bot's behalf (see
#     evaluate_linear_progress_update_judge's docstring).
# `applying` is a transient, PERSISTED sentinel (unlike `approved`, see
# below): the claiming caller writes it (plus decided_at/
# decided_by_actor_id/decision_source, to satisfy
# `ck_proposal_holds_decision_consistency` below) and commits, releasing
# the row lock, BEFORE calling the kind-scoped fingerprinter/applier. A
# second concurrent caller that acquires the lock while this is in flight
# reads `applying` (not `pending`), takes the already-decided branch, and
# never reaches the applier a second time -- this is what actually closes
# the double-Linear-write race; the DB-level dedup on the terminal write
# alone was not enough; see `_apply_or_finalize_proposal_hold`'s docstring.
# `approved` is a value this CHECK still accepts (see the "frozen
# migration" note below) but is NEVER actually persisted: it is the
# in-memory verdict the auto-judge returns, immediately converted to a
# claiming `applying` write (see above) before any commit a concurrent
# reader could observe -- a hold is never left sitting at rest in
# `approved`, because `decide_proposal` treats any non-`pending` status as
# already-decided and `list_pending_proposal_holds` only surfaces
# `status='pending'`, which would strand it. `stale` is reachable only via
# that apply-time fingerprint re-check (see ProposalHold's class
# docstring), never directly from `pending`: it is detected after decision
# fields (`decided_at`/`decided_by_actor_id`/`decision_source`) are
# already stamped (at the `applying` claim), and
# `ck_proposal_holds_decision_consistency` requires those fields whenever
# `status != 'pending'`.
# NOTE: these three tuples are mirrored as literal SQL in migration
# d23b37d4e187's CHECK constraints (migrations are frozen once applied, so
# they cannot import from this module) -- `applying` specifically was
# added later, via migration e2f7a91c5b34's ALTER of
# ck_proposal_holds_status only (the other CHECK constraints in
# d23b37d4e187 already accommodate it, see that migration's docstring).
# Editing any of these tuples requires a NEW migration to ALTER the
# corresponding CHECK constraint(s) in the database -- there is no drift
# detection between this file and the DB schema, so keep them in sync by
# hand.
PROPOSAL_HOLD_STATUSES = (
    "pending",
    "approved",
    "applying",
    "rejected",
    "applied",
    "apply_failed",
    "stale",
)
PROPOSAL_HOLD_DECISION_SOURCES = ("human", "auto")
# Shared closed vocabulary for the three self-reported, advisory-only axes
# (confidence/importance/impact) AND the server-derived `priority` -- same
# three levels, different provenance (see ProposalHold.priority).
PROPOSAL_HOLD_LEVELS = ("low", "medium", "high")


class Base(DeclarativeBase):
    type_annotation_map = {  # noqa: RUF012 — SQLAlchemy declarative config, not mutable state
        datetime: TIMESTAMP(timezone=True),
        dict[str, Any]: JSONB,
    }


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )


def _created_at() -> Mapped[datetime]:
    return mapped_column(nullable=False, server_default=text("now()"))


def _updated_at() -> Mapped[datetime]:
    # ORM-managed only (onupdate=...) — there is no DB-level BEFORE UPDATE
    # trigger. A raw SQL UPDATE (a bulk data-fix migration, an admin
    # backfill, etc.) that bypasses the ORM will NOT refresh this column.
    # Go through the ORM for every mutation of a row using this helper
    # (``conversations``, most notably, whose ``state`` mutates in place)
    # or this timestamp goes stale silently.
    return mapped_column(nullable=False, server_default=text("now()"), onupdate=text("now()"))


class Agent(Base):
    """A board-admitted agent, bound to an OAuth-verified owner.

    ``sub`` is the agent's agent-jwt JWT subject and the board-wide identity
    key. ``owner_sub``/``owner_email`` always come from verified token
    claims at bind time — never from tool parameters. They are also kept
    fresh (bounded-staleness cache, TECH-5593) after bind time by
    ``service.write_through_ownership`` (from a later request's verified,
    registry-backed token claims) and ``service.reconcile_agent_ownership``
    (``owner_sub`` only, from the configured ``OwnershipClient`` seam,
    out-of-band) — never from a caller-supplied, unverified claim either
    way; see those functions' own docstrings for exactly what gates each.
    """

    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(f"status IN {AGENT_STATUSES!r}", name="ck_agents_status"),
        # Schema-version capability negotiation: the wire-schema version range
        # this agent's own code can correctly interpret, declared at
        # ``comms_register`` time. min/max both default to 1 (today's only
        # version). The board negotiates down to the highest version every
        # participant in a new conversation mutually supports (see
        # ``service._negotiate_schema_version``); this CHECK is a DB-level
        # backstop mirroring the same ``min <= max`` validation
        # ``service.register_agent`` already performs at the app layer.
        CheckConstraint(
            "min_schema_version >= 1 AND min_schema_version <= max_schema_version",
            name="ck_agents_schema_version_range",
        ),
        # Backs service.lookup_agent_by_email's
        # func.lower(Agent.owner_email) == ... AND status == "active" ...
        # ORDER BY bound_at DESC query (migration bb1ea7d2a0cf).
        # Declared here too, not just in the migration -- every other
        # migration-created index in this file has a matching declaration;
        # without one, a future `alembic revision --autogenerate` sees this
        # index in the DB but not in metadata and silently emits a DROP
        # INDEX for it. text() rather than func.lower(Agent.owner_email):
        # __table_args__ is evaluated before this class's own attributes
        # exist as a fully-formed class, so "Agent" isn't a valid name yet
        # at this point in the class body.
        #
        # Column 1 stays text("lower(owner_email)") -- Postgres stores a
        # computed expression like this as a raw expression in
        # pg_index.indexprs, and Alembic's autogenerate comparator treats
        # text() as that same kind of opaque expression, so the two compare
        # equal. Column 2 must NOT also be text() -- verified via
        # `alembic revision --autogenerate` against a live DB: Postgres
        # stores `bound_at DESC NULLS LAST` as a plain column reference plus
        # sort attributes in pg_index.indoption, which autogenerate
        # introspects as a structured column+modifier, not raw expression
        # text -- a text()-based declaration never compares equal to that,
        # so autogenerate kept proposing to DROP this index, defeating the
        # entire point of declaring it here. column(...).desc().nullslast()
        # produces the structured form that actually round-trips.
        #
        # Both string literals below ("owner_email", "bound_at") are bare
        # names with no referential tie to the `owner_email`/`bound_at`
        # mapped_column attributes defined further down this class -- a
        # future rename of either column won't propagate here, and
        # autogenerate will silently start proposing DROP + CREATE again.
        # Keep these in sync by hand if either column is ever renamed.
        Index(
            "idx_agents_lower_owner_email_active",
            text("lower(owner_email)"),
            column("bound_at").desc().nullslast(),
            postgresql_where=text("status = 'active'"),
        ),
        # Backs service.reconcile_agent_ownership's keyset-ish "oldest
        # never/least-recently-reconciled first" ordering (TECH-5593 item 4,
        # Argus round-1 BLOCKING fix): NULLS FIRST so an agent that has
        # never been reconciled sorts before one reconciled at any real
        # timestamp, and the partial WHERE excludes both terminal (non-
        # `active`) and `is_shared` agents -- the same predicate
        # `reconcile_agent_ownership`'s own query filters on -- so shared
        # agents never occupy a batch slot at all, not merely get skipped
        # in Python after already consuming one. `id` is a secondary sort
        # key (Argus round-2 SUGGESTION, treated as load-bearing rather
        # than cosmetic): every agent processed within one reconciliation
        # batch is stamped with the SAME `now()` value (`reconcile_agent_
        # ownership`'s own `now = _now()`, read once per call, not once per
        # row), so once a tie group's size exceeds `limit`, an
        # `owner_reconciled_at`-only ORDER BY has no defined tiebreak and
        # Postgres is free to return a different arbitrary subset of that
        # tied group on each call -- silently reintroducing this same
        # cursor's own starvation failure mode for exactly the rows that
        # already share a reconciliation timestamp. `id` has no semantic
        # meaning here; it only needs to be stable and total, which a
        # primary key already is.
        Index(
            "idx_agents_owner_reconciled_at",
            column("owner_reconciled_at").asc().nullsfirst(),
            column("id").asc(),
            postgresql_where=text("status = 'active' AND is_shared = false"),
        ),
        # Backs service.register_agent's display-name-collision check
        # (func.lower(Agent.display_name) == ... AND status == "active")
        # and, since migration a45f344c9c00's in-place amendment, is a
        # UNIQUE index -- a DB-level backstop closing the race the
        # app-level read-then-insert check alone can't (see that
        # migration's docstring). Declared here too, not just in the
        # migration, for the same autogenerate-drift reason as
        # idx_agents_lower_owner_email_active above.
        Index(
            "idx_agents_lower_display_name_active",
            text("lower(display_name)"),
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
        # NOTE: no `idx_agents_sub_prefix` here. service.register_agent's
        # sibling-identity prefix check
        # (Agent.sub.startswith(f"{base_sub}::", autoescape=True)) compiles
        # to `LIKE 'base_sub::%' ESCAPE '\\'`, which a `text_pattern_ops`
        # index can't serve -- that opclass only accelerates the
        # two-argument `~~` (plain LIKE) operator, not the ESCAPE form.
        # Dropping `autoescape=True` to make the index usable was
        # considered and rejected: `base_sub` comes from
        # `identity.try_resolve_email`'s `email`/`preferred_username`
        # claims, which are IdP-controlled and not restricted against
        # `%`/`_` the way `agent_key` is. So this query accepts a
        # sequential scan on this small table instead of an index that
        # would either be dead weight or unsafe. See migration
        # a45f344c9c00's docstring for the full history.
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    sub: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    owner_sub: Mapped[str] = mapped_column(Text, nullable=False)
    owner_email: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(String(MAX_DISPLAY_NAME_LENGTH), nullable=False)
    # Opt-out capability declaration (TECH-5822 follow-up): an EMPTY array is
    # the "accept every message type" sentinel, not "accept nothing" -- it is
    # the default for a caller that omits accepted_types at registration
    # (service._validate_display_name_and_accepted_types), and it
    # automatically covers any message type added to schemas.MESSAGE_TYPES in
    # the future with no row update needed. A non-empty array is an explicit,
    # deliberate restriction to exactly that set (service.
    # _enforce_message_type_accepted). Stays NOT NULL -- the sentinel is an
    # empty array, never NULL, so no column carries three-valued (NULL vs.
    # empty vs. populated) ambiguity.
    accepted_types: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    # Wire-schema version range this agent declares it can
    # correctly interpret. Both default to 1 (today's only version) via a
    # server_default in the migration, so existing rows backfill cleanly.
    min_schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    max_schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    # Frozen at first registration (service.register_agent) - an
    # admission-decision input (DESIGN.md §9), so a later re-registration
    # must never be able to change it. Self-declaring True on first
    # registration requires the caller's token to carry `comms:admin`
    # (scopes.py); see providers.comms.register.
    is_shared: Mapped[bool] = mapped_column(
        nullable=False, default=False, server_default=text("false")
    )
    # Not one of DESIGN.md §5's five listed columns, but an additive,
    # non-conflicting bookkeeping field: the idempotent `comms_register`
    # tool (§4) re-binds an existing agent row on every call, and needs a
    # timestamp for "last (re)registered" distinct from `created_at`.
    bound_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Last time service.reconcile_agent_ownership actually looked this agent
    # up against the configured OwnershipClient (TECH-5593 item 4) --
    # distinct from bound_at (last comms_register call) and updated_at (any
    # column change, including this one). NULL means "never reconciled",
    # which idx_agents_owner_reconciled_at sorts first so a fresh agent is
    # reconciled at least once before the batch cursor moves on to agents
    # already reconciled at least once -- this is what gives repeated
    # reconciliation calls forward progress through the whole table instead
    # of re-checking the same oldest-bound_at page forever.
    owner_reconciled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class Conversation(Base):
    """A typed, expiring conversation between board agents."""

    __tablename__ = "conversations"
    __table_args__ = (
        CheckConstraint(f"state IN {CONVERSATION_STATES!r}", name="ck_conversations_state"),
        Index("idx_conversations_state_expires_at", "state", "expires_at"),
        Index("idx_conversations_created_by_created_at", "created_by", "created_at"),
        # Sparse partial index over archived rows only -- there is no
        # read path today that lists "all archived conversations" (archiving
        # is a per-conversation flag, not a filter comms_list_conversations
        # exposes), but this mirrors every other nullable-timestamp column's
        # declared-index convention in this file (see owner_reconciled_at
        # above) rather than leaving a plausible future query with no index
        # to land on.
        Index(
            "idx_conversations_archived_at",
            "archived_at",
            postgresql_where=text("archived_at IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    type: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    # Frozen verified owner-set snapshot at creation time (DESIGN.md §9),
    # ``{"owners": [...]}`` — populated only for
    # ``internal``/``asymmetric`` conversations (NULL for ``open``, which
    # has no ownership concept). ``service.invite`` reads this to reject an
    # invite that would introduce an owner outside the frozen set, rather
    # than silently expanding it or re-deriving it from current
    # participants (which would let a later invite retroactively loosen
    # admission for prior messages).
    owner_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # NULL = not archived (the default/common case); a timestamp = archived
    # at that instant (TECH-5887, comms_archive_conversation). Deliberately
    # NOT folded into ``state``/``CONVERSATION_STATES``: archiving is an
    # orthogonal, symmetric-permission flag layered on top of the existing
    # state machine, not a new state in it -- a conversation can be
    # archived while ``active``, ``completed``, ``canceled``, or ``expired``,
    # and archiving never runs a ``resulting_conversation_state`` transition
    # or interacts with ``is_message_legal``. Only two things key off this
    # column: ``service.invite``/``service.post_message`` (and
    # ``service.accept_invite`` -- see that function's own docstring for why
    # accept is treated the same as a new invite here) deny with the
    # specific ``ConversationArchivedError`` when it is set; every read path
    # (``get_conversation``, ``inbox``, ``list_conversations``) is
    # completely unaffected -- past messages remain fully readable forever,
    # archiving is not a delete or a redaction. Archiving has no undo path
    # (no "unarchive" tool) -- see ``service.archive_conversation``'s
    # docstring.
    archived_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class Participant(Base):
    """Membership row — membership IS visibility (checked at call time).

    Per DESIGN.md §4 (invite/accept revision): everyone added via
    ``start_conversation`` or ``invite`` starts as ``invited``, not
    ``active`` — no unilateral disclosure. ``joined_at`` is set only when
    the participant explicitly accepts (``invited`` -> ``active``);
    ``invited_at`` records when the invite/creation happened.
    """

    __tablename__ = "participants"
    __table_args__ = (
        CheckConstraint(f"role IN {PARTICIPANT_ROLES!r}", name="ck_participants_role"),
        CheckConstraint(f"status IN {PARTICIPANT_STATUSES!r}", name="ck_participants_status"),
        # Covers both service.inbox's pending-invites query (WHERE agent_id
        # = ... AND status = 'invited' ORDER BY invited_at DESC LIMIT ...,
        # added alongside its read-side page cap, TECH-5377) and every
        # other (agent_id, status)-only lookup this table previously used
        # its own separate 2-column idx_participants_agent_id_status for.
        # That 2-column index was dropped (Argus round-2 SUGGESTION): it
        # was a strict left-prefix of this one, so Postgres serves every
        # query it covered via this index's own prefix -- keeping both
        # would double index-maintenance cost on every participants
        # INSERT/UPDATE/DELETE for zero query-plan benefit.
        Index(
            "idx_participants_agent_id_status_invited_at",
            "agent_id",
            "status",
            "invited_at",
        ),
    )

    # The (conversation_id, agent_id) pair is the primary key, which also
    # provides the spec's UNIQUE(conversation_id, agent_id). No surrogate
    # `id` column: nothing else in the schema needs to reference an
    # individual participant row, so the composite PK is simpler and is
    # the idiomatic SQLAlchemy 2.x shape for a pure association/membership
    # table.
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id"), primary_key=True
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), primary_key=True)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id"), nullable=True)
    invited_at: Mapped[datetime] = mapped_column(nullable=False, server_default=text("now()"))
    joined_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_read_seq: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )


class Message(Base):
    """Append-only, schema-validated typed message. Never updated/deleted."""

    __tablename__ = "messages"
    __table_args__ = (
        # Doubles as the (conversation_id, seq) read index.
        UniqueConstraint("conversation_id", "seq", name="uq_messages_conversation_id_seq"),
        Index(
            "idx_messages_conversation_id_sender_id_created_at",
            "conversation_id",
            "sender_id",
            "created_at",
        ),
        # Backs service._enforce_sender_global_rate_limit's
        # WHERE sender_id = ... AND created_at > ... query (no
        # conversation_id predicate) -- the index above has conversation_id
        # as its leading column, so Postgres can't use it for a query that
        # never filters on conversation_id, and would sequential-scan
        # `messages` on every post_message/start_conversation call.
        # Same "declare here too, not just in the
        # migration" convention as every other migration-created index in
        # this file.
        Index("idx_messages_sender_id_created_at", "sender_id", "created_at"),
        # Backs service._conversation_has_note_history's
        # WHERE conversation_id = ... AND type IN ('note', 'instruction_share')
        # LIMIT 1 query (TECH-5735, broadened for TECH-5822) -- without this,
        # Postgres uses the composite index above (conversation_id-leading)
        # and scans every message in the conversation until it finds a match
        # or exhausts the set. Partial on plugins.BARRIER_SENSITIVE_TYPES's
        # current members since no other message type participates in this
        # lookup -- if that frozenset gains a member, this WHERE clause (and
        # migration c1a2b3d4e5f6) must be updated to match; there's no way to
        # derive a partial index predicate from a Python frozenset here.
        Index(
            "idx_messages_conversation_id_free_text",
            "conversation_id",
            postgresql_where=text("type IN ('note', 'instruction_share')"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    sender_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class AuditLog(Base):
    """Append-only audit trail: every mutation and every authorization denial."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("idx_audit_log_conversation_id", "conversation_id"),
        Index("idx_audit_log_at", "at"),
        # Backs service._deny_rate_limited_proposals's per-bot rate-limit
        # COUNT query -- see migration 9a1c2d3e4f5b's docstring for why the
        # rate-limit count lives on this append-only log rather than on
        # proposal_holds itself. Built CONCURRENTLY in the follow-on
        # migration a9faca2517d7 (split out from 9a1c2d3e4f5b per Argus
        # review B1, round 3); declared here as a normal Index like every
        # other index in this file -- postgresql_concurrently is a
        # migration-time build detail, not part of the index's identity
        # that autogenerate compares on.
        Index("idx_audit_log_actor_sub_action_at", "actor_sub", "action", "at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(nullable=False, server_default=text("now()"))
    actor_sub: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id"), nullable=True)
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversations.id"), nullable=True
    )
    message_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id"), nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


class ApprovalHold(Base):
    """A high-risk message, OR an invite requiring approval, held pending
    a human decision (TECH-5389 PR2, DESIGN.md §9 Axis 2; invite holds:
    TECH-5735).

    Mutable (status flips as the hold moves through its lifecycle), unlike
    ``messages``/``audit_log``'s append-only invariant — hence the
    ``updated_at`` column every other mutable table in this file has.

    ``kind`` discriminates the two shapes this row can take:

    - ``"message"`` (the original, TECH-5389 PR2): a high-risk message
      diverted from ``messages``. No ``high_risk`` boolean — a hold exists
      ONLY because the risk scorer's verdict was high-risk, so
      ``risk_reason``/``risk_scorer`` alone carry the verdict.
      ``sender_agent_id`` is the message's actual sender;
      ``target_agent_id`` is NULL; ``message_type``/``schema_version``/
      ``payload`` are the real held message content, inserted as-is into
      ``messages`` on approval.
    - ``"invite"`` (TECH-5735): an invite into a conversation that already
      has free-text (``note``) history — held because ``comms_accept``
      grants full retroactive history read the moment a participant is
      admitted, and that exposure can't be caught by any later per-message
      check. ``sender_agent_id`` is the INVITER's agent id (not a message
      sender); ``target_agent_id`` is the agent being invited;
      ``message_type``/``schema_version``/``payload`` carry placeholder/
      contextual values only (see ``service._divert_invite_for_approval``)
      — approval creates a ``Participant`` row, not a ``Message`` row.

    ``owner_sub`` IS snapshotted at hold-creation time (from the sender's
    — or for an invite hold, the inviter's — verified ``owner_sub`` claim,
    falling back to ``agents.owner_sub`` when absent) rather than read live
    from the ``agents`` row at decide time. Once agent-token verification
    becomes pluggable (a separate companion ticket, TECH-5396), a
    live-resolving verifier could change what ``agents.owner_sub`` means
    between hold-creation and decide-time, so a decide-time join to the
    frozen row is no longer equivalent to a snapshot -- see
    ``docs/TECH-5389-APPROVAL-PIPELINE.md`` §15.4.
    """

    __tablename__ = "approval_holds"
    __table_args__ = (
        CheckConstraint(f"status IN {APPROVAL_HOLD_STATUSES!r}", name="ck_approval_holds_status"),
        CheckConstraint(
            f"auto_decision IS NULL OR auto_decision IN {APPROVAL_HOLD_AUTO_DECISIONS!r}",
            name="ck_approval_holds_auto_decision",
        ),
        CheckConstraint(f"kind IN {APPROVAL_HOLD_KINDS!r}", name="ck_approval_holds_kind"),
        CheckConstraint(
            "kind != 'invite' OR target_agent_id IS NOT NULL",
            name="ck_approval_holds_invite_target_agent_id",
        ),
        UniqueConstraint("message_id", name="uq_approval_holds_message_id"),
        # Backs comms_get_hold_status's sender-only lookup and
        # GET /approvals/pending's owner-filtered pending_human listing,
        # both of which filter on (sender_agent_id, status) with
        # created_at as the sort column. The hold-rate-limit count
        # (_deny_rate_limited_holds) deliberately does NOT filter on
        # status -- it counts every hold created in the window regardless
        # of outcome, since a submission-spam control must count attempts,
        # not just currently-pending ones -- so this index only partially
        # serves that query (sender_agent_id + created_at range, scanning
        # across status values rather than a clean prefix match). Argus
        # round-1 caught this comment overclaiming full coverage; not
        # worth a dedicated index at current scale.
        Index(
            "idx_approval_holds_sender_agent_id_status_created_at",
            "sender_agent_id",
            "status",
            "created_at",
        ),
        # Backs GET /approvals/pending's owner-filtered pending_human listing
        # against the hold's own owner_sub snapshot, not a join to `agents`.
        Index(
            "idx_approval_holds_owner_sub_status_created_at",
            "owner_sub",
            "status",
            "created_at",
        ),
        Index("idx_approval_holds_conversation_id", "conversation_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id"), nullable=False
    )
    # For kind="message": the message's real sender. For kind="invite":
    # the INVITER (not a message sender at all) -- see class docstring.
    sender_agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), nullable=False)
    # kind="invite" only: the agent being invited. NULL for kind="message".
    # Named explicitly (matching the migration's pinned
    # `approval_holds_target_agent_id_fkey` -- see that migration's own
    # comment) so this can never diverge from the DB constraint's real
    # name if a `naming_convention` is later added to `Base.metadata`.
    target_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agents.id", name="approval_holds_target_agent_id_fkey"), nullable=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'message'"))
    # Snapshotted from the sender's (or, for kind="invite", the inviter's)
    # verified owner_sub claim at hold-creation time (fallback:
    # agents.owner_sub) -- see the class docstring and
    # docs/TECH-5389-APPROVAL-PIPELINE.md §15.4. Never the frozen agents row.
    owner_sub: Mapped[str] = mapped_column(Text, nullable=False)
    # kind="message": the ORIGINAL message type (e.g. "note") -- posts as
    # itself on approval. kind="invite": a fixed sentinel, not a real
    # schemas.MessageType (see service._divert_invite_for_approval).
    message_type: Mapped[str] = mapped_column(Text, nullable=False)
    # kind="invite" only: fixed at 1 (there is no real schema-version
    # concept for an invite; see service._divert_invite_for_approval).
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # kind="message": validated, normalized dump (insert-ready) --
    # schemas.validate_payload's output, exactly what would have gone into
    # messages.payload had the verdict not been high-risk. kind="invite":
    # contextual info for the human reviewer (target_agent_id is already
    # its own column; this also carries e.g. target_display_name) --
    # already surfaced generically by list_pending_approval_holds.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # kind="message": the risk scorer's verdict reason (e.g.
    # "boundary_crossing"). kind="invite": always
    # "note_history_requires_approval" (see service.INVITE_HOLD_RISK_REASON).
    risk_reason: Mapped[str] = mapped_column(Text, nullable=False)
    # kind="invite" only: a fixed label, not a real plugins.RISK_SCORERS
    # name -- no RiskScorer plugin is invoked for an invite hold.
    risk_scorer: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    auto_approver: Mapped[str | None] = mapped_column(Text, nullable=True)
    auto_decision: Mapped[str | None] = mapped_column(Text, nullable=True)
    auto_decided_at: Mapped[datetime | None] = mapped_column(nullable=True)
    decided_by_sub: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Optional free-text human "why" (both directions -- approve or reject).
    # The one deliberate free-text field outside `note`: it flows in exactly
    # one direction, human -> the submitting agent's own owner, never
    # crossing into another owner's trust domain (DESIGN.md §8/§9's
    # no-free-text posture is about inter-agent payloads, not this).
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    message_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id"), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class ProposalHold(Base):
    """A generalized bot-action human-approval escape hatch (TECH-5871).

    A sibling table to ``approval_holds``, not a variant of it --
    ``approval_holds`` is specifically the message/invite-diversion
    pipeline for THIS board's own comms traffic (TECH-5389/TECH-5735).
    ``proposal_holds`` generalizes the same "propose, hold for a human,
    decide, apply" shape to any autonomous bot's arbitrary action
    (starting with a Linear tech-team progress bot on ReClaw), independent
    of whether the proposer is a board-registered ``agents`` row at all --
    hence ``proposed_by_bot_id``/``decided_by_actor_id`` are plain opaque
    identifiers here, not FKs to ``agents``.

    ``kind`` is, at the DB level, an OPEN TEXT column -- deliberately NOT
    CHECK-constrained -- same convention as ``conversations.type``/
    ``messages.type`` (see this module's docstring): adding a new
    bot/action kind is a code change, not a migration.

    That DB-level openness is broader than what the *service* currently
    accepts, though: ``service._derive_proposal_priority`` raises for any
    ``kind`` other than ``"linear_progress_update"`` -- e.g. a proposal
    with ``kind="arc_board_change"`` will 422 at submission time even
    though the column would happily store it. Adding a new kind requires
    both a new ``_derive_proposal_priority`` branch and a registered judge
    in ``_PROPOSAL_JUDGES``, not just writing the row.

    ``owner_sub`` is snapshotted at creation time from the proposing bot's
    verified owner claim (falling back to the agent-owner registry, same
    pattern as ``ApprovalHold.owner_sub`` -- see that class's docstring),
    not read live at decide time.

    ``confidence``/``importance``/``impact`` are self-reported by the
    proposing bot and purely advisory -- nothing in this schema or its
    constraints acts on them. ``priority`` looks identical (same
    ``PROPOSAL_HOLD_LEVELS`` vocabulary) but is a DIFFERENT column with a
    different contract: it is always derived server-side from ``kind`` +
    ``action`` by whatever service code creates the row, and a caller-
    supplied value for it must never be trusted or persisted as-is.

    ``target_fingerprint`` is a sha256 hex digest of the target's state at
    proposal-submission time, for detecting staleness (the target changed
    between proposal and decision/apply) -- compared, not stored as, a
    later re-fingerprint by whatever service code applies the action.

    The two CHECK constraints below enforce that ``decided_at``/
    ``decided_by_actor_id``/``decision_source`` are set if AND ONLY IF
    ``status`` has left ``"pending"``, and that ``applied_at`` is never set
    for any status other than ``"applied"``.
    """

    __tablename__ = "proposal_holds"
    __table_args__ = (
        CheckConstraint(f"status IN {PROPOSAL_HOLD_STATUSES!r}", name="ck_proposal_holds_status"),
        CheckConstraint(
            f"decision_source IS NULL OR decision_source IN {PROPOSAL_HOLD_DECISION_SOURCES!r}",
            name="ck_proposal_holds_decision_source",
        ),
        CheckConstraint(
            f"confidence IN {PROPOSAL_HOLD_LEVELS!r}", name="ck_proposal_holds_confidence"
        ),
        CheckConstraint(
            f"importance IN {PROPOSAL_HOLD_LEVELS!r}", name="ck_proposal_holds_importance"
        ),
        CheckConstraint(f"impact IN {PROPOSAL_HOLD_LEVELS!r}", name="ck_proposal_holds_impact"),
        CheckConstraint(f"priority IN {PROPOSAL_HOLD_LEVELS!r}", name="ck_proposal_holds_priority"),
        # decided_at/decided_by_actor_id/decision_source are null iff status
        # is still "pending" -- a decision (human or auto) always stamps all
        # three together, and none of them is ever set while pending.
        CheckConstraint(
            "(status = 'pending' AND decided_at IS NULL AND decided_by_actor_id IS NULL "
            "AND decision_source IS NULL) "
            "OR (status != 'pending' AND decided_at IS NOT NULL "
            "AND decided_by_actor_id IS NOT NULL AND decision_source IS NOT NULL)",
            name="ck_proposal_holds_decision_consistency",
        ),
        CheckConstraint(
            "status = 'applied' OR applied_at IS NULL",
            name="ck_proposal_holds_applied_at_consistency",
        ),
        # Backs a pending-queue listing (a future PR's endpoint/tool), same
        # shape as approval_holds' sender-scoped index -- ordered by
        # created_at within a status.
        Index("idx_proposal_holds_status_created_at", "status", "created_at"),
        # Backs an owner-filtered pending listing, same convention as
        # idx_approval_holds_owner_sub_status_created_at.
        Index(
            "idx_proposal_holds_owner_sub_status_created_at", "owner_sub", "status", "created_at"
        ),
        # DB-level backstop for the create-time dedup app-level SELECT in
        # service.create_proposal / service._proposal_dedup_where uses --
        # see migration 9a1c2d3e4f5b's own docstring for the full B1/B2
        # rationale. Declared here too so a future
        # `alembic revision --autogenerate` doesn't propose dropping it.
        # Predicate widened to also cover `applying` (migration
        # e2f7a91c5b34, Argus review round-3 B1): a claimed-but-not-yet-
        # terminal hold is not "pending" anymore, but it is very much
        # still a live in-flight duplicate a resubmission must be blocked
        # against -- `pending`-only left a ~10s window, for the duration
        # of the external Linear round-trip, where a resubmission with the
        # same dedup key found no `pending` row and inserted a fresh one,
        # silently bypassing dedup.
        Index(
            "idx_proposal_holds_pending_dedup",
            "kind",
            "proposed_by_bot_id",
            text("(action ->> 'target_id')"),
            text("(action ->> 'action_type')"),
            postgresql_where=text("status IN ('pending', 'applying')"),
            unique=True,
        ),
        # Backs proposed_by_bot_id-scoped lookups (an ops/observability
        # query, or a future per-bot listing) -- see migration
        # 9a1c2d3e4f5b's docstring (S1).
        Index("idx_proposal_holds_bot_id_created_at", "proposed_by_bot_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_by_bot_id: Mapped[str] = mapped_column(Text, nullable=False)
    owner_sub: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(Text, nullable=False)
    importance: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'pending'"))
    decision_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by_actor_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(nullable=True)
    apply_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


__all__ = [
    "AGENT_STATUSES",
    "APPROVAL_HOLD_AUTO_DECISIONS",
    "APPROVAL_HOLD_KINDS",
    "APPROVAL_HOLD_STATUSES",
    "CONVERSATION_STATES",
    "PARTICIPANT_ROLES",
    "PARTICIPANT_STATUSES",
    "PROPOSAL_HOLD_DECISION_SOURCES",
    "PROPOSAL_HOLD_LEVELS",
    "PROPOSAL_HOLD_STATUSES",
    "Agent",
    "ApprovalHold",
    "AuditLog",
    "Base",
    "Conversation",
    "Message",
    "Participant",
    "ProposalHold",
]
