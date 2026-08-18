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
    claims at bind time — never from tool parameters.
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
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    sub: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    owner_sub: Mapped[str] = mapped_column(Text, nullable=False)
    owner_email: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(String(MAX_DISPLAY_NAME_LENGTH), nullable=False)
    accepted_types: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
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
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class Conversation(Base):
    """A typed, expiring conversation between board agents."""

    __tablename__ = "conversations"
    __table_args__ = (
        CheckConstraint(f"state IN {CONVERSATION_STATES!r}", name="ck_conversations_state"),
        Index("idx_conversations_state_expires_at", "state", "expires_at"),
        Index("idx_conversations_created_by_created_at", "created_by", "created_at"),
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
    """A high-risk message diverted from ``messages`` pending approval
    (TECH-5389 PR2, DESIGN.md §9 Axis 2).

    Mutable (status flips as the hold moves through its lifecycle), unlike
    ``messages``/``audit_log``'s append-only invariant — hence the
    ``updated_at`` column every other mutable table in this file has.

    No ``high_risk`` boolean: a hold exists ONLY because the risk scorer's
    verdict was high-risk, so ``risk_reason``/``risk_scorer`` alone carry
    the verdict. No ``owner_sub`` snapshot either: ``agents.owner_sub`` is
    frozen at first registration (``service.register_agent``), so the
    decide-time join against the live ``agents`` row reads the identical
    value a snapshot would have captured.
    """

    __tablename__ = "approval_holds"
    __table_args__ = (
        CheckConstraint(
            f"status IN {APPROVAL_HOLD_STATUSES!r}", name="ck_approval_holds_status"
        ),
        CheckConstraint(
            f"auto_decision IS NULL OR auto_decision IN {APPROVAL_HOLD_AUTO_DECISIONS!r}",
            name="ck_approval_holds_auto_decision",
        ),
        UniqueConstraint("message_id", name="uq_approval_holds_message_id"),
        # Backs the hold-rate-limit count, comms_get_hold_status's
        # sender-only lookup, and GET /approvals/pending's owner-filtered
        # pending_human listing -- all three key off (sender_agent_id,
        # status) with created_at as the sort/window column.
        Index(
            "idx_approval_holds_sender_agent_id_status_created_at",
            "sender_agent_id",
            "status",
            "created_at",
        ),
        Index("idx_approval_holds_conversation_id", "conversation_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id"), nullable=False
    )
    sender_agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), nullable=False)
    # The ORIGINAL message type (e.g. "note") -- posts as itself on approval.
    message_type: Mapped[str] = mapped_column(Text, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Validated, normalized dump (insert-ready) -- schemas.validate_payload's
    # output, exactly what would have gone into messages.payload had the
    # verdict not been high-risk.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    risk_reason: Mapped[str] = mapped_column(Text, nullable=False)
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


__all__ = [
    "AGENT_STATUSES",
    "APPROVAL_HOLD_AUTO_DECISIONS",
    "APPROVAL_HOLD_STATUSES",
    "CONVERSATION_STATES",
    "PARTICIPANT_ROLES",
    "PARTICIPANT_STATUSES",
    "Agent",
    "ApprovalHold",
    "AuditLog",
    "Base",
    "Conversation",
    "Message",
    "Participant",
]
