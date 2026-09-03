"""add proposal_holds table

Revision ID: d23b37d4e187
Revises: b2bb6ccde02e
Create Date: 2026-09-03 00:00:00.000000

TECH-5871: a new, sibling table to ``approval_holds`` -- NOT a modification
of it, and no existing consumer of ``approval_holds`` is touched by this
revision. ``approval_holds`` stays the message/invite-diversion pipeline
for this board's own comms traffic (TECH-5389/TECH-5735); ``proposal_holds``
generalizes the same "propose, hold for a human, decide, apply" shape to
any autonomous bot's arbitrary action (starting with a Linear tech-team
progress bot on ReClaw), keyed by an open ``kind`` discriminator rather
than a closed one. See models.py's ``ProposalHold`` docstring for the full
column-by-column rationale.

Migration only -- no endpoints/routes/business logic ship in this
revision (follow-on work, separate tickets/PRs).

DEPLOYMENT: safe for a normal rolling deploy, same reasoning as every
other purely-additive migration in this directory (f4a9c1d2b3e7, etc.) --
a brand-new table with no readers/writers anywhere in this codebase yet.

Uses ``if_not_exists``/``if_exists`` guards for indexes (matching this
directory's convention), but not for ``create_table`` (Postgres has no
``CREATE TABLE IF NOT EXISTS`` that Alembic can still manage).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d23b37d4e187"
down_revision: str | None = "b2bb6ccde02e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LEVELS = ("low", "medium", "high")
_STATUSES = ("pending", "approved", "rejected", "applied", "apply_failed", "stale")
_DECISION_SOURCES = ("human", "auto")


def upgrade() -> None:
    op.create_table(
        "proposal_holds",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        # Open vocabulary (e.g. "arc_board_change", "linear_progress_update")
        # -- deliberately NOT CHECK-constrained, same convention as
        # conversations.type/messages.type (see models.py's module
        # docstring): a new kind is a code change, not a migration.
        sa.Column("kind", sa.Text(), nullable=False),
        # Opaque bot identifier -- not an FK to `agents`. Proposers here are
        # not necessarily board-registered agents (see models.py's
        # ProposalHold docstring).
        sa.Column("proposed_by_bot_id", sa.Text(), nullable=False),
        sa.Column("owner_sub", sa.Text(), nullable=False),
        sa.Column("action", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Text(), nullable=False),
        sa.Column("importance", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        # Server-derived from kind + action, never caller-supplied -- see
        # ProposalHold.priority's docstring for how this differs from the
        # three self-reported columns above despite sharing a vocabulary.
        sa.Column("priority", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("decision_source", sa.Text(), nullable=True),
        sa.Column("decided_by_actor_id", sa.Text(), nullable=True),
        sa.Column("decided_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        # sha256 hex digest of the target's state at proposal-submission
        # time -- for detecting staleness between proposal and decide/apply.
        sa.Column("target_fingerprint", sa.Text(), nullable=False),
        sa.Column("applied_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("apply_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(f"status IN {_STATUSES!r}", name="ck_proposal_holds_status"),
        sa.CheckConstraint(
            f"decision_source IS NULL OR decision_source IN {_DECISION_SOURCES!r}",
            name="ck_proposal_holds_decision_source",
        ),
        sa.CheckConstraint(f"confidence IN {_LEVELS!r}", name="ck_proposal_holds_confidence"),
        sa.CheckConstraint(f"importance IN {_LEVELS!r}", name="ck_proposal_holds_importance"),
        sa.CheckConstraint(f"impact IN {_LEVELS!r}", name="ck_proposal_holds_impact"),
        sa.CheckConstraint(f"priority IN {_LEVELS!r}", name="ck_proposal_holds_priority"),
        sa.CheckConstraint(
            "(status = 'pending' AND decided_at IS NULL AND decided_by_actor_id IS NULL "
            "AND decision_source IS NULL) "
            "OR (status != 'pending' AND decided_at IS NOT NULL "
            "AND decided_by_actor_id IS NOT NULL AND decision_source IS NOT NULL)",
            name="ck_proposal_holds_decision_consistency",
        ),
        sa.CheckConstraint(
            "status = 'applied' OR applied_at IS NULL",
            name="ck_proposal_holds_applied_at_consistency",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_proposal_holds_status_created_at",
        "proposal_holds",
        ["status", "created_at"],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(
        "idx_proposal_holds_owner_sub_status_created_at",
        "proposal_holds",
        ["owner_sub", "status", "created_at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_proposal_holds_owner_sub_status_created_at",
        table_name="proposal_holds",
        if_exists=True,
    )
    op.drop_index(
        "idx_proposal_holds_status_created_at", table_name="proposal_holds", if_exists=True
    )
    op.execute("DROP TABLE IF EXISTS proposal_holds")
