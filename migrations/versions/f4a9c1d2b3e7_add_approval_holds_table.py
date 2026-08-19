"""add approval_holds table

Revision ID: f4a9c1d2b3e7
Revises: 136265b3f22d
Create Date: 2026-08-17 00:00:02.000000

TECH-5389 PR2: the approval-holds pipeline's data model (docs/TECH-5389-
APPROVAL-PIPELINE.md §5/§12). One additive table -- ``boundary_safe`` never
existed in the DB (its removal, done in PR1, was code-only), so there is
nothing to migrate away from.

DEPLOYMENT: safe for a normal rolling deploy, same reasoning as every prior
additive migration in this directory (a1b2c3d4e5f6, 6d2a8e63e469, etc.) --
a brand-new table with no existing readers/writers until this PR's own
code (service.py's diversion flow) ships in the same deploy, and
``entrypoint.sh`` already runs ``alembic upgrade head`` before the service
starts serving, atomically, on every container startup.

Uses ``if_not_exists``/``if_exists`` guards for indexes (matching this
directory's convention), but NOT for ``create_table``/the unique constraint
(Postgres has no ``CREATE TABLE IF NOT EXISTS`` that Alembic can still
manage, and no ``ADD CONSTRAINT IF NOT EXISTS`` at all -- same asymmetry
6d2a8e63e469 already documents and accepts for the same reason).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f4a9c1d2b3e7"
down_revision: str | None = "136265b3f22d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_holds",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("conversation_id", sa.UUID(), nullable=False),
        sa.Column("sender_agent_id", sa.UUID(), nullable=False),
        sa.Column("owner_sub", sa.Text(), nullable=False),
        sa.Column("message_type", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_reason", sa.Text(), nullable=False),
        sa.Column("risk_scorer", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("auto_approver", sa.Text(), nullable=True),
        sa.Column("auto_decision", sa.Text(), nullable=True),
        sa.Column("auto_decided_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("decided_by_sub", sa.Text(), nullable=True),
        sa.Column("decided_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("message_id", sa.UUID(), nullable=True),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
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
        sa.CheckConstraint(
            "status IN ('pending_auto', 'pending_human', 'auto_approved', 'approved', "
            "'rejected', 'expired')",
            name="ck_approval_holds_status",
        ),
        sa.CheckConstraint(
            "auto_decision IS NULL OR auto_decision IN ('cleared', 'escalated')",
            name="ck_approval_holds_auto_decision",
        ),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"]),
        sa.ForeignKeyConstraint(["sender_agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("message_id", name="uq_approval_holds_message_id"),
    )
    op.create_index(
        "idx_approval_holds_sender_agent_id_status_created_at",
        "approval_holds",
        ["sender_agent_id", "status", "created_at"],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(
        "idx_approval_holds_owner_sub_status_created_at",
        "approval_holds",
        ["owner_sub", "status", "created_at"],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(
        "idx_approval_holds_conversation_id",
        "approval_holds",
        ["conversation_id"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_approval_holds_conversation_id", table_name="approval_holds", if_exists=True)
    op.drop_index(
        "idx_approval_holds_owner_sub_status_created_at",
        table_name="approval_holds",
        if_exists=True,
    )
    op.drop_index(
        "idx_approval_holds_sender_agent_id_status_created_at",
        table_name="approval_holds",
        if_exists=True,
    )
    op.execute("DROP TABLE IF EXISTS approval_holds")
