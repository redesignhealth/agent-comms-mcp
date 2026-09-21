"""add sender_agent_id to proposal_holds

Revision ID: c74fb78c66e4
Revises: 44da57c6d9b9
Create Date: 2026-09-21 00:00:00.000000

TECH-6668: adds best-effort bot/agent attribution to ``proposal_holds``,
mirroring ``approval_holds.sender_agent_id``, WITHOUT requiring proposers to
be registered board agents.

Adds a single nullable UUID column, ``sender_agent_id``, referencing
``agents(id)``. This column is nullable and stays nullable because
``ProposalHold``'s design contract is that a proposing bot need not be
board-registered at all (cite ``main.py``'s
``_authenticate_proposal_submitter`` docstring and ``providers/proposals.py``'s
``_require_bot_sub`` docstring, which both state this explicitly) -- NULL
means "submitter is not a registered agent," never "lookup failed," and no
backfill is possible or intended for pre-existing rows.

Pure additive column, nullable, with a foreign key created NOT VALID and
validated in a separate step, plus a composite index on
``(sender_agent_id, status, created_at)``. Safe for a normal rolling deploy
in either direction.

``downgrade()`` drops the index, FK constraint, and column, all with
``if_exists=True`` guards.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c74fb78c66e4"
down_revision: str | None = "44da57c6d9b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "proposal_holds",
        sa.Column("sender_agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True,
    )
    op.create_foreign_key(
        "fk_proposal_holds_sender_agent_id",
        "proposal_holds",
        "agents",
        ["sender_agent_id"],
        ["id"],
        postgresql_not_valid=True,
    )
    op.execute("ALTER TABLE proposal_holds VALIDATE CONSTRAINT fk_proposal_holds_sender_agent_id")
    op.create_index(
        "idx_proposal_holds_sender_agent_id_status_created_at",
        "proposal_holds",
        ["sender_agent_id", "status", "created_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_proposal_holds_sender_agent_id_status_created_at",
        table_name="proposal_holds",
        schema="public",
        if_exists=True,
    )
    op.drop_constraint(
        "fk_proposal_holds_sender_agent_id",
        "proposal_holds",
        type_="foreignkey",
        if_exists=True,
    )
    op.drop_column("proposal_holds", "sender_agent_id", if_exists=True)
