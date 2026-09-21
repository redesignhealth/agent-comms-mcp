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

Pure additive column, nullable, with a foreign key created NOT VALID
(``postgresql_not_valid=True``) so this migration only takes a brief
``ACCESS EXCLUSIVE`` lock to add the catalog entries -- no table scan, since
``NOT VALID`` skips checking existing rows. The scan that validates existing
rows is deferred to the next migration (``ef3600cf1d37``), which runs it in
its own transaction so it takes ``SHARE UPDATE EXCLUSIVE`` instead of
``ACCESS EXCLUSIVE`` (matching the established pattern of ``cf72736e07f5`` /
``572b2b9a96d6``). Safe for a normal rolling deploy in either direction.

``downgrade()`` drops the FK constraint and column using raw SQL with genuine
``IF EXISTS`` guards for true idempotence.
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


def downgrade() -> None:
    op.execute(
        "ALTER TABLE proposal_holds DROP CONSTRAINT IF EXISTS fk_proposal_holds_sender_agent_id"
    )
    op.execute("ALTER TABLE proposal_holds DROP COLUMN IF EXISTS sender_agent_id")
