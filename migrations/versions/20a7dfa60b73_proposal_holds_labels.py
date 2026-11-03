"""add labels to proposal_holds (TECH-8080)

Revision ID: 20a7dfa60b73
Revises: 58dd9bd941a6
Create Date: 2026-10-30 00:00:00.000000

TECH-8080 PR9: stores a small routing/classification labels mapping on
``proposal_holds`` (lane, source_type, evidence_type) for the routine's
decision log.

Pure additive nullable JSONB column, no CHECK constraint, no backfill,
no index. Accepts every existing row's implicit NULL. Safe for a rolling deploy.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20a7dfa60b73"
down_revision: str | None = "58dd9bd941a6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "proposal_holds",
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_column("proposal_holds", "labels", if_exists=True)
