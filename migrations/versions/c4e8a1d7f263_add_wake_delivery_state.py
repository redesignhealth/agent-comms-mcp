"""add wake_delivery_state (TECH-9890)

Revision ID: c4e8a1d7f263
Revises: b5d2e8f41a96
Create Date: 2026-11-24 00:00:00.000000

TECH-9890: one brand-new table holding the wake delivery pause switch. At most
one row (``id`` is always 1); no row means delivery is on. No row is seeded, so
this ships un-paused. Purely additive; ``downgrade()`` drops it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4e8a1d7f263"
down_revision: str | None = "b5d2e8f41a96"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "wake_delivery_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("paused", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("paused_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("paused_by", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_wake_delivery_state_single_row"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("wake_delivery_state")
