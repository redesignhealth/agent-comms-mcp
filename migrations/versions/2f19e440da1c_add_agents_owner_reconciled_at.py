"""add agents.owner_reconciled_at + reconciliation cursor index

Revision ID: 2f19e440da1c
Revises: f4a9c1d2b3e7
Create Date: 2026-08-24 00:00:00.000000

TECH-5593 item 4, Argus round-1 BLOCKING fix: ``service.reconcile_agent_ownership``
previously had no way to make forward progress across repeated calls --
``ORDER BY bound_at ASC LIMIT N`` with nothing written back meant every
call re-processed the identical oldest-N rows forever, and any agent past
the first page was never reconciled. ``owner_reconciled_at`` gives that
function a per-agent cursor: it stamps ``now()`` on every agent it actually
looks up (whether or not the lookup changed anything), and orders by this
column (NULLS FIRST) instead of ``bound_at`` -- a just-checked agent sorts
to the back of the queue, so the next call naturally advances.

DEPLOYMENT: safe for a normal rolling deploy, same reasoning as
a1b2c3d4e5f6/4af015077bf8 -- a plain additive, nullable column (no
``server_default`` needed: NULL means "never reconciled", which is the
correct value for every pre-existing row) plus a plain additive partial
index. An old container running alongside a migrated schema simply never
reads or writes this column, and reconciliation for `is_shared` or non-
`active` agents was never supported anyway -- the partial index's
``WHERE`` mirrors the query's own filter, per column-index-parity with
every other index in this table (see ``idx_agents_lower_owner_email_active``'s
own comment on why this file keeps that declaration in sync with
``models.py`` by hand).

Rollback: dropping the column is safe -- it is pure reconciliation
bookkeeping, read by nothing else.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "2f19e440da1c"
down_revision: str | None = "f4a9c1d2b3e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("owner_reconciled_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        "idx_agents_owner_reconciled_at",
        "agents",
        [sa.text("owner_reconciled_at ASC NULLS FIRST")],
        postgresql_where=sa.text("status = 'active' AND is_shared = false"),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_agents_owner_reconciled_at", table_name="agents", if_exists=True)
    op.drop_column("agents", "owner_reconciled_at", if_exists=True)
