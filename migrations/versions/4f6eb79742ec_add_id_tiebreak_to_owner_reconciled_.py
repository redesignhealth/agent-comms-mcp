"""add id tiebreak to owner_reconciled_at reconciliation index

Revision ID: 4f6eb79742ec
Revises: 2f19e440da1c
Create Date: 2026-08-24 01:00:00.000000

TECH-5593 item 4, Argus round-2 SUGGESTION (treated as load-bearing, not
cosmetic -- see this migration's own reasoning below): the previous
revision's ``idx_agents_owner_reconciled_at`` ordered by
``owner_reconciled_at`` alone. ``service.reconcile_agent_ownership`` reads
``now()`` ONCE per call and stamps that same value on every agent processed
in the batch, so once a single reconciliation run's tie group grows past
``limit``, an ``owner_reconciled_at``-only ``ORDER BY ... LIMIT n`` has no
defined tiebreak -- Postgres is free to return a different arbitrary subset
of that tied group on successive calls, silently reintroducing the exact
staleness-starvation failure mode this whole cursor column was added (in
the immediately prior revision) to fix. Adding ``id`` as a second,
purely-mechanical sort key (a primary key is already a stable total order;
it carries no semantic meaning here) makes the ordering deterministic
across calls even within a tied group.

A NEW migration, not an edit to ``2f19e440da1c`` (that revision is
immutable from the moment it was pushed -- see e.g.
``da3e1646c44d``'s own docstring on why this repo never edits an
already-pushed migration file, even to fix a gap found in the same PR).

DEPLOYMENT: safe for a normal rolling deploy -- ``DROP INDEX`` +
``CREATE INDEX`` (not ``CONCURRENTLY``, matching every other index in this
migrations directory; see 4af015077bf8's own comment on why) on a small
table (``agents``), no data migration, and no code in this repo queries
the index by name -- only by the columns/predicate ``reconcile_agent_
ownership``'s ORDER BY already specifies, which this migration keeps in
sync with. Briefly index-less between the DROP and CREATE, both inside the
same transactional ``alembic upgrade head``, which is an acceptable window
for a table this size.

Rollback: recreates the single-column index from ``2f19e440da1c`` --
correct, since a downgrade to that revision means production code will
only ever run its ORDER BY again (``owner_reconciled_at`` only), not this
revision's two-column ORDER BY.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4f6eb79742ec"
down_revision: str | None = "2f19e440da1c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_WHERE = sa.text("status = 'active' AND is_shared = false")


def upgrade() -> None:
    op.drop_index("idx_agents_owner_reconciled_at", table_name="agents", if_exists=True)
    op.create_index(
        "idx_agents_owner_reconciled_at",
        "agents",
        [sa.text("owner_reconciled_at ASC NULLS FIRST"), "id"],
        postgresql_where=_WHERE,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_agents_owner_reconciled_at", table_name="agents", if_exists=True)
    op.create_index(
        "idx_agents_owner_reconciled_at",
        "agents",
        [sa.text("owner_reconciled_at ASC NULLS FIRST")],
        postgresql_where=_WHERE,
        if_not_exists=True,
    )
