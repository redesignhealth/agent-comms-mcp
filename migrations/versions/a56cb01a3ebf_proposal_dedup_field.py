"""proposal_dedup_field (TECH-8080 PR3)

Revision ID: a56cb01a3ebf
Revises: c7665a1b2d3e
Create Date: 2026-10-30 14:50:16.707600

Rebuilds ``idx_proposal_holds_pending_dedup`` with ``COALESCE(action ->> 'dedup_field', '')``
as its sixth key component, so two pending proposals with the same
``(kind, bot, target_id, action_type, cross_target)`` but different
fields (e.g. startDate and targetDate on the same project) no longer collide.

The extra key is ``COALESCE(action ->> 'dedup_field', '')`` -- the empty string
for every proposal without a dedup_field (including every existing row),
so dedup behavior for all current traffic is byte-identical (a NULL would
make every row distinct in a unique index, which is why the COALESCE is
load-bearing). Widening a unique index's key set can only ever make rows
more distinct -- it can never cause a new collision on existing data, so
no row cleanup is needed on upgrade.

On downgrade, two live pending/applying rows differing only by dedup_field
could collide when narrowing the key. The downgrade resolves this by keeping
the oldest per narrow key.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a56cb01a3ebf"
down_revision: str | None = "c7665a1b2d3e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_COLUMNS = (
    "kind",
    "proposed_by_bot_id",
    sa.text("(action ->> 'target_id')"),
    sa.text("(action ->> 'action_type')"),
    sa.text("COALESCE(cross_brain ->> 'target_sub', '')"),
)
_NEW_COLUMNS = (*_OLD_COLUMNS, sa.text("COALESCE(action ->> 'dedup_field', '')"))
_WHERE = sa.text("status IN ('pending', 'applying')")


def upgrade() -> None:
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
    op.create_index(
        "idx_proposal_holds_pending_dedup",
        "proposal_holds",
        list(_NEW_COLUMNS),
        unique=True,
        postgresql_where=_WHERE,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
    # Narrowing CAN collide: two live rows differing only by dedup_field.
    # Resolve by keeping the oldest per narrow key.
    op.execute("""
        DELETE FROM proposal_holds a USING proposal_holds b
        WHERE a.status IN ('pending', 'applying')
          AND b.status IN ('pending', 'applying')
          AND a.kind = b.kind
          AND a.proposed_by_bot_id = b.proposed_by_bot_id
          AND a.action->>'target_id' = b.action->>'target_id'
          AND a.action->>'action_type' = b.action->>'action_type'
          AND COALESCE(a.cross_brain->>'target_sub', '')
            = COALESCE(b.cross_brain->>'target_sub', '')
          AND a.created_at > b.created_at
    """)
    op.create_index(
        "idx_proposal_holds_pending_dedup",
        "proposal_holds",
        list(_OLD_COLUMNS),
        unique=True,
        postgresql_where=_WHERE,
        if_not_exists=True,
    )
