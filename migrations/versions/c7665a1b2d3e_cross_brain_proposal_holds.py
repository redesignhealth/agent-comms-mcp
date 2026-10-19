"""cross-brain columns on proposal_holds (TECH-7665)

Revision ID: c7665a1b2d3e
Revises: ef3600cf1d37
Create Date: 2026-10-19 00:00:00.000000

Adds two nullable JSONB columns (both NULL for every existing and every
own-brain hold, so legacy behavior is unchanged):

* ``cross_brain``: ``{target_sub, target_agent_id, target_display_name,
  target_owner_sub, target_owner_email, required_owner_subs}`` for a proposal
  that names ANOTHER agent's brain as its target.
* ``approvals``: ``[{sub, at}, ...]`` the human owners who have approved so far
  (a cross-brain hold applies only once every required owner has approved).

It also rebuilds ``idx_proposal_holds_pending_dedup`` with the cross-brain
target in the key, so two pending proposals with the same
``(kind, bot, target_id, action_type)`` but different cross-brain targets no
longer collide. The extra key is ``COALESCE(cross_brain ->> 'target_sub', '')``
-- the empty string for every non-cross-brain hold, so dedup for those is
byte-identical to before (a NULL would make every row distinct in a unique
index, which is why the COALESCE is load-bearing).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c7665a1b2d3e"
down_revision: str | None = "ef3600cf1d37"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_COLUMNS = (
    "kind",
    "proposed_by_bot_id",
    sa.text("(action ->> 'target_id')"),
    sa.text("(action ->> 'action_type')"),
)
_NEW_COLUMNS = (*_OLD_COLUMNS, sa.text("COALESCE(cross_brain ->> 'target_sub', '')"))
_WHERE = sa.text("status IN ('pending', 'applying')")


def upgrade() -> None:
    op.add_column(
        "proposal_holds", sa.Column("cross_brain", postgresql.JSONB(astext_type=sa.Text()))
    )
    op.add_column("proposal_holds", sa.Column("approvals", postgresql.JSONB(astext_type=sa.Text())))
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
    # A downgrade must be able to rebuild the narrower unique index: cross-brain
    # holds that only differ by target would collide, so drop them first.
    op.execute("DELETE FROM proposal_holds WHERE cross_brain IS NOT NULL")
    op.create_index(
        "idx_proposal_holds_pending_dedup",
        "proposal_holds",
        list(_OLD_COLUMNS),
        unique=True,
        postgresql_where=_WHERE,
        if_not_exists=True,
    )
    op.drop_column("proposal_holds", "approvals")
    op.drop_column("proposal_holds", "cross_brain")
