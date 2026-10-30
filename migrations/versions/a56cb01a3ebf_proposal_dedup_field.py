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

To prevent blocking write traffic against ``proposal_holds`` during index build:
1. Inside an ``autocommit_block()``, drop any leftover temporary index from a prior
   failed run (e.g. an INVALID index from an aborted CONCURRENTLY build) and build
   ``idx_proposal_holds_pending_dedup_new`` with ``CONCURRENTLY``. Uniqueness is checked
   as rows are scanned, while live reads and writes continue unimpeded.
2. In a brief transaction, drop the old narrower ``idx_proposal_holds_pending_dedup``
   and rename ``idx_proposal_holds_pending_dedup_new`` to ``idx_proposal_holds_pending_dedup``.
   Because drop and rename happen in a single transaction, uniqueness is enforced
   continuously without a gap, and the ACCESS EXCLUSIVE lock on the table catalog is held
   only for microseconds with zero table scan.

On downgrade:
Before attempting to restore the narrower index, the migration explicitly checks for
collisions on the narrow key among active rows (status IN ('pending', 'applying')).
If any collisions exist, it raises a RuntimeError instructing the operator to resolve
the duplicate active proposals manually. It never silently deletes or merges valid rows.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

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
    # 1. Build the replacement index concurrently outside a transaction so
    # live writes to proposal_holds are never blocked.
    with op.get_context().autocommit_block():
        op.drop_index(
            "idx_proposal_holds_pending_dedup_new",
            table_name="proposal_holds",
            if_exists=True,
            postgresql_concurrently=True,
        )
        op.create_index(
            "idx_proposal_holds_pending_dedup_new",
            "proposal_holds",
            list(_NEW_COLUMNS),
            unique=True,
            postgresql_where=_WHERE,
            postgresql_concurrently=True,
            if_not_exists=True,
        )

    # 2. Swap: drop the old index and rename the new one in a single transaction.
    # Uniqueness is preserved continuously and catalog lock duration is minimal.
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
    op.execute(
        "ALTER INDEX IF EXISTS idx_proposal_holds_pending_dedup_new "
        "RENAME TO idx_proposal_holds_pending_dedup"
    )


def downgrade() -> None:
    # Check for collisions on the narrow key first. Never delete or merge rows.
    if not context.is_offline_mode():
        bind = op.get_bind()
        if bind is not None:
            collisions = bind.execute(
                sa.text("""
                    SELECT
                        kind,
                        proposed_by_bot_id,
                        action ->> 'target_id' AS target_id,
                        action ->> 'action_type' AS action_type,
                        COALESCE(cross_brain ->> 'target_sub', '') AS cross_target_sub,
                        COUNT(*) AS count
                    FROM proposal_holds
                    WHERE status IN ('pending', 'applying')
                    GROUP BY
                        kind,
                        proposed_by_bot_id,
                        action ->> 'target_id',
                        action ->> 'action_type',
                        COALESCE(cross_brain ->> 'target_sub', '')
                    HAVING COUNT(*) > 1
                """)
            ).fetchall()
            if collisions:
                details = [
                    f"(kind={r[0]!r}, bot={r[1]!r}, target_id={r[2]!r}, "
                    f"action_type={r[3]!r}, cross_target={r[4]!r}): {r[5]} rows"
                    for r in collisions
                ]
                raise RuntimeError(
                    f"Cannot downgrade migration a56cb01a3ebf: found {len(collisions)} collision(s) "
                    f"on the narrow proposal dedup key among active pending/applying proposals: "
                    f"{'; '.join(details)}. An operator must manually resolve (decide, withdraw, "
                    f"or reject) duplicate proposals before the narrow unique index can be restored. "
                    f"No rows were deleted."
                )

    with op.get_context().autocommit_block():
        op.drop_index(
            "idx_proposal_holds_pending_dedup_old",
            table_name="proposal_holds",
            if_exists=True,
            postgresql_concurrently=True,
        )
        op.create_index(
            "idx_proposal_holds_pending_dedup_old",
            "proposal_holds",
            list(_OLD_COLUMNS),
            unique=True,
            postgresql_where=_WHERE,
            postgresql_concurrently=True,
            if_not_exists=True,
        )

    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
    op.execute(
        "ALTER INDEX IF EXISTS idx_proposal_holds_pending_dedup_old "
        "RENAME TO idx_proposal_holds_pending_dedup"
    )
