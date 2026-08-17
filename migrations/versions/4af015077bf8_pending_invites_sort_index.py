"""add sort-covering index for pending-invites inbox query

Revision ID: 4af015077bf8
Revises: a1b2c3d4e5f6
Create Date: 2026-08-17 00:00:00.000000

DEPLOYMENT: safe for a normal rolling deploy, same reasoning as
a1b2c3d4e5f6 -- a plain additive index, no data migration, no
backward-compatibility concern for an old container running alongside a
migrated schema (an old container simply doesn't benefit from the new
index yet). Uses ``if_not_exists``/``if_exists`` for idempotent
upgrade/downgrade, matching this migrations directory's existing
convention (see a1b2c3d4e5f6).

Not run ``CONCURRENTLY``: this table is expected to stay small relative
to ``messages``, and ``entrypoint.sh`` already runs migrations inside a
single transactional ``alembic upgrade head`` before serving traffic --
a ``CONCURRENTLY`` index build can't run inside that transaction anyway
(Postgres disallows it), so adopting it here would need a separate
deployment step this migrations directory doesn't otherwise use.
Revisit if ``participants`` ever grows large enough for a
regular-build lock to matter in practice.

Also drops ``idx_participants_agent_id_status`` (from ef8394b37c8d,
initial schema): Argus round-2 SUGGESTION -- it's a strict left-prefix
of the new 3-column index, so Postgres serves every query it covered
via this one's own prefix. Keeping both would double index-maintenance
cost on every ``participants`` INSERT/UPDATE/DELETE for zero query-plan
benefit. Recreated in ``downgrade()`` to actually reverse this migration.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "4af015077bf8"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "idx_participants_agent_id_status_invited_at",
        "participants",
        ["agent_id", "status", "invited_at"],
        if_not_exists=True,
    )
    op.drop_index(
        "idx_participants_agent_id_status",
        table_name="participants",
        if_exists=True,
    )


def downgrade() -> None:
    op.create_index(
        "idx_participants_agent_id_status",
        "participants",
        ["agent_id", "status"],
        if_not_exists=True,
    )
    op.drop_index(
        "idx_participants_agent_id_status_invited_at",
        table_name="participants",
        if_exists=True,
    )
