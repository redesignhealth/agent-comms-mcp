"""drop redundant 2-column participants index superseded by 3-column one

Revision ID: 136265b3f22d
Revises: 4af015077bf8
Create Date: 2026-08-17 00:00:00.000001

DEPLOYMENT: safe for a normal rolling deploy, same reasoning as
a1b2c3d4e5f6/4af015077bf8 -- a plain index drop, no data migration. An
old container running alongside this migrated schema tolerates the
drop fine: `idx_participants_agent_id_status` (agent_id, status) is a
strict left-prefix of `idx_participants_agent_id_status_invited_at`
(agent_id, status, invited_at), added in 4af015077bf8, so every query
the old index served is still served by the new one's own prefix --
nothing in this codebase's query patterns changes behavior, only which
index Postgres picks.

Separate migration, not folded into 4af015077bf8 itself (Argus round-3
BLOCKING catch on an earlier round of this same PR, which briefly did
exactly that): once a migration file is created and pushed, alembic
tracks completion by revision id, not file content, so editing an
already-shared migration's `upgrade()` would silently no-op in any
environment that had already applied that exact revision. The correct
fix for "an earlier migration should have gone further" is always a
new migration.

Uses ``if_exists``/``if_not_exists`` for idempotent upgrade/downgrade,
matching this migrations directory's existing convention.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "136265b3f22d"
down_revision: str | None = "4af015077bf8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
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
