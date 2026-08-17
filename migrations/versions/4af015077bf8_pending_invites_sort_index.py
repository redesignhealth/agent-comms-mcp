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

The now-redundant ``idx_participants_agent_id_status`` (superseded by
this migration's new index, a strict left-prefix of it) is dropped in
136265b3f22d, a SEPARATE later migration -- not folded into this one
(Argus round-3 BLOCKING catch): once a migration file is created and
pushed, it must be treated as immutable. Editing this file's own
``upgrade()`` in place to add that drop, as an earlier round of this
same PR briefly did, would silently no-op in any environment where
this exact revision had already been applied (alembic tracks
completion by revision id, not file content, so it would never re-run
to pick up the edit) -- the correct fix for "this migration should have
done more" is always a new migration, never a mutation of an existing
one.
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


def downgrade() -> None:
    op.drop_index(
        "idx_participants_agent_id_status_invited_at",
        table_name="participants",
        if_exists=True,
    )
