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
pushed, it must be treated as immutable. An earlier round of this same
PR briefly violated that by editing this file's own
``upgrade()``/``downgrade()`` directly (since reverted) -- and a later
round briefly over-corrected by adding a "defensive" recreate of
``idx_participants_agent_id_status`` back into THIS file's
``downgrade()`` (also since removed, per Argus round-5 SUGGESTION): that
recreate was itself dead code in every reachable stamping history, since
downgrading through this revision always means 136265b3f22d's own
``downgrade()`` already ran first and recreated the index -- the
``if_not_exists=True`` guard would silently no-op every time, making the
code's own justifying comment factually false for any history that
could actually reach it. The lesson holding across all of this: a gap
in an already-pushed migration gets fixed by a new migration, never by
editing the existing one, even in the name of a defensive safety net.
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
