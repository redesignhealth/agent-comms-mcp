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
(Argus round-3 BLOCKING catch). This file went through two edits across
this same PR before landing here: an earlier round briefly added the
drop directly to this file's own ``upgrade()``/``downgrade()`` (since
reverted), which is exactly the risk the split into 136265b3f22d avoids
going forward -- neither this PR's branch nor this migration's revision
id has been applied anywhere outside local/CI testing, so no real
environment is actually stuck on that intermediate shape today, but
``downgrade()`` below still defensively recreates
``idx_participants_agent_id_status`` (guarded, a no-op if it's already
there) specifically to stay correct even if some transient local/CI run
during this PR's review did apply that intermediate revision and later
needs to downgrade through it.
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
    # Defensive recreate (Argus round-4 BLOCKING catch): a no-op if the
    # index is already there (the normal case, since 136265b3f22d's own
    # downgrade recreates it first when downgrading further than this
    # revision), but restores it if this exact revision was ever stamped
    # via this migration's briefly-mutated intermediate shape (see module
    # docstring) without 136265b3f22d on top of it -- without this, a
    # downgrade all the way to ef8394b37c8d would otherwise silently leave
    # `participants` with neither index.
    op.create_index(
        "idx_participants_agent_id_status",
        "participants",
        ["agent_id", "status"],
        if_not_exists=True,
    )
