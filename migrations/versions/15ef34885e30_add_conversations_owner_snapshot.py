"""add conversations owner_snapshot

Revision ID: 15ef34885e30
Revises: 6d2a8e63e469
Create Date: 2026-08-12 13:54:44.149046

Adds ``conversations.owner_snapshot``, which records the verified
owner-set union at conversation-open time for ``internal``/``asymmetric``
conversations (NULL for ``open``, which has no ownership concept) — see
``service._authorize_conversation_open``/``service.invite``'s owner-set-
freeze check.

Also backfills any pre-existing ``conversations.type = 'scheduling.availability'``
rows to ``'open'`` (the rename). ``type`` has no DB-level
CHECK constraint, so a row created under the pre-rename code (already
merged/deployed per ``6d2a8e63e469``'s own note) would otherwise be silent
dead weight that every ``internal``/``asymmetric``-only code path (boundary
crossing, invite-freeze) fails closed on — ``owner_snapshot`` stays NULL
for these rows post-backfill, exactly as it does for every other ``open``
conversation, so no further data migration is needed.

NOTE on in-place amendment: authored and iterated on entirely within this
single unmerged PR -- it does not exist on `main`, and has
never been applied to any persistent or shared database. In-place
amendment during code review is therefore safe. Once this PR merges, treat
this file as frozen: any further schema change requires a NEW Alembic
revision, never an edit to this one (mirrors 6d2a8e63e469's own note,
which — unlike this one — IS already applied on `main`/dev, so
phase 3 drops the `tasks` table via a new revision rather than editing
6d2a8e63e469 in place).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "15ef34885e30"
down_revision: str | None = "6d2a8e63e469"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "conversations",
        sa.Column("owner_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        if_not_exists=True,
    )
    op.execute(
        "UPDATE conversations SET type = 'open', updated_at = now() "
        "WHERE type = 'scheduling.availability'"
    )


def downgrade() -> None:
    # Not reversed: renaming 'open' back to 'scheduling.availability' would
    # also catch rows that were genuinely created as 'open' post-rename, not
    # just the backfilled legacy rows -- there is no way to distinguish them
    # after the fact. Same lossy-downgrade posture as da3e1646c44d.
    op.drop_column("conversations", "owner_snapshot", if_exists=True)
