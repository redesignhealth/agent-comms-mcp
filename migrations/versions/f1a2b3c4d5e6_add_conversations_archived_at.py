"""add conversations.archived_at

Revision ID: f1a2b3c4d5e6
Revises: d23b37d4e187
Create Date: 2026-09-03 00:00:00.000000

Rebased onto d23b37d4e187 (TECH-5871, proposal_holds table): both this
migration and d23b37d4e187 were originally authored against d5c8f1a2b4e7
concurrently; d23b37d4e187 merged to main first, so this one is re-chained
on top of it rather than left as a second head off the same parent.

TECH-5887: adds ``conversations.archived_at`` -- NULL means "not archived"
(the default, and the only value every pre-existing row can have, so this
is a pure additive widening with no backfill needed). A non-NULL timestamp
means the conversation was archived at that instant via the new
``comms_archive_conversation`` tool (``service.archive_conversation``).

Deliberately NOT folded into ``conversations.state``/``CONVERSATION_STATES``
-- see ``models.Conversation.archived_at``'s own docstring for why
archiving is an orthogonal flag layered on top of the state machine rather
than a new state value. No CHECK constraint is needed here: unlike `state`,
every value of this column (NULL or any timestamp) is valid.

Also adds a partial index over non-NULL rows only (``idx_conversations_
archived_at``), mirroring this file's existing sparse-nullable-column
index convention (e.g. ``idx_agents_owner_reconciled_at``) even though no
read path queries "all archived conversations" today -- see that index's
declaration in models.py for the same rationale.

Safe as a standard rolling deploy: an old container that doesn't know
about ``archived_at`` simply never reads or writes it; a new container
reads/writes it correctly from the moment this migration lands, whether
or not any row has ever been archived yet.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "d23b37d4e187"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "conversations",
        sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        "idx_conversations_archived_at",
        "conversations",
        ["archived_at"],
        unique=False,
        postgresql_where=sa.text("archived_at IS NOT NULL"),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_conversations_archived_at", table_name="conversations", if_exists=True)
    op.drop_column("conversations", "archived_at", if_exists=True)
