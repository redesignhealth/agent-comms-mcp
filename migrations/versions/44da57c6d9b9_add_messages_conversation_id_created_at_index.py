"""add messages conversation_id/created_at index

Revision ID: 44da57c6d9b9
Revises: 572b2b9a96d6
Create Date: 2026-09-11 00:00:00.000000

TECH-6197 (Argus round-1 BLOCKING): ``service.get_conversation``'s new
context-band query (``WHERE conversation_id = ? AND created_at >= ? AND
created_at < ? ORDER BY seq DESC LIMIT 501``) filters on
``(conversation_id, created_at)`` with no ``sender_id`` or leading ``seq``
predicate. Neither existing index supports that: ``uq_messages_conversation_id_seq``
is on ``(conversation_id, seq)`` (which already serves the in-window query's
``seq > ?`` predicate, but has no ``seq`` filter here to range-scan on),
and ``idx_messages_conversation_id_sender_id_created_at`` has ``sender_id``
between ``conversation_id`` and ``created_at``, so Postgres can't use it for
a range scan on ``created_at`` alone. Without this index, the context-band
query on a long-lived conversation would fall back to a full scan + filter
instead of an index range scan -- making the new 72h-default read path
slower than the old full-history path.

Purely additive (no column/constraint change) -- an old container that
doesn't know about this index simply never uses it and is unaffected by
its presence.

Not ``CREATE INDEX CONCURRENTLY``: matches this repo's established
``messages``-table convention (see b2bb6ccde02e, c1a2b3d4e5f6,
f3a1b9c7d2e4 -- all reasoned identically) of a plain, transactional
``CREATE INDEX`` for this table, since it is not yet large enough for the
brief ``ShareLock`` window a normal index build takes to matter. This is a
plain composite index (no partial predicate, nothing to DROP first), so it
uses ``op.create_index``/``op.drop_index`` directly rather than those three
migrations' raw ``op.execute`` DDL -- same structural shape as the sibling
``idx_messages_conversation_id_sender_id_created_at`` index added in
18f2d7735523.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "44da57c6d9b9"
down_revision: str | None = "572b2b9a96d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "idx_messages_conversation_id_created_at",
        "messages",
        ["conversation_id", "created_at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    # Schema-qualified per this migration chain's established convention
    # (see da3e1646c44d, bb1ea7d2a0cf) -- unqualified DROP INDEX under a
    # wrong search_path would silently no-op with if_exists=True.
    op.drop_index(
        "idx_messages_conversation_id_created_at",
        table_name="messages",
        schema="public",
        if_exists=True,
    )
