"""index messages conversation_id note type

Revision ID: b2bb6ccde02e
Revises: e73892f01b89
Create Date: 2026-08-28 00:03:52.559445

TECH-5735: backs ``service._conversation_has_note_history``'s
``WHERE conversation_id = ? AND type = 'note' LIMIT 1`` query. Without this,
Postgres uses the existing ``(conversation_id, sender_id, created_at)``
composite index for the ``conversation_id`` predicate alone, then scans every
message row in the conversation until it finds a note or exhausts the set --
O(N) per ``invite`` call on a note-free conversation with many messages.
Partial on ``type = 'note'`` since no other message type participates in
this lookup.

DEPLOYMENT: safe for a normal rolling deploy -- a pure additive index, no
column/constraint change. An old container running alongside a migrated
schema never queries this index and is unaffected by its presence.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "b2bb6ccde02e"
down_revision: str | None = "e73892f01b89"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Not CREATE INDEX CONCURRENTLY: that can't run inside a transaction,
    # and Alembic's env.py wraps every migration in one by default. The
    # ShareLock this acquires blocks writes to `messages` for the duration
    # of the build, a negligible window at today's table size -- revisit if
    # `messages` grows large enough for that lock to matter.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_note "
        "ON messages (conversation_id) "
        "WHERE type = 'note'"
    )


def downgrade() -> None:
    # Schema-qualified per this migration chain's established convention
    # (see bb1ea7d2a0cf): unqualified DROP INDEX under a wrong search_path
    # would silently no-op (IF EXISTS makes that failure invisible),
    # leaving the index behind for a later re-upgrade to collide with.
    op.execute("DROP INDEX IF EXISTS public.idx_messages_conversation_id_note")
