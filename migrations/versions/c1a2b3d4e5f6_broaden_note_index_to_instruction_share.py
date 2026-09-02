"""broaden messages conversation_id note index to instruction_share

Revision ID: c1a2b3d4e5f6
Revises: a45f344c9c00
Create Date: 2026-09-01 21:00:00.000000

TECH-5822: ``service._conversation_has_note_history`` (TECH-5735's
invite-time free-text approval gate) now also checks for
``instruction_share`` history, since that type joined ``note`` in
``plugins.BARRIER_SENSITIVE_TYPES`` as a second bounded-but-real free-text
type. The existing ``idx_messages_conversation_id_note`` partial index
(``WHERE type = 'note'``) can't serve a query that also matches
``instruction_share`` rows, so this migration drops it and creates a
replacement partial index covering both types. If ``BARRIER_SENSITIVE_TYPES``
gains a third free-text type in the future, this index's ``WHERE`` clause
must be updated to match -- there is no way to derive a partial index
predicate from a Python frozenset at migration-authoring time, so this is a
manual sync point, same as the frozenset's own membership.

DEPLOYMENT: safe for a normal rolling deploy -- an old container still
running ``WHERE type = 'note'``-only queries continues to work fine against
the broadened index (a query's own WHERE clause doesn't have to name every
value the index's WHERE clause covers).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "c1a2b3d4e5f6"
down_revision: str | None = "a45f344c9c00"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Not CREATE INDEX CONCURRENTLY: matches b2bb6ccde02e's own rationale --
    # Alembic's env.py wraps every migration in a transaction, and this
    # table is not yet large enough for the ShareLock window to matter.
    op.execute("DROP INDEX IF EXISTS public.idx_messages_conversation_id_note")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_free_text "
        "ON messages (conversation_id) "
        "WHERE type IN ('note', 'instruction_share')"
    )


def downgrade() -> None:
    # Schema-qualified per this migration chain's established convention
    # (see bb1ea7d2a0cf) -- unqualified DROP INDEX under a wrong search_path
    # would silently no-op.
    op.execute("DROP INDEX IF EXISTS public.idx_messages_conversation_id_free_text")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_note "
        "ON messages (conversation_id) "
        "WHERE type = 'note'"
    )
