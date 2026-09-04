"""broaden messages conversation_id free-text index to docs

Revision ID: f3a1b9c7d2e4
Revises: e2f7a91c5b34
Create Date: 2026-09-04 00:00:00.000000

TECH-5998: ``docs`` (a summary + citation-list message type, verified by
the new ``plugins.DocsVerifier`` seam before it can reach a recipient)
joins ``note`` and ``instruction_share`` in ``plugins.BARRIER_SENSITIVE_TYPES``
as a third bounded-but-real free-text type -- a ``docs`` summary is
human-authored free text same as a ``note``, so ``invite``'s pre-existing
free-text history gate (``service._conversation_has_note_history``, TECH-5735,
broadened once already for ``instruction_share`` in c1a2b3d4e5f6) must treat
it identically: admitting a new participant into a conversation with prior
``docs`` history needs the same retroactive-read scrutiny as prior ``note``
or ``instruction_share`` history. The existing
``idx_messages_conversation_id_free_text`` partial index
(``WHERE type IN ('note', 'instruction_share')``) can't serve a query that
also matches ``docs`` rows, so this migration drops it and creates a
replacement partial index covering all three types. If
``BARRIER_SENSITIVE_TYPES`` gains a fourth free-text type in the future,
this index's ``WHERE`` clause must be updated to match -- there is no way to
derive a partial index predicate from a Python frozenset at
migration-authoring time, so this is a manual sync point, same as the
frozenset's own membership (see models.py's own comment on this index).

DEPLOYMENT: safe for a normal rolling deploy -- an old container still
running ``WHERE type IN ('note', 'instruction_share')``-only queries
continues to work fine against the broadened index (a query's own WHERE
clause doesn't have to name every value the index's WHERE clause covers).

DOWNGRADE HAZARD (Argus round 1): ``downgrade()`` narrows the index back to
``WHERE type IN ('note', 'instruction_share')``, which no longer covers
``docs`` rows. If code and migrations ever roll back independently -- an
old migration state applied against code that still posts/queries ``docs``
messages (e.g. a partial rollback, or this migration reverted ahead of
``plugins.BARRIER_SENSITIVE_TYPES`` itself being reverted) --
``_conversation_has_note_history``'s query against ``docs`` history would
fall back to a full table scan instead of an index scan. That's a silent
performance regression, not a correctness one: the query still returns the
right answer, just slower as ``messages`` grows. Re-apply this migration
(or avoid downgrading past it while ``docs`` is still a live message type)
rather than accepting the scan.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "f3a1b9c7d2e4"
down_revision: str | None = "e2f7a91c5b34"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Not CREATE INDEX CONCURRENTLY: matches c1a2b3d4e5f6's own rationale --
    # Alembic's env.py wraps every migration in a transaction, and this
    # table is not yet large enough for the ShareLock window to matter.
    op.execute("DROP INDEX IF EXISTS public.idx_messages_conversation_id_free_text")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_free_text "
        "ON messages (conversation_id) "
        "WHERE type IN ('note', 'instruction_share', 'docs')"
    )


def downgrade() -> None:
    # Schema-qualified per this migration chain's established convention
    # (see bb1ea7d2a0cf) -- unqualified DROP INDEX under a wrong search_path
    # would silently no-op.
    op.execute("DROP INDEX IF EXISTS public.idx_messages_conversation_id_free_text")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_free_text "
        "ON messages (conversation_id) "
        "WHERE type IN ('note', 'instruction_share')"
    )
