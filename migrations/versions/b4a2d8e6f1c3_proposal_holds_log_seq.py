"""add proposal_holds log_seq and per-bot monotonic counter trigger (TECH-8080 PR10)

Revision ID: b4a2d8e6f1c3
Revises: fd6d97e05ca5
Create Date: 2026-10-30 00:00:00.000000

Adds a per-bot, commit-ordered ``log_seq`` column to ``proposal_holds`` backed by a
``proposal_bot_log_seq`` counter table and a BEFORE INSERT OR UPDATE trigger
``trg_proposal_holds_log_seq`` (TECH-8080 PR10).

RATIONALE FOR FIRST TRIGGER IN REPO:
Unlike messages.seq which is assigned under an application-held row lock on conversations,
proposing bots do not have an Agent table row to lock. Allocation order must strictly equal
commit order per bot to prevent incremental cursor feeds from missing rows committed late.
The database trigger ensures:
1. Operational raw SQL manual reconciliations of stuck holds (site 10) are automatically
   assigned a fresh log_seq and delivered to downstream cursor consumers.
2. Complex rollback/recovery paths in proposal finalization do not require threaded DB calls.
3. Every current and future write site on proposal_holds is guaranteed commit-ordered sequence
   assignment with zero deployment version-skew hazard.

LOCKING & DEPLOYMENT:
- Migration acquires ACCESS EXCLUSIVE on proposal_holds for the column addition, backfill,
  and trigger installation under a single bounded transaction with lock_timeout = 5s (SET LOCAL).
- Mid-migration autocommit_block() exits the transaction to run concurrent index builds,
  temporarily releasing env.py's pg_advisory_xact_lock(0x5245434C). To maintain cross-process
  migration serialization during this window, pg_advisory_lock(0x5245434C) is explicitly acquired
  in the autocommit block and released on exit.
- All steps before autocommit_block() are strictly idempotent and safe to re-run on retry.
- Backfill size guard protects against lock starvation if proposal_holds exceeds 100,000 rows.
- Trailing index builds for uq_proposal_holds_bot_id_log_seq and
  idx_proposal_holds_bot_id_status_log_seq run CONCURRENTLY in the autocommit block with
  pre-build INVALID recovery and post-build validity checks.

DEADLOCK CONSIDERATIONS FOR MULTI-ROW UPDATES:
The BEFORE INSERT OR UPDATE trigger acquires a row-level lock on proposal_bot_log_seq for
each row's proposed_by_bot_id. If a single transaction updates proposal_holds rows across
multiple distinct bots concurrently with another transaction updating the same bots in a
different order, a deadlock can occur on the counter row locks.
Mitigation: bulk operations should either:
1. Scope updates to a single bot_id per transaction, OR
2. Order touched rows deterministically by proposed_by_bot_id before performing updates.

BATCHED BACKFILL RUNBOOK (if table exceeds 100,000 rows):
If proposal_holds has > 100,000 un-backfilled rows, the single-statement UPDATE is aborted
to avoid holding ACCESS EXCLUSIVE for too long. To backfill manually prior to re-running:
1. Add the nullable column and create the counter table explicitly if missing:
   ALTER TABLE proposal_holds ADD COLUMN IF NOT EXISTS log_seq BIGINT;
   CREATE TABLE IF NOT EXISTS proposal_bot_log_seq (
       bot_id TEXT PRIMARY KEY,
       last_seq BIGINT NOT NULL
   );
   ALTER TABLE proposal_bot_log_seq SET (
       fillfactor = 70, autovacuum_vacuum_scale_factor = 0.0, autovacuum_vacuum_threshold = 1000
   );
2. Run per-bot batched updates in chunks (e.g. 10,000 rows), starting from COALESCE(MAX(log_seq), 0):
   DO $$
   DECLARE
       b TEXT;
       r RECORD;
       curr_seq BIGINT;
   BEGIN
       FOR b IN SELECT DISTINCT proposed_by_bot_id FROM proposal_holds WHERE log_seq IS NULL LOOP
           SELECT COALESCE(MAX(log_seq), 0) INTO curr_seq
           FROM proposal_holds WHERE proposed_by_bot_id = b;
           FOR r IN SELECT id FROM proposal_holds WHERE proposed_by_bot_id = b AND log_seq IS NULL
                    ORDER BY COALESCE(decided_at, created_at), created_at, id LOOP
               curr_seq := curr_seq + 1;
               UPDATE proposal_holds SET log_seq = curr_seq WHERE id = r.id;
               IF curr_seq % 10000 = 0 THEN COMMIT; END IF;
           END LOOP;
           INSERT INTO proposal_bot_log_seq (bot_id, last_seq) VALUES (b, curr_seq)
           ON CONFLICT (bot_id) DO UPDATE SET last_seq = GREATEST(proposal_bot_log_seq.last_seq, EXCLUDED.last_seq);
           COMMIT;
       END LOOP;
   END $$;
3. Re-run `alembic upgrade head`. The migration will observe 0 NULL rows, skip the backfill,
   enforce NOT NULL, install the trigger, and build concurrent indexes.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision: str = "b4a2d8e6f1c3"
down_revision: str | None = "fd6d97e05ca5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SIZE_GUARD_THRESHOLD = 100_000
_MIGRATION_LOCK_KEY = 1380270924  # 0x5245_434C

_CREATE_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION proposal_holds_assign_log_seq() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE next_seq BIGINT;
BEGIN
    INSERT INTO public.proposal_bot_log_seq AS c (bot_id, last_seq)
    VALUES (NEW.proposed_by_bot_id, 1)
    ON CONFLICT (bot_id) DO UPDATE SET last_seq = c.last_seq + 1
    RETURNING c.last_seq INTO next_seq;
    NEW.log_seq := next_seq;
    RETURN NEW;
END;
$$;
"""

_CREATE_TRIGGER_SQL = """
CREATE TRIGGER trg_proposal_holds_log_seq
BEFORE INSERT OR UPDATE ON proposal_holds
FOR EACH ROW EXECUTE FUNCTION proposal_holds_assign_log_seq();
"""


def _index_validity(name: str) -> bool | None:
    """True = valid, False = present but INVALID/not-ready, None = absent."""
    row = (
        op.get_bind()
        .execute(
            sa.text("""
            SELECT i.indisvalid AND i.indisready AS ok
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_index   i ON i.indexrelid = c.oid
            WHERE c.relname = :name AND n.nspname = current_schema()
        """),
            {"name": name},
        )
        .first()
    )
    return None if row is None else bool(row.ok)


def _create_index_concurrently_checked(
    name: str, table: str, cols: list[str], *, unique: bool
) -> None:
    if context.is_offline_mode():
        op.create_index(
            name,
            table,
            cols,
            unique=unique,
            postgresql_concurrently=True,
            if_not_exists=True,
        )
        return
    # 1. RECOVER: clear a leftover INVALID index from a previously failed build.
    if _index_validity(name) is False:
        op.execute(f'DROP INDEX CONCURRENTLY IF EXISTS "{name}"')
    # 2. BUILD
    op.create_index(
        name,
        table,
        cols,
        unique=unique,
        postgresql_concurrently=True,
        if_not_exists=True,
    )
    # 3. FAIL EXPLICITLY: never let an INVALID index ship as a green migration.
    if _index_validity(name) is not True:
        raise RuntimeError(
            f"index {name} is INVALID after a CONCURRENTLY build. "
            f'Drop it ("DROP INDEX CONCURRENTLY IF EXISTS {name}") and re-run this migration.'
        )


def upgrade() -> None:
    # 0. Session timeouts scoped locally to this transaction
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '120s'")

    # 1. Nullable column, idempotent via information_schema guard
    col_exists = False
    if not context.is_offline_mode():
        col_exists = bool(
            op.get_bind()
            .execute(
                sa.text(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = 'proposal_holds' "
                    "AND column_name = 'log_seq'"
                )
            )
            .scalar()
        )
    if not col_exists:
        op.add_column("proposal_holds", sa.Column("log_seq", sa.BigInteger(), nullable=True))

    # 2. Counter table with idempotent IF NOT EXISTS
    op.create_table(
        "proposal_bot_log_seq",
        sa.Column("bot_id", sa.Text(), primary_key=True),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
        if_not_exists=True,
    )
    op.execute(
        "ALTER TABLE proposal_bot_log_seq SET ("
        "fillfactor = 70, "
        "autovacuum_vacuum_scale_factor = 0.0, "
        "autovacuum_vacuum_threshold = 1000)"
    )

    # 3. Size guard -- fail explicitly rather than lock the table for minutes
    if not context.is_offline_mode():
        if col_exists:
            count_sql = "SELECT count(*) FROM proposal_holds WHERE log_seq IS NULL"
        else:
            count_sql = "SELECT count(*) FROM proposal_holds"
        n = op.get_bind().execute(sa.text(count_sql)).scalar_one()
        threshold = int(os.environ.get("_TEST_SIZE_GUARD_THRESHOLD", _SIZE_GUARD_THRESHOLD))
        if n > threshold:
            raise RuntimeError(
                f"proposal_holds has {n} un-backfilled rows (> {threshold}); the single-statement "
                "log_seq backfill would hold ACCESS EXCLUSIVE for too long. Follow the batched "
                "backfill runbook documented in this migration's docstring before re-running."
            )

    # 4. Deterministic backfill (only populate rows where log_seq IS NULL)
    op.execute("""
        WITH ranked AS (
            SELECT id,
                   COALESCE(
                       (SELECT MAX(h2.log_seq) FROM proposal_holds h2 WHERE h2.proposed_by_bot_id = proposal_holds.proposed_by_bot_id),
                       0
                   ) + row_number() OVER (
                       PARTITION BY proposed_by_bot_id
                       ORDER BY COALESCE(decided_at, created_at), created_at, id
                   ) AS rn
            FROM proposal_holds
            WHERE log_seq IS NULL
        )
        UPDATE proposal_holds h
        SET log_seq = r.rn
        FROM ranked r
        WHERE h.id = r.id AND h.log_seq IS NULL;
    """)

    # 5. Seed the counter from the backfill with GREATEST upsert
    op.execute("""
        INSERT INTO proposal_bot_log_seq (bot_id, last_seq)
        SELECT proposed_by_bot_id, COALESCE(MAX(log_seq), 0)
        FROM proposal_holds
        GROUP BY proposed_by_bot_id
        ON CONFLICT (bot_id) DO UPDATE
        SET last_seq = GREATEST(proposal_bot_log_seq.last_seq, EXCLUDED.last_seq);
    """)

    # 6. NOT NULL constraint (cheap scan; the table is already exclusively locked)
    op.alter_column("proposal_holds", "log_seq", nullable=False)

    # 7. Function + trigger (search_path pinned, idempotent)
    op.execute(_CREATE_FUNCTION_SQL)
    op.execute("DROP TRIGGER IF EXISTS trg_proposal_holds_log_seq ON proposal_holds")
    op.execute(_CREATE_TRIGGER_SQL)

    # 8. Indexes outside the migration transaction
    with op.get_context().autocommit_block():
        # Manage statement timeout and re-acquire advisory lock outside transaction
        op.execute("SET statement_timeout = '300s'")
        op.execute("RESET lock_timeout")
        if not context.is_offline_mode():
            op.execute(f"SELECT pg_advisory_lock({_MIGRATION_LOCK_KEY})")
        try:
            _create_index_concurrently_checked(
                "uq_proposal_holds_bot_id_log_seq",
                "proposal_holds",
                ["proposed_by_bot_id", "log_seq"],
                unique=True,
            )
            _create_index_concurrently_checked(
                "idx_proposal_holds_bot_id_status_log_seq",
                "proposal_holds",
                ["proposed_by_bot_id", "status", "log_seq"],
                unique=False,
            )
        finally:
            if not context.is_offline_mode():
                op.execute(f"SELECT pg_advisory_unlock({_MIGRATION_LOCK_KEY})")
            op.execute("RESET statement_timeout")


def downgrade() -> None:
    # 1. Restructure B1: drop concurrent indexes outside transaction first
    with op.get_context().autocommit_block():
        op.drop_index(
            "uq_proposal_holds_bot_id_log_seq",
            table_name="proposal_holds",
            if_exists=True,
            postgresql_concurrently=True,
        )
        op.drop_index(
            "idx_proposal_holds_bot_id_status_log_seq",
            table_name="proposal_holds",
            if_exists=True,
            postgresql_concurrently=True,
        )

    # 2. In single ambient transaction: drop trigger, function, column, and table
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("SET LOCAL statement_timeout = '120s'")
    op.execute("DROP TRIGGER IF EXISTS trg_proposal_holds_log_seq ON proposal_holds")
    op.execute("DROP FUNCTION IF EXISTS proposal_holds_assign_log_seq()")
    op.drop_column("proposal_holds", "log_seq")
    op.drop_table("proposal_bot_log_seq", if_exists=True)
