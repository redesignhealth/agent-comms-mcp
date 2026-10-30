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
  and trigger installation under a single bounded transaction with lock_timeout = 5s.
- Backfill size guard protects against lock starvation if proposal_holds exceeds 100,000 rows.
- Trailing index builds for uq_proposal_holds_bot_id_log_seq and
  idx_proposal_holds_bot_id_status_log_seq run CONCURRENTLY in an autocommit block with
  pre-build INVALID recovery and post-build validity checks.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision: str = "b4a2d8e6f1c3"
down_revision: str | None = "fd6d97e05ca5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CREATE_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION proposal_holds_assign_log_seq() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE next_seq BIGINT;
BEGIN
    INSERT INTO proposal_bot_log_seq AS c (bot_id, last_seq)
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
    op.execute("SET lock_timeout = '5s'")
    op.execute("SET statement_timeout = '120s'")

    # 1. nullable column (instant on PG11+)
    op.add_column("proposal_holds", sa.Column("log_seq", sa.BigInteger(), nullable=True))

    # 2. counter table
    op.create_table(
        "proposal_bot_log_seq",
        sa.Column("bot_id", sa.Text(), primary_key=True),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
    )
    op.execute(
        "ALTER TABLE proposal_bot_log_seq SET ("
        "fillfactor = 70, "
        "autovacuum_vacuum_scale_factor = 0.0, "
        "autovacuum_vacuum_threshold = 1000)"
    )

    # 3. size guard -- fail explicitly rather than lock the table for minutes
    if not context.is_offline_mode():
        n = op.get_bind().execute(sa.text("SELECT count(*) FROM proposal_holds")).scalar_one()
        if n > 100_000:
            raise RuntimeError(
                f"proposal_holds has {n} rows; the single-statement log_seq backfill would "
                "hold ACCESS EXCLUSIVE for too long. Run the batched backfill documented in "
                "this migration's docstring instead."
            )

    # 4. deterministic backfill (trigger not installed yet)
    op.execute("""
        WITH ranked AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY proposed_by_bot_id
                       ORDER BY COALESCE(decided_at, created_at), created_at, id
                   ) AS rn
            FROM proposal_holds
        )
        UPDATE proposal_holds h SET log_seq = r.rn FROM ranked r WHERE h.id = r.id
    """)

    # 5. seed the counter from the backfill
    op.execute("""
        INSERT INTO proposal_bot_log_seq (bot_id, last_seq)
        SELECT proposed_by_bot_id, COALESCE(MAX(log_seq), 0) FROM proposal_holds
        GROUP BY proposed_by_bot_id
    """)

    # 6. NOT NULL (cheap scan; the table is already exclusively locked)
    op.alter_column("proposal_holds", "log_seq", nullable=False)

    # 7. function + trigger
    op.execute(_CREATE_FUNCTION_SQL)
    op.execute(_CREATE_TRIGGER_SQL)

    # 8. indexes, outside the migration transaction
    with op.get_context().autocommit_block():
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


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_proposal_holds_log_seq ON proposal_holds")
    op.execute("DROP FUNCTION IF EXISTS proposal_holds_assign_log_seq()")

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

    op.drop_column("proposal_holds", "log_seq")
    op.drop_table("proposal_bot_log_seq")
