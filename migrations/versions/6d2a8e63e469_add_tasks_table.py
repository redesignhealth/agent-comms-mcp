"""add tasks table

Revision ID: 6d2a8e63e469
Revises: 18f2d7735523
Create Date: 2026-08-12 00:09:33.389567

NOTE on in-place amendment (mirrors migrations/versions/18f2d7735523's own
note): this revision has been authored and iterated on entirely within
this single unmerged PR (agent-comms-mcp PR #9) — it does not
exist on `main`, and it has never been applied to any persistent or shared
database. CI runs `alembic upgrade head` against a fresh, ephemeral
Postgres service container on every run; local review testing always ran
full `downgrade base` -> `upgrade head` cycles against the latest file
content. In-place amendment during code review is therefore safe — there
is no environment where this revision is recorded as already-applied in a
state older than the one below. Once this PR merges, treat this file as
frozen: any further schema change requires a NEW Alembic revision, never
an edit to this one.

Every DROP in downgrade() below is guarded (if_exists, or raw `DROP ...
IF EXISTS` SQL for drop_constraint()/drop_table(), neither of which has an
if_exists kwarg) so re-running downgrade against a partially-applied state
never aborts — belt-and-suspenders on top of the in-place-amendment
rationale above. The CREATEs in upgrade() are
guarded for indexes (if_not_exists) and the one column add (raw `ADD
COLUMN IF NOT EXISTS` SQL), but NOT for `create_table("tasks", ...)` or the
two FK/CHECK constraint adds: Postgres has no `CREATE TABLE IF NOT EXISTS`
equivalent that also lets Alembic manage the table via `op.create_table`,
and no `ADD CONSTRAINT IF NOT EXISTS` syntax at all — matching the same
non-idempotent constraint-add precedent already set by
ef8394b37c8d/18f2d7735523. In practice this asymmetry is harmless here:
upgrade() only ever needs to re-run from a clean base per the in-place-
amendment rationale above (there is no partially-upgraded state to resume
into), so the guarding effort went into downgrade(), where a partial state
is the exact case this file's own iterative dev/review cycle exercises.

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "6d2a8e63e469"
down_revision: str | None = "18f2d7735523"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("assignee_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'open'"), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("status IN ('open', 'done', 'declined')", name="ck_tasks_status"),
        sa.CheckConstraint("created_by <> assignee_id", name="ck_tasks_distinct_parties"),
        sa.ForeignKeyConstraint(["created_by"], ["agents.id"]),
        sa.ForeignKeyConstraint(["assignee_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_tasks_assignee_id_status",
        "tasks",
        ["assignee_id", "status"],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(
        "idx_tasks_created_by_status",
        "tasks",
        ["created_by", "status"],
        unique=False,
        if_not_exists=True,
    )
    # Descending on both columns to match get_tasks's ORDER BY created_at
    # DESC, id DESC (newest-first pagination) — a forward scan of a DESC
    # index serves that query directly, rather than relying on Postgres's
    # ability to walk an ascending index backward.
    op.create_index(
        "idx_tasks_created_at_id",
        "tasks",
        [sa.text("created_at DESC"), sa.text("id DESC")],
        unique=False,
        if_not_exists=True,
    )
    op.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS task_id UUID")
    op.create_foreign_key("audit_log_task_id_fkey", "audit_log", "tasks", ["task_id"], ["id"])
    op.create_index(
        "idx_audit_log_task_id", "audit_log", ["task_id"], unique=False, if_not_exists=True
    )


def downgrade() -> None:
    op.drop_index("idx_audit_log_task_id", table_name="audit_log", if_exists=True)
    # op.drop_constraint() has no if_exists kwarg (unlike op.drop_index()) —
    # raw SQL, same escape hatch already used for the column add/drop above.
    op.execute("ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_task_id_fkey")
    op.execute("ALTER TABLE audit_log DROP COLUMN IF EXISTS task_id")
    op.drop_index("idx_tasks_created_at_id", table_name="tasks", if_exists=True)
    op.drop_index("idx_tasks_created_by_status", table_name="tasks", if_exists=True)
    op.drop_index("idx_tasks_assignee_id_status", table_name="tasks", if_exists=True)
    # op.drop_table() has no if_exists kwarg either — same raw-SQL pattern.
    # No CASCADE: every dependent index/constraint is already dropped above,
    # in dependency order, so a plain DROP TABLE is sufficient and doesn't
    # risk silently cascading into some future, as-yet-unwritten dependent
    # object this line was never updated to account for.
    op.execute("DROP TABLE IF EXISTS tasks")
