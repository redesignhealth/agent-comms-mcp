"""drop tasks table

Revision ID: da3e1646c44d
Revises: 15ef34885e30
Create Date: 2026-08-12 14:42:56.308473

This revision ("tasks-as-conversations") drops the dedicated `tasks`
table and `audit_log.task_id` FK/index added by 6d2a8e63e469,
now that task lifecycle is represented as a conversation carrying
`task_assign`/`task_report`/`task_complete`/`task_decline`/`task_cancel`
messages instead. 6d2a8e63e469 is already applied on `main`/dev (confirmed:
its own `alembic_version` row exists in the local dev DB), so per that
revision's own frozen-file note, this is a NEW revision, not an edit to
6d2a8e63e469 in place.

NOTE on in-place amendment: authored and iterated on entirely within this
single unmerged PR -- it does not exist on `main`, and has
never been applied to any persistent or shared database. In-place
amendment during code review is therefore safe. Once this PR merges, treat
this file as frozen: any further schema change requires a NEW Alembic
revision, never an edit to this one.

DEPLOYMENT WARNING: `entrypoint.sh` runs `alembic upgrade head` in the new
container before the old container drains (no expand/contract split
exists in this pipeline today). `ALTER TABLE audit_log DROP COLUMN
task_id` here breaks every ORM audit-log INSERT from a still-running old
container for the entire drain window (any `AuditLog` insert maps
`task_id`, not just task-scoped ones). This PR must ship as a
stop-then-start deploy, or during a confirmed-idle traffic window --
standard rolling/blue-green deploy of this image is NOT safe for this
specific revision.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "da3e1646c44d"
down_revision: str | None = "15ef34885e30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Pre-flight guard, run FIRST (before any schema change below): this
    # drop is unconditional and the table's data is unrecoverable (see
    # downgrade()'s warning) -- if the table exists at all, refuse to
    # proceed unless it's already empty, rather than silently destroying
    # any task rows a real deployment might still hold. Postgres DDL is
    # transactional, so a RAISE EXCEPTION here rolls back the whole
    # migration regardless of statement order -- placing it first is belt
    # and suspenders against a future non-transactional statement being
    # added ahead of it. Schema-qualified (public.tasks) so a `tasks`
    # table in a different schema on this connection's search_path can't
    # be found by the catalog check and then silently miss on the row
    # check (or vice versa).
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.tasks') IS NOT NULL
                AND EXISTS (SELECT 1 FROM public.tasks LIMIT 1)
            THEN
                RAISE EXCEPTION
                    'tasks table is not empty -- confirm zero rows before running this migration';
            END IF;
        END $$;
        """
    )
    # Schema-qualified throughout (matching the guard above) so none of
    # these resolve through search_path to a different schema than the
    # guard actually inspected.
    op.drop_index(
        "idx_tasks_assignee_id_status", table_name="tasks", schema="public", if_exists=True
    )
    op.drop_index("idx_tasks_created_at_id", table_name="tasks", schema="public", if_exists=True)
    op.drop_index(
        "idx_tasks_created_by_status", table_name="tasks", schema="public", if_exists=True
    )
    op.drop_index("idx_audit_log_task_id", table_name="audit_log", schema="public", if_exists=True)
    # Raw SQL for IF EXISTS guards — op.drop_constraint/op.drop_column/op.drop_table
    # have no native IF EXISTS support, and this migration may run on a DB where
    # 6d2a8e63e469 was never applied (e.g. a fresh dev environment).
    op.execute("ALTER TABLE public.audit_log DROP CONSTRAINT IF EXISTS audit_log_task_id_fkey")
    op.execute("ALTER TABLE public.audit_log DROP COLUMN IF EXISTS task_id")
    op.execute("DROP TABLE IF EXISTS public.tasks")


def downgrade() -> None:
    # WARNING: this downgrade is permanently lossy — all task data (now
    # represented as conversations with task_assign/etc messages) is
    # unrecoverable by reverting this migration. Downgrade is provided for
    # schema completeness only, not as a data-recovery path.
    #
    # The table and its indexes are schema-qualified (schema="public"),
    # symmetric with upgrade()'s public.tasks qualification -- otherwise a
    # connection whose search_path isn't public-first could recreate them
    # in a different schema than upgrade() dropped them from. FK reference
    # strings (["agents.id"]) are deliberately left unqualified: this repo
    # relies on a public-first search_path for referent resolution
    # everywhere else (e.g. ef8394b37c8d's own FKs are unqualified), so
    # qualifying just these two would be an inconsistent one-off rather
    # than a real hardening -- the raw `REFERENCES public.tasks(id)` SQL
    # below is qualified only because it's hand-written DDL text, not
    # SQLAlchemy metadata resolved via search_path the same way.
    op.create_table(
        "tasks",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column("created_by", sa.UUID(), autoincrement=False, nullable=False),
        sa.Column("assignee_id", sa.UUID(), autoincrement=False, nullable=False),
        sa.Column(
            "status",
            sa.TEXT(),
            server_default=sa.text("'open'::text"),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column("schema_version", sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column(
            "payload", postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=False
        ),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            autoincrement=False,
            nullable=False,
        ),
        # Use the original IN(...) form to match 6d2a8e63e469 exactly and
        # avoid schema-drift noise from autogenerate's array normalization.
        sa.CheckConstraint(
            "status IN ('open', 'done', 'declined')",
            name="ck_tasks_status",
        ),
        sa.CheckConstraint("created_by <> assignee_id", name="ck_tasks_distinct_parties"),
        sa.ForeignKeyConstraint(["assignee_id"], ["agents.id"], name="tasks_assignee_id_fkey"),
        sa.ForeignKeyConstraint(["created_by"], ["agents.id"], name="tasks_created_by_fkey"),
        sa.PrimaryKeyConstraint("id", name="tasks_pkey"),
        schema="public",
    )
    op.create_index(
        "idx_tasks_created_by_status",
        "tasks",
        ["created_by", "status"],
        unique=False,
        schema="public",
        if_not_exists=True,
    )
    op.create_index(
        "idx_tasks_created_at_id",
        "tasks",
        [sa.literal_column("created_at DESC"), sa.literal_column("id DESC")],
        unique=False,
        schema="public",
        if_not_exists=True,
    )
    op.create_index(
        "idx_tasks_assignee_id_status",
        "tasks",
        ["assignee_id", "status"],
        unique=False,
        schema="public",
        if_not_exists=True,
    )
    op.execute(
        "ALTER TABLE public.audit_log ADD COLUMN IF NOT EXISTS task_id "
        "UUID REFERENCES public.tasks(id)"
    )
    op.create_index(
        "idx_audit_log_task_id",
        "audit_log",
        ["task_id"],
        unique=False,
        schema="public",
        if_not_exists=True,
    )
