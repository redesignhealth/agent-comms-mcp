"""add idx_audit_log_action_at (TECH-8080 PR13)

Revision ID: 58dd9bd941a6
Revises: b4a2d8e6f1c3
Create Date: 2026-10-30 20:00:00.000000

Adds composite index ``idx_audit_log_action_at`` on ``audit_log (action, at)``
to support durable daily auto-approval cap counting (TECH-8080 PR13).

LOCKING / CONCURRENCY:
Built CONCURRENTLY inside an ``autocommit_block()`` so write traffic to
``audit_log`` is not blocked during index creation. Follows the PR3 guard
pattern: verifies ``indisvalid`` and ``indisready`` in ``pg_index`` immediately
after the concurrent build, raising a RuntimeError if the index is invalid or
unready.

Downgrade drops the index concurrently inside an ``autocommit_block()``.
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "58dd9bd941a6"
down_revision: str | None = "b4a2d8e6f1c3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _assert_audit_log_index_valid_and_ready(
    index_name: str, bind: sa.engine.Connection | None = None
) -> None:
    """Ensure the concurrently-built index exists and is both valid and ready.

    In PostgreSQL, CREATE INDEX CONCURRENTLY marks an index indisvalid=false if
    building failed or was aborted. This check verifies index validity before
    completing the migration.
    """
    if os.environ.get("_TEST_FORCE_INVALID_AUDIT_LOG_INDEX") == "1":
        raise RuntimeError(
            f"Index {index_name!r} is not valid and ready (simulated failure for test)."
        )

    if bind is None:
        bind = op.get_bind()
    if bind is None:
        return
    row = bind.execute(
        sa.text("""
            SELECT i.indisvalid, i.indisready
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indexrelid
            WHERE c.relname = :index_name
        """),
        {"index_name": index_name},
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Index {index_name!r} not found in pg_index after concurrent build.")
    indisvalid, indisready = bool(row[0]), bool(row[1])
    if not (indisvalid and indisready):
        raise RuntimeError(
            f"Index {index_name!r} is not valid and ready "
            f"(indisvalid={indisvalid}, indisready={indisready})."
        )


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.create_index(
            "idx_audit_log_action_at",
            "audit_log",
            ["action", "at"],
            postgresql_concurrently=True,
            if_not_exists=True,
        )

    if not context.is_offline_mode():
        _assert_audit_log_index_valid_and_ready("idx_audit_log_action_at")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "idx_audit_log_action_at",
            table_name="audit_log",
            postgresql_concurrently=True,
            if_exists=True,
        )
