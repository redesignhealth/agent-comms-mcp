"""Alembic offline-mode ("alembic upgrade head --sql") regression test.

Deliberately its own module, separate from test_db_models.py: that module's
`_migrated_schema` fixture is `autouse=True` at module scope and requires a
reachable Postgres, which would defeat the point of this test — offline
mode's whole purpose is generating DDL for a human/DBA to review without a
live connection, so this test must not require Postgres reachable either.

Regression coverage for the `if not context.is_offline_mode():` guard in
18f2d7735523_rate_limit_indexes_and_display_name_.py, which previously
called `op.get_bind().execute(...)` unconditionally — `op.get_bind()`
returns `None` in offline mode, crashing with an `AttributeError` on
`alembic upgrade head --sql`.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).parent.parent

# Same default as docker-compose.yml's `postgres` service — irrelevant to
# this test's actual behavior (offline mode never connects), but Alembic's
# config still expects DATABASE_URL to be set and well-formed at import time.
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


def test_alembic_offline_mode_emits_sql_without_a_live_connection() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=SERVICE_ROOT,
        env={**os.environ, "DATABASE_URL": _DEFAULT_TEST_DATABASE_URL},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "ALTER TABLE agents ADD CONSTRAINT ck_agents_accepted_types_max" in result.stdout
    assert "CREATE INDEX IF NOT EXISTS idx_conversations_created_by_created_at" in result.stdout
    # owner_snapshot column
    assert "ALTER TABLE conversations ADD COLUMN IF NOT EXISTS owner_snapshot" in result.stdout
    # backfill legacy scheduling.availability rows to open
    assert (
        "UPDATE conversations SET type = 'open', updated_at = now() "
        "WHERE type = 'scheduling.availability'" in result.stdout
    )
    # tasks table dropped via raw SQL (IF EXISTS guards)
    assert "DROP TABLE IF EXISTS public.tasks" in result.stdout
    assert "ALTER TABLE public.audit_log DROP COLUMN IF EXISTS task_id" in result.stdout
    # pre-flight guard against dropping non-empty tasks rows
    assert "tasks table is not empty" in result.stdout
    # upgrade()'s index drops are schema-qualified
    # to match the guard. This is upgrade()-side coverage only -- alembic
    # --sql only emits forward DDL, so this offline test never runs
    # downgrade() at all. The live-DB _migrated_schema autouse fixture
    # (defined identically in test_db_models.py, test_comms_tools.py, and
    # test_service.py) does exercise downgrade() end-to-end when a prior
    # test module left the DB already at head. What that live-DB path still
    # doesn't cover: CI's search_path is public-first, so it can't
    # distinguish a qualified FK referent from an unqualified one, and
    # there's no schema-level assertion confirming the recreated `tasks`
    # table actually lands in `public` rather than merely working by
    # search_path coincidence.
    assert "DROP INDEX IF EXISTS public.idx_tasks_assignee_id_status" in result.stdout
    assert "DROP INDEX IF EXISTS public.idx_tasks_created_at_id" in result.stdout
    assert "DROP INDEX IF EXISTS public.idx_tasks_created_by_status" in result.stdout
    assert "DROP INDEX IF EXISTS public.idx_audit_log_task_id" in result.stdout
    # accepted_types enforcement follow-up: backfill grandfathers every
    # pre-existing agent row to the full message-type set so the new
    # per-message capability gate doesn't retroactively break an agent
    # registered under the old "informational, no effect" contract.
    assert (
        "UPDATE public.agents SET accepted_types = ARRAY['availability_request', "
        "'availability_response', 'confirm', 'counter_proposal', 'decline', "
        "'needs_clarification', 'note', 'task_assign', 'task_cancel', "
        "'task_complete', 'task_decline', 'task_report']::text[], "
        "updated_at = now();" in result.stdout
    )
    # bb1ea7d2a0cf: partial expression index backing lookup_agent_by_email
    assert (
        "CREATE INDEX IF NOT EXISTS idx_agents_lower_owner_email_active "
        "ON agents (lower(owner_email), bound_at DESC NULLS LAST) "
        "WHERE status = 'active'" in result.stdout
    )
    # 2cc5185360c7 (TECH-5160): agents.min/max_schema_version columns,
    # the DB-level >= 1 / <= max CHECK constraint, and the
    # (sender_id, created_at) index backing
    # service._enforce_sender_global_rate_limit (Argus round 1).
    assert "ADD COLUMN IF NOT EXISTS min_schema_version INTEGER DEFAULT 1 NOT NULL" in result.stdout
    assert "ADD COLUMN IF NOT EXISTS max_schema_version INTEGER DEFAULT 1 NOT NULL" in result.stdout
    assert (
        "ALTER TABLE agents ADD CONSTRAINT ck_agents_schema_version_range "
        "CHECK (min_schema_version >= 1 AND min_schema_version <= max_schema_version)"
        in result.stdout
    )
    assert (
        "CREATE INDEX IF NOT EXISTS idx_messages_sender_id_created_at "
        "ON messages (sender_id, created_at)" in result.stdout
    )
