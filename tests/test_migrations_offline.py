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
    # 2cc5185360c7: agents.min/max_schema_version columns,
    # the DB-level >= 1 / <= max CHECK constraint, and the
    # (sender_id, created_at) index backing
    # service._enforce_sender_global_rate_limit.
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
    # a1b2c3d4e5f6: agents.is_shared column (idempotent add/drop guards).
    assert (
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_shared BOOLEAN DEFAULT false NOT NULL"
        in result.stdout
    )
    # 4af015077bf8: sort-covering index for inbox's pending-invites query.
    assert (
        "CREATE INDEX IF NOT EXISTS idx_participants_agent_id_status_invited_at "
        "ON participants (agent_id, status, invited_at)" in result.stdout
    )
    # 136265b3f22d: drop of the now-redundant 2-column index 4af015077bf8
    # superseded (a separate later migration, not folded into 4af015077bf8
    # itself -- Argus round-3 BLOCKING catch). Terminated with `;` so this
    # doesn't also match as a prefix of the longer
    # idx_participants_agent_id_status_invited_at DROP (Argus round-3
    # SUGGESTION -- there isn't one here today, but a future migration
    # dropping that longer index would otherwise satisfy this assertion
    # too without actually proving the shorter one was dropped).
    assert "DROP INDEX IF EXISTS idx_participants_agent_id_status;" in result.stdout
    # f4a9c1d2b3e7 (TECH-5389 PR2): approval_holds table -- both CHECKs,
    # both indexes, the message_id UNIQUE constraint.
    assert "CREATE TABLE approval_holds" in result.stdout
    assert (
        "CONSTRAINT ck_approval_holds_status CHECK (status IN "
        "('pending_auto', 'pending_human', 'auto_approved', 'approved', 'rejected', 'expired'))"
        in result.stdout
    )
    assert (
        "CONSTRAINT ck_approval_holds_auto_decision CHECK "
        "(auto_decision IS NULL OR auto_decision IN ('cleared', 'escalated'))" in result.stdout
    )
    assert "CONSTRAINT uq_approval_holds_message_id UNIQUE (message_id)" in result.stdout
    assert (
        "CREATE INDEX IF NOT EXISTS idx_approval_holds_sender_agent_id_status_created_at "
        "ON approval_holds (sender_agent_id, status, created_at)" in result.stdout
    )
    assert (
        "CREATE INDEX IF NOT EXISTS idx_approval_holds_owner_sub_status_created_at "
        "ON approval_holds (owner_sub, status, created_at)" in result.stdout
    )
    assert (
        "CREATE INDEX IF NOT EXISTS idx_approval_holds_conversation_id "
        "ON approval_holds (conversation_id)" in result.stdout
    )
    # e73892f01b89 (TECH-5735): kind + target_agent_id on approval_holds.
    assert (
        "ALTER TABLE approval_holds ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'message' NOT NULL"
        in result.stdout
    )
    assert "ALTER TABLE approval_holds ADD COLUMN IF NOT EXISTS target_agent_id UUID" in (
        result.stdout
    )
    assert (
        "ALTER TABLE approval_holds ADD CONSTRAINT approval_holds_target_agent_id_fkey "
        "FOREIGN KEY(target_agent_id) REFERENCES agents (id)" in result.stdout
    )
    assert (
        "ALTER TABLE approval_holds ADD CONSTRAINT ck_approval_holds_kind "
        "CHECK (kind IN ('message', 'invite'))" in result.stdout
    )
    assert (
        "ALTER TABLE approval_holds ADD CONSTRAINT ck_approval_holds_invite_target_agent_id "
        "CHECK (kind != 'invite' OR target_agent_id IS NOT NULL)" in result.stdout
    )
    # b2bb6ccde02e (TECH-5735): partial index backing
    # service._conversation_has_note_history.
    assert (
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_note "
        "ON messages (conversation_id) WHERE type = 'note'" in result.stdout
    )
    # a45f344c9c00 (TECH-5736): register_agent's display-name-collision
    # guard index. idx_agents_lower_display_name_active is UNIQUE
    # (DB-enforced, race-free display-name-collision guard -- Argus
    # round-2), not just a performance index. This migration originally
    # also added idx_agents_sub_prefix (text_pattern_ops on `sub`), but
    # that index was removed -- it never actually served the
    # sibling-identity query's `LIKE ... ESCAPE` predicate, and making it
    # usable by dropping the query's `autoescape=True` would have been
    # unsafe given `base_sub`'s IdP-controlled content. See the
    # migration's own docstring for the full history.
    assert (
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_lower_display_name_active "
        "ON agents (lower(display_name)) WHERE status = 'active'" in result.stdout
    )
    assert "idx_agents_sub_prefix" not in result.stdout
    # c1a2b3d4e5f6 (TECH-5822, Argus round 2 SUGGESTION): broadens the
    # note-only partial index to cover instruction_share too, backing
    # service._conversation_has_note_history's now-broadened
    # Message.type.in_(BARRIER_SENSITIVE_TYPES) query. Explicit assertions
    # here (not just relying on this file's existing per-migration
    # convention) since the offline --sql output is cumulative across every
    # migration in order -- a typo in this migration's index name, column,
    # or WHERE predicate would otherwise be invisible to CI, exactly as the
    # stale b2bb6ccde02e assertion above would keep passing regardless.
    assert "DROP INDEX IF EXISTS public.idx_messages_conversation_id_note" in result.stdout
    assert (
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_free_text "
        "ON messages (conversation_id) WHERE type IN ('note', 'instruction_share')" in result.stdout
    )
    # d5c8f1a2b4e7 (TECH-5822 follow-up): accepted_types opt-out default --
    # new-row server default, and the targeted backfill of pre-existing rows
    # still at e1db7c2e6b70's frozen old-default 12-type set.
    assert (
        "ALTER TABLE public.agents ALTER COLUMN accepted_types SET DEFAULT '{}'::text[]"
        in result.stdout
    )
    assert (
        "UPDATE public.agents SET accepted_types = ARRAY[]::text[], updated_at = now() "
        "WHERE accepted_types <@ ARRAY['availability_request', 'availability_response', "
        "'confirm', 'counter_proposal', 'decline', 'needs_clarification', 'note', "
        "'task_assign', 'task_cancel', 'task_complete', 'task_decline', 'task_report']::text[] "
        "AND accepted_types @> ARRAY['availability_request', 'availability_response', "
        "'confirm', 'counter_proposal', 'decline', 'needs_clarification', 'note', "
        "'task_assign', 'task_cancel', 'task_complete', 'task_decline', 'task_report']::text[];"
        in result.stdout
    )
