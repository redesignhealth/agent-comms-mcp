"""Schema tests for the comms domain models — real Postgres only.

This module never mocks the database. It runs the Alembic
migration chain against a live Postgres (the ``postgres`` service in
docker-compose.yml, or whatever ``DATABASE_URL`` points at) and asserts
that all five tables, their key columns, and the indexes called out in
DESIGN.md §5 actually exist afterward.

If Postgres is unreachable (e.g. ``docker compose up -d postgres`` was
never run), every test in this module is skipped with a clear reason
rather than failing — there is no in-memory/sqlite fallback, since that
would defeat the point of testing against the real dialect (JSONB,
ARRAY, gen_random_uuid(), etc).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import Index, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from models import ProposalHold
from schemas import MAX_CONVERSATION_NAME_LENGTH, MAX_DISPLAY_NAME_LENGTH

SERVICE_ROOT = Path(__file__).parent.parent

# Same default as docker-compose.yml's `postgres` service.
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


def _test_database_url() -> str:
    url = os.environ.get("DATABASE_URL", _DEFAULT_TEST_DATABASE_URL)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def _can_connect(url: str) -> bool:
    try:
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return True
    except Exception:  # any connection failure just means "skip this module"
        return False


@pytest.fixture(scope="module")
def database_url() -> str:
    url = _test_database_url()
    if not asyncio.run(_can_connect(url)):
        pytest.skip(
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise the real-database schema tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
    """Run the full Alembic chain (downgrade base -> upgrade head) once per module.

    Runs `alembic` as a subprocess (rather than calling into Alembic's API
    in-process) so migrations/env.py's own `asyncio.run()` never collides
    with pytest-asyncio's event loop.
    """
    env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
    for args in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )


@pytest_asyncio.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(database_url)
    yield eng
    await eng.dispose()


async def _columns(engine: AsyncEngine, table: str) -> dict[str, str]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = :table"
            ),
            {"table": table},
        )
        return {row.column_name: row.data_type for row in result}


async def _column_max_length(engine: AsyncEngine, table: str, column: str) -> int | None:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT character_maximum_length FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = :table "
                "AND column_name = :column"
            ),
            {"table": table, "column": column},
        )
        return result.scalar_one_or_none()


async def _indexes(engine: AsyncEngine, table: str) -> set[str]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = 'public' AND tablename = :table"
            ),
            {"table": table},
        )
        return {row.indexname for row in result}


class TestSchema:
    """All five DESIGN.md §5 tables exist with their expected shape."""

    @pytest.mark.parametrize(
        "table",
        ["agents", "conversations", "participants", "messages", "audit_log"],
    )
    async def test_table_exists(self, engine: AsyncEngine, table: str) -> None:
        cols = await _columns(engine, table)
        assert cols, f"expected table {table!r} to exist with columns"

    async def test_agents_columns(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "agents")
        for expected in (
            "id",
            "sub",
            "owner_sub",
            "owner_email",
            "display_name",
            "accepted_types",
            "status",
            "created_at",
            "updated_at",
        ):
            assert expected in cols, f"agents.{expected} missing"
        assert cols["accepted_types"] == "ARRAY"
        assert cols["created_at"] == "timestamp with time zone"
        assert cols["display_name"] == "character varying"
        max_length = await _column_max_length(engine, "agents", "display_name")
        assert max_length == MAX_DISPLAY_NAME_LENGTH, (
            "agents.display_name character_maximum_length is None or wrong "
            "-- has migration 18f2d7735523 been applied?"
        )

    async def test_agents_accepted_types_check_constraint(self, engine: AsyncEngine) -> None:
        # DB-level backstop (migrations/versions/18f2d7735523...) capping
        # agents.accepted_types at 20 entries via cardinality(), not
        # array_length() — cardinality() never returns NULL for an empty
        # array, so the constraint can't be silently satisfied for that edge
        # case the way array_length() would.
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'agents'::regclass "
                    "AND conname = 'ck_agents_accepted_types_max'"
                )
            )
            constraint_def = result.scalar_one_or_none()
        assert constraint_def is not None, "ck_agents_accepted_types_max constraint missing"
        assert "cardinality" in constraint_def

    async def test_agents_schema_version_range_columns_default_and_constraint(
        self, engine: AsyncEngine
    ) -> None:
        """min/max_schema_version backfill to 1/1 on a row that
        omits them (migration 2cc5185360c7's server_default -- a prior
        version of this test asserted on a ``LIMIT 0`` result
        object rather than reading back an actual row, so it never verified
        the backfill value at all), and are DB-level constrained to
        ``min >= 1 AND min <= max``."""
        cols = await _columns(engine, "agents")
        assert "min_schema_version" in cols
        assert "max_schema_version" in cols
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO agents "
                    "(sub, owner_sub, owner_email, display_name, accepted_types, status) "
                    "VALUES (:sub, :owner_sub, :owner_email, :display_name, ARRAY['note'], "
                    "'active')"
                ),
                {
                    "sub": "test-schema-version-backfill-row",
                    "owner_sub": "test-schema-version-backfill-row",
                    "owner_email": "test-schema-version-backfill-row",
                    "display_name": "test-schema-version-backfill-row",
                },
            )
            row = (
                await conn.execute(
                    text(
                        "SELECT min_schema_version, max_schema_version FROM agents WHERE sub = :sub"
                    ),
                    {"sub": "test-schema-version-backfill-row"},
                )
            ).one()
            assert row.min_schema_version == 1
            assert row.max_schema_version == 1
            constraint_def = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid = 'agents'::regclass "
                        "AND conname = 'ck_agents_schema_version_range'"
                    )
                )
            ).scalar_one_or_none()
            # Cleanup: this module has no autouse table-truncation fixture
            # (unlike test_service.py/test_comms_tools.py), so a row this
            # test itself inserted must be removed, or it leaks into every
            # later test/module run against the same database.
            await conn.execute(
                text("DELETE FROM agents WHERE sub = :sub"),
                {"sub": "test-schema-version-backfill-row"},
            )
        assert constraint_def is not None, "ck_agents_schema_version_range constraint missing"
        assert "min_schema_version" in constraint_def
        assert "max_schema_version" in constraint_def
        # The prior assertions only checked both column
        # names appeared, which would still pass even if the >= 1 lower
        # bound (added specifically to close a 0/negative-range security
        # gap) were ever reverted.
        assert ">= 1" in constraint_def

    async def test_agents_is_shared_column_default_and_not_null(self, engine: AsyncEngine) -> None:
        """Migration a1b2c3d4e5f6: ``is_shared`` backfills to ``False`` on
        a row that omits it, and is NOT NULL at the DB level."""
        cols = await _columns(engine, "agents")
        assert "is_shared" in cols
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO agents "
                    "(sub, owner_sub, owner_email, display_name, accepted_types, status) "
                    "VALUES (:sub, :owner_sub, :owner_email, :display_name, ARRAY['note'], "
                    "'active')"
                ),
                {
                    "sub": "test-is-shared-backfill-row",
                    "owner_sub": "test-is-shared-backfill-row",
                    "owner_email": "test-is-shared-backfill-row",
                    "display_name": "test-is-shared-backfill-row",
                },
            )
            row = (
                await conn.execute(
                    text("SELECT is_shared FROM agents WHERE sub = :sub"),
                    {"sub": "test-is-shared-backfill-row"},
                )
            ).one()
            assert row.is_shared is False
            nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'agents' "
                        "AND column_name = 'is_shared'"
                    )
                )
            ).scalar_one_or_none()
            # Cleanup: this module has no autouse table-truncation fixture,
            # so a row this test itself inserted must be removed, or it
            # leaks into every later test/module run against the same
            # database.
            await conn.execute(
                text("DELETE FROM agents WHERE sub = :sub"),
                {"sub": "test-is-shared-backfill-row"},
            )
        assert nullable == "NO"

    async def test_conversations_columns(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "conversations")
        for expected in (
            "id",
            "name",
            "type",
            "state",
            "created_by",
            "expires_at",
            "owner_snapshot",
            "archived_at",
            "created_at",
            "updated_at",
        ):
            assert expected in cols, f"conversations.{expected} missing"
        assert cols["owner_snapshot"] == "jsonb"

    async def test_conversations_archived_at_nullable(self, engine: AsyncEngine) -> None:
        """TECH-5887: ``archived_at`` is nullable -- NULL means "not
        archived", the only value every pre-existing row can have."""
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'conversations' "
                    "AND column_name = 'archived_at'"
                )
            )
            assert result.scalar_one() == "YES"

    async def test_conversations_name_column_is_nullable_varchar_120(
        self, engine: AsyncEngine
    ) -> None:
        """Migration d885dda2ffda: ``name`` is a nullable, length-capped
        human label -- NULL for an unnamed conversation, not derived."""
        cols = await _columns(engine, "conversations")
        assert cols["name"] == "character varying"
        max_length = await _column_max_length(engine, "conversations", "name")
        assert max_length == MAX_CONVERSATION_NAME_LENGTH, (
            "conversations.name character_maximum_length is None or wrong "
            "-- has migration d885dda2ffda been applied?"
        )
        async with engine.connect() as conn:
            nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'conversations' "
                        "AND column_name = 'name'"
                    )
                )
            ).scalar_one_or_none()
        assert nullable == "YES"

    async def test_participants_columns_and_invite_accept_model(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "participants")
        for expected in (
            "conversation_id",
            "agent_id",
            "role",
            "status",
            "invited_by",
            "invited_at",
            "joined_at",
            "last_read_seq",
        ):
            assert expected in cols, f"participants.{expected} missing"

        # DESIGN.md §4: 'invited' must be an allowed status (invite/accept
        # model), and there must be no standalone surrogate PK column —
        # (conversation_id, agent_id) is the composite key.
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = 'ck_participants_status'"
                )
            )
            constraint_def = result.scalar_one()
        assert "invited" in constraint_def

        async with engine.connect() as conn:
            pk_cols = await conn.execute(
                text(
                    "SELECT a.attname FROM pg_index i "
                    "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                    "WHERE i.indrelid = 'participants'::regclass AND i.indisprimary"
                )
            )
            pk_col_names = {row.attname for row in pk_cols}
        assert pk_col_names == {"conversation_id", "agent_id"}

    async def test_messages_columns_and_append_only_shape(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "messages")
        for expected in (
            "id",
            "conversation_id",
            "seq",
            "sender_id",
            "type",
            "schema_version",
            "payload",
            "created_at",
        ):
            assert expected in cols, f"messages.{expected} missing"
        assert cols["payload"] == "jsonb"

    async def test_audit_log_columns(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "audit_log")
        for expected in (
            "id",
            "at",
            "actor_sub",
            "action",
            "agent_id",
            "conversation_id",
            "message_id",
            "detail",
        ):
            assert expected in cols, f"audit_log.{expected} missing"
        assert cols["detail"] == "jsonb"
        assert "task_id" not in cols, "task_id should be dropped"

    async def test_tasks_table_dropped(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "tasks")
        assert not cols, "tasks table should be dropped"

    async def test_designed_indexes_exist(self, engine: AsyncEngine) -> None:
        agent_indexes = await _indexes(engine, "agents")
        assert "idx_agents_lower_owner_email_active" in agent_indexes

        participant_indexes = await _indexes(engine, "participants")
        # idx_participants_agent_id_status (2-column) was dropped as a
        # redundant prefix of the 3-column index below (Argus round-2
        # SUGGESTION; the drop itself lives in migration 136265b3f22d, a
        # separate later migration from the one that added the 3-column
        # index (4af015077bf8) -- see 136265b3f22d's own docstring for why
        # it's split out).
        assert "idx_participants_agent_id_status" not in participant_indexes
        assert "idx_participants_agent_id_status_invited_at" in participant_indexes

        conversation_indexes = await _indexes(engine, "conversations")
        assert "idx_conversations_state_expires_at" in conversation_indexes
        assert "idx_conversations_created_by_created_at" in conversation_indexes
        assert "idx_conversations_archived_at" in conversation_indexes

        audit_indexes = await _indexes(engine, "audit_log")
        assert "idx_audit_log_conversation_id" in audit_indexes
        assert "idx_audit_log_at" in audit_indexes
        assert "idx_audit_log_task_id" not in audit_indexes

        message_indexes = await _indexes(engine, "messages")
        assert "idx_messages_conversation_id_sender_id_created_at" in message_indexes
        # Backs service._enforce_sender_global_rate_limit's sender_id/created_at
        # query, which has no conversation_id predicate and so can't use
        # the (conversation_id, sender_id, created_at) index above.
        assert "idx_messages_sender_id_created_at" in message_indexes
        # Backs service.get_conversation's TECH-6197 context-band query,
        # which filters on (conversation_id, created_at) with no sender_id
        # predicate and no seq predicate (unlike the in-window query,
        # which can use uq_messages_conversation_id_seq), avoiding a full
        # scan + filter (Argus round-1 BLOCKING, migration 44da57c6d9b9).
        assert "idx_messages_conversation_id_created_at" in message_indexes

    async def test_messages_seq_unique_per_conversation(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = 'messages'::regclass AND contype = 'u'"
                )
            )
            unique_constraints = {row.conname for row in result}
        assert "uq_messages_conversation_id_seq" in unique_constraints


class TestApprovalHoldsSchema:
    """approval_holds table (TECH-5389 PR2, migration f4a9c1d2b3e7)."""

    async def test_approval_holds_columns(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "approval_holds")
        for expected in (
            "id",
            "conversation_id",
            "sender_agent_id",
            "owner_sub",
            "message_type",
            "schema_version",
            "payload",
            "risk_reason",
            "risk_scorer",
            "status",
            "auto_approver",
            "auto_decision",
            "auto_decided_at",
            "decided_by_sub",
            "decided_at",
            "decision_reason",
            "message_id",
            "expires_at",
            "created_at",
            "updated_at",
        ):
            assert expected in cols, f"approval_holds.{expected} missing"
        assert cols["payload"] == "jsonb"

    async def test_owner_sub_not_nullable(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'approval_holds' "
                        "AND column_name = 'owner_sub'"
                    )
                )
            ).scalar_one_or_none()
        assert nullable == "NO"

    async def test_decision_reason_nullable(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'approval_holds' "
                        "AND column_name = 'decision_reason'"
                    )
                )
            ).scalar_one_or_none()
        assert nullable == "YES"

    async def test_status_check_constraint(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            constraint_def = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid = 'approval_holds'::regclass "
                        "AND conname = 'ck_approval_holds_status'"
                    )
                )
            ).scalar_one_or_none()
        assert constraint_def is not None
        for status in (
            "pending_auto",
            "pending_human",
            "auto_approved",
            "approved",
            "rejected",
            "expired",
        ):
            assert status in constraint_def

    async def test_auto_decision_check_constraint(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            constraint_def = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid = 'approval_holds'::regclass "
                        "AND conname = 'ck_approval_holds_auto_decision'"
                    )
                )
            ).scalar_one_or_none()
        assert constraint_def is not None
        assert "cleared" in constraint_def
        assert "escalated" in constraint_def

    async def test_message_id_unique_and_fks(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            unique_constraints = {
                row.conname
                for row in (
                    await conn.execute(
                        text(
                            "SELECT conname FROM pg_constraint "
                            "WHERE conrelid = 'approval_holds'::regclass AND contype = 'u'"
                        )
                    )
                )
            }
            fk_targets = {
                row.confrelid_name
                for row in (
                    await conn.execute(
                        text(
                            "SELECT confrelid::regclass::text AS confrelid_name "
                            "FROM pg_constraint "
                            "WHERE conrelid = 'approval_holds'::regclass AND contype = 'f'"
                        )
                    )
                )
            }
        assert "uq_approval_holds_message_id" in unique_constraints
        assert fk_targets == {"conversations", "agents", "messages"}

    async def test_indexes_exist(self, engine: AsyncEngine) -> None:
        indexes = await _indexes(engine, "approval_holds")
        assert "idx_approval_holds_sender_agent_id_status_created_at" in indexes
        assert "idx_approval_holds_conversation_id" in indexes
        assert "idx_approval_holds_owner_sub_status_created_at" in indexes

    async def test_round_trip_insert_and_read(self, engine: AsyncEngine) -> None:
        """Full round-trip through raw SQL (this module never mocks the
        database): insert a minimal agent + conversation, then a hold
        referencing both, and read it back."""
        async with engine.begin() as conn:
            agent_row = (
                await conn.execute(
                    text(
                        "INSERT INTO agents "
                        "(sub, owner_sub, owner_email, display_name, accepted_types, status) "
                        "VALUES ('test-hold-sender', 'test-hold-owner', "
                        "'test-hold-owner@example.com', 'test-hold-sender', ARRAY['note'], "
                        "'active') RETURNING id"
                    )
                )
            ).one()
            conversation_row = (
                await conn.execute(
                    text(
                        "INSERT INTO conversations (type, state, created_by, expires_at) "
                        "VALUES ('open', 'active', :created_by, now() + interval '7 days') "
                        "RETURNING id"
                    ),
                    {"created_by": agent_row.id},
                )
            ).one()
            hold_row = (
                await conn.execute(
                    text(
                        "INSERT INTO approval_holds "
                        "(conversation_id, sender_agent_id, owner_sub, message_type, "
                        "schema_version, payload, risk_reason, risk_scorer, status, "
                        "expires_at) "
                        "VALUES (:conversation_id, :sender_agent_id, 'test-hold-owner', "
                        "'note', 1, "
                        '\'{"type": "note", "text": "hi"}\'::jsonb, \'boundary_crossing\', '
                        "'boundary_v1', 'pending_human', now() + interval '7 days') "
                        "RETURNING id, status, decision_reason, message_id"
                    ),
                    {"conversation_id": conversation_row.id, "sender_agent_id": agent_row.id},
                )
            ).one()
            assert hold_row.status == "pending_human"
            assert hold_row.decision_reason is None
            assert hold_row.message_id is None

            # Cleanup: this module has no autouse table-truncation fixture.
            await conn.execute(
                text("DELETE FROM approval_holds WHERE id = :id"), {"id": hold_row.id}
            )
            await conn.execute(
                text("DELETE FROM conversations WHERE id = :id"), {"id": conversation_row.id}
            )
            await conn.execute(text("DELETE FROM agents WHERE id = :id"), {"id": agent_row.id})


class TestProposalHoldsSchema:
    """proposal_holds table (TECH-5871, migration d23b37d4e187).

    A sibling table to approval_holds -- not a variant of it. This class
    never touches approval_holds or any of its rows.
    """

    async def test_proposal_holds_columns(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "proposal_holds")
        for expected in (
            "id",
            "sender_agent_id",
            "kind",
            "proposed_by_bot_id",
            "owner_sub",
            "action",
            "rationale",
            "confidence",
            "importance",
            "impact",
            "priority",
            "status",
            "decision_source",
            "decided_by_actor_id",
            "decided_at",
            "decision_note",
            "target_fingerprint",
            "applied_at",
            "apply_error",
            "apply_result",
            "decision_reason_code",
            "log_seq",
            "created_at",
            "updated_at",
        ):
            assert expected in cols, f"proposal_holds.{expected} missing"
        assert cols["action"] == "jsonb"
        assert cols["sender_agent_id"] == "uuid"
        assert cols["log_seq"] == "bigint"
        # migration d88cc7e6e21b (TECH-5873 follow-up: open_ticket creates
        # a real Linear issue) -- apply_result is nullable JSONB, same
        # column type/nullability as `action`, just nullable.
        assert cols["apply_result"] == "jsonb"
        async with engine.connect() as conn:
            nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'proposal_holds' "
                        "AND column_name = 'apply_result'"
                    )
                )
            ).scalar_one()
            sender_agent_id_nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'proposal_holds' "
                        "AND column_name = 'sender_agent_id'"
                    )
                )
            ).scalar_one()
            log_seq_nullable = (
                await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'proposal_holds' "
                        "AND column_name = 'log_seq'"
                    )
                )
            ).scalar_one()
        assert nullable == "YES"
        assert sender_agent_id_nullable == "YES"
        assert log_seq_nullable == "NO"

    async def test_status_defaults_to_pending(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            default = (
                await conn.execute(
                    text(
                        "SELECT column_default FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'proposal_holds' "
                        "AND column_name = 'status'"
                    )
                )
            ).scalar_one_or_none()
        assert default is not None
        assert "pending" in default

    async def test_status_check_constraint(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            constraint_def = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid = 'proposal_holds'::regclass "
                        "AND conname = 'ck_proposal_holds_status'"
                    )
                )
            ).scalar_one_or_none()
        assert constraint_def is not None
        for status in (
            "pending",
            "approved",
            "applying",
            "rejected",
            "applied",
            "apply_failed",
            "stale",
        ):
            assert status in constraint_def

    async def test_applying_status_accepted_at_db_level(self, engine: AsyncEngine) -> None:
        """Argus review round-3 S7: an ORM-level roundtrip against the
        REAL migrated schema (unlike a truncated fixture, which can't
        confirm the actual migration's CHECK constraint), confirming
        migration e2f7a91c5b34's widened
        ``ck_proposal_holds_status`` genuinely accepts ``'applying'`` at
        the database, not just in Python's ``PROPOSAL_HOLD_STATUSES``
        tuple."""
        async with engine.connect() as conn:
            async with conn.begin():
                row_id = (
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'applying', "
                            "'human', 'test-actor', now(), 'deadbeef') "
                            "RETURNING id"
                        )
                    )
                ).scalar_one()
                read_back = (
                    await conn.execute(
                        text("SELECT status FROM proposal_holds WHERE id = :id"),
                        {"id": row_id},
                    )
                ).scalar_one()
                assert read_back == "applying"
                # Clean up within the same transaction -- this test's own
                # insert must not leak a row into any other test in this
                # module-scoped-engine class.
                await conn.execute(
                    text("DELETE FROM proposal_holds WHERE id = :id"), {"id": row_id}
                )

    async def test_status_check_constraint_rejects_invalid_value(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_status"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'bogus_status', "
                            "'human', 'test-actor', now(), 'deadbeef')"
                        )
                    )

    async def test_level_check_constraints(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            for column in ("confidence", "importance", "impact", "priority"):
                constraint_def = (
                    await conn.execute(
                        text(
                            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                            "WHERE conrelid = 'proposal_holds'::regclass "
                            "AND conname = :conname"
                        ),
                        {"conname": f"ck_proposal_holds_{column}"},
                    )
                ).scalar_one_or_none()
                assert constraint_def is not None, f"missing CHECK for {column}"
                for level in ("low", "medium", "high"):
                    assert level in constraint_def

    @pytest.mark.parametrize("column", ["confidence", "importance", "impact", "priority"])
    async def test_level_check_constraints_reject_invalid_value(
        self, engine: AsyncEngine, column: str
    ) -> None:
        levels = {"confidence": "low", "importance": "low", "impact": "low", "priority": "low"}
        levels[column] = "bogus_level"
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match=f"ck_proposal_holds_{column}"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', :confidence, :importance, :impact, "
                            ":priority, 'pending', 'deadbeef')"
                        ),
                        {
                            "confidence": levels["confidence"],
                            "importance": levels["importance"],
                            "impact": levels["impact"],
                            "priority": levels["priority"],
                        },
                    )

    async def test_decision_source_check_constraint(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            constraint_def = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid = 'proposal_holds'::regclass "
                        "AND conname = 'ck_proposal_holds_decision_source'"
                    )
                )
            ).scalar_one_or_none()
        assert constraint_def is not None
        for decision_source in ("human", "auto"):
            assert decision_source in constraint_def

    async def test_decision_source_check_constraint_rejects_invalid_value(
        self, engine: AsyncEngine
    ) -> None:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_decision_source"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'approved', "
                            "'bogus_source', 'test-actor', now(), 'deadbeef')"
                        )
                    )

    async def test_decision_reason_code_check_constraint(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            constraint_def = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid = 'proposal_holds'::regclass "
                        "AND conname = 'ck_proposal_holds_decision_reason_code'"
                    )
                )
            ).scalar_one_or_none()
        assert constraint_def is not None
        for code in (
            "not_now",
            "wrong_target",
            "incorrect_facts",
            "insufficient_evidence",
            "duplicate",
            "policy",
            "human_will_handle",
            "other",
        ):
            assert code in constraint_def

    async def test_decision_reason_code_check_constraint_rejects_invalid_value(
        self, engine: AsyncEngine
    ) -> None:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_decision_reason_code"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "decision_reason_code, target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'rejected', "
                            "'human', 'test-actor', now(), 'bogus_code', 'deadbeef')"
                        )
                    )

    async def test_decision_reason_code_migration_upgrade_idempotent(
        self, engine: AsyncEngine, database_url: str
    ) -> None:
        """Item 4: second upgrade attempt of 5ef4403d7f33 after constraint exists succeeds."""
        env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        try:
            async with engine.begin() as conn:
                await conn.execute(text("UPDATE alembic_version SET version_num = 'a56cb01a3ebf'"))
            res = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "5ef4403d7f33"],
                cwd=SERVICE_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            assert res.returncode == 0, res.stderr
        finally:
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

    async def test_indexes_exist(self, engine: AsyncEngine) -> None:
        indexes = await _indexes(engine, "proposal_holds")
        assert "idx_proposal_holds_status_created_at" in indexes
        assert "idx_proposal_holds_owner_sub_status_created_at" in indexes
        assert "idx_proposal_holds_pending_dedup" in indexes
        assert "uq_proposal_holds_bot_id_log_seq" in indexes
        assert "idx_proposal_holds_bot_id_status_log_seq" in indexes
        assert "idx_proposal_holds_bot_id_decided_at" not in indexes

    async def test_proposal_bot_log_seq_table_and_trigger(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "proposal_bot_log_seq")
        assert "bot_id" in cols
        assert "last_seq" in cols
        assert cols["last_seq"] == "bigint"

        async with engine.connect() as conn:
            # Trigger exists and is enabled ('O')
            tgenabled = (
                await conn.execute(
                    text(
                        "SELECT tgenabled FROM pg_trigger "
                        "WHERE tgname = 'trg_proposal_holds_log_seq'"
                    )
                )
            ).scalar_one_or_none()
            assert tgenabled in ("O", b"O")

            # No proposal_holds row has NULL log_seq
            null_count = (
                await conn.execute(
                    text("SELECT count(*) FROM proposal_holds WHERE log_seq IS NULL")
                )
            ).scalar_one()
            assert null_count == 0

    def test_proposal_holds_pending_dedup_index_matches_migration(self) -> None:
        from migrations.versions.a56cb01a3ebf_proposal_dedup_field import _NEW_COLUMNS, _WHERE

        dedup_indexes = [
            elem
            for elem in ProposalHold.__table_args__
            if isinstance(elem, Index) and elem.name == "idx_proposal_holds_pending_dedup"
        ]
        assert len(dedup_indexes) == 1
        idx = dedup_indexes[0]
        assert idx.unique is True
        model_where = idx.dialect_options["postgresql"]["where"]
        assert str(model_where) == str(_WHERE)
        model_exprs = [
            expr.name if hasattr(expr, "name") else str(expr) for expr in idx.expressions
        ]
        migration_exprs = [str(expr) for expr in _NEW_COLUMNS]
        assert model_exprs == migration_exprs

    async def test_sender_agent_id_fk(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            fk_info = [
                (row.conname, row.confrelid_name)
                for row in (
                    await conn.execute(
                        text(
                            "SELECT conname, confrelid::regclass::text AS confrelid_name "
                            "FROM pg_constraint "
                            "WHERE conrelid = 'proposal_holds'::regclass AND contype = 'f'"
                        )
                    )
                )
            ]
        assert any(
            name == "fk_proposal_holds_sender_agent_id" and target == "agents"
            for name, target in fk_info
        )

        # FK violation raises IntegrityError
        bogus_agent_id = uuid.uuid4()
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="fk_proposal_holds_sender_agent_id"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "target_fingerprint, sender_agent_id) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'pending', "
                            "'deadbeef', :sender_agent_id)"
                        ),
                        {"sender_agent_id": bogus_agent_id},
                    )

    async def test_tech_6668_migration_upgrade_and_downgrade_cleanly(
        self, engine: AsyncEngine, database_url: str
    ) -> None:
        """TECH-6668: verify migrations c74fb78c66e4 and ef3600cf1d37 downgrade
        and upgrade cleanly."""
        env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
        try:
            # Downgrade from head (ef3600cf1d37) to c74fb78c66e4 (step 1)
            res_down1 = subprocess.run(
                [sys.executable, "-m", "alembic", "downgrade", "c74fb78c66e4"],
                cwd=SERVICE_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            assert res_down1.returncode == 0, res_down1.stderr
            cols_mid = await _columns(engine, "proposal_holds")
            assert "sender_agent_id" in cols_mid

            # Downgrade to 44da57c6d9b9 (step 2)
            res_down2 = subprocess.run(
                [sys.executable, "-m", "alembic", "downgrade", "44da57c6d9b9"],
                cwd=SERVICE_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            assert res_down2.returncode == 0, res_down2.stderr
            cols_after_down = await _columns(engine, "proposal_holds")
            assert "sender_agent_id" not in cols_after_down
        finally:
            # Upgrade back to head so subsequent tests have full schema
            res_up = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            assert res_up.returncode == 0, res_up.stderr
        cols_after_up = await _columns(engine, "proposal_holds")
        assert "sender_agent_id" in cols_after_up

    async def test_tech_8080_downgrade_collision_raises(
        self, engine: AsyncEngine, database_url: str
    ) -> None:
        """TECH-8080 PR3: downgrade must detect collisions on the narrow key among
        active pending/applying proposals, raise RuntimeError, and NOT delete any rows."""
        env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        row1_id = uuid.uuid4()
        row2_id = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO proposal_holds "
                    "(id, kind, proposed_by_bot_id, owner_sub, action, rationale, "
                    "confidence, importance, impact, priority, status, target_fingerprint) "
                    "VALUES "
                    "(:id1, 'linear_progress_update', 'bot-collision', 'owner-a', "
                    '\'{"target_id": "proj-col", "action_type": "set_dates", '
                    '"dedup_field": "project:startDate"}\'::jsonb, '
                    "'rat1', 'medium', 'medium', 'medium', 'medium', 'pending', 'fp1'), "
                    "(:id2, 'linear_progress_update', 'bot-collision', 'owner-a', "
                    '\'{"target_id": "proj-col", "action_type": "set_dates", '
                    '"dedup_field": "project:targetDate"}\'::jsonb, '
                    "'rat2', 'medium', 'medium', 'medium', 'medium', 'pending', 'fp2')"
                ),
                {"id1": row1_id, "id2": row2_id},
            )

        try:
            res = subprocess.run(
                [sys.executable, "-m", "alembic", "downgrade", "c7665a1b2d3e"],
                cwd=SERVICE_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            assert res.returncode != 0, "Expected downgrade to fail on collision"
            assert "Cannot downgrade migration a56cb01a3ebf" in res.stderr
            assert "collision(s) on the narrow proposal dedup key" in res.stderr
            assert "An operator must manually resolve" in res.stderr
            assert "No rows were deleted" in res.stderr

            async with engine.connect() as conn:
                count = (
                    await conn.execute(
                        text("SELECT count(*) FROM proposal_holds WHERE id IN (:id1, :id2)"),
                        {"id1": row1_id, "id2": row2_id},
                    )
                ).scalar()
                assert count == 2, (
                    "Expected both rows to still exist; downgrade must not delete rows"
                )
        finally:
            async with engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM proposal_holds WHERE id IN (:id1, :id2)"),
                    {"id1": row1_id, "id2": row2_id},
                )
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

    async def test_tech_8080_downgrade_and_upgrade_clean_without_collisions(
        self, engine: AsyncEngine, database_url: str
    ) -> None:
        """TECH-8080 PR3: verify migration a56cb01a3ebf downgrades and upgrades cleanly
        when no narrow key collisions exist."""
        env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
        res_down = subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "c7665a1b2d3e"],
            cwd=SERVICE_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        assert res_down.returncode == 0, res_down.stderr

        try:
            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        "SELECT indexdef FROM pg_indexes "
                        "WHERE schemaname = 'public' AND tablename = 'proposal_holds' "
                        "AND indexname = 'idx_proposal_holds_pending_dedup'"
                    )
                )
                row = result.fetchone()
                assert row is not None
                assert "dedup_field" not in row[0]

            res_up = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            assert res_up.returncode == 0, res_up.stderr

            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        "SELECT indexdef FROM pg_indexes "
                        "WHERE schemaname = 'public' AND tablename = 'proposal_holds' "
                        "AND indexname = 'idx_proposal_holds_pending_dedup'"
                    )
                )
                row = result.fetchone()
                assert row is not None
                assert "dedup_field" in row[0]
        finally:
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

    async def test_tech_8080_scratch_index_valid_and_ready_guard(self, engine: AsyncEngine) -> None:
        """TECH-8080 PR3: _assert_scratch_index_valid_and_ready validates both indisvalid
        and indisready, and raises RuntimeError when missing, invalid, or unready."""
        from migrations.versions.a56cb01a3ebf_proposal_dedup_field import (
            _assert_scratch_index_valid_and_ready,
        )

        async with engine.connect() as conn:
            # 1. Missing index raises RuntimeError against real pg_index
            def _check_missing(sync_conn):
                with pytest.raises(RuntimeError, match="not found in pg_index"):
                    _assert_scratch_index_valid_and_ready(
                        "idx_missing_scratch_test", bind=sync_conn
                    )

            await conn.run_sync(_check_missing)

            # 2. Valid index passes against real pg_index
            await conn.execute(
                text("CREATE INDEX IF NOT EXISTS idx_scratch_guard_test ON proposal_holds (id)")
            )
            try:

                def _check_valid(sync_conn):
                    _assert_scratch_index_valid_and_ready("idx_scratch_guard_test", bind=sync_conn)

                await conn.run_sync(_check_valid)

                # 3 & 4. Invalid (indisvalid=false) and unready (indisready=false) guards:
                # Direct UPDATE pg_index requires PostgreSQL superuser privileges which are
                # not available in CI/RDS. We exercise the guard logic by monkeypatching the
                # query execution on the connection, asserting the exact RuntimeError behavior.
                class _MockRow:
                    def __init__(self, indisvalid: bool, indisready: bool) -> None:
                        self._row = (indisvalid, indisready)

                    def __getitem__(self, idx: int) -> bool:
                        return self._row[idx]

                class _MockQueryResult:
                    def __init__(self, row: _MockRow | None) -> None:
                        self._row = row

                    def fetchone(self) -> _MockRow | None:
                        return self._row

                class _MockBind:
                    def __init__(self, row: _MockRow | None) -> None:
                        self._row = row

                    def execute(self, statement: Any, parameters: Any = None) -> _MockQueryResult:
                        return _MockQueryResult(self._row)

                # indisvalid=False, indisready=True raises
                with pytest.raises(RuntimeError, match="not valid and ready"):
                    _assert_scratch_index_valid_and_ready(
                        "idx_scratch_guard_test", bind=_MockBind(_MockRow(False, True))
                    )

                # indisvalid=True, indisready=False raises
                with pytest.raises(RuntimeError, match="not valid and ready"):
                    _assert_scratch_index_valid_and_ready(
                        "idx_scratch_guard_test", bind=_MockBind(_MockRow(True, False))
                    )

                # indisvalid=False, indisready=False raises
                with pytest.raises(RuntimeError, match="not valid and ready"):
                    _assert_scratch_index_valid_and_ready(
                        "idx_scratch_guard_test", bind=_MockBind(_MockRow(False, False))
                    )
            finally:
                await conn.execute(text("DROP INDEX IF EXISTS idx_scratch_guard_test"))

    async def test_tech_8080_upgrade_invalid_scratch_index_leaves_original_intact(
        self, engine: AsyncEngine, database_url: str
    ) -> None:
        """TECH-8080 PR3: if the scratch index check fails during upgrade, the original
        idx_proposal_holds_pending_dedup index is left completely untouched."""
        env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
        # 1. Downgrade to c7665a1b2d3e
        subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "c7665a1b2d3e"],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

        try:
            # 2. Record original index definition and OID
            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        "SELECT c.oid, pg_get_indexdef(c.oid) "
                        "FROM pg_class c "
                        "WHERE c.relname = 'idx_proposal_holds_pending_dedup'"
                    )
                )
                orig_row = result.fetchone()
                assert orig_row is not None
                orig_oid, orig_indexdef = orig_row[0], orig_row[1]

            # 3. Run upgrade with simulated invalid scratch index
            res_failed = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env={**env, "_TEST_FORCE_INVALID_SCRATCH_INDEX": "1"},
                capture_output=True,
                text=True,
            )
            assert res_failed.returncode != 0
            assert "is not valid and ready (simulated failure for test)" in res_failed.stderr
            assert "Aborting swap to keep existing index intact" in res_failed.stderr

            # 4. Verify original index was NOT dropped and still has same OID and definition
            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        "SELECT c.oid, pg_get_indexdef(c.oid) "
                        "FROM pg_class c "
                        "WHERE c.relname = 'idx_proposal_holds_pending_dedup'"
                    )
                )
                after_row = result.fetchone()
                assert after_row is not None
                assert after_row[0] == orig_oid
                assert after_row[1] == orig_indexdef

            # 5. Clean upgrade without simulated failure succeeds and cleans up scratch index
            res_ok = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            assert res_ok.returncode == 0, res_ok.stderr

            # 6. Verify upgraded index has dedup_field
            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        "SELECT pg_get_indexdef(c.oid) "
                        "FROM pg_class c "
                        "WHERE c.relname = 'idx_proposal_holds_pending_dedup'"
                    )
                )
                upgraded_row = result.fetchone()
                assert upgraded_row is not None
                assert "dedup_field" in upgraded_row[0]
        finally:
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=SERVICE_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

    async def test_decision_consistency_check_constraint_rejects_pending_with_decision(
        self, engine: AsyncEngine
    ) -> None:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_decision_consistency"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'pending', "
                            "'human', 'test-actor', now(), 'deadbeef')"
                        )
                    )

    async def test_decision_consistency_check_constraint_rejects_approved_without_decision(
        self, engine: AsyncEngine
    ) -> None:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_decision_consistency"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'approved', "
                            "'deadbeef')"
                        )
                    )

    async def test_applied_at_consistency_check_constraint_rejects_non_applied(
        self, engine: AsyncEngine
    ) -> None:
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_applied_at_consistency"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "applied_at, target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'approved', "
                            "'human', 'test-actor', now(), now(), 'deadbeef')"
                        )
                    )

    async def test_apply_result_consistency_check_constraint_rejects_non_applied(
        self, engine: AsyncEngine
    ) -> None:
        """migration cf72736e07f5 -- ``apply_result`` set on a row that
        isn't ``status='applied'`` must be rejected, same shape as
        ``test_applied_at_consistency_check_constraint_rejects_non_applied``
        above for the analogous ``applied_at`` invariant."""
        async with engine.connect() as conn:
            with pytest.raises(IntegrityError, match="ck_proposal_holds_apply_result_consistency"):
                async with conn.begin():
                    await conn.execute(
                        text(
                            "INSERT INTO proposal_holds "
                            "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                            "confidence, importance, impact, priority, status, "
                            "decision_source, decided_by_actor_id, decided_at, "
                            "apply_result, target_fingerprint) "
                            "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                            "'{}'::jsonb, 'rationale', 'low', 'low', 'low', 'low', 'approved', "
                            "'human', 'test-actor', now(), '{\"id\": \"x\"}'::jsonb, 'deadbeef')"
                        )
                    )

    async def test_round_trip_insert_and_read(self, engine: AsyncEngine) -> None:
        """Full round-trip through raw SQL (this module never mocks the
        database): insert a minimal pending proposal hold, decide it, and
        read it back -- no FK to agents/conversations at all, unlike
        approval_holds."""
        async with engine.begin() as conn:
            hold_row = (
                await conn.execute(
                    text(
                        "INSERT INTO proposal_holds "
                        "(kind, proposed_by_bot_id, owner_sub, action, rationale, "
                        "confidence, importance, impact, priority, status, "
                        "target_fingerprint) "
                        "VALUES ('linear_progress_update', 'test-bot', 'test-owner', "
                        "'{\"issue\": \"TECH-5871\"}'::jsonb, 'because it needs doing', "
                        "'medium', 'high', 'low', 'high', 'pending', 'deadbeef') "
                        "RETURNING id, status, decided_at, applied_at"
                    )
                )
            ).one()
            assert hold_row.status == "pending"
            assert hold_row.decided_at is None
            assert hold_row.applied_at is None

            await conn.execute(
                text(
                    "UPDATE proposal_holds SET status = 'approved', decision_source = 'human', "
                    "decided_by_actor_id = 'test-actor', decided_at = now() WHERE id = :id"
                ),
                {"id": hold_row.id},
            )
            decided_row = (
                await conn.execute(
                    text("SELECT status, decision_source FROM proposal_holds WHERE id = :id"),
                    {"id": hold_row.id},
                )
            ).one()
            assert decided_row.status == "approved"
            assert decided_row.decision_source == "human"

            # Cleanup: this module has no autouse table-truncation fixture.
            await conn.execute(
                text("DELETE FROM proposal_holds WHERE id = :id"), {"id": hold_row.id}
            )

    async def test_orm_round_trip_pending_approved_stale(self, engine: AsyncEngine) -> None:
        """Exercise the ``ProposalHold`` ORM class itself (never instantiated
        elsewhere in this suite), through the ``pending -> approved -> stale``
        lifecycle -- ``stale`` is only ever reached from ``approved`` (see
        ``PROPOSAL_HOLD_STATUSES``'s comment in models.py), never directly
        from ``pending``."""
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        session: AsyncSession
        async with session_factory() as session:
            hold = ProposalHold(
                kind="linear_progress_update",
                proposed_by_bot_id="test-bot",
                owner_sub="test-owner",
                action={"issue": "TECH-5871"},
                rationale="because it needs doing",
                confidence="medium",
                importance="high",
                impact="low",
                priority="high",
                target_fingerprint="deadbeef",
            )
            session.add(hold)
            await session.commit()
            await session.refresh(hold)
            try:
                assert hold.status == "pending"
                assert hold.decided_at is None
                assert hold.applied_at is None

                # pending -> approved (decision fields stamped together).
                hold.status = "approved"
                hold.decision_source = "human"
                hold.decided_by_actor_id = "test-actor"
                hold.decided_at = datetime.now(UTC)
                await session.commit()
                await session.refresh(hold)
                assert hold.status == "approved"
                assert hold.decision_source == "human"

                # approved -> stale (apply-time target_fingerprint mismatch).
                hold.status = "stale"
                await session.commit()
                await session.refresh(hold)
                assert hold.status == "stale"

                fetched = await session.get(ProposalHold, hold.id)
                assert fetched is not None
                assert fetched.status == "stale"
                assert fetched.owner_sub == "test-owner"
            finally:
                # Roll back first: if a commit above failed partway through,
                # the session is left in a pending-rollback state and the
                # delete below would raise PendingRollbackError instead of
                # cleaning up, masking the real failure.
                await session.rollback()
                # Cleanup: this module has no autouse table-truncation fixture.
                await session.delete(hold)
                await session.commit()

    async def test_orm_round_trip_approved_applied(self, engine: AsyncEngine) -> None:
        """Exercise the ``approved -> applied`` transition through the ORM,
        confirming ``applied_at`` persists and the row re-reads correctly --
        the mirror image of ``test_applied_at_consistency_check_constraint_
        rejects_non_applied``'s negative case."""
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        session: AsyncSession
        async with session_factory() as session:
            hold = ProposalHold(
                kind="linear_progress_update",
                proposed_by_bot_id="test-bot",
                owner_sub="test-owner",
                action={"issue": "TECH-5871"},
                rationale="because it needs doing",
                confidence="medium",
                importance="high",
                impact="low",
                priority="high",
                status="approved",
                decision_source="human",
                decided_by_actor_id="test-actor",
                decided_at=datetime.now(UTC),
                target_fingerprint="deadbeef",
            )
            session.add(hold)
            await session.commit()
            await session.refresh(hold)
            try:
                assert hold.status == "approved"
                assert hold.applied_at is None

                # approved -> applied (terminal success state).
                applied_at = datetime.now(UTC)
                hold.status = "applied"
                hold.applied_at = applied_at
                await session.commit()
                await session.refresh(hold)
                assert hold.status == "applied"
                assert hold.applied_at is not None

                fetched = await session.get(ProposalHold, hold.id)
                assert fetched is not None
                assert fetched.status == "applied"
                assert fetched.applied_at is not None
            finally:
                await session.rollback()
                # Cleanup: this module has no autouse table-truncation fixture.
                await session.delete(hold)
                await session.commit()

    async def test_orm_round_trip_approved_applied_with_apply_result(
        self, engine: AsyncEngine
    ) -> None:
        """Positive-path mirror of
        ``test_apply_result_consistency_check_constraint_rejects_non_applied``
        above -- a row with ``status='applied'`` AND a populated
        ``apply_result`` must commit successfully, same shape as
        ``test_orm_round_trip_approved_applied``'s own ``applied_at``
        coverage."""
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        session: AsyncSession
        async with session_factory() as session:
            hold = ProposalHold(
                kind="linear_progress_update",
                proposed_by_bot_id="test-bot",
                owner_sub="test-owner",
                action={"issue": "TECH-5871"},
                rationale="because it needs doing",
                confidence="medium",
                importance="high",
                impact="low",
                priority="high",
                status="approved",
                decision_source="human",
                decided_by_actor_id="test-actor",
                decided_at=datetime.now(UTC),
                target_fingerprint="deadbeef",
            )
            session.add(hold)
            await session.commit()
            await session.refresh(hold)
            try:
                assert hold.status == "approved"
                assert hold.apply_result is None

                # approved -> applied, with apply_result populated (e.g.
                # apply_open_ticket's created-issue metadata).
                apply_result = {"id": "issue-id", "identifier": "TECH-9999", "url": "https://x"}
                hold.status = "applied"
                hold.applied_at = datetime.now(UTC)
                hold.apply_result = apply_result
                await session.commit()
                await session.refresh(hold)
                assert hold.status == "applied"
                assert hold.apply_result == apply_result

                fetched = await session.get(ProposalHold, hold.id)
                assert fetched is not None
                assert fetched.status == "applied"
                assert fetched.apply_result == apply_result
            finally:
                await session.rollback()
                # Cleanup: this module has no autouse table-truncation fixture.
                await session.delete(hold)
                await session.commit()
