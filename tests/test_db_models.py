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
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from schemas import MAX_DISPLAY_NAME_LENGTH

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
        """TECH-5160: min/max_schema_version backfill to 1/1 on a row that
        omits them (migration 2cc5185360c7's server_default -- Argus round
        1: a prior version of this test asserted on a ``LIMIT 0`` result
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
                        "SELECT min_schema_version, max_schema_version FROM agents "
                        "WHERE sub = :sub"
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
        # Argus round 2: the prior assertions only checked both column
        # names appeared, which would still pass even if the >= 1 lower
        # bound (added specifically to close a 0/negative-range security
        # gap) were ever reverted.
        assert ">= 1" in constraint_def

    async def test_conversations_columns(self, engine: AsyncEngine) -> None:
        cols = await _columns(engine, "conversations")
        for expected in (
            "id",
            "type",
            "state",
            "created_by",
            "expires_at",
            "owner_snapshot",
            "created_at",
            "updated_at",
        ):
            assert expected in cols, f"conversations.{expected} missing"
        assert cols["owner_snapshot"] == "jsonb"

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
        assert "idx_participants_agent_id_status" in participant_indexes

        conversation_indexes = await _indexes(engine, "conversations")
        assert "idx_conversations_state_expires_at" in conversation_indexes
        assert "idx_conversations_created_by_created_at" in conversation_indexes

        audit_indexes = await _indexes(engine, "audit_log")
        assert "idx_audit_log_conversation_id" in audit_indexes
        assert "idx_audit_log_at" in audit_indexes
        assert "idx_audit_log_task_id" not in audit_indexes

        message_indexes = await _indexes(engine, "messages")
        assert "idx_messages_conversation_id_sender_id_created_at" in message_indexes
        # TECH-5160 (Argus round 1): backs
        # service._enforce_sender_global_rate_limit's sender_id/created_at
        # query, which has no conversation_id predicate and so can't use
        # the (conversation_id, sender_id, created_at) index above.
        assert "idx_messages_sender_id_created_at" in message_indexes

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
