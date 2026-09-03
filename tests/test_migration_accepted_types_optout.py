"""Live-DB coverage for migration ``d5c8f1a2b4e7``'s backfill targeting
(TECH-5822 follow-up: opt-out accepted_types) — real Postgres only, same
skip-if-unreachable posture as ``test_db_models.py``.

Runs its own downgrade-to-just-before/insert-rows/upgrade-to-head dance
(rather than reusing that module's shared ``_migrated_schema`` fixture) so
it can insert rows in the specific pre-migration shape the backfill logic
actually branches on, then observe exactly which rows the migration does
and does not touch. Restores the DB to ``head`` when done — every other
test module's own autouse ``_migrated_schema`` fixture does a full
``downgrade base -> upgrade head`` before its own tests regardless, so
this module's end state is never load-bearing for another module's
correctness, only for tidiness.
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

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"

# The exact frozen set migration e1db7c2e6b70 widened every pre-existing row
# to, and the set migration d5c8f1a2b4e7's backfill matches against -- kept
# as a literal here too (not imported), same "migrations are frozen
# historical artifacts" rationale as those migrations' own docstrings.
_OLD_DEFAULT_TWELVE = [
    "availability_request",
    "availability_response",
    "confirm",
    "counter_proposal",
    "decline",
    "needs_clarification",
    "note",
    "task_assign",
    "task_cancel",
    "task_complete",
    "task_decline",
    "task_report",
]


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
    except Exception:
        return False


@pytest.fixture(scope="module")
def database_url() -> str:
    url = _test_database_url()
    if not asyncio.run(_can_connect(url)):
        pytest.skip(
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise the real-database migration test."
        )
    return url


def _run_alembic(database_url: str, *args: str) -> None:
    env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
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


async def test_backfill_widens_only_rows_matching_old_default_exactly(
    database_url: str, engine: AsyncEngine
) -> None:
    # Land on the revision immediately BEFORE this migration, so every row
    # inserted below reflects a pre-migration state.
    _run_alembic(database_url, "downgrade", "base")
    _run_alembic(database_url, "upgrade", "c1a2b3d4e5f6")

    rows = {
        # Untouched-by-anyone since e1db7c2e6b70 widened it -- the exact
        # case this migration exists to fix.
        "mig-old-default-exact": _OLD_DEFAULT_TWELVE,
        # Deliberately narrower than the old default -- an operator's own
        # earlier choice, must be left alone.
        "mig-deliberately-narrow": ["note", "confirm"],
        # Already includes a TECH-5822 type (registered after
        # e1db7c2e6b70, with a custom set) -- not the frozen default
        # shape, must be left alone.
        "mig-already-custom": [*_OLD_DEFAULT_TWELVE, "instruction_request"],
        # Already the new empty sentinel (e.g. registered under a
        # not-yet-released opt-out build) -- a no-op either way, but
        # confirms the predicate doesn't choke on an empty array.
        "mig-already-empty": [],
    }
    async with engine.begin() as conn:
        for sub, accepted_types in rows.items():
            await conn.execute(
                text(
                    "INSERT INTO agents "
                    "(sub, owner_sub, owner_email, display_name, accepted_types, status) "
                    "VALUES (:sub, :sub, :sub || '@example.com', :sub, :accepted_types, 'active')"
                ),
                {"sub": sub, "accepted_types": accepted_types},
            )

    _run_alembic(database_url, "upgrade", "head")

    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT sub, accepted_types FROM agents WHERE sub = ANY(:subs)"),
            {"subs": list(rows)},
        )
        after = {row.sub: list(row.accepted_types) for row in result}

    assert after["mig-old-default-exact"] == []
    assert sorted(after["mig-deliberately-narrow"]) == ["confirm", "note"]
    assert sorted(after["mig-already-custom"]) == sorted(
        [*_OLD_DEFAULT_TWELVE, "instruction_request"]
    )
    assert after["mig-already-empty"] == []


async def test_downgrade_restores_backfilled_rows_to_old_default(
    database_url: str, engine: AsyncEngine
) -> None:
    """Argus round-1 finding: a no-op downgrade() here would be actively
    unsafe, not just lossy -- pre-PR application code enforces
    ``accepted_types`` and treats '{}' as accept-NOTHING, and its
    validator also rejects an empty accepted_types outright, so an agent
    left at '{}' post-downgrade could not even self-recover via
    comms_register. downgrade() must restore the frozen 12-type default
    for exactly the rows this migration itself backfilled."""
    _run_alembic(database_url, "downgrade", "base")
    _run_alembic(database_url, "upgrade", "head")

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agents "
                "(sub, owner_sub, owner_email, display_name, accepted_types, status) "
                "VALUES ('mig-downgrade-empty', 'mig-downgrade-empty', "
                "'mig-downgrade-empty@example.com', 'mig-downgrade-empty', "
                "ARRAY[]::text[], 'active')"
            )
        )

    # Target this migration's own down_revision explicitly, not a relative
    # "-1" from head -- head has since gained later migrations (e.g.
    # d23b37d4e187) stacked on top of d5c8f1a2b4e7, and "-1" from head would
    # silently undo one of those instead of exercising THIS migration's
    # downgrade().
    _run_alembic(database_url, "downgrade", "c1a2b3d4e5f6")

    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT accepted_types FROM agents WHERE sub = 'mig-downgrade-empty'")
        )
        restored = list(result.scalar_one())

    assert sorted(restored) == sorted(_OLD_DEFAULT_TWELVE)

    _run_alembic(database_url, "upgrade", "head")
