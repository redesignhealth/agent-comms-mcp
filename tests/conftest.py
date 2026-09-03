"""Shared Postgres fixtures for the "real database, no mocks" test modules
(TECH-5389/TECH-5872 endpoint/service tests -- Argus review S15).

Extracted from ``test_approval_endpoint.py``/``test_proposal_endpoint.py``/
``test_proposal_service.py``, which each carried an identical ~80-line copy
of this block (``_test_database_url``, ``_can_connect``, ``database_url``,
``_migrated_schema``, ``engine``). ``_clean_tables`` is deliberately NOT
here -- which table(s) to truncate between tests differs per module, so
each module keeps its own.
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
            f"Postgres unreachable at {url!r} -- run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise this module's real-database tests."
        )
    return url


@pytest.fixture(scope="module")
def _migrated_schema(database_url: str) -> None:
    # Deliberately NOT autouse here: this conftest is shared by every test
    # module under tests/, most of which need no database at all. Making
    # this autouse at the conftest level would force every module to pull
    # in `database_url` (and therefore skip whenever Postgres is
    # unreachable) even for tests that never asked for a real DB. Each
    # real-database module opts in explicitly with
    # ``pytestmark = pytest.mark.usefixtures("_migrated_schema")``.
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
