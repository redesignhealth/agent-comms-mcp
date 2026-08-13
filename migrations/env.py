"""Alembic environment for agent-comms-mcp.

Async-Alembic idiom (SQLAlchemy 2.x): the sync Alembic runtime drives an
async engine via ``AsyncEngine.run_sync``, so autogenerate and
``upgrade``/``downgrade`` both work against the asyncpg driver used in
production and tests alike.

The database URL is never read from ``alembic.ini`` — it comes from
``DATABASE_URL`` (fail-fast via ``auth.require_env``), matching the
service's own config path (see db.py). Tests that need a specific target
database set ``DATABASE_URL`` in the environment before invoking Alembic,
or call ``config.set_main_option("sqlalchemy.url", ...)`` directly.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context
from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from db import database_url
from models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Stable lock key for the Postgres advisory lock that serializes concurrent
# `alembic upgrade` runs (see do_run_migrations below). Fixed and arbitrary —
# only needs to be unique to this service so it doesn't collide with some
# other advisory lock use in the same database. Derived from the service
# name so it's easy to recognize in `pg_locks` if it's ever inspected.
# "RECL" in ASCII hex; pg_advisory_xact_lock() takes bigint — any int8 value is valid.
_MIGRATION_LOCK_KEY = 0x5245_434C


def _url() -> str:
    """Resolve the migration target URL.

    Prefers an explicit ``sqlalchemy.url`` set programmatically on the
    Alembic ``Config`` (used by tests targeting a specific database),
    falling back to the same ``DATABASE_URL`` the running service uses.
    """
    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured
    return database_url()


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (SQL script generation)."""
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        # Serialize concurrent `alembic upgrade head` invocations (e.g. two
        # ECS tasks starting simultaneously during a rolling deploy) so the
        # second one blocks here rather than racing the first through the
        # same DDL and crashing on "relation already exists" /
        # "value too long" mid-migration. pg_advisory_xact_lock is held for
        # the lifetime of this transaction — which spans the whole
        # migration run — and releases automatically at commit/rollback, so
        # a slower-starting task blocks, wakes once the transaction ends,
        # observes the revision is already at head, and exits cleanly.
        connection.execute(
            sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": _MIGRATION_LOCK_KEY}
        )
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live database using an async engine."""
    connectable: AsyncEngine = create_async_engine(_url(), poolclass=pool.NullPool)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
