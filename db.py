"""Async SQLAlchemy engine/session wiring for agent-comms-mcp.

Pure-Postgres persistence: SQLAlchemy 2.x (async) + asyncpg, with
Alembic migrations under ``migrations/``. Connection config comes from a
single ``DATABASE_URL`` environment variable (fail-fast via
``auth.require_env`` — same policy as the auth secrets).

The engine is created lazily on first use rather than at import time so
that importing ``main``/``providers.comms`` (as the non-DB unit tests do)
never requires a database. Server startup validates ``DATABASE_URL``
eagerly in ``main.__main__`` so a misconfigured deploy still crashes at
boot, not on the first tool call.

Tests inject their own session factory by patching
``providers.comms.get_session_factory`` — the sessions are real Postgres
sessions (never mocked), just pointed at the migrated test database.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from auth import require_env

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def database_url() -> str:
    """Return ``DATABASE_URL`` normalized to the asyncpg driver.

    Accepts either ``postgresql://`` (the conventional form used in
    docker-compose / SSM) or an explicit ``postgresql+asyncpg://`` URL.
    """
    url = require_env("DATABASE_URL")
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


def get_engine() -> AsyncEngine:
    """Return the process-wide async engine, creating it on first use.

    Pool sizing is deliberately modest: this service is a low-QPS internal
    board, and every tool call opens/closes one session.
    """
    global _engine
    if _engine is None:
        _engine = create_async_engine(database_url(), pool_size=5, max_overflow=5)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide async session factory (lazily built).

    ``expire_on_commit=False`` so ORM objects stay readable after the
    service layer commits (tools serialize results post-commit).
    """
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


__all__ = ["database_url", "get_engine", "get_session_factory"]
