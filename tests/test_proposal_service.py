"""Service-layer tests for proposal_holds (TECH-5872/5875/5877) — real
Postgres only, same idiom as ``tests/test_service.py``: never mocks the
database, runs the full Alembic migration chain once per module, and skips
the whole module (with a clear reason) if Postgres is unreachable.

Covers: create-time dedup vs. insert branching, server-derived priority,
the TECH-5875 per-bot rate limit, and the owner_sub-scoped visibility of
``list_pending_proposal_holds``. The judge's own four decision paths are
covered independently (no DB needed) in ``tests/test_proposal_judge.py``;
this file additionally checks that ``create_proposal`` actually applies the
judge's verdict end-to-end.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from exceptions import RateLimitExceededError
from models import ProposalHold
from service import (
    MAX_PROPOSALS_PER_BOT_PER_WINDOW,
    create_proposal,
    list_pending_proposal_holds,
)

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
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise the proposal-holds service tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
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


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE proposal_holds RESTART IDENTITY CASCADE"))
    yield


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


def _action(
    action_type: str = "open_ticket", target_id: str = "TECH-1234", **extra: Any
) -> dict[str, Any]:
    return {"action_type": action_type, "target_id": target_id, **extra}


async def _submit(
    session: AsyncSession,
    *,
    kind: str = "linear_progress_update",
    proposed_by_bot_id: str = "bot-1",
    owner_sub: str = "owner-a@example.com",
    action: dict[str, Any] | None = None,
    rationale: str = "because reasons",
    confidence: str = "medium",
    importance: str = "medium",
    impact: str = "medium",
    target_fingerprint: str = "deadbeef",
) -> dict[str, Any]:
    return await create_proposal(
        session,
        kind=kind,
        proposed_by_bot_id=proposed_by_bot_id,
        owner_sub=owner_sub,
        action=action if action is not None else _action(),
        rationale=rationale,
        confidence=confidence,
        importance=importance,
        impact=impact,
        target_fingerprint=target_fingerprint,
    )


class TestDedup:
    async def test_no_existing_pending_row_inserts(self, session: AsyncSession) -> None:
        result = await _submit(session)
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1
        assert result["proposal_id"] == str(rows[0].id)

    async def test_matching_pending_row_updates_in_place_not_insert(
        self, session: AsyncSession
    ) -> None:
        first = await _submit(session, rationale="first rationale", target_fingerprint="fp1")
        second = await _submit(session, rationale="second rationale", target_fingerprint="fp2")

        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1
        assert second["proposal_id"] == first["proposal_id"]
        assert rows[0].rationale == "second rationale"
        assert rows[0].target_fingerprint == "fp2"

    async def test_different_target_id_does_not_dedup(self, session: AsyncSession) -> None:
        await _submit(session, action=_action(target_id="TECH-1"))
        await _submit(session, action=_action(target_id="TECH-2"))
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2

    async def test_different_action_type_does_not_dedup(self, session: AsyncSession) -> None:
        await _submit(session, action=_action(action_type="open_ticket"))
        await _submit(session, action=_action(action_type="close_ticket"))
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2

    async def test_different_kind_does_not_dedup(self, session: AsyncSession) -> None:
        await _submit(session, kind="linear_progress_update")
        await _submit(session, kind="arc_board_change")
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2

    async def test_non_pending_row_is_not_deduped_against(self, session: AsyncSession) -> None:
        """A previously auto-approved row (same kind/target_id/action_type)
        must not be updated in place -- dedup only ever matches a currently
        ``pending`` row."""
        first = await _submit(
            session, action=_action(source_message_url="https://slack.example/p1")
        )
        assert first["status"] == "approved"

        second = await _submit(session, target_fingerprint="fp-new")
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2
        assert second["proposal_id"] != first["proposal_id"]

    async def test_missing_target_id_raises_value_error(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError):
            await _submit(session, action={"action_type": "open_ticket"})

    async def test_missing_action_type_raises_value_error(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError):
            await _submit(session, action={"target_id": "TECH-1"})


class TestServerDerivedPriority:
    async def test_priority_is_never_caller_supplied(self, session: AsyncSession) -> None:
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={**_action(action_type="close_ticket"), "priority": "low"},
            rationale="r",
            confidence="low",
            importance="low",
            impact="low",
            target_fingerprint="fp",
        )
        # close_ticket derives "high" server-side, ignoring the caller's
        # attempted "low" override embedded in the action payload.
        assert result["priority"] == "high"

    async def test_open_ticket_derives_medium(self, session: AsyncSession) -> None:
        result = await _submit(session, action=_action(action_type="open_ticket"))
        assert result["priority"] == "medium"

    async def test_unknown_action_type_derives_low(self, session: AsyncSession) -> None:
        result = await _submit(session, action=_action(action_type="reassign_project"))
        assert result["priority"] == "low"


class TestJudgeIntegration:
    async def test_open_ticket_with_citation_is_auto_approved(self, session: AsyncSession) -> None:
        result = await _submit(
            session,
            action=_action(
                action_type="open_ticket", source_message_url="https://slack.example/p1"
            ),
        )
        assert result["status"] == "approved"
        assert result["decision_source"] == "auto"
        assert result["decided_by_actor_id"] == "system:judge"

    async def test_open_ticket_without_citation_stays_pending(self, session: AsyncSession) -> None:
        result = await _submit(session, action=_action(action_type="open_ticket"))
        assert result["status"] == "pending"
        assert "decision_source" not in result

    async def test_unregistered_kind_stays_pending(self, session: AsyncSession) -> None:
        result = await _submit(
            session,
            kind="arc_board_change",
            action=_action(source_message_url="https://slack.example/p1"),
        )
        assert result["status"] == "pending"


class TestRateLimit:
    async def test_exceeding_per_bot_window_limit_raises(self, session: AsyncSession) -> None:
        for i in range(MAX_PROPOSALS_PER_BOT_PER_WINDOW):
            await _submit(session, action=_action(target_id=f"TECH-{i}"))
        with pytest.raises(RateLimitExceededError):
            await _submit(
                session, action=_action(target_id=f"TECH-{MAX_PROPOSALS_PER_BOT_PER_WINDOW}")
            )

    async def test_different_bots_have_independent_limits(self, session: AsyncSession) -> None:
        for i in range(MAX_PROPOSALS_PER_BOT_PER_WINDOW):
            await _submit(
                session, proposed_by_bot_id="bot-a", action=_action(target_id=f"TECH-{i}")
            )
        # bot-b's own limit is untouched by bot-a's volume.
        result = await _submit(session, proposed_by_bot_id="bot-b", action=_action())
        assert result["proposed_by_bot_id"] == "bot-b"


class TestOwnerSubVisibility:
    async def test_caller_only_sees_own_owner_sub_pending_proposals(
        self, session: AsyncSession
    ) -> None:
        await _submit(session, owner_sub="owner-a@example.com", action=_action(target_id="T1"))
        await _submit(session, owner_sub="owner-b@example.com", action=_action(target_id="T2"))

        result = await list_pending_proposal_holds(session, owner_sub="owner-a@example.com")
        assert len(result["proposals"]) == 1
        assert result["proposals"][0]["action"]["target_id"] == "T1"

    async def test_approved_proposals_are_excluded_from_pending_listing(
        self, session: AsyncSession
    ) -> None:
        await _submit(
            session,
            owner_sub="owner-a@example.com",
            action=_action(source_message_url="https://slack.example/p1"),
        )
        result = await list_pending_proposal_holds(session, owner_sub="owner-a@example.com")
        assert result["proposals"] == []

    async def test_no_matching_owner_sub_returns_empty(self, session: AsyncSession) -> None:
        await _submit(session, owner_sub="owner-a@example.com")
        result = await list_pending_proposal_holds(session, owner_sub="owner-nobody@example.com")
        assert result["proposals"] == []
