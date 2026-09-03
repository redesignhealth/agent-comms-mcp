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

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from exceptions import RateLimitExceededError
from models import ProposalHold
from service import (
    MAX_PROPOSALS_PER_BOT_PER_WINDOW,
    create_proposal,
    list_pending_proposal_holds,
)

# Real-Postgres fixtures (database_url, _migrated_schema, engine) are shared
# via tests/conftest.py (Argus review S15) -- this module opts in explicitly
# since conftest's `_migrated_schema` is deliberately not autouse globally.
pytestmark = pytest.mark.usefixtures("_migrated_schema")


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE TABLE proposal_holds, audit_log RESTART IDENTITY CASCADE")
        )
    yield


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


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
        """``idx_proposal_holds_pending_dedup`` scopes on ``kind`` too --
        two rows with the same ``(proposed_by_bot_id, target_id,
        action_type)`` but different ``kind`` must both persist as
        separate pending rows. Exercised directly against ``ProposalHold``
        (bypassing ``create_proposal``/``_submit``) rather than through
        ``kind="arc_board_change"`` as this test used pre-Argus-review-S7:
        ``models.ProposalHold``'s own docstring documents ``"arc_board_change"``
        as a legitimate OPEN-vocabulary ``kind`` value at the DB layer, but
        ``_derive_proposal_priority`` only has a branch for
        ``"linear_progress_update"`` today and now raises fast for anything
        else (S7) rather than silently defaulting -- so a second literal
        ``kind`` can no longer flow through the public service function in
        this test without tripping that guard. Constructing the rows
        directly is the correct level for this assertion anyway: it is the
        index's scoping, not the service's kind support, being tested."""
        action = _action()
        common = {
            "proposed_by_bot_id": "bot-1",
            "owner_sub": "owner-a@example.com",
            "action": action,
            "rationale": "because reasons",
            "confidence": "medium",
            "importance": "medium",
            "impact": "medium",
            "priority": "medium",
            "target_fingerprint": "deadbeef",
        }
        session.add_all(
            [
                ProposalHold(kind="linear_progress_update", **common),
                ProposalHold(kind="arc_board_change", **common),
            ]
        )
        await session.commit()
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2

    async def test_cross_bot_dedup_blocked(self, session: AsyncSession) -> None:
        """TECH-5872 Argus review B1: two DIFFERENT bots proposing the same
        ``(kind, target_id, action_type)`` must each get their own pending
        row -- a different bot must never silently overwrite (and
        potentially get auto-approved under) another bot's proposal."""
        first = await _submit(
            session, proposed_by_bot_id="bot-a", action=_action(target_id="TECH-42")
        )
        second = await _submit(
            session, proposed_by_bot_id="bot-b", action=_action(target_id="TECH-42")
        )

        assert first["proposal_id"] != second["proposal_id"]
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2
        bot_ids = {row.proposed_by_bot_id for row in rows}
        assert bot_ids == {"bot-a", "bot-b"}

    async def test_same_bot_still_dedups_against_own_pending_row(
        self, session: AsyncSession
    ) -> None:
        """Companion to ``test_cross_bot_dedup_blocked``: the SAME bot
        resubmitting the same ``(kind, target_id, action_type)`` must still
        dedup in place -- B1 narrows the key, it does not remove dedup for
        the submitting bot's own repeat submissions."""
        first = await _submit(
            session, proposed_by_bot_id="bot-a", action=_action(target_id="TECH-42")
        )
        second = await _submit(
            session,
            proposed_by_bot_id="bot-a",
            action=_action(target_id="TECH-42"),
            target_fingerprint="fp-updated",
        )

        assert first["proposal_id"] == second["proposal_id"]
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1

    async def test_non_pending_row_is_not_deduped_against(self, session: AsyncSession) -> None:
        """A previously auto-approved row (same kind/target_id/action_type)
        must not be updated in place -- dedup only ever matches a currently
        ``pending`` row."""
        first = await _submit(
            session,
            action=_action(source_message_url="https://redesignhealth.slack.com/archives/C1/p1"),
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

    async def test_integrity_error_race_falls_back_to_select_and_update(
        self,
        session: AsyncSession,
        session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """B2's race-recovery path (Argus review S5): a concurrent bot wins
        the INSERT for the same dedup key between this session's initial
        SELECT (miss) and its own INSERT attempt, so ``session.flush()``
        raises ``IntegrityError`` on ``idx_proposal_holds_pending_dedup``.
        Mocks ``session.flush`` to simulate exactly that race (inserting
        and committing the "winning" row via a second, real session inside
        the mock, then raising the same shape of ``IntegrityError``
        ``_is_constraint_violation`` inspects) rather than relying on
        genuine concurrency timing, so this test is deterministic."""
        winning_row_id: dict[str, Any] = {}

        async def _insert_via_second_session() -> ProposalHold:
            async with session_factory() as other:
                winner = await create_proposal(
                    other,
                    kind="linear_progress_update",
                    proposed_by_bot_id="bot-1",
                    owner_sub="owner-a@example.com",
                    action=_action(target_id="TECH-race"),
                    rationale="winning rationale",
                    confidence="medium",
                    importance="medium",
                    impact="medium",
                    target_fingerprint="fp-winner",
                )
                return winner

        real_flush = session.flush
        call_count = {"n": 0}

        async def _flush_raising_once() -> None:
            call_count["n"] += 1
            if call_count["n"] == 1:
                winner = await _insert_via_second_session()
                winning_row_id["id"] = winner["proposal_id"]
                cause = Exception()
                cause.constraint_name = "idx_proposal_holds_pending_dedup"  # type: ignore[attr-defined]
                orig = Exception()
                orig.__cause__ = cause
                raise IntegrityError("duplicate key", params=None, orig=orig)
            await real_flush()

        monkeypatch.setattr(session, "flush", AsyncMock(side_effect=_flush_raising_once))

        result = await _submit(
            session,
            action=_action(target_id="TECH-race"),
            rationale="loser rationale",
            target_fingerprint="fp-loser",
        )

        assert result["proposal_id"] == winning_row_id["id"]
        assert result["rationale"] == "loser rationale"
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1


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
                action_type="open_ticket",
                source_message_url="https://redesignhealth.slack.com/archives/C1/p1",
            ),
        )
        assert result["status"] == "approved"
        assert result["decision_source"] == "auto"
        assert result["decided_by_actor_id"] == "system:judge"

    async def test_open_ticket_without_citation_stays_pending(self, session: AsyncSession) -> None:
        result = await _submit(session, action=_action(action_type="open_ticket"))
        assert result["status"] == "pending"
        assert "decision_source" not in result

    async def test_unregistered_kind_raises(self, session: AsyncSession) -> None:
        """Argus review S7: an unrecognized ``kind`` now fails fast in
        ``_derive_proposal_priority`` (raising ``ValueError``, well before
        the ``_PROPOSAL_JUDGES`` lookup this class otherwise covers) rather
        than silently defaulting to a generic ``"medium"`` priority and
        staying pending with no judge -- this replaces the pre-S7 version
        of this test, which asserted that stays-pending-with-no-judge
        fallback."""
        with pytest.raises(ValueError, match="no branch for kind"):
            await _submit(
                session,
                kind="arc_board_change",
                action=_action(
                    source_message_url="https://redesignhealth.slack.com/archives/C1/p1"
                ),
            )

    async def test_resubmit_with_citation_auto_approves_pending_row(
        self, session: AsyncSession
    ) -> None:
        """TECH-5872 decision #2 (Argus review B5): once the dedup fix (B1)
        scopes the dedup match to the SAME submitting bot, a bot
        progressively refining its own proposal by adding a citation on
        resubmission is expected to auto-approve the existing pending row
        in place -- this is not a new escalation path, so no additional
        guard is added for it; this test is the explicit regression
        coverage the review asked for instead."""
        first = await _submit(
            session, action=_action(action_type="open_ticket", target_id="TECH-99")
        )
        assert first["status"] == "pending"

        second = await _submit(
            session,
            action=_action(
                action_type="open_ticket",
                target_id="TECH-99",
                source_message_url="https://redesignhealth.slack.com/archives/C1/p1",
            ),
        )
        assert second["proposal_id"] == first["proposal_id"]
        assert second["status"] == "approved"
        assert second["decision_source"] == "auto"

        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1


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
            action=_action(source_message_url="https://redesignhealth.slack.com/archives/C1/p1"),
        )
        result = await list_pending_proposal_holds(session, owner_sub="owner-a@example.com")
        assert result["proposals"] == []

    async def test_no_matching_owner_sub_returns_empty(self, session: AsyncSession) -> None:
        await _submit(session, owner_sub="owner-a@example.com")
        result = await list_pending_proposal_holds(session, owner_sub="owner-nobody@example.com")
        assert result["proposals"] == []
