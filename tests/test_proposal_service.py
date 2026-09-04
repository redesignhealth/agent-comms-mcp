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
import uuid
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from exceptions import AccessDeniedError, HoldAlreadyDecidedError, RateLimitExceededError
from linear_client import LinearAPIError, LinearTokenMissingError, LinearTransportError
from models import AuditLog, ProposalHold
from service import (
    _APPLY_ERROR_CANCELLED_MESSAGE,
    MAX_PROPOSALS_PER_BOT_PER_WINDOW,
    _sanitize_apply_error,
    create_proposal,
    decide_proposal,
    get_proposal_for_bot,
    list_pending_proposal_holds,
    withdraw_proposal,
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
        """A previously auto-approved (now auto-applied) row (same
        kind/target_id/action_type) must not be updated in place -- dedup
        only ever matches a currently ``pending`` row."""
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="deadbeef"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()),
        ):
            first = await _submit(
                session,
                action=_action(
                    source_message_url="https://redesignhealth.slack.com/archives/C1/p1"
                ),
            )
        assert first["status"] == "applied"

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
        """TECH-5873 Argus review B1: the judge's "approved" verdict is
        never itself persisted -- it resolves synchronously to "applied"
        here (matching fingerprint, successful Linear write)."""
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="deadbeef"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            result = await _submit(
                session,
                action=_action(
                    action_type="open_ticket",
                    source_message_url="https://redesignhealth.slack.com/archives/C1/p1",
                ),
            )
        assert result["status"] == "applied"
        assert result["decision_source"] == "auto"
        assert result["decided_by_actor_id"] == "system:judge"
        mock_apply.assert_awaited_once()

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
        with pytest.raises(ValueError, match="unsupported kind"):
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

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="deadbeef"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()),
        ):
            second = await _submit(
                session,
                action=_action(
                    action_type="open_ticket",
                    target_id="TECH-99",
                    source_message_url="https://redesignhealth.slack.com/archives/C1/p1",
                ),
            )
        assert second["proposal_id"] == first["proposal_id"]
        assert second["status"] == "applied"
        assert second["decision_source"] == "auto"

        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1

    async def test_auto_apply_fingerprinter_failure_sets_apply_failed(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-2 B2: a ``LinearAPIError`` from the
        fingerprinter (not just the applier) during the auto-judge's
        synchronous apply must resolve to ``apply_failed``, not propagate
        past ``create_proposal`` into a generic 500 -- the auto-apply
        path shares the same fingerprinter-wrapping bug the human-decide
        path had."""
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(
                    side_effect=LinearTokenMissingError("LINEAR_API_TOKEN is not configured")
                ),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            result = await _submit(
                session,
                action=_action(
                    action_type="open_ticket",
                    source_message_url="https://redesignhealth.slack.com/archives/C1/p1",
                ),
            )
        assert result["status"] == "apply_failed"
        # Argus review round-5 S4: the raw LinearAPIError message is no
        # longer returned verbatim to API callers -- it's mapped to one of
        # a small allowlisted set (see `_sanitize_apply_error`).
        assert result["apply_error"] == "Linear API token not configured"
        mock_apply.assert_not_awaited()


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
        """Name predates TECH-5873 B1: a well-cited proposal now resolves
        past "approved" straight to "applied", but the assertion under
        test -- it's gone from the pending listing -- still holds."""
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="deadbeef"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()),
        ):
            await _submit(
                session,
                owner_sub="owner-a@example.com",
                action=_action(
                    source_message_url="https://redesignhealth.slack.com/archives/C1/p1"
                ),
            )
        result = await list_pending_proposal_holds(session, owner_sub="owner-a@example.com")
        assert result["proposals"] == []

    async def test_no_matching_owner_sub_returns_empty(self, session: AsyncSession) -> None:
        await _submit(session, owner_sub="owner-a@example.com")
        result = await list_pending_proposal_holds(session, owner_sub="owner-nobody@example.com")
        assert result["proposals"] == []


class TestDecideProposal:
    """Service-layer coverage for ``decide_proposal`` (TECH-5873):
    approve/reject, ownership/anti-enumeration, staleness, apply failure,
    and applied-hold idempotency. Linear is mocked at the module-qualified
    ``service.linear_client`` names -- this file never touches the network.
    """

    async def test_unknown_hold_raises_access_denied(self, session: AsyncSession) -> None:
        with pytest.raises(AccessDeniedError):
            await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.uuid4(),
                decision="approve",
                decision_note=None,
            )

    async def test_not_owner_raises_access_denied(self, session: AsyncSession) -> None:
        submitted = await _submit(session, owner_sub="owner-a@example.com")
        with pytest.raises(AccessDeniedError):
            await decide_proposal(
                session,
                approver_sub="owner-b@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )

    async def test_reject_without_decision_note_raises_value_error(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session)
        with pytest.raises(ValueError):
            await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="reject",
                decision_note=None,
            )

    async def test_reject_with_note_sets_rejected(self, session: AsyncSession) -> None:
        submitted = await _submit(session)
        decided = await decide_proposal(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not appropriate",
        )
        assert decided["status"] == "rejected"
        assert decided["decision_note"] == "not appropriate"
        assert decided["decision_source"] == "human"
        assert decided["decided_by_actor_id"] == "owner-a@example.com"

    async def test_approve_matching_fingerprint_applies_and_calls_linear_once(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session, target_fingerprint="fp-match")
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp-match"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            decided = await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )
        assert decided["status"] == "applied"
        assert "applied_at" in decided
        # rationale is threaded as an explicit second argument, not part of
        # the action dict (Argus review round-5 B2).
        mock_apply.assert_awaited_once_with(submitted["action"], "because reasons")

    async def test_approve_stale_fingerprint_skips_apply(self, session: AsyncSession) -> None:
        submitted = await _submit(session, target_fingerprint="fp-original")
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp-drifted"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            decided = await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )
        assert decided["status"] == "stale"
        mock_apply.assert_not_awaited()

    async def test_approve_linear_failure_sets_apply_failed(self, session: AsyncSession) -> None:
        submitted = await _submit(session, target_fingerprint="fp-match")
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp-match"),
            ),
            patch(
                "service.linear_client.apply_progress_update",
                AsyncMock(side_effect=LinearAPIError("linear is down")),
            ),
        ):
            decided = await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )
        assert decided["status"] == "apply_failed"
        # Argus review round-5 S4: unrecognized LinearAPIError messages map
        # to the generic allowlisted message, not the raw exception text.
        assert decided["apply_error"] == "Linear API returned an error"
        assert "applied_at" not in decided

    async def test_retrying_applied_hold_is_idempotent_no_op(self, session: AsyncSession) -> None:
        submitted = await _submit(session, target_fingerprint="fp-match")
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp-match"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            first = await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )
            second = await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )
        assert first["status"] == "applied"
        assert second["status"] == "applied"
        assert second["applied_at"] == first["applied_at"]
        mock_apply.assert_awaited_once()

    async def test_deciding_already_rejected_hold_raises_already_decided(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session)
        await decide_proposal(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="no thanks",
        )
        with pytest.raises(HoldAlreadyDecidedError):
            await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )

    async def test_approve_fingerprinter_failure_sets_apply_failed(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-2 B2: a ``LinearAPIError`` from the
        fingerprinter must resolve the hold to ``apply_failed`` the same
        way an applier failure does -- previously only the applier call
        was wrapped, so this propagated past ``decide_proposal`` into a
        generic 500 instead of the documented graceful degradation."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(side_effect=LinearAPIError("linear is down")),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            decided = await decide_proposal(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
                decision_note=None,
            )
        assert decided["status"] == "apply_failed"
        # Argus review round-5 S4: unrecognized LinearAPIError messages map
        # to the generic allowlisted message, not the raw exception text.
        assert decided["apply_error"] == "Linear API returned an error"
        mock_apply.assert_not_awaited()

    async def test_cancellation_during_fingerprinting_resolves_to_apply_failed(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-6 suggestion: the round-5 B1 cooperative-
        cancellation machinery (catch ``asyncio.CancelledError``, still
        write a terminal status, re-raise) had zero test coverage. This
        covers the fingerprinter-cancelled branch: the hold must reach
        ``apply_failed`` (NOT be left stranded at ``applying``), and the
        cancellation must still propagate out of ``decide_proposal``."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        hold_id = uuid.UUID(submitted["proposal_id"])
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(side_effect=asyncio.CancelledError()),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            with pytest.raises(asyncio.CancelledError):
                await decide_proposal(
                    session,
                    approver_sub="owner-a@example.com",
                    hold_id=hold_id,
                    decision="approve",
                    decision_note=None,
                )
        mock_apply.assert_not_awaited()
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "apply_failed"
        # Argus review round-8 suggestion: content, not just non-None --
        # and specifically the FIXED public constant (Argus review round-8
        # BLOCKING fix: `apply_error` must never carry cancellation detail
        # that could leak internal information via the API response).
        assert row.apply_error == _APPLY_ERROR_CANCELLED_MESSAGE
        # Argus review round-9 suggestion: the bare-CancelledError fallback
        # text (the other branch of `_cancellation_apply_error`, exercised
        # by `test_cancellation_with_message_uses_message_in_raw_error_only`
        # for the WITH-message case) should also land in the audit log.
        # Argus review round-10 suggestion: filter by `hold_id` (a JSONB
        # field on `detail`), not `order_by(at.desc()).first()` -- the
        # timestamp-ordering approach only happened to work because this
        # test's own hold is the only row this action type could produce
        # in an otherwise-truncated table; filtering directly is correct
        # regardless of ordering or what else might run in this table.
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.apply_failed",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "apply cancelled before completion" in audit_row.detail["error"]

    async def test_cancellation_during_apply_resolves_to_apply_failed(
        self, session: AsyncSession
    ) -> None:
        """Same as above, for the applier-cancelled branch specifically --
        cancellation during the fingerprinter vs. during the applier are
        two distinct ``except asyncio.CancelledError`` sites in
        ``_apply_or_finalize_proposal_hold``."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        hold_id = uuid.UUID(submitted["proposal_id"])
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp-match"),
            ),
            patch(
                "service.linear_client.apply_progress_update",
                AsyncMock(side_effect=asyncio.CancelledError()),
            ) as mock_apply,
        ):
            with pytest.raises(asyncio.CancelledError):
                await decide_proposal(
                    session,
                    approver_sub="owner-a@example.com",
                    hold_id=hold_id,
                    decision="approve",
                    decision_note=None,
                )
        # Argus review round-7 suggestion: without this, a regression that
        # took the fingerprinter-cancelled path (which never calls the
        # applier at all) instead of the applier-cancelled path this test
        # is meant to cover would still pass on the status/apply_error
        # assertions alone.
        mock_apply.assert_awaited_once()
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "apply_failed"
        assert row.apply_error == _APPLY_ERROR_CANCELLED_MESSAGE
        # Argus review round-10 suggestion: mirror the fingerprinter-
        # cancelled test's audit-log assertion here, for the applier-
        # cancelled branch specifically -- these are two distinct
        # `except asyncio.CancelledError` call sites in
        # `_apply_or_finalize_proposal_hold`, both of which write to the
        # audit log independently.
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.apply_failed",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "apply cancelled before completion" in audit_row.detail["error"]

    async def test_cancellation_with_message_uses_message_in_raw_error_only(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-8 suggestion: `_cancellation_apply_error`'s
        non-empty-``str(exc)`` branch (``task.cancel(msg=...)``) was never
        exercised -- both cancellation tests above inject a bare
        ``CancelledError()``. This also verifies the round-8 BLOCKING
        fix's split: the enriched message reaches the AUDIT log
        (internal-only), but `apply_error` (the API-response field) stays
        the fixed constant regardless of what the cancellation message
        says."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        hold_id = uuid.UUID(submitted["proposal_id"])
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(side_effect=asyncio.CancelledError("watchdog: 30s timeout")),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()),
        ):
            with pytest.raises(asyncio.CancelledError):
                await decide_proposal(
                    session,
                    approver_sub="owner-a@example.com",
                    hold_id=hold_id,
                    decision="approve",
                    decision_note=None,
                )
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "apply_failed"
        assert row.apply_error == _APPLY_ERROR_CANCELLED_MESSAGE
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.apply_failed",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "watchdog: 30s timeout" in audit_row.detail["error"]

    async def test_cancellation_racing_concurrent_resolution_reraises_without_terminal_write(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-6 suggestion: the early-return path (hold
        resolved by something else during the external round-trip, see
        ``test_hold_resolved_during_apply_window_raises_already_decided``
        directly below) must ALSO re-raise a cancellation when one landed,
        rather than only in the normal terminal-write path -- a caller
        cancelled mid-apply is owed a cancelled task regardless of which
        return this function takes. No terminal write happens on this
        path: the row keeps whatever status the concurrent mutation left
        it at."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        hold_id = uuid.UUID(submitted["proposal_id"])

        async def _mutate_then_cancel(_target_id: str) -> str:
            await session.execute(
                update(ProposalHold)
                .where(ProposalHold.id == hold_id)
                .values(
                    status="rejected",
                    decision_source="human",
                    decided_by_actor_id="someone-else@example.com",
                    decided_at=text("now()"),
                )
            )
            await session.commit()
            raise asyncio.CancelledError()

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(side_effect=_mutate_then_cancel),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            with pytest.raises(asyncio.CancelledError):
                await decide_proposal(
                    session,
                    approver_sub="owner-a@example.com",
                    hold_id=hold_id,
                    decision="approve",
                    decision_note=None,
                )
        mock_apply.assert_not_awaited()
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        # Unchanged by this call's own (nonexistent) terminal write --
        # still whatever the concurrent mutation left it at.
        assert row.status == "rejected"

    async def test_hold_resolved_during_apply_window_raises_already_decided(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-2 B1/S4: this decide call CLAIMS the hold
        (status="applying") before releasing the row lock, so a second
        caller can no longer reach the applier for the SAME hold -- but if
        something outside this call's own claim still manages to change
        the hold's status during the ~10s external round-trip (simulated
        here via the fingerprinter mock's side effect), this call must
        raise 409, not silently return the concurrent state as its own
        200 (S4): this call never got to decide anything."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        hold_id = uuid.UUID(submitted["proposal_id"])

        async def _mutate_then_fingerprint(_target_id: str) -> str:
            await session.execute(
                update(ProposalHold)
                .where(ProposalHold.id == hold_id)
                .values(
                    status="rejected",
                    decision_source="human",
                    decided_by_actor_id="someone-else@example.com",
                    decided_at=text("now()"),
                )
            )
            await session.commit()
            return "fp-match"

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(side_effect=_mutate_then_fingerprint),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            with pytest.raises(HoldAlreadyDecidedError) as exc_info:
                await decide_proposal(
                    session,
                    approver_sub="owner-a@example.com",
                    hold_id=hold_id,
                    decision="approve",
                    decision_note=None,
                )
        assert exc_info.value.status == "rejected"
        mock_apply.assert_awaited_once()

    async def test_decide_on_already_applying_hold_raises_already_decided(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-3 S8: the initial status check in
        ``decide_proposal`` (before this call's own claim attempt) must
        already reject a hold some OTHER caller has claimed --
        ``test_hold_resolved_during_apply_window_raises_already_decided``
        above covers the helper's own re-check after a race started
        mid-flight; this covers the simpler, more common case of a
        decide call landing on a hold that was ALREADY ``"applying"``
        before this call ever acquired its lock."""
        submitted = await _submit(session, target_fingerprint="fp-match")
        hold_id = uuid.UUID(submitted["proposal_id"])
        await session.execute(
            update(ProposalHold)
            .where(ProposalHold.id == hold_id)
            .values(
                status="applying",
                decision_source="auto",
                decided_by_actor_id="system:judge",
                decided_at=text("now()"),
            )
        )
        await session.commit()

        with patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply:
            with pytest.raises(HoldAlreadyDecidedError) as exc_info:
                await decide_proposal(
                    session,
                    approver_sub="owner-a@example.com",
                    hold_id=hold_id,
                    decision="approve",
                    decision_note=None,
                )
        assert exc_info.value.status == "applying"
        mock_apply.assert_not_awaited()


class TestSanitizeApplyError:
    """Pure-function tests for ``_sanitize_apply_error`` -- no DB needed,
    but this module is the only place that imports ``service``'s proposal
    internals, so it lives here rather than a new file for three cases."""

    def test_token_missing_maps_to_token_message(self) -> None:
        exc = LinearTokenMissingError("LINEAR_API_TOKEN is not configured")
        assert _sanitize_apply_error(exc) == "Linear API token not configured"

    def test_transport_error_maps_to_unavailable_message(self) -> None:
        """Argus review round-6 suggestion: this branch (triggered by
        ``LinearTransportError``, raised by ``linear_client._post_graphql``
        on an ``httpx``/JSON-decode failure) previously had no test --
        both existing apply-failure tests used a plain ``LinearAPIError``,
        which never exercises this case."""
        exc = LinearTransportError("Linear API request failed: connection refused")
        assert _sanitize_apply_error(exc) == "Linear API unavailable"

    def test_generic_linear_api_error_maps_to_generic_message(self) -> None:
        """A message that merely happens to contain "is not configured" --
        e.g. echoed back from Linear's own GraphQL error payload -- must
        NOT be misclassified as a local token-configuration problem now
        that dispatch is by exception TYPE, not substring match (Argus
        review round-6 suggestion, the whole point of
        ``LinearTokenMissingError``/``LinearTransportError`` as distinct
        types)."""
        exc = LinearAPIError("Linear API returned errors: field X is not configured on this team")
        assert _sanitize_apply_error(exc) == "Linear API returned an error"


class TestGetProposalForBot:
    """Service-layer coverage for ``get_proposal_for_bot`` (TECH-6018):
    sender-only visibility and uniform anti-enumeration posture."""

    async def test_unknown_hold_raises_access_denied(self, session: AsyncSession) -> None:
        with pytest.raises(AccessDeniedError):
            await get_proposal_for_bot(session, hold_id=uuid.uuid4(), requesting_bot_sub="bot-1")

    async def test_different_bot_raises_access_denied(self, session: AsyncSession) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        with pytest.raises(AccessDeniedError):
            await get_proposal_for_bot(
                session,
                hold_id=uuid.UUID(submitted["proposal_id"]),
                requesting_bot_sub="bot-2",
            )

    async def test_submitting_bot_can_read_own_pending_proposal(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        result = await get_proposal_for_bot(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
        )
        assert result["status"] == "pending"
        assert result["proposal_id"] == submitted["proposal_id"]

    async def test_submitting_bot_can_read_own_decided_proposal(
        self, session: AsyncSession
    ) -> None:
        """Confirms the whole point of this endpoint: a decided outcome
        stays readable by the submitting bot after the fact, not just in
        the synchronous response to whatever call decided it."""
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        await decide_proposal(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )
        result = await get_proposal_for_bot(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
        )
        assert result["status"] == "rejected"
        assert result["decision_note"] == "not needed"


class TestWithdrawProposal:
    """Service-layer coverage for ``withdraw_proposal`` (TECH-6018):
    sender-only retraction of a still-pending proposal, and the dedup
    unlock it produces for a same-key resubmission."""

    async def test_unknown_hold_raises_access_denied(self, session: AsyncSession) -> None:
        with pytest.raises(AccessDeniedError):
            await withdraw_proposal(
                session, hold_id=uuid.uuid4(), requesting_bot_sub="bot-1", reason=None
            )

    async def test_different_bot_raises_access_denied(self, session: AsyncSession) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        with pytest.raises(AccessDeniedError):
            await withdraw_proposal(
                session,
                hold_id=uuid.UUID(submitted["proposal_id"]),
                requesting_bot_sub="bot-2",
                reason=None,
            )

    async def test_withdraw_pending_sets_withdrawn_with_bot_decision_source(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        result = await withdraw_proposal(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
            reason="superseded by a newer proposal",
        )
        assert result["status"] == "withdrawn"
        assert result["decision_source"] == "bot"
        assert result["decided_by_actor_id"] == "bot-1"
        assert result["decision_note"] == "superseded by a newer proposal"

    async def test_withdraw_already_decided_raises_already_decided(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        await decide_proposal(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )
        with pytest.raises(HoldAlreadyDecidedError):
            await withdraw_proposal(
                session,
                hold_id=uuid.UUID(submitted["proposal_id"]),
                requesting_bot_sub="bot-1",
                reason=None,
            )

    async def test_withdraw_then_resubmit_same_key_creates_fresh_row(
        self, session: AsyncSession
    ) -> None:
        """The whole point of withdraw over just leaving a stale pending
        row sitting: once withdrawn, the SAME (kind, bot, target_id,
        action_type) key is free for a fresh submission instead of being
        blocked by/silently updating the withdrawn row."""
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        await withdraw_proposal(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
            reason="stale",
        )
        resubmitted = await _submit(session, proposed_by_bot_id="bot-1")
        assert resubmitted["proposal_id"] != submitted["proposal_id"]
        assert resubmitted["status"] == "pending"
