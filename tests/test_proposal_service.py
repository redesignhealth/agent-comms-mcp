"""Service-layer tests for proposal_holds (TECH-5872/5875/5877) — real
Postgres only, same idiom as ``tests/test_service.py``: never mocks the
database, runs the full Alembic migration chain once per module, and skips
the whole module (with a clear reason) if Postgres is unreachable.

Covers: create-time dedup vs. insert branching, the TECH-5875 per-bot rate
limit, the owner_sub-scoped visibility of ``list_pending_proposal_holds``,
and the board-mechanics side of the judge/apply/staleness state machine
(claim, staleness comparison, apply_failed/applied terminal writes,
concurrent-resubmission abandonment) -- exercised against a scriptable
``FakeProposalJudge`` (``tests/proposal_judge_fakes.py``), never a real
Linear/GitHub-backed judge. Which citation shapes a REAL judge
auto-approves is entirely out of scope here -- that lives in
``agent-comms-approvals``' own test suite, against its own
``RHProposalJudge`` (see ``docs/DESIGN.md``'s "Core and immutable
principle" section for why).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import service
from exceptions import (
    AccessDeniedError,
    HoldAlreadyDecidedError,
    ProposalTargetUnavailableError,
    RateLimitExceededError,
)
from models import AuditLog, ProposalHold
from plugins import (
    FINGERPRINT_DIGEST,
    FINGERPRINT_UNAVAILABLE,
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalFingerprint,
    ProposalJudge,
    ProposalTargetError,
    ProposalVerdict,
)
from service import (
    _APPLY_ERROR_BOARD_COMMIT_FAILURE_MESSAGE,
    _APPLY_ERROR_CANCELLED_MESSAGE,
    _APPLY_ERROR_INDETERMINATE_MESSAGE,
    MAX_PROPOSALS_PER_BOT_PER_WINDOW,
    PROPOSAL_SUBMITTER_SURFACES,
    PROPOSAL_TERMINAL_STATUSES,
    _proposal_resubmission_snapshot,
    _redact_bot_facing_dict,
    audit_denied_proposal_submission,
    create_proposal,
    decide_proposal,
    get_proposal_for_bot,
    list_pending_proposal_holds,
    list_proposal_history_for_owner,
    list_proposals_for_bot,
    withdraw_proposal,
)
from tests.proposal_judge_fakes import FakeProposalJudge

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


def _default_judge() -> ProposalJudge:
    """A ``FakeProposalJudge`` with harmless defaults (never fingerprints a
    real target, never auto-approves) -- used by ``_submit``/``_decide``
    whenever a test doesn't care what the injected judge actually does,
    same role ``EscalateAllProposalJudge`` plays in production."""
    return FakeProposalJudge()


def _action(
    action_type: str = "close_ticket", target_id: str = "TECH-1234", **extra: Any
) -> dict[str, Any]:
    """Default ``action_type`` is ``close_ticket`` -- kept for continuity
    with the pre-seam default body shape. Every test using this helper's
    default is exercising GENERIC proposal mechanics (dedup, rate
    limiting, the fingerprint-check-then-apply-or-stale flow) against an
    injected ``FakeProposalJudge``, not any real judge's rule content --
    what a given ``action_type`` means (whether it's ``FINGERPRINT_NO_TARGET``-
    exempt, what artifact it requires, etc.) is entirely up to whichever
    judge is injected at each call site."""
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
    judge: ProposalJudge | None = None,
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
        judge=judge if judge is not None else _default_judge(),
        target_fingerprint=target_fingerprint,
    )


async def _decide(
    session: AsyncSession,
    *,
    approver_sub: str = "owner-a@example.com",
    hold_id: uuid.UUID,
    decision: str = "approve",
    decision_note: str | None = None,
    judge: ProposalJudge | None = None,
) -> dict[str, Any]:
    return await decide_proposal(
        session,
        approver_sub=approver_sub,
        hold_id=hold_id,
        decision=decision,
        decision_note=decision_note,
        judge=judge if judge is not None else _default_judge(),
    )


class TestRedactBotFacingDict:
    """Direct, DB-free coverage of ``_redact_bot_facing_dict`` (Argus
    review round-5 suggestion) -- the shared rule ``_bot_facing_proposal_dict``
    and ``create_proposal``'s auto-judge happy path both delegate to. Pins
    the extracted contract independently of any integration path, so the
    refactor's stated goal (a call site can't silently regress by
    hardcoding the wrong ``decision_source`` or dropping the call
    entirely) is actually enforced by a test, not just exercised
    incidentally by unrelated ones."""

    def test_pops_decided_by_actor_id_when_human(self) -> None:
        result = _redact_bot_facing_dict(
            {"decided_by_actor_id": "owner-a@example.com"}, decision_source="human"
        )
        assert "decided_by_actor_id" not in result

    def test_preserves_decided_by_actor_id_when_not_human(self) -> None:
        for decision_source in ("auto", "bot", None):
            result = _redact_bot_facing_dict(
                {"decided_by_actor_id": "bot-1"}, decision_source=decision_source
            )
            assert result["decided_by_actor_id"] == "bot-1"


class TestDedup:
    async def test_no_existing_pending_row_inserts(self, session: AsyncSession) -> None:
        result = await _submit(session)
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 1
        assert result["proposal_id"] == str(rows[0].id)

    async def test_matching_pending_row_updates_in_place_not_insert(
        self, session: AsyncSession
    ) -> None:
        """``target_fingerprint`` is server-computed at submission time via
        the injected judge's ``fingerprint()`` -- each submission's stored
        value comes from whatever THAT call's judge reports, not a
        caller-supplied literal, so the two submissions below use two
        independently-configured fakes to prove the SECOND submission's
        freshly re-fetched fingerprint is what ends up persisted."""
        first = await _submit(
            session,
            rationale="first rationale",
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp1")
            ),
        )
        second = await _submit(
            session,
            rationale="second rationale",
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp2")
            ),
        )

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
        whether a ``kind`` is admitted at all is now entirely up to the
        injected judge's ``classify()`` (``FakeProposalJudge`` here has no
        opinion on ``"arc_board_change"`` one way or the other, but a real
        judge could raise for it) -- so a second literal ``kind`` can no
        longer flow through the public service function in this test
        without depending on judge behavior this test isn't about.
        Constructing the rows
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
        auto_approve_judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        first = await _submit(session, judge=auto_approve_judge)
        assert first["status"] == "applied"

        second = await _submit(session, target_fingerprint="fp-new")
        rows = (await session.execute(select(ProposalHold))).scalars().all()
        assert len(rows) == 2
        assert second["proposal_id"] != first["proposal_id"]

    async def test_resubmission_against_applying_row_redacts_human_decider(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-3 suggestion: the exact scenario the round-2
        BLOCKING fix (``_bot_facing_proposal_dict``) was written for --
        seed an ``'applying'`` row a HUMAN concurrently claimed (dedup's
        partial index covers ``'applying'`` too, per
        ``service._proposal_dedup_where``'s own docstring), resubmit
        against the SAME dedup key, and confirm the submitting bot's
        response never discloses that human's identity. Covers
        ``create_proposal``'s ``if not auto_approved:`` return path
        specifically -- without the round-2 fix, that path returned a bare
        ``_proposal_dict`` and this test would still pass green if it only
        checked ``status`` -- it must assert the REDACTION itself. The lost-
        claim-race and auto-judge return paths are separately reachable
        only via a hand-authored race (see
        ``test_integrity_error_race_falls_back_to_select_and_update`` for
        that pattern) and are not exercised by this test -- see
        ``TestRedactBotFacingDict`` for direct coverage of the shared
        ``_redact_bot_facing_dict`` rule those paths delegate to."""
        action = _action(target_id="TECH-77")
        applying_hold = ProposalHold(
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action=action,
            rationale="because reasons",
            confidence="medium",
            importance="medium",
            impact="medium",
            priority="medium",
            target_fingerprint="deadbeef",
            status="applying",
            decision_source="human",
            decided_by_actor_id="owner-a@example.com",
            decided_at=datetime.now(UTC),
        )
        session.add(applying_hold)
        await session.commit()

        result = await _submit(session, action=action, target_fingerprint="fp-new")

        assert result["status"] == "applying"
        assert result["proposal_id"] == str(applying_hold.id)
        assert "decided_by_actor_id" not in result

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
                    judge=_default_judge(),
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


class TestClassifyDispatch:
    """Board-side coverage of the ``judge.classify()`` call site in
    ``create_proposal`` (via the defensive ``_classify_proposal`` wrapper):
    ``priority`` is always whatever the injected judge reports, never a
    caller-supplied value, and a contract-violating priority is rejected
    rather than trusted. Which ``kind``/``action_type`` combinations a REAL
    judge admits, and at what priority, is entirely that judge's own
    concern -- see ``agent-comms-approvals``' test suite for RH's rules."""

    async def test_priority_is_never_caller_supplied(self, session: AsyncSession) -> None:
        result = await _submit(
            session,
            action={**_action(), "priority": "low"},
            judge=FakeProposalJudge(classify_result=ProposalClassification(priority="high")),
        )
        # The judge derives "high" -- the caller's attempted "low" override
        # embedded in the action payload is ignored.
        assert result["priority"] == "high"

    async def test_classify_receives_kind_and_action(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge()
        action = _action(action_type="open_ticket")
        await _submit(session, action=action, judge=judge)
        assert judge.classify_calls == [("linear_progress_update", action)]

    async def test_unsupported_kind_raises_value_error(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(classify_raises=ValueError("unsupported kind: 'nonsense'"))
        pattern = "unsupported proposal kind: 'linear_progress_update'"
        with pytest.raises(ValueError, match=pattern) as exc_info:
            await _submit(session, judge=judge)
        assert "unsupported kind: 'nonsense'" in str(exc_info.value.__cause__)


class TestJudgeApplyBoardMechanics:
    """Board-mechanics coverage of the create_proposal -> claim ->
    judge.apply() synchronous auto-apply pipeline (TECH-5877/5873), against
    a scriptable ``FakeProposalJudge`` -- never a real Linear/GitHub-backed
    judge. What artifact justifies a REAL judge auto-approving a given
    proposal is out of scope here entirely (see this module's own
    docstring); this class only asserts what the BOARD does once a verdict
    says "approved": claim the row, compare fingerprints, call apply() (or
    not), and write the correct terminal status."""

    async def test_approved_verdict_claims_and_applies(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved: reasons"),
            apply_result=ProposalApplyOutcome(
                applied=True, result={"id": "abc"}, caller_error=None, log_detail=None
            ),
        )
        result = await _submit(session, judge=judge)
        assert result["status"] == "applied"
        assert result["apply_result"] == {"id": "abc"}
        assert len(judge.judge_calls) == 1
        assert len(judge.apply_calls) == 1
        assert judge.apply_calls[0].action == result["action"]
        assert judge.apply_calls[0].rationale == "because reasons"

    async def test_approved_verdict_with_drifted_fingerprint_goes_stale_without_apply(
        self, session: AsyncSession
    ) -> None:
        """``create_proposal`` calls ``judge.fingerprint()`` twice within
        one request: once at submission time (stored as
        ``target_fingerprint``) and again, synchronously, inside
        ``_apply_or_finalize_proposal_hold`` right after claiming the
        auto-approved verdict. A judge whose target genuinely drifted
        between those two calls (simulated here by returning two different
        digests in sequence) must resolve the hold to ``"stale"`` without
        ever calling ``apply()``."""

        class _DriftingFingerprintJudge(FakeProposalJudge):
            def __init__(self) -> None:
                super().__init__(
                    judge_result=ProposalVerdict(approved=True, decision_note="auto-approved")
                )
                self._digests = iter(["fp-at-submit", "fp-drifted-before-apply"])

            async def fingerprint(self, ctx: Any) -> ProposalFingerprint:
                self.fingerprint_calls.append(ctx)
                return ProposalFingerprint(status=FINGERPRINT_DIGEST, digest=next(self._digests))

        judge = _DriftingFingerprintJudge()
        result = await _submit(session, judge=judge)
        assert result["status"] == "stale"
        assert judge.apply_calls == []
        # Finding 12: the judge's own "auto-approved" verdict note is a
        # non-empty `original_decision_note` here, exercising the `if`
        # branch of `_stale_decision_note` (wrapping it for context) --
        # the sibling human-decide test below exercises the other branch
        # (no original note to wrap).
        assert result["decision_note"] == (
            "not applied: target changed after approval; no write to the target was "
            "performed (approval reason was: auto-approved)"
        )

    async def test_apply_returning_applied_false_sets_apply_failed(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="target system unavailable",
                log_detail="raw upstream detail, never returned to the caller",
            ),
        )
        result = await _submit(session, judge=judge)
        assert result["status"] == "apply_failed"
        assert result["apply_error"] == "target system unavailable"
        # log_detail is never surfaced over the API -- only the sanitized
        # caller_error is.
        assert "raw upstream detail" not in str(result)

    async def test_pending_verdict_never_calls_apply(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(judge_result=ProposalVerdict(approved=False, decision_note=None))
        result = await _submit(session, judge=judge)
        assert result["status"] == "pending"
        assert judge.apply_calls == []

    async def test_judge_raising_resolves_to_pending_with_judge_error_note(
        self, session: AsyncSession
    ) -> None:
        """Fail closed: an exception from ``judge.judge()`` (a plugin bug,
        or a future lane's real I/O failing) must never be mistaken for an
        "approved" verdict, and must never crash ``create_proposal``
        outright -- same ``except Exception`` shape this module has always
        used for the rule/judge call. The isolated, no-DB coverage of
        every OTHER plugin call raising (``classify``/``fingerprint``/
        ``apply``) lives in ``tests/test_proposal_judge_seam.py``; this one
        needs the DB because the fail-closed handling is inline in
        ``create_proposal`` itself, not a separately-testable helper."""
        judge = FakeProposalJudge(judge_raises=RuntimeError("boom"))
        result = await _submit(session, judge=judge)
        assert result["status"] == "pending"
        assert result["decision_note"] == "judge error: RuntimeError"
        assert judge.apply_calls == []

    async def test_concurrent_resubmission_supersedes_judged_payload(
        self, session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The CAS guard in ``_claim_proposal_hold_for_applying``: if a
        concurrent resubmission updates the pending row's payload while
        this judge's verdict is still in flight, the stale verdict is
        abandoned (never applied) rather than misapplied to the new
        payload -- exercised here by mutating the row from inside the
        judge's own ``judge()`` call, simulating that race deterministically
        rather than relying on real concurrency timing."""
        target_id = "TECH-race-payload"

        class _MutatingJudge(FakeProposalJudge):
            def __init__(self, other_session: AsyncSession) -> None:
                super().__init__(
                    judge_result=ProposalVerdict(approved=True, decision_note="auto-approved")
                )
                self._other_session = other_session

            async def judge(self, ctx: Any) -> ProposalVerdict:
                self.judge_calls.append(ctx)
                async with self._other_session() as other:
                    await _submit(
                        other,
                        action=_action(target_id=target_id),
                        rationale="superseding resubmission",
                        judge=FakeProposalJudge(),
                    )
                return self.judge_result

        judge = _MutatingJudge(session_factory)
        result = await _submit(session, action=_action(target_id=target_id), judge=judge)
        # The stale verdict never reached apply() -- the concurrent
        # resubmission's own (pending) judgment is what's left standing.
        assert judge.apply_calls == []
        assert result["status"] == "pending"
        assert result["rationale"] == "superseding resubmission"

    async def test_resubmit_with_updated_payload_auto_approves_pending_row(
        self, session: AsyncSession
    ) -> None:
        """A bot progressively refining its own still-pending proposal (not
        a new escalation path): resubmitting against the same dedup key
        with a judge that now approves must auto-apply on this pass. Kept
        by this exact name -- referenced from ``create_proposal``'s own
        docstring (nee ``TestJudgeIntegration::
        test_resubmit_with_citation_auto_approves_pending_row``, before the
        artifact-citation-specific verdict content moved to
        ``agent-comms-approvals``)."""
        target_id = "TECH-resubmit-approve"
        pending_judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=False, decision_note=None)
        )
        first = await _submit(session, action=_action(target_id=target_id), judge=pending_judge)
        assert first["status"] == "pending"

        approving_judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved: refined"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        second = await _submit(session, action=_action(target_id=target_id), judge=approving_judge)
        assert second["proposal_id"] == first["proposal_id"]
        assert second["status"] == "applied"


class TestProposalResubmissionSnapshot:
    """Pins the JSON-normalization behavior of
    ``_proposal_resubmission_snapshot`` (Problem 1 fix) -- no DB needed,
    a plain in-memory ``ProposalHold`` is enough. Guards against
    ``copy.deepcopy`` silently creeping back in: a raw deepcopy would
    preserve a nested ``tuple`` in ``action`` as-is, which would then
    fail to compare equal against the SAME logical value once it has
    round-tripped through a real JSONB column (asyncpg always decodes a
    JSON array as a ``list``, never a ``tuple``) -- exactly the kind of
    false CAS mismatch this normalization exists to prevent."""

    def test_nested_tuple_in_action_is_normalized_to_a_list(self) -> None:
        hold = ProposalHold(
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"nested": ("a", "b")},
            rationale="because reasons",
            confidence="medium",
            importance="medium",
            impact="medium",
            priority="medium",
            target_fingerprint="deadbeef",
        )
        snapshot = _proposal_resubmission_snapshot(hold)
        action_snapshot = snapshot[0]
        assert action_snapshot == {"nested": ["a", "b"]}
        assert isinstance(action_snapshot["nested"], list)


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

    async def test_fingerprint_fetch_failure_does_not_burn_rate_limit_slot(
        self, session: AsyncSession
    ) -> None:
        """Argus review: the target-fingerprint fetch now runs BEFORE the
        rate-limit attempt marker is committed, so a judge reporting
        FINGERPRINT_UNAVAILABLE there must not consume the bot's rate-limit
        budget for a proposal that was never created -- a normal submission
        right after a full window's worth of failed fetches must still
        succeed."""
        failing_judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_UNAVAILABLE,
                error=ProposalTargetError(
                    status_code=503,
                    error_code="service_unavailable",
                    detail="target system unavailable",
                    log_detail="boom",
                ),
            )
        )
        for i in range(MAX_PROPOSALS_PER_BOT_PER_WINDOW + 1):
            with pytest.raises(ProposalTargetUnavailableError):
                await _submit(
                    session, action=_action(target_id=f"TECH-fail-{i}"), judge=failing_judge
                )

        result = await _submit(session, action=_action(target_id="TECH-ok"))
        assert result["proposed_by_bot_id"] == "bot-1"


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
        """Name predates TECH-5873 B1: an auto-approved proposal now resolves
        past "approved" straight to "applied", but the assertion under
        test -- it's gone from the pending listing -- still holds."""
        auto_approve_judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        await _submit(session, owner_sub="owner-a@example.com", judge=auto_approve_judge)
        result = await list_pending_proposal_holds(session, owner_sub="owner-a@example.com")
        assert result["proposals"] == []

    async def test_no_matching_owner_sub_returns_empty(self, session: AsyncSession) -> None:
        await _submit(session, owner_sub="owner-a@example.com")
        result = await list_pending_proposal_holds(session, owner_sub="owner-nobody@example.com")
        assert result["proposals"] == []


class TestListProposalHistoryForOwner:
    """Service-layer coverage for ``list_proposal_history_for_owner``
    (TECH-6030) -- mirrors ``TestOwnerSubVisibility`` above, but for the
    terminal-status/human-history side rather than pending."""

    async def test_caller_only_sees_own_owner_sub_decided_proposals(
        self, session: AsyncSession
    ) -> None:
        submitted_a = await _submit(
            session, owner_sub="owner-a@example.com", action=_action(target_id="T1")
        )
        submitted_b = await _submit(
            session, owner_sub="owner-b@example.com", action=_action(target_id="T2")
        )
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted_a["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )
        await _decide(
            session,
            approver_sub="owner-b@example.com",
            hold_id=uuid.UUID(submitted_b["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )

        result = await list_proposal_history_for_owner(session, owner_sub="owner-a@example.com")
        assert len(result["proposals"]) == 1
        assert result["proposals"][0]["action"]["target_id"] == "T1"

    async def test_pending_proposals_excluded_from_history(self, session: AsyncSession) -> None:
        await _submit(session, owner_sub="owner-a@example.com")
        result = await list_proposal_history_for_owner(session, owner_sub="owner-a@example.com")
        assert result["proposals"] == []

    async def test_withdrawn_proposal_included_and_unredacted(self, session: AsyncSession) -> None:
        """Unlike the bot-facing ``list_proposals_for_bot``, this human-
        facing listing must NOT redact ``decided_by_actor_id`` -- the
        reviewer is exactly who's entitled to see who/what decided it."""
        submitted = await _submit(session, owner_sub="owner-a@example.com")
        await withdraw_proposal(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
            reason="stale",
        )
        result = await list_proposal_history_for_owner(session, owner_sub="owner-a@example.com")
        assert len(result["proposals"]) == 1
        assert result["proposals"][0]["status"] == "withdrawn"
        assert result["proposals"][0]["decided_by_actor_id"] == "bot-1"

    async def test_no_matching_owner_sub_returns_empty(self, session: AsyncSession) -> None:
        submitted = await _submit(session, owner_sub="owner-a@example.com")
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )
        result = await list_proposal_history_for_owner(
            session, owner_sub="owner-nobody@example.com"
        )
        assert result["proposals"] == []

    async def test_limit_clamped_and_has_more(self, session: AsyncSession) -> None:
        limit = 2
        for i in range(limit + 1):
            submitted = await _submit(
                session, owner_sub="owner-a@example.com", action=_action(target_id=f"T{i}")
            )
            await _decide(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="reject",
                decision_note="not needed",
            )

        result = await list_proposal_history_for_owner(
            session, owner_sub="owner-a@example.com", limit=limit
        )
        assert len(result["proposals"]) == limit
        assert result["has_more"] is True

    async def test_has_more_false_when_at_or_below_limit(self, session: AsyncSession) -> None:
        """Argus review round 1 (TECH-6030 PR): the ``has_more=True`` path
        above had no ``has_more=False`` counterpart, so an off-by-one in the
        ``limit + 1`` fetch (e.g. dropping the ``+ 1``) would silently
        return ``False`` for every query without failing a single test."""
        limit = 2
        for i in range(limit):
            submitted = await _submit(
                session, owner_sub="owner-a@example.com", action=_action(target_id=f"T{i}")
            )
            await _decide(
                session,
                approver_sub="owner-a@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="reject",
                decision_note="not needed",
            )

        result = await list_proposal_history_for_owner(
            session, owner_sub="owner-a@example.com", limit=limit
        )
        assert len(result["proposals"]) == limit
        assert result["has_more"] is False

    async def test_ordered_newest_decided_first(self, session: AsyncSession) -> None:
        """Argus review round 1 (TECH-6030 PR): unlike
        ``list_pending_proposal_holds``'s oldest-first order, history is
        ordered ``created_at`` DESC on purpose -- terminal rows accumulate
        forever, so oldest-first plus the 200-row cap would eventually make
        a reviewer's newest decisions permanently unreachable. Assert the
        actual order, not just the count, so a regression back to ASC (or
        no explicit order at all) fails a test."""
        submitted_first = await _submit(
            session, owner_sub="owner-a@example.com", action=_action(target_id="FIRST")
        )
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted_first["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )
        submitted_second = await _submit(
            session, owner_sub="owner-a@example.com", action=_action(target_id="SECOND")
        )
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(submitted_second["proposal_id"]),
            decision="reject",
            decision_note="not needed",
        )

        result = await list_proposal_history_for_owner(session, owner_sub="owner-a@example.com")
        target_ids = [p["action"]["target_id"] for p in result["proposals"]]
        assert target_ids == ["SECOND", "FIRST"]

    async def test_all_terminal_statuses_included(self, session: AsyncSession) -> None:
        """Argus review round 1 (TECH-6030 PR): the other tests in this
        class only ever produce ``rejected``/``withdrawn`` rows, so a typo
        in the ``.in_(PROPOSAL_TERMINAL_STATUSES)`` filter that silently
        dropped ``applied``/``apply_failed``/``stale`` would pass every
        other test in this file. Drive one proposal to each of the
        remaining three terminal statuses via the same paths
        ``TestDecideProposal`` uses below.

        ``target_fingerprint`` is server-computed at submission time via
        the injected judge, so each submission below uses its own
        independently-configured ``FakeProposalJudge`` -- an independent
        call site from the one the later ``decide`` call configures --
        rather than trusting a caller-supplied literal. The APPLIED/
        APPLY_FAILED cases use the SAME digest at both submit and decide
        time (a genuinely unchanged target); STALE deliberately uses two
        DIFFERENT digests, to prove a real mismatch, not a shared
        hardcoded string."""
        applied_judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_DIGEST, digest="fp-applied-match"
            ),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        applied_submitted = await _submit(
            session,
            owner_sub="owner-a@example.com",
            action=_action(target_id="APPLIED"),
            judge=applied_judge,
        )
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(applied_submitted["proposal_id"]),
            decision="approve",
            judge=applied_judge,
        )

        apply_failed_judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_DIGEST, digest="fp-apply-failed-match"
            ),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="Linear API returned an error",
                log_detail="linear is down",
            ),
        )
        apply_failed_submitted = await _submit(
            session,
            owner_sub="owner-a@example.com",
            action=_action(target_id="APPLY_FAILED"),
            judge=apply_failed_judge,
        )
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(apply_failed_submitted["proposal_id"]),
            decision="approve",
            judge=apply_failed_judge,
        )

        stale_judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-original")
        )
        stale_submitted = await _submit(
            session,
            owner_sub="owner-a@example.com",
            action=_action(target_id="STALE"),
            judge=stale_judge,
        )
        stale_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-drifted"
        )
        await _decide(
            session,
            approver_sub="owner-a@example.com",
            hold_id=uuid.UUID(stale_submitted["proposal_id"]),
            decision="approve",
            judge=stale_judge,
        )

        result = await list_proposal_history_for_owner(session, owner_sub="owner-a@example.com")
        statuses_by_target = {p["action"]["target_id"]: p["status"] for p in result["proposals"]}
        assert statuses_by_target == {
            "APPLIED": "applied",
            "APPLY_FAILED": "apply_failed",
            "STALE": "stale",
        }


class TestDecideProposal:
    """Service-layer coverage for ``decide_proposal`` (TECH-5873):
    approve/reject, ownership/anti-enumeration, staleness, apply failure,
    and applied-hold idempotency. The injected ``FakeProposalJudge``
    stands in for whatever real judge is configured -- this class asserts
    only board mechanics (claim, staleness comparison, terminal-status
    writes, cancellation handling), never a real judge's own rule content.
    """

    async def test_unknown_hold_raises_access_denied(self, session: AsyncSession) -> None:
        with pytest.raises(AccessDeniedError):
            await _decide(session, hold_id=uuid.uuid4(), decision="approve")

    async def test_not_owner_raises_access_denied(self, session: AsyncSession) -> None:
        submitted = await _submit(session, owner_sub="owner-a@example.com")
        with pytest.raises(AccessDeniedError):
            await _decide(
                session,
                approver_sub="owner-b@example.com",
                hold_id=uuid.UUID(submitted["proposal_id"]),
                decision="approve",
            )

    async def test_reject_without_decision_note_raises_value_error(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session)
        with pytest.raises(ValueError):
            await _decide(session, hold_id=uuid.UUID(submitted["proposal_id"]), decision="reject")

    async def test_reject_with_note_sets_rejected(self, session: AsyncSession) -> None:
        submitted = await _submit(session)
        decided = await _decide(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not appropriate",
        )
        assert decided["status"] == "rejected"
        assert decided["decision_note"] == "not appropriate"
        assert decided["decision_source"] == "human"
        assert decided["decided_by_actor_id"] == "owner-a@example.com"

    async def test_approve_matching_fingerprint_applies_and_calls_apply_once(
        self, session: AsyncSession
    ) -> None:
        """The submit-time fingerprint and the later apply-time re-fetch
        are two independent calls to the SAME judge instance here, not one
        hardcoded literal shared between them -- both happen to return the
        same digest, representing a target that genuinely hasn't
        changed."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        decided = await _decide(
            session, hold_id=uuid.UUID(submitted["proposal_id"]), decision="approve", judge=judge
        )
        assert decided["status"] == "applied"
        assert "applied_at" in decided
        assert len(judge.apply_calls) == 1
        # rationale is threaded as its own ProposalContext field, not part
        # of the action dict.
        assert judge.apply_calls[0].action == submitted["action"]
        assert judge.apply_calls[0].rationale == "because reasons"

    async def test_approve_stale_fingerprint_skips_apply(self, session: AsyncSession) -> None:
        """The submit-time fingerprint and the apply-time re-fetch below
        are two DIFFERENT digests -- a genuine mismatch, not a
        caller-supplied literal the test controls on both ends."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-original"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-drifted"
        )
        decided = await _decide(
            session, hold_id=uuid.UUID(submitted["proposal_id"]), decision="approve", judge=judge
        )
        assert decided["status"] == "stale"
        assert judge.apply_calls == []
        # Sibling assertion to the auto-apply staleness test above, for the
        # human-decide path: the same honest-stale note applies here too --
        # no write happened, and this path passed no original decision_note
        # to wrap for context.
        assert decided["decision_note"] == (
            "not applied: target changed after approval; no write to the target was performed"
        )

    async def test_approve_apply_failure_sets_apply_failed(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="Linear API returned an error",
                log_detail="linear is down",
            ),
        )
        submitted = await _submit(session, judge=judge)
        decided = await _decide(
            session, hold_id=uuid.UUID(submitted["proposal_id"]), decision="approve", judge=judge
        )
        assert decided["status"] == "apply_failed"
        assert decided["apply_error"] == "Linear API returned an error"
        assert "applied_at" not in decided

    async def test_retrying_applied_hold_is_idempotent_no_op(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        first = await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        second = await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert first["status"] == "applied"
        assert second["status"] == "applied"
        assert second["applied_at"] == first["applied_at"]
        assert len(judge.apply_calls) == 1

    async def test_deciding_already_rejected_hold_raises_already_decided(
        self, session: AsyncSession
    ) -> None:
        submitted = await _submit(session)
        hold_id = uuid.UUID(submitted["proposal_id"])
        await _decide(session, hold_id=hold_id, decision="reject", decision_note="no thanks")
        with pytest.raises(HoldAlreadyDecidedError):
            await _decide(session, hold_id=hold_id, decision="approve")

    async def test_approve_fingerprint_unavailable_sets_apply_failed(
        self, session: AsyncSession
    ) -> None:
        """A judge reporting FINGERPRINT_UNAVAILABLE at apply time must
        resolve the hold to ``apply_failed`` the same way an ``apply()``
        failure does -- symmetrical to ``create_proposal``'s own submit-time
        handling of the same status."""
        submitted = await _submit(
            session,
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match")
            ),
        )
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_UNAVAILABLE,
                error=ProposalTargetError(
                    status_code=422,
                    error_code="invalid_request",
                    detail="Linear API returned an error",
                    log_detail="linear is down",
                ),
            )
        )
        decided = await _decide(
            session, hold_id=uuid.UUID(submitted["proposal_id"]), decision="approve", judge=judge
        )
        assert decided["status"] == "apply_failed"
        assert decided["apply_error"] == "Linear API returned an error"
        assert judge.apply_calls == []

    async def test_cancellation_during_fingerprinting_resolves_to_apply_failed(
        self, session: AsyncSession
    ) -> None:
        """Argus review round-6 suggestion: the round-5 B1 cooperative-
        cancellation machinery (catch ``asyncio.CancelledError``, still
        write a terminal status, re-raise) had zero test coverage. This
        covers the fingerprinter-cancelled branch: the hold must reach
        ``apply_failed`` (NOT be left stranded at ``applying``), and the
        cancellation must still propagate out of ``decide_proposal``."""
        submitted = await _submit(
            session,
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match")
            ),
        )
        hold_id = uuid.UUID(submitted["proposal_id"])
        judge = FakeProposalJudge(fingerprint_raises=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert judge.apply_calls == []
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "apply_failed"
        # Argus review round-8 suggestion: content, not just non-None --
        # and specifically the FIXED public constant (Argus review round-8
        # BLOCKING fix: `apply_error` must never carry cancellation detail
        # that could leak internal information via the API response).
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
        assert "apply cancelled before completion" in audit_row.detail["error"]

    async def test_cancellation_during_apply_leaves_hold_at_applying(
        self, session: AsyncSession
    ) -> None:
        """TECH-6213 PR-B1 (FIX 4): cancellation during apply is indeterminate.
        The hold must remain at 'applying' (NOT 'apply_failed') so create-time dedup
        blocks resubmissions from minting a new hold_id, preventing duplicate
        external writes."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_raises=asyncio.CancelledError(),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert len(judge.apply_calls) == 1
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "applying"
        assert row.apply_error == _APPLY_ERROR_INDETERMINATE_MESSAGE
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.apply_indeterminate",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "apply cancelled before completion" in audit_row.detail["error"]

    async def test_indeterminate_apply_outcome_leaves_hold_at_applying_and_blocks_resubmission(
        self, session: AsyncSession
    ) -> None:
        """TECH-6213 PR-B1 (FIX 4): an indeterminate apply outcome leaves status='applying',
        and a subsequent resubmission attempt for the same target key folds into the
        existing row as a no-op, minting NO new hold_id."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="apply outcome could not be confirmed; awaiting manual reconciliation",
                log_detail="retry budget exhausted",
                indeterminate=True,
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        decided = await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert decided["status"] == "applying"
        assert decided["apply_error"] == _APPLY_ERROR_INDETERMINATE_MESSAGE

        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "applying"
        assert row.apply_error == _APPLY_ERROR_INDETERMINATE_MESSAGE
        assert row.applied_at is None
        assert row.apply_result is None

        # Check audit log recorded proposal.apply_indeterminate
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.apply_indeterminate",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "retry budget exhausted" in audit_row.detail["error"]

        # Resubmit with the same target key
        resubmitted = await _submit(session, judge=judge)
        assert resubmitted["proposal_id"] == str(hold_id)
        assert resubmitted["status"] == "applying"

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
        submitted = await _submit(
            session,
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match")
            ),
        )
        hold_id = uuid.UUID(submitted["proposal_id"])
        judge = FakeProposalJudge(
            fingerprint_raises=asyncio.CancelledError("watchdog: 30s timeout")
        )
        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
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
        submitted = await _submit(
            session,
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match")
            ),
        )
        hold_id = uuid.UUID(submitted["proposal_id"])

        class _MutateThenCancelJudge(FakeProposalJudge):
            async def fingerprint(self, ctx: Any) -> ProposalFingerprint:
                self.fingerprint_calls.append(ctx)
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

        judge = _MutateThenCancelJudge()
        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert judge.apply_calls == []
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
        caller can no longer reach apply() for the SAME hold -- but if
        something outside this call's own claim still manages to change
        the hold's status during the ~10s external round-trip (simulated
        here via the fingerprint call's side effect), this call must
        raise 409, not silently return the concurrent state as its own
        200 (S4): this call never got to decide anything."""
        submitted = await _submit(
            session,
            judge=FakeProposalJudge(
                fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match")
            ),
        )
        hold_id = uuid.UUID(submitted["proposal_id"])

        class _MutateThenFingerprintJudge(FakeProposalJudge):
            async def fingerprint(self, ctx: Any) -> ProposalFingerprint:
                self.fingerprint_calls.append(ctx)
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
                return ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match")

        judge = _MutateThenFingerprintJudge(
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            )
        )
        with pytest.raises(HoldAlreadyDecidedError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert exc_info.value.status == "rejected"
        assert len(judge.apply_calls) == 1

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
        submitted = await _submit(session)
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

        judge = FakeProposalJudge()
        with pytest.raises(HoldAlreadyDecidedError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)
        assert exc_info.value.status == "applying"
        assert judge.apply_calls == []


class TestTerminalCommitFailureRecovery:
    """Argus review round-9 B1/B2/S1/S2: the terminal-commit failure
    recovery block in ``_apply_or_finalize_proposal_hold`` had zero test
    coverage despite claims elsewhere that the stranded-row scenario
    couldn't happen. Simulates a DB-level failure on exactly the terminal
    commit (the 3rd ``session.commit()`` of a normal approve call -- see
    the commit sequence below) via a monkeypatched ``session.commit``,
    never by faking anything about the judge/plugin seam itself.

    Commit sequence in ``decide_proposal`` -> ``_apply_or_finalize_proposal_hold``:
    - Call 1: ``_claim_proposal_hold_for_applying`` (service.py ~line 7162) --
      claims ``status="applying"`` under row lock and commits.
    - Call 2: ``_apply_or_finalize_proposal_hold`` (service.py ~line 7491) --
      releases read connection before external fingerprint/apply I/O.
    - Call 3: ``_apply_or_finalize_proposal_hold`` (service.py ~line 7658) --
      terminal commit attempting to persist final status (injected failure point).
    - Call 4: ``_apply_or_finalize_proposal_hold`` (service.py ~line 7718) --
      recovery commit attempting to persist genuine terminal state after rollback.
    - Call 5: ``_apply_or_finalize_proposal_hold`` (service.py ~line 7742) --
      last-ditch commit retrying the SAME genuine terminal state again (or a
      minimal ``apply_failed`` write, if that state was already ``apply_failed``)
      if the recovery commit also fails.
    """

    @staticmethod
    def _fail_nth_commit(session: AsyncSession, fail_at: int, *exceptions: Exception) -> AsyncMock:
        """Build a ``session.commit`` replacement that raises
        ``exceptions[0]`` on the ``fail_at``-th call, ``exceptions[1]`` on
        the ``(fail_at + 1)``-th call (if provided), and so on past the
        end of ``exceptions`` -- every other call delegates to the real
        ``session.commit``."""
        real_commit = session.commit
        call_count = {"n": 0}

        async def _commit() -> None:
            call_count["n"] += 1
            index = call_count["n"] - fail_at
            if 0 <= index < len(exceptions):
                raise exceptions[index]
            await real_commit()

        return AsyncMock(side_effect=_commit)

    async def test_recovery_after_commit_failure_recovers_to_applied_with_result_intact(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A post-apply terminal commit failure must recover to
        ``"applied"`` with ``apply_result`` intact, NOT ``"apply_failed"``
        (fix (a)) -- the external write already happened; discarding that
        and reporting failure would cause a retrying caller to duplicate
        it."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=True, result={"ticket": "TECH-1"}, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("db down"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        decided = await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 4
        assert decided["status"] == "applied"
        assert decided["apply_result"] == {"ticket": "TECH-1"}
        assert "apply_error" not in decided
        assert len(judge.apply_calls) == 1
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.applied",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert audit_row is not None
        assert "error" not in audit_row.detail

    async def test_recovery_after_commit_failure_recovers_to_stale(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A post-stale terminal commit failure must recover to
        ``"stale"`` with the honest ``_stale_decision_note`` text, not
        ``"apply_failed"`` (fix (a))."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-original"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-drifted"
        )
        hold_id = uuid.UUID(submitted["proposal_id"])
        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("db down"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        decided = await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 4
        assert decided["status"] == "stale"
        assert decided["decision_note"] == (
            "not applied: target changed after approval; no write to the target was performed"
        )
        assert "apply_error" not in decided
        assert judge.apply_calls == []
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.stale",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert audit_row is not None
        assert "error" not in audit_row.detail

    async def test_recovery_after_commit_failure_recovers_to_apply_failed(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A post-apply_failed terminal commit failure must recover to
        ``"apply_failed"`` with the GENUINE plugin ``caller_error``
        preserved, not the board-owned commit-failure message (fix (a) +
        the "preserve existing apply_error" half of fix S1)."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="Linear API returned an error",
                log_detail="linear is down",
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("db down"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        decided = await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 4
        assert decided["status"] == "apply_failed"
        assert decided["apply_error"] == "Linear API returned an error"
        assert decided["apply_error"] != _APPLY_ERROR_BOARD_COMMIT_FAILURE_MESSAGE
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
        assert audit_row is not None
        assert audit_row.detail.get("error") == "linear is down"

    async def test_recovery_reraises_cancellation_instead_of_returning_normally(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fix (b): every OTHER return path in this function re-raises a
        ``cancelled_exc`` caught earlier before returning -- this recovery
        path must too, instead of silently swallowing it and returning a
        normal result as if nothing happened."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        judge.fingerprint_raises = asyncio.CancelledError()
        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("db down"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 4
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "apply_failed"
        assert row.apply_error == _APPLY_ERROR_CANCELLED_MESSAGE

    async def test_last_ditch_reraises_cancellation_after_two_commit_failures(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Finding 5: cancellation during fingerprint, COMBINED with both the
        terminal commit AND the recovery commit failing (reaching the
        last-ditch write), must still re-raise the cancellation -- not
        just when the recovery commit alone fails (the sibling test
        above)."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        judge.fingerprint_raises = asyncio.CancelledError()
        commit_mock = self._fail_nth_commit(
            session,
            3,
            OperationalError("first", {}, Exception("terminal commit failed")),
            OperationalError("second", {}, Exception("recovery commit also failed")),
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 5
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        # A cancellation sets apply_error/terminal_status="apply_failed"
        # BEFORE any commit is even attempted -- so the last-ditch write
        # here takes the minimal-fallback branch (fix 2's other case),
        # same as the non-cancelled apply_failed scenario above.
        assert row.status == "apply_failed"
        assert row.apply_error == _APPLY_ERROR_BOARD_COMMIT_FAILURE_MESSAGE

    async def test_recovery_fallthrough_on_concurrent_resolution_reraises_cancellation(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Finding 1: if fingerprint was cancelled, terminal commit fails, AND
        recovery_hold is concurrently resolved (recovery_hold.status != expected_status),
        the fallthrough must re-raise cancelled_exc instead of commit_exc."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        judge.fingerprint_raises = asyncio.CancelledError()

        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("terminal commit failed"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        real_find = service._find_proposal_hold
        find_for_update_calls = 0

        async def _find_hook(sess: Any, hid: Any, for_update: bool = False) -> Any:
            nonlocal find_for_update_calls
            h = await real_find(sess, hid, for_update=for_update)
            if for_update and h is not None:
                find_for_update_calls += 1
                if find_for_update_calls == 3:
                    # 3rd for_update find is the recovery find; simulate concurrent resolution
                    h.status = "rejected"
            return h

        monkeypatch.setattr(service, "_find_proposal_hold", _find_hook)

        with pytest.raises(asyncio.CancelledError):
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 3
        assert find_for_update_calls == 3

    async def test_recovery_fallthrough_on_concurrent_resolution_raises_commit_exc(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When not cancelled, recovery fallthrough on concurrent resolution raises commit_exc."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])

        first_exc = OperationalError("boom", {}, Exception("terminal commit failed"))
        commit_mock = self._fail_nth_commit(session, 3, first_exc)
        monkeypatch.setattr(session, "commit", commit_mock)

        real_find = service._find_proposal_hold
        find_for_update_calls = 0

        async def _find_hook(sess: Any, hid: Any, for_update: bool = False) -> Any:
            nonlocal find_for_update_calls
            h = await real_find(sess, hid, for_update=for_update)
            if for_update and h is not None:
                find_for_update_calls += 1
                if find_for_update_calls == 3:
                    h.status = "rejected"
            return h

        monkeypatch.setattr(service, "_find_proposal_hold", _find_hook)

        with pytest.raises(OperationalError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert exc_info.value is first_exc
        assert commit_mock.call_count == 3
        assert find_for_update_calls == 3

    async def test_indeterminate_commit_failure_with_cancellation_reraises(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BLOCKING #3 (A): apply cancellation + commit failure must re-raise
        cancelled_exc from commit_exc."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_raises=asyncio.CancelledError(),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("db down"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(asyncio.CancelledError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert isinstance(exc_info.value.__cause__, OperationalError)
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "applying"

    async def test_indeterminate_commit_failure_without_cancellation_returns_none(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BLOCKING #3 (B): indeterminate outcome + commit failure (no cancellation)
        must return None and leave row at status='applying'."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="retry budget exhausted",
                log_detail="detail",
                indeterminate=True,
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        commit_mock = self._fail_nth_commit(
            session, 3, OperationalError("boom", {}, Exception("db down"))
        )
        monkeypatch.setattr(session, "commit", commit_mock)

        claimed = await service._claim_proposal_hold_for_applying(
            session,
            hold_id=hold_id,
            decided_by_actor_id="user-1",
            decision_source="human",
            decision_note=None,
            expected_payload=None,
        )
        assert claimed is True

        result = await service._apply_or_finalize_proposal_hold(
            session,
            hold_id=hold_id,
            expected_status="applying",
            decided_by_actor_id="user-1",
            decision_source="human",
            decision_note=None,
            judge=judge,
        )
        assert result is None
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "applying"

    async def test_recovery_commit_also_failing_preserves_original_exception_context(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fix S2 / Finding 2 / Finding 12 / Argus review round-4 B2: if the
        RECOVERY commit itself also fails, the last-ditch commit must retry
        the SAME genuine terminal state ("applied" here, with apply_result
        intact) rather than downgrading it to a false apply_failed --
        silently discarding a real successful external write and reporting
        failure would let a retrying caller duplicate that write (the
        dedup check does not block resubmission against an apply_failed
        row). The original (terminal) commit exception still propagates,
        with the secondary exception explicitly chained via __cause__ and
        __context__."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=True, result={"ticket": "TECH-1"}, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        first_exc = OperationalError("first", {}, Exception("terminal commit failed"))
        second_exc = OperationalError("second", {}, Exception("recovery commit also failed"))
        commit_mock = self._fail_nth_commit(session, 3, first_exc, second_exc)
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(OperationalError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 5
        assert exc_info.value is first_exc
        assert first_exc.__cause__ is second_exc
        assert first_exc.__context__ is second_exc
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "applied"
        assert row.apply_result == {"ticket": "TECH-1"}
        assert row.apply_error is None
        assert row.applied_at is not None
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.applied",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "error" not in audit_row.detail

    async def test_last_ditch_write_preserves_stale(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fix 2 (BLOCKING): the last-ditch write must retry "stale" (with
        the honest ``_stale_decision_note`` text) too, not just "applied"
        -- a "stale" outcome is just as much a real, already-computed
        terminal state as "applied" is, and downgrading it to a false
        apply_failed would be equally misleading."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-original"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-drifted"
        )
        hold_id = uuid.UUID(submitted["proposal_id"])
        first_exc = OperationalError("first", {}, Exception("terminal commit failed"))
        second_exc = OperationalError("second", {}, Exception("recovery commit also failed"))
        commit_mock = self._fail_nth_commit(session, 3, first_exc, second_exc)
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(OperationalError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 5
        assert exc_info.value is first_exc
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "stale"
        assert row.decision_note == (
            "not applied: target changed after approval; no write to the target was performed"
        )
        assert judge.apply_calls == []
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.stale",
                        AuditLog.detail["hold_id"].astext == str(hold_id),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert "error" not in audit_row.detail

    async def test_last_ditch_write_uses_minimal_fallback_only_for_apply_failed(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fix 2 (BLOCKING): when the ALREADY-computed terminal state was
        itself ``apply_failed`` (no successful external write to
        protect), the last-ditch write correctly falls back to the
        minimal board-owned ``_APPLY_ERROR_BOARD_COMMIT_FAILURE_MESSAGE``
        -- this is the one case where that minimal write remains
        correct."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="Linear API returned an error",
                log_detail="linear is down",
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        first_exc = OperationalError("first", {}, Exception("terminal commit failed"))
        second_exc = OperationalError("second", {}, Exception("recovery commit also failed"))
        commit_mock = self._fail_nth_commit(session, 3, first_exc, second_exc)
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(OperationalError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 5
        assert exc_info.value is first_exc
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "apply_failed"
        assert row.apply_error == _APPLY_ERROR_BOARD_COMMIT_FAILURE_MESSAGE

    async def test_recovery_commit_and_last_ditch_both_failing_strands_row(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Finding 2 option (a) residual gap: if terminal commit, recovery commit,
        AND last-ditch commit all fail (3 consecutive DB failures), the row remains
        stranded at applying and commit_exc from recovery_exc is raised."""
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-match"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        submitted = await _submit(session, judge=judge)
        hold_id = uuid.UUID(submitted["proposal_id"])
        first_exc = OperationalError("first", {}, Exception("terminal commit failed"))
        second_exc = OperationalError("second", {}, Exception("recovery commit also failed"))
        third_exc = OperationalError("third", {}, Exception("last-ditch commit also failed"))
        commit_mock = self._fail_nth_commit(session, 3, first_exc, second_exc, third_exc)
        monkeypatch.setattr(session, "commit", commit_mock)

        with pytest.raises(OperationalError) as exc_info:
            await _decide(session, hold_id=hold_id, decision="approve", judge=judge)

        assert commit_mock.call_count == 5
        assert exc_info.value is first_exc
        assert first_exc.__cause__ is second_exc
        row = (
            await session.execute(select(ProposalHold).where(ProposalHold.id == hold_id))
        ).scalar_one()
        assert row.status == "applying"


class TestProposalJudgeSeamValidation:
    """Board-side seam validation this module is well-placed to exercise
    end-to-end against a real Postgres row (the seam's own isolated
    fail-closed/contract-violation coverage, with no DB at all, lives in
    ``tests/test_proposal_judge_seam.py``): a plugin-returned ``priority``
    outside ``PROPOSAL_HOLD_LEVELS`` is rejected at the seam
    rather than reaching the ``ck_proposal_holds_priority`` CHECK; a
    plugin-supplied ``caller_error`` is exactly what surfaces over the API;
    and a plugin's ``log_detail`` never surfaces over the API but does land
    in the audit row."""

    async def test_priority_outside_hold_levels_raises_value_error(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(classify_result=ProposalClassification(priority="urgent!!"))
        with pytest.raises(ValueError, match="invalid priority"):
            await _submit(session, judge=judge)

    async def test_caller_error_is_what_surfaces_over_the_api(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="a small, allowlisted, caller-safe message",
                log_detail="the raw upstream detail, credentials and all",
            ),
        )
        result = await _submit(session, judge=judge)
        assert result["apply_error"] == "a small, allowlisted, caller-safe message"
        assert "log_detail" not in result
        assert "raw upstream detail" not in str(result)

    async def test_log_detail_lands_in_the_audit_row_only(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="a small, allowlisted, caller-safe message",
                log_detail="the raw upstream detail, credentials and all",
            ),
        )
        result = await _submit(session, judge=judge)
        audit_row = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "proposal.apply_failed",
                        AuditLog.detail["hold_id"].astext == result["proposal_id"],
                    )
                )
            )
            .scalars()
            .one()
        )
        assert audit_row.detail["error"] == "the raw upstream detail, credentials and all"

    async def test_non_json_serializable_apply_result_resolves_cleanly_to_apply_failed(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=True,
                result={"invalid_set": {1, 2, 3}},
                caller_error=None,
                log_detail=None,
            ),
        )
        result = await _submit(session, judge=judge)
        assert result["status"] == "apply_failed"
        assert result["apply_error"] == "unable to apply this proposal"

        # Verify hold in DB is not stranded at 'applying'
        hold = await session.get(ProposalHold, uuid.UUID(result["proposal_id"]))
        assert hold is not None
        assert hold.status == "apply_failed"
        assert hold.apply_error == "unable to apply this proposal"

    async def test_overlong_decision_note_is_truncated(self, session: AsyncSession) -> None:
        overlong_note = "n" * 2500
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note=overlong_note),
            apply_result=ProposalApplyOutcome(
                applied=True, result={"ok": True}, caller_error=None, log_detail=None
            ),
        )
        result = await _submit(session, judge=judge)
        assert len(result["decision_note"]) == 2000
        assert result["decision_note"].endswith("... [truncated]")
        assert result["decision_note"].startswith("n" * 100)

    async def test_overlong_caller_error_is_truncated(self, session: AsyncSession) -> None:
        overlong_error = "e" * 600
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approved"),
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error=overlong_error,
                log_detail="raw",
            ),
        )
        result = await _submit(session, judge=judge)
        assert result["status"] == "apply_failed"
        assert len(result["apply_error"]) == 500
        assert result["apply_error"].endswith("... [truncated]")
        assert result["apply_error"].startswith("e" * 100)

    async def test_legitimate_decision_note_starting_with_judge_error_does_not_trigger_error_branch(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(
                approved=False,
                decision_note="judge error: legitimate business reason to hold for human",
            )
        )
        result = await _submit(session, judge=judge)
        assert result["status"] == "pending"
        # Since this was a normal plugin-supplied verdict and not an internal judge error,
        # the error-branch pre-return commit did not fire and no error note was persisted.
        assert "decision_note" not in result
        hold = await session.get(ProposalHold, uuid.UUID(result["proposal_id"]))
        assert hold is not None
        assert hold.decision_note is None


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
        await _decide(
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
        # Argus review suggestion: the human reviewer's own identity must
        # not be disclosed to the submitting bot.
        assert "decided_by_actor_id" not in result

    async def test_submitting_bot_can_read_own_bot_withdrawn_proposal(
        self, session: AsyncSession
    ) -> None:
        """Redaction is conditioned on ``decision_source == "human"``, not
        blanket -- a proposal the SUBMITTING BOT itself withdrew has
        ``decided_by_actor_id`` set to that same bot's own sub, which is
        not a privacy leak (it's just telling the bot its own action was
        recorded), so it must stay present (Argus review round-2)."""
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        await withdraw_proposal(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
            reason=None,
        )
        result = await get_proposal_for_bot(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
        )
        assert result["status"] == "withdrawn"
        assert result["decided_by_actor_id"] == "bot-1"

    async def test_unknown_hold_denial_is_audited(self, session: AsyncSession) -> None:
        with pytest.raises(AccessDeniedError):
            await get_proposal_for_bot(session, hold_id=uuid.uuid4(), requesting_bot_sub="bot-1")
        rows = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == "denied.unknown_proposal_hold")
                )
            )
            .scalars()
            .all()
        )
        assert rows

    async def test_different_bot_denial_is_audited(self, session: AsyncSession) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        with pytest.raises(AccessDeniedError):
            await get_proposal_for_bot(
                session,
                hold_id=uuid.UUID(submitted["proposal_id"]),
                requesting_bot_sub="bot-2",
            )
        rows = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == "denied.proposal_hold_not_submitter")
                )
            )
            .scalars()
            .all()
        )
        assert rows


class TestWithdrawProposal:
    """Service-layer coverage for ``withdraw_proposal`` (TECH-6018):
    sender-only retraction of a proposal the submitting bot has since
    determined is stale or wrong, before a human can decide it -- NOT for
    unlocking a same-key resubmission, which the create-time dedup already
    handles by updating the existing pending row in place (see
    ``withdraw_proposal``'s own docstring)."""

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
        await _decide(
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
        """A withdrawn row does not block or get silently updated by a
        later same-key submission -- verifies the create-time dedup
        partial index excludes ``'withdrawn'`` rows, so a fresh submission
        for the same ``(kind, bot, target_id, action_type)`` key becomes a
        genuinely new pending row rather than colliding with the retired
        one. (NOT withdraw's purpose, which is retracting a proposal the
        bot now considers stale/wrong before a human decides it -- see
        ``TestWithdrawProposal``'s own class docstring.)"""
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

    async def test_withdraw_applying_hold_raises_already_decided(
        self, session: AsyncSession
    ) -> None:
        """The highest-risk case the FOR UPDATE lock exists to protect:
        a hold already CLAIMED (mid-flight on the auto-judge's or a
        concurrent decide's own external Linear round-trip) must not be
        withdrawn out from under it."""
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        hold = await session.get(ProposalHold, uuid.UUID(submitted["proposal_id"]))
        assert hold is not None
        hold.status = "applying"
        hold.decided_at = hold.created_at
        hold.decided_by_actor_id = "owner-a@example.com"
        hold.decision_source = "human"
        await session.commit()

        with pytest.raises(HoldAlreadyDecidedError):
            await withdraw_proposal(
                session,
                hold_id=uuid.UUID(submitted["proposal_id"]),
                requesting_bot_sub="bot-1",
                reason=None,
            )

    async def test_withdraw_is_audited(self, session: AsyncSession) -> None:
        submitted = await _submit(session, proposed_by_bot_id="bot-1")
        await withdraw_proposal(
            session,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            requesting_bot_sub="bot-1",
            reason="stale",
        )
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "proposal.withdraw")))
            .scalars()
            .all()
        )
        assert rows


class TestAuditDeniedProposalSubmission:
    """Direct, service-level coverage of ``audit_denied_proposal_submission``'s
    ``surface`` parameter (Argus review round-2 suggestion) -- the HTTP-level
    tests in ``test_proposal_endpoint.py`` cover this indirectly through
    ``main._authenticate_proposal_submitter``, but a typo in the ``surface``
    literal at either of THOSE call sites could still slip past a test that
    only checks "some denial row exists" rather than pinning the exact
    formatted action string this function produces for each surface."""

    @pytest.mark.parametrize("surface", sorted(PROPOSAL_SUBMITTER_SURFACES))
    async def test_missing_scope_action_string(self, session: AsyncSession, surface: str) -> None:
        await audit_denied_proposal_submission(
            session, actor_sub="bot-1", reason="missing_scope", surface=surface
        )
        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == f"denied.proposal_{surface}_missing_scope"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

    @pytest.mark.parametrize("surface", sorted(PROPOSAL_SUBMITTER_SURFACES))
    async def test_not_agent_token_action_string(self, session: AsyncSession, surface: str) -> None:
        await audit_denied_proposal_submission(
            session, actor_sub="bot-1", reason="not_agent_token", surface=surface
        )
        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == f"denied.proposal_{surface}_not_agent_token"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

    def test_default_surface_is_submit(self) -> None:
        """Backward-compatibility guarantee: pre-existing callers that
        don't pass ``surface`` at all must still produce
        ``denied.proposal_submit_*``, unchanged."""
        import inspect

        assert (
            inspect.signature(audit_denied_proposal_submission).parameters["surface"].default
            == "submit"
        )


class TestListProposalsForBot:
    """Direct unit coverage for ``list_proposals_for_bot`` (TECH-6018
    follow-up, Argus review round-1 suggestion) -- previously only
    exercised indirectly through the Postgres-dependent MCP tool tests in
    ``tests/test_proposal_tools.py``, which skip when Postgres is
    unreachable. This file already requires Postgres for every other test
    (module-scoped Alembic chain), so this coverage isn't redundant with
    that skip -- it's the same real-database idiom, just without a live
    MCP client in the loop."""

    async def test_scoped_to_requesting_bot_only(self, session: AsyncSession) -> None:
        await _submit(session, proposed_by_bot_id="bot-a", action=_action(target_id="A"))
        await _submit(session, proposed_by_bot_id="bot-b", action=_action(target_id="B"))

        result = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-a", statuses=("pending",)
        )
        subs = {p["proposed_by_bot_id"] for p in result["proposals"]}
        assert subs == {"bot-a"}

    async def test_status_filter_applied(self, session: AsyncSession) -> None:
        pending = await _submit(session, proposed_by_bot_id="bot-1", action=_action(target_id="C"))
        withdrawn = await _submit(
            session, proposed_by_bot_id="bot-1", action=_action(target_id="D")
        )
        await withdraw_proposal(
            session,
            hold_id=uuid.UUID(withdrawn["proposal_id"]),
            requesting_bot_sub="bot-1",
            reason=None,
        )

        pending_only = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-1", statuses=("pending",)
        )
        assert {p["proposal_id"] for p in pending_only["proposals"]} == {pending["proposal_id"]}

        terminal_only = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-1", statuses=PROPOSAL_TERMINAL_STATUSES
        )
        assert {p["proposal_id"] for p in terminal_only["proposals"]} == {withdrawn["proposal_id"]}

    async def test_limit_clamped_to_minimum_of_one(self, session: AsyncSession) -> None:
        await _submit(session, proposed_by_bot_id="bot-1", action=_action(target_id="E"))
        await _submit(session, proposed_by_bot_id="bot-1", action=_action(target_id="F"))

        result = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-1", statuses=("pending",), limit=0
        )
        assert len(result["proposals"]) == 1

    async def test_limit_clamped_to_maximum_of_200(self, session: AsyncSession) -> None:
        await _submit(session, proposed_by_bot_id="bot-1", action=_action(target_id="G"))

        result = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-1", statuses=("pending",), limit=500
        )
        assert result["has_more"] is False
        assert len(result["proposals"]) == 1

    async def test_has_more_true_when_more_rows_exist(self, session: AsyncSession) -> None:
        for i in range(3):
            await _submit(
                session, proposed_by_bot_id="bot-1", action=_action(target_id=f"PAGE-{i}")
            )

        result = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-1", statuses=("pending",), limit=2
        )
        assert len(result["proposals"]) == 2
        assert result["has_more"] is True

    async def test_has_more_false_when_exactly_at_limit(self, session: AsyncSession) -> None:
        for i in range(2):
            await _submit(
                session, proposed_by_bot_id="bot-1", action=_action(target_id=f"EXACT-{i}")
            )

        result = await list_proposals_for_bot(
            session, requesting_bot_sub="bot-1", statuses=("pending",), limit=2
        )
        assert len(result["proposals"]) == 2
        assert result["has_more"] is False

    async def test_terminal_statuses_pinned_against_hold_statuses(self) -> None:
        from models import PROPOSAL_HOLD_STATUSES

        assert set(PROPOSAL_TERMINAL_STATUSES) | {"pending", "applying", "approved"} == set(
            PROPOSAL_HOLD_STATUSES
        )
