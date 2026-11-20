"""TECH-9214: board side of the ``catalog_candidate`` proposal kind.

* Never auto-approved, whatever the judge plugin returns.
* An open row is never edited in place by a resubmission.
* The proposal owner cannot decide it (an external reviewer does), and it stays
  out of the owner's pending queue.
* ``action`` is capped at 256 KiB, not the 16 KiB default.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import service
from exceptions import ProposalDecisionValidationError, ProposalImmutableError
from models import ProposalHold
from plugins import ProposalVerdict
from tests.proposal_judge_fakes import FakeProposalJudge

pytestmark = pytest.mark.usefixtures("_migrated_schema")

_OWNER = "owner-a@example.com"
_BOT = "paperclip-agent-1"
_KIND = "catalog_candidate"
_ACTION: dict[str, Any] = {
    "target_id": "concept:remote-patient-monitoring",
    "action_type": "create",
    "payload": {"slug": "remote-patient-monitoring", "name": "Remote patient monitoring"},
}


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE proposal_holds, proposal_bot_log_seq, audit_log, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


async def _submit(
    session: AsyncSession,
    *,
    kind: str = _KIND,
    action: dict[str, Any] | None = None,
    rationale: str = "add the concept",
    judge: FakeProposalJudge | None = None,
) -> dict[str, Any]:
    return await service.create_proposal(
        session,
        kind=kind,
        proposed_by_bot_id=_BOT,
        owner_sub=_OWNER,
        action=action if action is not None else dict(_ACTION),
        rationale=rationale,
        confidence="medium",
        importance="medium",
        impact="medium",
        judge=judge if judge is not None else FakeProposalJudge(),
        target_fingerprint="ignored",
    )


async def _rows(session: AsyncSession) -> list[ProposalHold]:
    session.expire_all()
    return list(
        (await session.execute(select(ProposalHold).order_by(ProposalHold.created_at)))
        .scalars()
        .all()
    )


class TestNeverAutoApproved:
    async def test_approving_verdict_on_first_submission_stays_pending(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(judge_result=ProposalVerdict(approved=True, decision_note=None))
        result = await _submit(session, judge=judge)
        assert result["status"] == "pending"
        assert judge.apply_calls == []
        rows = await _rows(session)
        assert [r.status for r in rows] == ["pending"]
        assert rows[0].decided_at is None

    async def test_approving_verdict_on_identical_retry_stays_pending(
        self, session: AsyncSession
    ) -> None:
        first = await _submit(session)
        judge = FakeProposalJudge(judge_result=ProposalVerdict(approved=True, decision_note=None))
        second = await _submit(session, judge=judge)
        assert second["proposal_id"] == first["proposal_id"]
        assert second["status"] == "pending"
        assert judge.apply_calls == []

    async def test_a_rule_named_by_the_judge_does_not_help(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note=None, rule="any_rule")
        )
        result = await _submit(session, judge=judge)
        assert result["status"] == "pending"
        assert judge.apply_calls == []

    def test_kind_is_registered_in_the_board_sets(self) -> None:
        assert _KIND in service.HUMAN_APPROVAL_ONLY_PROPOSAL_KINDS
        assert _KIND in service.IMMUTABLE_PROPOSAL_KINDS
        assert _KIND in service.EXTERNALLY_RESOLVED_PROPOSAL_KINDS


class TestImmutable:
    async def test_identical_resubmission_returns_the_same_row(self, session: AsyncSession) -> None:
        first = await _submit(session)
        second = await _submit(session)
        assert second["proposal_id"] == first["proposal_id"]
        assert len(await _rows(session)) == 1

    async def test_changed_resubmission_is_refused(self, session: AsyncSession) -> None:
        await _submit(session)
        changed = {**_ACTION, "payload": {"slug": "remote-patient-monitoring", "name": "Changed"}}
        with pytest.raises(ProposalImmutableError):
            await _submit(session, action=changed)
        assert (await _rows(session))[0].action == _ACTION


class TestOwnerCannotDecide:
    @pytest.mark.parametrize("decision", ["approve", "reject"])
    async def test_owner_decide_is_refused_and_nothing_changes(
        self, session: AsyncSession, decision: str
    ) -> None:
        created = await _submit(session)
        judge = FakeProposalJudge()
        with pytest.raises(ProposalDecisionValidationError):
            await service.decide_proposal(
                session,
                approver_sub=_OWNER,
                hold_id=uuid.UUID(created["proposal_id"]),
                decision=decision,
                decision_note="no" if decision == "reject" else None,
                judge=judge,
            )
        rows = await _rows(session)
        assert [r.status for r in rows] == ["pending"]
        assert judge.apply_calls == []

    async def test_catalog_candidates_are_left_out_of_the_owner_queue(
        self, session: AsyncSession
    ) -> None:
        await _submit(session)
        other = await _submit(
            session,
            kind="linear_progress_update",
            action={"action_type": "label_ticket", "target_id": "TECH-1"},
            judge=FakeProposalJudge(
                judge_result=ProposalVerdict(approved=False, decision_note=None)
            ),
        )
        pending = await service.list_pending_proposal_holds(session, owner_sub=_OWNER)
        assert [p["proposal_id"] for p in pending["proposals"]] == [other["proposal_id"]]


class TestActionCap:
    def test_catalog_candidate_cap_is_256_kib(self) -> None:
        assert service.max_proposal_action_bytes(_KIND) == 256 * 1024
        assert service.max_proposal_action_bytes("gmail_send") == 16_384
        assert _KIND not in service.DOCUMENT_PROPOSAL_KINDS
