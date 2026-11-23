"""BLU-18: board side of the ``site_catalog_match`` proposal kind.

* Never auto-approved, whatever the judge plugin returns; never decided by the owner.
* An open row is never edited in place by a resubmission.
* ``action`` is capped at 64 KiB, not the 16 KiB default.
* Resolved externally: ``applied`` and ``rejected`` work, ``already_decided`` is final.
* Arcadia's refusal is relayed, and the kind is served on the external queue.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import service
from exceptions import (
    ExternalResolutionError,
    ProposalDecisionValidationError,
    ProposalImmutableError,
)
from models import ProposalHold
from plugins import ProposalVerdict
from providers import proposal_schemas
from tests.proposal_judge_fakes import FakeProposalJudge

pytestmark = pytest.mark.usefixtures("_migrated_schema")

_OWNER = "owner-a@example.com"
_BOT = "site-agent-1"
_RESOLVER = "arcadia-service"
_FORWARDER = "agent-comms-approvals"
_KIND = "site_catalog_match"
_ACTION: dict[str, Any] = proposal_schemas.schema_for_kind(_KIND)["examples"]["rank"]  # type: ignore[index]


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
    judge: FakeProposalJudge | None = None,
    bot: str = _BOT,
) -> dict[str, Any]:
    return await service.create_proposal(
        session,
        kind=kind,
        proposed_by_bot_id=bot,
        owner_sub=_OWNER,
        action=action if action is not None else copy.deepcopy(_ACTION),
        rationale="a catalog match for the site",
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


def _with_seq(seq: int) -> dict[str, Any]:
    action = copy.deepcopy(_ACTION)
    action["target_id"] = action["target_id"].rsplit(":r", 1)[0] + f":r{seq}"
    return action


class TestNeverAutoApproved:
    def test_kind_is_registered_in_the_board_sets(self) -> None:
        assert _KIND in service.HUMAN_APPROVAL_ONLY_PROPOSAL_KINDS
        assert _KIND in service.IMMUTABLE_PROPOSAL_KINDS
        assert _KIND in service.EXTERNALLY_RESOLVED_PROPOSAL_KINDS

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
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note=None, rule="any_rule")
        )
        second = await _submit(session, judge=judge)
        assert second["proposal_id"] == first["proposal_id"]
        assert second["status"] == "pending"
        assert judge.apply_calls == []

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
        assert [r.status for r in await _rows(session)] == ["pending"]
        assert judge.apply_calls == []

    async def test_left_out_of_the_owner_queue(self, session: AsyncSession) -> None:
        await _submit(session)
        other = await _submit(
            session,
            kind="linear_progress_update",
            action={"action_type": "label_ticket", "target_id": "TECH-1"},
        )
        pending = await service.list_pending_proposal_holds(session, owner_sub=_OWNER)
        assert [p["proposal_id"] for p in pending["proposals"]] == [other["proposal_id"]]


class TestImmutable:
    async def test_identical_resubmission_returns_the_same_row(self, session: AsyncSession) -> None:
        first = await _submit(session)
        second = await _submit(session)
        assert second["proposal_id"] == first["proposal_id"]
        assert len(await _rows(session)) == 1

    async def test_changed_resubmission_is_refused(self, session: AsyncSession) -> None:
        await _submit(session)
        changed = copy.deepcopy(_ACTION)
        changed["payload"]["agent_score"] = 12
        with pytest.raises(ProposalImmutableError):
            await _submit(session, action=changed)
        assert (await _rows(session))[0].action == _ACTION

    async def test_a_new_request_sequence_is_a_separate_proposal(
        self, session: AsyncSession
    ) -> None:
        first = await _submit(session, action=_with_seq(3))
        second = await _submit(session, action=_with_seq(4))
        assert second["proposal_id"] != first["proposal_id"]
        assert [r.status for r in await _rows(session)] == ["pending", "pending"]


class TestActionCap:
    def test_cap_is_64_kib(self) -> None:
        assert service.MAX_SITE_CATALOG_MATCH_ACTION_BYTES == 64 * 1024
        assert service.max_proposal_action_bytes(_KIND) == 64 * 1024
        assert service.max_proposal_action_bytes("gmail_send") == 16_384
        assert service.max_proposal_action_bytes("catalog_candidate") == 256 * 1024
        assert _KIND not in service.DOCUMENT_PROPOSAL_KINDS

    def test_the_example_is_far_below_the_cap(self) -> None:
        assert service.proposal_action_serialized_bytes(_ACTION) < 8 * 1024


class TestExternalResolution:
    async def _resolve(
        self, session: AsyncSession, pid: str, outcome: str, note: str | None
    ) -> dict[str, Any]:
        return await service.resolve_external_proposal(
            session,
            resolver_sub=_RESOLVER,
            hold_id=uuid.UUID(pid),
            outcome=outcome,
            note=note,
            external_ref="match-17",
        )

    async def test_applied_with_an_empty_note(self, session: AsyncSession) -> None:
        pid = str((await _submit(session))["proposal_id"])
        result = await self._resolve(session, pid, "applied", None)
        assert result["status"] == "applied"
        hold = (await _rows(session))[0]
        assert (hold.status, hold.decision_source) == ("applied", "external")
        assert hold.external_ref == "match-17"

    async def test_rejected_needs_a_note_and_keeps_it(self, session: AsyncSession) -> None:
        pid = str((await _submit(session))["proposal_id"])
        with pytest.raises(ExternalResolutionError):
            await self._resolve(session, pid, "rejected", None)
        await self._resolve(session, pid, "rejected", "not_a_priority: later")
        hold = (await _rows(session))[0]
        assert (hold.status, hold.decision_note) == ("rejected", "not_a_priority: later")

    async def test_already_decided_is_final(self, session: AsyncSession) -> None:
        pid = str((await _submit(session))["proposal_id"])
        await self._resolve(session, pid, "applied", None)
        with pytest.raises(ExternalResolutionError) as caught:
            await self._resolve(session, pid, "rejected", "Superseded: ranking request 4")
        assert caught.value.code == "already_decided"
        assert (await _rows(session))[0].status == "applied"

    async def test_the_agent_sees_the_outcome_not_who_decided(self, session: AsyncSession) -> None:
        pid = str((await _submit(session))["proposal_id"])
        await self._resolve(session, pid, "rejected", "Superseded: ranking request 4")
        seen = await service.get_proposal_for_bot(
            session, hold_id=uuid.UUID(pid), requesting_bot_sub=_BOT
        )
        assert seen["status"] == "rejected"
        assert seen["decision_note"] == "Superseded: ranking request 4"
        assert "decided_by_actor_id" not in seen
        assert _RESOLVER not in repr(seen)


class TestExternalQueueAndRefusal:
    async def test_pending_matches_are_on_the_external_queue(self, session: AsyncSession) -> None:
        pid = str((await _submit(session))["proposal_id"])
        listed = await service.list_external_resolution_queue(
            session, requesting_sub=_FORWARDER, kind=_KIND
        )
        assert [p["hold_id"] for p in listed["proposals"]] == [pid]
        catalog = await service.list_external_resolution_queue(
            session, requesting_sub=_FORWARDER, kind="catalog_candidate"
        )
        assert catalog["proposals"] == []

    async def test_a_refusal_closes_it_and_the_agent_reads_the_reason(
        self, session: AsyncSession
    ) -> None:
        pid = str((await _submit(session))["proposal_id"])
        errors = [{"path": "payload.need.0", "rule": "CITATION_NOT_RESOLVED", "message": "x"}]
        await service.record_forward_refusal(
            session,
            forwarder_sub=_FORWARDER,
            hold_id=uuid.UUID(pid),
            note="Arcadia refused this proposal (HTTP 422, INVALID_PAYLOAD).",
            code="INVALID_PAYLOAD",
            errors=errors,
        )
        seen = await service.get_proposal_for_bot(
            session, hold_id=uuid.UUID(pid), requesting_bot_sub=_BOT
        )
        assert seen["status"] == "rejected"
        assert seen["external_refusal"] == {"code": "INVALID_PAYLOAD", "errors": errors}
