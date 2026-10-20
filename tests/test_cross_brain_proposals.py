"""Cross-brain proposals (TECH-7665) -- real Postgres, same idiom as
``tests/test_proposal_service.py``. Covers the kill switch, target
resolution, the dedup key, the human-only multi-owner approval flow, owner
visibility, the pending caps, and bot-facing redaction.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from exceptions import (
    AccessDeniedError,
    HoldAlreadyDecidedError,
    InvalidProposalActionError,
    ProposalTargetUnavailableError,
    RateLimitExceededError,
)
from models import Agent, ProposalHold
from plugins import ProposalApplyOutcome, ProposalVerdict
from service import (
    CROSS_BRAIN_ENABLED_ENV_VAR,
    CROSS_BRAIN_MAX_PENDING_PER_SUBMITTER_ENV_VAR,
    CROSS_BRAIN_MAX_PENDING_PER_TARGET_ENV_VAR,
    _apply_or_finalize_proposal_hold,
    create_proposal,
    decide_proposal,
    get_proposal_apply_record,
    get_proposal_for_bot,
    list_pending_proposal_holds,
    list_proposal_history_for_owner,
)
from tests.proposal_judge_fakes import FakeProposalJudge

pytestmark = pytest.mark.usefixtures("_migrated_schema")

KIND = "arcana_source_add"
SUBMITTER = "paperclip-agent-sub"
SUBMITTER_OWNER = "alice@example.com"
TARGET = "paperclip-agent-target"
TARGET_OWNER = "bob@example.com"


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE TABLE proposal_holds, audit_log, agents RESTART IDENTITY CASCADE")
        )
    yield


@pytest.fixture(autouse=True)
def _flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CROSS_BRAIN_ENABLED_ENV_VAR, "true")
    monkeypatch.delenv(CROSS_BRAIN_MAX_PENDING_PER_SUBMITTER_ENV_VAR, raising=False)
    monkeypatch.delenv(CROSS_BRAIN_MAX_PENDING_PER_TARGET_ENV_VAR, raising=False)


async def _agent(session: AsyncSession, sub: str, owner: str, *, status: str = "active") -> Agent:
    agent = Agent(
        sub=sub,
        owner_sub=owner,
        owner_email=owner,
        display_name=sub,
        status=status,
        bound_at=datetime.now(UTC),
    )
    session.add(agent)
    await session.commit()
    return agent


def _action(
    ref: str | None = None,
    target_id: str = "doc-1",
    citations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    action: dict[str, Any] = {"action_type": "add_source", "target_id": target_id}
    if ref is not None:
        action["target"] = ref
    if citations is not None:
        action["citations"] = citations
    return action


def _applied_judge() -> FakeProposalJudge:
    return FakeProposalJudge(
        apply_result=ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )
    )


async def _submit(
    session: AsyncSession,
    ref: str | None,
    *,
    bot: str = SUBMITTER,
    owner: str = SUBMITTER_OWNER,
    target_id: str = "doc-1",
    judge: FakeProposalJudge | None = None,
    citations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return await create_proposal(
        session,
        kind=KIND,
        proposed_by_bot_id=bot,
        owner_sub=owner,
        action=_action(ref, target_id, citations),
        rationale="r",
        confidence="medium",
        importance="medium",
        impact="medium",
        judge=judge or FakeProposalJudge(),
        target_fingerprint="x",
    )


async def _decide(
    session: AsyncSession,
    hold_id: str,
    approver: str,
    decision: str = "approve",
    judge: FakeProposalJudge | None = None,
) -> dict[str, Any]:
    return await decide_proposal(
        session,
        approver_sub=approver,
        hold_id=uuid.UUID(hold_id),
        decision=decision,
        decision_note="no" if decision == "reject" else None,
        judge=judge or _applied_judge(),
    )


@pytest_asyncio.fixture
async def agents(session: AsyncSession) -> tuple[Agent, Agent]:
    return (
        await _agent(session, SUBMITTER, SUBMITTER_OWNER),
        await _agent(session, TARGET, TARGET_OWNER),
    )


class TestResolution:
    async def test_flag_off_refuses_target(
        self, session: AsyncSession, agents: tuple[Agent, Agent], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CROSS_BRAIN_ENABLED_ENV_VAR, "false")
        with pytest.raises(ValueError, match="unsupported proposal kind"):
            await _submit(session, TARGET)
        assert (await session.execute(select(ProposalHold))).scalars().all() == []

    async def test_no_target_unaffected_by_flag(
        self, session: AsyncSession, agents: tuple[Agent, Agent], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CROSS_BRAIN_ENABLED_ENV_VAR, "false")
        result = await _submit(session, None)
        assert "cross_brain" not in result

    async def test_target_by_sub_and_by_id_resolve_to_canonical_sub(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        by_sub = await _submit(session, TARGET)
        by_id = await _submit(session, str(agents[1].id))
        assert by_sub["proposal_id"] == by_id["proposal_id"]  # same dedup key
        hold = (await session.execute(select(ProposalHold))).scalar_one()
        assert hold.cross_brain is not None
        assert hold.cross_brain["target_sub"] == TARGET
        assert hold.cross_brain["required_owner_subs"] == [TARGET_OWNER, SUBMITTER_OWNER]
        assert "target" not in hold.action

    @pytest.mark.parametrize("ref", ["nobody", str(uuid.uuid4()), ""])
    async def test_unknown_target_is_opaque_404(
        self, session: AsyncSession, agents: tuple[Agent, Agent], ref: str
    ) -> None:
        with pytest.raises((ProposalTargetUnavailableError, ValueError)) as exc:
            await _submit(session, ref)
        if isinstance(exc.value, ProposalTargetUnavailableError):
            assert exc.value.status_code == 404
            assert exc.value.error_code == "target_not_found"

    async def test_suspended_target_looks_like_unknown(self, session: AsyncSession) -> None:
        await _agent(session, SUBMITTER, SUBMITTER_OWNER)
        await _agent(session, TARGET, TARGET_OWNER, status="suspended")
        with pytest.raises(ProposalTargetUnavailableError) as exc:
            await _submit(session, TARGET)
        assert exc.value.error_code == "target_not_found"

    async def test_naming_yourself_is_own_brain(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        await _submit(session, SUBMITTER)
        hold = (await session.execute(select(ProposalHold))).scalar_one()
        assert hold.cross_brain is None

    async def test_cross_brain_citations_are_refused_at_submit(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        with pytest.raises(InvalidProposalActionError) as exc:
            await _submit(session, TARGET, citations=[{"revision_id": "rev-1"}])
        assert exc.value.field_errors == (("citations", "unsupported"),)
        assert (await session.execute(select(ProposalHold))).scalars().all() == []

    async def test_cross_brain_empty_citations_are_accepted(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        await _submit(session, TARGET, citations=[])
        hold = (await session.execute(select(ProposalHold))).scalar_one()
        assert hold.cross_brain is not None

    async def test_own_brain_citations_are_not_refused_here(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        # naming yourself is an own-brain proposal; citations stay valid there
        await _submit(session, SUBMITTER, citations=[{"revision_id": "rev-1"}])
        hold = (await session.execute(select(ProposalHold))).scalar_one()
        assert hold.cross_brain is None

    async def test_same_owner_requires_one_approval(self, session: AsyncSession) -> None:
        await _agent(session, SUBMITTER, SUBMITTER_OWNER)
        await _agent(session, TARGET, SUBMITTER_OWNER)
        await _submit(session, TARGET)
        hold = (await session.execute(select(ProposalHold))).scalar_one()
        assert hold.cross_brain is not None
        assert hold.cross_brain["required_owner_subs"] == [SUBMITTER_OWNER]


class TestDedupAndAutoApprove:
    async def test_different_targets_do_not_dedup(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        await _agent(session, "third", "carol@example.com")
        await _submit(session, TARGET)
        await _submit(session, "third")
        await _submit(session, None)
        assert len((await session.execute(select(ProposalHold))).scalars().all()) == 3

    async def test_never_auto_approved(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto"),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        result = await _submit(session, TARGET, judge=judge)
        assert result["status"] == "pending"
        assert judge.apply_calls == []


class TestApprovalFlow:
    async def test_both_owners_must_approve_then_applies(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, TARGET))["proposal_id"]
        judge = _applied_judge()

        first = await _decide(session, hold_id, TARGET_OWNER, judge=judge)
        assert first["status"] == "pending"
        assert [a["sub"] for a in first["approvals"]] == [TARGET_OWNER]
        assert judge.apply_calls == []

        again = await _decide(session, hold_id, TARGET_OWNER, judge=judge)  # idempotent
        assert len(again["approvals"]) == 1
        assert judge.apply_calls == []

        final = await _decide(session, hold_id, SUBMITTER_OWNER, judge=judge)
        assert final["status"] == "applied"
        assert len(judge.apply_calls) == 1

        record = await get_proposal_apply_record(
            session, hold_id=uuid.UUID(hold_id), requesting_sub="svc"
        )
        assert record["cross_brain"]["target_sub"] == TARGET
        assert {a["sub"] for a in record["approvals"]} == {TARGET_OWNER, SUBMITTER_OWNER}

    async def test_one_reject_ends_it(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, TARGET))["proposal_id"]
        await _decide(session, hold_id, SUBMITTER_OWNER)
        judge = _applied_judge()
        rejected = await _decide(session, hold_id, TARGET_OWNER, "reject", judge=judge)
        assert rejected["status"] == "rejected"
        assert judge.apply_calls == []
        with pytest.raises(HoldAlreadyDecidedError):
            await _decide(session, hold_id, SUBMITTER_OWNER)

    async def test_stranger_is_denied(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, TARGET))["proposal_id"]
        with pytest.raises(AccessDeniedError):
            await _decide(session, hold_id, "mallory@example.com")

    async def test_own_brain_still_only_submitter_owner(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, None))["proposal_id"]
        with pytest.raises(AccessDeniedError):
            await _decide(session, hold_id, TARGET_OWNER)
        assert (await _decide(session, hold_id, SUBMITTER_OWNER))["status"] == "applied"


class TestVisibility:
    async def test_target_owner_sees_pending_and_history(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, TARGET))["proposal_id"]
        for owner in (TARGET_OWNER, SUBMITTER_OWNER):
            pending = await list_pending_proposal_holds(session, owner_sub=owner)
            assert [p["proposal_id"] for p in pending["proposals"]] == [hold_id]
        stranger = await list_pending_proposal_holds(session, owner_sub="carol@example.com")
        assert stranger["proposals"] == []

        await _decide(session, hold_id, TARGET_OWNER, "reject")
        history = await list_proposal_history_for_owner(session, owner_sub=TARGET_OWNER)
        assert [h["proposal_id"] for h in history["proposals"]] == [hold_id]

    async def test_bot_view_hides_owner_identities(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, TARGET))["proposal_id"]
        await _decide(session, hold_id, TARGET_OWNER)
        view = await get_proposal_for_bot(
            session, hold_id=uuid.UUID(hold_id), requesting_bot_sub=SUBMITTER
        )
        assert view["cross_brain"] == {
            "target_sub": TARGET,
            "target_display_name": TARGET,
            "approvals_required": 2,
            "approvals_received": 1,
        }
        assert "approvals" not in view
        assert TARGET_OWNER not in str(view)


class TestCaps:
    async def test_per_submitter_cap(
        self, session: AsyncSession, agents: tuple[Agent, Agent], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CROSS_BRAIN_MAX_PENDING_PER_SUBMITTER_ENV_VAR, "2")
        await _submit(session, TARGET, target_id="d1")
        await _submit(session, TARGET, target_id="d2")
        with pytest.raises(RateLimitExceededError):
            await _submit(session, TARGET, target_id="d3")
        await _submit(session, None, target_id="d3")  # own-brain unaffected

    async def test_per_target_cap(
        self, session: AsyncSession, agents: tuple[Agent, Agent], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CROSS_BRAIN_MAX_PENDING_PER_TARGET_ENV_VAR, "1")
        await _agent(session, "other", "dave@example.com")
        await _submit(session, TARGET, target_id="d1")
        with pytest.raises(RateLimitExceededError):
            await _submit(session, TARGET, bot="other", owner="dave@example.com", target_id="d2")


class TestApplyContext:
    async def test_judge_sees_target_at_every_stage(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        judge = _applied_judge()
        hold_id = (await _submit(session, TARGET, judge=judge))["proposal_id"]
        assert judge.fingerprint_calls[0].cross_brain_target_sub == TARGET
        assert judge.judge_calls[0].cross_brain_target_sub == TARGET
        await _decide(session, hold_id, TARGET_OWNER, judge=judge)
        await _decide(session, hold_id, SUBMITTER_OWNER, judge=judge)
        assert judge.apply_calls[0].cross_brain_target_sub == TARGET

    async def test_own_brain_context_has_no_target(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        judge = _applied_judge()
        hold_id = (await _submit(session, None, judge=judge))["proposal_id"]
        await _decide(session, hold_id, SUBMITTER_OWNER, judge=judge)
        assert judge.apply_calls[0].cross_brain_target_sub is None

    async def test_apply_refuses_without_every_approval(
        self, session: AsyncSession, agents: tuple[Agent, Agent]
    ) -> None:
        hold_id = (await _submit(session, TARGET))["proposal_id"]
        hold = (await session.execute(select(ProposalHold))).scalar_one()
        hold.status = "applying"
        hold.decision_source = "human"
        hold.decided_by_actor_id = TARGET_OWNER
        hold.decided_at = datetime.now(UTC)
        hold.approvals = [{"sub": TARGET_OWNER}]
        await session.commit()
        judge = _applied_judge()
        result = await _apply_or_finalize_proposal_hold(
            session,
            hold_id=uuid.UUID(hold_id),
            expected_status="applying",
            decided_by_actor_id=TARGET_OWNER,
            decision_source="human",
            decision_note=None,
            judge=judge,
        )
        assert result is not None
        assert result["status"] == "apply_failed"
        assert judge.apply_calls == []
