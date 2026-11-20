"""TECH-9214: ``service.resolve_external_proposal`` -- an external reviewer
system's decision closes a pending ``catalog_candidate`` proposal. The MCP tool
that exposes it, and its access control, are covered with the tool."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import service
from exceptions import ExternalResolutionError
from models import AuditLog, ProposalHold
from tests.proposal_judge_fakes import FakeProposalJudge

pytestmark = pytest.mark.usefixtures("_migrated_schema")

SERVICE_ROOT = Path(__file__).parent.parent
_OWNER = "owner-a@example.com"
_BOT = "catalog-agent"
_RESOLVER = "arcadia-service"
_KIND = "catalog_candidate"
_ACTION: dict[str, Any] = {
    "target_id": "concept:remote-patient-monitoring",
    "action_type": "create",
    "payload": {"slug": "remote-patient-monitoring", "name": "RPM"},
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


async def _seed(
    session: AsyncSession, *, kind: str = _KIND, target: str = "concept:remote-patient-monitoring"
) -> str:
    result = await service.create_proposal(
        session,
        kind=kind,
        proposed_by_bot_id=_BOT,
        owner_sub=_OWNER,
        action={**_ACTION, "target_id": target},
        rationale="add it",
        confidence="medium",
        importance="medium",
        impact="medium",
        judge=FakeProposalJudge(),
        target_fingerprint="ignored",
    )
    return str(result["proposal_id"])


async def _hold(session: AsyncSession, proposal_id: str) -> ProposalHold:
    session.expire_all()
    return (
        await session.execute(select(ProposalHold).where(ProposalHold.id == uuid.UUID(proposal_id)))
    ).scalar_one()


async def _audited(session: AsyncSession, action: str) -> list[str]:
    session.expire_all()
    return list(
        (await session.execute(select(AuditLog.action).where(AuditLog.action == action)))
        .scalars()
        .all()
    )


async def _resolve(
    session: AsyncSession,
    proposal_id: str,
    outcome: str = "applied",
    external_ref: str = "cand-1",
    note: str | None = None,
    resolver: str = _RESOLVER,
) -> dict[str, Any]:
    return await service.resolve_external_proposal(
        session,
        resolver_sub=resolver,
        hold_id=uuid.UUID(proposal_id),
        outcome=outcome,
        note=note,
        external_ref=external_ref,
    )


class TestOutcomes:
    async def test_applied(self, session: AsyncSession) -> None:
        pid = await _seed(session)
        result = await _resolve(session, pid, "applied", "cand-7", note="merged")
        assert result["status"] == "applied"
        assert result["already_recorded"] is False
        hold = await _hold(session, pid)
        assert hold.status == "applied"
        assert hold.decision_source == "external"
        assert hold.decided_by_actor_id == _RESOLVER
        assert hold.decided_at is not None
        assert hold.applied_at is not None
        assert hold.external_ref == "cand-7"
        assert hold.decision_note == "merged"
        assert hold.apply_result == {"external": True, "external_ref": "cand-7"}
        assert await _audited(session, "proposal.resolve_external")

    @pytest.mark.parametrize("outcome", ["rejected", "changes_requested"])
    async def test_rejected_and_changes_requested_close_with_note_and_ref(
        self, session: AsyncSession, outcome: str
    ) -> None:
        pid = await _seed(session)
        await _resolve(session, pid, outcome, "cand-8", note="please cite a source")
        hold = await _hold(session, pid)
        assert hold.status == outcome
        assert hold.decision_note == "please cite a source"
        assert hold.external_ref == "cand-8"
        assert hold.applied_at is None
        assert hold.apply_result is None

    async def test_the_submitting_bot_sees_the_outcome_but_not_who_decided(
        self, session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(session, pid, "changes_requested", "cand-9", note="tighten the summary")
        seen = await service.get_proposal_for_bot(
            session, hold_id=uuid.UUID(pid), requesting_bot_sub=_BOT
        )
        assert seen["status"] == "changes_requested"
        assert seen["decision_note"] == "tighten the summary"
        assert seen["external_ref"] == "cand-9"
        assert seen["decision_source"] == "external"
        assert "decided_by_actor_id" not in seen
        assert _RESOLVER not in repr(seen)

    async def test_the_bots_lists_put_it_in_history_not_pending(
        self, session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(session, pid, "changes_requested", "c", note="n")
        history = await service.list_proposals_for_bot(
            session,
            requesting_bot_sub=_BOT,
            statuses=service.PROPOSAL_TERMINAL_STATUSES,
            limit=50,
            order="created_at",
            since=None,
            cursor_kind="history",
        )
        pending = await service.list_proposals_for_bot(
            session,
            requesting_bot_sub=_BOT,
            statuses=("pending",),
            limit=50,
            order="created_at",
            since=None,
            cursor_kind="pending",
        )
        assert [p["proposal_id"] for p in history["proposals"]] == [pid]
        assert pending["proposals"] == []
        assert "decided_by_actor_id" not in history["proposals"][0]
        assert history["proposals"][0]["external_ref"] == "c"
        assert history["proposals"][0]["decision_note"] == "n"

    async def test_after_resolution_the_bot_can_submit_a_new_proposal_for_the_target(
        self, session: AsyncSession
    ) -> None:
        first = await _seed(session)
        await _resolve(session, first, "changes_requested", "c", note="n")
        second = await _seed(session)
        assert second != first
        assert (await _hold(session, second)).status == "pending"


class TestIdempotencyAndConflicts:
    async def test_repeating_an_outcome_changes_nothing(self, session: AsyncSession) -> None:
        pid = await _seed(session)
        await _resolve(session, pid, "rejected", "cand-1", note="first note")
        again = await _resolve(session, pid, "rejected", "cand-OTHER", note="a different note")
        assert again["already_recorded"] is True
        hold = await _hold(session, pid)
        assert hold.decision_note == "first note"
        assert hold.external_ref == "cand-1"
        assert len(await _audited(session, "proposal.resolve_external")) == 1

    @pytest.mark.parametrize(
        ("first", "second"),
        [("applied", "rejected"), ("rejected", "applied"), ("changes_requested", "applied")],
    )
    async def test_a_different_outcome_after_one_is_recorded_is_refused(
        self, session: AsyncSession, first: str, second: str
    ) -> None:
        pid = await _seed(session)
        await _resolve(session, pid, first, "c1", note="n")
        with pytest.raises(ExternalResolutionError) as excinfo:
            await _resolve(session, pid, second, "c1", note="n")
        assert excinfo.value.code == "already_decided"
        assert excinfo.value.status == first
        assert (await _hold(session, pid)).status == first

    async def test_a_withdrawn_proposal_cannot_be_resolved(self, session: AsyncSession) -> None:
        pid = await _seed(session)
        await service.withdraw_proposal(
            session, hold_id=uuid.UUID(pid), requesting_bot_sub=_BOT, reason=None
        )
        with pytest.raises(ExternalResolutionError) as excinfo:
            await _resolve(session, pid, "applied", "c1")
        assert excinfo.value.code == "already_decided"
        assert (await _hold(session, pid)).status == "withdrawn"

    async def test_an_ordinary_proposal_can_never_be_resolved_this_way(
        self, session: AsyncSession
    ) -> None:
        pid = await _seed(session, kind="linear_progress_update", target="TECH-1")
        with pytest.raises(ExternalResolutionError) as excinfo:
            await _resolve(session, pid, "applied", "c1")
        assert excinfo.value.code == "not_externally_resolved"
        hold = await _hold(session, pid)
        assert hold.status == "pending"
        assert hold.external_ref is None
        assert await _audited(session, "denied.proposal_resolve_external_kind_not_allowed")

    async def test_unknown_proposal(self, session: AsyncSession) -> None:
        with pytest.raises(ExternalResolutionError) as excinfo:
            await _resolve(session, str(uuid.uuid4()))
        assert excinfo.value.code == "unknown_proposal"


class TestValidation:
    @pytest.mark.parametrize("outcome", ["rejected", "changes_requested"])
    @pytest.mark.parametrize("note", [None, "", "   "])
    async def test_note_is_required_unless_applied(
        self, session: AsyncSession, outcome: str, note: str | None
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ExternalResolutionError) as excinfo:
            await _resolve(session, pid, outcome, "c1", note=note)
        assert excinfo.value.code == "invalid_request"
        assert (await _hold(session, pid)).status == "pending"

    @pytest.mark.parametrize("ref", ["", "  ", "x" * 201, "bad\nref", "tab\tref"])
    async def test_external_ref_is_bounded_and_printable(
        self, session: AsyncSession, ref: str
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ExternalResolutionError) as excinfo:
            await _resolve(session, pid, "applied", ref)
        assert excinfo.value.code == "invalid_request"
        assert (await _hold(session, pid)).status == "pending"

    async def test_note_length_is_bounded(self, session: AsyncSession) -> None:
        pid = await _seed(session)
        with pytest.raises(ExternalResolutionError):
            await _resolve(
                session,
                pid,
                "rejected",
                "c1",
                note="x" * (service.MAX_DECISION_REASON_LENGTH + 1),
            )

    @pytest.mark.parametrize("outcome", ["approved", "", "APPLIED"])
    async def test_unknown_outcome_is_refused(self, session: AsyncSession, outcome: str) -> None:
        pid = await _seed(session)
        with pytest.raises(ExternalResolutionError):
            await _resolve(session, pid, outcome, "c1", note="n")
        assert (await _hold(session, pid)).status == "pending"


class TestMigration:
    async def test_downgrade_maps_new_values_to_old_and_upgrade_restores_schema(
        self, engine: AsyncEngine, session: AsyncSession, database_url: str
    ) -> None:
        env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}

        def alembic(*args: str) -> None:
            subprocess.run(
                [sys.executable, "-m", "alembic", *args],
                cwd=SERVICE_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        applied = await _seed(session, target="concept:a")
        changes = await _seed(session, target="concept:b")
        pending = await _seed(session, target="concept:c")
        await _resolve(session, applied, "applied", "c-a")
        await _resolve(session, changes, "changes_requested", "c-b", note="n")
        await session.rollback()  # no open transaction may block the ALTERs
        try:
            await engine.dispose()
            alembic("downgrade", "20a7dfa60b73")
            async with engine.connect() as conn:
                rows = {
                    str(r[0]): (r[1], r[2])
                    for r in (
                        await conn.execute(
                            text("SELECT id, status, decision_source FROM proposal_holds")
                        )
                    ).all()
                }
            assert rows[applied] == ("applied", "human")
            assert rows[changes] == ("rejected", "human")
            assert rows[pending] == ("pending", None)
        finally:
            await engine.dispose()
            alembic("upgrade", "head")
