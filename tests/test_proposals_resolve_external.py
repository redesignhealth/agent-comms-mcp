"""TECH-9214: ``proposals_admin_resolve_external`` -- the external reviewer
system (Arcadia) closes a pending ``catalog_candidate`` proposal.

Every call goes through the real mounted MCP server (scope middleware, tool
dispatch), like ``tests/test_proposal_tools.py``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from fastmcp import Client
from fastmcp.exceptions import ToolError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import mint_token
import plugins
import service
from models import AuditLog, ProposalHold
from scopes import PROPOSAL_RESOLVE_EXTERNAL_SCOPE, PROPOSAL_SUBMIT_SCOPE, TOOL_SCOPES
from tests.proposal_judge_fakes import FakeProposalJudge
from tests.test_proposal_tools import _ENV_PATCH, _OIDC_PATCH, _import_main

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


@pytest.fixture(autouse=True)
def _allow_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROPOSAL_RESOLVE_EXTERNAL_ALLOWED_SUBS", _RESOLVER)
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: FakeProposalJudge())


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


def _token(sub: str, scopes: list[str]) -> MagicMock:
    token = MagicMock()
    token.claims = {"iss": "agent-jwt", "sub": sub, "scopes": scopes, "owner_sub": _OWNER}
    token.scopes = []
    token.client_id = sub
    return token


def _resolver_token(sub: str = _RESOLVER) -> MagicMock:
    return _token(sub, [PROPOSAL_RESOLVE_EXTERNAL_SCOPE])


def _bot_token() -> MagicMock:
    return _token(_BOT, [PROPOSAL_SUBMIT_SCOPE])


async def _call(
    main: Any,
    factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    tool: str,
    args: dict[str, Any],
) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.proposals.get_access_token", return_value=token),
        patch("providers.proposals.get_session_factory", return_value=factory),
    ):
        async with Client(main.mcp) as client:
            return (await client.call_tool(tool, args)).data


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
    main: Any,
    factory: async_sessionmaker[AsyncSession],
    proposal_id: str,
    outcome: str = "applied",
    external_ref: str = "cand-1",
    note: str | None = None,
    token: MagicMock | None = None,
) -> Any:
    args: dict[str, Any] = {
        "proposal_id": proposal_id,
        "outcome": outcome,
        "external_ref": external_ref,
    }
    if note is not None:
        args["note"] = note
    return await _call(
        main, factory, token or _resolver_token(), "proposals_admin_resolve_external", args
    )


class TestRegistration:
    async def test_tool_is_mounted_and_gated_by_its_own_scope(self, main: Any) -> None:
        mounted = {t.name for t in await main.mcp.list_tools()}
        assert "proposals_admin_resolve_external" in mounted
        assert TOOL_SCOPES["proposals_admin_resolve_external"] == PROPOSAL_RESOLVE_EXTERNAL_SCOPE
        assert PROPOSAL_RESOLVE_EXTERNAL_SCOPE not in {
            scope
            for name, scope in TOOL_SCOPES.items()
            if name != "proposals_admin_resolve_external"
        }
        assert PROPOSAL_RESOLVE_EXTERNAL_SCOPE in mint_token._VALID_SCOPES


class TestWhoMayResolve:
    async def test_a_bot_with_only_the_submit_scope_is_refused_by_the_middleware(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ToolError, match="requires elevated permissions"):
            await _resolve(main, session_factory, pid, token=_bot_token())
        assert (await _hold(session, pid)).status == "pending"

    async def test_the_submitting_bot_cannot_resolve_its_own_proposal_even_with_the_scope(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        token = _token(_BOT, [PROPOSAL_SUBMIT_SCOPE, PROPOSAL_RESOLVE_EXTERNAL_SCOPE])
        with pytest.raises(ToolError, match="access_denied"):
            await _resolve(main, session_factory, pid, token=token)
        assert (await _hold(session, pid)).status == "pending"
        assert await _audited(session, "denied.proposal_resolve_external_sub_not_allowed")

    async def test_the_allowlist_defaults_to_nobody(
        self,
        main: Any,
        session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("PROPOSAL_RESOLVE_EXTERNAL_ALLOWED_SUBS")
        pid = await _seed(session)
        with pytest.raises(ToolError, match="access_denied"):
            await _resolve(main, session_factory, pid)
        assert (await _hold(session, pid)).status == "pending"

    async def test_an_interactive_caller_is_refused_and_audited(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        token = MagicMock()
        token.claims = {"iss": "https://example.okta.com/oauth2/default", "email": _OWNER}
        token.scopes = []
        token.client_id = _OWNER
        with pytest.raises(ToolError):
            await _resolve(main, session_factory, pid, token=token)
        assert (await _hold(session, pid)).status == "pending"

    async def test_an_allowlisted_sub_without_the_scope_is_refused_and_audited(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        """The middleware normally stops this; the handler re-checks."""
        from providers import proposals

        pid = await _seed(session)
        token = _token(_RESOLVER, [PROPOSAL_SUBMIT_SCOPE])
        with (
            patch("providers.proposals.get_access_token", return_value=token),
            patch("providers.proposals.get_session_factory", return_value=session_factory),
            pytest.raises(ToolError, match="access_denied"),
        ):
            await proposals._require_resolver_sub()
        assert await _audited(session, "denied.proposal_resolve_external_missing_scope")
        assert (await _hold(session, pid)).status == "pending"


class TestOutcomes:
    async def test_applied(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        result = await _resolve(main, session_factory, pid, "applied", "cand-7", note="merged")
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
        self,
        main: Any,
        session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        outcome: str,
    ) -> None:
        pid = await _seed(session)
        await _resolve(main, session_factory, pid, outcome, "cand-8", note="please cite a source")
        hold = await _hold(session, pid)
        assert hold.status == outcome
        assert hold.decision_note == "please cite a source"
        assert hold.external_ref == "cand-8"
        assert hold.applied_at is None
        assert hold.apply_result is None

    async def test_the_submitting_bot_sees_the_outcome_but_not_who_decided(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(
            main, session_factory, pid, "changes_requested", "cand-9", note="tighten the summary"
        )
        seen = await _call(
            main, session_factory, _bot_token(), "proposals_get", {"proposal_id": pid}
        )
        assert seen["status"] == "changes_requested"
        assert seen["decision_note"] == "tighten the summary"
        assert seen["external_ref"] == "cand-9"
        assert seen["decision_source"] == "external"
        assert "decided_by_actor_id" not in seen
        assert _RESOLVER not in repr(seen)

    async def test_changes_requested_shows_in_the_bots_history_not_pending(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(main, session_factory, pid, "changes_requested", "c", note="n")
        history = await _call(main, session_factory, _bot_token(), "proposals_list_history", {})
        pending = await _call(main, session_factory, _bot_token(), "proposals_list_pending", {})
        assert [p["proposal_id"] for p in history["proposals"]] == [pid]
        assert pending["proposals"] == []
        assert "decided_by_actor_id" not in history["proposals"][0]

    async def test_after_resolution_the_bot_can_submit_a_new_proposal_for_the_target(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        first = await _seed(session)
        await _resolve(main, session_factory, first, "changes_requested", "c", note="n")
        second = await _seed(session)
        assert second != first
        assert (await _hold(session, second)).status == "pending"


class TestIdempotencyAndConflicts:
    async def test_repeating_an_outcome_changes_nothing(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(main, session_factory, pid, "rejected", "cand-1", note="first note")
        again = await _resolve(
            main, session_factory, pid, "rejected", "cand-OTHER", note="a different note"
        )
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
        self,
        main: Any,
        session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        first: str,
        second: str,
    ) -> None:
        pid = await _seed(session)
        await _resolve(main, session_factory, pid, first, "c1", note="n")
        with pytest.raises(ToolError, match="already_decided"):
            await _resolve(main, session_factory, pid, second, "c1", note="n")
        assert (await _hold(session, pid)).status == first

    async def test_a_withdrawn_proposal_cannot_be_resolved(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _call(main, session_factory, _bot_token(), "proposals_withdraw", {"proposal_id": pid})
        with pytest.raises(ToolError, match="already_decided"):
            await _resolve(main, session_factory, pid, "applied", "c1")
        assert (await _hold(session, pid)).status == "withdrawn"

    async def test_an_ordinary_proposal_can_never_be_resolved_this_way(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session, kind="linear_progress_update", target="TECH-1")
        with pytest.raises(ToolError, match="not_externally_resolved"):
            await _resolve(main, session_factory, pid, "applied", "c1")
        hold = await _hold(session, pid)
        assert hold.status == "pending"
        assert hold.external_ref is None
        assert await _audited(session, "denied.proposal_resolve_external_kind_not_allowed")

    async def test_unknown_proposal(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(ToolError, match="unknown_proposal"):
            await _resolve(main, session_factory, str(uuid.uuid4()))

    async def test_malformed_proposal_id(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(ToolError, match="not a valid UUID"):
            await _resolve(main, session_factory, "nope")


class TestValidation:
    @pytest.mark.parametrize("outcome", ["rejected", "changes_requested"])
    @pytest.mark.parametrize("note", [None, "", "   "])
    async def test_note_is_required_unless_applied(
        self,
        main: Any,
        session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        outcome: str,
        note: str | None,
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ToolError, match="invalid_request"):
            await _resolve(main, session_factory, pid, outcome, "c1", note=note)
        assert (await _hold(session, pid)).status == "pending"

    @pytest.mark.parametrize("ref", ["", "  ", "x" * 201, "bad\nref", "tab\tref"])
    async def test_external_ref_is_bounded_and_printable(
        self,
        main: Any,
        session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        ref: str,
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ToolError, match="invalid_request"):
            await _resolve(main, session_factory, pid, "applied", ref)
        assert (await _hold(session, pid)).status == "pending"

    async def test_note_length_is_bounded(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ToolError, match="invalid_request"):
            await _resolve(
                main,
                session_factory,
                pid,
                "rejected",
                "c1",
                note="x" * (service.MAX_DECISION_REASON_LENGTH + 1),
            )

    async def test_unknown_outcome_is_refused(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        with pytest.raises(ToolError):
            await _resolve(main, session_factory, pid, "approved", "c1")
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
        factory = async_sessionmaker(engine, expire_on_commit=False)
        main = _import_main()
        await _resolve(main, factory, applied, "applied", "c-a")
        await _resolve(main, factory, changes, "changes_requested", "c-b", note="n")
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
