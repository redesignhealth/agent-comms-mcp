"""TECH-9214: ``proposals_admin_resolve_external`` -- the external reviewer
system (Arcadia) closes a pending ``catalog_candidate`` proposal.

Every call goes through the real mounted MCP server (scope middleware, tool
dispatch), like ``tests/test_proposal_tools.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
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
        assert await _audited(session, "denied.proposal_resolve_external_sub_not_allowed")

    async def test_an_interactive_caller_is_refused_and_audited(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        token = MagicMock()
        token.claims = {"iss": "https://example.okta.com/oauth2/default", "email": _OWNER}
        token.scopes = []
        token.client_id = _OWNER
        with pytest.raises(ToolError, match="access_denied"):
            await _resolve(main, session_factory, pid, token=token)
        assert (await _hold(session, pid)).status == "pending"
        assert await _audited(session, "denied.proposal_resolve_external_not_agent_token")

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


class TestThroughTheTool:
    """The business rules are covered in ``test_resolve_external_service.py``;
    these check the tool wiring, argument mapping and error mapping."""

    async def test_applied_and_the_bot_sees_the_outcome_but_not_who_decided(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        result = await _resolve(main, session_factory, pid, "applied", "cand-7", note="merged")
        assert result["status"] == "applied"
        assert result["already_recorded"] is False
        hold = await _hold(session, pid)
        assert (hold.status, hold.decision_source, hold.decided_by_actor_id) == (
            "applied",
            "external",
            _RESOLVER,
        )
        assert (hold.external_ref, hold.decision_note) == ("cand-7", "merged")
        assert await _audited(session, "proposal.resolve_external")
        seen = await _call(
            main, session_factory, _bot_token(), "proposals_get", {"proposal_id": pid}
        )
        assert seen["status"] == "applied"
        assert seen["decision_note"] == "merged"
        assert seen["external_ref"] == "cand-7"
        assert "decided_by_actor_id" not in seen
        assert _RESOLVER not in repr(seen)

    async def test_changes_requested_closes_it_and_lists_under_history(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(main, session_factory, pid, "changes_requested", "cand-9", note="cite more")
        history = await _call(main, session_factory, _bot_token(), "proposals_list_history", {})
        pending = await _call(main, session_factory, _bot_token(), "proposals_list_pending", {})
        assert [p["proposal_id"] for p in history["proposals"]] == [pid]
        assert history["proposals"][0]["external_ref"] == "cand-9"
        assert pending["proposals"] == []

    async def test_repeat_is_idempotent_and_a_different_outcome_is_already_decided(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        pid = await _seed(session)
        await _resolve(main, session_factory, pid, "rejected", "cand-1", note="first")
        again = await _resolve(main, session_factory, pid, "rejected", "cand-X", note="second")
        assert again["already_recorded"] is True
        with pytest.raises(ToolError, match="already_decided"):
            await _resolve(main, session_factory, pid, "applied", "cand-1")
        assert len(await _audited(session, "proposal.resolve_external")) == 1
        hold = await _hold(session, pid)
        assert (hold.status, hold.decision_note, hold.external_ref) == (
            "rejected",
            "first",
            "cand-1",
        )

    async def test_error_codes_reach_the_caller(
        self, main: Any, session_factory: async_sessionmaker[AsyncSession], session: AsyncSession
    ) -> None:
        ordinary = await _seed(session, kind="linear_progress_update", target="TECH-1")
        with pytest.raises(ToolError, match="not_externally_resolved"):
            await _resolve(main, session_factory, ordinary, "applied", "c1")
        with pytest.raises(ToolError, match="unknown_proposal"):
            await _resolve(main, session_factory, str(uuid.uuid4()))
        with pytest.raises(ToolError, match="not a valid UUID"):
            await _resolve(main, session_factory, "nope")
        pid = await _seed(session)
        with pytest.raises(ToolError, match="invalid_request"):
            await _resolve(main, session_factory, pid, "rejected", "c1")  # note required
        with pytest.raises(ToolError, match="approved"):
            await _resolve(main, session_factory, pid, "approved", "c1", note="n")
        assert (await _hold(session, pid)).status == "pending"


class TestAuditHelper:
    async def test_unknown_denial_reason_is_a_value_error(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="unexpected denial reason"):
            await service.audit_denied_resolve_external(session, actor_sub="x", reason="nope")

    async def test_known_reason_persists_a_row(self, session: AsyncSession) -> None:
        await service.audit_denied_resolve_external(session, actor_sub="x", reason="missing_scope")
        assert await _audited(session, "denied.proposal_resolve_external_missing_scope")
