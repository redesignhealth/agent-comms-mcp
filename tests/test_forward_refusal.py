"""TECH-9214: ``POST /proposals/{id}/forward-refusal`` -- the approvals service
records that Arcadia permanently refused a forwarded ``catalog_candidate``."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.routing import Route

import plugins
from models import AuditLog, ProposalHold
from scopes import PROPOSAL_APPLY_RECORD_SCOPE, PROPOSAL_FORWARD_REFUSAL_SCOPE
from tests.proposal_judge_fakes import FakeProposalJudge
from tests.test_proposal_endpoint import (
    _ENV_PATCH,
    _OIDC_PATCH,
    _agent_jwt_token,
    _FakeAuthProvider,
    _import_main,
    _interactive_token,
)

pytestmark = pytest.mark.usefixtures("_migrated_schema")

_OWNER = "owner-a@example.com"
_BOT = "catalog-agent"
_SERVICE = "agent-comms-approvals"
_NOTE = "Arcadia refused it (HTTP 422, INVALID_PAYLOAD): payload.version.works_score (out_of_range)"


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


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest.fixture(autouse=True)
def _allow_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROPOSAL_FORWARD_REFUSAL_ALLOWED_SUBS", _SERVICE)
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: FakeProposalJudge())


@pytest_asyncio.fixture
async def client(
    main: Any, session_factory: async_sessionmaker[AsyncSession]
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    fake_provider = _FakeAuthProvider()
    app = Starlette(
        routes=[
            Route(
                "/proposals/{proposal_id}/forward-refusal",
                main.forward_refusal_route,
                methods=["POST"],
            ),
        ]
    )
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(main, "_auth_provider", fake_provider),
        patch.object(main, "_okta_provider", fake_provider.server),
        patch("main.get_session_factory", return_value=session_factory),
    ):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            fake_provider.tokens["svc"] = _agent_jwt_token(
                _SERVICE, scopes=[PROPOSAL_FORWARD_REFUSAL_SCOPE]
            )
            fake_provider.tokens["read-only"] = _agent_jwt_token(
                _SERVICE, scopes=[PROPOSAL_APPLY_RECORD_SCOPE]
            )
            fake_provider.tokens["other"] = _agent_jwt_token(
                "someone-else", scopes=[PROPOSAL_FORWARD_REFUSAL_SCOPE]
            )
            fake_provider.tokens["human"] = _interactive_token(_OWNER)
            yield http_client, fake_provider


async def _seed(
    session: AsyncSession, *, kind: str = "catalog_candidate", status: str = "pending"
) -> ProposalHold:
    hold = ProposalHold(
        kind=kind,
        proposed_by_bot_id=_BOT,
        owner_sub=_OWNER,
        action={"target_id": "concept:a", "action_type": "create"},
        rationale="add it",
        confidence="low",
        importance="high",
        impact="medium",
        priority="medium",
        target_fingerprint="n/a:no-pre-existing-target",
        status=status,
    )
    if status != "pending":
        hold.decision_source = "human"
        hold.decided_by_actor_id = _OWNER
        hold.decided_at = datetime.now(UTC)
    session.add(hold)
    await session.commit()
    await session.refresh(hold)
    return hold


async def _post(
    http_client: httpx.AsyncClient, hold_id: Any, body: Any = None, token: str = "svc"
) -> httpx.Response:
    return await http_client.post(
        f"/proposals/{hold_id}/forward-refusal",
        json={"note": _NOTE} if body is None else body,
        headers={"Authorization": f"Bearer {token}"},
    )


async def _audited(session: AsyncSession, action: str) -> int:
    session.expire_all()
    rows = (await session.execute(select(AuditLog.action).where(AuditLog.action == action))).all()
    return len(rows)


class TestRecordsTheRefusal:
    async def test_rejects_a_pending_proposal_with_the_note(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        resp = await _post(http_client, hold.id)
        assert resp.status_code == 200
        assert resp.json()["already_recorded"] is False
        await session.refresh(hold)
        assert hold.status == "rejected"
        assert hold.decision_note == _NOTE
        assert hold.decision_source == "external"
        assert hold.decided_by_actor_id == _SERVICE
        assert hold.external_ref == "forwarding-refused"
        assert hold.applied_at is None

    async def test_is_idempotent(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        assert (await _post(http_client, hold.id)).status_code == 200
        again = await _post(http_client, hold.id, {"note": "different"})
        assert again.status_code == 200
        assert again.json()["already_recorded"] is True
        await session.refresh(hold)
        assert hold.decision_note == _NOTE

    async def test_a_decided_proposal_is_not_changed(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session, status="applied")
        resp = await _post(http_client, hold.id)
        assert resp.status_code == 409
        assert resp.json()["error"] == "already_decided"
        await session.refresh(hold)
        assert hold.status == "applied"

    async def test_an_owner_decided_kind_is_refused(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session, kind="gmail_send")
        resp = await _post(http_client, hold.id)
        assert resp.status_code == 422
        assert resp.json()["error"] == "not_externally_resolved"
        await session.refresh(hold)
        assert hold.status == "pending"

    async def test_unknown_and_malformed_ids(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _ = client
        assert (await _post(http_client, uuid.uuid4())).status_code == 404
        assert (await _post(http_client, "not-a-uuid")).status_code == 404

    @pytest.mark.parametrize("body", [{}, {"note": 3}, {"note": "  "}, [], "x"])
    async def test_a_usable_note_is_required(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        body: Any,
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        resp = await _post(http_client, hold.id, body)
        assert resp.status_code == 422
        await session.refresh(hold)
        assert hold.status == "pending"


class TestWhoMayCall:
    async def test_no_token(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        resp = await http_client.post(f"/proposals/{hold.id}/forward-refusal", json={"note": "x"})
        assert resp.status_code == 401

    @pytest.mark.parametrize("token", ["read-only", "other", "human"])
    async def test_other_callers_are_refused_and_nothing_changes(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        token: str,
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        resp = await _post(http_client, hold.id, token=token)
        assert resp.status_code in (401, 403)
        await session.refresh(hold)
        assert hold.status == "pending"

    async def test_audits_a_refused_service(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        await _post(http_client, hold.id, token="read-only")
        await _post(http_client, hold.id, token="other")
        assert await _audited(session, "denied.proposal_forward_refusal_missing_scope") == 1
        assert await _audited(session, "denied.proposal_forward_refusal_sub_not_allowed") == 1

    async def test_off_by_default(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        monkeypatch.delenv("PROPOSAL_FORWARD_REFUSAL_ALLOWED_SUBS")
        assert (await _post(http_client, hold.id)).status_code == 403
        await session.refresh(hold)
        assert hold.status == "pending"

    def test_the_scope_is_not_an_mcp_tool_scope(self) -> None:
        from scopes import TOOL_SCOPES

        assert PROPOSAL_FORWARD_REFUSAL_SCOPE not in set(TOOL_SCOPES.values())
