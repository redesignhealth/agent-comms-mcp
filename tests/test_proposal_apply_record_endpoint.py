"""Tests for ``GET /proposals/{hold_id}/apply-record`` (TECH-7694): the
service-only read the approvals service uses to re-check an approval before
applying it. Reuses the fake auth provider idiom from
``tests/test_proposal_endpoint.py``.
"""

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

from models import AuditLog, ProposalHold
from scopes import PROPOSAL_APPLY_RECORD_SCOPE
from tests.test_proposal_endpoint import (
    _ENV_PATCH,
    _OIDC_PATCH,
    _agent_jwt_token,
    _FakeAuthProvider,
    _import_main,
    _interactive_token,
)

pytestmark = pytest.mark.usefixtures("_migrated_schema")

_APPROVER = "owner-a@example.com"
_ACTION = {
    "action_type": "source_add",
    "target_id": "arcana-source:doc-1",
    "content": "hello",
}


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE TABLE proposal_holds, audit_log, agents RESTART IDENTITY CASCADE")
        )
    yield


@pytest.fixture
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest_asyncio.fixture
async def client(
    main: Any, test_session_factory: async_sessionmaker[AsyncSession]
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    fake_provider = _FakeAuthProvider()
    app = Starlette(
        routes=[
            Route(
                "/proposals/{hold_id}/apply-record",
                main.get_proposal_apply_record_route,
                methods=["GET"],
            ),
        ]
    )
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(main, "_auth_provider", fake_provider),
        patch.object(main, "_okta_provider", fake_provider.server),
        patch("main.get_session_factory", return_value=test_session_factory),
    ):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            yield http_client, fake_provider


async def _seed_hold(
    session: AsyncSession, *, status: str = "applying", decision_source: str | None = "human"
) -> ProposalHold:
    hold = ProposalHold(
        kind="arcana_source_add",
        proposed_by_bot_id="paperclip-agent-1",
        owner_sub=_APPROVER,
        action=dict(_ACTION),
        rationale="because",
        confidence="medium",
        importance="medium",
        impact="medium",
        priority="medium",
        target_fingerprint="fp",
    )
    if status != "pending":
        hold.status = status
        hold.decision_source = decision_source
        hold.decided_by_actor_id = _APPROVER if decision_source == "human" else "system:judge"
        hold.decided_at = datetime.now(UTC)
    session.add(hold)
    await session.commit()
    await session.refresh(hold)
    return hold


def _service_token(*, sub: str = "agent-comms-approvals", scopes: list[str] | None = None) -> Any:
    return _agent_jwt_token(sub, scopes=[PROPOSAL_APPLY_RECORD_SCOPE] if scopes is None else scopes)


async def _get(
    http_client: httpx.AsyncClient, hold_id: uuid.UUID | str, token: str | None = "svc"
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return await http_client.get(f"/proposals/{hold_id}/apply-record", headers=headers)


class TestApplyRecordRoute:
    async def test_returns_the_recorded_decision(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["svc"] = _service_token()
        hold = await _seed_hold(session)
        resp = await _get(http_client, hold.id)
        assert resp.status_code == 200
        body = resp.json()
        assert body["hold_id"] == str(hold.id)
        assert body["status"] == "applying"
        assert body["kind"] == "arcana_source_add"
        assert body["proposed_by_bot_id"] == "paperclip-agent-1"
        assert body["owner_sub"] == _APPROVER
        assert body["target_id"] == "arcana-source:doc-1"
        assert body["action_type"] == "source_add"
        assert body["action"] == _ACTION
        assert body["rationale"] == "because"
        assert body["decision_source"] == "human"
        assert body["decided_by_actor_id"] == _APPROVER
        assert body["decided_at"] is not None

    async def test_pending_hold_has_no_decision(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["svc"] = _service_token()
        hold = await _seed_hold(session, status="pending")
        body = (await _get(http_client, hold.id)).json()
        assert body["status"] == "pending"
        assert body["decision_source"] is None
        assert body["decided_by_actor_id"] is None

    async def test_unknown_and_malformed_hold_ids_are_uniform_404(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["svc"] = _service_token()
        assert (await _get(http_client, uuid.uuid4())).status_code == 404
        assert (await _get(http_client, "not-a-uuid")).status_code == 404
        audited = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.action == "denied.unknown_proposal_hold")
                )
            )
            .scalars()
            .all()
        )
        assert audited

    async def test_missing_and_unverifiable_tokens_are_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        hold_id = uuid.uuid4()
        assert (await _get(http_client, hold_id, token=None)).status_code == 401
        assert (await _get(http_client, hold_id, token="garbage")).status_code == 401

    async def test_interactive_token_is_401_not_authorized(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        """An Okta/interactive caller never verifies on the agent chain."""
        http_client, provider = client
        provider.tokens["human"] = _interactive_token(_APPROVER)
        hold = await _seed_hold(session)
        assert (await _get(http_client, hold.id, token="human")).status_code == 401

    async def test_missing_scope_is_403_and_audited(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["bot"] = _service_token(scopes=["comms:proposals:write"])
        hold = await _seed_hold(session)
        assert (await _get(http_client, hold.id, token="bot")).status_code == 403
        audited = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_apply_record_missing_scope"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert audited

    async def test_scope_under_a_non_allowlisted_subject_is_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["other"] = _service_token(sub="some-other-service")
        hold = await _seed_hold(session)
        assert (await _get(http_client, hold.id, token="other")).status_code == 403

    async def test_allowlist_is_configurable(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv("PROPOSAL_APPLY_RECORD_ALLOWED_SUBS", "svc-a, svc-b")
        provider.tokens["a"] = _service_token(sub="svc-b")
        provider.tokens["default"] = _service_token()
        hold = await _seed_hold(session)
        assert (await _get(http_client, hold.id, token="a")).status_code == 200
        assert (await _get(http_client, hold.id, token="default")).status_code == 403
