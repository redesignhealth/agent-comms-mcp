"""TECH-9214: ``POST /proposals/{id}/forward-refusal`` -- the approvals forwarder
reports that Arcadia refused a pending ``catalog_candidate``; the board closes it
as ``rejected`` and keeps the structured refusal for ``proposals_get``."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
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
import service
from exceptions import ExternalResolutionError
from models import AuditLog, ProposalHold
from scopes import PROPOSAL_APPLY_RECORD_SCOPE, PROPOSAL_FORWARD_REFUSAL_SCOPE
from tests.conftest import SERVICE_ROOT
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
_FORWARDER = "agent-comms-approvals"
_KIND = "catalog_candidate"
_ACTION: dict[str, Any] = {
    "target_id": "concept:remote-patient-monitoring",
    "action_type": "create",
    "payload": {"slug": "remote-patient-monitoring", "name": "RPM"},
}
_ERRORS = [
    {"path": "payload.slug", "rule": "pattern", "message": "must be kebab-case"},
    {"path": "payload.name", "rule": "minLength", "message": "too short"},
]
_NOTE = "Arcadia refused this proposal (HTTP 422, INVALID_PAYLOAD)."


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
def _allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROPOSAL_FORWARD_REFUSAL_ALLOWED_SUBS", _FORWARDER)


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest_asyncio.fixture
async def client(
    main: Any, session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: FakeProposalJudge())
    fake_provider = _FakeAuthProvider()
    app = Starlette(
        routes=[
            Route(
                "/proposals/{hold_id}/forward-refusal", main.forward_refusal_route, methods=["POST"]
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
            fake_provider.tokens["forwarder"] = _agent_jwt_token(
                _FORWARDER, scopes=[PROPOSAL_FORWARD_REFUSAL_SCOPE]
            )
            fake_provider.tokens["human"] = _interactive_token(_OWNER)
            yield http_client, fake_provider


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


async def _post(
    http_client: httpx.AsyncClient,
    hold_id: str,
    body: Any = None,
    token: str = "forwarder",
) -> httpx.Response:
    return await http_client.post(
        f"/proposals/{hold_id}/forward-refusal",
        json=body
        if body is not None
        else {"note": _NOTE, "code": "INVALID_PAYLOAD", "errors": _ERRORS},
        headers={"Authorization": f"Bearer {token}"},
    )


class TestRoute:
    async def test_refusal_rejects_the_proposal_and_the_bot_reads_it(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        resp = await _post(http_client, pid)
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"
        assert resp.json()["already_recorded"] is False
        hold = await _hold(session, pid)
        assert hold.status == "rejected"
        assert hold.decision_source == "external"
        assert hold.decided_by_actor_id == _FORWARDER
        assert hold.decided_at is not None
        assert hold.decision_note == _NOTE
        assert hold.external_ref is None
        assert hold.external_refusal == {"code": "INVALID_PAYLOAD", "errors": _ERRORS}
        assert await _audited(session, "proposal.forward_refusal")

        seen = await service.get_proposal_for_bot(
            session, hold_id=uuid.UUID(pid), requesting_bot_sub=_BOT
        )
        assert seen["status"] == "rejected"
        assert seen["decision_note"] == _NOTE
        assert seen["external_refusal"] == {"code": "INVALID_PAYLOAD", "errors": _ERRORS}
        assert "decided_by_actor_id" not in seen

    async def test_the_proposal_leaves_the_external_queue(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        await _post(http_client, pid)
        listed = await service.list_external_resolution_queue(
            session, requesting_sub=_FORWARDER, kind=_KIND
        )
        assert [p["hold_id"] for p in listed["proposals"]] == []

    async def test_a_repeat_is_idempotent_and_changes_nothing(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        await _post(http_client, pid)
        again = await _post(http_client, pid, {"note": "different note", "errors": []})
        assert again.status_code == 200
        assert again.json()["already_recorded"] is True
        hold = await _hold(session, pid)
        assert hold.decision_note == _NOTE
        assert hold.external_refusal == {"code": "INVALID_PAYLOAD", "errors": _ERRORS}
        assert len(await _audited(session, "proposal.forward_refusal")) == 1

    async def test_a_note_only_body_is_accepted(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        """The worker before it sent structured errors posts ``{"note": ...}`` only."""
        http_client, _ = client
        pid = await _seed(session)
        resp = await _post(http_client, pid, {"note": _NOTE})
        assert resp.status_code == 200
        hold = await _hold(session, pid)
        assert hold.external_refusal == {"code": None, "errors": []}

    async def test_unknown_proposal_is_404_unknown_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        resp = await _post(http_client, str(uuid.uuid4()))
        assert resp.status_code == 404
        assert resp.json()["error"] == "unknown_proposal"
        assert await _audited(session, "denied.unknown_proposal_hold")

    async def test_a_malformed_id_is_404_unknown_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _ = client
        resp = await _post(http_client, "not-a-uuid")
        assert resp.status_code == 404
        assert resp.json()["error"] == "unknown_proposal"

    async def test_a_kind_the_owner_decides_is_404_and_untouched(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session, kind="open_ticket", target="team:tech")
        resp = await _post(http_client, pid)
        assert resp.status_code == 404
        assert resp.json()["error"] == "unknown_proposal"
        assert (await _hold(session, pid)).status == "pending"

    async def test_a_withdrawn_proposal_is_409_already_decided(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        await service.withdraw_proposal(
            session, hold_id=uuid.UUID(pid), requesting_bot_sub=_BOT, reason="changed my mind"
        )
        resp = await _post(http_client, pid)
        assert resp.status_code == 409
        assert resp.json()["error"] == "already_decided"
        assert resp.json()["status"] == "withdrawn"
        assert (await _hold(session, pid)).status == "withdrawn"

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"note": "   "},
            {"note": 5},
            {"note": "x" * 2001},
            {"note": "n", "code": 5},
            {"note": "n", "errors": "nope"},
            {"note": "n", "errors": ["nope"]},
            {"note": "n", "errors": [{"path": 5}]},
        ],
    )
    async def test_an_invalid_body_is_400_and_changes_nothing(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        body: dict[str, Any],
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        resp = await _post(http_client, pid, body)
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"
        assert (await _hold(session, pid)).status == "pending"

    async def test_errors_are_bounded_and_stripped_to_known_keys(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        many = [
            {"path": f"p{i}", "rule": "r", "message": "m" * 900, "extra": "x"} for i in range(30)
        ]
        resp = await _post(http_client, pid, {"note": "n", "code": "C", "errors": many})
        assert resp.status_code == 200
        stored = (await _hold(session, pid)).external_refusal
        assert stored is not None
        assert len(stored["errors"]) == service.MAX_REFUSAL_ERRORS
        assert set(stored["errors"][0]) == {"path", "rule", "message"}
        assert len(stored["errors"][0]["message"]) == service.MAX_REFUSAL_FIELD_LENGTH

    async def test_a_non_object_body_is_400(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        resp = await http_client.post(
            f"/proposals/{pid}/forward-refusal",
            json=["note"],
            headers={"Authorization": "Bearer forwarder"},
        )
        assert resp.status_code == 400


class TestAccess:
    async def test_no_token_is_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        resp = await http_client.post(f"/proposals/{pid}/forward-refusal", json={"note": "n"})
        assert resp.status_code == 401
        assert (await _hold(session, pid)).status == "pending"

    async def test_an_interactive_token_is_refused(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        pid = await _seed(session)
        assert (await _post(http_client, pid, token="human")).status_code == 401
        assert (await _hold(session, pid)).status == "pending"

    async def test_the_submitting_bot_cannot_reject_its_own_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["bot"] = _agent_jwt_token(_BOT, scopes=["comms:proposals:write"])
        pid = await _seed(session)
        assert (await _post(http_client, pid, token="bot")).status_code == 403
        assert (await _hold(session, pid)).status == "pending"
        assert await _audited(session, "denied.proposal_forward_refusal_missing_scope")

    async def test_the_apply_record_scope_does_not_grant_it(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["reader"] = _agent_jwt_token(
            _FORWARDER, scopes=[PROPOSAL_APPLY_RECORD_SCOPE]
        )
        pid = await _seed(session)
        assert (await _post(http_client, pid, token="reader")).status_code == 403

    async def test_the_scope_under_another_subject_is_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["other"] = _agent_jwt_token(
            "someone-else", scopes=[PROPOSAL_FORWARD_REFUSAL_SCOPE]
        )
        pid = await _seed(session)
        assert (await _post(http_client, pid, token="other")).status_code == 403
        assert (await _hold(session, pid)).status == "pending"

    async def test_an_empty_allowlist_means_nobody(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, _ = client
        monkeypatch.delenv("PROPOSAL_FORWARD_REFUSAL_ALLOWED_SUBS")
        pid = await _seed(session)
        assert (await _post(http_client, pid)).status_code == 403
        assert (await _hold(session, pid)).status == "pending"


class TestService:
    async def test_a_decided_proposal_is_already_decided(self, session: AsyncSession) -> None:
        pid = await _seed(session)
        await service.resolve_external_proposal(
            session,
            resolver_sub="arcadia",
            hold_id=uuid.UUID(pid),
            outcome="applied",
            note=None,
            external_ref="c-1",
        )
        with pytest.raises(ExternalResolutionError) as excinfo:
            await service.record_forward_refusal(
                session, forwarder_sub=_FORWARDER, hold_id=uuid.UUID(pid), note="n"
            )
        assert excinfo.value.code == "already_decided"
        assert (await _hold(session, pid)).external_refusal is None


class TestMigration:
    async def test_downgrade_drops_the_column_and_upgrade_restores_it(
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

        async def has_column() -> bool:
            async with engine.connect() as conn:
                return bool(
                    (
                        await conn.execute(
                            text(
                                "SELECT 1 FROM information_schema.columns "
                                "WHERE table_name = 'proposal_holds' "
                                "AND column_name = 'external_refusal'"
                            )
                        )
                    ).first()
                )

        assert await has_column()
        await session.rollback()  # no open transaction may block the ALTERs
        try:
            await engine.dispose()
            alembic("downgrade", "b9214c0e5d17")
            assert not await has_column()
        finally:
            await engine.dispose()
            alembic("upgrade", "head")
        assert await has_column()
