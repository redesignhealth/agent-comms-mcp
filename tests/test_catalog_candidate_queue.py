"""TECH-9214: ``GET /proposals/external-queue`` (the approvals service's feed of
pending ``catalog_candidate`` proposals), plus the HTTP behaviour of the owner
routes for an externally resolved kind."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
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
from scopes import PROPOSAL_APPLY_RECORD_SCOPE
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
            Route("/proposals/pending", main.list_pending_proposals, methods=["GET"]),
            Route("/proposals/external-queue", main.list_external_queue_route, methods=["GET"]),
            Route("/proposals/{hold_id}/decide", main.decide_proposal_route, methods=["POST"]),
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
            fake_provider.tokens["approvals"] = _agent_jwt_token(
                "agent-comms-approvals", scopes=[PROPOSAL_APPLY_RECORD_SCOPE]
            )
            fake_provider.tokens["human"] = _interactive_token(_OWNER)
            yield http_client, fake_provider


async def _seed(
    session: AsyncSession,
    *,
    kind: str = _KIND,
    status: str = "pending",
    created_at: datetime | None = None,
    target: str = "concept:remote-patient-monitoring",
) -> ProposalHold:
    hold = ProposalHold(
        kind=kind,
        proposed_by_bot_id=_BOT,
        owner_sub=_OWNER,
        action={**_ACTION, "target_id": target},
        rationale="add it",
        confidence="low",
        importance="high",
        impact="medium",
        priority="medium",
        target_fingerprint="n/a:no-pre-existing-target",
        status=status,
    )
    if created_at is not None:
        hold.created_at = created_at
    if status != "pending":
        hold.decision_source = "human"
        hold.decided_by_actor_id = _OWNER
        hold.decided_at = datetime.now(UTC)
    session.add(hold)
    await session.commit()
    await session.refresh(hold)
    return hold


async def _queue(
    http_client: httpx.AsyncClient, token: str = "approvals", **params: Any
) -> httpx.Response:
    return await http_client.get(
        "/proposals/external-queue",
        params={"kind": _KIND, **params},
        headers={"Authorization": f"Bearer {token}"},
    )


class TestQueueContents:
    async def test_lists_pending_catalog_candidates_with_the_forwarding_fields(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        await _seed(session, status="rejected", target="concept:decided")
        await _seed(session, kind="gmail_send", target="gmail:x")
        resp = await _queue(http_client)
        assert resp.status_code == 200
        body = resp.json()
        assert body["next_cursor"] is None
        assert [p["hold_id"] for p in body["proposals"]] == [str(hold.id)]
        item = body["proposals"][0]
        assert item["kind"] == _KIND
        assert item["status"] == "pending"
        assert item["proposed_by_bot_id"] == _BOT
        assert item["action"] == _ACTION
        assert item["target_id"] == "concept:remote-patient-monitoring"
        assert item["action_type"] == "create"
        assert item["rationale"] == "add it"
        assert (item["confidence"], item["importance"], item["impact"]) == (
            "low",
            "high",
            "medium",
        )
        assert item["created_at"]

    async def test_is_read_only(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        await _queue(http_client)
        await session.refresh(hold)
        assert hold.status == "pending"

    async def test_pages_oldest_first_without_starving_newer_proposals(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        base = datetime.now(UTC) - timedelta(hours=1)
        ids = [
            str(
                (
                    await _seed(
                        session, target=f"concept:c{i}", created_at=base + timedelta(minutes=i)
                    )
                ).id
            )
            for i in range(5)
        ]
        first = (await _queue(http_client, limit=2)).json()
        assert [p["hold_id"] for p in first["proposals"]] == ids[:2]
        second = (await _queue(http_client, limit=2, cursor=first["next_cursor"])).json()
        assert [p["hold_id"] for p in second["proposals"]] == ids[2:4]
        third = (await _queue(http_client, limit=2, cursor=second["next_cursor"])).json()
        assert [p["hold_id"] for p in third["proposals"]] == ids[4:]
        assert third["next_cursor"] is None

    async def test_limit_is_clamped(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        await _seed(session)
        assert (await _queue(http_client, limit=0)).status_code == 200
        assert (await _queue(http_client, limit=100000)).status_code == 200


class TestQueueValidationAndAccess:
    @pytest.mark.parametrize(
        "params",
        [{"kind": "gmail_send"}, {"kind": ""}, {"cursor": "garbage"}, {"limit": "x"}],
    )
    async def test_bad_requests_are_400(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], params: dict[str, str]
    ) -> None:
        http_client, _ = client
        resp = await http_client.get(
            "/proposals/external-queue",
            params={"kind": _KIND, **params},
            headers={"Authorization": "Bearer approvals"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_no_token_is_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _ = client
        resp = await http_client.get("/proposals/external-queue", params={"kind": _KIND})
        assert resp.status_code == 401

    async def test_human_token_is_refused(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _ = client
        assert (await _queue(http_client, token="human")).status_code == 401

    async def test_a_bot_with_the_submit_scope_is_403_and_audited(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["bot"] = _agent_jwt_token(_BOT, scopes=["comms:proposals:write"])
        assert (await _queue(http_client, token="bot")).status_code == 403
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

    async def test_a_holder_of_the_scope_off_the_allowlist_is_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["other"] = _agent_jwt_token(
            "someone-else", scopes=[PROPOSAL_APPLY_RECORD_SCOPE]
        )
        assert (await _queue(http_client, token="other")).status_code == 403

    async def test_kind_scoped_reader_outside_its_grant_gets_the_uniform_404(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv("PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS", "rh-google-mcp=gmail_send")
        provider.tokens["google"] = _agent_jwt_token(
            "rh-google-mcp", scopes=[PROPOSAL_APPLY_RECORD_SCOPE]
        )
        await _seed(session)
        resp = await _queue(http_client, token="google")
        assert resp.status_code == 404
        audited = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_apply_record_kind_not_allowed"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert audited

    async def test_kind_scoped_reader_inside_its_grant_can_read(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv(
            "PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS", "arcadia-reader=catalog_candidate"
        )
        provider.tokens["reader"] = _agent_jwt_token(
            "arcadia-reader", scopes=[PROPOSAL_APPLY_RECORD_SCOPE]
        )
        await _seed(session)
        resp = await _queue(http_client, token="reader")
        assert resp.status_code == 200
        assert len(resp.json()["proposals"]) == 1


class TestOwnerRoutesForCatalogCandidates:
    async def test_decide_is_400_and_changes_nothing(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        hold = await _seed(session)
        for decision in ("approve", "reject"):
            resp = await http_client.post(
                f"/proposals/{hold.id}/decide",
                headers={"Authorization": "Bearer human"},
                json={"decision": decision, "decision_note": "no"},
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "invalid_request"
        await session.refresh(hold)
        assert hold.status == "pending"

    async def test_pending_list_omits_the_kind_but_keeps_others(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        await _seed(session)
        other = await _seed(session, kind="gmail_send", target="gmail:x")
        resp = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human"}
        )
        assert resp.status_code == 200
        assert [p["proposal_id"] for p in resp.json()["proposals"]] == [str(other.id)]
