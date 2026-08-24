"""End-to-end tests for the non-MCP approval HTTP surface (main.py,
TECH-5389 PR2): ``POST /approvals/{hold_id}/decide`` and
``GET /approvals/pending``.

Own file, not folded into test_main.py: needs the Postgres fixture block
(mirrored from test_comms_tools.py/test_service.py), which test_main.py
deliberately lacks.

Auth is exercised against ``main._auth_provider`` directly (a fake standing
in for FastMCP's real ``MultiAuth.verify_token``) rather than a real Okta/
agent-jwt signing round trip -- these tests are about ``main.py``'s OWN
gate logic (hard interactive-only, owner_sub match, uniform 404s), not
about re-proving FastMCP's/JWTVerifier's own token verification.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.applications import Starlette
from starlette.routing import Route

from models import ApprovalHold, AuditLog, Conversation
from service import register_agent

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


def _test_database_url() -> str:
    url = os.environ.get("DATABASE_URL", _DEFAULT_TEST_DATABASE_URL)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def _can_connect(url: str) -> bool:
    try:
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def database_url() -> str:
    url = _test_database_url()
    if not asyncio.run(_can_connect(url)):
        pytest.skip(
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise the approval-endpoint tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
    env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
    for args in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )


@pytest_asyncio.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(database_url)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE audit_log, approval_holds, messages, participants, "
                "conversations, agents RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


@pytest.fixture
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


_MOCK_OIDC_CONFIG = MagicMock()
_OIDC_PATCH = patch(
    "fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration",
    return_value=_MOCK_OIDC_CONFIG,
)
_ENV_PATCH = patch.dict(
    os.environ,
    {
        "OKTA_ISSUER_URL": "https://example.okta.com/oauth2/default",
        "OKTA_CLIENT_ID": "test-id",
        "OKTA_CLIENT_SECRET": "test-secret",
        "BASE_URL": "http://localhost:8080",
        "MCP_JWT_SECRET": "test-jwt-secret",
        "AGENT_JWT_SECRET": "test-agent-jwt-secret-long-enough-for-hs256",
    },
)


def _import_main() -> Any:
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


class _FakeAccessToken:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims


class _FakeInteractiveOnlyProvider:
    """Stands in for ``main._auth_provider.server`` (the real Okta
    ``OktaOIDCProxy``): looks up the SAME token dict as the outer fake (so
    tests keep using one ``_interactive_token``/``_agent_jwt_token``-
    populated map), but -- matching real Okta behavior, which could never
    successfully verify an agent-jwt-shaped token -- returns ``None`` for
    anything that isn't interactive-shaped."""

    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") == "agent-jwt":
            return None
        return found


class _FakeAuthProvider:
    """Stands in for ``main._auth_provider`` (a real ``MultiAuth``): maps a
    bearer-token STRING to a canned ``AccessToken``, so these tests can
    control exactly what ``main._authenticate_approval_caller`` sees
    without a real Okta/agent-jwt signing round trip. ``.server`` stands in
    for ``main._okta_provider`` (the structural interactive-only gate,
    TECH-5389 pluggable-auth revision) -- patched in separately below since
    production code reads it as its own module attribute, not through this
    object."""

    def __init__(self) -> None:
        self.tokens: dict[str, _FakeAccessToken] = {}
        self.server = _FakeInteractiveOnlyProvider(self)

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        return self.tokens.get(token)


def _interactive_token(owner_email: str) -> _FakeAccessToken:
    return _FakeAccessToken({"iss": "https://agent-comms.example/mcp", "email": owner_email})


def _agent_jwt_token(sub: str, *, scopes: list[str] | None = None) -> _FakeAccessToken:
    return _FakeAccessToken(
        {"iss": "agent-jwt", "sub": sub, "scopes": scopes if scopes is not None else []}
    )


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest_asyncio.fixture
async def client(
    main: Any, test_session_factory: async_sessionmaker[AsyncSession]
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    fake_provider = _FakeAuthProvider()
    # A minimal Starlette app wrapping ONLY the two approval routes' plain
    # handler functions (``mcp.custom_route``'s decorator returns `fn`
    # unchanged -- verified against the installed FastMCP version), rather
    # than ``main.mcp.http_app()``: the full production app also builds the
    # real OAuth-metadata/DCR routes, which need a genuine OktaOIDCProxy
    # config (not satisfiable by a MagicMock stand-in) to construct at all
    # -- entirely orthogonal to what these tests are about (main.py's OWN
    # gate logic on these two routes, not FastMCP's OAuth machinery).
    app = Starlette(
        routes=[
            Route("/approvals/{hold_id}/decide", main.decide_approval, methods=["POST"]),
            Route("/approvals/pending", main.list_pending_approvals, methods=["GET"]),
            Route(
                "/admin/agents/reconcile-ownership",
                main.reconcile_ownership,
                methods=["POST"],
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


async def _make_hold(
    session: AsyncSession,
    *,
    sender_owner_sub: str = "owner-a@example.com",
    status: str = "pending_human",
    expires_at: datetime | None = None,
) -> tuple[Any, ApprovalHold]:
    sender = await register_agent(
        session,
        sub=f"hold-sender-{uuid.uuid4()}",
        owner_sub=sender_owner_sub,
        owner_email=sender_owner_sub,
        display_name="hold sender",
        accepted_types=["note"],
    )
    conversation = Conversation(
        type="open",
        state="active",
        created_by=sender.id,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    session.add(conversation)
    await session.flush()
    hold = ApprovalHold(
        conversation_id=conversation.id,
        sender_agent_id=sender.id,
        owner_sub=sender_owner_sub,
        message_type="note",
        schema_version=1,
        payload={"type": "note", "text": "the actual held content"},
        risk_reason="boundary_crossing",
        risk_scorer="boundary_v1",
        status=status,
        expires_at=expires_at or (datetime.now(UTC) + timedelta(days=7)),
    )
    session.add(hold)
    await session.commit()
    return sender, hold


class TestAuthGate:
    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.get("/approvals/pending")
        assert resp.status_code == 401

    async def test_unverifiable_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.get(
            "/approvals/pending", headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert resp.status_code == 401

    async def test_agent_jwt_token_returns_403_even_with_comms_admin_scope(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Load-bearing structural test: the decide/list surface has NO
        scope escape hatch, unlike providers/comms.py's
        ``is_interactive_token(token) or "comms:admin" in scopes``
        pattern. An agent-jwt token carrying ``comms:admin`` must still get
        403, not 200 -- proving the gate is issuer-structural, not scope-
        based."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-agent-sub", scopes=["comms:admin", "comms:read", "comms:write"]
        )
        resp = await http_client.get(
            "/approvals/pending", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_rejection_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token("some-agent-sub")
        await http_client.get("/approvals/pending", headers={"Authorization": "Bearer agent-token"})

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.approval_requires_interactive"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows


class TestDecideEndpoint:
    async def test_uniform_404_for_unknown_hold(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            f"/approvals/{uuid.uuid4()}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_malformed_hold_id(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            "/approvals/not-a-uuid/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_not_your_hold(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(session, sender_owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-b@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_reject_stores_reason_and_posts_no_message(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(session, sender_owner_sub="owner-reject@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-reject@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "reason": "not appropriate to share"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "rejected"
        assert body["decision_reason"] == "not appropriate to share"
        assert "message_id" not in body

        actions = (
            await session.execute(
                select(AuditLog.action, AuditLog.actor_sub).where(
                    AuditLog.conversation_id == hold.conversation_id
                )
            )
        ).all()
        assert any(
            action == "approval.reject" and actor_sub == "owner-reject@example.com"
            for action, actor_sub in actions
        )

    async def test_approve_posts_message_under_original_type(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        sender, hold = await _make_hold(session, sender_owner_sub="owner-approve@example.com")
        # The sender must be an active participant for the approve-time
        # capability re-check to have something to iterate over; the
        # conversation created in _make_hold has no participants at all,
        # which is fine -- an empty "other participants" set trivially
        # passes the capability gate.
        provider.tokens["human-token"] = _interactive_token("owner-approve@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve", "reason": "looks fine"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "approved"
        assert body["decision_reason"] == "looks fine"
        assert "message_id" in body

        from models import Message

        message_id = uuid.UUID(body["message_id"])
        message = (
            await session.execute(select(Message).where(Message.id == message_id))
        ).scalar_one()
        assert message.type == "note"
        assert message.payload == hold.payload
        assert message.sender_id == sender.id

    async def test_decide_uses_hold_snapshot_not_live_agents_row(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """TECH-5389 pluggable-auth revision (plan doc §15.4): the hold's
        own ``owner_sub`` snapshot is authoritative at decide time, not a
        live join to ``agents.owner_sub``. Mutate the sender's registered
        owner AFTER the hold exists and confirm decide still matches
        against the ORIGINAL owner (the snapshot), not the mutated one."""
        http_client, provider = client
        sender, hold = await _make_hold(session, sender_owner_sub="owner-original@example.com")

        from models import Agent

        sender_row = (
            await session.execute(select(Agent).where(Agent.id == sender.id))
        ).scalar_one()
        sender_row.owner_sub = "owner-mutated@example.com"
        await session.commit()

        # The mutated (current agents-row) owner must NOT be able to decide.
        provider.tokens["mutated-owner-token"] = _interactive_token("owner-mutated@example.com")
        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer mutated-owner-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 404

        # The original (snapshotted) owner still can.
        provider.tokens["original-owner-token"] = _interactive_token("owner-original@example.com")
        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer original-owner-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    async def test_already_decided_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session, sender_owner_sub="owner-again@example.com", status="approved"
        )
        provider.tokens["human-token"] = _interactive_token("owner-again@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 409
        assert resp.json()["error"] == "already_decided"
        assert resp.json()["status"] == "approved"

    async def test_expired_hold_returns_410(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session,
            sender_owner_sub="owner-expired@example.com",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        provider.tokens["human-token"] = _interactive_token("owner-expired@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 410

    async def test_awaiting_auto_review_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session, sender_owner_sub="owner-pending-auto@example.com", status="pending_auto"
        )
        provider.tokens["human-token"] = _interactive_token("owner-pending-auto@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 409
        assert resp.json()["error"] == "awaiting_auto_review"

    async def test_invalid_decision_returns_422(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(session, sender_owner_sub="owner-422@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-422@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "not-a-real-decision"},
        )
        assert resp.status_code == 422

    async def test_reason_over_length_returns_422(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(session, sender_owner_sub="owner-longreason@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-longreason@example.com")

        resp = await http_client.post(
            f"/approvals/{hold.id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "reason": "x" * 2001},
        )
        assert resp.status_code == 422


class TestListPendingEndpoint:
    async def test_owner_filtering_and_includes_held_text(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender_a, hold_a = await _make_hold(session, sender_owner_sub="owner-list-a@example.com")
        _sender_b, _hold_b = await _make_hold(session, sender_owner_sub="owner-list-b@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-list-a@example.com")

        resp = await http_client.get(
            "/approvals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 200
        body = resp.json()
        hold_ids = {h["hold_id"] for h in body["holds"]}
        assert str(hold_a.id) in hold_ids
        assert all(h["status"] == "pending_human" for h in body["holds"])
        matching = next(h for h in body["holds"] if h["hold_id"] == str(hold_a.id))
        assert matching["payload"] == hold_a.payload

    async def test_non_pending_human_holds_excluded(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session, sender_owner_sub="owner-list-approved@example.com", status="approved"
        )
        provider.tokens["human-token"] = _interactive_token("owner-list-approved@example.com")

        resp = await http_client.get(
            "/approvals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 200
        hold_ids = {h["hold_id"] for h in resp.json()["holds"]}
        assert str(hold.id) not in hold_ids


class TestReconcileOwnershipEndpoint:
    """TECH-5593 item 4's admin-triggered endpoint,
    ``POST /admin/agents/reconcile-ownership``. Auth-gate tests mirror
    ``TestAuthGate`` above but with the DELIBERATELY WIDER gate this route
    uses (interactive OR agent-jwt ``comms:admin`` -- unlike the
    approval-decision routes' hard interactive-only gate)."""

    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.post("/admin/agents/reconcile-ownership")
        assert resp.status_code == 401

    async def test_unverifiable_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.post(
            "/admin/agents/reconcile-ownership",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401

    async def test_agent_jwt_without_admin_scope_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-agent-sub", scopes=["comms:read", "comms:write"]
        )
        resp = await http_client.post(
            "/admin/agents/reconcile-ownership",
            headers={"Authorization": "Bearer agent-token"},
        )
        assert resp.status_code == 403

    async def test_agent_jwt_with_admin_scope_is_allowed(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Unlike the approval-decide/pending routes, this route DOES allow
        an agent-jwt caller through, provided it carries ``comms:admin`` --
        the wider gate documented on ``main.reconcile_ownership``."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token("admin-agent-sub", scopes=["comms:admin"])
        resp = await http_client.post(
            "/admin/agents/reconcile-ownership",
            headers={"Authorization": "Bearer agent-token"},
        )
        assert resp.status_code == 200

    async def test_interactive_caller_runs_reconciliation(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        await register_agent(
            session,
            sub="reconcile-endpoint-agent",
            owner_sub="owner-x@example.com",
            owner_email="owner-x@example.com",
            display_name="reconcile endpoint agent",
            accepted_types=["note"],
        )
        provider.tokens["human-token"] = _interactive_token("human@example.com")

        resp = await http_client.post(
            "/admin/agents/reconcile-ownership",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # The default OwnershipClient (AgentTableOwnershipClient) reads the
        # same agents.owner_sub column this endpoint is reconciling against
        # -- so this asserts the endpoint actually ran (checked the agent
        # just registered), not that anything drifted (nothing did).
        assert body == {"checked": 1, "updated": 0, "skipped_shared": 0, "errors": 0}

    async def test_invalid_limit_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("human@example.com")

        resp = await http_client.post(
            "/admin/agents/reconcile-ownership?limit=not-a-number",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 422
