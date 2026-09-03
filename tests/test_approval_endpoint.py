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

import os
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.routing import Route

from exceptions import AgentRetiredError, ConversationArchivedError
from models import ApprovalHold, AuditLog, Conversation, Participant
from service import register_agent

# Real-Postgres fixtures (database_url, _migrated_schema, engine) are shared
# via tests/conftest.py (Argus review S15) -- this module opts in explicitly
# since conftest's `_migrated_schema` is deliberately not autouse globally.
pytestmark = pytest.mark.usefixtures("_migrated_schema")


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
                "/approvals/{hold_id}/conversation",
                main.get_hold_conversation,
                methods=["GET"],
            ),
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
    sender_display_name: str = "hold sender",
) -> tuple[Any, ApprovalHold]:
    sender_sub = f"hold-sender-{uuid.uuid4()}"
    sender = await register_agent(
        session,
        sub=sender_sub,
        base_sub=sender_sub,
        owner_sub=sender_owner_sub,
        owner_email=sender_owner_sub,
        display_name=sender_display_name,
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
        kind="message",
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

    async def test_agent_retired_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        main: Any,
        session: AsyncSession,
    ) -> None:
        """TECH-5735: decide_hold's invite-branch re-validation can raise
        AgentRetiredError (the target was retired during the hold's
        pending window) -- newly reachable via this endpoint since this
        PR. Patches service.decide_hold directly (mirroring Argus's own
        suggested approach) rather than driving a real invite-hold
        through the registry seam, since main.py performs no pre-check of
        its own before calling into the service layer."""
        http_client, provider = client
        _sender, hold = await _make_hold(session, sender_owner_sub="owner-retired@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-retired@example.com")

        with patch.object(
            main.service,
            "decide_hold",
            AsyncMock(side_effect=AgentRetiredError(reason="denied.target_agent_retired")),
        ):
            resp = await http_client.post(
                f"/approvals/{hold.id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
        assert resp.status_code == 409
        assert resp.json() == {
            "error": "agent_retired",
            "detail": "agent retired: this agent has been retired and is no longer reachable",
        }

    async def test_conversation_archived_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        main: Any,
        session: AsyncSession,
    ) -> None:
        """TECH-5887: decide_hold's approve path raises
        ConversationArchivedError when the hold's conversation was
        archived while it sat pending_human. Mocked the same way as
        test_agent_retired_returns_409 -- no DB fixture needed, since
        main.py performs no pre-check of its own before calling into the
        service layer, and this endpoint-layer test only needs to verify
        the except-branch's status code and body shape, not the archived
        guard's own logic (already covered in test_service.py)."""
        http_client, provider = client
        _sender, hold = await _make_hold(session, sender_owner_sub="owner-archived@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-archived@example.com")

        with patch.object(
            main.service,
            "decide_hold",
            AsyncMock(
                side_effect=ConversationArchivedError(
                    "conversation_archived: this conversation has been archived and no "
                    "longer accepts write operations"
                )
            ),
        ):
            resp = await http_client.post(
                f"/approvals/{hold.id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
        assert resp.status_code == 409
        assert resp.json() == {"error": "conversation_archived"}

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
        _sender_a, hold_a = await _make_hold(
            session,
            sender_owner_sub="owner-list-a@example.com",
            sender_display_name="hold sender a",
        )
        _sender_b, _hold_b = await _make_hold(
            session,
            sender_owner_sub="owner-list-b@example.com",
            sender_display_name="hold sender b",
        )
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
            base_sub="reconcile-endpoint-agent",
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

    async def test_negative_limit_returns_422_not_500(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Argus round-1 BLOCKING catch: Postgres treats a negative SQL
        LIMIT as LIMIT ALL, so `?limit=-1` must be rejected with a clear
        422 at this layer -- not silently clamped deep inside the service
        call with no feedback, and not a 500 from an int() that parsed
        fine but produced a value the query never validated."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("human@example.com")

        resp = await http_client.post(
            "/admin/agents/reconcile-ownership?limit=-1",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 422

    async def test_zero_limit_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("human@example.com")

        resp = await http_client.post(
            "/admin/agents/reconcile-ownership?limit=0",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 422


class TestHoldConversationEndpoint:
    """``GET /approvals/{hold_id}/conversation`` (TECH-5751/TECH-5752):
    the decision page's "To" data source."""

    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.get(f"/approvals/{uuid.uuid4()}/conversation")
        assert resp.status_code == 401

    async def test_uniform_404_for_unknown_hold(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.get(
            f"/approvals/{uuid.uuid4()}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_malformed_hold_id(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.get(
            "/approvals/not-a-uuid/conversation",
            headers={"Authorization": "Bearer human-token"},
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

        resp = await http_client.get(
            f"/approvals/{hold.id}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_agent_jwt_token_returns_403_even_with_comms_admin_scope(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Same structural gate as TestAuthGate's identically-named test on
        /approvals/pending -- this route shares _authenticate_approval_caller,
        but Argus round-1 flagged that the gate had no per-route regression
        test of its own."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-agent-sub", scopes=["comms:admin", "comms:read", "comms:write"]
        )
        resp = await http_client.get(
            f"/approvals/{uuid.uuid4()}/conversation",
            headers={"Authorization": "Bearer agent-token"},
        )
        assert resp.status_code == 403

    async def test_expired_hold_returns_410(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session,
            sender_owner_sub="owner-expired@example.com",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        provider.tokens["human-token"] = _interactive_token("owner-expired@example.com")

        resp = await http_client.get(
            f"/approvals/{hold.id}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 410
        assert resp.json() == {"error": "expired"}

    async def test_already_decided_hold_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session, sender_owner_sub="owner-decided@example.com", status="rejected"
        )
        provider.tokens["human-token"] = _interactive_token("owner-decided@example.com")

        resp = await http_client.get(
            f"/approvals/{hold.id}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 409
        assert resp.json() == {"error": "already_decided", "status": "rejected"}

    async def test_pending_auto_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        _sender, hold = await _make_hold(
            session, sender_owner_sub="owner-pending-auto@example.com", status="pending_auto"
        )
        provider.tokens["human-token"] = _interactive_token("owner-pending-auto@example.com")

        resp = await http_client.get(
            f"/approvals/{hold.id}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 409
        assert resp.json() == {"error": "awaiting_auto_review"}

    async def test_returns_participants_for_the_holds_conversation(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        sender, hold = await _make_hold(session, sender_owner_sub="owner-participants@example.com")
        recipient_sub = f"hold-recipient-{uuid.uuid4()}"
        recipient = await register_agent(
            session,
            sub=recipient_sub,
            base_sub=recipient_sub,
            owner_sub="owner-recipient@example.com",
            owner_email="owner-recipient@example.com",
            display_name="hold recipient",
            accepted_types=["note"],
        )
        session.add(
            Participant(
                conversation_id=hold.conversation_id,
                agent_id=sender.id,
                role="member",
                status="active",
            )
        )
        session.add(
            Participant(
                conversation_id=hold.conversation_id,
                agent_id=recipient.id,
                role="member",
                status="invited",
            )
        )
        await session.commit()
        provider.tokens["human-token"] = _interactive_token("owner-participants@example.com")

        resp = await http_client.get(
            f"/approvals/{hold.id}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["conversation_id"] == str(hold.conversation_id)
        participants_by_name = {p["display_name"]: p for p in body["participants"]}
        assert set(participants_by_name) == {"hold sender", "hold recipient"}
        assert participants_by_name["hold sender"] == {
            "agent_id": str(sender.id),
            "display_name": "hold sender",
            "role": "member",
            "status": "active",
        }
        assert participants_by_name["hold recipient"] == {
            "agent_id": str(recipient.id),
            "display_name": "hold recipient",
            "role": "member",
            "status": "invited",
        }
        # No message content, no read-cursor field -- this endpoint is
        # participant metadata only (TECH-5751's narrower scope vs.
        # comms_get_conversation).
        assert "messages" not in body
        for participant in body["participants"]:
            assert "last_read_seq" not in participant

    async def test_excludes_left_and_declined_participants(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        sender, hold = await _make_hold(session, sender_owner_sub="owner-departed@example.com")
        left_sub = f"hold-left-{uuid.uuid4()}"
        left_agent = await register_agent(
            session,
            sub=left_sub,
            base_sub=left_sub,
            owner_sub="owner-left@example.com",
            owner_email="owner-left@example.com",
            display_name="left agent",
            accepted_types=["note"],
        )
        declined_sub = f"hold-declined-{uuid.uuid4()}"
        declined_agent = await register_agent(
            session,
            sub=declined_sub,
            base_sub=declined_sub,
            owner_sub="owner-declined@example.com",
            owner_email="owner-declined@example.com",
            display_name="declined agent",
            accepted_types=["note"],
        )
        session.add(
            Participant(
                conversation_id=hold.conversation_id,
                agent_id=sender.id,
                role="member",
                status="active",
            )
        )
        session.add(
            Participant(
                conversation_id=hold.conversation_id,
                agent_id=left_agent.id,
                role="member",
                status="left",
            )
        )
        session.add(
            Participant(
                conversation_id=hold.conversation_id,
                agent_id=declined_agent.id,
                role="member",
                status="declined",
            )
        )
        await session.commit()
        provider.tokens["human-token"] = _interactive_token("owner-departed@example.com")

        resp = await http_client.get(
            f"/approvals/{hold.id}/conversation",
            headers={"Authorization": "Bearer human-token"},
        )
        assert resp.status_code == 200
        display_names = {p["display_name"] for p in resp.json()["participants"]}
        assert display_names == {"hold sender"}
