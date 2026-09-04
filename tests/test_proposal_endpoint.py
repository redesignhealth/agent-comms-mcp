"""End-to-end tests for the non-MCP proposal HTTP surface (main.py,
TECH-5872/5875): ``POST /proposals`` and ``GET /proposals/pending``.

Own file, mirroring ``tests/test_approval_endpoint.py``'s Postgres fixture
block and fake-auth-provider idiom. Auth is exercised against
``main._auth_provider`` directly (a fake standing in for FastMCP's real
``MultiAuth.verify_token``), not a real Okta/agent-jwt signing round trip
-- these tests are about main.py's OWN gate logic on these two routes.
"""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.routing import Route

from models import AuditLog

# Real-Postgres fixtures (database_url, _migrated_schema, engine) are shared
# via tests/conftest.py (Argus review S15) -- this module opts in explicitly
# since conftest's `_migrated_schema` is deliberately not autouse globally.
pytestmark = pytest.mark.usefixtures("_migrated_schema")


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE TABLE proposal_holds, audit_log RESTART IDENTITY CASCADE")
        )
    yield


@pytest.fixture
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


# ``session`` fixture lives in tests/conftest.py (Argus review S10 -- this
# was the 5th byte-identical copy across the test suite).


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
    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") == "agent-jwt":
            return None
        return found


class _FakeAgentOnlyVerifier:
    """Stands in for one of ``MultiAuth.verifiers`` (real code: the default
    ``agent_jwt_hs256`` ``JWTVerifier``) -- verifies ONLY agent-jwt-issued
    tokens, mirroring ``_FakeInteractiveOnlyProvider``'s opposite restriction
    for ``.server``. Needed so ``main._verify_agent_token`` (Argus review
    S4's structural fix) has something real to iterate: it walks
    ``_auth_provider.verifiers`` directly, bypassing ``.server`` (Okta)
    entirely."""

    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") != "agent-jwt":
            return None
        return found


class _FakeAuthProvider:
    def __init__(self) -> None:
        self.tokens: dict[str, _FakeAccessToken] = {}
        self.server = _FakeInteractiveOnlyProvider(self)
        self.verifiers = [_FakeAgentOnlyVerifier(self)]

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        return self.tokens.get(token)


def _interactive_token(owner_email: str) -> _FakeAccessToken:
    return _FakeAccessToken({"iss": "https://agent-comms.example/mcp", "email": owner_email})


def _agent_jwt_token(
    sub: str, *, scopes: list[str] | None = None, owner_sub: str | None = None
) -> _FakeAccessToken:
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else [],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    return _FakeAccessToken(claims)


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
            Route("/proposals", main.submit_proposal, methods=["POST"]),
            Route("/proposals/pending", main.list_pending_proposals, methods=["GET"]),
            Route("/proposals/{proposal_id}", main.get_proposal, methods=["GET"]),
            Route(
                "/proposals/{proposal_id}/withdraw",
                main.withdraw_proposal_route,
                methods=["POST"],
            ),
            Route("/proposals/{hold_id}/decide", main.decide_proposal_route, methods=["POST"]),
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


_PROPOSAL_BODY = {
    "kind": "linear_progress_update",
    "action": {"action_type": "open_ticket", "target_id": "TECH-1"},
    "rationale": "because reasons",
    "confidence": "medium",
    "importance": "medium",
    "impact": "medium",
    "target_fingerprint": "fp1",
}


class TestSubmitAuthGate:
    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.post("/proposals", json=_PROPOSAL_BODY)
        assert resp.status_code == 401

    async def test_unverifiable_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer garbage"}
        )
        assert resp.status_code == 401

    async def test_interactive_token_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Opposite gate from ``/approvals/*``: proposals are submitted BY
        BOTS, not humans -- an interactive/Okta caller must be rejected."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 403

    async def test_interactive_token_rejection_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Mirrors test_approval_endpoint.py's
        test_agent_jwt_rejection_is_audited, for the opposite gate: an
        interactive/Okta caller on the bot-submission-only POST /proposals
        route is denied and the denial is audited (Argus review S4)."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_submit_not_agent_token"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

    async def test_agent_jwt_without_required_scope_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_missing_scope_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Mirrors test_interactive_token_rejection_is_audited /
        test_rate_limit_exceeded_is_audited for the third
        ``ALLOWED_DENIAL_REASONS`` entry: a verified agent-jwt token missing
        ``PROPOSAL_SUBMIT_SCOPE`` is denied and the denial is audited as
        ``denied.proposal_submit_missing_scope``."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_submit_missing_scope"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

    async def test_agent_jwt_with_required_scope_is_allowed(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["proposed_by_bot_id"] == "bot-1"


class TestSubmitProposal:
    async def test_missing_owner_sub_and_unregistered_bot_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token("bot-1", scopes=["comms:proposals:write"])
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "owner_sub_unresolvable"

    async def test_missing_action_target_id_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "action": {"action_type": "open_ticket"}}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422

    async def test_invalid_confidence_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "confidence": "extremely-sure"}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422

    async def test_non_json_body_returns_invalid_json_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals",
            content=b"not json at all",
            headers={
                "Authorization": "Bearer bot-token",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_json"

    async def test_non_dict_body_returns_invalid_body_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=[], headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_body"

    async def test_rationale_exceeding_max_length_returns_field_too_long(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "rationale": "x" * 4001}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert "exceeds" in resp.json()["detail"]

    async def test_target_fingerprint_exceeding_max_length_returns_field_too_long(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "target_fingerprint": "x" * 4001}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert "exceeds" in resp.json()["detail"]

    async def test_kind_exceeding_max_length_returns_field_too_long(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "kind": "x" * 201}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert "exceeds" in resp.json()["detail"]

    async def test_action_exceeding_max_bytes_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {
            **_PROPOSAL_BODY,
            "action": {
                "action_type": "open_ticket",
                "target_id": "TECH-1",
                "padding": "x" * 16_384,
            },
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert "exceeds" in resp.json()["detail"]

    async def test_action_target_id_exceeding_max_length_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {
            **_PROPOSAL_BODY,
            "action": {"action_type": "open_ticket", "target_id": "x" * 501},
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert "exceeds" in resp.json()["detail"]

    async def test_action_action_type_exceeding_max_length_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {
            **_PROPOSAL_BODY,
            "action": {"action_type": "x" * 501, "target_id": "TECH-1"},
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert "exceeds" in resp.json()["detail"]

    async def test_unsupported_kind_returns_422_not_500(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """``kind`` is an open TEXT column at the DB level, but the service
        only admits "linear_progress_update" today (``_derive_proposal_priority``
        raises for anything else). DESIGN.md/models.py previously advertised
        "arc_board_change" as a valid example kind even though the service
        never actually accepted it -- a caller following that (incorrect)
        documentation must get a client-error 422, not an unhandled 500."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "kind": "arc_board_change"}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422

    async def test_interactive_token_with_proposal_scope_still_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """An interactive/Okta token carrying (an irrelevant, since Okta
        tokens never carry agent-jwt scopes in practice) `scopes` claim
        with `comms:proposals:write` still can't submit -- the structural
        gate (Argus review S4) rejects it by VERIFICATION PATH, never by
        inspecting what scope claim it happens to carry."""
        http_client, provider = client
        token = _interactive_token("owner-a@example.com")
        token.claims["scopes"] = ["comms:proposals:write"]
        provider.tokens["human-token"] = token
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 403

    async def test_priority_in_body_is_ignored(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {
            **_PROPOSAL_BODY,
            "action": {**_PROPOSAL_BODY["action"], "action_type": "close_ticket"},
            "priority": "low",
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        # close_ticket server-derives "high" regardless of the caller's
        # top-level "priority": "low" in the request body.
        assert resp.json()["priority"] == "high"

    async def test_rate_limit_exceeded_returns_429(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        import service

        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        for i in range(service.MAX_PROPOSALS_PER_BOT_PER_WINDOW):
            body = {
                **_PROPOSAL_BODY,
                "action": {**_PROPOSAL_BODY["action"], "target_id": f"TECH-{i}"},
            }
            resp = await http_client.post(
                "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
            )
            assert resp.status_code == 200

        body = {
            **_PROPOSAL_BODY,
            "action": {
                **_PROPOSAL_BODY["action"],
                "target_id": f"TECH-{service.MAX_PROPOSALS_PER_BOT_PER_WINDOW}",
            },
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 429

    async def test_rate_limit_exceeded_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        import service

        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        for i in range(service.MAX_PROPOSALS_PER_BOT_PER_WINDOW):
            body = {
                **_PROPOSAL_BODY,
                "action": {**_PROPOSAL_BODY["action"], "target_id": f"TECH-{i}"},
            }
            resp = await http_client.post(
                "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
            )
            assert resp.status_code == 200

        body = {
            **_PROPOSAL_BODY,
            "action": {
                **_PROPOSAL_BODY["action"],
                "target_id": f"TECH-{service.MAX_PROPOSALS_PER_BOT_PER_WINDOW}",
            },
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 429

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.action == "denied.proposal_rate_limited")
                )
            )
            .scalars()
            .all()
        )
        assert rows


class TestListPendingAuthGate:
    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.get("/proposals/pending")
        assert resp.status_code == 401

    async def test_agent_jwt_token_returns_403_even_with_comms_admin_scope(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Same hard interactive-only gate as ``GET /approvals/pending`` --
        a bot's agent-jwt token, even with ``comms:admin``, can't list."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-bot", scopes=["comms:admin", "comms:proposals:write"]
        )
        resp = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_rejection_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Mirrors test_approval_endpoint.py's own test of the same name
        (Argus review S4): a bot's agent-jwt token on the interactive-only
        GET /proposals/pending route is denied and the denial is audited."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token("some-bot")
        resp = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposals_requires_interactive"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows


class TestListPendingProposals:
    async def test_owner_filtering(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        provider.tokens["other-human-token"] = _interactive_token("owner-b@example.com")

        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200

        own = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert own.status_code == 200
        assert len(own.json()["proposals"]) == 1

        other = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer other-human-token"}
        )
        assert other.status_code == 200
        assert other.json()["proposals"] == []

    async def test_approved_proposals_excluded(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        body = {
            **_PROPOSAL_BODY,
            "action": {
                **_PROPOSAL_BODY["action"],
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p1",
            },
        }
        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value=_PROPOSAL_BODY["target_fingerprint"]),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()),
        ):
            submit_resp = await http_client.post(
                "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
            )
        assert submit_resp.status_code == 200
        # TECH-5873 Argus review B1: the auto-judge's "approved" verdict is
        # never itself persisted -- it resolves synchronously to "applied"
        # here (matching fingerprint, successful Linear write).
        assert submit_resp.json()["status"] == "applied"

        pending = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert pending.json()["proposals"] == []

    async def test_invalid_limit_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        resp = await http_client.get(
            "/proposals/pending?limit=abc", headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_limit"

    async def test_has_more_true_when_more_than_limit_pending(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Mirrors ``test_service.py``'s
        ``TestListPendingApprovalHolds::test_all_expired_page_reports_has_more_false``
        family: inserting ``limit + 1`` pending proposals and requesting
        exactly ``limit`` must report ``has_more=True`` and return only
        ``limit`` rows -- not silently return everything."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        limit = 2
        for i in range(limit + 1):
            body = {
                **_PROPOSAL_BODY,
                "action": {**_PROPOSAL_BODY["action"], "target_id": f"TECH-{i}"},
            }
            resp = await http_client.post(
                "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
            )
            assert resp.status_code == 200

        pending = await http_client.get(
            f"/proposals/pending?limit={limit}",
            headers={"Authorization": "Bearer human-token"},
        )
        assert pending.status_code == 200
        body = pending.json()
        assert len(body["proposals"]) == limit
        assert body["has_more"] is True


async def _submit_via_http(
    http_client: httpx.AsyncClient,
    provider: _FakeAuthProvider,
    *,
    owner_sub: str = "owner-a@example.com",
    target_id: str = "TECH-1",
) -> str:
    provider.tokens["bot-token"] = _agent_jwt_token(
        "bot-1", scopes=["comms:proposals:write"], owner_sub=owner_sub
    )
    body = {**_PROPOSAL_BODY, "action": {**_PROPOSAL_BODY["action"], "target_id": target_id}}
    resp = await http_client.post(
        "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
    )
    assert resp.status_code == 200
    proposal_id: str = resp.json()["proposal_id"]
    return proposal_id


class TestDecideProposalEndpoint:
    async def test_uniform_404_for_unknown_hold(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            f"/proposals/{uuid.uuid4()}/decide",
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
            "/proposals/not-a-uuid/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_not_your_hold(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-b@example.com")

        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_bot_token_cannot_decide(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """A bot can never self-approve its own proposal: the decide route
        is gated on the same interactive-only check as ``/approvals/*``,
        so an agent-jwt token is rejected structurally, even with every
        scope."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["agent-token"] = _agent_jwt_token(
            "bot-1",
            scopes=["comms:admin", "comms:proposals:write"],
            owner_sub="owner-a@example.com",
        )
        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer agent-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 403

    async def test_reject_without_decision_note_returns_400(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "decision_note_required"

    async def test_reject_with_decision_note_returns_rejected(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "not needed"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "rejected"
        assert body["decision_note"] == "not needed"

    async def test_approve_matching_fingerprint_applies(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp1"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            resp = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "applied"
        mock_apply.assert_awaited_once()

    async def test_approve_stale_fingerprint_returns_stale_without_calling_linear_apply(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="a-completely-different-fingerprint"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            resp = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "stale"
        mock_apply.assert_not_awaited()

    async def test_approve_linear_failure_returns_apply_failed(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        from linear_client import LinearAPIError

        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp1"),
            ),
            patch(
                "service.linear_client.apply_progress_update",
                AsyncMock(side_effect=LinearAPIError("linear unavailable")),
            ),
        ):
            resp = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "apply_failed"
        # Argus review round-5 S4: the raw LinearAPIError message is no
        # longer returned verbatim to API callers -- unrecognized messages
        # map to the generic allowlisted message (see `_sanitize_apply_error`).
        assert body["apply_error"] == "Linear API returned an error"

    async def test_retrying_applied_hold_does_not_double_call_linear(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        with (
            patch(
                "service.linear_client.fetch_current_fingerprint",
                AsyncMock(return_value="fp1"),
            ),
            patch("service.linear_client.apply_progress_update", AsyncMock()) as mock_apply,
        ):
            first = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
            second = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "approve"},
            )
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["status"] == "applied"
        assert second.json()["status"] == "applied"
        mock_apply.assert_awaited_once()

    async def test_deciding_already_rejected_hold_returns_409(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        reject_resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "no thanks"},
        )
        assert reject_resp.status_code == 200

        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 409
        assert resp.json()["status"] == "rejected"

    async def test_deciding_already_applying_hold_returns_409(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Argus review round-5 S3: only ``test_proposal_service.py`` had
        coverage for the ``"applying"``-observed-mid-decide 409 path
        (``test_hold_resolved_during_apply_window_raises_already_decided``,
        ``test_decide_on_already_applying_hold_raises_already_decided``) --
        nothing exercised it through the actual HTTP route, which is what
        callers other than this module's own test suite actually hit."""
        from models import ProposalHold

        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        hold = await session.get(ProposalHold, uuid.UUID(proposal_id))
        assert hold is not None
        hold.status = "applying"
        # `ck_proposal_holds_decision_consistency` requires all three
        # decision fields set together whenever status != "pending".
        hold.decided_at = hold.created_at
        hold.decided_by_actor_id = "owner-a@example.com"
        hold.decision_source = "human"
        await session.commit()

        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 409
        assert resp.json() == {"error": "already_decided", "status": "applying"}


class TestGetProposalEndpoint:
    """``GET /proposals/{proposal_id}`` (TECH-6018): bot-only, sender-only
    polling of a proposal's own status after the fact."""

    async def test_interactive_token_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Opposite gate from ``/proposals/{id}/decide``: this route is for
        the bot side, not a human reviewer."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 403

    async def test_uniform_404_for_unknown_hold(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.get(
            f"/proposals/{uuid.uuid4()}", headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_malformed_proposal_id(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.get(
            "/proposals/not-a-uuid", headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_a_different_bots_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["other-bot-token"] = _agent_jwt_token(
            "bot-2", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": "Bearer other-bot-token"}
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_submitting_bot_can_read_its_own_pending_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"

    async def test_submitting_bot_can_read_its_own_decided_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """The whole point of this route: the outcome of a human decide
        call is readable by the submitting bot later, not just in that
        decide call's own response."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        decide_resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "no thanks"},
        )
        assert decide_resp.status_code == 200

        resp = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"
        assert resp.json()["decision_note"] == "no thanks"


class TestWithdrawProposalEndpoint:
    """``POST /proposals/{proposal_id}/withdraw`` (TECH-6018): bot-only,
    sender-only retraction of a still-pending proposal."""

    async def test_interactive_token_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer human-token"},
            json={},
        )
        assert resp.status_code == 403

    async def test_uniform_404_for_unknown_hold(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            f"/proposals/{uuid.uuid4()}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_uniform_404_for_a_different_bots_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["other-bot-token"] = _agent_jwt_token(
            "bot-2", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer other-bot-token"},
            json={},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_submitting_bot_can_withdraw_its_own_pending_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={"reason": "superseded"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "withdrawn"
        assert body["decision_source"] == "bot"
        assert body["decision_note"] == "superseded"

    async def test_withdraw_without_body_succeeds_with_no_reason(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """``reason`` is optional -- an empty/absent body must not 422."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            content=b"",
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "withdrawn"

    async def test_withdraw_already_decided_returns_409(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        decide_resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "no thanks"},
        )
        assert decide_resp.status_code == 200

        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={},
        )
        assert resp.status_code == 409
        assert resp.json() == {"error": "already_decided", "status": "rejected"}

    async def test_withdraw_then_resubmit_same_target_creates_fresh_pending_proposal(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, target_id="TECH-99")
        withdraw_resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={"reason": "stale"},
        )
        assert withdraw_resp.status_code == 200

        resubmit_resp = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "action": {**_PROPOSAL_BODY["action"], "target_id": "TECH-99"}},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resubmit_resp.status_code == 200
        resubmitted = resubmit_resp.json()
        assert resubmitted["proposal_id"] != proposal_id
        assert resubmitted["status"] == "pending"
