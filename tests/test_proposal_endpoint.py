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
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.routing import Route

import plugins
import service
from models import AuditLog, ProposalHold
from plugins import (
    FINGERPRINT_DIGEST,
    FINGERPRINT_UNAVAILABLE,
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalFingerprint,
    ProposalTargetError,
    ProposalVerdict,
)
from tests.proposal_judge_fakes import FakeProposalJudge

# Real-Postgres fixtures (database_url, _migrated_schema, engine) are shared
# via tests/conftest.py (Argus review S15) -- this module opts in explicitly
# since conftest's `_migrated_schema` is deliberately not autouse globally.
pytestmark = pytest.mark.usefixtures("_migrated_schema")


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


_DEFAULT_SUBMIT_TIME_FINGERPRINT = "fp-submit-time-default"


@pytest.fixture(autouse=True)
def _default_proposal_judge(monkeypatch: pytest.MonkeyPatch) -> FakeProposalJudge:
    """Every proposal route in ``main.py`` resolves
    ``plugins.get_proposal_judge()`` fresh per request -- monkeypatch it to
    always return the SAME ``FakeProposalJudge`` instance for the duration
    of one test, so a test can reconfigure its attributes (read at call
    time, not construction time) to drive a specific submit/decide outcome
    across multiple requests in the same test. Defaults to a stable digest
    fingerprint and a never-approves verdict, mirroring
    ``_DEFAULT_SUBMIT_TIME_FINGERPRINT``'s old role. Tests that DO care
    about a specific fingerprint match/mismatch or apply outcome
    reconfigure this fixture's returned object directly."""
    fake = FakeProposalJudge(
        fingerprint_result=ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest=_DEFAULT_SUBMIT_TIME_FINGERPRINT
        )
    )
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: fake)
    return fake


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
            Route("/proposals/history", main.list_proposal_history, methods=["GET"]),
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


# action_type is "close_ticket", not "open_ticket" (TECH-5873
# redefinition): every test in this file using this default body is
# exercising GENERIC HTTP-layer mechanics (auth gates, validation,
# dedup, pending/history listing) against the fixture's own
# FakeProposalJudge, not any real judge's rule content -- kept as
# "close_ticket" for continuity with the pre-seam default body shape.
_PROPOSAL_BODY = {
    "kind": "linear_progress_update",
    "action": {"action_type": "close_ticket", "target_id": "TECH-1"},
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
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """``kind`` is an open TEXT column at the DB level; whether it's
        admitted at all is entirely up to the configured judge's
        ``classify()``, which raises ``ValueError`` for a kind it doesn't
        recognize -- must surface as a client-error 422, not an unhandled
        500."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        _default_proposal_judge.classify_raises = ValueError("unsupported kind: 'arc_board_change'")
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
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        _default_proposal_judge.classify_result = ProposalClassification(priority="high")
        body = {
            **_PROPOSAL_BODY,
            "action": {**_PROPOSAL_BODY["action"], "action_type": "close_ticket"},
            "priority": "low",
        }
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        # The judge server-derives "high" regardless of the caller's
        # top-level "priority": "low" in the request body.
        assert resp.json()["priority"] == "high"

    async def test_target_fingerprint_in_body_is_ignored(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Bug fix: ``target_fingerprint`` in the request body is
        DEPRECATED and ignored -- the value actually stored (and later
        compared against at decide time) is always computed server-side.
        Mirrors ``test_priority_in_body_is_ignored`` above for this
        field: submit with a body value that could never match the
        judge's server-computed fingerprint, then decide with that SAME
        server-computed value re-fetched -- reaching ``"applied"`` (not
        ``"stale"``) proves the server-computed value, not the body
        value, was stored and matched."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        body = {
            **_PROPOSAL_BODY,
            "action": {**_PROPOSAL_BODY["action"], "target_id": "TECH-FINGERPRINT-IGNORED"},
            "target_fingerprint": "body-value",
        }
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="server-value"
        )
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        proposal_id = resp.json()["proposal_id"]

        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )
        decide_resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert decide_resp.json()["status"] == "applied"

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

    async def test_fingerprint_unavailable_during_submission_returns_422(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round-3 B1: service.create_proposal's server-side
        target-fingerprint fetch can fail (target doesn't exist, target
        system error) -- must surface as a client-facing status code with
        the judge's own sanitized message, never a raw error string."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_UNAVAILABLE,
            error=ProposalTargetError(
                status_code=422,
                error_code="invalid_request",
                detail="Linear returned an error",
                log_detail="target issue does not exist",
            ),
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_request"
        assert resp.json()["detail"] == "Linear returned an error"

    async def test_fingerprint_unavailable_during_submission_returns_500_sanitized(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round-3 B1: a missing-credential-shaped judge
        failure must return 500 without leaking the internal env-var
        name."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_UNAVAILABLE,
            error=ProposalTargetError(
                status_code=500,
                error_code="server_configuration_error",
                detail="server configuration error",
                log_detail="LINEAR_API_TOKEN is not configured",
            ),
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 500
        assert resp.json()["error"] == "server_configuration_error"
        assert resp.json()["detail"] == "server configuration error"

    async def test_fingerprint_unavailable_during_submission_returns_503_sanitized(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round-3 B1: a transport-failure-shaped judge
        failure must return 503 without leaking raw transport details."""
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_UNAVAILABLE,
            error=ProposalTargetError(
                status_code=503,
                error_code="service_unavailable",
                detail="Linear API unavailable",
                log_detail="Linear API request failed: connection refused",
            ),
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 503
        assert resp.json()["error"] == "service_unavailable"
        assert resp.json()["detail"] == "Linear API unavailable"


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
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
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
        _default_proposal_judge.judge_result = ProposalVerdict(
            approved=True, decision_note="auto-approved"
        )
        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )
        submit_resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert submit_resp.status_code == 200
        # TECH-5873 Argus review B1: the auto-judge's "approved" verdict is
        # never itself persisted -- it resolves synchronously to "applied"
        # here (matching fingerprint, successful write).
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


class TestProposalHistoryAuthGate:
    async def test_missing_token_returns_401(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _provider = client
        resp = await http_client.get("/proposals/history")
        assert resp.status_code == 401

    async def test_agent_jwt_token_returns_403(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Same hard interactive-only gate as ``GET /proposals/pending`` --
        a bot's agent-jwt token can't list history either."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-bot", scopes=["comms:proposals:write"]
        )
        resp = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_token_returns_403_even_with_comms_admin_scope(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Argus review round 1 (TECH-6030 PR), mirroring
        ``TestListPendingAuthGate``'s own test of the same name: the
        interactive-only gate has no scope escape hatch, not even
        ``comms:admin``."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token(
            "some-bot", scopes=["comms:admin", "comms:proposals:write"]
        )
        resp = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403

    async def test_agent_jwt_rejection_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Argus review round 1 (TECH-6030 PR), mirroring
        ``TestListPendingAuthGate``'s own test of the same name: a bot's
        agent-jwt token on this interactive-only route is denied AND the
        denial is audited under its own ``surface="proposals_history"``
        action name (distinct from ``pending``'s
        ``denied.proposals_requires_interactive``), so the two routes'
        bot-token denials stay distinguishable in the audit trail."""
        http_client, provider = client
        provider.tokens["agent-token"] = _agent_jwt_token("some-bot")
        resp = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer agent-token"}
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposals_history_requires_interactive"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows


class TestListProposalHistory:
    async def test_owner_filtering(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        provider.tokens["other-human-token"] = _interactive_token("owner-b@example.com")

        decide_resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "not needed"},
        )
        assert decide_resp.status_code == 200

        own = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer human-token"}
        )
        assert own.status_code == 200
        assert len(own.json()["proposals"]) == 1
        assert own.json()["proposals"][0]["status"] == "rejected"

        other = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer other-human-token"}
        )
        assert other.status_code == 200
        assert other.json()["proposals"] == []

    async def test_pending_proposals_excluded(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        history = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer human-token"}
        )
        assert history.status_code == 200
        assert history.json()["proposals"] == []

        pending = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert len(pending.json()["proposals"]) == 1

    async def test_withdrawn_proposal_included(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        withdraw_resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={"reason": "superseded"},
        )
        assert withdraw_resp.status_code == 200

        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        history = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer human-token"}
        )
        assert history.status_code == 200
        body = history.json()["proposals"]
        assert len(body) == 1
        assert body[0]["status"] == "withdrawn"
        assert body[0]["decided_by_actor_id"] == "bot-1"

    async def test_invalid_limit_returns_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        resp = await http_client.get(
            "/proposals/history?limit=abc", headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_limit"

    async def test_non_positive_limit_is_silently_clamped_to_one(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Argus review round 1 (TECH-6030 PR): ``limit=0``/``limit=-5``
        parse as valid ints, so they never hit the 422 branch above --
        document the actual (intentional) behavior, that the service layer
        silently clamps them up to 1, rather than leaving it untested."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        for i in range(2):
            proposal_id = await _submit_via_http(
                http_client, provider, owner_sub="owner-a@example.com", target_id=f"TECH-{i}"
            )
            decide_resp = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "reject", "decision_note": "not needed"},
            )
            assert decide_resp.status_code == 200

        for bad_limit in (0, -5):
            resp = await http_client.get(
                f"/proposals/history?limit={bad_limit}",
                headers={"Authorization": "Bearer human-token"},
            )
            assert resp.status_code == 200
            assert len(resp.json()["proposals"]) == 1

    async def test_all_terminal_statuses_included(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round 1 (TECH-6030 PR), endpoint-level mirror of the
        same-named service-layer test: drive one proposal each to
        ``applied``/``apply_failed``/``stale`` via the live decide route and
        confirm all three surface through ``GET /proposals/history``.

        ``target_fingerprint`` is server-computed at submission time via
        the injected judge, so each submission below reconfigures the
        shared fixture judge's fingerprint independently -- rather than
        trusting the (now-ignored) request body field. The APPLIED/
        APPLY_FAILED cases use the SAME digest at both submit and decide
        time (a genuinely unchanged target); STALE deliberately uses two
        DIFFERENT digests, to prove a real mismatch."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-applied-match"
        )
        applied_id = await _submit_via_http(
            http_client, provider, owner_sub="owner-a@example.com", target_id="APPLIED"
        )
        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )
        resp = await http_client.post(
            f"/proposals/{applied_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.json()["status"] == "applied"

        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-apply-failed-match"
        )
        apply_failed_id = await _submit_via_http(
            http_client, provider, owner_sub="owner-a@example.com", target_id="APPLY_FAILED"
        )
        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="Linear API returned an error",
            log_detail="linear unavailable",
        )
        resp = await http_client.post(
            f"/proposals/{apply_failed_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.json()["status"] == "apply_failed"

        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp-original"
        )
        stale_id = await _submit_via_http(
            http_client, provider, owner_sub="owner-a@example.com", target_id="STALE"
        )
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="a-completely-different-fingerprint"
        )
        resp = await http_client.post(
            f"/proposals/{stale_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.json()["status"] == "stale"

        history = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer human-token"}
        )
        assert history.status_code == 200
        statuses_by_target = {
            p["action"]["target_id"]: p["status"] for p in history.json()["proposals"]
        }
        assert statuses_by_target == {
            "APPLIED": "applied",
            "APPLY_FAILED": "apply_failed",
            "STALE": "stale",
        }

    async def test_ordered_newest_decided_first(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Argus review round 1 (TECH-6030 PR), endpoint-level mirror of the
        same-named service-layer test."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        first_id = await _submit_via_http(
            http_client, provider, owner_sub="owner-a@example.com", target_id="FIRST"
        )
        await http_client.post(
            f"/proposals/{first_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "not needed"},
        )
        second_id = await _submit_via_http(
            http_client, provider, owner_sub="owner-a@example.com", target_id="SECOND"
        )
        await http_client.post(
            f"/proposals/{second_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "not needed"},
        )

        history = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer human-token"}
        )
        target_ids = [p["action"]["target_id"] for p in history.json()["proposals"]]
        assert target_ids == ["SECOND", "FIRST"]

    async def test_has_more_true_when_more_than_limit_decided(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        limit = 2
        for i in range(limit + 1):
            proposal_id = await _submit_via_http(
                http_client, provider, owner_sub="owner-a@example.com", target_id=f"TECH-{i}"
            )
            decide_resp = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "reject", "decision_note": "not needed"},
            )
            assert decide_resp.status_code == 200

        history = await http_client.get(
            f"/proposals/history?limit={limit}",
            headers={"Authorization": "Bearer human-token"},
        )
        assert history.status_code == 200
        body = history.json()
        assert len(body["proposals"]) == limit
        assert body["has_more"] is True

    async def test_has_more_false_when_at_or_below_limit(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """Argus review round 1 (TECH-6030 PR): endpoint-level mirror of the
        same-named service-layer test -- no prior test in this class
        exercised the ``has_more=False`` path."""
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        limit = 2
        for i in range(limit):
            proposal_id = await _submit_via_http(
                http_client, provider, owner_sub="owner-a@example.com", target_id=f"TECH-{i}"
            )
            decide_resp = await http_client.post(
                f"/proposals/{proposal_id}/decide",
                headers={"Authorization": "Bearer human-token"},
                json={"decision": "reject", "decision_note": "not needed"},
            )
            assert decide_resp.status_code == 200

        history = await http_client.get(
            f"/proposals/history?limit={limit}",
            headers={"Authorization": "Bearer human-token"},
        )
        assert history.status_code == 200
        body = history.json()
        assert len(body["proposals"]) == limit
        assert body["has_more"] is False


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
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """``target_fingerprint`` is server-computed at submission time via
        the injected judge: the submit and the later decide below share
        the SAME fixture judge instance and happen to agree on the digest,
        representing a target that hasn't changed."""
        http_client, provider = client
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp1"
        )
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )
        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "applied"
        assert len(_default_proposal_judge.apply_calls) == 1

    async def test_approve_stale_fingerprint_returns_stale_without_calling_apply(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Explicit submit-time fingerprint, matching
        ``test_approve_matching_fingerprint_applies``/
        ``test_approve_apply_failure_returns_apply_failed`` above --
        self-contained rather than implicitly relying on the autouse
        ``_default_proposal_judge`` fixture's default digest."""
        http_client, provider = client
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp1"
        )
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="a-completely-different-fingerprint"
        )
        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "stale"
        assert _default_proposal_judge.apply_calls == []

    async def test_approve_apply_failure_returns_apply_failed(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        http_client, provider = client
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp1"
        )
        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="Linear API returned an error",
            log_detail="linear unavailable",
        )
        resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "approve"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "apply_failed"
        # Argus review round-5 S4: the raw upstream message is no longer
        # returned verbatim to API callers -- only the judge's own
        # allowlisted caller_error is.
        assert body["apply_error"] == "Linear API returned an error"

    async def test_retrying_applied_hold_does_not_double_apply(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        http_client, provider = client
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="fp1"
        )
        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )

        proposal_id = await _submit_via_http(http_client, provider, owner_sub="owner-a@example.com")
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
        assert len(_default_proposal_judge.apply_calls) == 1

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

    async def test_interactive_token_rejection_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Guards the ``surface="get"`` literal threaded through
        ``_authenticate_proposal_submitter`` -> ``audit_denied_proposal_submission``
        (Argus review round-2 suggestion): a typo in that literal would
        raise a ``ValueError`` (unioned into ``PROPOSAL_SUBMITTER_SURFACES``)
        rather than silently misrecording as a ``submit`` denial, so this
        must assert the EXACT action string, not just "some row exists"."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": "Bearer human-token"}
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_get_not_agent_token"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

    async def test_agent_jwt_missing_scope_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Same guard as ``test_interactive_token_rejection_is_audited``,
        for the other ``ALLOWED_DENIAL_REASONS`` branch."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["under-scoped-bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.get(
            f"/proposals/{proposal_id}",
            headers={"Authorization": "Bearer under-scoped-bot-token"},
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_get_missing_scope"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

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
        # Privacy redaction (Argus review round-2 BLOCKING): the human
        # reviewer's own identity must never reach the submitting bot.
        assert "decided_by_actor_id" not in resp.json()


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

    async def test_interactive_token_rejection_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Guards the ``surface="withdraw"`` literal (Argus review round-2
        suggestion) -- see the twin test on ``TestGetProposalEndpoint`` for
        why the exact action string matters here, not just row existence."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer human-token"},
            json={},
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_withdraw_not_agent_token"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

    async def test_agent_jwt_missing_scope_is_audited(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        provider.tokens["under-scoped-bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer under-scoped-bot-token"},
            json={},
        )
        assert resp.status_code == 403

        rows = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "denied.proposal_withdraw_missing_scope"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows

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

    async def test_uniform_404_for_malformed_proposal_id(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals/not-a-uuid/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "not_found"}

    async def test_non_dict_body_returns_invalid_body_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json=[],
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_body"

    async def test_non_empty_malformed_json_body_returns_invalid_json_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        """A truly empty body is a lenient no-reason withdraw (see
        ``test_withdraw_without_body_succeeds_with_no_reason``), but a
        NON-empty body that fails to parse as JSON is malformed input, not
        an absent one -- Argus review round-2 suggestion."""
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            content=b"not json",
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_json"

    async def test_non_string_reason_returns_invalid_reason_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={"reason": 123},
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_reason"

    async def test_reason_exceeding_max_length_returns_invalid_reason_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        proposal_id = await _submit_via_http(http_client, provider)
        resp = await http_client.post(
            f"/proposals/{proposal_id}/withdraw",
            headers={"Authorization": "Bearer bot-token"},
            json={"reason": "x" * 2001},
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_reason"


class TestProposalRouteRegistrationOrder:
    """Guards the route-ordering invariant ``get_proposal``'s own docstring
    depends on (Argus review suggestion): Starlette matches routes in
    registration order, so ``/proposals/pending``/``/proposals/history``
    (static) MUST be registered before ``/proposals/{proposal_id}``
    (wildcard), or a GET to either would resolve to ``get_proposal`` with
    ``proposal_id="pending"``/``"history"`` instead of
    ``list_pending_proposals``/``list_proposal_history`` -- silently
    returning a uniform 404 for every caller instead of the intended
    listing. This module's own test fixture hand-builds an
    independently-ordered ``Route`` list (see the ``client`` fixture
    above), so it can't catch a production ordering regression -- this
    test inspects ``main.mcp``'s ACTUAL registered routes instead."""

    def test_pending_and_history_registered_before_wildcard_proposal_id(self) -> None:
        main = _import_main()
        # `_additional_http_routes` is a private FastMCP attribute (Argus
        # review round-2 suggestion) -- a future FastMCP upgrade could
        # rename or drop it. Skip rather than fail so an unrelated
        # dependency bump doesn't block CI on a test whose only job is
        # guarding an internal-to-this-repo invariant, not FastMCP's API.
        if not hasattr(main.mcp, "_additional_http_routes"):
            pytest.skip(
                "main.mcp._additional_http_routes no longer exists on this FastMCP "
                "version -- this test needs a new way to inspect registered routes"
            )
        paths = [getattr(route, "path", None) for route in main.mcp._additional_http_routes]
        assert "/proposals/pending" in paths
        assert "/proposals/history" in paths
        assert "/proposals/{proposal_id}" in paths
        assert paths.index("/proposals/pending") < paths.index("/proposals/{proposal_id}")
        assert paths.index("/proposals/history") < paths.index("/proposals/{proposal_id}")


class TestProposalSenderAgentIdAttribution:
    """TECH-6668: sender_agent_id attribution on proposal_holds."""

    async def test_submitting_with_no_agent_key_unregistered_bot(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sender_agent_id" not in data
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None

    async def test_submitting_with_valid_agent_key_populates_all_four_surfaces(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        agent = await service.register_agent(
            session,
            sub="bot-1::worker",
            base_sub="bot-1",
            owner_sub="owner-a@example.com",
            owner_email="owner-a@example.com",
            display_name="Worker Bot",
            accepted_types=None,
        )
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        provider.tokens["human-token"] = _interactive_token("owner-a@example.com")

        body = {**_PROPOSAL_BODY, "agent_key": "worker"}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        data = resp.json()
        proposal_id = data["proposal_id"]
        assert data["sender_agent_id"] == str(agent.id)

        # Verify DB row
        hold = await session.get(ProposalHold, uuid.UUID(proposal_id))
        assert hold is not None
        assert hold.sender_agent_id == agent.id

        # Surface 1: GET /proposals/pending (human caller)
        pending_resp = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-token"}
        )
        assert pending_resp.status_code == 200
        pending_proposals = pending_resp.json()["proposals"]
        matching = [p for p in pending_proposals if p["proposal_id"] == proposal_id]
        assert len(matching) == 1
        assert matching[0]["sender_agent_id"] == str(agent.id)

        # Surface 2: GET /proposals/{proposal_id} (bot caller)
        get_resp = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": "Bearer bot-token"}
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["sender_agent_id"] == str(agent.id)

        # Surface 3: POST /proposals/{proposal_id}/decide (human caller)
        decide_resp = await http_client.post(
            f"/proposals/{proposal_id}/decide",
            headers={"Authorization": "Bearer human-token"},
            json={"decision": "reject", "decision_note": "rejected"},
        )
        assert decide_resp.status_code == 200
        assert decide_resp.json()["sender_agent_id"] == str(agent.id)

        # Surface 4: GET /proposals/history (human caller)
        history_resp = await http_client.get(
            "/proposals/history", headers={"Authorization": "Bearer human-token"}
        )
        assert history_resp.status_code == 200
        history_proposals = history_resp.json()["proposals"]
        matching_history = [p for p in history_proposals if p["proposal_id"] == proposal_id]
        assert len(matching_history) == 1
        assert matching_history[0]["sender_agent_id"] == str(agent.id)

    async def test_submitting_with_unresolvable_agent_key_is_none_no_error(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        body = {**_PROPOSAL_BODY, "agent_key": "unregistered-key"}
        resp = await http_client.post(
            "/proposals", json=body, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sender_agent_id" not in data
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None

    async def test_dedup_resubmission_updates_previously_null_sender_agent_id(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        agent = await service.register_agent(
            session,
            sub="bot-1::worker",
            base_sub="bot-1",
            owner_sub="owner-a@example.com",
            owner_email="owner-a@example.com",
            display_name="Worker Bot",
            accepted_types=None,
        )
        agent_id = agent.id
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )

        # First submission without agent_key
        resp1 = await http_client.post(
            "/proposals", json=_PROPOSAL_BODY, headers={"Authorization": "Bearer bot-token"}
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert "sender_agent_id" not in data1
        hold1 = await session.get(ProposalHold, uuid.UUID(data1["proposal_id"]))
        assert hold1 is not None
        assert hold1.sender_agent_id is None

        # Second submission with agent_key="worker" for same target
        resp2 = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "agent_key": "worker"},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["proposal_id"] == data1["proposal_id"]
        assert data2["sender_agent_id"] == str(agent_id)

        # Re-fetch from DB
        session.expire_all()
        hold2 = await session.get(ProposalHold, uuid.UUID(data1["proposal_id"]))
        assert hold2 is not None
        assert hold2.sender_agent_id == agent_id

    async def test_latent_bug_fix_owner_sub_fallback_with_agent_key(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        http_client, provider = client
        agent = await service.register_agent(
            session,
            sub="bot-1::keyed",
            base_sub="bot-1",
            owner_sub="owner-from-agent@example.com",
            owner_email="owner-from-agent@example.com",
            display_name="Keyed Agent",
            accepted_types=None,
        )
        # Token carries NO owner_sub claim
        provider.tokens["bot-token"] = _agent_jwt_token("bot-1", scopes=["comms:proposals:write"])
        resp = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "agent_key": "keyed"},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["sender_agent_id"] == str(agent.id)
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.owner_sub == "owner-from-agent@example.com"
        assert hold.sender_agent_id == agent.id

    async def test_invalid_agent_key_type_rejected(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, provider = client
        provider.tokens["bot-token"] = _agent_jwt_token(
            "bot-1", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "agent_key": 123},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp.status_code == 422
        assert resp.json()["error"] == "invalid_request"

    async def test_sub_containing_colons_without_agent_key_succeeds_unregistered(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Regression test for TECH-6668 finding: bot_sub containing '::'
        submitting without agent_key must not be rejected by _compose_sub."""
        http_client, provider = client
        opaque_sub = "opaque::legacy::bot-sub"
        provider.tokens["bot-token"] = _agent_jwt_token(
            opaque_sub, scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals",
            json=_PROPOSAL_BODY,
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sender_agent_id" not in data
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None
        assert hold.proposed_by_bot_id == opaque_sub

    async def test_sub_containing_colons_without_agent_key_resolves_registered_agent(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Bot with sub containing '::' matches a registered agent with that raw sub."""
        http_client, provider = client
        opaque_sub = "opaque::legacy::bot-sub"
        agent = await service.register_agent(
            session,
            sub=opaque_sub,
            base_sub=opaque_sub,
            owner_sub="owner-a@example.com",
            owner_email="owner-a@example.com",
            display_name="Legacy Opaque Bot",
            accepted_types=None,
        )
        provider.tokens["bot-token"] = _agent_jwt_token(
            opaque_sub, scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals",
            json=_PROPOSAL_BODY,
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["sender_agent_id"] == str(agent.id)
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id == agent.id

    async def test_sub_containing_colons_with_agent_key_degrades_gracefully(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Bot with sub containing '::' passing agent_key triggers composition error,
        which must degrade gracefully to sender_agent_id=None without failing submission."""
        http_client, provider = client
        opaque_sub = "opaque::legacy::bot-sub"
        provider.tokens["bot-token"] = _agent_jwt_token(
            opaque_sub, scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )
        resp = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "agent_key": "some-key"},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sender_agent_id" not in data
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None

    async def test_unresolvable_agent_key_falls_back_to_base_bot_owner_sub(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """BLOCKING #3: unresolvable agent_key must not break owner_sub resolution
        when base bot_sub is registered and token lacks owner_sub claim."""
        http_client, provider = client
        base_sub = "http-base-registered-bot"
        await service.register_agent(
            session,
            sub=base_sub,
            base_sub=base_sub,
            owner_sub="fallback-owner@example.com",
            owner_email="fallback-owner@example.com",
            display_name="HTTP Base Registered Bot",
            accepted_types=None,
        )
        # Token carries NO owner_sub
        provider.tokens["bot-token"] = _agent_jwt_token(base_sub, scopes=["comms:proposals:write"])
        resp = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "agent_key": "unresolvable-key"},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sender_agent_id" not in data
        hold = await session.get(ProposalHold, uuid.UUID(data["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None
        assert hold.owner_sub == "fallback-owner@example.com"

    async def test_dedup_resubmission_without_agent_key_preserves_sender_agent_id(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
    ) -> None:
        """Suggestion #5: dedup resubmission without agent_key preserves existing
        sender_agent_id."""
        http_client, provider = client
        agent = await service.register_agent(
            session,
            sub="http-dedup-bot::worker",
            base_sub="http-dedup-bot",
            owner_sub="owner-a@example.com",
            owner_email="owner-a@example.com",
            display_name="HTTP Dedup Worker",
            accepted_types=None,
        )
        agent_id = agent.id
        provider.tokens["bot-token"] = _agent_jwt_token(
            "http-dedup-bot", scopes=["comms:proposals:write"], owner_sub="owner-a@example.com"
        )

        # First submission with agent_key="worker"
        resp1 = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "agent_key": "worker"},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["sender_agent_id"] == str(agent_id)
        proposal_id = data1["proposal_id"]

        # Second submission without agent_key for same action
        resp2 = await http_client.post(
            "/proposals",
            json={**_PROPOSAL_BODY, "rationale": "new rationale without key"},
            headers={"Authorization": "Bearer bot-token"},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["proposal_id"] == proposal_id
        assert data2["sender_agent_id"] == str(agent_id)

        session.expire_all()
        hold = await session.get(ProposalHold, uuid.UUID(proposal_id))
        assert hold is not None
        assert hold.sender_agent_id == agent_id
