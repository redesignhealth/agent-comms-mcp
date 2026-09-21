"""End-to-end tests for the proposals MCP tool surface (providers/proposals.py)
-- TECH-6018 follow-up.

Mirrors ``tests/test_comms_tools.py``'s real-Postgres + in-memory
``fastmcp.Client`` idiom: every tool call goes through the REAL mounted
server (auth middleware, scope enforcement, tool dispatch), never the raw
Python function. ``providers.proposals.get_session_factory`` is patched to
the test database's session factory (the documented test-injection seam,
db.py's docstring).

Deliberately does NOT re-test business logic already covered by
``tests/test_proposal_service.py`` (dedup, rate limiting, the TECH-5877
judge) -- these tests are about the TRANSPORT layer: scope enforcement, the
new sender-only listing tools, and that a proposing bot need not be a
board-registered agent (unlike every ``comms_*`` tool).
"""

from __future__ import annotations

import asyncio
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
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import plugins
import service
from models import ProposalHold
from plugins import (
    FINGERPRINT_DIGEST,
    FINGERPRINT_UNAVAILABLE,
    ProposalApplyOutcome,
    ProposalFingerprint,
    ProposalTargetError,
)
from service import decide_proposal
from tests.proposal_judge_fakes import FakeProposalJudge

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"

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
    """Import a fresh ``main`` module under the OIDC/env patches."""
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


# --- Database fixtures (mirrors tests/test_comms_tools.py) ------------------------


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
            "(or set DATABASE_URL) to exercise the real-database tool tests."
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
            text("TRUNCATE TABLE proposal_holds, audit_log RESTART IDENTITY CASCADE")
        )
    yield


_DEFAULT_SUBMIT_TIME_FINGERPRINT = "fp-submit-time-default"


@pytest.fixture(autouse=True)
def _default_proposal_judge(monkeypatch: pytest.MonkeyPatch) -> FakeProposalJudge:
    """``proposals_submit`` -> ``service.create_proposal`` resolves
    ``plugins.get_proposal_judge()`` fresh per call -- monkeypatch it to
    always return the SAME ``FakeProposalJudge`` instance for the duration
    of one test. None of the tests in this file exercise the auto-judge/
    apply path (see this module's own docstring -- that's
    ``tests/test_proposal_service.py``'s job), so a single stable digest
    default here is all any test needs; it just keeps submission from
    reaching a FINGERPRINT_UNAVAILABLE outcome."""
    fake = FakeProposalJudge(
        fingerprint_result=ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest=_DEFAULT_SUBMIT_TIME_FINGERPRINT
        )
    )
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: fake)
    return fake


@pytest.fixture
def test_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


# --- MCP client helpers -------------------------------------------------------------


def _token(sub: str, *, scopes: list[str] | None = None, owner_sub: str | None = None) -> MagicMock:
    """A minimal agent-jwt-shaped ``AccessToken`` stand-in for a proposing bot."""
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else ["comms:proposals:write"],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    token = MagicMock()
    token.claims = claims
    token.scopes = []
    token.client_id = sub
    return token


async def _call(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    tool_name: str,
    args: dict[str, Any] | None = None,
) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.proposals.get_access_token", return_value=token),
        patch("providers.proposals.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data


@pytest.fixture
def main() -> Any:
    return _import_main()


def _action(
    action_type: str = "close_ticket", target_id: str = "TECH-1234", **extra: Any
) -> dict[str, Any]:
    # action_type default is "close_ticket", not "open_ticket" (TECH-5873
    # redefinition) -- see the identical rationale in
    # tests/test_proposal_service.py's own `_action` docstring.
    return {"action_type": action_type, "target_id": target_id, **extra}


async def _submit(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    *,
    bot_sub: str = "bot-1",
    owner_sub: str = "owner-a@example.com",
    action: dict[str, Any] | None = None,
    target_fingerprint: str = "deadbeef",
) -> dict[str, Any]:
    token = _token(bot_sub, owner_sub=owner_sub)
    result: dict[str, Any] = await _call(
        main,
        test_session_factory,
        token,
        "proposals_submit",
        {
            "kind": "linear_progress_update",
            "action": action if action is not None else _action(),
            "rationale": "because reasons",
            "confidence": "medium",
            "importance": "medium",
            "impact": "medium",
            "target_fingerprint": target_fingerprint,
        },
    )
    return result


# --- Registry / scope enforcement ----------------------------------------------


class TestScopeEnforcement:
    async def test_all_five_tools_are_registry_enrolled(self, main: Any) -> None:
        from scopes import TOOL_SCOPES

        tools = await main.mcp.list_tools()
        mounted = {t.name for t in tools}
        expected = {
            "proposals_submit",
            "proposals_get",
            "proposals_list_pending",
            "proposals_list_history",
            "proposals_withdraw",
        }
        assert expected <= mounted
        assert expected <= set(TOOL_SCOPES)

    async def test_missing_scope_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("scope-test-bot", scopes=[])
        with pytest.raises(ToolError, match="requires elevated permissions"):
            await _call(main, test_session_factory, token, "proposals_list_pending")

    async def test_unregistered_bot_can_still_submit(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Unlike every ``comms_*`` tool, a proposing bot need not be a
        board-registered ``Agent`` -- this is a deliberate, pre-existing
        distinction (see ``providers/proposals.py``'s module docstring)."""
        result = await _submit(main, test_session_factory, bot_sub="never-registered-bot")
        assert result["status"] in ("pending", "applied", "apply_failed")

    async def test_interactive_caller_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Argus review round-1 BLOCKING catch: unlike every ``comms_*``
        tool, an interactive (Okta) token must NOT be able to reach these
        tools at all -- ``ScopeEnforcementMiddleware`` lets interactive
        callers bypass ``TOOL_SCOPES`` entirely, so ``_require_bot_sub``
        must reject one outright."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "human@example.com",
        }
        token.scopes = []
        token.client_id = "human@example.com"
        with pytest.raises(ToolError, match="bot"):
            await _call(main, test_session_factory, token, "proposals_list_pending")

    async def test_missing_token_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", return_value=None),
            patch("providers.proposals.get_access_token", return_value=None),
            patch("providers.proposals.get_session_factory", return_value=test_session_factory),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(ToolError):
                    await client.call_tool("proposals_list_pending", {})

    async def test_unresolvable_identity_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("bot-no-identity")
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", return_value=token),
            patch("providers.proposals.get_access_token", return_value=token),
            patch("providers.proposals.get_session_factory", return_value=test_session_factory),
            patch("providers.proposals.try_resolve_email", return_value=None),
        ):
            async with Client(main.mcp) as client:
                with pytest.raises(ToolError, match="identity"):
                    await client.call_tool("proposals_list_pending", {})


# --- Submit / get / withdraw round-trips ----------------------------------------


class TestSubmitGetWithdraw:
    async def test_submit_then_get_round_trips(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-rt")
        token = _token("bot-rt")
        fetched = await _call(
            main,
            test_session_factory,
            token,
            "proposals_get",
            {"proposal_id": submitted["proposal_id"]},
        )
        assert fetched["proposal_id"] == submitted["proposal_id"]

    async def test_get_another_bots_proposal_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-owner")
        other_token = _token("bot-intruder")
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                other_token,
                "proposals_get",
                {"proposal_id": submitted["proposal_id"]},
            )

    async def test_withdraw_own_pending_proposal(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-withdraw")
        token = _token("bot-withdraw")
        result = await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": submitted["proposal_id"], "reason": "no longer needed"},
        )
        assert result["status"] == "withdrawn"

    async def test_withdraw_allows_empty_string_reason(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Matches ``withdraw_proposal_route``'s HTTP semantics exactly --
        an empty-string ``reason`` is explicitly permitted, unlike the
        general ``validate_proposal_string_field`` helper used elsewhere."""
        submitted = await _submit(main, test_session_factory, bot_sub="bot-empty-reason")
        token = _token("bot-empty-reason")
        result = await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": submitted["proposal_id"], "reason": ""},
        )
        assert result["status"] == "withdrawn"

    async def test_withdraw_reason_over_cap_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        import service

        submitted = await _submit(main, test_session_factory, bot_sub="bot-long-reason")
        token = _token("bot-long-reason")
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                token,
                "proposals_withdraw",
                {
                    "proposal_id": submitted["proposal_id"],
                    "reason": "x" * (service.MAX_DECISION_REASON_LENGTH + 1),
                },
            )

    async def test_withdraw_another_bots_proposal_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        submitted = await _submit(main, test_session_factory, bot_sub="bot-withdraw-owner")
        other_token = _token("bot-withdraw-intruder")
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                other_token,
                "proposals_withdraw",
                {"proposal_id": submitted["proposal_id"]},
            )

    async def test_get_malformed_proposal_id_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("bot-malformed-get")
        with pytest.raises(ToolError, match="not a valid UUID"):
            await _call(
                main,
                test_session_factory,
                token,
                "proposals_get",
                {"proposal_id": "not-a-uuid"},
            )

    async def test_withdraw_malformed_proposal_id_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("bot-malformed-withdraw")
        with pytest.raises(ToolError, match="not a valid UUID"):
            await _call(
                main,
                test_session_factory,
                token,
                "proposals_withdraw",
                {"proposal_id": "not-a-uuid"},
            )

    async def test_withdraw_already_decided_proposal_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Verifies HoldAlreadyDecidedError -> ToolError mapping at the MCP
        transport layer, not just the service layer (already covered in
        test_proposal_service.py)."""
        submitted = await _submit(main, test_session_factory, bot_sub="bot-double-withdraw")
        token = _token("bot-double-withdraw")
        await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": submitted["proposal_id"]},
        )
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                token,
                "proposals_withdraw",
                {"proposal_id": submitted["proposal_id"]},
            )

    async def test_owner_sub_unresolvable_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """No ``owner_sub`` claim on the token, and no matching board
        ``Agent`` row to fall back to."""
        token = _token("bot-no-owner-sub", owner_sub=None)
        with pytest.raises(ToolError, match="owner_sub_unresolvable"):
            await _call(
                main,
                test_session_factory,
                token,
                "proposals_submit",
                {
                    "kind": "linear_progress_update",
                    "action": _action(),
                    "rationale": "because reasons",
                    "confidence": "medium",
                    "importance": "medium",
                    "impact": "medium",
                    "target_fingerprint": "deadbeef",
                },
            )

    async def test_target_fingerprint_argument_is_ignored(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Mirrors ``tests/test_proposal_endpoint.py::TestSubmitProposal::
        test_target_fingerprint_in_body_is_ignored`` for the MCP tool
        path: a caller-supplied ``target_fingerprint`` is DEPRECATED and
        ignored -- the value actually stored (and later compared against
        at decide time) is always computed server-side. Submit with a
        tool argument value that could never match the judge's
        server-computed fingerprint, then decide (via
        ``service.decide_proposal`` directly -- there is no MCP tool for
        deciding, see this module's own docstring) against that SAME
        shared fixture judge -- reaching ``"applied"`` (not ``"stale"``)
        proves the server-computed value, not the tool argument, was
        stored and matched."""
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_DIGEST, digest="server-value"
        )
        submitted = await _submit(
            main,
            test_session_factory,
            bot_sub="bot-fp-ignored",
            owner_sub="owner-fp-ignored@example.com",
            action=_action(target_id="TECH-FINGERPRINT-IGNORED"),
            target_fingerprint="tool-argument-value",
        )
        assert submitted["status"] == "pending"

        _default_proposal_judge.apply_result = ProposalApplyOutcome(
            applied=True, result=None, caller_error=None, log_detail=None
        )
        decided = await decide_proposal(
            session,
            approver_sub="owner-fp-ignored@example.com",
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="approve",
            decision_note=None,
            judge=_default_proposal_judge,
        )
        assert decided["status"] == "applied"

    async def test_fingerprint_unavailable_during_submission_raises_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round-3 B1: service.create_proposal's server-side
        target-fingerprint fetch can fail (target doesn't exist, target
        system error) -- must surface as a ToolError with the judge's own
        sanitized message."""
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_UNAVAILABLE,
            error=ProposalTargetError(
                status_code=422,
                error_code="invalid_request",
                detail="Linear returned an error",
                log_detail="target issue does not exist",
            ),
        )
        with pytest.raises(ToolError, match=r"^Linear returned an error$"):
            await _submit(main, test_session_factory, bot_sub="bot-linear-error")

    async def test_fingerprint_unavailable_missing_credential_raises_sanitized_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round-3 B1: a missing-credential-shaped judge
        failure must raise ToolError without leaking the internal env-var
        name."""
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_UNAVAILABLE,
            error=ProposalTargetError(
                status_code=500,
                error_code="server_configuration_error",
                detail="server configuration error",
                log_detail="LINEAR_API_TOKEN is not configured",
            ),
        )
        with pytest.raises(ToolError, match=r"^server configuration error$"):
            await _submit(main, test_session_factory, bot_sub="bot-token-error")

    async def test_fingerprint_unavailable_transport_failure_raises_sanitized_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        _default_proposal_judge: FakeProposalJudge,
    ) -> None:
        """Argus review round-3 B1: a transport-failure-shaped judge
        failure must raise ToolError without leaking transport
        internals."""
        _default_proposal_judge.fingerprint_result = ProposalFingerprint(
            status=FINGERPRINT_UNAVAILABLE,
            error=ProposalTargetError(
                status_code=503,
                error_code="service_unavailable",
                detail="Linear API unavailable",
                log_detail="Linear API request failed: connection refused",
            ),
        )
        with pytest.raises(ToolError, match=r"^Linear API unavailable$"):
            await _submit(main, test_session_factory, bot_sub="bot-transport-error")


# --- list_pending / list_history -------------------------------------------------


class TestListPendingAndHistory:
    async def test_list_pending_scoped_to_own_bot(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _submit(main, test_session_factory, bot_sub="bot-mine", action=_action(target_id="A"))
        await _submit(
            main, test_session_factory, bot_sub="bot-other", action=_action(target_id="B")
        )

        token = _token("bot-mine")
        result = await _call(main, test_session_factory, token, "proposals_list_pending")
        subs = {p["proposed_by_bot_id"] for p in result["proposals"]}
        assert subs <= {"bot-mine"}
        assert len(result["proposals"]) >= 1

    async def test_list_history_excludes_pending(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        bot_sub = "bot-history"
        await _submit(main, test_session_factory, bot_sub=bot_sub, action=_action(target_id="C"))

        token = _token(bot_sub)
        history = await _call(main, test_session_factory, token, "proposals_list_history")
        assert history["proposals"] == []

        pending = await _call(main, test_session_factory, token, "proposals_list_pending")
        assert len(pending["proposals"]) == 1

    async def test_list_history_includes_human_decided_and_withdrawn(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        bot_sub = "bot-history-2"
        owner_sub = "owner-history-2@example.com"
        rejected = await _submit(
            main,
            test_session_factory,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            action=_action(target_id="D"),
        )
        withdrawn = await _submit(
            main,
            test_session_factory,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            action=_action(target_id="E"),
        )

        await decide_proposal(
            session,
            approver_sub=owner_sub,
            hold_id=uuid.UUID(rejected["proposal_id"]),
            decision="reject",
            decision_note="not appropriate",
            judge=FakeProposalJudge(),
        )
        token = _token(bot_sub)
        await _call(
            main,
            test_session_factory,
            token,
            "proposals_withdraw",
            {"proposal_id": withdrawn["proposal_id"]},
        )

        history = await _call(main, test_session_factory, token, "proposals_list_history")
        by_id = {p["proposal_id"]: p for p in history["proposals"]}
        assert by_id[rejected["proposal_id"]]["status"] == "rejected"
        assert by_id[withdrawn["proposal_id"]]["status"] == "withdrawn"

    async def test_list_history_redacts_human_decider(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        bot_sub = "bot-redact"
        owner_sub = "owner-redact@example.com"
        submitted = await _submit(
            main,
            test_session_factory,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            action=_action(target_id="F"),
        )
        await decide_proposal(
            session,
            approver_sub=owner_sub,
            hold_id=uuid.UUID(submitted["proposal_id"]),
            decision="reject",
            decision_note="not appropriate",
            judge=FakeProposalJudge(),
        )

        token = _token(bot_sub)
        history = await _call(main, test_session_factory, token, "proposals_list_history")
        assert len(history["proposals"]) == 1
        assert "decided_by_actor_id" not in history["proposals"][0]

    async def test_list_pending_has_more_true_when_over_limit(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        bot_sub = "bot-pagination"
        for i in range(3):
            await _submit(
                main, test_session_factory, bot_sub=bot_sub, action=_action(target_id=f"PAGE-{i}")
            )

        token = _token(bot_sub)
        result = await _call(
            main, test_session_factory, token, "proposals_list_pending", {"limit": 2}
        )
        assert len(result["proposals"]) == 2
        assert result["has_more"] is True

    async def test_list_pending_limit_clamped_to_minimum(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        bot_sub = "bot-limit-min"
        await _submit(main, test_session_factory, bot_sub=bot_sub, action=_action(target_id="G"))
        await _submit(main, test_session_factory, bot_sub=bot_sub, action=_action(target_id="H"))

        token = _token(bot_sub)
        result = await _call(
            main, test_session_factory, token, "proposals_list_pending", {"limit": 0}
        )
        assert len(result["proposals"]) == 1

    async def test_list_pending_limit_clamped_to_maximum(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        bot_sub = "bot-limit-max"
        await _submit(main, test_session_factory, bot_sub=bot_sub, action=_action(target_id="I"))

        token = _token(bot_sub)
        result = await _call(
            main, test_session_factory, token, "proposals_list_pending", {"limit": 201}
        )
        assert result["has_more"] is False
        assert len(result["proposals"]) == 1


class TestProposalToolsSenderAgentId:
    """TECH-6668: sender_agent_id attribution on proposal tools."""

    async def test_submit_with_valid_agent_key_populates_sender_agent_id(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        agent = await service.register_agent(
            session,
            sub="tool-bot::worker",
            base_sub="tool-bot",
            owner_sub="owner@example.com",
            owner_email="owner@example.com",
            display_name="Tool Worker",
            accepted_types=None,
        )
        token = _token("tool-bot", owner_sub="owner@example.com")
        submitted = await _call(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": _action(target_id="TOOL-1"),
                "rationale": "because reasons",
                "confidence": "medium",
                "importance": "medium",
                "impact": "medium",
                "agent_key": "worker",
            },
        )
        assert submitted["sender_agent_id"] == str(agent.id)
        proposal_id = submitted["proposal_id"]

        # proposals_get
        got = await _call(
            main,
            test_session_factory,
            token,
            "proposals_get",
            {"proposal_id": proposal_id},
        )
        assert got["sender_agent_id"] == str(agent.id)

        # proposals_list_pending
        pending = await _call(
            main,
            test_session_factory,
            token,
            "proposals_list_pending",
        )
        matching = [p for p in pending["proposals"] if p["proposal_id"] == proposal_id]
        assert len(matching) == 1
        assert matching[0]["sender_agent_id"] == str(agent.id)

        # decide and check proposals_list_history
        await decide_proposal(
            session,
            approver_sub="owner@example.com",
            hold_id=uuid.UUID(proposal_id),
            decision="reject",
            decision_note="rejected",
            judge=FakeProposalJudge(),
        )
        history = await _call(
            main,
            test_session_factory,
            token,
            "proposals_list_history",
        )
        matching_hist = [p for p in history["proposals"] if p["proposal_id"] == proposal_id]
        assert len(matching_hist) == 1
        assert matching_hist[0]["sender_agent_id"] == str(agent.id)

    async def test_submit_with_unresolvable_agent_key_omits_sender_agent_id(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        token = _token("tool-bot", owner_sub="owner@example.com")
        submitted = await _call(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": _action(target_id="TOOL-2"),
                "rationale": "because reasons",
                "confidence": "medium",
                "importance": "medium",
                "impact": "medium",
                "agent_key": "unregistered",
            },
        )
        assert "sender_agent_id" not in submitted

    async def test_submit_without_owner_sub_falls_back_to_keyed_agent(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        agent = await service.register_agent(
            session,
            sub="tool-bot-no-owner::keyed",
            base_sub="tool-bot-no-owner",
            owner_sub="fallback-owner@example.com",
            owner_email="fallback-owner@example.com",
            display_name="Fallback Agent",
            accepted_types=None,
        )
        # Token carries NO owner_sub
        token = _token("tool-bot-no-owner", owner_sub=None)
        submitted = await _call(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": _action(target_id="TOOL-3"),
                "rationale": "because reasons",
                "confidence": "medium",
                "importance": "medium",
                "impact": "medium",
                "agent_key": "keyed",
            },
        )
        assert submitted["sender_agent_id"] == str(agent.id)
        hold = await session.get(ProposalHold, uuid.UUID(submitted["proposal_id"]))
        assert hold is not None
        assert hold.owner_sub == "fallback-owner@example.com"

    async def test_sub_containing_colons_without_agent_key_succeeds_unregistered(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """Regression test: proposing bot with sub containing '::' without agent_key
        must not fail due to _compose_sub."""
        opaque_sub = "opaque::legacy::tool-bot"
        token = _token(opaque_sub, owner_sub="owner@example.com")
        submitted = await _call(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": _action(target_id="TOOL-OPAQUE-1"),
                "rationale": "because reasons",
                "confidence": "medium",
                "importance": "medium",
                "impact": "medium",
            },
        )
        assert "sender_agent_id" not in submitted
        hold = await session.get(ProposalHold, uuid.UUID(submitted["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None
        assert hold.proposed_by_bot_id == opaque_sub

    async def test_sub_containing_colons_without_agent_key_resolves_registered(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """Proposing bot with sub containing '::' matches a registered agent with that raw sub."""
        opaque_sub = "opaque::legacy::tool-bot-reg"
        agent = await service.register_agent(
            session,
            sub=opaque_sub,
            base_sub=opaque_sub,
            owner_sub="owner@example.com",
            owner_email="owner@example.com",
            display_name="Legacy Opaque MCP Bot",
            accepted_types=None,
        )
        token = _token(opaque_sub, owner_sub="owner@example.com")
        submitted = await _call(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": _action(target_id="TOOL-OPAQUE-2"),
                "rationale": "because reasons",
                "confidence": "medium",
                "importance": "medium",
                "impact": "medium",
            },
        )
        assert submitted["sender_agent_id"] == str(agent.id)
        hold = await session.get(ProposalHold, uuid.UUID(submitted["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id == agent.id

    async def test_sub_containing_colons_with_agent_key_degrades_gracefully(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """Proposing bot with sub containing '::' passing agent_key must degrade gracefully
        to sender_agent_id=None without failing submission."""
        opaque_sub = "opaque::legacy::tool-bot-keyed"
        token = _token(opaque_sub, owner_sub="owner@example.com")
        submitted = await _call(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": _action(target_id="TOOL-OPAQUE-3"),
                "rationale": "because reasons",
                "confidence": "medium",
                "importance": "medium",
                "impact": "medium",
                "agent_key": "some-key",
            },
        )
        assert "sender_agent_id" not in submitted
        hold = await session.get(ProposalHold, uuid.UUID(submitted["proposal_id"]))
        assert hold is not None
        assert hold.sender_agent_id is None
