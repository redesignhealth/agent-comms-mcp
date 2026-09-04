"""End-to-end tests for the comms MCP tool surface (providers/comms.py).

Mirrors ``tests/test_service.py``'s real-Postgres idiom (module-scoped
Alembic chain, function-scoped engine/session, autouse truncate, skip the
whole module with a clear reason if Postgres is unreachable) combined with
``tests/test_main.py``'s in-memory ``fastmcp.Client`` end-to-end idiom
(fresh ``main`` import under OIDC/env patches, ``get_access_token`` mocked
per simulated caller).

Every tool call goes through the REAL mounted server (auth middleware,
scope enforcement, tool dispatch) — never the raw Python function — so
these tests exercise the full stack this stage was built to wire up.
``providers.comms.get_session_factory`` is patched to the test database's
session factory (the documented test-injection seam, db.py's docstring).
"""

from __future__ import annotations

import asyncio
import os
import re
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
from schemas import MESSAGE_TYPES

# Coverage for MESSAGE_TYPES fitting within MAX_ACCEPTED_TYPES (a precondition
# for sorted(MESSAGE_TYPES) as a default accepted_types below) lives in
# tests/test_schemas.py as a collected test, not a module-level assert here.

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


# --- Database fixtures (mirrors tests/test_service.py) ----------------------------


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
            text(
                "TRUNCATE TABLE audit_log, messages, participants, conversations, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


@pytest.fixture
def test_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


# --- MCP client helpers -------------------------------------------------------------


def _token(
    sub: str,
    *,
    scopes: list[str] | None = None,
    owner_sub: str | None = None,
    owner_email: str | None = None,
    registry_backed: bool = False,
) -> MagicMock:
    """A minimal agent-jwt-shaped ``AccessToken`` stand-in for ``sub``.

    ``registry_backed=True`` stamps ``auth.AGENT_TOKEN_VERIFIER_CLAIM`` with
    a non-default plugin name, simulating a token that went through an
    operator-configured ``AGENT_TOKEN_VERIFIERS`` plugin rather than the
    built-in default -- the trust signal TECH-5593's ownership
    write-through (``providers.comms._resolve_caller_agent``) gates on via
    ``scopes.is_registry_backed_agent_token``. The real
    ``_NormalizingVerifier`` stamps this on every verified token
    (tests/test_auth.py covers that in isolation); this fixture simulates
    its effect directly since these tests bypass verification entirely via
    the ``get_access_token`` patch.
    """
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else ["comms:read", "comms:write"],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    if owner_email is not None:
        claims["owner_email"] = owner_email
    if registry_backed:
        from auth import AGENT_TOKEN_VERIFIER_CLAIM

        claims[AGENT_TOKEN_VERIFIER_CLAIM] = "tests.test_comms_tools:_fake_registry_verifier"
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
        patch("providers.comms.get_access_token", return_value=token),
        patch("providers.comms.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data


@pytest.fixture
def main() -> Any:
    return _import_main()


async def _register(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    sub: str,
    *,
    display_name: str | None = None,
    accepted_types: list[str] | None = None,
    owner_sub: str | None = None,
    owner_email: str | None = None,
    min_schema_version: int | None = None,
    max_schema_version: int | None = None,
) -> dict[str, Any]:
    token = _token(sub, owner_sub=owner_sub, owner_email=owner_email)
    args: dict[str, Any] = {
        "display_name": display_name or sub,
        # Permissive default so tests unrelated to the accepted_types
        # capability gate don't need to opt in per-type; those tests
        # narrow this explicitly via the accepted_types param.
        "accepted_types": accepted_types or sorted(MESSAGE_TYPES),
    }
    # Schema-version fields are only included when a test opts in, so most
    # callers keep exercising the 1/1 default path unchanged.
    if min_schema_version is not None:
        args["min_schema_version"] = min_schema_version
    if max_schema_version is not None:
        args["max_schema_version"] = max_schema_version
    result: dict[str, Any] = await _call(
        main,
        test_session_factory,
        token,
        "comms_register",
        args,
    )
    return result


def _availability_request() -> dict[str, Any]:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    return {
        "window": {"start": now.isoformat(), "end": (now + timedelta(hours=2)).isoformat()},
        "duration_min": 30,
        "modality": "video",
        "priority": "normal",
        "constraints": [],
    }


def _availability_response() -> dict[str, Any]:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    return {
        "slots": [
            {
                "start": now.isoformat(),
                "end": (now + timedelta(hours=1)).isoformat(),
                "preference": 0.8,
            }
        ]
    }


def _confirm_payload() -> dict[str, Any]:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    return {"slot": {"start": now.isoformat(), "end": (now + timedelta(hours=1)).isoformat()}}


# --- Registration ---------------------------------------------------------------


class TestRegister:
    async def test_register_persists_and_is_visible_via_whoami(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-a", owner_sub="owner-a-human", owner_email="ownera@example.com")
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Agent A", "accepted_types": ["availability_request"]},
        )
        assert result["sub"] == "agent-a"
        assert result["display_name"] == "Agent A"
        assert result["accepted_types"] == ["availability_request"]
        assert result["status"] == "active"
        assert result["owner_email"] == "ownera@example.com"

        whoami = await _call(main, test_session_factory, token, "comms_whoami")
        assert whoami["identity"] == "agent-a"

    async def test_register_is_idempotent(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-b")
        first = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "B v1", "accepted_types": ["availability_request"]},
        )
        second = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "B v2", "accepted_types": ["availability_request"]},
        )
        assert first["agent_id"] == second["agent_id"]
        assert second["display_name"] == "B v2"

    async def test_register_with_agent_key_creates_distinct_row(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Two agents sharing one token's base identity (today's reality for
        multiple EA-managed agents acting for the same human) must not
        collapse into one board row — a distinct ``agent_key``
        each is what keeps them apart."""
        token = _token("shared-human-sub", owner_sub="shared-human-sub")
        first = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Bond 007",
                "accepted_types": ["availability_request"],
                "agent_key": "bond-007",
            },
        )
        second = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Pepper Pots",
                "accepted_types": ["availability_request"],
                "agent_key": "pepper-pots",
                # TECH-5736: a second identity under the same base_sub is
                # exactly the collision guard's target case -- this test's
                # whole point is that it's a legitimate, deliberate use,
                # so it must explicitly confirm it.
                "confirm_new_identity": True,
            },
        )
        assert first["agent_id"] != second["agent_id"]
        assert first["sub"] == "shared-human-sub::bond-007"
        assert second["sub"] == "shared-human-sub::pepper-pots"
        assert first["display_name"] == "Bond 007"
        assert second["display_name"] == "Pepper Pots"
        # owner_sub is unaffected by agent_key — both rows are still owned
        # by the same verified human, which is what admission decisions key on.
        assert first["owner_email"] == second["owner_email"]

    async def test_register_without_agent_key_matches_prior_behavior(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-no-key")
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "No Key", "accepted_types": ["availability_request"]},
        )
        assert result["sub"] == "agent-no-key"

    async def test_register_empty_agent_key_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-empty-key")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Empty Key",
                    "accepted_types": ["availability_request"],
                    "agent_key": "   ",
                },
            )

    async def test_register_oversized_agent_key_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-oversized-key")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Oversized Key",
                    "accepted_types": ["availability_request"],
                    "agent_key": "x" * 101,
                },
            )

    async def test_register_without_owner_claims_falls_back_to_self(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-self-owned")
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Self", "accepted_types": ["availability_request"]},
        )
        # No owner_sub/owner_email claims on the token — self-owned fallback.
        assert result["owner_email"] == "agent-self-owned"

    async def test_register_agent_jwt_forged_email_claim_not_trusted(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """An agent-jwt (agent) token's ``email`` claim is caller-supplied and
        unverified — it must never be trusted as ``owner_email``, even when
        present. ``mint_token``'s CLI never sets an ``email`` claim (it only
        ever sets ``owner_sub``, deliberately, via ``--owner-email``), so
        this scenario models a hand-crafted token bypassing that CLI. This
        is the negative case the existing "no email claim at all" tests
        don't cover: here the token DOES carry an ``email`` claim, and it
        must still be ignored in favor of the sub-derived self-owned
        fallback."""
        token = _token("agent-forged-email")
        token.claims["email"] = "forged@attacker.com"

        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Forged", "accepted_types": ["availability_request"]},
        )
        assert result["owner_email"] != "forged@attacker.com"
        assert result["owner_email"] == "agent-forged-email"

    async def test_register_unknown_accepted_type_names_valid_set_in_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Unlike a generic ``invalid_request`` ValueError, an unrecognized
        ``accepted_types`` entry surfaces a specific ``ToolError`` naming
        the actual valid set — a caller (e.g. an external agent probing
        the API) does not have to guess at ``schemas.CONVERSATION_TYPES``
        one rejected call at a time. See exceptions.py's module docstring
        for why this is deliberately not folded into the uniform-denial
        posture used for authorization failures."""
        token = _token("agent-probes-valid-types")
        with pytest.raises(ToolError, match=r"accepted_types must be a subset of"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {"display_name": "Prober", "accepted_types": ["__probe_invalid_type__"]},
            )

    async def test_register_empty_accepted_types_is_accept_everything_sentinel(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Boundary-level counterpart to
        ``test_service.test_empty_accepted_types_is_accept_everything_sentinel``:
        an empty (or omitted) ``accepted_types`` is the opt-out "accept
        everything" sentinel (TECH-5822 follow-up), not a validation
        failure -- both shapes must round-trip through the MCP tool
        boundary as an empty list, not raise."""
        token = _token("agent-empty-types-boundary")
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Empty Types", "accepted_types": []},
        )
        assert result["accepted_types"] == []

        token2 = _token("agent-omitted-types-boundary")
        result2 = await _call(
            main,
            test_session_factory,
            token2,
            "comms_register",
            {"display_name": "Omitted Types"},
        )
        assert result2["accepted_types"] == []

    async def test_register_over_count_accepted_types_generic_tool_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Boundary-level counterpart to
        ``test_service.test_oversized_accepted_types_of_unknown_values_still_hits_count_cap``:
        21 entries hits the count cap (a bare ``ValueError``) before any
        entry is checked against ``CONVERSATION_TYPES``, so the MCP layer
        sees the generic ``invalid_request`` shape, not the specific
        unknown-type error."""
        token = _token("agent-oversized-types-boundary")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Oversized Types",
                    "accepted_types": [f"bogus-{i}" for i in range(21)],
                },
            )

    async def test_register_oversized_single_accepted_type_entry_generic_tool_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Boundary test for the per-entry length cap:
        a single oversized entry (101 chars) must be rejected at the MCP
        boundary as generic invalid_request, not echoed verbatim."""
        token = _token("agent-oversized-entry-boundary")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {"display_name": "Entry Length Test", "accepted_types": ["x" * 101]},
            )

    async def test_register_schema_version_defaults_and_persists(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """min/max_schema_version default to 1/1 and round-trip
        through both comms_register's own response and comms_whoami."""
        token = _token("agent-schema-default")
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Schema Default", "accepted_types": ["availability_request"]},
        )
        assert result["min_schema_version"] == 1
        assert result["max_schema_version"] == 1

        whoami = await _call(main, test_session_factory, token, "comms_whoami")
        assert whoami["min_schema_version"] == 1
        assert whoami["max_schema_version"] == 1

    async def test_register_explicit_schema_version_range_persists(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-schema-explicit")
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Schema Explicit",
                "accepted_types": ["availability_request"],
                "min_schema_version": 1,
                "max_schema_version": 2,
            },
        )
        assert result["min_schema_version"] == 1
        assert result["max_schema_version"] == 2

    async def test_register_min_schema_version_over_max_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("agent-schema-bad-range")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Bad Range",
                    "accepted_types": ["availability_request"],
                    "min_schema_version": 3,
                    "max_schema_version": 2,
                },
            )

    async def test_register_min_schema_version_below_one_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The lower-bound guard applies at the
        tool layer too, not just service.register_agent directly."""
        token = _token("agent-schema-below-one-tool")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Below One",
                    "accepted_types": ["availability_request"],
                    "min_schema_version": 0,
                    "max_schema_version": 0,
                },
            )

    async def test_whoami_omits_schema_version_before_registration(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A caller who hasn't called comms_register yet gets the same
        whoami shape as before schema-version negotiation was added — no
        schema-version fields, and no error just for having never registered
        (whoami is DB-optional)."""
        token = _token("agent-never-registered")
        whoami = await _call(main, test_session_factory, token, "comms_whoami")
        assert "min_schema_version" not in whoami
        assert "max_schema_version" not in whoami

    async def test_register_is_shared_true_baseline_scope_succeeds(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A caller with only the baseline ``comms:write`` scope CAN
        self-declare ``is_shared=True`` on its own first registration (as of
        2026-09-03, confirmed product decision, DESIGN.md §5): an agent
        declaring its own ``is_shared`` isn't a privilege escalation, since
        it only affects admission/risk-scoring checks involving that same
        agent. This is unrelated to ``comms_set_agent_shared`` and
        ``comms_admin_register``, which still require elevated scope because
        they act on a `sub` other than the caller's own."""
        token = _token("agent-is-shared-self-declare", scopes=["comms:read", "comms:write"])
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Self Declared Shared",
                "accepted_types": ["availability_request"],
                "is_shared": True,
            },
        )
        assert result["is_shared"] is True

    async def test_register_is_shared_true_with_admin_scope_succeeds(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """An elevated ``comms:admin`` scope also succeeds for self-registration
        with ``is_shared=True`` (it was the only path before 2026-09-03, and
        remains a valid, non-minimal path now that baseline ``comms:write``
        alone suffices too); the response echoes ``is_shared``."""
        token = _token(
            "agent-is-shared-authorized", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Authorized Shared",
                "accepted_types": ["availability_request"],
                "is_shared": True,
            },
        )
        assert result["is_shared"] is True

    async def test_register_is_shared_default_false_no_admin_scope_needed(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The default (``is_shared`` omitted, i.e. ``False``) never needed
        the elevated scope -- and as of TECH-6002 (2026-09-03), requesting
        ``True`` on self-registration doesn't need it either."""
        token = _token("agent-is-shared-default", scopes=["comms:read", "comms:write"])
        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Default Not Shared", "accepted_types": ["availability_request"]},
        )
        assert result["is_shared"] is False

    async def test_register_is_shared_frozen_at_mcp_boundary(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Tool-layer counterpart to
        ``test_service.test_is_shared_frozen_on_reregister``: re-registering
        through the MCP tool without the admin scope the second time neither
        gets denied (the gate only fires on FIRST registration) nor changes
        the already-frozen stored value -- freeze semantics hold at this
        boundary too."""
        admin_token = _token(
            "agent-is-shared-freeze-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        first = await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_register",
            {
                "display_name": "Freeze v1",
                "accepted_types": ["availability_request"],
                "is_shared": True,
            },
        )
        assert first["is_shared"] is True

        unauthorized_token = _token(
            "agent-is-shared-freeze-mcp", scopes=["comms:read", "comms:write"]
        )
        second = await _call(
            main,
            test_session_factory,
            unauthorized_token,
            "comms_register",
            {
                "display_name": "Freeze v2",
                "accepted_types": ["availability_request"],
                "is_shared": True,
            },
        )
        assert second["is_shared"] is True
        assert second["display_name"] == "Freeze v2"

    async def test_register_is_shared_false_to_true_upgrade_attempt_stays_false(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The freeze boundary in the OTHER direction: an agent first
        registered with ``is_shared=False`` cannot be upgraded to ``True``
        on re-registration, even without attempting the admin-scope gate
        (freeze is checked before authorization would even matter, since
        ``is_shared_authorized`` only gates FIRST registration)."""
        token = _token("agent-is-shared-upgrade-attempt", scopes=["comms:read", "comms:write"])
        first = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {"display_name": "Upgrade v1", "accepted_types": ["availability_request"]},
        )
        assert first["is_shared"] is False

        second = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Upgrade v2",
                "accepted_types": ["availability_request"],
                "is_shared": True,
            },
        )
        assert second["is_shared"] is False
        assert second["display_name"] == "Upgrade v2"

    async def test_register_is_shared_true_interactive_caller_succeeds(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """As of TECH-6002 (2026-09-03), ALL callers can self-declare
        ``is_shared=True`` on first registration -- there's no ``comms:admin``
        gate left for any caller type to bypass. This exercises an interactive
        (Okta) caller specifically: one with no ``scopes`` claim at all still
        succeeds, same as a plain ``comms:write`` agent-jwt caller would."""
        interactive_token = MagicMock()
        interactive_token.claims = {
            "iss": "https://agent-comms.example/mcp",
            "sub": "interactive-shared-owner",
            "email": "interactive-shared-owner@example.com",
        }
        interactive_token.scopes = []
        interactive_token.client_id = "interactive-shared-owner"

        result = await _call(
            main,
            test_session_factory,
            interactive_token,
            "comms_register",
            {
                "display_name": "Interactive Shared",
                "accepted_types": ["availability_request"],
                "is_shared": True,
            },
        )
        assert result["is_shared"] is True

    async def test_omitting_agent_key_after_a_keyed_registration_is_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """TECH-5736 regression: the exact incident shape. A caller
        registers once with ``agent_key="bond-007"``, then calls again
        omitting ``agent_key`` entirely -- this must be rejected as an
        identity fork, not silently create a second, stray row on the
        bare base sub."""
        token = _token("dan-example-mcp", owner_sub="dan-example-mcp")
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Bond 007",
                "accepted_types": ["availability_request"],
                "agent_key": "bond-007",
            },
        )

        with pytest.raises(ToolError, match="identity_fork_detected"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Bond 007 (stray)",
                    "accepted_types": ["availability_request"],
                },
            )

        whoami_original = await _call(
            main,
            test_session_factory,
            _token("dan-example-mcp", owner_sub="dan-example-mcp"),
            "comms_lookup_agent_by_email",
            {"owner_email": "dan-example-mcp"},
        )
        # The stray bare-sub row was never created -- the directory lookup
        # still resolves to the ORIGINAL, correctly-keyed identity.
        assert whoami_original["agent"]["sub"] == "dan-example-mcp::bond-007"

    async def test_confirm_new_identity_allows_the_fork_deliberately(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("multi-agent-human-mcp", owner_sub="multi-agent-human-mcp")
        await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Agent One",
                "accepted_types": ["availability_request"],
                "agent_key": "one",
            },
        )

        result = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Agent Two",
                "accepted_types": ["availability_request"],
                "agent_key": "two",
                "confirm_new_identity": True,
            },
        )
        assert result["sub"] == "multi-agent-human-mcp::two"

    async def test_display_name_collision_rejected_across_different_base_subs(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(
            main, test_session_factory, "display-collision-agent-a", display_name="Bond 007"
        )

        with pytest.raises(ToolError, match="display_name_collision"):
            await _call(
                main,
                test_session_factory,
                _token("display-collision-agent-b"),
                "comms_register",
                {"display_name": "Bond 007", "accepted_types": ["availability_request"]},
            )

    async def test_display_name_collision_not_triggered_by_own_re_registration(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(
            main, test_session_factory, "self-rename-agent-mcp", display_name="Same Name"
        )

        result = await _call(
            main,
            test_session_factory,
            _token("self-rename-agent-mcp"),
            "comms_register",
            {"display_name": "Same Name", "accepted_types": ["availability_request"]},
        )
        assert result["display_name"] == "Same Name"


# --- Admin override of is_shared -------------------------------------------------


class TestSetAgentShared:
    async def test_admin_scope_can_correct_is_shared(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """An agent that self-registered with the wrong ``is_shared`` value
        (frozen against its own re-registration, see ``TestRegister``'s
        freeze tests) can be corrected via ``comms_set_agent_shared`` by a
        ``comms:admin``-scoped caller."""
        registered = await _register(main, test_session_factory, "wrongly-not-shared-mcp")
        assert registered["is_shared"] is False

        admin_token = _token(
            "admin-operator-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        result = await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_set_agent_shared",
            {"agent_id": registered["agent_id"], "is_shared": True},
        )
        assert result["is_shared"] is True
        assert result["agent_id"] == registered["agent_id"]

    async def test_requires_admin_scope(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        registered = await _register(main, test_session_factory, "override-unauthorized-mcp")

        unauthorized_token = _token(
            "unauthorized-operator-mcp", scopes=["comms:read", "comms:write"]
        )
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                unauthorized_token,
                "comms_set_agent_shared",
                {"agent_id": registered["agent_id"], "is_shared": True},
            )

    async def test_unknown_agent_id_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        admin_token = _token(
            "admin-operator-mcp-2", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                admin_token,
                "comms_set_agent_shared",
                {"agent_id": str(uuid.uuid4()), "is_shared": True},
            )

    async def test_interactive_caller_no_admin_scope_needed(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        registered = await _register(main, test_session_factory, "wrongly-not-shared-interactive")

        interactive_token = MagicMock()
        interactive_token.claims = {
            "iss": "https://agent-comms.example/mcp",
            "sub": "interactive-admin-operator",
        }
        interactive_token.scopes = []
        interactive_token.client_id = "interactive-admin-operator"

        result = await _call(
            main,
            test_session_factory,
            interactive_token,
            "comms_set_agent_shared",
            {"agent_id": registered["agent_id"], "is_shared": True},
        )
        assert result["is_shared"] is True


class TestDeregisterAgent:
    """TECH-5736: comms_deregister_agent, the tool that finally exercises
    AGENT_STATUSES's long-unused "suspended" value."""

    async def test_admin_scope_can_deregister(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        registered = await _register(main, test_session_factory, "stray-agent-mcp")

        admin_token = _token(
            "admin-operator-deregister-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        result = await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": registered["agent_id"]},
        )
        assert result["status"] == "suspended"
        assert result["agent_id"] == registered["agent_id"]

    async def test_requires_admin_scope(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        registered = await _register(main, test_session_factory, "deregister-unauthorized-mcp")

        unauthorized_token = _token(
            "unauthorized-deregister-operator-mcp", scopes=["comms:read", "comms:write"]
        )
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                unauthorized_token,
                "comms_deregister_agent",
                {"agent_id": registered["agent_id"]},
            )

    async def test_unknown_agent_id_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        admin_token = _token(
            "admin-operator-deregister-mcp-2", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                admin_token,
                "comms_deregister_agent",
                {"agent_id": str(uuid.uuid4())},
            )

    async def test_interactive_caller_no_admin_scope_needed(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        registered = await _register(main, test_session_factory, "stray-agent-interactive-mcp")

        interactive_token = MagicMock()
        interactive_token.claims = {
            "iss": "https://agent-comms.example/mcp",
            "sub": "interactive-deregister-operator",
        }
        interactive_token.scopes = []
        interactive_token.client_id = "interactive-deregister-operator"

        result = await _call(
            main,
            test_session_factory,
            interactive_token,
            "comms_deregister_agent",
            {"agent_id": registered["agent_id"]},
        )
        assert result["status"] == "suspended"

    async def test_suspended_agent_loses_read_path_access(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """TECH-5736 suggestion: suspension is meant to be a real kill
        switch, but before this fix, `_resolve_caller_agent` had no status
        filter -- a suspended agent's still-unexpired token kept working
        for every read-path tool (comms_inbox and friends) that resolves the
        caller's own identity through it. Confirms comms_inbox now rejects a
        suspended caller instead of quietly serving it."""
        registered = await _register(main, test_session_factory, "kill-switch-target-mcp")

        admin_token = _token(
            "admin-operator-kill-switch-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": registered["agent_id"]},
        )

        with pytest.raises(ToolError, match="agent_suspended"):
            await _call(
                main,
                test_session_factory,
                _token("kill-switch-target-mcp"),
                "comms_inbox",
            )

    async def test_suspended_agent_cannot_re_register(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """TECH-5736 suggestion: the same `_resolve_caller_agent`
        suspension check covered above for `comms_inbox` also needs
        coverage on the `comms_register` tool-boundary itself -- the write
        path a suspended agent is most likely to retry with its
        still-unexpired token. Confirms a deregistered agent calling
        `comms_register` again (same `sub`, same token) is rejected with
        `agent_suspended` rather than being silently reactivated."""
        registered = await _register(main, test_session_factory, "kill-switch-reregister-mcp")

        admin_token = _token(
            "admin-operator-kill-switch-reregister-mcp",
            scopes=["comms:read", "comms:write", "comms:admin"],
        )
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": registered["agent_id"]},
        )

        with pytest.raises(ToolError, match="agent_suspended"):
            await _register(main, test_session_factory, "kill-switch-reregister-mcp")

    async def test_new_agent_key_after_suspending_all_siblings_requires_confirmation(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """MCP-boundary regression for the kill-switch-bypass gap
        (mirrors ``test_service.py``'s
        ``test_reentry_after_suspending_all_siblings_requires_confirmation``):
        register agent A under a base sub with ``agent_key="a1"``, suspend
        it via ``comms_deregister_agent``, then attempt to register a NEW
        ``agent_key="a2"`` under the same base sub without
        ``confirm_new_identity``. The fully-suspended base sub must still
        be treated as having an existing sibling identity, not a fresh
        one -- this must raise ``identity_fork_detected``, not silently
        succeed."""
        base_sub = "kill-switch-fork-mcp"
        token = _token(base_sub, owner_sub=base_sub)
        registered = await _call(
            main,
            test_session_factory,
            token,
            "comms_register",
            {
                "display_name": "Agent A1",
                "accepted_types": ["availability_request"],
                "agent_key": "a1",
            },
        )

        admin_token = _token(
            "admin-operator-kill-switch-fork-mcp",
            scopes=["comms:read", "comms:write", "comms:admin"],
        )
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": registered["agent_id"]},
        )

        with pytest.raises(ToolError, match="identity_fork_detected") as exc_info:
            await _call(
                main,
                test_session_factory,
                _token(base_sub, owner_sub=base_sub),
                "comms_register",
                {
                    "display_name": "Agent A2",
                    "accepted_types": ["availability_request"],
                    "agent_key": "a2",
                },
            )
        assert "a1" not in str(exc_info.value)

        confirmed = await _call(
            main,
            test_session_factory,
            _token(base_sub, owner_sub=base_sub),
            "comms_register",
            {
                "display_name": "Agent A2",
                "accepted_types": ["availability_request"],
                "agent_key": "a2",
                "confirm_new_identity": True,
            },
        )
        assert confirmed["agent_id"]

    async def test_admin_can_still_deregister_target_while_admins_own_agent_suspended(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The caller-suspension check lives in `_resolve_caller_agent`,
        which resolves the CALLER's own identity -- `comms_deregister_agent`
        looks up its TARGET directly by `agent_id`
        (`service._find_agent_by_id`), never through that function. An
        admin whose own registered agent has been suspended must still be
        able to deregister someone else -- the admin scope on the token is
        what gates this tool, not the admin's own board-agent row."""
        admin_registered = await _register(main, test_session_factory, "admin-self-suspended-mcp")
        target = await _register(main, test_session_factory, "another-stray-agent-mcp")

        admin_token = _token(
            "admin-self-suspended-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        # Suspend the admin's own agent row first.
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": admin_registered["agent_id"]},
        )

        # The admin's token (comms:admin scope) can still deregister a
        # different target -- the tool never resolves the admin's own agent
        # row via _resolve_caller_agent.
        result = await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": target["agent_id"]},
        )
        assert result["status"] == "suspended"


class TestAdminRegister:
    """Argus round 1 finding (TECH-5786 PR follow-up): the service-layer
    tests in test_service.py call service.admin_register_agent directly
    with admin_authorized pre-set, so they can't catch a wrong
    provider-side authorization computation. These exercise the actual
    MCP boundary -- comms_admin_register's own token-gate and
    _map_service_errors path -- mirroring TestSetAgentShared/
    TestDeregisterAgent's own coverage of their sibling admin tools."""

    async def test_admin_scope_can_register(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        admin_token = _token(
            "admin-operator-register-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        result = await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_admin_register",
            {
                "sub": "arc-bot-mcp-boundary",
                "owner_sub": "owner-arc-bot-mcp-boundary",
                "owner_email": "arc-bot-mcp-boundary@example.com",
                "display_name": "Arc Bot MCP Boundary",
                "accepted_types": sorted(MESSAGE_TYPES),
                "is_shared": True,
            },
        )
        assert result["sub"] == "arc-bot-mcp-boundary"
        assert result["owner_email"] == "arc-bot-mcp-boundary@example.com"
        assert result["is_shared"] is True
        assert result["status"] == "active"
        assert result["min_schema_version"] == 1
        assert result["max_schema_version"] == 1
        assert result["accepted_types"] == sorted(MESSAGE_TYPES)
        assert "agent_id" in result

    async def test_interactive_caller_no_admin_scope_needed(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        interactive_token = MagicMock()
        interactive_token.claims = {
            "iss": "https://agent-comms.example/mcp",
            "sub": "interactive-admin-register-operator",
        }
        interactive_token.scopes = []
        interactive_token.client_id = "interactive-admin-register-operator"

        result = await _call(
            main,
            test_session_factory,
            interactive_token,
            "comms_admin_register",
            {
                "sub": "arc-bot-interactive-mcp",
                "owner_sub": "owner-arc-bot-interactive-mcp",
                "owner_email": "arc-bot-interactive-mcp@example.com",
                "display_name": "Arc Bot Interactive MCP",
                "accepted_types": sorted(MESSAGE_TYPES),
            },
        )
        assert result["sub"] == "arc-bot-interactive-mcp"

    async def test_requires_admin_scope(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        unauthorized_token = _token(
            "unauthorized-admin-register-operator-mcp", scopes=["comms:read", "comms:write"]
        )
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                unauthorized_token,
                "comms_admin_register",
                {
                    "sub": "arc-bot-unauthorized-mcp",
                    "owner_sub": "owner-arc-bot-unauthorized-mcp",
                    "owner_email": "arc-bot-unauthorized-mcp@example.com",
                    "display_name": "Arc Bot Unauthorized MCP",
                    "accepted_types": sorted(MESSAGE_TYPES),
                },
            )

    async def test_already_registered_maps_to_tool_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        registered = await _register(main, test_session_factory, "already-registered-mcp")
        admin_token = _token(
            "admin-operator-already-registered-mcp",
            scopes=["comms:read", "comms:write", "comms:admin"],
        )
        with pytest.raises(ToolError, match=re.escape("already_registered")):
            await _call(
                main,
                test_session_factory,
                admin_token,
                "comms_admin_register",
                {
                    "sub": registered["sub"],
                    "owner_sub": "owner-already-registered-mcp",
                    "owner_email": "already-registered-mcp-new@example.com",
                    "display_name": "Already Registered MCP Attempt",
                    "accepted_types": sorted(MESSAGE_TYPES),
                },
            )

    async def test_invalid_schema_version_range_maps_to_tool_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        admin_token = _token(
            "admin-operator-bad-schema-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        with pytest.raises(ToolError, match=re.escape("invalid_request")):
            await _call(
                main,
                test_session_factory,
                admin_token,
                "comms_admin_register",
                {
                    "sub": "arc-bot-bad-schema-mcp",
                    "owner_sub": "owner-arc-bot-bad-schema-mcp",
                    "owner_email": "arc-bot-bad-schema-mcp@example.com",
                    "display_name": "Arc Bot Bad Schema MCP",
                    "accepted_types": sorted(MESSAGE_TYPES),
                    "min_schema_version": 2,
                    "max_schema_version": 1,
                },
            )

    async def test_sibling_identity_fork_denied_without_confirm(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Argus round 2 BLOCKING finding (TECH-5786 PR follow-up): the
        confirm_new_identity forwarding at the provider layer is untested
        at any provider-layer boundary -- service-layer tests call
        admin_register_agent directly with admin_authorized pre-set, so a
        provider wrapper that silently dropped or hardcoded
        confirm_new_identity=False would pass the whole suite while
        reopening the §8 kill-switch bypass invariant."""
        await _register(main, test_session_factory, "fork-mcp-base-sub")

        admin_token = _token(
            "admin-operator-fork-mcp", scopes=["comms:read", "comms:write", "comms:admin"]
        )
        with pytest.raises(ToolError, match="identity_fork_detected"):
            await _call(
                main,
                test_session_factory,
                admin_token,
                "comms_admin_register",
                {
                    "sub": "fork-mcp-base-sub::second-key",
                    "owner_sub": "owner-fork-mcp-base-sub-second-key",
                    "owner_email": "fork-mcp-base-sub-second-key@example.com",
                    "display_name": "Fork MCP Base Sub Second Key",
                    "accepted_types": sorted(MESSAGE_TYPES),
                },
            )

    async def test_confirm_new_identity_allows_the_fork_deliberately(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "fork-confirmed-mcp-base-sub")

        admin_token = _token(
            "admin-operator-fork-confirmed-mcp",
            scopes=["comms:read", "comms:write", "comms:admin"],
        )
        result = await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_admin_register",
            {
                "sub": "fork-confirmed-mcp-base-sub::second-key",
                "owner_sub": "owner-fork-confirmed-mcp-base-sub-second-key",
                "owner_email": "fork-confirmed-mcp-base-sub-second-key@example.com",
                "display_name": "Fork Confirmed MCP Base Sub Second Key",
                "accepted_types": sorted(MESSAGE_TYPES),
                "confirm_new_identity": True,
            },
        )
        assert result["sub"] == "fork-confirmed-mcp-base-sub::second-key"

    async def test_already_registered_maps_to_tool_error_when_suspended(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Argus round 2 suggestion (TECH-5786 PR follow-up):
        test_already_registered_maps_to_tool_error only covers the
        active-status case; the underlying _deny_agent_already_registered
        helper doesn't distinguish status, but the MCP-boundary path was
        otherwise unverified for a suspended target."""
        registered = await _register(main, test_session_factory, "suspended-already-registered-mcp")
        admin_token = _token(
            "admin-operator-suspended-already-registered-mcp",
            scopes=["comms:read", "comms:write", "comms:admin"],
        )
        await _call(
            main,
            test_session_factory,
            admin_token,
            "comms_deregister_agent",
            {"agent_id": registered["agent_id"]},
        )

        with pytest.raises(ToolError, match=re.escape("already_registered")):
            await _call(
                main,
                test_session_factory,
                admin_token,
                "comms_admin_register",
                {
                    "sub": registered["sub"],
                    "owner_sub": "owner-suspended-already-registered-mcp",
                    "owner_email": "suspended-already-registered-mcp-new@example.com",
                    "display_name": "Suspended Already Registered MCP Attempt",
                    "accepted_types": sorted(MESSAGE_TYPES),
                },
            )


# --- AXI empty-state / shape spot checks --------------------------------------------


class TestAxiShapes:
    async def test_inbox_empty_state_is_explicit(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "lonely-agent")
        result = await _call(main, test_session_factory, _token("lonely-agent"), "comms_inbox")
        assert result == {
            "unread": [],
            "unread_has_more": False,
            "pending_invites": [],
            "pending_invites_has_more": False,
            "total_count": 0,
        }

    async def test_inbox_excludes_own_message_by_default(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """comms_post_message never advances the sender's own read cursor,
        so B's own reply -- posted without B ever reading anything via
        comms_get_conversation -- must not echo back as "unread" on B's
        own next comms_inbox call, unless B opts back in via
        include_own_messages=True."""
        await _register(main, test_session_factory, "inbox-tool-a")
        await _register(main, test_session_factory, "inbox-tool-b")
        token_a = _token("inbox-tool-a")
        token_b = _token("inbox-tool-b")

        list_result = await _call(main, test_session_factory, token_a, "comms_list_agents")
        b_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "inbox-tool-b")

        started = await _call(
            main,
            test_session_factory,
            token_a,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [b_id],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            token_b,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        # B reads A's initial message, then posts its own reply on top --
        # only B's own message is now ahead of B's cursor.
        await _call(
            main,
            test_session_factory,
            token_b,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        await _call(
            main,
            test_session_factory,
            token_b,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "availability_response",
                "payload": _availability_response(),
            },
        )

        default_result = await _call(main, test_session_factory, token_b, "comms_inbox")
        assert default_result["unread"] == []
        assert default_result["total_count"] == 0

        with_own = await _call(
            main, test_session_factory, token_b, "comms_inbox", {"include_own_messages": True}
        )
        assert len(with_own["unread"]) == 1
        assert with_own["unread"][0]["conversation_id"] == conversation_id
        assert with_own["unread"][0]["unread_count"] == 1

    async def test_inbox_include_read_surfaces_fully_read_conversation(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "inbox-tool-read-a")
        await _register(main, test_session_factory, "inbox-tool-read-b")
        token_a = _token("inbox-tool-read-a")
        token_b = _token("inbox-tool-read-b")

        list_result = await _call(main, test_session_factory, token_a, "comms_list_agents")
        b_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "inbox-tool-read-b")

        started = await _call(
            main,
            test_session_factory,
            token_a,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [b_id],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            token_b,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        await _call(
            main,
            test_session_factory,
            token_b,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )

        default_result = await _call(main, test_session_factory, token_b, "comms_inbox")
        assert default_result["unread"] == []

        read_result = await _call(
            main, test_session_factory, token_b, "comms_inbox", {"include_read": True}
        )
        assert len(read_result["unread"]) == 1
        assert read_result["unread"][0]["conversation_id"] == conversation_id
        assert read_result["unread"][0]["unread_count"] == 0

    async def test_list_agents_includes_total_count(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "dir-agent-1")
        await _register(main, test_session_factory, "dir-agent-2")
        result = await _call(main, test_session_factory, _token("dir-agent-1"), "comms_list_agents")
        assert result["total_count"] == 2
        assert result["has_more"] is False
        assert {a["sub"] for a in result["agents"]} == {"dir-agent-1", "dir-agent-2"}

    async def test_list_agents_surfaces_is_shared(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Regression pin: `_agent_public`'s directory projection must
        include `is_shared` -- it was dropped silently (only `agent_id`,
        `sub`, `display_name`, `owner_email`, `accepted_types`, `status`
        were emitted), so an agent deciding how much to disclose to a peer
        on the board had no field to consult before answering."""
        await _register(main, test_session_factory, "dir-agent-plain")
        await _call(
            main,
            test_session_factory,
            _token("dir-agent-shared", scopes=["comms:read", "comms:write", "comms:admin"]),
            "comms_register",
            {
                "display_name": "dir-agent-shared",
                "accepted_types": sorted(MESSAGE_TYPES),
                "is_shared": True,
            },
        )
        result = await _call(
            main, test_session_factory, _token("dir-agent-plain"), "comms_list_agents"
        )
        by_sub = {a["sub"]: a for a in result["agents"]}
        assert by_sub["dir-agent-plain"]["is_shared"] is False
        assert by_sub["dir-agent-shared"]["is_shared"] is True

    async def test_lookup_agent_by_email_finds_registered_agent(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "ea-dan", owner_email="Dan@Example.com")
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": "  dan@example.com\t"},
        )
        assert result["found"] is True
        assert result["agent"]["sub"] == "ea-dan"
        assert result["agent"]["owner_email"] == "Dan@Example.com"
        assert result["agent"]["is_shared"] is False

    async def test_lookup_agent_by_email_unknown_email_returns_none(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": "nobody@example.com"},
        )
        assert result == {"agent": None, "found": False}

    async def test_lookup_agent_by_email_rejects_empty_email(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": "   "},
        )
        assert result == {"agent": None, "found": False}

    async def test_lookup_agent_by_email_rejects_over_length_email(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # One over service.MAX_LOOKUP_EMAIL_LENGTH -- never reaches the
        # query, so no matching row is required for this to prove the
        # guard fires rather than a legitimate not-found (mirrors
        # test_service.py::TestLookupAgentByEmail.test_over_length_fails_closed
        # at the tool layer).
        from service import MAX_LOOKUP_EMAIL_LENGTH

        over_length = "a" * (MAX_LOOKUP_EMAIL_LENGTH + 1)
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": over_length},
        )
        assert result == {"agent": None, "found": False}

    async def test_lookup_agent_by_email_excludes_suspended_agent(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(
            main, test_session_factory, "ea-suspended", owner_email="suspend@example.com"
        )
        async with test_session_factory() as session:
            await session.execute(
                text("UPDATE agents SET status = 'suspended' WHERE sub = 'ea-suspended'")
            )
            await session.commit()
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": "suspend@example.com"},
        )
        assert result == {"agent": None, "found": False}

    async def test_lookup_agent_by_email_tie_break_prefers_most_recently_bound(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Same owner_email, two distinct subs -- an anticipated state (the
        # agent_key mechanism lets one owner run multiple board-active
        # agents under one email), not an error case. bound_at is forced
        # apart explicitly rather than relied on via real-time gaps between
        # the two registrations, which could otherwise tie down to the
        # microsecond.
        await _register(main, test_session_factory, "ea-old", owner_email="multi@example.com")
        await _register(main, test_session_factory, "ea-new", owner_email="multi@example.com")
        async with test_session_factory() as session:
            await session.execute(
                text(
                    "UPDATE agents SET bound_at = "
                    "(SELECT bound_at FROM agents WHERE sub = 'ea-new') - interval '1 hour' "
                    "WHERE sub = 'ea-old'"
                )
            )
            await session.commit()
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": "multi@example.com"},
        )
        assert result["found"] is True
        assert result["agent"]["sub"] == "ea-new"

    async def test_lookup_agent_by_email_tie_break_falls_through_to_id(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # The documented equal-bound_at case (see
        # test_service.py::TestLookupAgentByEmail's equal-bound_at-and-created_at
        # test): two agents sharing bound_at AND created_at (both forced equal here
        # via direct SQL UPDATE, not merely left to same-transaction chance)
        # must still resolve deterministically via the id tiebreaker, not
        # arbitrarily.
        await _register(main, test_session_factory, "ea-tie-a", owner_email="tie@example.com")
        await _register(main, test_session_factory, "ea-tie-b", owner_email="tie@example.com")
        async with test_session_factory() as session:
            await session.execute(
                text(
                    "UPDATE agents SET bound_at = "
                    "(SELECT bound_at FROM agents WHERE sub = 'ea-tie-a'), "
                    "created_at = (SELECT created_at FROM agents WHERE sub = 'ea-tie-a') "
                    "WHERE sub = 'ea-tie-b'"
                )
            )
            await session.commit()
            ids = {
                row[0]: row[1]
                for row in (
                    await session.execute(
                        text("SELECT sub, id FROM agents WHERE sub IN ('ea-tie-a', 'ea-tie-b')")
                    )
                ).all()
            }
        # Agent.id.asc() -- the smaller id sorts first and wins the tie.
        expected_sub = "ea-tie-a" if ids["ea-tie-a"] < ids["ea-tie-b"] else "ea-tie-b"
        result = await _call(
            main,
            test_session_factory,
            _token("dir-agent-1"),
            "comms_lookup_agent_by_email",
            {"owner_email": "tie@example.com"},
        )
        assert result["found"] is True
        assert result["agent"]["sub"] == expected_sub

    async def test_lookup_agent_by_email_denied_without_read_scope(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("scope-test-lookup", scopes=["comms:write"])
        with pytest.raises(ToolError, match="requires elevated permissions"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_lookup_agent_by_email",
                {"owner_email": "nobody@example.com"},
            )


# --- Unregistered-caller path --------------------------------------------------------


class TestNotRegistered:
    async def test_unregistered_caller_gets_distinct_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(ToolError, match="not_registered"):
            await _call(main, test_session_factory, _token("never-registered"), "comms_inbox")


# --- Full happy-path negotiation ------------------------------------------------------


class TestFullNegotiationFlow:
    async def test_full_flow(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "agent-a")
        await _register(main, test_session_factory, "agent-b")
        await _register(main, test_session_factory, "agent-c")

        token_a = _token("agent-a")
        token_b = _token("agent-b")
        token_c = _token("agent-c")

        # A starts a conversation with B and C.
        list_result = await _call(main, test_session_factory, token_a, "comms_list_agents")
        by_sub = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

        started = await _call(
            main,
            test_session_factory,
            token_a,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [by_sub["agent-b"], by_sub["agent-c"]],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]
        assert started["state"] == "active"

        # B accepts, then sees full history (the seq-1 availability_request).
        accepted = await _call(
            main,
            test_session_factory,
            token_b,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        assert accepted["status"] == "active"

        b_view = await _call(
            main,
            test_session_factory,
            token_b,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert b_view["invited"] is False
        assert [m["type"] for m in b_view["messages"]] == ["availability_request"]
        # Tool-boundary rename: the count key is ``messages_returned``, not
        # ``total_count`` (which would misleadingly imply the conversation's
        # total message count rather than this since_seq-filtered slice).
        assert "messages_returned" in b_view
        assert b_view["messages_returned"] == 1
        assert "total_count" not in b_view
        # page_max_seq is the documented continuation token (Argus round-2
        # SUGGESTION: untested at the tool boundary until now).
        assert b_view["page_max_seq"] == 1
        assert b_view["has_more"] is False

        # C never accepts — metadata-only, no message content.
        c_view = await _call(
            main,
            test_session_factory,
            token_c,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert c_view["invited"] is True
        assert c_view["messages"] == []
        # Metadata-only path: no message-count field at all (neither the
        # renamed ``messages_returned`` nor the original ``total_count``),
        # unlike the active-member path asserted above.
        assert "messages_returned" not in c_view
        assert "total_count" not in c_view
        assert "invited_by" in c_view
        assert c_view["has_more"] is False

        # B posts an availability_response.
        b_response = await _call(
            main,
            test_session_factory,
            token_b,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "availability_response",
                "payload": _availability_response(),
            },
        )
        assert b_response["seq"] == 2

        # A confirms — conversation completes.
        a_confirm = await _call(
            main,
            test_session_factory,
            token_a,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "confirm",
                "payload": _confirm_payload(),
            },
        )
        assert a_confirm["seq"] == 3

        final_view = await _call(
            main,
            test_session_factory,
            token_a,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert final_view["conversation"]["state"] == "completed"

        # Further posts are rejected — a state-machine violation, NOT the
        # uniform denial (the caller is still an authorized active member).
        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_b,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "availability_response",
                    "payload": _availability_response(),
                },
            )
        assert "access_denied" not in str(exc_info.value)
        assert "completed" in str(exc_info.value)

    async def test_uniform_denial_identical_for_non_member_and_uninvited_caller(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "owner-x")
        await _register(main, test_session_factory, "invitee-x")
        await _register(main, test_session_factory, "outsider-x")

        token_owner = _token("owner-x")
        token_invitee = _token("invitee-x")
        token_outsider = _token("outsider-x")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        invitee_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "invitee-x")

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [invitee_id],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        # invitee-x is INVITED but has not accepted — posting is denied.
        with pytest.raises(ToolError) as invitee_exc:
            await _call(
                main,
                test_session_factory,
                token_invitee,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "availability_response",
                    "payload": _availability_response(),
                },
            )

        # outsider-x is a registered agent with NO participant row at all.
        with pytest.raises(ToolError) as outsider_exc:
            await _call(
                main,
                test_session_factory,
                token_outsider,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "availability_response",
                    "payload": _availability_response(),
                },
            )

        # Anti-enumeration: byte-identical denial message for both causes.
        assert str(invitee_exc.value) == str(outsider_exc.value)
        assert str(invitee_exc.value) == "access_denied: not authorized for this resource"

        # Same uniform message reading a conversation the outsider was
        # never named on at all.
        with pytest.raises(ToolError) as outsider_read_exc:
            await _call(
                main,
                test_session_factory,
                token_outsider,
                "comms_get_conversation",
                {"conversation_id": conversation_id},
            )
        assert str(outsider_read_exc.value) == str(invitee_exc.value)


# --- Rate limit / schema validation: distinct, informative messages -----------------


class TestRateLimitAndSchemaErrors:
    async def test_rate_limit_error_is_specific_not_uniform(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import service

        monkeypatch.setattr(service, "MAX_CONVERSATION_STARTS_PER_HOUR", 1)

        await _register(main, test_session_factory, "rl-owner")
        await _register(main, test_session_factory, "rl-target")
        token_owner = _token("rl-owner")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "rl-target")

        # First start succeeds and consumes the (patched) budget of 1.
        await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target_id],
                "initial_message": _availability_request(),
            },
        )

        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [target_id],
                    "initial_message": _availability_request(),
                },
            )
        message = str(exc_info.value)
        assert "rate_limited" in message
        assert message != "access_denied: not authorized for this resource"

    async def test_schema_validation_error_is_specific_not_uniform(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "sv-owner")
        await _register(main, test_session_factory, "sv-target")
        token_owner = _token("sv-owner")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "sv-target")

        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [target_id],
                    # missing required fields (duration_min, modality, priority)
                    "initial_message": {"window": _availability_request()["window"]},
                },
            )
        message = str(exc_info.value)
        assert "payload failed schema validation" in message
        assert message != "access_denied: not authorized for this resource"

    async def test_unknown_conversation_type_error_is_specific_not_uniform(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """An unsupported ``conversation_type`` surfaces a specific
        ``ToolError`` naming the actual valid set, the same
        discoverability fix as ``comms_register``'s ``accepted_types``
        (see ``TestRegister.test_register_unknown_accepted_type_names_valid_set_in_error``).
        Checked before any target lookup, so a bogus type doesn't need a
        real target to reproduce."""
        await _register(main, test_session_factory, "uct-owner")
        token_owner = _token("uct-owner")

        with pytest.raises(ToolError, match=r"unknown conversation_type 'bogus'"):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "bogus",
                    "target_agent_ids": [str(uuid.uuid4())],
                    "initial_message": _availability_request(),
                },
            )

    async def test_expires_at_beyond_ceiling_gives_actionable_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Argus round-1 BLOCKING catch: a too-far-future ``expires_at``
        must not fall through to the generic
        ``_map_service_errors``-collapsed ``ValueError`` message -- an
        agent gets no indication a ceiling exists at all otherwise. Fixed
        with a proactive tool-layer check (same pattern as the
        participant-count cap), mirroring TestRateLimitAndSchemaErrors'
        other specific-not-uniform tests in this class."""
        from datetime import UTC, datetime, timedelta

        from service import MAX_CONVERSATION_TTL

        await _register(main, test_session_factory, "ttl-ceiling-owner")
        await _register(main, test_session_factory, "ttl-ceiling-target")
        token_owner = _token("ttl-ceiling-owner")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "ttl-ceiling-target"
        )
        too_far = datetime.now(UTC) + MAX_CONVERSATION_TTL + timedelta(seconds=1)

        with pytest.raises(ToolError, match="expires_at may not be more than"):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [target_id],
                    "initial_message": _availability_request(),
                    "expires_at": too_far.isoformat(),
                },
            )

    async def test_negative_since_seq_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "neg-seq-owner")
        token_owner = _token("neg-seq-owner")

        # No conversation needs to exist yet — this is a pure input-shape
        # check the tool boundary performs before ever touching the DB.
        with pytest.raises(ToolError, match=re.escape("invalid_request: since_seq must be >= 0")):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_get_conversation",
                {"conversation_id": str(uuid.uuid4()), "since_seq": -1},
            )

    async def test_target_agent_ids_over_participant_cap_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        from schemas import MAX_PARTICIPANTS_PER_CONVERSATION

        await _register(main, test_session_factory, "cap-owner")
        token_owner = _token("cap-owner")
        too_many_ids = [str(uuid.uuid4()) for _ in range(MAX_PARTICIPANTS_PER_CONVERSATION + 1)]

        with pytest.raises(
            ToolError,
            match=re.escape(
                "invalid_request: target_agent_ids exceeds the participant cap "
                f"({MAX_PARTICIPANTS_PER_CONVERSATION})"
            ),
        ):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": too_many_ids,
                    "initial_message": _availability_request(),
                },
            )

    async def test_schema_version_mismatch_error_is_specific_not_uniform(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """An initiator and target with non-overlapping declared
        schema-version ranges get a specific ``ToolError``, not the uniform
        access-denied string — same anti-enumeration posture as the other
        specific errors in this class (rate limits, schema validation,
        unknown conversation type)."""
        await _register(
            main,
            test_session_factory,
            "sv-mismatch-owner",
            min_schema_version=1,
            max_schema_version=1,
        )
        await _register(
            main,
            test_session_factory,
            "sv-mismatch-target",
            min_schema_version=2,
            max_schema_version=2,
        )
        token_owner = _token("sv-mismatch-owner")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "sv-mismatch-target"
        )

        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [target_id],
                    "initial_message": _availability_request(),
                },
            )
        message = str(exc_info.value)
        assert "schema_version_mismatch" in message
        assert message != "access_denied: not authorized for this resource"
        # Anti-enumeration: the message is a fixed,
        # deterministic string with no embedded range values at all --
        # asserting full equality (rather than "no digits", which is
        # fragile against unrelated future digits in the text) is both
        # stronger and more specific here.
        assert message == (
            "schema_version_mismatch: no wire schema version is supported by "
            "every participant in this conversation"
        )

    async def test_start_conversation_response_includes_negotiated_schema_version(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The negotiated version must be
        discoverable from the response, not just silently applied."""
        await _register(main, test_session_factory, "sv-response-owner")
        await _register(main, test_session_factory, "sv-response-target")
        token_owner = _token("sv-response-owner")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "sv-response-target"
        )

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target_id],
                "initial_message": _availability_request(),
            },
        )
        assert started["schema_version"] == 1
        # TECH-5887 round-2: archived/archived_at are hand-maintained on
        # this one response (every other projection flows through
        # service._conversation_dict) -- assert both explicitly so drift
        # here is caught rather than only defended against by comment.
        assert started["archived"] is False
        assert started["archived_at"] is None


class TestOwnershipClientSeamIntegration:
    """Regression coverage for the actual functional change wiring the pluggable
    OwnershipClient seam (TECH-5396 open question 1) into providers/comms.py:
    the three call sites there now go through service.get_ownership_client_factory()
    instead of constructing AgentTableOwnershipClient directly. Exercise that
    through a real comms_start_conversation call, not just the seam in isolation
    (tests/test_plugins.py) or against service.py directly (bypasses providers/
    comms.py entirely)."""

    async def test_asymmetric_open_consults_the_configured_ownership_client(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import service

        # Two agents with genuinely DIFFERENT frozen owner_sub values -- an
        # asymmetric conversation between them would be denied
        # (denied.no_owner_overlap) under the real AgentTableOwnershipClient.
        # A fake plugin reporting them as sharing one owner set must admit it
        # instead, proving providers/comms.py actually consulted the
        # configured seam rather than constructing AgentTableOwnershipClient
        # directly.
        await _register(main, test_session_factory, "seam-owner-1", owner_sub="owner-a")
        await _register(main, test_session_factory, "seam-target-1", owner_sub="owner-b")
        token_owner = _token("seam-owner-1")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "seam-target-1"
        )

        class _FakeSharedOwnerClient:
            async def get_agent_owners(self, agent_id: Any) -> dict[str, Any]:
                return {"is_shared": False, "owners": ["same-owner-for-both@example.com"]}

        fake_instance = _FakeSharedOwnerClient()
        monkeypatch.setenv(
            service.OWNERSHIP_CLIENT_ENV_VAR,
            "tests.test_comms_tools:_fake_shared_owner_client_factory",
        )
        monkeypatch.setattr(
            "tests.test_comms_tools._fake_shared_owner_client_factory_instance", fake_instance
        )
        monkeypatch.setattr(service, "_ownership_client_factory", None)

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "asymmetric",
                "target_agent_ids": [target_id],
                "initial_message": _availability_request(),
            },
        )
        assert started["state"] == "active"

    async def test_asymmetric_open_deny_path_also_consults_the_configured_ownership_client(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import service

        # Two agents with the SAME frozen owner_sub -- under the real
        # AgentTableOwnershipClient, an asymmetric conversation between them
        # would be ADMITTED (owners overlap). A fake plugin reporting them as
        # having DISJOINT owner sets must instead deny it, proving the deny
        # branch also routes through the configured seam rather than
        # hardcoding AgentTableOwnershipClient (which the admit-path test
        # above cannot distinguish from this branch on its own).
        await _register(main, test_session_factory, "seam-owner-2", owner_sub="owner-shared")
        await _register(main, test_session_factory, "seam-target-2", owner_sub="owner-shared")
        token_owner = _token("seam-owner-2")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(
            a["agent_id"] for a in list_result["agents"] if a["sub"] == "seam-target-2"
        )

        class _FakeDisjointOwnerClient:
            def __init__(self) -> None:
                self._calls = 0

            async def get_agent_owners(self, agent_id: Any) -> dict[str, Any]:
                self._calls += 1
                owner = f"disjoint-owner-{self._calls}@example.com"
                return {"is_shared": False, "owners": [owner]}

        fake_instance = _FakeDisjointOwnerClient()
        monkeypatch.setenv(
            service.OWNERSHIP_CLIENT_ENV_VAR,
            "tests.test_comms_tools:_fake_shared_owner_client_factory",
        )
        monkeypatch.setattr(
            "tests.test_comms_tools._fake_shared_owner_client_factory_instance", fake_instance
        )
        monkeypatch.setattr(service, "_ownership_client_factory", None)

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "asymmetric",
                    "target_agent_ids": [target_id],
                    "initial_message": _availability_request(),
                },
            )


_fake_shared_owner_client_factory_instance: Any = None


def _fake_shared_owner_client_factory() -> Any:
    return lambda session: _fake_shared_owner_client_factory_instance


# --- Membership mutation tools: invite / leave / decline_invite ---------------------


class TestMembershipTools:
    async def test_invite_leave_decline_round_trip(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "mem-owner")
        await _register(main, test_session_factory, "mem-b")
        await _register(main, test_session_factory, "mem-c")

        token_owner = _token("mem-owner")
        token_b = _token("mem-b")
        token_c = _token("mem-c")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [ids["mem-b"]],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            token_b,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        # B (now active) invites C.
        invite_result = await _call(
            main,
            test_session_factory,
            token_b,
            "comms_invite",
            {"conversation_id": conversation_id, "target_agent_id": ids["mem-c"]},
        )
        assert invite_result["status"] == "invited"

        # C declines — terminal, no access granted.
        decline_result = await _call(
            main,
            test_session_factory,
            token_c,
            "comms_decline_invite",
            {"conversation_id": conversation_id},
        )
        assert decline_result["status"] == "declined"

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token_c,
                "comms_get_conversation",
                {"conversation_id": conversation_id},
            )

        # B leaves.
        leave_result = await _call(
            main, test_session_factory, token_b, "comms_leave", {"conversation_id": conversation_id}
        )
        assert leave_result["status"] == "left"

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token_b,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "availability_response",
                    "payload": _availability_response(),
                },
            )

    async def test_invite_schema_version_mismatch_surfaces_as_tool_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """comms_invite's SchemaVersionMismatchError
        path has service-layer coverage (TestInviteSchemaVersionRecheck in
        test_service.py) but this exercises the actual _map_service_errors
        integration through the real mounted tool."""
        await _register(main, test_session_factory, "inv-sv-owner")
        await _register(main, test_session_factory, "inv-sv-member")
        await _register(
            main,
            test_session_factory,
            "inv-sv-incompatible",
            min_schema_version=2,
            max_schema_version=2,
        )

        token_owner = _token("inv-sv-owner")
        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [ids["inv-sv-member"]],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_invite",
                {
                    "conversation_id": conversation_id,
                    "target_agent_id": ids["inv-sv-incompatible"],
                },
            )
        message = str(exc_info.value)
        # Full equality, matching the sibling
        # start_conversation test's strengthened assertion -- locks in the
        # anti-enumeration property at the integration level, not just
        # "the string mentions the right topic".
        assert message == (
            "schema_version_mismatch: no wire schema version is supported by "
            "every participant in this conversation"
        )
        assert message != "access_denied: not authorized for this resource"

    async def test_start_conversation_retired_target_surfaces_as_specific_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TECH-5703: exceptions.AgentRetiredError has service-layer
        coverage (TestStartConversation in test_service.py) but this
        exercises the actual _map_service_errors integration through the
        real mounted tool -- confirms the class stays in the "pass through
        unwrapped" branch rather than collapsing into the generic
        access_denied string."""
        await _register(main, test_session_factory, "sc-ret-owner")
        await _register(main, test_session_factory, "sc-ret-target")

        token_owner = _token("sc-ret-owner")
        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

        class _RetireOne:
            async def is_active(self, sub: str) -> bool:
                return sub != "sc-ret-target"

        monkeypatch.setattr(plugins, "_active_checker", _RetireOne())

        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [ids["sc-ret-target"]],
                    "initial_message": _availability_request(),
                },
            )
        message = str(exc_info.value)
        assert message == ("agent retired: this agent has been retired and is no longer reachable")
        assert message != "access_denied: not authorized for this resource"

    async def test_invite_retired_target_surfaces_as_specific_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TECH-5703 sibling of the start_conversation test above, for
        comms_invite's own AgentRetiredError check."""
        await _register(main, test_session_factory, "inv-ret-owner")
        await _register(main, test_session_factory, "inv-ret-member")
        await _register(main, test_session_factory, "inv-ret-target")

        token_owner = _token("inv-ret-owner")
        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [ids["inv-ret-member"]],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        class _RetireOne:
            async def is_active(self, sub: str) -> bool:
                return sub != "inv-ret-target"

        monkeypatch.setattr(plugins, "_active_checker", _RetireOne())

        with pytest.raises(ToolError) as exc_info:
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_invite",
                {
                    "conversation_id": conversation_id,
                    "target_agent_id": ids["inv-ret-target"],
                },
            )
        message = str(exc_info.value)
        assert message == ("agent retired: this agent has been retired and is no longer reachable")
        assert message != "access_denied: not authorized for this resource"

    async def test_invite_runtime_error_surfaces_as_generic_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """Tool-boundary coverage for
        service._conversation_pinned_schema_version's internal-invariant
        RuntimeError (service-layer coverage already exists in
        test_service.py's TestInviteSchemaVersionRecheck) -- confirms
        _map_service_errors' bare-RuntimeError branch actually applies to
        comms_invite, not just that the service layer raises it."""
        await _register(main, test_session_factory, "inv-rte-owner")
        await _register(main, test_session_factory, "inv-rte-member")
        await _register(main, test_session_factory, "inv-rte-other")

        token_owner = _token("inv-rte-owner")
        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [ids["inv-rte-member"]],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        # Simulate the internal-invariant violation directly -- this state
        # is unreachable via any public tool call, only reproduced here by
        # deleting the seq-1 message's audit reference then the row itself.
        await session.execute(
            text(
                "DELETE FROM audit_log WHERE message_id IN "
                "(SELECT id FROM messages WHERE conversation_id = :cid AND seq = 1)"
            ),
            {"cid": conversation_id},
        )
        await session.execute(
            text("DELETE FROM messages WHERE conversation_id = :cid AND seq = 1"),
            {"cid": conversation_id},
        )
        await session.commit()

        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_invite",
                {
                    "conversation_id": conversation_id,
                    "target_agent_id": ids["inv-rte-other"],
                },
            )


class TestArchiveConversation:
    """TECH-5887: ``comms_archive_conversation`` end-to-end coverage through
    the real mounted tool stack (mirrors ``TestMembershipTools``'s idiom)."""

    async def _start_open_conversation(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        *,
        owner_sub: str,
        member_sub: str,
    ) -> tuple[str, dict[str, str]]:
        await _register(main, test_session_factory, owner_sub)
        await _register(main, test_session_factory, member_sub)
        token_owner = _token(owner_sub)
        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}
        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [ids[member_sub]],
                "initial_message": _availability_request(),
            },
        )
        return started["conversation_id"], ids

    async def test_non_owner_participant_can_archive(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Any CURRENT active member may archive -- not just the
        conversation's owner/created_by agent (the feature's core symmetric-
        permission requirement)."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-1",
            member_sub="arc-member-1",
        )
        token_member = _token("arc-member-1")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        result = await _call(
            main,
            test_session_factory,
            token_member,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )
        assert result["archived"] is True
        assert result["archived_at"] is not None

        conv = await _call(
            main,
            test_session_factory,
            token_member,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert conv["conversation"]["archived"] is True
        assert conv["conversation"]["archived_at"] == result["archived_at"]

    async def test_archived_conversation_rejects_invite(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-2",
            member_sub="arc-member-2",
        )
        await _register(main, test_session_factory, "arc-target-2")
        list_result = await _call(
            main, test_session_factory, _token("arc-owner-2"), "comms_list_agents"
        )
        ids = {a["sub"]: a["agent_id"] for a in list_result["agents"]}
        token_owner = _token("arc-owner-2")

        await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )

        with pytest.raises(ToolError, match="conversation_archived"):
            await _call(
                main,
                test_session_factory,
                token_owner,
                "comms_invite",
                {"conversation_id": conversation_id, "target_agent_id": ids["arc-target-2"]},
            )

    async def test_archived_conversation_rejects_post_message(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-3",
            member_sub="arc-member-3",
        )
        token_member = _token("arc-member-3")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )

        with pytest.raises(ToolError, match="conversation_archived"):
            await _call(
                main,
                test_session_factory,
                token_member,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "availability_response",
                    "payload": _availability_response(),
                },
            )

    async def test_archived_conversation_rejects_pending_accept(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A pending (not-yet-accepted) invite sent BEFORE archiving can no
        longer be accepted afterward -- accepting admits a new active
        participant, treated the same as a fresh invite (documented policy
        decision, see service.accept_invite's docstring)."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-4",
            member_sub="arc-member-4",
        )
        token_owner = _token("arc-owner-4")
        token_member = _token("arc-member-4")

        # Member is still only `invited` (never called comms_accept) when
        # the owner archives.
        await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )

        with pytest.raises(ToolError, match="conversation_archived"):
            await _call(
                main,
                test_session_factory,
                token_member,
                "comms_accept",
                {"conversation_id": conversation_id},
            )

        # comms_decline_invite still works -- declining only narrows access.
        decline_result = await _call(
            main,
            test_session_factory,
            token_member,
            "comms_decline_invite",
            {"conversation_id": conversation_id},
        )
        assert decline_result["status"] == "declined"

    async def test_archive_is_idempotent(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-5",
            member_sub="arc-member-5",
        )
        token_owner = _token("arc-owner-5")
        token_member = _token("arc-member-5")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        first = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )
        # A second archive, by a DIFFERENT active participant, is a
        # silent no-op that returns the SAME archived_at -- not an error,
        # and not a bumped timestamp.
        second = await _call(
            main,
            test_session_factory,
            token_member,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )
        assert second["archived"] is True
        assert second["archived_at"] == first["archived_at"]

        async with test_session_factory() as session:
            row_count = (
                await session.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action = 'conversation.archive' AND conversation_id = :cid"
                    ),
                    {"cid": conversation_id},
                )
            ).scalar_one()
        assert row_count == 1

    async def test_archive_orthogonal_to_terminal_conversation_state(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Archiving has no precondition on conversation.state -- an
        already-completed/canceled/expired conversation may still be
        archived, per archive_conversation's own docstring."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-10",
            member_sub="arc-member-10",
        )
        token_owner = _token("arc-owner-10")
        token_member = _token("arc-member-10")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        async with test_session_factory() as session:
            await session.execute(
                text("UPDATE conversations SET state = 'completed' WHERE id = :cid"),
                {"cid": conversation_id},
            )
            await session.commit()

        result = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )
        assert result["archived"] is True
        assert result["archived_at"] is not None

    async def test_archiving_does_not_hide_history_from_reads(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Past messages remain fully readable via comms_get_conversation,
        comms_inbox, and comms_list_conversations after archiving -- this is
        not a delete or a redaction."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-6",
            member_sub="arc-member-6",
        )
        token_owner = _token("arc-owner-6")
        token_member = _token("arc-member-6")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "availability_response",
                "payload": _availability_response(),
            },
        )

        before = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert len(before["messages"]) == 2  # seq 1 (opener) + the response above

        await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )

        after = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_get_conversation",
            {"conversation_id": conversation_id, "since_seq": 0},
        )
        assert after["conversation"]["archived"] is True
        assert len(after["messages"]) == 2
        assert [m["seq"] for m in after["messages"]] == [m["seq"] for m in before["messages"]]

        listed = await _call(
            main, test_session_factory, token_owner, "comms_list_conversations", {}
        )
        listed_ids = {c["conversation_id"] for c in listed["conversations"]}
        assert conversation_id in listed_ids
        listed_conv = next(
            c for c in listed["conversations"] if c["conversation_id"] == conversation_id
        )
        assert listed_conv["archived"] is True

        inbox = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_inbox",
            {"include_own_messages": True, "include_read": True},
        )
        inbox_conv = next(
            (c for c in inbox["unread"] if c["conversation_id"] == conversation_id), None
        )
        assert inbox_conv is not None
        assert inbox_conv["archived"] is True
        assert inbox_conv["archived_at"] is not None

    async def test_archive_requires_active_membership(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A caller who was never a participant gets the uniform denial,
        same precondition every other conversation-scoped write shares."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-7",
            member_sub="arc-member-7",
        )
        await _register(main, test_session_factory, "arc-outsider-7")
        token_outsider = _token("arc-outsider-7")

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token_outsider,
                "comms_archive_conversation",
                {"conversation_id": conversation_id},
            )

    async def test_archive_denied_for_invited_not_yet_accepted_participant(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """An `invited` participant (hasn't called comms_accept yet) is not
        `active` and gets the same uniform denial as a non-participant --
        archive_conversation's `required_status="active"` check applies
        just as strictly to a pending invite as to a total stranger."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-8",
            member_sub="arc-member-8",
        )
        token_member = _token("arc-member-8")
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token_member,
                "comms_archive_conversation",
                {"conversation_id": conversation_id},
            )

    async def test_archive_denied_for_left_participant(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A participant who accepted and then left is no longer `active`
        and gets the same uniform denial -- leaving revokes archive
        eligibility just like every other write path."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-9",
            member_sub="arc-member-9",
        )
        token_member = _token("arc-member-9")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_leave",
            {"conversation_id": conversation_id},
        )
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token_member,
                "comms_archive_conversation",
                {"conversation_id": conversation_id},
            )

    async def test_get_hold_status_unaffected_by_archiving(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """comms_get_hold_status is a read path, unlike comms_invite/
        comms_post_message/comms_accept/decide_hold's approve path -- it
        must keep working normally on an archived conversation's existing
        holds. Not explicitly gated on archived_at anywhere, but unverified
        until now; a future change accidentally adding that gate would go
        undetected without this test."""
        conversation_id, _ids = await self._start_open_conversation(
            main,
            test_session_factory,
            owner_sub="arc-owner-10",
            member_sub="arc-member-10",
        )
        token_owner = _token("arc-owner-10")
        token_member = _token("arc-member-10")
        await _call(
            main,
            test_session_factory,
            token_member,
            "comms_accept",
            {"conversation_id": conversation_id},
        )
        held = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "note",
                "payload": {"text": "secret cross-boundary note"},
            },
        )
        assert held["held_for_approval"] is True

        await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_archive_conversation",
            {"conversation_id": conversation_id},
        )

        status = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_get_hold_status",
            {"hold_id": held["hold_id"]},
        )
        assert status["hold_id"] == held["hold_id"]
        assert status["status"] == "pending_human"


class TestTaskLifecycleToolLayer:
    """End-to-end coverage for tasks-as-conversations: task_assign opens a
    conversation, task_report/task_complete/task_decline/task_cancel drive
    it through comms_post_message."""

    async def test_full_task_lifecycle(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(
            main, test_session_factory, "task-bond-007", owner_sub="owner-dan@example.com"
        )
        assignee = await _register(
            main, test_session_factory, "task-pepper-potts", owner_sub="owner-dan@example.com"
        )
        assigner_token = _token("task-bond-007", owner_sub="owner-dan@example.com")
        assignee_token = _token("task-pepper-potts", owner_sub="owner-dan@example.com")

        started = await _call(
            main,
            test_session_factory,
            assigner_token,
            "comms_start_conversation",
            {
                "conversation_type": "internal",
                "target_agent_ids": [assignee["agent_id"]],
                "initial_message": {"action": "report_status"},
                "message_type": "task_assign",
            },
        )
        assert started["type"] == "internal"
        conversation_id = started["conversation_id"]

        await _call(
            main,
            test_session_factory,
            assignee_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        report = await _call(
            main,
            test_session_factory,
            assignee_token,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "task_report",
                "payload": {"status": "in_progress"},
            },
        )
        assert report["type"] == "task_report"
        mid_state = await _call(
            main,
            test_session_factory,
            assigner_token,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert mid_state["conversation"]["state"] == "active"

        completed = await _call(
            main,
            test_session_factory,
            assigner_token,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "task_complete",
                "payload": {},
            },
        )
        assert completed["type"] == "task_complete"
        final_state = await _call(
            main,
            test_session_factory,
            assigner_token,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert final_state["conversation"]["state"] == "completed"

    async def test_different_owner_agents_denied_internal_admission(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(
            main, test_session_factory, "task-bond-2", owner_sub="owner-dan@example.com"
        )
        other = await _register(
            main, test_session_factory, "task-other-2", owner_sub="owner-priya@example.com"
        )
        token = _token("task-bond-2", owner_sub="owner-dan@example.com")

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_start_conversation",
                {
                    "conversation_type": "internal",
                    "target_agent_ids": [other["agent_id"]],
                    "initial_message": {"action": "report_status"},
                    "message_type": "task_assign",
                },
            )

    async def test_task_decline_from_assigner_uniformly_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(
            main, test_session_factory, "task-bond-3", owner_sub="owner-dan@example.com"
        )
        assignee = await _register(
            main, test_session_factory, "task-pepper-3", owner_sub="owner-dan@example.com"
        )
        assigner_token = _token("task-bond-3", owner_sub="owner-dan@example.com")
        assignee_token = _token("task-pepper-3", owner_sub="owner-dan@example.com")

        started = await _call(
            main,
            test_session_factory,
            assigner_token,
            "comms_start_conversation",
            {
                "conversation_type": "internal",
                "target_agent_ids": [assignee["agent_id"]],
                "initial_message": {"action": "report_status"},
                "message_type": "task_assign",
            },
        )
        conversation_id = started["conversation_id"]
        await _call(
            main,
            test_session_factory,
            assignee_token,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                assigner_token,
                "comms_post_message",
                {
                    "conversation_id": conversation_id,
                    "message_type": "task_decline",
                    "payload": {"reason": "unable_to_complete"},
                },
            )


class TestMessageTypeAcceptedToolLayer:
    """MCP-boundary counterpart to test_service.py's
    TestMessageTypeAcceptedCapability -- confirms denied.message_type_not_accepted
    collapses to the same uniform ToolError every other denial family does,
    not a leaked reason string."""

    async def test_denied_uniformly_at_tool_boundary(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "cap-tool-initiator")
        target = await _register(
            main, test_session_factory, "cap-tool-target", accepted_types=["confirm"]
        )
        initiator_token = _token("cap-tool-initiator")

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                initiator_token,
                "comms_start_conversation",
                {
                    "conversation_type": "open",
                    "target_agent_ids": [target["agent_id"]],
                    "initial_message": _availability_request(),
                    "message_type": "availability_request",
                },
            )

    async def test_post_message_denied_uniformly_at_tool_boundary(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "cap-tool-post-initiator")
        target = await _register(
            main,
            test_session_factory,
            "cap-tool-post-target",
            accepted_types=["availability_request"],
        )
        initiator_token = _token("cap-tool-post-initiator")
        target_token = _token("cap-tool-post-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        # target's accepted_types doesn't include availability_response.
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                initiator_token,
                "comms_post_message",
                {
                    "conversation_id": started["conversation_id"],
                    "message_type": "availability_response",
                    "payload": _availability_response(),
                },
            )


# --- Registry parity / scope enforcement still intact --------------------------------


class TestScopesUnaffected:
    async def test_all_new_tools_are_registry_enrolled(self, main: Any) -> None:
        from scopes import TOOL_SCOPES

        tools = await main.mcp.list_tools()
        mounted = {t.name for t in tools}
        expected = {
            "comms_register",
            "comms_set_agent_shared",
            "comms_list_agents",
            "comms_lookup_agent_by_email",
            "comms_list_conversations",
            "comms_start_conversation",
            "comms_post_message",
            "comms_get_conversation",
            "comms_inbox",
            "comms_accept",
            "comms_decline_invite",
            "comms_invite",
            "comms_leave",
            "comms_archive_conversation",
            "comms_get_hold_status",
            "comms_admin_register",
        }
        assert expected <= mounted
        assert expected <= set(TOOL_SCOPES)

    async def test_missing_scope_still_denied_for_new_write_tool(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # comms:read only — comms_register requires comms:write.
        token = _token("scope-test-agent", scopes=["comms:read"])
        with pytest.raises(ToolError, match="requires elevated permissions"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {"display_name": "x", "accepted_types": ["availability_request"]},
            )

    async def test_unenrolled_tool_still_rejected(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        token = _token("scope-test-agent-2", scopes=["comms:read", "comms:write"])
        with pytest.raises(ToolError, match="requires elevated permissions"):
            await _call(main, test_session_factory, token, "comms_not_a_real_tool")


# --- availability_response's none_available branch, end-to-end -------------------


class TestAvailabilityResponseNoneAvailable:
    async def test_none_available_with_reason_accepted_and_round_trips(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "na-owner")
        await _register(main, test_session_factory, "na-target")
        token_owner = _token("na-owner")
        token_target = _token("na-target")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "na-target")

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target_id],
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]
        await _call(
            main,
            test_session_factory,
            token_target,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        posted = await _call(
            main,
            test_session_factory,
            token_target,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "availability_response",
                "payload": {"none_available": True, "reason": "no_overlap"},
            },
        )
        assert posted["payload"]["none_available"] is True
        assert posted["payload"]["reason"] == "no_overlap"
        assert posted["payload"].get("slots") is None

        view = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        response_message = next(m for m in view["messages"] if m["type"] == "availability_response")
        assert response_message["payload"]["none_available"] is True
        assert response_message["payload"]["reason"] == "no_overlap"


# --- lazy expiry, end-to-end -----------------------------------------------------


class TestLazyExpiryEndToEnd:
    async def test_get_conversation_reflects_expired_state(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        from datetime import UTC, datetime, timedelta

        await _register(main, test_session_factory, "exp-owner")
        await _register(main, test_session_factory, "exp-target")
        token_owner = _token("exp-owner")
        token_target = _token("exp-target")

        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        target_id = next(a["agent_id"] for a in list_result["agents"] if a["sub"] == "exp-target")

        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target_id],
                "initial_message": _availability_request(),
                "expires_at": past,
            },
        )
        conversation_id = started["conversation_id"]
        await _call(
            main,
            test_session_factory,
            token_target,
            "comms_accept",
            {"conversation_id": conversation_id},
        )

        view = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_get_conversation",
            {"conversation_id": conversation_id},
        )
        assert view["conversation"]["state"] == "expired"


# --- concurrent seq assignment, exercised through the full tool stack ------------


class TestConcurrentPostMessageToolLayer:
    async def test_concurrent_posts_get_distinct_contiguous_seqs(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # ``_call``'s module-level ``_OIDC_PATCH``/``_ENV_PATCH``/``patch(...)``
        # context managers are singleton objects that raise "Patch is already
        # started" if entered twice concurrently, so ``asyncio.gather`` over
        # several ``_call`` invocations is not viable here. Instead, patch
        # ``get_access_token`` ONCE (outside the gather) with a resolver keyed
        # off a ``contextvars.ContextVar`` — asyncio.Task copies the calling
        # context at creation, so each gathered task's own ``.set()`` is
        # invisible to its siblings, giving per-task caller identity under
        # true concurrency without re-entering any patch.
        import contextvars

        await _register(main, test_session_factory, "race-owner")
        member_subs = [f"race-member-{i}" for i in range(4)]
        for sub in member_subs:
            await _register(main, test_session_factory, sub)

        token_owner = _token("race-owner")
        list_result = await _call(main, test_session_factory, token_owner, "comms_list_agents")
        ids_by_sub = {a["sub"]: a["agent_id"] for a in list_result["agents"]}
        member_ids = [ids_by_sub[sub] for sub in member_subs]

        started = await _call(
            main,
            test_session_factory,
            token_owner,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": member_ids,
                "initial_message": _availability_request(),
            },
        )
        conversation_id = started["conversation_id"]

        for sub in member_subs:
            await _call(
                main,
                test_session_factory,
                _token(sub),
                "comms_accept",
                {"conversation_id": conversation_id},
            )

        current_token: contextvars.ContextVar[MagicMock] = contextvars.ContextVar("current_token")

        async def _post(sub: str) -> int:
            current_token.set(_token(sub))
            async with Client(main.mcp) as client:
                result = await client.call_tool(
                    "comms_post_message",
                    {
                        "conversation_id": conversation_id,
                        "message_type": "availability_response",
                        "payload": _availability_response(),
                    },
                )
            seq: int = result.data["seq"]
            return seq

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", side_effect=current_token.get),
            patch("providers.comms.get_access_token", side_effect=current_token.get),
            patch("providers.comms.get_session_factory", return_value=test_session_factory),
        ):
            seqs = await asyncio.gather(*[_post(sub) for sub in member_subs])

        assert sorted(seqs) == [2, 3, 4, 5]
        assert len(set(seqs)) == len(seqs)


class TestListConversationsTool:
    async def test_empty_returns_structure(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _register(main, test_session_factory, "listconv-tool-empty")
        token = _token("listconv-tool-empty")
        result = await _call(main, test_session_factory, token, "comms_list_conversations")
        assert result["conversations"] == []
        assert result["has_more"] is False
        assert result["next_cursor"] is None

    async def test_own_conversation_visible(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _register(main, test_session_factory, "listconv-tool-creator")
        target = await _register(main, test_session_factory, "listconv-tool-target")
        creator_token = _token("listconv-tool-creator")
        payload = _availability_request()
        conv = await _call(
            main,
            test_session_factory,
            creator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "message_type": "availability_request",
                "initial_message": payload,
            },
        )
        result = await _call(main, test_session_factory, creator_token, "comms_list_conversations")
        ids = [c["conversation_id"] for c in result["conversations"]]
        assert conv["conversation_id"] in ids

    async def test_filter_by_type_and_state(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _register(main, test_session_factory, "listconv-tool-filter-c")
        target = await _register(main, test_session_factory, "listconv-tool-filter-t")
        creator_token = _token("listconv-tool-filter-c")
        payload = _availability_request()
        await _call(
            main,
            test_session_factory,
            creator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "message_type": "availability_request",
                "initial_message": payload,
            },
        )
        result_open = await _call(
            main,
            test_session_factory,
            creator_token,
            "comms_list_conversations",
            {"type": "open", "state": "active"},
        )
        assert len(result_open["conversations"]) == 1

        result_internal = await _call(
            main,
            test_session_factory,
            creator_token,
            "comms_list_conversations",
            {"type": "internal"},
        )
        assert result_internal["conversations"] == []

    async def test_malformed_cursor_maps_to_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _register(main, test_session_factory, "listconv-tool-bad-cursor")
        token = _token("listconv-tool-bad-cursor")

        with pytest.raises(ToolError, match="invalid_request: the request could not be processed"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_list_conversations",
                {"cursor": "not-a-valid-cursor"},
            )

    @pytest.mark.parametrize(
        ("field", "value"),
        [("role", "bogus"), ("type", "bogus"), ("state", "bogus")],
    )
    async def test_invalid_filter_value_maps_to_tool_error(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        field: str,
        value: str,
    ) -> None:
        await _register(main, test_session_factory, f"listconv-tool-bad-{field}")
        token = _token(f"listconv-tool-bad-{field}")

        with pytest.raises(ToolError, match=f"invalid_request: {field} must be one of"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_list_conversations",
                {field: value},
            )


# --- Approval pipeline (TECH-5389 PR2) ---------------------------------------


class TestDecisionUrlHelper:
    """Unit coverage of ``providers.comms._decision_url``'s own normalization,
    independent of any specific tool's held-response wiring (see
    TestApprovalPipeline below for the end-to-end assertions)."""

    def test_strips_trailing_slash_on_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from providers.comms import _decision_url

        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com/")
        assert _decision_url("abc-123") == "https://decisions.example.com/holds/abc-123"

    def test_rejects_non_https_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from providers.comms import _decision_url

        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "http://decisions.example.com")
        assert _decision_url("abc-123") is None


class TestApprovalPipeline:
    """End-to-end coverage of the divert-not-deny pipeline at the MCP tool
    boundary: a high-risk ``comms_post_message``/``comms_start_conversation``
    call returns the distinct held-for-approval shape (not an error), and
    ``comms_get_hold_status`` lets the sender poll the outcome."""

    async def test_note_into_open_conversation_returns_held_shape(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "hold-e2e-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-target")
        initiator_token = _token("hold-e2e-initiator")
        target_token = _token("hold-e2e-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        result = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_post_message",
            {
                "conversation_id": started["conversation_id"],
                "message_type": "note",
                "payload": {"text": "secret cross-boundary note"},
            },
        )
        assert result["held_for_approval"] is True
        assert result["status"] == "pending_human"
        assert result["risk_reason"] == "boundary_crossing"
        assert "hold_id" in result
        assert "seq" not in result

        status = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_get_hold_status",
            {"hold_id": result["hold_id"]},
        )
        assert status["hold_id"] == result["hold_id"]
        assert status["status"] == "pending_human"
        assert status["risk_reason"] == "boundary_crossing"
        assert status["kind"] == "message"
        assert "message_seq" not in status

        # The held content never became a visible message.
        conversation_view = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_get_conversation",
            {"conversation_id": started["conversation_id"]},
        )
        assert all(m["type"] != "note" for m in conversation_view["messages"])

    async def test_post_message_held_response_omits_decision_url_when_unset(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("DECISION_PAGE_BASE_URL", raising=False)

        await _register(main, test_session_factory, "hold-e2e-nourl-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-nourl-target")
        initiator_token = _token("hold-e2e-nourl-initiator")
        target_token = _token("hold-e2e-nourl-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        result = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_post_message",
            {
                "conversation_id": started["conversation_id"],
                "message_type": "note",
                "payload": {"text": "secret cross-boundary note"},
            },
        )
        assert result["held_for_approval"] is True
        assert "decision_url" not in result

    async def test_post_message_held_response_includes_decision_url_when_set(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")

        await _register(main, test_session_factory, "hold-e2e-url-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-url-target")
        initiator_token = _token("hold-e2e-url-initiator")
        target_token = _token("hold-e2e-url-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        result = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_post_message",
            {
                "conversation_id": started["conversation_id"],
                "message_type": "note",
                "payload": {"text": "secret cross-boundary note"},
            },
        )
        assert result["held_for_approval"] is True
        assert result["decision_url"] == f"https://decisions.example.com/holds/{result['hold_id']}"

    async def test_invite_into_conversation_with_note_history_returns_held_shape(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """TECH-5735: comms_invite diverts into an approval hold (not a
        Participant row) when the target conversation already has `note`
        history -- exercised end-to-end through the MCP tool boundary, not
        just service.invite() directly (test_service.py's coverage)."""
        owner_sub = "owner-invite-hold-e2e@example.com"
        await _register(main, test_session_factory, "invite-hold-e2e-owner", owner_sub=owner_sub)
        member = await _register(
            main, test_session_factory, "invite-hold-e2e-member", owner_sub=owner_sub
        )
        new_agent = await _register(
            main, test_session_factory, "invite-hold-e2e-new", owner_sub=owner_sub
        )
        owner_token = _token("invite-hold-e2e-owner", owner_sub=owner_sub)
        new_token = _token("invite-hold-e2e-new", owner_sub=owner_sub)

        started = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_start_conversation",
            {
                "conversation_type": "internal",
                "target_agent_ids": [member["agent_id"]],
                "initial_message": {"text": "hello"},
                "message_type": "note",
            },
        )
        conversation_id = started["conversation_id"]

        result = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_invite",
            {"conversation_id": conversation_id, "target_agent_id": new_agent["agent_id"]},
        )
        assert result["held_for_approval"] is True
        assert result["status"] == "pending_human"
        assert result["risk_reason"] == "note_history_requires_approval"
        assert "hold_id" in result

        status = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_get_hold_status",
            {"hold_id": result["hold_id"]},
        )
        assert status["kind"] == "invite"
        assert status["target_agent_id"] == new_agent["agent_id"]
        assert "participant_status" not in status

        # No Participant row exists yet -- the invitee is not a member.
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                new_token,
                "comms_get_conversation",
                {"conversation_id": conversation_id},
            )

    async def test_invite_held_response_omits_decision_url_when_unset(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("DECISION_PAGE_BASE_URL", raising=False)

        owner_sub = "owner-invite-hold-nourl@example.com"
        await _register(main, test_session_factory, "invite-hold-nourl-owner", owner_sub=owner_sub)
        member = await _register(
            main, test_session_factory, "invite-hold-nourl-member", owner_sub=owner_sub
        )
        new_agent = await _register(
            main, test_session_factory, "invite-hold-nourl-new", owner_sub=owner_sub
        )
        owner_token = _token("invite-hold-nourl-owner", owner_sub=owner_sub)

        started = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_start_conversation",
            {
                "conversation_type": "internal",
                "target_agent_ids": [member["agent_id"]],
                "initial_message": {"text": "hello"},
                "message_type": "note",
            },
        )

        result = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_invite",
            {
                "conversation_id": started["conversation_id"],
                "target_agent_id": new_agent["agent_id"],
            },
        )
        assert result["held_for_approval"] is True
        assert "decision_url" not in result

    async def test_invite_held_response_includes_decision_url_when_set(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")

        owner_sub = "owner-invite-hold-url@example.com"
        await _register(main, test_session_factory, "invite-hold-url-owner", owner_sub=owner_sub)
        member = await _register(
            main, test_session_factory, "invite-hold-url-member", owner_sub=owner_sub
        )
        new_agent = await _register(
            main, test_session_factory, "invite-hold-url-new", owner_sub=owner_sub
        )
        owner_token = _token("invite-hold-url-owner", owner_sub=owner_sub)

        started = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_start_conversation",
            {
                "conversation_type": "internal",
                "target_agent_ids": [member["agent_id"]],
                "initial_message": {"text": "hello"},
                "message_type": "note",
            },
        )

        result = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_invite",
            {
                "conversation_id": started["conversation_id"],
                "target_agent_id": new_agent["agent_id"],
            },
        )
        assert result["held_for_approval"] is True
        assert result["decision_url"] == f"https://decisions.example.com/holds/{result['hold_id']}"

    async def test_get_hold_status_uniform_denial_for_non_sender(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "hold-e2e-owner")
        target = await _register(main, test_session_factory, "hold-e2e-other-target")
        await _register(main, test_session_factory, "hold-e2e-nosy")
        initiator_token = _token("hold-e2e-owner")
        target_token = _token("hold-e2e-other-target")
        other_token = _token("hold-e2e-nosy")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )
        held = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_post_message",
            {
                "conversation_id": started["conversation_id"],
                "message_type": "note",
                "payload": {"text": "not for you"},
            },
        )

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                other_token,
                "comms_get_hold_status",
                {"hold_id": held["hold_id"]},
            )

    async def test_get_hold_status_uniform_denial_for_unknown_hold(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "hold-e2e-unknown-caller")
        token = _token("hold-e2e-unknown-caller")

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_get_hold_status",
                {"hold_id": str(uuid.uuid4())},
            )

    async def test_seq1_diverted_opener_response_shape(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A high-risk seq-1 opener (TECH-5389 PR2 §6): the conversation is
        created with a service-synthesized ``conversation_opened`` marker,
        and the response carries the held-for-approval block alongside the
        normal conversation-created shape."""
        await _register(main, test_session_factory, "hold-e2e-opener-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-opener-target")
        initiator_token = _token("hold-e2e-opener-initiator")
        target_token = _token("hold-e2e-opener-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": {"text": "secret opener"},
                "message_type": "note",
            },
        )
        assert started["held_for_approval"] is True
        assert started["hold_status"] == "pending_human"
        assert started["risk_reason"] == "boundary_crossing"
        assert "hold_id" in started

        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )
        conversation_view = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_get_conversation",
            {"conversation_id": started["conversation_id"]},
        )
        assert len(conversation_view["messages"]) == 1
        assert conversation_view["messages"][0]["type"] == "conversation_opened"
        assert conversation_view["messages"][0]["seq"] == 1

    async def test_start_conversation_held_response_omits_decision_url_when_unset(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("DECISION_PAGE_BASE_URL", raising=False)

        await _register(main, test_session_factory, "hold-e2e-opener-nourl-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-opener-nourl-target")
        initiator_token = _token("hold-e2e-opener-nourl-initiator")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": {"text": "secret opener"},
                "message_type": "note",
            },
        )
        assert started["held_for_approval"] is True
        assert "decision_url" not in started

    async def test_start_conversation_held_response_includes_decision_url_when_set(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")

        await _register(main, test_session_factory, "hold-e2e-opener-url-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-opener-url-target")
        initiator_token = _token("hold-e2e-opener-url-initiator")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": {"text": "secret opener"},
                "message_type": "note",
            },
        )
        assert started["held_for_approval"] is True
        assert (
            started["decision_url"] == f"https://decisions.example.com/holds/{started['hold_id']}"
        )

    async def test_direct_post_of_system_message_type_denied(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _register(main, test_session_factory, "hold-e2e-forge-initiator")
        target = await _register(main, test_session_factory, "hold-e2e-forge-target")
        initiator_token = _token("hold-e2e-forge-initiator")
        target_token = _token("hold-e2e-forge-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ):
            await _call(
                main,
                test_session_factory,
                initiator_token,
                "comms_post_message",
                {
                    "conversation_id": started["conversation_id"],
                    "message_type": "conversation_opened",
                    "payload": {"reason": "pending_approval"},
                },
            )

    async def test_review_reason_forces_hold_even_in_internal_conversation(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """TECH-5786: ``review_reason`` on ``comms_post_message`` reaches the
        service layer and forces a hold inside an ``internal`` conversation --
        the one conversation type that never reaches a hold on its own."""
        owner_sub = "hold-e2e-review-reason-owner"
        await _register(
            main, test_session_factory, "hold-e2e-review-reason-initiator", owner_sub=owner_sub
        )
        target = await _register(
            main, test_session_factory, "hold-e2e-review-reason-target", owner_sub=owner_sub
        )
        initiator_token = _token("hold-e2e-review-reason-initiator", owner_sub=owner_sub)
        target_token = _token("hold-e2e-review-reason-target", owner_sub=owner_sub)

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "internal",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        result = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_post_message",
            {
                "conversation_id": started["conversation_id"],
                "message_type": "note",
                "payload": {"text": "please double check this"},
                "review_reason": "unsure this is safe to send",
            },
        )
        assert result["held_for_approval"] is True
        assert result["status"] == "pending_human"
        assert result["risk_reason"] == "agent_requested"

    async def test_review_reason_exceeding_length_cap_rejected_at_tool_boundary(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Argus round-2 SUGGESTION catch: the 2000-char review_reason cap
        (providers/comms.py's MAX_REVIEW_REASON_LENGTH) had no regression
        coverage -- the guard could be silently removed without CI noticing."""
        await _register(main, test_session_factory, "hold-e2e-review-reason-toolong-initiator")
        target = await _register(
            main, test_session_factory, "hold-e2e-review-reason-toolong-target"
        )
        initiator_token = _token("hold-e2e-review-reason-toolong-initiator")
        target_token = _token("hold-e2e-review-reason-toolong-target")

        started = await _call(
            main,
            test_session_factory,
            initiator_token,
            "comms_start_conversation",
            {
                "conversation_type": "open",
                "target_agent_ids": [target["agent_id"]],
                "initial_message": _availability_request(),
                "message_type": "availability_request",
            },
        )
        await _call(
            main,
            test_session_factory,
            target_token,
            "comms_accept",
            {"conversation_id": started["conversation_id"]},
        )

        with pytest.raises(
            ToolError,
            match=re.escape("invalid_request: review_reason exceeds 2000 characters"),
        ):
            await _call(
                main,
                test_session_factory,
                initiator_token,
                "comms_post_message",
                {
                    "conversation_id": started["conversation_id"],
                    "message_type": "note",
                    "payload": {"text": "hello"},
                    "review_reason": "x" * 2001,
                },
            )


class TestOwnershipWriteThrough:
    """TECH-5593 item 1, end-to-end through the real tool surface: a
    registry-backed token's owner claims write through to ``agents``
    on any subsequent tool call that resolves the caller's own row; a
    default (legacy) token's claims never do."""

    async def test_registry_backed_token_writes_through_on_next_call(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        from sqlalchemy import select

        from models import Agent

        await _register(
            main,
            test_session_factory,
            "write-through-agent",
            owner_sub="original-owner",
            owner_email="original@example.com",
        )

        registry_token = _token(
            "write-through-agent",
            owner_sub="reassigned-owner",
            owner_email="reassigned@example.com",
            registry_backed=True,
        )
        await _call(main, test_session_factory, registry_token, "comms_inbox")

        row = (
            await session.execute(select(Agent).where(Agent.sub == "write-through-agent"))
        ).scalar_one()
        assert row.owner_sub == "reassigned-owner"
        assert row.owner_email == "reassigned@example.com"

    async def test_default_verifier_token_never_writes_through(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """The trust gate: a caller-supplied owner claim on a token NOT
        stamped as registry-backed (the default agent_jwt_hs256 shape) must
        never overwrite the cached owner_sub/owner_email -- otherwise this
        would reopen the exact forgery hole register_agent's freeze on
        re-registration exists to close."""
        from sqlalchemy import select

        from models import Agent

        await _register(
            main,
            test_session_factory,
            "no-write-through-agent",
            owner_sub="original-owner",
            owner_email="original@example.com",
        )

        legacy_token = _token(
            "no-write-through-agent",
            owner_sub="attempted-forged-owner",
            owner_email="attempted-forged@example.com",
            registry_backed=False,
        )
        await _call(main, test_session_factory, legacy_token, "comms_inbox")

        row = (
            await session.execute(select(Agent).where(Agent.sub == "no-write-through-agent"))
        ).scalar_one()
        assert row.owner_sub == "original-owner"
        assert row.owner_email == "original@example.com"

    async def test_registry_backed_token_with_no_owner_claims_is_a_no_op(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """A registry-backed token that simply doesn't carry owner_sub/
        owner_email claims (e.g. a plugin that only resolves ownership for
        some subs) must leave the cached row untouched, not write through
        ``None``."""
        from sqlalchemy import select

        from models import Agent

        await _register(
            main,
            test_session_factory,
            "no-claims-agent",
            owner_sub="original-owner",
            owner_email="original@example.com",
        )

        registry_token_no_claims = _token("no-claims-agent", registry_backed=True)
        await _call(main, test_session_factory, registry_token_no_claims, "comms_inbox")

        row = (
            await session.execute(select(Agent).where(Agent.sub == "no-claims-agent"))
        ).scalar_one()
        assert row.owner_sub == "original-owner"
        assert row.owner_email == "original@example.com"

    async def test_non_string_owner_claim_is_ignored_not_coerced(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        """A malformed registry-backed token carrying a non-string
        owner_sub (e.g. an int) must leave the cached row untouched, not
        write through str()'s repr of the garbage value (Argus round-1
        BLOCKING catch)."""
        from sqlalchemy import select

        from models import Agent

        await _register(
            main,
            test_session_factory,
            "malformed-claim-agent",
            owner_sub="original-owner",
            owner_email="original@example.com",
        )

        malformed_token = _token("malformed-claim-agent", registry_backed=True)
        malformed_token.claims["owner_sub"] = 12345
        malformed_token.claims["owner_email"] = ["not", "a", "string"]
        await _call(main, test_session_factory, malformed_token, "comms_inbox")

        row = (
            await session.execute(select(Agent).where(Agent.sub == "malformed-claim-agent"))
        ).scalar_one()
        assert row.owner_sub == "original-owner"
        assert row.owner_email == "original@example.com"
