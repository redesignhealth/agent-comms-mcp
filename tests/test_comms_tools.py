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
) -> MagicMock:
    """A minimal agent-jwt-shaped ``AccessToken`` stand-in for ``sub``."""
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": scopes if scopes is not None else ["comms:read", "comms:write"],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    if owner_email is not None:
        claims["owner_email"] = owner_email
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
        unverified (the JWT issuer CLI accepts arbitrary extra
        claims) — it must never be trusted as ``owner_email``, even when
        present. This is the negative case the existing "no email claim at
        all" tests don't cover: here the token DOES carry an ``email``
        claim, and it must still be ignored in favor of the sub-derived
        self-owned fallback."""
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
        with pytest.raises(ToolError, match=r"accepted_types must be a non-empty subset of"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {"display_name": "Prober", "accepted_types": ["__probe_invalid_type__"]},
            )

    async def test_register_empty_accepted_types_generic_tool_error(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Boundary-level counterpart to
        ``test_service.test_empty_accepted_types_raises_plain_value_error``:
        an empty ``accepted_types`` list is a bare ``ValueError`` at the
        service layer, which ``_map_service_errors`` maps to the generic
        ``invalid_request`` ``ToolError`` shape (not the specific
        ``UnknownConversationTypeError`` message) at the MCP boundary."""
        token = _token("agent-empty-types-boundary")
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {"display_name": "Empty Types", "accepted_types": []},
            )

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

    async def test_register_is_shared_true_requires_admin_scope(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """A caller with only the baseline ``comms:write`` scope cannot
        self-declare ``is_shared=True`` on first registration -- it is an
        admission-decision input (DESIGN.md §9), so unscoped self-escalation
        would be a privilege escalation. See ``scopes.py``'s ``comms:admin``
        entry and ``service.register_agent``'s ``is_shared_authorized``."""
        token = _token("agent-is-shared-unauthorized", scopes=["comms:read", "comms:write"])
        with pytest.raises(
            ToolError, match=re.escape("access_denied: not authorized for this resource")
        ) as exc_info:
            await _call(
                main,
                test_session_factory,
                token,
                "comms_register",
                {
                    "display_name": "Unauthorized Shared",
                    "accepted_types": ["availability_request"],
                    "is_shared": True,
                },
            )
        assert "is_shared" not in str(exc_info.value)

    async def test_register_is_shared_true_with_admin_scope_succeeds(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """The ``comms:admin`` scope is what lets a caller mint a shared
        agent on first registration; the response echoes ``is_shared``."""
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
        """The default (``is_shared`` omitted, i.e. ``False``) never needs
        the elevated scope -- only requesting ``True`` does."""
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

    async def test_register_is_shared_true_interactive_caller_no_admin_scope_needed(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Interactive (Okta) callers bypass scope checks entirely elsewhere
        in this module (``is_interactive_token``); the same bypass applies
        to the ``comms:admin`` gate on ``is_shared=True`` -- an interactive
        caller needs no scopes claim at all to set it on first registration."""
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
