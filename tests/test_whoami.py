"""Unit tests for the comms_whoami placeholder tool (raw function path)."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError

# ``@comms_server.tool`` registers the coroutine and returns it unchanged
# in fastmcp 3.4.2, so the tool body can be invoked directly.
from providers.comms import whoami as _whoami

# TECH-5160: whoami now does a best-effort DB lookup for
# min_schema_version/max_schema_version. Every test below mocks BOTH
# get_session_factory and service.get_agent_by_sub (Argus round 1) so
# these unit tests exercise the intended DB-free-identity /
# agent-found / agent-not-found paths deliberately, rather than
# accidentally exercising the connectivity-failure fallback just because
# no real DATABASE_URL is configured in this test environment (which is
# what happened before this round: get_session_factory() raised
# RuntimeError via db.require_env, silently swallowed by whoami's
# broad-then-narrowed except clause, so these tests passed for the wrong
# reason and never verified the path they claimed to).


@asynccontextmanager
async def _dummy_session() -> Any:
    yield MagicMock(name="session")


def _patched_session_factory() -> Any:
    """A ``get_session_factory`` stand-in whose ``()()`` call yields a
    working (fake) async-context-managed session, so ``whoami``'s
    ``async with get_session_factory()() as session:`` succeeds without a
    real database."""
    return patch("providers.comms.get_session_factory", return_value=lambda: _dummy_session())


class TestWhoami:
    def test_okta_caller_reports_interactive_identity(self) -> None:
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "alice@example.com",
        }

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
        ):
            result = asyncio.run(_whoami())

        assert result == {
            "identity": "alice@example.com",
            "issuer": "https://example.okta.com/oauth2/default",
            "caller_type": "interactive",
            "scopes": [],
        }

    def test_agent_jwt_caller_reports_service_identity_and_scopes(self) -> None:
        token = MagicMock()
        token.claims = {
            "iss": "agent-jwt",
            "sub": "ea-agent-svc",
            "scopes": ["comms:read"],
        }

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
        ):
            result = asyncio.run(_whoami())

        assert result == {
            "identity": "ea-agent-svc",
            "issuer": "agent-jwt",
            "caller_type": "service",
            "scopes": ["comms:read"],
        }

    def test_agent_jwt_caller_with_forged_email_claim_is_not_impersonated(self) -> None:
        """agent-jwt identity comes from ``sub`` only — a forged ``email``
        claim must not surface as the caller identity."""
        token = MagicMock()
        token.claims = {
            "iss": "agent-jwt",
            "sub": "ea-agent-svc",
            "email": "victim@example.com",
            "scopes": ["comms:read"],
        }

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
        ):
            result = asyncio.run(_whoami())

        assert result["identity"] == "ea-agent-svc"

    def test_missing_token_raises_tool_error(self) -> None:
        with patch("providers.comms.get_access_token", return_value=None):
            with pytest.raises(ToolError, match="no access token"):
                asyncio.run(_whoami())

    def test_registered_identity_includes_schema_version_range(self) -> None:
        """TECH-5160: an identity that has already registered gets
        min_schema_version/max_schema_version back from whoami."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}
        fake_agent = MagicMock(min_schema_version=1, max_schema_version=2)

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
        ):
            result = asyncio.run(_whoami())

        assert result["min_schema_version"] == 1
        assert result["max_schema_version"] == 2

    def test_unregistered_identity_omits_schema_version_fields(self) -> None:
        """The DB is reachable and answers "no agent for this sub" --
        distinct from the connectivity-failure case below, which must
        reach the same omission via a different path."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
        ):
            result = asyncio.run(_whoami())

        assert "min_schema_version" not in result
        assert "max_schema_version" not in result

    def test_db_connectivity_failure_still_returns_identity_fields(self) -> None:
        """TECH-5160 (Argus round 1): a genuine connectivity/config failure
        (DATABASE_URL unset, Postgres unreachable, etc.) must not break
        whoami's core identity/scopes contract -- it only omits the
        schema-version fields, exactly like the unregistered-caller case,
        but via the narrowed (RuntimeError/OperationalError/InterfaceError/
        OSError) except clause rather than the agent-is-None branch."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}

        with (
            patch("providers.comms.get_access_token", return_value=token),
            patch(
                "providers.comms.get_session_factory",
                side_effect=RuntimeError("Required environment variable DATABASE_URL is not set"),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["identity"] == "ea-agent-svc"
        assert result["issuer"] == "agent-jwt"
        assert result["caller_type"] == "service"
        assert result["scopes"] == ["comms:read"]
        assert "min_schema_version" not in result
        assert "max_schema_version" not in result

    def test_unnarrowed_exception_is_not_swallowed(self) -> None:
        """TECH-5160 (Argus round 1): a genuine programming/schema bug in
        the lookup path (anything other than the narrowed connectivity/
        config exception types) must propagate, not be silently absorbed
        into a successful-looking, field-less response."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch(
                "providers.comms.service.get_agent_by_sub",
                AsyncMock(side_effect=AttributeError("boom")),
            ),
            pytest.raises(AttributeError, match="boom"),
        ):
            asyncio.run(_whoami())
