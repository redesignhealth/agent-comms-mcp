"""Unit tests for the comms_whoami placeholder tool (raw function path)."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from sqlalchemy.exc import OperationalError

# ``@comms_server.tool`` registers the coroutine and returns it unchanged
# in fastmcp 3.4.2, so the tool body can be invoked directly.
from providers.comms import whoami as _whoami

# whoami now does a best-effort DB lookup for
# min_schema_version/max_schema_version. Every test below mocks BOTH
# get_session_factory and service.get_agent_by_sub so
# these unit tests exercise the intended DB-free-identity /
# agent-found / agent-not-found paths deliberately, rather than
# accidentally exercising the connectivity-failure fallback just because
# no real DATABASE_URL is configured in this test environment (which is
# what happened previously: get_session_factory() raised
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
            patch("providers.comms.service.list_sibling_identities", AsyncMock(return_value=[])),
        ):
            result = asyncio.run(_whoami())

        assert result == {
            "identity": "alice@example.com",
            "issuer": "https://example.okta.com/oauth2/default",
            "caller_type": "interactive",
            "scopes": [],
            "status": "not_registered",
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
            patch("providers.comms.service.list_sibling_identities", AsyncMock(return_value=[])),
        ):
            result = asyncio.run(_whoami())

        assert result == {
            "identity": "ea-agent-svc",
            "issuer": "agent-jwt",
            "caller_type": "service",
            "scopes": ["comms:read"],
            "status": "not_registered",
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
            patch("providers.comms.service.list_sibling_identities", AsyncMock(return_value=[])),
        ):
            result = asyncio.run(_whoami())

        assert result["identity"] == "ea-agent-svc"
        assert result["status"] == "not_registered"

    def test_missing_token_raises_tool_error(self) -> None:
        with patch("providers.comms.get_access_token", return_value=None):
            with pytest.raises(ToolError, match="no access token"):
                asyncio.run(_whoami())

    def test_registered_identity_includes_schema_version_range(self) -> None:
        """An identity that has already registered gets
        status and min_schema_version/max_schema_version back from whoami."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}
        fake_agent = MagicMock(status="active", min_schema_version=1, max_schema_version=2)

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
            patch("providers.comms.service.list_sibling_identities", AsyncMock(return_value=[])),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "active"
        assert result["min_schema_version"] == 1
        assert result["max_schema_version"] == 2

    def test_registered_suspended_identity_includes_suspended_status(self) -> None:
        """A registered but suspended identity surfaces status='suspended'
        in comms_whoami (TECH-6267)."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}
        fake_agent = MagicMock(status="suspended", min_schema_version=1, max_schema_version=1)

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
            patch("providers.comms.service.list_sibling_identities", AsyncMock(return_value=[])),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "suspended"
        assert result["min_schema_version"] == 1
        assert result["max_schema_version"] == 1

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
            patch("providers.comms.service.list_sibling_identities", AsyncMock(return_value=[])),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "not_registered"
        assert "min_schema_version" not in result
        assert "max_schema_version" not in result

    def test_db_connectivity_failure_still_returns_identity_fields(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A genuine connectivity/config failure
        (DATABASE_URL unset here) must not break whoami's core
        identity/scopes contract -- it only omits the schema-version
        fields, exactly like the unregistered-caller case. Specifically
        exercises the FIRST of whoami's two try-blocks: this patches
        get_session_factory itself to raise, so it hits block 1's narrow
        RuntimeError catch and returns early -- block 2's separate
        OperationalError/InterfaceError/OSError catch, for a failure during
        the query itself, is covered by
        ``test_db_query_failure_still_returns_identity_fields`` below.
        Also asserts the swallowed failure is actually logged: a prior
        version of this test never checked this, so the log call could be
        deleted without failing anything."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}

        with (
            patch("providers.comms.get_access_token", return_value=token),
            patch(
                "providers.comms.get_session_factory",
                side_effect=RuntimeError("Required environment variable DATABASE_URL is not set"),
            ),
            caplog.at_level("WARNING", logger="providers.comms"),
        ):
            result = asyncio.run(_whoami())

        assert result["identity"] == "ea-agent-svc"
        assert result["issuer"] == "agent-jwt"
        assert result["caller_type"] == "service"
        assert result["scopes"] == ["comms:read"]
        assert "status" not in result
        assert "min_schema_version" not in result
        assert "max_schema_version" not in result
        # "unavailable", not just "schema-version lookup":
        # the broader substring also matches block 2's "... lookup failed
        # ..." message below, so it wouldn't actually prove this test hit
        # block 1 specifically, despite the docstring's claim that it does.
        assert any("schema-version lookup unavailable" in r.message for r in caplog.records)

    def test_db_query_failure_still_returns_identity_fields(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Distinct from the test above -- this
        exercises whoami's SECOND try-block, where get_session_factory()
        itself succeeds but the query fails with a connection-level error
        (OperationalError/InterfaceError/OSError) mid-lookup. Same outcome
        contract as block 1's failure (identity fields intact,
        schema-version fields omitted, a WARNING logged), but via the
        code path block 1's own test structurally cannot reach."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}

        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch(
                "providers.comms.service.get_agent_by_sub",
                AsyncMock(
                    side_effect=OperationalError("SELECT 1", {}, Exception("connection reset"))
                ),
            ),
            caplog.at_level("WARNING", logger="providers.comms"),
        ):
            result = asyncio.run(_whoami())

        assert result["identity"] == "ea-agent-svc"
        assert result["issuer"] == "agent-jwt"
        assert result["caller_type"] == "service"
        assert result["scopes"] == ["comms:read"]
        assert "status" not in result
        assert "min_schema_version" not in result
        assert "max_schema_version" not in result
        assert any("schema-version lookup failed" in r.message for r in caplog.records)

    def test_unnarrowed_exception_is_not_swallowed(self) -> None:
        """A genuine programming/schema bug in
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

    def test_suspended_caller_with_one_active_sibling_includes_suggestion(self) -> None:
        """(a) Caller status suspended + exactly one active sibling -> suggested_agent_key
        present and correct."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "dan.costanza@redesignhealth.com",
        }
        fake_agent = MagicMock(status="suspended", min_schema_version=1, max_schema_version=1)
        siblings = [
            {
                "agent_key": "claude-code",
                "sub": "dan.costanza@redesignhealth.com::claude-code",
                "display_name": "Claude Code",
                "status": "active",
            }
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "suspended"
        assert result["identity"] == "dan.costanza@redesignhealth.com"
        assert result["other_identities"] == siblings
        assert result["suggested_agent_key"] == "claude-code"

    def test_suspended_caller_with_one_active_bare_sibling_includes_bare_suggestion(
        self,
    ) -> None:
        """(a2) Caller status suspended + exactly one active sibling, and that
        sibling is the BARE base_sub identity (agent_key is None) ->
        ``suggested_bare_identity: True`` is set instead of the ambiguous
        ``suggested_agent_key: None`` (Fix for TECH-6368 doc-drift review)."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "dan.costanza@redesignhealth.com",
        }
        fake_agent = MagicMock(status="suspended", min_schema_version=1, max_schema_version=1)
        siblings = [
            {
                "agent_key": None,
                "sub": "dan.costanza@redesignhealth.com",
                "display_name": "Bare Agent",
                "status": "active",
            }
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "suspended"
        assert result["other_identities"] == siblings
        assert result["suggested_bare_identity"] is True
        assert "suggested_agent_key" not in result

    def test_unregistered_caller_with_zero_active_siblings_omits_suggestion(self) -> None:
        """(b) Caller status not_registered + zero active siblings -> other_identities
        present if suspended siblings exist, but no suggested_agent_key."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "dan.costanza@redesignhealth.com",
        }
        siblings = [
            {
                "agent_key": "old-agent",
                "sub": "dan.costanza@redesignhealth.com::old-agent",
                "display_name": "Old Agent",
                "status": "suspended",
            }
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "not_registered"
        assert result["other_identities"] == siblings
        assert "suggested_agent_key" not in result

    def test_unregistered_caller_with_multiple_active_siblings_includes_guidance(self) -> None:
        """(c) Caller status not_registered + 2+ active siblings -> other_identities
        present, no suggested_agent_key (ambiguous which one), but
        active_identity_candidates lists every active sibling plus a
        guidance string (TECH-6461 -- the "exactly one" gate no longer
        leaves the caller with zero signal)."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "dan.costanza@redesignhealth.com",
        }
        siblings = [
            {
                "agent_key": "bot-1",
                "sub": "dan.costanza@redesignhealth.com::bot-1",
                "display_name": "Bot 1",
                "status": "active",
            },
            {
                "agent_key": "bot-2",
                "sub": "dan.costanza@redesignhealth.com::bot-2",
                "display_name": "Bot 2",
                "status": "active",
            },
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "not_registered"
        assert result["other_identities"] == siblings
        assert "suggested_agent_key" not in result
        assert "suggested_bare_identity" not in result
        assert result["active_identity_candidates"] == [
            {"agent_key": "bot-1", "display_name": "Bot 1", "is_bare_identity": False},
            {"agent_key": "bot-2", "display_name": "Bot 2", "is_bare_identity": False},
        ]
        assert "guidance" in result
        assert "active_identity_candidates" in result["guidance"]

    def test_multiple_active_siblings_including_bare_identity_marks_is_bare_identity(
        self,
    ) -> None:
        """(c2) When one of several active siblings is the BARE base_sub
        identity (agent_key is None), its candidate dict has
        is_bare_identity=True and the guidance explicitly warns against
        passing the literal string 'None' (Argus round-1 BLOCKING fix,
        TECH-6461)."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "dan.costanza@redesignhealth.com",
        }
        siblings = [
            {
                "agent_key": None,
                "sub": "dan.costanza@redesignhealth.com",
                "display_name": "Bare Agent",
                "status": "active",
            },
            {
                "agent_key": "bot-2",
                "sub": "dan.costanza@redesignhealth.com::bot-2",
                "display_name": "Bot 2",
                "status": "active",
            },
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["active_identity_candidates"] == [
            {"agent_key": None, "display_name": "Bare Agent", "is_bare_identity": True},
            {"agent_key": "bot-2", "display_name": "Bot 2", "is_bare_identity": False},
        ]
        assert "is_bare_identity" in result["guidance"]
        assert "literal string 'None'" in result["guidance"]

    def test_sibling_lookup_db_failure_returns_cleanly(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """(d) Sibling-lookup DB failure -> whoami still returns cleanly,
        other_identities/suggested_agent_key simply absent."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}
        fake_agent = MagicMock(status="active", min_schema_version=1, max_schema_version=1)
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(
                    side_effect=OperationalError("SELECT siblings", {}, Exception("db error"))
                ),
            ),
            caplog.at_level("WARNING", logger="providers.comms"),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "active"
        assert result["min_schema_version"] == 1
        assert "other_identities" not in result
        assert "suggested_agent_key" not in result
        assert any("sibling lookup failed" in r.message for r in caplog.records)

    def test_healthy_active_caller_with_siblings_omits_suggestion(self) -> None:
        """(e) Healthy active caller with siblings present -> other_identities present,
        no suggested_agent_key."""
        token = MagicMock()
        token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}
        fake_agent = MagicMock(status="active", min_schema_version=1, max_schema_version=1)
        siblings = [
            {
                "agent_key": "other-agent",
                "sub": "ea-agent-svc::other-agent",
                "display_name": "Other Agent",
                "status": "active",
            }
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=fake_agent)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["status"] == "active"
        assert result["other_identities"] == siblings
        assert "suggested_agent_key" not in result

    def test_identity_is_never_rewritten_to_sibling_sub(self) -> None:
        """(f) Assert identity is never rewritten to a sibling's sub in any case."""
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "dan.costanza@redesignhealth.com",
        }
        siblings = [
            {
                "agent_key": "claude-code",
                "sub": "dan.costanza@redesignhealth.com::claude-code",
                "display_name": "Claude Code",
                "status": "active",
            }
        ]
        with (
            patch("providers.comms.get_access_token", return_value=token),
            _patched_session_factory(),
            patch("providers.comms.service.get_agent_by_sub", AsyncMock(return_value=None)),
            patch(
                "providers.comms.service.list_sibling_identities",
                AsyncMock(return_value=siblings),
            ),
        ):
            result = asyncio.run(_whoami())

        assert result["identity"] == "dan.costanza@redesignhealth.com"
        assert result["suggested_agent_key"] == "claude-code"
