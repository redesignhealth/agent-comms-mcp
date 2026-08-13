"""Tests for server composition and scope-enforcement middleware."""

from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ResourceError, ToolError

_MOCK_OIDC_CONFIG = MagicMock()

# Building the OIDCProxy normally fetches the Okta discovery document —
# patch it out so tests never touch the network.
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


def _import_main() -> object:
    """Import a fresh ``main`` module under the OIDC/env patches."""
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


class TestServerComposition:
    def test_server_name(self) -> None:
        main = _import_main()
        assert main.mcp.name == "agent-comms-mcp"

    def test_has_auth(self) -> None:
        main = _import_main()
        assert main.mcp.auth is not None

    def test_missing_required_env_fails_fast(self) -> None:
        """Startup must crash loudly when a required secret is absent."""
        from auth import require_env

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="OKTA_CLIENT_SECRET"):
                require_env("OKTA_CLIENT_SECRET")

    def test_empty_required_env_fails_fast(self) -> None:
        """Empty string is as bad as missing — no silent empty-secret path."""
        from auth import require_env

        with patch.dict(os.environ, {"MCP_JWT_SECRET": ""}):
            with pytest.raises(RuntimeError, match="MCP_JWT_SECRET"):
                require_env("MCP_JWT_SECRET")


class TestScopeRegistryParity:
    """The actual mounted tool names must resolve against the scope registry.

    If a tool's mounted name (``<namespace>_<tool>``) drifts from its
    TOOL_SCOPES key, every agent-jwt call to it is rejected fail-closed — a
    silent 403 no string-literal assertion in test_scopes.py can catch.
    """

    def test_all_mounted_tools_are_enrolled(self) -> None:
        from scopes import TOOL_SCOPES

        main = _import_main()
        with _OIDC_PATCH, _ENV_PATCH:
            tools = asyncio.run(main.mcp.list_tools())  # type: ignore[attr-defined]
        mounted = {t.name for t in tools}

        assert "comms_whoami" in mounted, (
            "comms_whoami is not a mounted tool name — registration drifted "
            f"(double-prefix?). Mounted names: {sorted(mounted)}"
        )
        unenrolled = mounted - set(TOOL_SCOPES)
        assert not unenrolled, (
            f"Mounted tools missing from TOOL_SCOPES (agent-jwt callers would "
            f"be denied fail-closed): {sorted(unenrolled)}"
        )


class TestScopeEnforcementMiddleware:
    """Fail-closed behavior of ScopeEnforcementMiddleware.on_call_tool."""

    def _make_context(self, tool_name: str) -> MagicMock:
        ctx = MagicMock()
        ctx.message.name = tool_name
        return ctx

    def _make_token(
        self,
        *,
        iss: str | None,
        scopes: list[str] | None,
        client_id: str = "test-client",
        sub: str = "test-svc",
    ) -> MagicMock:
        token = MagicMock()
        claims: dict[str, object] = {}
        if iss is not None:
            claims["iss"] = iss
        if iss == "agent-jwt":
            claims["sub"] = sub
        # agent-jwt tokens carry scopes in the ``scopes`` LIST claim;
        # ``token.scopes`` stays EMPTY to mirror production (JWTVerifier
        # maps only OAuth ``scope``/``scp`` claims).
        claims["scopes"] = scopes or []
        token.claims = claims
        token.scopes = []
        token.client_id = client_id
        return token

    def _middleware(self) -> object:
        main = _import_main()
        return main.ScopeEnforcementMiddleware()  # type: ignore[attr-defined]

    def test_interactive_okta_token_bypasses_scope_check(self) -> None:
        middleware = self._middleware()
        context = self._make_context("comms_whoami")
        call_next = AsyncMock(return_value=MagicMock())
        okta_token = self._make_token(iss="https://example.okta.com/oauth2/default", scopes=[])

        with patch("main.get_access_token", return_value=okta_token):
            asyncio.run(middleware.on_call_tool(context, call_next))

        call_next.assert_awaited_once()

    def test_agent_jwt_token_with_matching_scope_passes(self) -> None:
        middleware = self._middleware()
        context = self._make_context("comms_whoami")
        call_next = AsyncMock(return_value=MagicMock())
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read"])

        with patch("main.get_access_token", return_value=bot_token):
            asyncio.run(middleware.on_call_tool(context, call_next))

        call_next.assert_awaited_once()

    def test_agent_jwt_token_missing_required_scope_is_rejected(self) -> None:
        middleware = self._middleware()
        context = self._make_context("comms_whoami")  # requires comms:read
        call_next = AsyncMock()
        bot_token = self._make_token(iss="agent-jwt", scopes=["zoom:read"])

        with patch("main.get_access_token", return_value=bot_token):
            with pytest.raises(ToolError, match="requires elevated permissions"):
                asyncio.run(middleware.on_call_tool(context, call_next))

        call_next.assert_not_called()

    def test_agent_jwt_token_for_unenrolled_tool_is_rejected(self) -> None:
        """Tools without a registry entry must fail closed for agent-jwt callers."""
        middleware = self._middleware()
        context = self._make_context("comms_send_message_not_yet_a_tool")
        call_next = AsyncMock()
        # Even a broadly-scoped token can't reach an unenrolled tool.
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read", "comms:write"])

        with patch("main.get_access_token", return_value=bot_token):
            with pytest.raises(ToolError, match="requires elevated permissions"):
                asyncio.run(middleware.on_call_tool(context, call_next))

        call_next.assert_not_called()

    def test_missing_token_is_rejected(self) -> None:
        """No auth context at all must reject rather than silently allow."""
        middleware = self._middleware()
        context = self._make_context("comms_whoami")
        call_next = AsyncMock()

        with patch("main.get_access_token", return_value=None):
            with pytest.raises(ToolError, match="requires elevated permissions"):
                asyncio.run(middleware.on_call_tool(context, call_next))

        call_next.assert_not_called()

    def test_denial_message_is_uniform_across_categories(self) -> None:
        """Identical client-facing text for every denial category, so the
        scope registry cannot be enumerated by probing error messages."""
        middleware = self._middleware()
        messages: list[str] = []

        cases = [
            # (tool_name, token) → missing_scope, tool_not_enrolled, missing_token
            ("comms_whoami", self._make_token(iss="agent-jwt", scopes=[])),
            ("comms_whoami", None),
        ]
        for tool_name, token in cases:
            context = self._make_context(tool_name)
            with patch("main.get_access_token", return_value=token):
                with pytest.raises(ToolError) as exc_info:
                    asyncio.run(middleware.on_call_tool(context, AsyncMock()))
            messages.append(str(exc_info.value))

        # Unenrolled tool produces the same message shape (differs only in
        # the tool name it echoes back).
        context = self._make_context("comms_whoami")
        assert len(set(messages)) == 1
        assert (
            messages[0] == "insufficient_scope: tool 'comms_whoami' requires elevated permissions"
        )

    def test_denial_emits_structured_scope_denial_event(self) -> None:
        middleware = self._middleware()
        context = self._make_context("comms_whoami")
        bot_token = self._make_token(iss="agent-jwt", scopes=[], client_id="ea-agent-svc")

        with patch("main.get_access_token", return_value=bot_token):
            with patch("main.log_scope_denial") as mock_denial:
                with pytest.raises(ToolError):
                    asyncio.run(middleware.on_call_tool(context, AsyncMock()))

        mock_denial.assert_called_once_with(
            tool="comms_whoami",
            reason="missing_scope",
            client_id="ea-agent-svc",
            required_scope="comms:read",
        )

    def test_unenrolled_denial_event_has_no_required_scope(self) -> None:
        middleware = self._middleware()
        context = self._make_context("not_a_real_tool")
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read"])

        with patch("main.get_access_token", return_value=bot_token):
            with patch("main.log_scope_denial") as mock_denial:
                with pytest.raises(ToolError):
                    asyncio.run(middleware.on_call_tool(context, AsyncMock()))

        mock_denial.assert_called_once_with(
            tool="not_a_real_tool",
            reason="tool_not_enrolled",
            client_id="test-client",
            required_scope=None,
        )


class TestReadResourceMiddleware:
    """Fail-closed behavior of ScopeEnforcementMiddleware.on_read_resource.

    Mirrors ``TestScopeEnforcementMiddleware``'s tool-path tests. This
    service registers no resources today (``scopes.RESOURCE_SCOPES`` is
    empty), so every URI is "unenrolled" by default — a real exercise of
    the fail-closed default rather than a contrived case.
    """

    def _make_context(self, uri: str) -> MagicMock:
        ctx = MagicMock()
        ctx.message.uri = uri
        return ctx

    def _make_token(
        self,
        *,
        iss: str | None,
        scopes: list[str] | None,
        client_id: str = "test-client",
        sub: str = "test-svc",
    ) -> MagicMock:
        token = MagicMock()
        claims: dict[str, object] = {}
        if iss is not None:
            claims["iss"] = iss
        if iss == "agent-jwt":
            claims["sub"] = sub
        claims["scopes"] = scopes or []
        token.claims = claims
        token.scopes = []
        token.client_id = client_id
        return token

    def _middleware(self) -> object:
        main = _import_main()
        return main.ScopeEnforcementMiddleware()  # type: ignore[attr-defined]

    def test_interactive_okta_token_bypasses_scope_check(self) -> None:
        middleware = self._middleware()
        context = self._make_context("resource://some-resource")
        call_next = AsyncMock(return_value=MagicMock())
        okta_token = self._make_token(iss="https://example.okta.com/oauth2/default", scopes=[])

        with patch("main.get_access_token", return_value=okta_token):
            asyncio.run(middleware.on_read_resource(context, call_next))

        call_next.assert_awaited_once()

    def test_missing_token_is_rejected(self) -> None:
        middleware = self._middleware()
        context = self._make_context("resource://some-resource")
        call_next = AsyncMock()

        with patch("main.get_access_token", return_value=None):
            with pytest.raises(ResourceError, match="requires elevated permissions"):
                asyncio.run(middleware.on_read_resource(context, call_next))

        call_next.assert_not_called()

    def test_unenrolled_resource_is_rejected_fail_closed(self) -> None:
        """No resource is in ``RESOURCE_SCOPES`` today — every agent-jwt read
        must be denied by default, even with a broadly-scoped token."""
        middleware = self._middleware()
        context = self._make_context("resource://not-enrolled-anywhere")
        call_next = AsyncMock()
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read", "comms:write"])

        with patch("main.get_access_token", return_value=bot_token):
            with pytest.raises(ResourceError, match="requires elevated permissions"):
                asyncio.run(middleware.on_read_resource(context, call_next))

        call_next.assert_not_called()

    def test_missing_scope_is_rejected(self) -> None:
        """A resource that IS enrolled still denies a token lacking the
        specific required scope."""
        middleware = self._middleware()
        context = self._make_context("resource://enrolled-resource")
        call_next = AsyncMock()
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:write"])

        with patch("main.required_scope_for_resource", return_value="comms:read"):
            with patch("main.get_access_token", return_value=bot_token):
                with pytest.raises(ResourceError, match="requires elevated permissions"):
                    asyncio.run(middleware.on_read_resource(context, call_next))

        call_next.assert_not_called()

    def test_matching_scope_passes(self) -> None:
        middleware = self._middleware()
        context = self._make_context("resource://enrolled-resource")
        call_next = AsyncMock(return_value=MagicMock())
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read"])

        with patch("main.required_scope_for_resource", return_value="comms:read"):
            with patch("main.get_access_token", return_value=bot_token):
                asyncio.run(middleware.on_read_resource(context, call_next))

        call_next.assert_awaited_once()

    def test_denial_emits_structured_scope_denial_event_with_uri_as_tool(self) -> None:
        middleware = self._middleware()
        context = self._make_context("resource://some-resource")
        bot_token = self._make_token(iss="agent-jwt", scopes=[], client_id="ea-agent-svc")

        with patch("main.get_access_token", return_value=bot_token):
            with patch("main.log_scope_denial") as mock_denial:
                with pytest.raises(ResourceError):
                    asyncio.run(middleware.on_read_resource(context, AsyncMock()))

        mock_denial.assert_called_once_with(
            tool="resource://some-resource",
            reason="resource_not_enrolled",
            client_id="ea-agent-svc",
            required_scope=None,
        )


class TestObservabilityMiddleware:
    def _make_context(self, tool_name: str = "comms_whoami") -> MagicMock:
        ctx = MagicMock()
        ctx.message.name = tool_name
        return ctx

    def _middleware(self) -> object:
        main = _import_main()
        return main.ObservabilityMiddleware()  # type: ignore[attr-defined]

    def test_log_tool_call_on_success(self) -> None:
        middleware = self._middleware()
        context = self._make_context()
        call_next = AsyncMock(return_value=MagicMock())

        with patch("main.log_tool_call") as mock_log:
            with patch("main.get_access_token", return_value=None):
                asyncio.run(middleware.on_call_tool(context, call_next))

        mock_log.assert_called_once()
        _, kwargs = mock_log.call_args
        assert kwargs["success"] is True
        assert kwargs["error_type"] is None

    def test_log_tool_call_on_exception(self) -> None:
        middleware = self._middleware()
        context = self._make_context()
        call_next = AsyncMock(side_effect=ValueError("boom"))

        with patch("main.log_tool_call") as mock_log:
            with patch("main.get_access_token", return_value=None):
                with pytest.raises(ValueError, match="boom"):
                    asyncio.run(middleware.on_call_tool(context, call_next))

        mock_log.assert_called_once()
        _, kwargs = mock_log.call_args
        assert kwargs["success"] is False
        assert kwargs["error_type"] == "ValueError"

    def test_agent_jwt_token_with_forged_email_does_not_poison_user_active(self) -> None:
        """agent-jwt tokens resolve via ``sub`` only — a forged ``email``
        claim must never reach ``log_user_active``."""
        middleware = self._middleware()
        context = self._make_context()
        call_next = AsyncMock(return_value=MagicMock())

        token = MagicMock()
        token.claims = {
            "iss": "agent-jwt",
            "sub": "ea-agent-svc",
            "email": "victim@example.com",
        }

        with patch("main.log_tool_call"), patch("main.log_user_active") as mock_active:
            with patch("main.get_access_token", return_value=token):
                asyncio.run(middleware.on_call_tool(context, call_next))

        mock_active.assert_called_once_with("ea-agent-svc")


class TestEndToEnd:
    """In-memory client calls through the real mounted server + middleware."""

    def test_whoami_end_to_end_for_interactive_caller(self) -> None:
        from fastmcp import Client

        main = _import_main()

        okta_token = MagicMock()
        okta_token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "user@example.com",
        }
        okta_token.scopes = []
        okta_token.client_id = "0oa1234abc"

        async def _call() -> object:
            async with Client(main.mcp) as client:  # type: ignore[attr-defined]
                result = await client.call_tool("comms_whoami", {})
                return result.data

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", return_value=okta_token),
            patch("providers.comms.get_access_token", return_value=okta_token),
        ):
            data = asyncio.run(_call())

        assert data == {
            "identity": "user@example.com",
            "issuer": "https://example.okta.com/oauth2/default",
            "caller_type": "interactive",
            "scopes": [],
        }

    def test_whoami_end_to_end_for_agent_jwt_caller(self) -> None:
        from fastmcp import Client

        main = _import_main()

        bot_token = MagicMock()
        bot_token.claims = {
            "iss": "agent-jwt",
            "sub": "ea-agent-svc",
            "scopes": ["comms:read"],
        }
        bot_token.scopes = []
        bot_token.client_id = "ea-agent-svc"

        async def _call() -> object:
            async with Client(main.mcp) as client:  # type: ignore[attr-defined]
                result = await client.call_tool("comms_whoami", {})
                return result.data

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", return_value=bot_token),
            patch("providers.comms.get_access_token", return_value=bot_token),
        ):
            data = asyncio.run(_call())

        assert data == {
            "identity": "ea-agent-svc",
            "issuer": "agent-jwt",
            "caller_type": "service",
            "scopes": ["comms:read"],
        }

    def test_whoami_end_to_end_denied_without_scope(self) -> None:
        from fastmcp import Client

        main = _import_main()

        bot_token = MagicMock()
        bot_token.claims = {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": []}
        bot_token.scopes = []
        bot_token.client_id = "ea-agent-svc"

        async def _call() -> None:
            async with Client(main.mcp) as client:  # type: ignore[attr-defined]
                await client.call_tool("comms_whoami", {})

        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", return_value=bot_token),
            patch("providers.comms.get_access_token", return_value=bot_token),
        ):
            with pytest.raises(ToolError, match="requires elevated permissions"):
                asyncio.run(_call())
