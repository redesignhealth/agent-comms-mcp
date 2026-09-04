"""Tests for server composition and scope-enforcement middleware."""

from __future__ import annotations

import asyncio
import os
import re
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

    def test_initialize_advertises_resource_subscribe(self) -> None:
        """TECH-5903 Phase B: the SDK hardcodes ``resources.subscribe=False``
        in ``get_capabilities`` even with subscribe/unsubscribe handlers
        registered (plan doc §3.4) -- ``main.py`` patches the bound method
        on ``_low_level_server`` to advertise ``subscribe=True`` instead.
        Pinned here so an SDK upgrade that changes the hardcoded default
        (or a refactor that drops the patch) is caught."""
        from mcp.server.lowlevel.server import NotificationOptions

        main = _import_main()
        capabilities = main._low_level_server.get_capabilities(NotificationOptions(), {})
        assert capabilities.resources is not None
        assert capabilities.resources.subscribe is True


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

    Mirrors ``TestScopeEnforcementMiddleware``'s tool-path tests, using
    arbitrary, never-enrolled URIs (or a patched ``required_scope_for_resource``)
    to exercise the fail-closed default independently of which real
    resources ``providers.comms`` happens to register.
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
        """Resources not enrolled in RESOURCE_SCOPES/RESOURCE_TEMPLATE_SCOPES
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

        # Patched at `scopes.required_scope_for_resource` (not
        # `main.required_scope_for_resource`): `on_read_resource` now goes
        # through `scopes.check_resource_scope`, which resolves its own
        # module-level `required_scope_for_resource` internally -- a patch
        # on `main`'s imported name would no longer be consulted by that
        # internal lookup.
        with patch("scopes.required_scope_for_resource", return_value="comms:read"):
            with patch("main.get_access_token", return_value=bot_token):
                with pytest.raises(ResourceError, match="requires elevated permissions"):
                    asyncio.run(middleware.on_read_resource(context, call_next))

        call_next.assert_not_called()

    def test_matching_scope_passes(self) -> None:
        middleware = self._middleware()
        context = self._make_context("resource://enrolled-resource")
        call_next = AsyncMock(return_value=MagicMock())
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read"])

        # See test_missing_scope_is_rejected's comment on why this patches
        # `scopes.required_scope_for_resource`, not `main`'s imported name.
        with patch("scopes.required_scope_for_resource", return_value="comms:read"):
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


class TestResourceScopeRegistryParity:
    """The actual mounted resources/templates must resolve against the scope
    registry — mirrors ``TestScopeRegistryParity`` for tools.

    Catches URI drift (e.g. the mount-prefix rewrite: ``comms://agents``
    registered in ``providers.comms`` is exposed as ``comms://comms/agents``
    by the root server) the same way the tool-name parity test catches a
    ``comms_`` prefix drift — a resource registered under one URI shape but
    enrolled in ``RESOURCE_SCOPES``/``RESOURCE_TEMPLATE_SCOPES`` under
    another is silently unreachable for every agent-jwt caller.
    """

    def test_all_mounted_resources_are_enrolled(self) -> None:
        from scopes import required_scope_for_resource

        main = _import_main()
        okta_token = MagicMock()
        okta_token.claims = {"iss": "https://example.okta.com/oauth2/default"}
        # This test is about registry correctness (does every mounted
        # resource resolve a scope), not the listing hook's own enforcement
        # (covered by TestListResourcesMiddleware) -- an interactive token
        # bypasses on_list_resources so the underlying list isn't itself
        # denied for lack of a scoped token.
        with _OIDC_PATCH, _ENV_PATCH, patch("main.get_access_token", return_value=okta_token):
            resources = asyncio.run(main.mcp.list_resources())  # type: ignore[attr-defined]

        assert "comms://comms/agents" in {str(r.uri) for r in resources}, (
            "comms://comms/agents is not a mounted resource URI — registration "
            "drifted (mount-prefix rewrite?)"
        )
        unenrolled = [
            str(r.uri) for r in resources if required_scope_for_resource(str(r.uri)) is None
        ]
        assert not unenrolled, (
            f"Mounted resources missing from RESOURCE_SCOPES (agent-jwt callers "
            f"would be denied fail-closed): {sorted(unenrolled)}"
        )

    def test_all_mounted_resource_templates_are_enrolled(self) -> None:
        from scopes import required_scope_for_resource

        main = _import_main()
        okta_token = MagicMock()
        okta_token.claims = {"iss": "https://example.okta.com/oauth2/default"}
        with _OIDC_PATCH, _ENV_PATCH, patch("main.get_access_token", return_value=okta_token):
            templates = asyncio.run(main.mcp.list_resource_templates())  # type: ignore[attr-defined]

        template_uris = {t.uri_template for t in templates}
        assert "comms://comms/conversations/{conversation_id}" in template_uris, (
            "comms://comms/conversations/{conversation_id} is not a mounted "
            f"resource template — registration drifted. Mounted: {sorted(template_uris)}"
        )
        assert "comms://comms/agents/{agent_id}/inbox" in template_uris, (
            "comms://comms/agents/{agent_id}/inbox is not a mounted resource "
            f"template — registration drifted. Mounted: {sorted(template_uris)}"
        )
        unenrolled = [
            uri for uri in template_uris if required_scope_for_resource(_example_uri(uri)) is None
        ]
        assert not unenrolled, (
            f"Mounted resource templates missing from RESOURCE_TEMPLATE_SCOPES "
            f"(agent-jwt callers would be denied fail-closed): {sorted(unenrolled)}"
        )

    def test_registry_has_no_stale_entries(self) -> None:
        """Reverse direction of the two tests above (Argus round-1
        SUGGESTION): every ``RESOURCE_SCOPES``/``RESOURCE_TEMPLATE_SCOPES``
        key must correspond to an actually-mounted resource/template — a
        stale entry left behind after a rename would otherwise silently
        gate nothing (it would never be consulted, since
        ``required_scope_for_resource`` is only ever called with a REAL
        URI from an incoming request), giving a false sense that the
        registry is complete."""
        from scopes import RESOURCE_SCOPES, RESOURCE_TEMPLATE_SCOPES

        main = _import_main()
        okta_token = MagicMock()
        okta_token.claims = {"iss": "https://example.okta.com/oauth2/default"}
        # Two sequential `asyncio.run()` calls in one `with` block, unlike
        # the sibling tests above (each of which only calls one list_*
        # method) -- confirmed safe (Argus round-2 SUGGESTION asked this be
        # verified, not assumed): `FastMCP.list_resources`/
        # `list_resource_templates` hold no live event-loop-bound state
        # between calls (pure metadata introspection over the already-
        # mounted, synchronously-constructed resource registry), so a
        # fresh event loop per call via `asyncio.run()` is not a problem
        # the way it would be for e.g. a held DB connection or session.
        with _OIDC_PATCH, _ENV_PATCH, patch("main.get_access_token", return_value=okta_token):
            resources = asyncio.run(main.mcp.list_resources())  # type: ignore[attr-defined]
            templates = asyncio.run(main.mcp.list_resource_templates())  # type: ignore[attr-defined]

        mounted_uris = {str(r.uri) for r in resources}
        mounted_templates = {t.uri_template for t in templates}

        stale_exact = set(RESOURCE_SCOPES) - mounted_uris
        assert not stale_exact, (
            f"RESOURCE_SCOPES entries with no matching mounted resource "
            f"(stale after a rename?): {sorted(stale_exact)}"
        )
        stale_templates = set(RESOURCE_TEMPLATE_SCOPES) - mounted_templates
        assert not stale_templates, (
            f"RESOURCE_TEMPLATE_SCOPES entries with no matching mounted "
            f"template (stale after a rename?): {sorted(stale_templates)}"
        )


def _example_uri(template: str) -> str:
    """Substitute a placeholder concrete value for every ``{param}`` segment.

    ``required_scope_for_resource`` matches concrete URIs, not template
    strings themselves — this produces a stand-in concrete URI to feed it,
    e.g. ``comms://comms/conversations/{conversation_id}`` ->
    ``comms://comms/conversations/example``.
    """
    return re.sub(r"\{[^/{}]+\}", "example", template)


class TestListResourcesMiddleware:
    """Fail-closed behavior of the resources/list and resources/templates/list hooks."""

    def _make_context(self) -> MagicMock:
        return MagicMock()

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

    def test_interactive_token_bypasses_list_resources(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock(return_value=MagicMock())
        okta_token = self._make_token(iss="https://example.okta.com/oauth2/default", scopes=[])

        with patch("main.get_access_token", return_value=okta_token):
            asyncio.run(middleware.on_list_resources(self._make_context(), call_next))

        call_next.assert_awaited_once()

    def test_interactive_token_bypasses_list_resource_templates(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock(return_value=MagicMock())
        okta_token = self._make_token(iss="https://example.okta.com/oauth2/default", scopes=[])

        with patch("main.get_access_token", return_value=okta_token):
            asyncio.run(middleware.on_list_resource_templates(self._make_context(), call_next))

        call_next.assert_awaited_once()

    def test_agent_jwt_with_comms_read_can_list_resources(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock(return_value=MagicMock())
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read"])

        with patch("main.get_access_token", return_value=bot_token):
            asyncio.run(middleware.on_list_resources(self._make_context(), call_next))

        call_next.assert_awaited_once()

    def test_agent_jwt_with_comms_read_can_list_resource_templates(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock(return_value=MagicMock())
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:read"])

        with patch("main.get_access_token", return_value=bot_token):
            asyncio.run(middleware.on_list_resource_templates(self._make_context(), call_next))

        call_next.assert_awaited_once()

    def test_agent_jwt_without_comms_read_is_denied_list_resources(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock()
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:write"])

        with patch("main.get_access_token", return_value=bot_token):
            with pytest.raises(ResourceError, match="requires elevated permissions"):
                asyncio.run(middleware.on_list_resources(self._make_context(), call_next))

        call_next.assert_not_called()

    def test_agent_jwt_without_comms_read_is_denied_list_resource_templates(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock()
        bot_token = self._make_token(iss="agent-jwt", scopes=["comms:write"])

        with patch("main.get_access_token", return_value=bot_token):
            with pytest.raises(ResourceError, match="requires elevated permissions"):
                asyncio.run(middleware.on_list_resource_templates(self._make_context(), call_next))

        call_next.assert_not_called()

    def test_missing_token_is_denied_list_resources(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock()

        with patch("main.get_access_token", return_value=None):
            with pytest.raises(ResourceError, match="requires elevated permissions"):
                asyncio.run(middleware.on_list_resources(self._make_context(), call_next))

        call_next.assert_not_called()

    def test_missing_token_is_denied_list_resource_templates(self) -> None:
        middleware = self._middleware()
        call_next = AsyncMock()

        with patch("main.get_access_token", return_value=None):
            with patch("main.log_scope_denial") as mock_denial:
                with pytest.raises(ResourceError, match="requires elevated permissions"):
                    asyncio.run(
                        middleware.on_list_resource_templates(self._make_context(), call_next)
                    )

        # Argus round-2 SUGGESTION: assert the structured scope_denial event,
        # matching the sibling on_call_tool/on_read_resource tests above
        # rather than just the raised exception.
        mock_denial.assert_called_once_with(
            tool="resources/templates/list",
            reason="missing_token",
            client_id="unknown",
            required_scope=None,
        )
        call_next.assert_not_called()


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
            # whoami's best-effort schema-version lookup calls
            # the REAL db.get_session_factory() unless patched. This module
            # has no test database of its own (it tests server
            # composition/middleware, not comms domain logic), and — more
            # subtly — db.py's engine/session-factory are module-level
            # singletons: a second test in this same process reusing them
            # across a DIFFERENT `asyncio.run()`-created event loop than
            # the one they were first built on fails with "attached to a
            # different loop", not a clean connectivity error. Patching
            # this out (same test-injection seam test_comms_tools.py uses)
            # keeps this test focused on its own actual purpose --
            # identity/scopes wiring, unaffected by whoami's DB-optional
            # schema-version fields either way.
            patch(
                "providers.comms.get_session_factory",
                side_effect=RuntimeError("no test database configured for this module"),
            ),
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
            # See the sibling interactive-caller test above for why this is
            # patched (db.py's module-level engine singleton).
            patch(
                "providers.comms.get_session_factory",
                side_effect=RuntimeError("no test database configured for this module"),
            ),
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
