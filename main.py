"""agent-comms-mcp entrypoint.

MCP service for permissioned, structured agent-to-agent communications.
Mounts the comms provider behind Okta OIDC (humans) + agent-jwt JWT (agents)
auth, with fail-closed per-tool scope enforcement.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, NoReturn

import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from auth import build_auth_provider
from db import database_url
from identity import AGENT_JWT_ISSUER, try_resolve_email
from observability import (
    configure_logging,
    log_scope_denial,
    log_tool_call,
    log_user_active,
)
from plugins import validate_configuration as validate_plugin_configuration
from providers.comms import comms_server
from scopes import (
    is_interactive_token,
    required_scope_for,
    required_scope_for_resource,
    safe_client_id,
    scopes_for_token,
)

configure_logging()

logger = logging.getLogger(__name__)


# Uniform denial messages — identical across denial categories so the scope
# registry cannot be enumerated by probing denial messages. The missing
# scope is logged server-side only (see ``log_scope_denial``).
_DENIAL_MESSAGE = "insufficient_scope: tool '{tool_name}' requires elevated permissions"
_RESOURCE_DENIAL_MESSAGE = "insufficient_scope: resource '{uri}' requires elevated permissions"


class ScopeEnforcementMiddleware(Middleware):
    """Enforce agent-jwt scopes on every tool dispatch.

    Runs *inside* ``ObservabilityMiddleware``: middleware are registered in
    outer→inner order, and observability is registered first. ToolErrors
    raised here propagate outward through ObservabilityMiddleware, which
    records them as failed ``tool_call`` events. **Do not reorder middleware
    registration** — moving scope enforcement outermost would hide scope
    denials from the observability log.

    Behavior:
      * Interactive callers (Okta OIDC) bypass the check — verified via
        ``is_interactive_token``.
      * agent-jwt Bearer callers must present a token whose ``scopes`` claim
        contains the scope listed in ``scopes.TOOL_SCOPES`` for the tool.
      * Any tool not present in ``TOOL_SCOPES`` is rejected for agent-jwt
        callers (fail-closed). New tools must be enrolled in the same PR
        that introduces them.
      * Missing auth context (no token, non-interactive) is rejected —
        FastMCP should never dispatch unauthenticated calls, but they must
        not be silently allowed if it ever does.

    Every denial branch emits a structured ``scope_denial`` event (see
    observability.py) and raises the uniform client-facing denial message.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name: str = context.message.name
        token = get_access_token()

        if is_interactive_token(token):
            # Okta-authenticated human — bypass scope enforcement.
            return await call_next(context)

        if token is None:
            self._deny(tool_name, reason="missing_token", client_id=None)

        required = required_scope_for(tool_name)
        if required is None:
            # Fail-closed: agent-jwt caller invoking a tool with no scope mapping.
            self._deny(tool_name, reason="tool_not_enrolled", client_id=safe_client_id(token))

        # agent-jwt tokens carry scopes in the ``scopes`` LIST claim, which
        # FastMCP's JWTVerifier does NOT map onto ``token.scopes`` — read the
        # raw claim via ``scopes_for_token`` (see scopes.py).
        if required not in scopes_for_token(token):
            self._deny(
                tool_name,
                reason="missing_scope",
                client_id=safe_client_id(token),
                required_scope=required,
            )

        return await call_next(context)

    async def on_read_resource(
        self,
        context: MiddlewareContext[mt.ReadResourceRequestParams],
        call_next: CallNext[mt.ReadResourceRequestParams, Any],
    ) -> Any:
        """Enforce agent-jwt scopes on resource reads (mirrors the tool path).

        This service registers no resources today; the hook exists so any
        future resource is fail-closed for agent-jwt callers by default.
        """
        uri = str(context.message.uri)
        token = get_access_token()

        if is_interactive_token(token):
            return await call_next(context)

        if token is None:
            self._deny_resource(uri, reason="missing_token", client_id=None)

        required = required_scope_for_resource(uri)
        if required is None:
            self._deny_resource(
                uri, reason="resource_not_enrolled", client_id=safe_client_id(token)
            )

        if required not in scopes_for_token(token):
            self._deny_resource(
                uri,
                reason="missing_scope",
                client_id=safe_client_id(token),
                required_scope=required,
            )

        return await call_next(context)

    @staticmethod
    def _deny(
        tool_name: str,
        *,
        reason: str,
        client_id: str | None,
        required_scope: str | None = None,
    ) -> NoReturn:
        """Log a structured ``scope_denial`` event and raise a uniform ToolError."""
        log_scope_denial(
            tool=tool_name,
            reason=reason,
            client_id=client_id or "unknown",
            required_scope=required_scope,
        )
        raise ToolError(_DENIAL_MESSAGE.format(tool_name=tool_name))

    @staticmethod
    def _deny_resource(
        uri: str,
        *,
        reason: str,
        client_id: str | None,
        required_scope: str | None = None,
    ) -> NoReturn:
        """Resource-read analogue of ``_deny`` — raises ResourceError."""
        log_scope_denial(
            tool=uri,
            reason=reason,
            client_id=client_id or "unknown",
            required_scope=required_scope,
        )
        raise ResourceError(_RESOURCE_DENIAL_MESSAGE.format(uri=uri))


class ObservabilityMiddleware(Middleware):
    """Emit a structured ``tool_call`` event for every tool dispatch.

    Records wall-clock duration, success/failure, and a privacy-safe user
    identifier. Identity resolution is issuer-gated: agent-jwt tokens resolve
    strictly via ``try_resolve_email`` so
    forged email claims cannot poison ``log_user_active``; Okta tokens
    prefer the canonical ``upstream_claims.email`` threaded through the
    OIDCProxy, falling back to the shared resolver.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name: str = context.message.name
        t0 = time.monotonic()
        error_type: str | None = None
        try:
            result: ToolResult = await call_next(context)
            return result
        except Exception as exc:
            error_type = type(exc).__name__
            raise
        finally:
            duration_ms = (time.monotonic() - t0) * 1000
            email: str | None = None
            try:
                token = get_access_token()
                if token is not None:
                    if token.claims.get("iss") == AGENT_JWT_ISSUER:
                        email = try_resolve_email(token)
                    else:
                        upstream: dict[str, Any] = token.claims.get("upstream_claims", {})
                        email = upstream.get("email") or try_resolve_email(token)
            except Exception:
                # WARN so a regression in claim extraction surfaces in
                # CloudWatch without flipping the ECS log level to DEBUG.
                logger.warning("Failed to extract user identity for observability", exc_info=True)
            log_tool_call(
                tool=tool_name,
                duration_ms=duration_ms,
                success=error_type is None,
                error_type=error_type,
                email=email,
            )
            if email:
                log_user_active(email)


mcp: FastMCP[Any] = FastMCP(
    "agent-comms-mcp",
    instructions=(
        "Permissioned, structured agent-to-agent communications layer. "
        "Supports EA-style agents negotiating availability "
        "and coordinating tasks across users via scoped, structured "
        "messages — no free text except the provisional 'note' type "
        "(info-barrier sensitive; pre-quarantine pipeline, subject to change) "
        "type. Register with comms_register, then use "
        "comms_start_conversation with conversation_type 'internal' (same "
        "verified owner, invite/accept same as the other types — the "
        "distinction is the ownership check, not the invite flow), "
        "'asymmetric' (owner sets intersect, invite/accept), or 'open' "
        "(unrestricted, invite/accept). "
        "comms_post_message negotiates availability (availability_request/"
        "response, counter_proposal, confirm, decline, needs_clarification) "
        "or coordinates a task (task_assign, task_report, task_complete, "
        "task_decline, task_cancel) within a conversation. comms_inbox / "
        "comms_get_conversation / comms_list_conversations read, and "
        "comms_accept / comms_decline_invite / comms_invite / comms_leave "
        "manage membership. comms_whoami returns the authenticated caller's "
        "identity and scopes; comms_list_agents lists the board directory; "
        "comms_lookup_agent_by_email finds a board-active agent by owner "
        "email ({'agent': ..., 'found': bool}). "
        "accepted_types in comms_register declares which message types an "
        "agent accepts (e.g. 'task_assign', 'availability_request') and is "
        "enforced: a message of a type you haven't declared is denied on "
        "the sender's call, with no direct feedback to you, so declare "
        "every type you actually handle."
    ),
    auth=build_auth_provider(),
)

mcp.add_middleware(ObservabilityMiddleware())
# Scope enforcement runs INSIDE observability so denials propagate outward
# as ToolError and are recorded as failed tool_call events. Denials are
# distinguished from provider failures via the dedicated `scope_denial`
# event emitted by ScopeEnforcementMiddleware._deny.
mcp.add_middleware(ScopeEnforcementMiddleware())

mcp.mount(comms_server, namespace="comms")


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> PlainTextResponse:
    """Unauthenticated liveness check for the Dockerfile HEALTHCHECK / ECS
    container healthCheck (both hit this path — see Dockerfile and
    infrastructure/modules/mcp-server's health_check_command). custom_route
    registers a plain Starlette route outside MultiAuth, so this must not
    return anything sensitive.
    """
    return PlainTextResponse("ok")


def _cli() -> None:
    """Entry point for the ``agent-comms-mcp`` console script."""
    # Fail fast on a missing/malformed DATABASE_URL at process start rather
    # than lazily on the first tool call that touches the DB (db.get_engine
    # builds the engine lazily so DB-less unit tests can import this module
    # freely). This does not open a connection — it only validates the URL
    # is present and well-formed via db.database_url()'s require_env check.
    database_url()
    # Same fail-fast posture for the pluggable risk-scorer seam
    # (plugins.py): an unknown RISK_SCORER name or a bad import path must
    # crash at boot, not lazily on the first high-risk message.
    validate_plugin_configuration()

    # Bind loopback by default; docker-compose overrides MCP_HOST=0.0.0.0
    # to reach the port mapping from the host.
    mcp.run(
        transport="streamable-http",
        host=os.environ.get("MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MCP_PORT", "8080")),
    )


if __name__ == "__main__":
    _cli()
