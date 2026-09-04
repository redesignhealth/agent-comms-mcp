"""agent-comms-mcp entrypoint.

MCP service for permissioned, structured agent-to-agent communications.
Mounts the comms provider behind Okta OIDC (humans) + agent-jwt JWT (agents)
auth, with fail-closed per-tool scope enforcement.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, NoReturn

import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.server.lowlevel.server import NotificationOptions
from mcp.shared.exceptions import McpError
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

import plugins
import service
import subscriptions
from auth import build_auth_provider
from db import database_url, get_session_factory
from exceptions import (
    AccessDeniedError,
    AgentRetiredError,
    ConversationArchivedError,
    HoldAlreadyDecidedError,
    HoldAwaitingAutoReviewError,
    HoldExpiredError,
    InvalidConversationStateError,
    RateLimitExceededError,
)
from identity import AGENT_JWT_ISSUER, try_resolve_email
from observability import (
    configure_logging,
    log_scope_denial,
    log_tool_call,
    log_user_active,
)
from plugins import validate_configuration as validate_plugin_configuration
from providers.comms import ResourceSubscribeDeniedError, authorize_resource_subscribe, comms_server
from scopes import (
    PROPOSAL_SUBMIT_SCOPE,
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

# Flat scope requirement for resources/list and resources/templates/list
# (see ScopeEnforcementMiddleware._gate_resource_listing) — every resource
# this service registers today requires comms:read (TECH-5903).
_LIST_RESOURCES_REQUIRED_SCOPE = "comms:read"


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

        Every resource ``providers.comms`` registers is enrolled in
        ``scopes.RESOURCE_SCOPES``/``RESOURCE_TEMPLATE_SCOPES`` (TECH-5903);
        an unenrolled resource URI is fail-closed for agent-jwt callers by
        default, same contract as an unenrolled tool.
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

    async def on_list_resources(
        self,
        context: MiddlewareContext[mt.ListResourcesRequest],
        call_next: CallNext[mt.ListResourcesRequest, Any],
    ) -> Any:
        """Gate ``resources/list`` on ``comms:read`` for agent-jwt callers.

        The listed metadata (URI/name/description) is static and
        non-sensitive, but this keeps "an agent-jwt token with zero scopes
        learns nothing" true even for listing, same interactive bypass as
        every other hook. Flat scope requirement (not per-resource) because
        every resource this service registers today requires the same
        ``comms:read`` scope (TECH-5903) — if a resource requiring a
        different scope is ever added, listing would need to become
        per-item filtering instead of an all-or-nothing gate.
        """
        return await self._gate_resource_listing("resources/list", call_next, context)

    async def on_list_resource_templates(
        self,
        context: MiddlewareContext[mt.ListResourceTemplatesRequest],
        call_next: CallNext[mt.ListResourceTemplatesRequest, Any],
    ) -> Any:
        """Gate ``resources/templates/list`` on ``comms:read`` — see ``on_list_resources``."""
        return await self._gate_resource_listing("resources/templates/list", call_next, context)

    @staticmethod
    async def _gate_resource_listing(
        pseudo_uri: str,
        call_next: CallNext[Any, Any],
        context: MiddlewareContext[Any],
    ) -> Any:
        """Shared body for ``on_list_resources``/``on_list_resource_templates``.

        ``pseudo_uri`` is a fixed, non-URI label (not a real resource URI —
        there is no single URI to attribute a *listing* denial to) fed to
        ``_deny_resource`` purely so its existing ``scope_denial`` logging
        and ``ResourceError`` shape are reused unchanged rather than
        duplicated for this call site.
        """
        token = get_access_token()

        if is_interactive_token(token):
            return await call_next(context)

        if token is None:
            ScopeEnforcementMiddleware._deny_resource(
                pseudo_uri, reason="missing_token", client_id=None
            )
        if token is None:
            # Not an `assert` (Argus round-2 BLOCKING catch, same reasoning
            # as the `_okta_server is None` check above): assertions are
            # stripped under `python -O`/`-OO`, which would silently let
            # `None` flow into `scopes_for_token` below instead of failing
            # loudly here. `_deny_resource` is `NoReturn` so this branch is
            # unreachable in practice — but that guarantee lives entirely
            # in a separate function's annotation, not in this branch's own
            # control flow.
            raise RuntimeError("_deny_resource must have raised: token should be non-None here")

        if _LIST_RESOURCES_REQUIRED_SCOPE not in scopes_for_token(token):
            ScopeEnforcementMiddleware._deny_resource(
                pseudo_uri,
                reason="missing_scope",
                client_id=safe_client_id(token),
                required_scope=_LIST_RESOURCES_REQUIRED_SCOPE,
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

    Known gap (TECH-5965, filed from a TECH-5903 Argus round-1 SUGGESTION):
    this only hooks ``on_call_tool``. Resource
    *denials* are observable via ``ScopeEnforcementMiddleware``'s own
    ``scope_denial`` event (``_deny_resource``), but a successful resource
    read or list emits no equivalent of this class's ``tool_call`` event --
    that surface is invisible in metrics today. Not addressed in this PR;
    add ``on_read_resource``/``on_list_resources``/``on_list_resource_templates``
    hooks here before Phase B's subscription notifications make resource
    traffic volume-relevant.
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


# Built once and reused by the non-MCP approval HTTP routes below (TECH-5389
# PR2): mcp.custom_route registers plain Starlette routes OUTSIDE MultiAuth
# (verified against this server's own /health route, which self-documents
# that fact) -- so /approvals/{hold_id}/decide and /approvals/pending must
# self-verify their bearer token against the SAME provider instance FastMCP
# uses for /mcp, rather than a second, independently-configured one.
_auth_provider = build_auth_provider()

# The interactive-only gate below (TECH-5389 pluggable-auth-verification
# revision, plan doc §9/§15) must be structural by WHICH PROVIDER verified
# the token, not by inspecting claims on a token that was verified through
# the combined agent+interactive chain: MultiAuth.verify_token tries
# _auth_provider's sources -- the Okta server, then each agent-token
# verifier -- in order and returns the first success, so verifying against
# `_auth_provider.server` directly (bypassing MultiAuth's verifier chain
# entirely) means no agent-token verifier, default or a future TECH-5396
# plugin, is EVER consulted for authorization on this surface. `.server` is
# the exact same OktaOIDCProxy instance MultiAuth itself uses as its first
# source -- not a second, independently-constructed one.
_okta_server = _auth_provider.server
if _okta_server is None:
    # Not an `assert` (Argus round-1 BLOCKING catch): assertions are
    # stripped under `python -O`/`-OO`, which would silently boot with
    # `_okta_provider` unset and fail every approval request at runtime
    # instead of failing here at startup.
    raise RuntimeError("build_auth_provider() always sets server=Okta")
_okta_provider = _okta_server

mcp: FastMCP[Any] = FastMCP(
    "agent-comms-mcp",
    instructions=(
        "Permissioned, structured agent-to-agent communications layer. "
        "Supports EA-style agents negotiating availability "
        "and coordinating tasks across users via scoped, structured "
        "messages — no free text except the 'note' type (info-barrier "
        "sensitive: posts immediately unless it would cross an ownership "
        "boundary, in which case it is held for human approval rather than "
        "denied — see comms_post_message and comms_get_hold_status). "
        "Register with comms_register, then use "
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
        "email ({'agent': ..., 'found': bool}). comms_get_hold_status polls "
        "the status of a message held for human approval (sender-only). "
        "accepted_types in comms_register is optional and defaults to "
        "accepting every message type, including ones added in the future; "
        "pass an explicit, non-empty list only to deliberately restrict "
        "yourself to that narrower set (e.g. ['task_assign', "
        "'availability_request']). A restricted agent's declared list is "
        "enforced: a message of a type it hasn't declared is denied on the "
        "sender's call, with no direct feedback to the recipient."
    ),
    auth=_auth_provider,
)

mcp.add_middleware(ObservabilityMiddleware())
# Scope enforcement runs INSIDE observability so denials propagate outward
# as ToolError and are recorded as failed tool_call events. Denials are
# distinguished from provider failures via the dedicated `scope_denial`
# event emitted by ScopeEnforcementMiddleware._deny.
mcp.add_middleware(ScopeEnforcementMiddleware())

mcp.mount(comms_server, namespace="comms")

_RESOURCE_SUBSCRIBE_DENIAL_MESSAGE = "access_denied: not authorized for this resource"


def _deny_resource_subscribe() -> NoReturn:
    """Uniform denial for the low-level subscribe/unsubscribe handlers below.

    Mirrors ``_deny_resource``'s client-facing string, but raises the raw
    SDK ``McpError`` type rather than ``fastmcp.exceptions.ResourceError``:
    these handlers are registered directly on the low-level server (see
    below), which never passes through FastMCP's own exception-translation
    layer the way ``@comms_server.resource``-decorated reads do.
    """
    raise McpError(mt.ErrorData(code=mt.INVALID_PARAMS, message=_RESOURCE_SUBSCRIBE_DENIAL_MESSAGE))


# Low-level subscribe/unsubscribe handlers (TECH-5903 Phase B). FastMCP's
# own `@comms_server.resource` decorator has no subscribe counterpart, so
# these are registered directly on `mcp._mcp_server` (the underlying
# low-level `mcp.server.lowlevel.Server`) via its own
# `subscribe_resource()`/`unsubscribe_resource()` decorators -- which means
# they bypass `ScopeEnforcementMiddleware`/`ObservabilityMiddleware`
# entirely (those only ever see `on_call_tool`/`on_read_resource`/
# `on_list_resources`-shaped dispatch). All authz is therefore
# reimplemented in `providers.comms.authorize_resource_subscribe`, which
# both handlers below call and nothing else.
_low_level_server = mcp._mcp_server


@_low_level_server.subscribe_resource()  # type: ignore[no-untyped-call, untyped-decorator]
async def _handle_subscribe_resource(uri: AnyUrl) -> None:
    uri_str = str(uri)
    try:
        caller, base_sub = await authorize_resource_subscribe(uri_str)
    except ResourceSubscribeDeniedError:
        _deny_resource_subscribe()
    session = _low_level_server.request_context.session
    await subscriptions.subscribe(uri_str, session, agent_id=caller.id, sub=base_sub)
    async with get_session_factory()() as db_session:
        await service.audit_resource_subscription(
            db_session,
            actor_sub=base_sub,
            agent_id=caller.id,
            action="resource.subscribe",
            uri=uri_str,
        )


@_low_level_server.unsubscribe_resource()  # type: ignore[no-untyped-call, untyped-decorator]
async def _handle_unsubscribe_resource(uri: AnyUrl) -> None:
    uri_str = str(uri)
    try:
        caller, base_sub = await authorize_resource_subscribe(uri_str)
    except ResourceSubscribeDeniedError:
        _deny_resource_subscribe()
    session = _low_level_server.request_context.session
    await subscriptions.unsubscribe(uri_str, session)
    async with get_session_factory()() as db_session:
        await service.audit_resource_subscription(
            db_session,
            actor_sub=base_sub,
            agent_id=caller.id,
            action="resource.unsubscribe",
            uri=uri_str,
        )


# The SDK hardcodes `resources.subscribe=False` in `get_capabilities` even
# with subscribe/unsubscribe handlers registered (plan doc §3.4 --
# `mcp/server/lowlevel/server.py::get_capabilities`, verified against
# fastmcp 3.4.2). Patch the bound method on THIS server instance, after
# registration above, to advertise `subscribe=True` instead -- otherwise a
# spec-compliant client never even attempts `resources/subscribe`. See
# `tests/test_main.py`'s capability test, which pins this so an SDK
# upgrade that changes the hardcoded default is caught rather than
# silently regressing.
_original_get_capabilities = _low_level_server.get_capabilities


def _get_capabilities_with_subscribe(
    notification_options: NotificationOptions,
    experimental_capabilities: dict[str, dict[str, Any]],
) -> mt.ServerCapabilities:
    capabilities = _original_get_capabilities(notification_options, experimental_capabilities)
    if capabilities.resources is not None:
        capabilities.resources = capabilities.resources.model_copy(update={"subscribe": True})
    return capabilities


_low_level_server.get_capabilities = _get_capabilities_with_subscribe  # type: ignore[method-assign]


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> PlainTextResponse:
    """Unauthenticated liveness check for the Dockerfile HEALTHCHECK / ECS
    container healthCheck (both hit this path — see Dockerfile and
    infrastructure/modules/mcp-server's health_check_command). custom_route
    registers a plain Starlette route outside MultiAuth, so this must not
    return anything sensitive.
    """
    return PlainTextResponse("ok")


_MAX_DECISION_REASON_LENGTH = 2000
_UNIFORM_HOLD_NOT_FOUND = {"error": "not_found"}


def _extract_bearer_token(request: Request) -> str | None:
    """Pull the raw bearer token string out of ``Authorization``, or
    ``None`` if the header is missing/malformed/empty.

    Shared by every non-MCP ``mcp.custom_route`` handler that self-verifies
    its own bearer token (``mcp.custom_route`` runs outside MultiAuth, so
    each one must) -- previously duplicated inline in both
    ``_authenticate_approval_caller`` and ``reconcile_ownership``.
    """
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token_str = header[len("Bearer ") :].strip()
    return token_str or None


async def _authenticate_approval_caller(
    request: Request, *, surface: str = "approval"
) -> tuple[str | None, int]:
    """Self-verify the bearer token for a non-MCP approval-shaped route
    (``mcp.custom_route`` runs outside MultiAuth). Returns
    ``(approver_sub, 200)`` on success, or ``(None, 401 | 403)`` on
    failure — 401 for a missing/malformed/unverifiable token, 403 for a
    token that verifies fine but fails the interactive-only gate (this is
    the load-bearing distinction: an agent-jwt token, even one carrying
    ``comms:admin``, must get 403, never 401, to prove the gate actually
    inspected and rejected it rather than merely failing to authenticate).

    ``surface`` (Argus review S6) distinguishes the denial audit action
    across the three HTTP surfaces sharing this same gate: ``"approval"``
    (default -- ``/approvals/*``), ``"proposals"`` (``GET
    /proposals/pending``), and ``"proposals_decide"`` (``POST
    /proposals/{hold_id}/decide``) -- passed straight through to
    ``service.audit_denied_approval_requires_interactive`` (validated there
    against ``ALLOWED_SURFACES``) so the surfaces' denials are no longer
    indistinguishable in the audit trail.

    Structural gate, deliberately with NO scope escape hatch, and now
    structural by VERIFICATION PATH, not claim inspection (plan doc §9/§15):
    the token is verified against ``_okta_provider`` ONLY -- the agent-token
    verifier chain (``_auth_provider``'s non-Okta sources; today just the
    default ``JWTVerifier``, in the future possibly a TECH-5396 plugin) is
    NEVER consulted for authorization here, so no agent credential of any
    format can pass this gate regardless of any scope it carries, even
    under a misconfigured or malicious agent-verifier plugin. This is
    stronger than the claim-inspection pattern in ``providers/comms.py``'s
    ``is_interactive_token(token) or "comms:admin" in scopes_for_token(token)``
    (which exists precisely so an agent CAN self-approve certain admin
    actions) -- this gate is what makes agent self-approval of its own
    high-risk content structurally impossible, not merely scope-gated.
    ``is_interactive_token`` is still asserted below as a belt-and-braces
    check on the Okta-verified result. The agent chain is consulted ONLY on
    the failure path, solely to attribute the ``denied.approval_requires_
    interactive`` audit row to whatever identity an agent token carries (a
    plain missing/malformed header, or a token that fails BOTH chains,
    never reaches the DB at all, since there is no caller identity yet to
    attribute the audit row to).
    """
    token_str = _extract_bearer_token(request)
    if token_str is None:
        return None, 401
    access_token = await _okta_provider.verify_token(token_str)
    if access_token is not None and is_interactive_token(access_token):
        caller_sub = try_resolve_email(access_token)
        if caller_sub is None:
            return None, 401
        return caller_sub, 200

    # Interactive verification failed (or, defensively, succeeded but
    # somehow didn't look interactive) -- fall back to the full agent+
    # interactive chain SOLELY to attribute the denial audit row; this
    # result is never used for authorization.
    agent_checked_token = await _auth_provider.verify_token(token_str)
    if agent_checked_token is None:
        return None, 401
    rejected_sub = try_resolve_email(agent_checked_token) or "unknown"
    async with get_session_factory()() as session:
        await service.audit_denied_approval_requires_interactive(
            session, actor_sub=rejected_sub, surface=surface
        )
    return None, 403


_MAX_PROPOSAL_STRING_FIELD_LENGTH = 4000
# Argus review S1: `kind` is a category label (e.g. "linear_progress_update"),
# not free text -- a much lower cap than the general string-field cap above.
_MAX_PROPOSAL_KIND_LENGTH = 200
# Argus review S2: `action` is an arbitrary JSONB payload with no size/depth
# limit otherwise -- bound its serialized size, and separately cap the two
# sub-fields used as dedup keys (target_id/action_type) since an oversized
# value there would otherwise flow straight into the DB-level dedup index.
_MAX_PROPOSAL_ACTION_BYTES = 16_384
_MAX_PROPOSAL_ACTION_FIELD_LENGTH = 500


async def _verify_agent_token(token_str: str) -> Any | None:
    """Verify ``token_str`` against ONLY the agent-token verifier chain
    (``_auth_provider.verifiers`` -- ``agent_jwt_hs256`` by default, or a
    future TECH-5396 plugin), NEVER the Okta server. Structural mirror of
    ``_okta_provider`` (which is ``_auth_provider.server``) for the opposite
    gate.

    Each source is tried in order; the first non-``None`` result wins --
    same "each source tried independently" contract ``MultiAuth.verify_
    token`` documents for the full chain.
    """
    for verifier in _auth_provider.verifiers:
        try:
            result = await verifier.verify_token(token_str)
        except Exception:
            logger.warning("agent token verifier %r raised unexpectedly", verifier, exc_info=True)
            continue
        if result is not None:
            return result
    return None


async def _authenticate_proposal_submitter(
    request: Request,
) -> tuple[str | None, Any | None, int]:
    """Self-verify the bearer token for ``POST /proposals`` (TECH-5872).

    Structural mirror of ``_authenticate_approval_caller``, but the OPPOSITE
    gate: proposals are submitted BY BOTS, not humans. Argus review S4: this
    used to verify against the FULL ``_auth_provider`` chain (which tries
    the Okta server FIRST) and then reject via ``is_interactive_token`` --
    a claim-inspection check on the result, not a structural one. A token
    with a missing/malformed ``iss`` claim would misclassify as
    non-interactive (a bot) and slip past that check. This now verifies
    directly against ``_verify_agent_token`` (the agent-verifier chain
    ONLY, bypassing the Okta source entirely) -- an Okta-issued token cannot
    verify here at all, regardless of what claims it carries, the same
    structural posture ``_authenticate_approval_caller`` uses for its own
    (opposite) gate. The full ``_auth_provider`` chain is consulted ONLY on
    the failure path below, solely to distinguish "no identity at all"
    (401) from "this IS a legitimately verified interactive caller,
    structurally rejected" (403) and to attribute that denial's audit row
    -- never for authorization.

    A verified agent token must carry ``scopes.PROPOSAL_SUBMIT_SCOPE`` in
    its ``scopes`` claim -- this route is a non-MCP ``mcp.custom_route``, so
    ``ScopeEnforcementMiddleware`` never sees it; the scope check has to
    happen here instead. Every 403 here is now audited (Argus review S5,
    ``service.audit_denied_proposal_submission``) -- previously logged
    server-side only via ``logger.warning``.

    Returns ``(bot_sub, token, 200)`` on success, or ``(None, None, 401 |
    403)`` on failure. ``bot_sub`` is the verified agent-jwt ``sub`` claim
    (via ``try_resolve_email``, same resolver every other agent-jwt identity
    in this service uses) -- the bot's own opaque identifier, used as
    ``proposal_holds.proposed_by_bot_id``. Not resolved through
    ``service.get_agent_by_sub``: a proposing bot need not be a
    board-registered ``agents`` row at all (see
    ``models.ProposalHold``'s docstring). The verified ``token`` is returned
    too so the caller can extract ``owner_sub`` without re-verifying.
    """
    token_str = _extract_bearer_token(request)
    if token_str is None:
        return None, None, 401

    token = await _verify_agent_token(token_str)
    if token is not None:
        if PROPOSAL_SUBMIT_SCOPE not in scopes_for_token(token):
            audit_sub = try_resolve_email(token) or "unknown"
            async with get_session_factory()() as session:
                await service.audit_denied_proposal_submission(
                    session, actor_sub=audit_sub, reason="missing_scope"
                )
            return None, None, 403
        bot_sub = try_resolve_email(token)
        if bot_sub is None:
            return None, None, 401
        return bot_sub, token, 200

    # Not verifiable as an agent-jwt token at all -- fall back to the full
    # chain (including Okta) SOLELY to distinguish 401 from 403 and
    # attribute the denial audit row; this result is never used for
    # authorization.
    full_chain_token = await _auth_provider.verify_token(token_str)
    if full_chain_token is None:
        return None, None, 401
    rejected_sub = try_resolve_email(full_chain_token) or "unknown"
    async with get_session_factory()() as session:
        await service.audit_denied_proposal_submission(
            session, actor_sub=rejected_sub, reason="not_agent_token"
        )
    return None, None, 403


def _resolve_proposal_owner_sub(token: Any) -> str | None:
    """Best-effort ``owner_sub`` extraction from a verified bot token's
    claims (TECH-5872) -- same "trust only a registry-backed verifier's
    claim shape" posture as ``providers.comms._string_claim``, duplicated
    here rather than imported since that helper is private to
    ``providers.comms`` and takes a FastMCP ``AccessToken`` from a
    different call site's variable naming, not because the logic differs.
    """
    value = token.claims.get("owner_sub")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        return None
    return value


def _validate_proposal_string_field(
    name: str, value: Any, *, max_length: int = _MAX_PROPOSAL_STRING_FIELD_LENGTH
) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required and must be a non-empty string")
    if len(value) > max_length:
        raise ValueError(f"{name} exceeds {max_length} characters")
    return value


@mcp.custom_route("/proposals", methods=["POST"])
async def submit_proposal(request: Request) -> Response:
    """Bot-submission endpoint for a generalized action-approval proposal
    (TECH-5872/5875/5877). Body:
    ``{"kind": str, "action": {..., "target_id": str, "action_type": str},
    "rationale": str, "confidence": "low"|"medium"|"high",
    "importance": "low"|"medium"|"high", "impact": "low"|"medium"|"high",
    "target_fingerprint": str}``.

    Auth: agent-jwt bearer token carrying ``comms:proposals:write`` (see
    ``_authenticate_proposal_submitter``) -- NOT the interactive-only gate
    the ``/approvals/*`` decide/list routes use, since this is the
    submission side, not the human-decide side.

    Rate-limited per bot (TECH-5875, 429 on rejection, logged for
    operational visibility). Deduplicates against an existing
    ``status='pending'`` row matching ``(kind, proposed_by_bot_id,
    target_id, action_type)`` by updating it in place instead of inserting
    a duplicate (TECH-5872) -- scoped to the submitting bot (Argus review
    B1): a different bot proposing the same ``(kind, target_id,
    action_type)`` gets its own row, never silently overwrites another
    bot's pending proposal.
    Immediately judged by the TECH-5877 kind-scoped deterministic rules
    engine -- ``priority`` is always server-derived, never caller-supplied.
    """
    bot_sub, bot_token, status = await _authenticate_proposal_submitter(request)
    if bot_sub is None or bot_token is None:
        return JSONResponse({"error": "unauthorized"}, status_code=status)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid_json"}, status_code=422)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_body"}, status_code=422)

    action = body.get("action")
    try:
        kind = _validate_proposal_string_field(
            "kind", body.get("kind"), max_length=_MAX_PROPOSAL_KIND_LENGTH
        )
    except ValueError as exc:
        return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=422)
    if not isinstance(action, dict):
        return JSONResponse(
            {"error": "invalid_request", "detail": "action is required and must be an object"},
            status_code=422,
        )
    # Argus review S2: `action` is an arbitrary caller-supplied JSONB blob
    # with no size/depth limit otherwise -- bound its serialized size, and
    # separately cap target_id/action_type since they flow straight into
    # the DB-level dedup index (idx_proposal_holds_pending_dedup).
    if len(json.dumps(action)) > _MAX_PROPOSAL_ACTION_BYTES:
        return JSONResponse(
            {
                "error": "invalid_request",
                "detail": f"action exceeds {_MAX_PROPOSAL_ACTION_BYTES} bytes serialized",
            },
            status_code=422,
        )
    try:
        rationale = _validate_proposal_string_field("rationale", body.get("rationale"))
        target_fingerprint = _validate_proposal_string_field(
            "target_fingerprint", body.get("target_fingerprint")
        )
        for action_field in ("target_id", "action_type"):
            if action_field in action:
                _validate_proposal_string_field(
                    f"action.{action_field}",
                    action.get(action_field),
                    max_length=_MAX_PROPOSAL_ACTION_FIELD_LENGTH,
                )
    except ValueError as exc:
        return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=422)

    confidence = body.get("confidence")
    importance = body.get("importance")
    impact = body.get("impact")
    try:
        if not isinstance(confidence, str) or not isinstance(importance, str):
            raise ValueError("confidence/importance must each be a string")
        if not isinstance(impact, str):
            raise ValueError("impact must be a string")
        # Argus review S14: membership-check logic lives in exactly one
        # place (service.validate_hold_level), shared with this module's
        # own defense-in-depth re-check in service.create_proposal, rather
        # than duplicated here.
        service.validate_hold_level(confidence, "confidence")
        service.validate_hold_level(importance, "importance")
        service.validate_hold_level(impact, "impact")
    except ValueError as exc:
        return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=422)

    owner_sub = _resolve_proposal_owner_sub(bot_token)
    if owner_sub is None:
        async with get_session_factory()() as session:
            agent = await service.get_agent_by_sub(session, bot_sub)
        owner_sub = agent.owner_sub if agent is not None else None
    if owner_sub is None:
        return JSONResponse(
            {
                "error": "owner_sub_unresolvable",
                "detail": (
                    "no owner_sub claim on the bot's token, and no registered "
                    "board agent to fall back to"
                ),
            },
            status_code=422,
        )

    async with get_session_factory()() as session:
        try:
            result = await service.create_proposal(
                session,
                kind=kind,
                proposed_by_bot_id=bot_sub,
                owner_sub=owner_sub,
                action=action,
                rationale=rationale,
                confidence=confidence,
                importance=importance,
                impact=impact,
                target_fingerprint=target_fingerprint,
            )
        except RateLimitExceededError as exc:
            # TECH-5875: rejection is operationally visible via this WARNING
            # log (proposal_holds has no dedicated metrics pipeline yet).
            logger.warning("proposal submission rate-limited for proposed_by_bot_id=%s", bot_sub)
            return JSONResponse({"error": "rate_limited", "detail": str(exc)}, status_code=429)
        except ValueError as exc:
            return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=422)

    return JSONResponse(result, status_code=200)


@mcp.custom_route("/proposals/pending", methods=["GET"])
async def list_pending_proposals(request: Request) -> Response:
    """List the caller's pending proposal holds (TECH-5872) -- same
    interactive-only, owner_sub-scoped auth gate as
    ``GET /approvals/pending`` (``_authenticate_approval_caller``): a human
    reviewing what's awaiting their decision, not a bot.
    """
    owner_sub, status = await _authenticate_approval_caller(request, surface="proposals")
    if owner_sub is None:
        return JSONResponse({"error": "unauthorized"}, status_code=status)

    limit_str = request.query_params.get("limit")
    try:
        limit = int(limit_str) if limit_str is not None else 50
    except ValueError:
        return JSONResponse({"error": "invalid_limit"}, status_code=422)

    async with get_session_factory()() as session:
        result = await service.list_pending_proposal_holds(
            session, owner_sub=owner_sub, limit=limit
        )
    return JSONResponse(result, status_code=200)


@mcp.custom_route("/proposals/{hold_id}/decide", methods=["POST"])
async def decide_proposal_route(request: Request) -> Response:
    """Human decide endpoint for a pending proposal hold (TECH-5873).

    Body: ``{"decision": "approve" | "reject", "decision_note": "<required
    for reject, optional for approve, max 2000 chars>"}``. Same hard
    interactive-token gate as ``/approvals/{hold_id}/decide``
    (``_authenticate_approval_caller``) -- a bot can never reach this
    route at all, which is what makes a bot self-approving its own
    proposal structurally impossible (see ``service.decide_proposal``'s
    docstring). Unknown-hold and not-your-hold are a UNIFORM 404
    (anti-enumeration, same as ``/approvals/*``).

    ``approve`` re-fetches the target's live state and compares its
    fingerprint against the one recorded at submission time before
    writing anything; a mismatch resolves the hold as ``"stale"`` rather
    than applying a write against drifted state. A write failure resolves
    the hold as ``"apply_failed"`` (with ``apply_error`` populated) rather
    than raising -- both are 200 responses, not errors, since the hold
    itself was successfully decided.
    """
    approver_sub, status = await _authenticate_approval_caller(request, surface="proposals_decide")
    if approver_sub is None:
        return JSONResponse({"error": "unauthorized"}, status_code=status)

    hold_id_str = request.path_params["hold_id"]
    try:
        hold_id = uuid.UUID(hold_id_str)
    except ValueError:
        return JSONResponse(_UNIFORM_HOLD_NOT_FOUND, status_code=404)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid_json"}, status_code=422)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_body"}, status_code=422)
    decision = body.get("decision")
    if decision not in ("approve", "reject"):
        return JSONResponse(
            {"error": "invalid_decision", "detail": "decision must be 'approve' or 'reject'"},
            status_code=422,
        )
    decision_note = body.get("decision_note")
    if decision_note is not None:
        if not isinstance(decision_note, str):
            return JSONResponse({"error": "invalid_decision_note"}, status_code=422)
        if len(decision_note) > _MAX_DECISION_REASON_LENGTH:
            return JSONResponse(
                {
                    "error": "invalid_decision_note",
                    "detail": f"decision_note exceeds {_MAX_DECISION_REASON_LENGTH} characters",
                },
                status_code=422,
            )
    if decision == "reject" and (not isinstance(decision_note, str) or not decision_note.strip()):
        return JSONResponse(
            {
                "error": "decision_note_required",
                "detail": "decision_note is required and must be non-empty to reject",
            },
            status_code=400,
        )

    async with get_session_factory()() as session:
        try:
            result = await service.decide_proposal(
                session,
                approver_sub=approver_sub,
                hold_id=hold_id,
                decision=decision,
                decision_note=decision_note,
            )
        except AccessDeniedError:
            return JSONResponse(_UNIFORM_HOLD_NOT_FOUND, status_code=404)
        except HoldAlreadyDecidedError as exc:
            return JSONResponse({"error": "already_decided", "status": exc.status}, status_code=409)
        except Exception:
            logger.exception("decide_proposal invariant violation for hold_id=%s", hold_id)
            return JSONResponse({"error": "internal_error"}, status_code=500)

    return JSONResponse(result, status_code=200)


@mcp.custom_route("/approvals/{hold_id}/decide", methods=["POST"])
async def decide_approval(request: Request) -> Response:
    """Human decide endpoint for a held message (TECH-5389 PR2 §9).

    Body: ``{"decision": "approve" | "reject", "reason": "<optional, max
    2000 chars>"}``. Hard interactive-token gate (no agent-jwt escape
    hatch, see ``_authenticate_approval_caller``); the caller's verified
    sub must equal the held message's sender agent's frozen ``owner_sub``.
    Unknown-hold and not-your-hold are a UNIFORM 404 (anti-enumeration,
    matching the MCP tools' uniform ``AccessDeniedError`` posture).
    """
    approver_sub, status = await _authenticate_approval_caller(request)
    if approver_sub is None:
        return JSONResponse({"error": "unauthorized"}, status_code=status)

    hold_id_str = request.path_params["hold_id"]
    try:
        hold_id = uuid.UUID(hold_id_str)
    except ValueError:
        return JSONResponse(_UNIFORM_HOLD_NOT_FOUND, status_code=404)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid_json"}, status_code=422)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_body"}, status_code=422)
    decision = body.get("decision")
    if decision not in ("approve", "reject"):
        return JSONResponse(
            {"error": "invalid_decision", "detail": "decision must be 'approve' or 'reject'"},
            status_code=422,
        )
    reason = body.get("reason")
    if reason is not None:
        if not isinstance(reason, str):
            return JSONResponse({"error": "invalid_reason"}, status_code=422)
        if len(reason) > _MAX_DECISION_REASON_LENGTH:
            return JSONResponse(
                {
                    "error": "invalid_reason",
                    "detail": f"reason exceeds {_MAX_DECISION_REASON_LENGTH} characters",
                },
                status_code=422,
            )

    async with get_session_factory()() as session:
        try:
            result = await service.decide_hold(
                session,
                approver_sub=approver_sub,
                hold_id=hold_id,
                decision=decision,
                reason=reason,
                ownership_client=service.get_ownership_client_factory()(session),
                active_checker=plugins.get_active_checker(),
            )
        except AccessDeniedError:
            return JSONResponse(_UNIFORM_HOLD_NOT_FOUND, status_code=404)
        except AgentRetiredError as exc:
            return JSONResponse({"error": "agent_retired", "detail": str(exc)}, status_code=409)
        except HoldExpiredError:
            return JSONResponse({"error": "expired"}, status_code=410)
        except HoldAwaitingAutoReviewError:
            return JSONResponse({"error": "awaiting_auto_review"}, status_code=409)
        except HoldAlreadyDecidedError as exc:
            return JSONResponse({"error": "already_decided", "status": exc.status}, status_code=409)
        except InvalidConversationStateError:
            return JSONResponse({"error": "conversation_not_active"}, status_code=409)
        except ConversationArchivedError:
            return JSONResponse({"error": "conversation_archived"}, status_code=409)
        except RuntimeError:
            logger.exception("decide_hold invariant violation for hold_id=%s", hold_id)
            return JSONResponse({"error": "internal_error"}, status_code=500)

    # TECH-5903 Phase B: private keys service.decide_hold's approve path
    # attaches for this handler only -- popped and consumed here, AFTER the
    # session above closed (post-commit, matching
    # service._fire_approval_notifier's posture), never sent to the caller.
    notify_conversation_id = result.pop("_notify_conversation_id", None)
    notify_active_agent_ids = result.pop("_notify_active_agent_ids", None)
    notify_inbox_agent_ids = result.pop("_notify_inbox_agent_ids", None)
    if notify_conversation_id is not None:
        await subscriptions.notify_conversation_event(
            uuid.UUID(notify_conversation_id),
            active_agent_ids={uuid.UUID(a) for a in notify_active_agent_ids or []},
            inbox_agent_ids=[uuid.UUID(a) for a in notify_inbox_agent_ids or []],
        )

    return JSONResponse(result, status_code=200)


@mcp.custom_route("/approvals/pending", methods=["GET"])
async def list_pending_approvals(request: Request) -> Response:
    """List the caller's pending approval holds, INCLUDING the held text
    (TECH-5389 PR2 §10) -- same auth gate as the decide endpoint. Owner-
    filtered implicitly: only holds whose sender agent's ``owner_sub``
    matches the caller's verified sub are ever returned.
    """
    owner_sub, status = await _authenticate_approval_caller(request)
    if owner_sub is None:
        return JSONResponse({"error": "unauthorized"}, status_code=status)

    limit_str = request.query_params.get("limit")
    try:
        limit = int(limit_str) if limit_str is not None else 50
    except ValueError:
        return JSONResponse({"error": "invalid_limit"}, status_code=422)

    async with get_session_factory()() as session:
        result = await service.list_pending_approval_holds(
            session, owner_sub=owner_sub, limit=limit
        )
    return JSONResponse(result, status_code=200)


@mcp.custom_route("/approvals/{hold_id}/conversation", methods=["GET"])
async def get_hold_conversation(request: Request) -> Response:
    """Participant list ("To") for one pending hold's conversation
    (TECH-5751) -- same auth gate as the decide endpoint. Unknown-hold and
    not-your-hold are a uniform 404 (anti-enumeration, matching
    ``decide_approval``/``list_pending_approvals``). Scoped to a still-
    pending hold, same as the decide endpoint: 410 if expired, 409 if
    already decided or still awaiting auto-review.
    """
    approver_sub, status = await _authenticate_approval_caller(request)
    if approver_sub is None:
        return JSONResponse({"error": "unauthorized"}, status_code=status)

    hold_id_str = request.path_params["hold_id"]
    try:
        hold_id = uuid.UUID(hold_id_str)
    except ValueError:
        return JSONResponse(_UNIFORM_HOLD_NOT_FOUND, status_code=404)

    async with get_session_factory()() as session:
        try:
            result = await service.get_hold_conversation_participants(
                session, approver_sub=approver_sub, hold_id=hold_id
            )
        except AccessDeniedError:
            return JSONResponse(_UNIFORM_HOLD_NOT_FOUND, status_code=404)
        except HoldExpiredError:
            return JSONResponse({"error": "expired"}, status_code=410)
        except HoldAwaitingAutoReviewError:
            return JSONResponse({"error": "awaiting_auto_review"}, status_code=409)
        except HoldAlreadyDecidedError as exc:
            return JSONResponse({"error": "already_decided", "status": exc.status}, status_code=409)
        except RuntimeError:
            logger.exception(
                "get_hold_conversation_participants invariant violation for hold_id=%s", hold_id
            )
            return JSONResponse({"error": "internal_error"}, status_code=500)

    return JSONResponse(result, status_code=200)


@mcp.custom_route("/admin/agents/reconcile-ownership", methods=["POST"])
async def reconcile_ownership(request: Request) -> Response:
    """Admin-triggered run of TECH-5593 item 4's ownership reconciliation
    backstop (``service.reconcile_agent_ownership``) -- for agents that
    never make another verified tool call after registration, so the
    per-request ownership write-through (``providers.comms._resolve_caller_agent``)
    never fires for them and their cached ``owner_sub`` can drift forever.
    This repo has no in-process scheduler (see that function's own
    docstring), so wiring this to run periodically -- an external
    scheduler hitting this endpoint, or an in-process one a future PR
    adds -- is an operational decision, not something this route decides.

    Auth: interactive (Okta) caller OR an agent-jwt token carrying
    ``comms:admin`` -- same elevated-scope convention
    ``providers.comms.register``/``set_agent_shared`` already use for
    ``is_shared=True``, verified against the FULL ``_auth_provider`` chain
    (unlike ``_authenticate_approval_caller``'s Okta-only verification for
    hold decisions). That stricter, no-escape-hatch gate exists specifically
    to make an agent's self-approval of its OWN high-risk content
    structurally impossible; reconciliation has no analogous self-dealing
    risk to guard against here -- it only triggers a read-then-
    conditionally-write pass against the platform's own configured
    ``OwnershipClient``, which an agent cannot direct toward a
    self-chosen outcome.
    """
    token_str = _extract_bearer_token(request)
    if token_str is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    access_token = await _auth_provider.verify_token(token_str)
    if access_token is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not (is_interactive_token(access_token) or "comms:admin" in scopes_for_token(access_token)):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    limit_str = request.query_params.get("limit")
    try:
        limit = (
            int(limit_str) if limit_str is not None else service.DEFAULT_RECONCILIATION_BATCH_SIZE
        )
    except ValueError:
        return JSONResponse({"error": "invalid_limit"}, status_code=422)
    # Reject non-positive values here rather than relying solely on
    # service.reconcile_agent_ownership's own internal clamp (Argus round-1
    # BLOCKING catch): Postgres treats a negative SQL LIMIT as LIMIT ALL, so
    # a value like -1 must surface as a clear 422 at this layer, not
    # silently get clamped deep inside the service call with no feedback to
    # the caller that their input was invalid.
    if limit < 1:
        return JSONResponse({"error": "invalid_limit"}, status_code=422)

    async with get_session_factory()() as session:
        result = await service.reconcile_agent_ownership(
            session,
            ownership_client=service.get_ownership_client_factory()(session),
            limit=limit,
        )
    return JSONResponse(result, status_code=200)


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
    # Same posture for the OwnershipClient seam (TECH-5396 open question 1) --
    # lives in service.py, not plugins.py, since AgentTableOwnershipClient's
    # registry entry needs service.py's own types.
    service.validate_ownership_client_configuration()

    # Bind loopback by default; docker-compose overrides MCP_HOST=0.0.0.0
    # to reach the port mapping from the host.
    mcp.run(
        transport="streamable-http",
        host=os.environ.get("MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MCP_PORT", "8080")),
    )


if __name__ == "__main__":
    _cli()
