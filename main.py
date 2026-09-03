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
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

import plugins
import service
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
)
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
        return await self._gate_resource_listing(
            "resources/templates/list", call_next, context
        )

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
        # Argus round-1 SUGGESTION: `_deny_resource` is `NoReturn`, so this
        # is unreachable in practice -- but that guarantee lives entirely
        # in a separate function's annotation, not in this branch's own
        # control flow. Making it explicit means a future change that
        # weakens `_deny_resource`'s NoReturn contract fails loudly here
        # instead of silently passing `None` into `scopes_for_token` below.
        assert token is not None

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

    Known gap (TECH-5903 Argus round-1 SUGGESTION, tracked as backlog
    before Phase B ships): this only hooks ``on_call_tool``. Resource
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


async def _authenticate_approval_caller(request: Request) -> tuple[str | None, int]:
    """Self-verify the bearer token for a non-MCP approval route
    (``mcp.custom_route`` runs outside MultiAuth). Returns
    ``(approver_sub, 200)`` on success, or ``(None, 401 | 403)`` on
    failure — 401 for a missing/malformed/unverifiable token, 403 for a
    token that verifies fine but fails the interactive-only gate (this is
    the load-bearing distinction: an agent-jwt token, even one carrying
    ``comms:admin``, must get 403, never 401, to prove the gate actually
    inspected and rejected it rather than merely failing to authenticate).

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
        await service.audit_denied_approval_requires_interactive(session, actor_sub=rejected_sub)
    return None, 403


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
