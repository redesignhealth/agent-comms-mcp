"""Scope registry and enforcement helpers for agent-comms-mcp tools.

Maps each fully-qualified, mount-prefixed tool name to the single agent-jwt
scope required to invoke it. The mapping is the source of truth — every new
tool MUST be added here in the same PR that introduces it, or it will be
unreachable by agent-jwt Bearer callers (fail-closed default in
``ScopeEnforcementMiddleware``).

Caller classification
---------------------
Interactive users (Okta OIDCProxy) bypass scope checks: their tokens carry
an ``iss`` claim that is NOT ``"agent-jwt"`` (the OIDCProxy issues
FastMCP-internal JWTs whose ``iss`` is the server's own URL). All
non-interactive callers must present an ``iss="agent-jwt"`` token and carry
the required scope in the token's ``scopes`` claim.
"""

from __future__ import annotations

# FastMCP's AccessToken (adds the `claims` field) rather than the base SDK
# AccessToken from `mcp.server.auth.provider`, which has no claims attribute.
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken

from identity import AGENT_JWT_ISSUER, validate_sub_shape
from observability import log_auth_rejected

# Fully-qualified tool names (post-mount prefix in FastMCP 3.x:
# ``<namespace>_<tool>`` with a single underscore separator).
#
# Scope format: ``<service>:<verb>`` (or ``<service>:<sub>:<verb>`` for
# finer-grained gates). Verbs:
#   :read   — pure reads / lookups / searches
#   :write  — mutates state (create, update, delete)
#   :run    — triggers a unit of work that may write derived data
#   :admin  — gates a specific privileged PARAMETER within an already-scoped
#             tool, not the tool call itself. Not listed in TOOL_SCOPES
#             below (that table gates whether a tool is reachable at all;
#             an in-handler check like this gates one input to a reachable
#             tool). Currently: ``comms:admin``, required by
#             ``providers.comms.register`` to accept ``is_shared=True`` on
#             first registration (see that tool's docstring and
#             ``service.register_agent``'s ``is_shared_authorized`` param),
#             and by ``providers.comms.set_agent_shared`` to correct an
#             existing agent's ``is_shared`` value after the fact (see
#             ``service.set_agent_shared``'s ``is_shared_authorized`` param).
TOOL_SCOPES: dict[str, str] = {
    # --- comms (provider: providers/comms.py, namespace="comms") ---
    "comms_whoami": "comms:read",
    # Reads
    "comms_list_agents": "comms:read",
    "comms_lookup_agent_by_email": "comms:read",
    "comms_list_conversations": "comms:read",
    "comms_get_conversation": "comms:read",
    "comms_inbox": "comms:read",
    # Writes (mutate board/agent/conversation state)
    "comms_register": "comms:write",
    "comms_set_agent_shared": "comms:write",
    "comms_start_conversation": "comms:write",
    "comms_post_message": "comms:write",
    "comms_accept": "comms:write",
    "comms_decline_invite": "comms:write",
    "comms_invite": "comms:write",
    "comms_leave": "comms:write",
}


# Resources gated for agent-jwt callers (interactive Okta users bypass, like
# tools). Maps resource URI to required scope. Fail-closed: an agent-jwt
# caller reading an unmapped resource is denied, mirroring the unmapped-tool
# behavior. Empty today — this service registers no resources yet.
RESOURCE_SCOPES: dict[str, str] = {}


def is_interactive_token(token: AccessToken | None) -> bool:
    """Return True if ``token`` was issued by the Okta OIDC path.

    Interactive (browser) users authenticate via FastMCP's OIDCProxy, which
    mints its own FastMCP-internal JWT whose ``iss`` claim is the server's
    own URL — never ``"agent-jwt"``. agent-jwt Bearer tokens always carry
    ``iss="agent-jwt"`` (enforced by the JWTVerifier in
    ``auth.build_auth_provider``).

    A missing token (None) is treated as NON-interactive so the middleware
    fails closed if FastMCP ever dispatches a tool call without an auth
    context. A missing/``None`` ``iss`` claim is treated the same way — an
    absent issuer must not fall through to the interactive (scope-bypass)
    branch by default; it should only rely on upstream verification as a
    second line of defense, not the sole one.
    """
    if token is None:
        return False
    issuer = token.claims.get("iss")
    if issuer is None:
        return False
    return bool(issuer != AGENT_JWT_ISSUER)


def required_scope_for(tool_name: str) -> str | None:
    """Return the scope required for ``tool_name``, or None if unmapped.

    Unmapped tools are rejected for agent-jwt callers by the enforcement
    middleware (fail-closed). Interactive callers bypass the lookup entirely
    via ``is_interactive_token``.
    """
    return TOOL_SCOPES.get(tool_name)


def required_scope_for_resource(uri: str) -> str | None:
    """Return the scope required to read resource ``uri``, or None if unmapped."""
    return RESOURCE_SCOPES.get(uri)


_REDACTED_CLIENT_ID = "invalid_sub"


def safe_client_id(token: AccessToken) -> str:
    """Return ``token.client_id``, redacted if the agent-jwt ``sub`` is
    shape-invalid.

    FastMCP's ``JWTVerifier`` pre-resolves ``AccessToken.client_id`` from
    ``azp`` → ``sub`` → ``"unknown"``. For agent-jwt tokens ``azp`` is never
    set, so ``client_id`` IS the raw ``sub`` — including the
    attacker-controlled payload of a forged token. Redacting shape-invalid
    subs keeps impersonation payloads out of the ``scope_denial`` metric
    stream.

    Side effect: ``log_auth_rejected`` is emitted on rejection. This is the
    single emission point for ``auth_rejected`` — it covers every denial
    path (``missing_scope``, ``tool_not_enrolled``, ``missing_token``),
    including the enrollment paths that never reach ``scopes_for_token``.
    Non-agent-jwt (Okta) tokens pass through unchanged: their ``client_id``
    is a registered app ID, not user input.
    """
    if token.claims.get("iss") == AGENT_JWT_ISSUER:
        if not token.claims.get("sub"):
            log_auth_rejected(reason="sub_missing", issuer=AGENT_JWT_ISSUER)
            return _REDACTED_CLIENT_ID
        try:
            validate_sub_shape(token.claims)
        except ToolError:
            log_auth_rejected(reason="sub_shape", issuer=AGENT_JWT_ISSUER)
            return _REDACTED_CLIENT_ID
    return token.client_id or "unknown"


def scopes_for_token(token: AccessToken) -> list[str]:
    """Return the agent-jwt scope list from a verified token's ``claims``.

    agent-jwt tokens carry their capability set in a ``scopes`` LIST claim
    (agent-jwt's format), NOT the OAuth-standard ``scope`` string. FastMCP's
    ``JWTVerifier`` only maps ``scope``/``scp`` onto ``AccessToken.scopes``,
    so ``.scopes`` is empty for agent-jwt tokens — the raw ``scopes`` claim
    must be read instead. (Reading ``token.scopes`` here would deny every
    agent-jwt call as ``missing_scope``.)

    Guards (fail closed with an empty list):
    - non-agent-jwt issuer → no agent-jwt scopes, even with a ``scopes`` claim
    - missing/empty ``sub`` → malformed mint or tampered payload
    - shape-invalid ``sub`` (email-shaped / whitespace) → impersonation
    - non-list ``scopes`` claim → never iterate a string into bogus scopes
    """
    if token.claims.get("iss") != AGENT_JWT_ISSUER:
        return []
    if not token.claims.get("sub"):
        return []
    try:
        validate_sub_shape(token.claims)
    except ToolError:
        return []
    raw = token.claims.get("scopes", [])
    return [str(s) for s in raw] if isinstance(raw, list) else []


__all__ = [
    "RESOURCE_SCOPES",
    "TOOL_SCOPES",
    "is_interactive_token",
    "required_scope_for",
    "required_scope_for_resource",
    "safe_client_id",
    "scopes_for_token",
]
