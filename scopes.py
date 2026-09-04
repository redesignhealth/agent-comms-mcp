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

import re

# FastMCP's AccessToken (adds the `claims` field) rather than the base SDK
# AccessToken from `mcp.server.auth.provider`, which has no claims attribute.
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken

from auth import AGENT_TOKEN_VERIFIER_CLAIM, DEFAULT_AGENT_TOKEN_VERIFIER
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
#             ``providers.comms.set_agent_shared`` to correct an
#             existing agent's ``is_shared`` value after the fact (see
#             ``service.set_agent_shared``'s ``is_shared_authorized`` param),
#             and by ``providers.comms.deregister_agent`` (TECH-5736) to
#             transition an agent to ``status="suspended"`` (see
#             ``service.deregister_agent``'s ``deregister_authorized`` param),
#             and by ``providers.comms.admin_register`` to perform an
#             on-behalf-of FIRST registration for a ``sub`` other than the
#             caller's own (see ``service.admin_register_agent``'s
#             ``admin_authorized`` param). As of TECH-6002 (2026-09-03),
#             ``comms:admin`` is no longer required by
#             ``providers.comms.register``'s ``is_shared=True``
#             self-registration path -- an agent may now self-declare its
#             OWN ``is_shared`` with only the baseline ``comms:write``
#             scope. The remaining ``comms:admin`` consumers are exactly
#             the three listed above: ``comms_set_agent_shared``,
#             ``comms_deregister_agent``, and ``comms_admin_register``.
TOOL_SCOPES: dict[str, str] = {
    # --- comms (provider: providers/comms.py, namespace="comms") ---
    "comms_whoami": "comms:read",
    # Reads
    "comms_list_agents": "comms:read",
    "comms_lookup_agent_by_email": "comms:read",
    "comms_list_conversations": "comms:read",
    "comms_get_conversation": "comms:read",
    "comms_inbox": "comms:read",
    "comms_get_hold_status": "comms:read",
    # Writes (mutate board/agent/conversation state)
    "comms_register": "comms:write",
    # Registered at comms:write deliberately -- the elevated `comms:admin`
    # requirement to correct `is_shared` is enforced by an in-handler
    # `comms:admin`-or-interactive-caller check (see the `:admin` verb note
    # above), not by this table. Do not assume TOOL_SCOPES alone gates this
    # tool's `is_shared` correction.
    "comms_set_agent_shared": "comms:write",
    # Registered at comms:write deliberately -- the actual authorization
    # (comms:admin OR an interactive/Okta caller) is enforced by an
    # in-handler check (see the `:admin` verb note above), not by this
    # table. If that in-handler check is ever removed, this entry alone
    # would silently grant every comms:write token deregistration power --
    # do not assume TOOL_SCOPES alone gates this tool.
    "comms_deregister_agent": "comms:write",
    # Registered at comms:write deliberately -- the actual authorization
    # (comms:admin OR an interactive/Okta caller) is enforced by an
    # in-handler check (see the `:admin` verb note above), not by this
    # table. If that in-handler check is ever removed, this entry alone
    # would silently grant every comms:write token on-behalf-of
    # registration power -- do not assume TOOL_SCOPES alone gates this
    # tool.
    "comms_admin_register": "comms:write",
    "comms_start_conversation": "comms:write",
    "comms_post_message": "comms:write",
    "comms_accept": "comms:write",
    "comms_decline_invite": "comms:write",
    "comms_invite": "comms:write",
    "comms_leave": "comms:write",
    # TECH-5887: symmetric across every current participant, same as
    # comms_leave -- no elevated scope, no owner-only gate. Unlike
    # comms_leave (which only ever narrows the CALLER's own access),
    # archiving is conversation-wide and irreversible (no unarchive tool),
    # and -- unlike comms_post_message/comms_start_conversation/
    # comms_invite -- has no rate limit. Threat model: a compromised
    # comms:write token active in N conversations could archive all N
    # without throttling; accepted for v1 because the blast radius is
    # "conversation becomes read-only" (no data loss, no content
    # disclosure), not comparable to comms_deregister_agent/
    # comms_set_agent_shared/comms_admin_register's elevated-scope class of
    # damage. Revisit if a rate limit consistent with the other mutating
    # tools' pattern is ever added.
    "comms_archive_conversation": "comms:write",
}


# Resources gated for agent-jwt callers (interactive Okta users bypass, like
# tools). Maps a resource's exact, post-mount URI to its required scope.
# Fail-closed: an agent-jwt caller reading an unmapped resource is denied,
# mirroring the unmapped-tool behavior. Templated URIs (containing a
# `{param}` segment) do NOT belong here — see RESOURCE_TEMPLATE_SCOPES below.
RESOURCE_SCOPES: dict[str, str] = {
    "comms://comms/agents": "comms:read",
}

# Templated resource URIs (one entry per `@comms_server.resource(...)`
# registered with a `{param}` segment), mapped to their required scope.
# Matched via the compiled regexes in _COMPILED_RESOURCE_TEMPLATES below —
# `RESOURCE_SCOPES.get(uri)` can never exact-match a concrete URI like
# `comms://comms/conversations/<uuid>` against a template key.
RESOURCE_TEMPLATE_SCOPES: dict[str, str] = {
    "comms://comms/conversations/{conversation_id}": "comms:read",
    "comms://comms/agents/{agent_id}/inbox": "comms:read",
}

# Matches one `{param}` placeholder segment in a template string, e.g.
# `{conversation_id}` — deliberately excludes `/` inside the braces so a
# malformed template can't accidentally span a path separator.
_TEMPLATE_PARAM_RE = re.compile(r"\{[^/{}]+\}")


def _compile_resource_template(template: str) -> re.Pattern[str]:
    """Compile a resource template string into a matching regex.

    One wildcard segment (``[^/]+``) per ``{param}`` placeholder — e.g.
    ``comms://comms/conversations/{conversation_id}`` matches any concrete
    ``comms://comms/conversations/<value>`` URI. Every other character is
    escaped literally. No dependency on FastMCP internals — this is a
    from-scratch regex built once at import time (RESOURCE_TEMPLATE_SCOPES
    is static), not per lookup.
    """
    pattern_parts: list[str] = []
    last_end = 0
    for match in _TEMPLATE_PARAM_RE.finditer(template):
        pattern_parts.append(re.escape(template[last_end : match.start()]))
        pattern_parts.append("[^/]+")
        last_end = match.end()
    pattern_parts.append(re.escape(template[last_end:]))
    return re.compile("^" + "".join(pattern_parts) + "$")


_COMPILED_RESOURCE_TEMPLATES: list[tuple[re.Pattern[str], str]] = [
    (_compile_resource_template(template), scope)
    for template, scope in RESOURCE_TEMPLATE_SCOPES.items()
]


def compile_uri_template(template: str) -> re.Pattern[str]:
    """Compile a resource template into a regex with one NAMED capture group
    per ``{param}`` placeholder (named after the placeholder itself).

    Sibling of ``_compile_resource_template`` above, which is deliberately
    non-capturing (it only needs a yes/no match for scope lookup). This
    variant is for callers that need the matched value(s) back out --
    e.g. ``providers.comms.authorize_resource_subscribe``, which used to
    hand-roll its own ``_CONVERSATION_SUBSCRIBE_URI_RE``/
    ``_INBOX_SUBSCRIBE_URI_RE`` regexes duplicating these same URI shapes
    (Argus round-2 SUGGESTION) -- deriving them from
    ``RESOURCE_TEMPLATE_SCOPES``'s own template strings via this function
    keeps the URI shape defined in exactly one place.
    """
    pattern_parts: list[str] = []
    last_end = 0
    for match in _TEMPLATE_PARAM_RE.finditer(template):
        name = template[match.start() + 1 : match.end() - 1]
        pattern_parts.append(re.escape(template[last_end : match.start()]))
        pattern_parts.append(f"(?P<{name}>[^/]+)")
        last_end = match.end()
    pattern_parts.append(re.escape(template[last_end:]))
    return re.compile("^" + "".join(pattern_parts) + "$")


def check_resource_scope(token: AccessToken | None, uri: str) -> bool:
    """Return True if ``token`` is authorized to read/subscribe to ``uri``.

    Shared by ``main.ScopeEnforcementMiddleware.on_read_resource`` and
    ``providers.comms.authorize_resource_subscribe`` (Argus round-2 BLOCKING
    catch: both independently re-implemented the identical interactive-
    bypass + ``required_scope_for_resource`` + ``scopes_for_token`` sequence
    before this was extracted).

    Returns ``False`` (never raises) for both "resource not enrolled"
    (``required_scope_for_resource`` returns ``None``) and "scope missing"
    -- callers that need to distinguish those two cases for logging/denial-
    reason purposes should call ``required_scope_for_resource`` themselves
    in addition to this; this function only answers the yes/no authorization
    question. A ``None`` token is treated as unauthorized (fail closed),
    matching ``is_interactive_token``'s own ``None`` handling.
    """
    if is_interactive_token(token):
        return True
    if token is None:
        return False
    required = required_scope_for_resource(uri)
    if required is None:
        return False
    return required in scopes_for_token(token)


# Not in TOOL_SCOPES: ``POST /proposals`` (TECH-5872) is a non-MCP
# ``mcp.custom_route`` in main.py, not a tool dispatched through
# ``ScopeEnforcementMiddleware`` -- that route self-checks this scope
# directly (see main.py's ``_authenticate_proposal_submitter``), the same
# way ``/approvals/*``'s routes self-check interactivity rather than going
# through this module's tool-dispatch machinery.
PROPOSAL_SUBMIT_SCOPE = "comms:proposals:write"


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


def is_registry_backed_agent_token(token: AccessToken | None) -> bool:
    """Return True if ``token``'s ``owner_sub``/``owner_email`` claims came
    from an operator-configured ``AGENT_TOKEN_VERIFIERS`` plugin OTHER than
    the built-in default (TECH-5593).

    The default verifier's ``owner_sub`` (``agent_jwt_hs256``, ``mint_token``'s
    CLI) is a caller-supplied, unverified claim -- ``service.register_agent``
    already refuses to trust it for anything beyond first registration (see
    that function's docstring). A consumer that configures a REPLACEMENT or
    ADDITIONAL verifier is asserting, by the act of configuring it, that its
    own verifier resolves ownership against a real source of truth (this
    repo has no way to confirm that -- it is an operator trust decision, the
    same one already implicit in choosing what goes in
    ``AGENT_TOKEN_VERIFIERS`` at all). This is the ONLY signal used to make
    that distinction: both the default and a consumer's own
    ``AGENT_TOKEN_VERIFIERS`` plugin normalize ``iss`` to the identical
    ``"agent-jwt"`` value BY DESIGN (the normalized-claims contract
    ``auth._NormalizingVerifier`` enforces on every configured verifier),
    so ``iss`` alone cannot be used to tell them apart -- hence stamping
    the verifier's own registry name/import-path onto the claims in
    ``auth._NormalizingVerifier`` instead.

    A missing token, one with no verifier-claim at all (i.e. not produced
    by ``_NormalizingVerifier`` -- shouldn't happen for anything that
    reaches a tool, but checked explicitly rather than assumed), or one
    whose ``iss`` isn't the agent-jwt issuer at all (an interactive/Okta
    token, which was never routed through ``_NormalizingVerifier`` in the
    first place and so could not legitimately carry this claim) all return
    False -- fail closed, since this result gates whether
    ``providers.comms`` writes a caller-supplied value into
    ``agents.owner_sub``/``owner_email``.
    """
    if token is None:
        return False
    if token.claims.get("iss") != AGENT_JWT_ISSUER:
        return False
    verifier_name = token.claims.get(AGENT_TOKEN_VERIFIER_CLAIM)
    return verifier_name is not None and verifier_name != DEFAULT_AGENT_TOKEN_VERIFIER


def required_scope_for(tool_name: str) -> str | None:
    """Return the scope required for ``tool_name``, or None if unmapped.

    Unmapped tools are rejected for agent-jwt callers by the enforcement
    middleware (fail-closed). Interactive callers bypass the lookup entirely
    via ``is_interactive_token``.
    """
    return TOOL_SCOPES.get(tool_name)


def required_scope_for_resource(uri: str) -> str | None:
    """Return the scope required to read resource ``uri``, or None if unmapped.

    Exact match against ``RESOURCE_SCOPES`` first (static resources), then a
    pattern match against the compiled ``RESOURCE_TEMPLATE_SCOPES`` regexes
    (templated resources) — see ``_compile_resource_template``. Unmatched
    (either table) returns ``None``, same fail-closed contract as
    ``required_scope_for``.
    """
    exact = RESOURCE_SCOPES.get(uri)
    if exact is not None:
        return exact
    for pattern, scope in _COMPILED_RESOURCE_TEMPLATES:
        if pattern.match(uri):
            return scope
    return None


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
    "PROPOSAL_SUBMIT_SCOPE",
    "RESOURCE_SCOPES",
    "RESOURCE_TEMPLATE_SCOPES",
    "TOOL_SCOPES",
    "check_resource_scope",
    "compile_uri_template",
    "is_interactive_token",
    "is_registry_backed_agent_token",
    "required_scope_for",
    "required_scope_for_resource",
    "safe_client_id",
    "scopes_for_token",
]
