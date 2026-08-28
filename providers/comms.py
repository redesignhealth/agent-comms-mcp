"""Comms provider — the MCP tool surface over ``service.py`` (DESIGN.md §7).

Every tool below follows the same shape:

1. Resolve the caller's identity via ``get_access_token()`` — never from
   tool arguments. ``try_resolve_email`` is the single source of truth for
   "who is calling" (agent-jwt: raw ``sub`` claim; Okta: email/sub) and is
   used here as the ``actor_sub``/``Agent.sub`` key uniformly, matching
   ``comms_whoami``'s existing identity resolution.
2. Resolve that identity to a board ``Agent`` row via
   ``service.get_agent_by_sub`` (every tool except ``comms_register``,
   which establishes that mapping in the first place). A caller with a
   valid token/scope who has never called ``comms_register`` gets a
   distinct, explicit error — this is about the caller's OWN registration
   state, not conversation access, so it is fine to be specific (unlike
   ``AccessDeniedError``, which must stay uniform).
3. Open one DB session (``db.get_session_factory``) and call exactly one
   ``service.py`` function.
4. Map the three service-layer exception shapes (``exceptions.py``) plus
   ``schemas.PayloadValidationError`` to ``fastmcp.exceptions.ToolError``.
   ``AccessDeniedError``'s message is passed through UNCHANGED (it is
   already the fixed, anti-enumeration-safe string) — never wrapped or
   annotated, which could otherwise leak which denial branch fired.
5. Return an AXI-shaped dict: compact fields, ``total_count``/``has_more``
   where relevant, explicit empty states (never a bare empty list/None).

Registration reminder (fail-closed ``TOOL_SCOPES``, see scopes.py): every
tool added here MUST be enrolled in ``scopes.TOOL_SCOPES`` under its
mounted name (``comms_<tool>``) in the same change, or agent-jwt callers can
never reach it.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from sqlalchemy.exc import InterfaceError, OperationalError

import plugins
import service
from db import get_session_factory
from exceptions import (
    AccessDeniedError,
    AgentRetiredError,
    InvalidConversationStateError,
    RateLimitExceededError,
    SchemaVersionMismatchError,
    UnknownConversationTypeError,
)
from identity import try_resolve_email
from models import CONVERSATION_STATES, PARTICIPANT_ROLES, Agent, ApprovalHold
from schemas import (
    CONVERSATION_TYPES,
    MAX_AGENT_KEY_LENGTH,
    MAX_PARTICIPANTS_PER_CONVERSATION,
    PayloadValidationError,
)
from scopes import is_interactive_token, is_registry_backed_agent_token, scopes_for_token

comms_server: FastMCP[Any] = FastMCP("comms")

# Plain stdlib logging, matching service.py's own module logger convention
# (see its docstring comment) -- this exists solely so a genuine
# connectivity/config failure swallowed by comms_whoami's best-effort
# schema-version lookup (see below) still lands somewhere instead of being
# silently discarded.
logger = logging.getLogger(__name__)


# --- Identity / session plumbing -------------------------------------------------


def _require_token() -> AccessToken:
    """Fetch the verified access token, or raise if dispatch happened anyway.

    Defense in depth, matching ``comms_whoami``: ``ScopeEnforcementMiddleware``
    should never dispatch an unauthenticated call, but a tool body must not
    silently proceed with a ``None`` token if it ever does.
    """
    token = get_access_token()
    if token is None:
        raise ToolError("no access token provided")
    return token


def _validate_agent_key(agent_key: str | None) -> str | None:
    """Validate agent_key if provided: reject :: delimiters and control characters.

    Returns the validated (stripped) agent_key, or None if not provided.
    Raises ToolError if validation fails.
    """
    if agent_key is None:
        return None

    agent_key = agent_key.strip()
    if not agent_key:
        raise ToolError("invalid_request: agent_key must be non-empty if provided")
    if len(agent_key) > MAX_AGENT_KEY_LENGTH:
        raise ToolError(f"invalid_request: agent_key exceeds {MAX_AGENT_KEY_LENGTH} characters")

    # Reject :: delimiter to prevent identity collisions
    if "::" in agent_key:
        raise ToolError("invalid_request: agent_key must not contain '::'")

    # Reject control characters (null, newline, tab, etc.)
    for i, char in enumerate(agent_key):
        if ord(char) < 32 or ord(char) == 127:  # ASCII control chars + DEL
            raise ToolError(
                f"invalid_request: agent_key contains invalid control character at position {i}"
            )

    # Strict allowlist: alphanumeric, dot, underscore, hyphen
    import re

    if not re.match(r"^[A-Za-z0-9._-]+$", agent_key):
        raise ToolError(
            "invalid_request: agent_key must contain only alphanumeric"
            " characters, dots, underscores, or hyphens"
        )

    return agent_key


def _compose_sub(base_sub: str, agent_key: str | None) -> str:
    """Compose the full sub by combining base_sub with optional agent_key.

    Guards against identity collisions by rejecting any base_sub or agent_key
    containing the '::' delimiter.
    """
    if "::" in base_sub:
        raise ToolError("invalid_request: base identity cannot contain '::' delimiter")
    if agent_key is None:
        return base_sub
    return f"{base_sub}::{agent_key}"


def _require_identity(token: AccessToken) -> str:
    """Resolve the caller's board identity (``Agent.sub``) from the token.

    Uses ``identity.try_resolve_email`` — the same resolver ``comms_whoami``
    reports as ``identity`` — so the string used as ``Agent.sub`` here is
    identical, per caller, to what every other tool (and the audit trail's
    ``actor_sub``) sees. ``try_resolve_email`` fails open with ``None`` on a
    malformed token (see its docstring); that must not silently become an
    empty-string identity here.
    """
    identity = try_resolve_email(token)
    if identity is None:
        raise ToolError("unable to resolve caller identity from token claims")
    return identity


async def _resolve_caller_agent(session: Any, sub: str, token: AccessToken | None = None) -> Agent:
    """Look up the caller's board ``Agent`` row, or raise a clear, specific error.

    Distinct from ``AccessDeniedError`` on purpose: "you have a valid
    token/scope but never called comms_register" is a fact about the
    caller's own state, not an enumeration risk about someone else's
    conversation, so DESIGN.md's uniform-denial rule does not apply here.

    ``token``, when given, feeds TECH-5593's ownership write-through: every
    tool call that resolves the caller's OWN agent row is an opportunity to
    refresh ``agents.owner_sub``/``owner_email`` from the request's verified
    claims, bounding that cache's staleness to the configured agent-token
    verifier's own TTL instead of leaving it frozen at registration time
    forever. Gated on ``scopes.is_registry_backed_agent_token`` -- the
    built-in default verifier's owner claims are caller-supplied and
    unverified (same reasoning as ``service.register_agent``'s freeze), so
    only a plugin-verified token's claims are trusted here. ``None`` (the
    default) skips write-through entirely -- callers that don't have a
    token handy, or that intentionally don't want this side effect, are
    unaffected.
    """
    agent = await service.get_agent_by_sub(session, sub)
    if agent is None:
        raise ToolError(
            "not_registered: no board agent is bound to this caller yet — call comms_register first"
        )
    if token is not None and is_registry_backed_agent_token(token):
        await service.write_through_ownership(
            session,
            agent,
            owner_sub=_string_claim(token, "owner_sub"),
            owner_email=_string_claim(token, "owner_email"),
        )
    return agent


def _string_claim(token: AccessToken, key: str) -> str | None:
    """Return ``token.claims[key]`` if present AND a ``str``, else ``None``.

    A registry-backed verifier is trusted for ownership write-through
    (``is_registry_backed_agent_token``), but that trust doesn't extend to
    the CLAIM'S SHAPE being well-formed -- a malformed or misconfigured
    plugin could still hand back a non-string ``owner_sub``/``owner_email``
    (an int, a dict, a list, ...). Un-coerced, ``str(...)`` on a non-string
    value would silently write that value's Python ``repr`` into
    ``agents.owner_sub``/``owner_email`` with no error surfaced anywhere
    (Argus round-1 BLOCKING catch) -- logging and treating it as absent
    instead means a malformed claim leaves the cached row untouched (the
    same no-op ``write_through_ownership`` already gives a genuinely
    absent claim), not a garbage write.
    """
    value = token.claims.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        logger.warning(
            "ignoring non-string %r claim on a registry-backed token (got %s)",
            key,
            type(value).__name__,
        )
        return None
    return value


@asynccontextmanager
async def _map_service_errors() -> AsyncIterator[None]:
    """Translate the service layer's exception shapes into ``ToolError``.

    ``AccessDeniedError``'s message is the fixed, uniform, anti-enumeration
    string (exceptions.py) and is passed through verbatim — no prefix, no
    detail, nothing that could distinguish denial causes to the caller.
    The next shapes are already client-safe/specific by design
    (state-machine violations, rate limits, payload validation, and
    unknown-conversation-type are not enumeration risks — see
    exceptions.py's module docstring), so their messages pass through
    unwrapped too. ``UnknownConversationTypeError`` in particular lists
    ``CONVERSATION_TYPES`` in its message on purpose: that's this
    service's own fixed, public capability list, not per-caller secret
    state, so naming it is not the kind of enumeration DESIGN.md's
    anti-enumeration rule is about. ``SchemaVersionMismatchError``
    is the same story for the wire-schema capability range
    negotiated at ``comms_start_conversation`` -- see exceptions.py.
    ``AgentRetiredError`` (TECH-5703) is deliberately specific rather than
    folded into ``AccessDeniedError`` -- see its own docstring.

    A bare ``ValueError`` is different: the service layer raises it for
    internal parameter-shape problems (e.g. an empty ``display_name`` or
    an over-length field) and its message text can embed internal
    schema/config detail that IS not client-safe in the general case.
    Those are mapped to a single generic, non-leaking message instead of
    being forwarded verbatim. A bare ``RuntimeError`` gets the same generic
    treatment — it signals an internal invariant violation, not anything
    the caller did wrong, and its message can embed internal state detail.
    """
    try:
        yield
    except AccessDeniedError as exc:
        raise ToolError(str(exc)) from None
    except (
        InvalidConversationStateError,
        RateLimitExceededError,
        PayloadValidationError,
        UnknownConversationTypeError,
        SchemaVersionMismatchError,
        AgentRetiredError,
    ) as exc:
        raise ToolError(str(exc)) from None
    except (ValueError, RuntimeError):
        raise ToolError("invalid_request: the request could not be processed") from None


# --- Parsing helpers --------------------------------------------------------------


def _parse_uuid(field: str, value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ToolError(f"invalid_request: {field} is not a valid UUID: {value!r}") from exc


def _parse_uuids(field: str, values: Iterable[str]) -> list[uuid.UUID]:
    return [_parse_uuid(field, v) for v in values]


def _parse_expires_at(value: str | None) -> datetime | None:
    """Parse an optional ISO 8601 ``expires_at`` override, rejecting naive datetimes."""
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolError(
            f"invalid_request: expires_at is not a valid ISO 8601 datetime: {value!r}"
        ) from exc
    if dt.tzinfo is None:
        raise ToolError("invalid_request: expires_at must be timezone-aware (include a UTC offset)")
    return dt


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


# --- Identity tool (existing) ------------------------------------------------------


@comms_server.tool
async def whoami(agent_key: str | None = None) -> dict[str, Any]:
    """Return the authenticated caller's identity, issuer, caller type, and scopes.

    Diagnostic tool: use it to verify that auth (Okta OIDC for humans,
    agent-jwt Bearer JWT for agents) and scope enforcement are wired
    correctly. ``scopes`` is the agent-jwt ``scopes`` claim for service
    callers; empty for interactive Okta callers (who bypass scope checks).

    When ``agent_key`` is provided, returns the composed identity
    (base_sub::agent_key) that will be used for agent lookups by other tools.

    If this identity has already called ``comms_register``, the response
    also includes ``min_schema_version``/``max_schema_version``
    reflecting this agent's currently-registered wire-schema capability
    range. Omitted entirely if the caller hasn't registered yet, or if the
    board database is unreachable — this tool doubles as an auth-only
    diagnostic (verifying token/scope wiring) and must not start requiring
    DB access to answer the identity/scopes questions it already answers.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    composed_sub = _compose_sub(base_sub, agent_key)
    interactive = is_interactive_token(token)
    result: dict[str, Any] = {
        "identity": composed_sub,
        "issuer": token.claims.get("iss"),
        "caller_type": "interactive" if interactive else "service",
        "scopes": scopes_for_token(token),
    }
    # Diagnostic tool, DB-optional (see docstring) — genuine connectivity/
    # configuration failures just omit the schema-version fields, same as
    # the already-handled "not registered yet" case (agent is None, below).
    # Deliberately narrow and split into two distinct try blocks (Argus
    # round 2) rather than one broad catch spanning both the session-
    # factory construction and the query: `RuntimeError` is ONLY expected
    # from `get_session_factory()` itself (`db.require_env` raises it for
    # a missing `DATABASE_URL`) -- a `RuntimeError` surfacing from inside
    # the query/lookup instead would be a genuine, unrelated programming
    # bug that this except clause must not also swallow. Logged at
    # WARNING, not silently dropped, so a genuine outage is still visible
    # in the tool's own logs even though the caller sees a clean response.
    try:
        session_factory = get_session_factory()
    except RuntimeError as exc:
        logger.warning(
            "whoami: schema-version lookup unavailable (%s), omitting fields",
            type(exc).__name__,
            exc_info=True,
        )
        return result
    try:
        async with session_factory() as session:
            agent = await service.get_agent_by_sub(session, composed_sub)
        if agent is not None:
            result["min_schema_version"] = agent.min_schema_version
            result["max_schema_version"] = agent.max_schema_version
    except (OperationalError, InterfaceError, OSError) as exc:
        # A genuine programming/schema bug (a renamed get_agent_by_sub, a
        # migration not yet applied) raises something OTHER than these
        # connection-level types and is deliberately left to propagate,
        # rather than being indistinguishable from an ordinary unregistered
        # caller / DB outage.
        logger.warning(
            "whoami: schema-version lookup failed (%s), omitting fields",
            type(exc).__name__,
            exc_info=True,
        )
    return result


# --- Board admission ---------------------------------------------------------------


@comms_server.tool
async def register(
    display_name: str,
    accepted_types: list[str],
    min_schema_version: int = 1,
    max_schema_version: int = 1,
    agent_key: str | None = None,
    is_shared: bool = False,
) -> dict[str, Any]:
    """Self-register or update this agent's board identity.

    Idempotent: re-calling with the same identity rebinds ``display_name``
    and ``accepted_types`` in place. Safe to call on startup every time.

    Parameters:

    - ``display_name``: human-readable label, max 255 chars.
    - ``accepted_types``: message types this agent will handle. Must be a
      subset of the 12 known types (see ``schemas.MessageType``):
      ``availability_request``, ``availability_response``,
      ``counter_proposal``, ``confirm``, ``decline``,
      ``needs_clarification``, ``note``, ``task_assign``, ``task_report``,
      ``task_complete``, ``task_decline``, ``task_cancel``.
      Each entry capped at 100 chars; list capped at 20 entries.
    - ``min_schema_version``/``max_schema_version``: the range
      of wire-schema versions this agent's own code can correctly
      interpret. Both default to ``1`` — the only version that exists
      today, so most callers can omit these entirely. When
      ``comms_start_conversation`` opens a new conversation, the board
      negotiates the highest version every participant (initiator + all
      named targets) mutually supports and refuses to open the
      conversation at all if no such version exists — so declaring a
      narrower range than your code actually handles gates you OUT of
      conversations the board would otherwise negotiate you into, and
      declaring a wider range than your code actually handles risks being
      pinned to a version you can't correctly parse. Must satisfy
      ``min_schema_version <= max_schema_version``.
    - ``agent_key``: stopgap for running multiple agents under
      one token. Appended to the token's verified sub
      (``"{base_sub}::{agent_key}"``) to produce a distinct board row.
      Omit if only one agent shares this token. A different ``agent_key``
      registers a separate row; the same ``agent_key`` rebinds the
      existing one.

      The ``email`` claim fallback is gated on ``is_interactive_token``
      (``scopes.py``). For a token with no ``iss`` at all, that check and
      ``identity``'s internal ``_is_agent_jwt_token`` both land on "don't
      trust the ``email`` claim" — but via different mechanisms, not a
      shared rule: ``is_interactive_token`` treats missing/``None`` ``iss``
      as simply "not confirmed interactive" (an unknown/deny outcome — it
      only decides whether to bypass scope checks, making no claim about
      identity), whereas ``_is_agent_jwt_token`` affirmatively treats
      missing/``None`` ``iss`` as agent-jwt-like (an assume-agent-jwt outcome —
      it feeds identity resolution, so it conservatively pins the caller's
      identity to ``sub`` and never trusts ``email``/``preferred_username``).
      Do not "harmonize" these two checks into one shared helper on the
      assumption that they encode the same rule — an agent-jwt (agent)
      token's claims are caller-supplied and unverified from this server's
      point of view (``mint_token``'s CLI, console script
      ``agent-comms-mcp-mint-token``, only ever sets ``owner_sub``
      deliberately via its ``--owner-email``/``--self-owned`` choice, and
      never touches ``email``, but a hand-crafted token bypassing that CLI
      could still carry one), so ``email`` must never be trusted as an
      ``owner_email`` fallback for those tokens, regardless of which check
      is used to detect them.
    - ``is_shared``: set ``True`` if this agent spans ownership boundaries
      (e.g. a shared bot that serves multiple users). Frozen at first
      registration — re-registering with a different value has no effect.
      A shared agent is admitted into ``asymmetric`` conversations without
      the usual pairwise ownership-overlap check, and its senders may post
      non-``boundary_safe`` messages there without an ownership-boundary
      check; neither bypass applies to ``internal`` conversations. Setting
      ``is_shared=True`` on FIRST registration requires the caller's token
      to carry the ``comms:admin`` scope (or be an interactive/Okta caller)
      — it is an admission-decision input, so self-declaring it with only
      the baseline ``comms:write`` scope would be a privilege escalation;
      a caller without that scope gets the standard anti-enumeration
      ``access_denied`` error (the specific reason,
      ``denied.is_shared_requires_elevated_scope``, is recorded only in the
      audit log — never returned to the caller).

    Calling again with the same caller identity AND the same ``agent_key``
    (both absent counts as the same) re-binds ``display_name``/
    ``accepted_types`` in place (see ``service.register_agent``); a
    different ``agent_key`` registers a distinct row instead.

    ``accepted_types`` is enforced, not just declarative (DESIGN.md §9's
    capability gate): a message type omitted here causes any message of
    that type directed at THIS agent to be denied for the SENDER, not for
    you — you get no direct feedback when this happens, since the failure
    surfaces on someone else's call, not yours. Declare every message type
    your implementation actually handles, not just enough to pass whatever
    you're testing right now.

    Identity (``owner_sub``, ``owner_email``) derives from verified token
    claims only — never accepted as parameters.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    owner_sub = str(token.claims.get("owner_sub") or base_sub)
    upstream_email = token.claims.get("email") if is_interactive_token(token) else None
    owner_email = str(token.claims.get("owner_email") or upstream_email or base_sub)

    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)

    # Shared with service.register_agent's own guard
    # (service.validate_schema_version_range) so tightening the rule in one
    # place tightens it in both layers -- this tool-layer
    # call exists only to surface a specific ToolError instead of the
    # generic bare-ValueError mapping _map_service_errors would otherwise
    # give it.
    try:
        service.validate_schema_version_range(min_schema_version, max_schema_version)
    except ValueError as exc:
        raise ToolError(f"invalid_request: {exc}") from None

    # `is_shared=True` is an admission-decision input (DESIGN.md §9): it
    # lets its holder bypass the pairwise ownership check for `asymmetric`
    # conversations. Interactive (Okta) callers already bypass scope checks
    # entirely elsewhere in this module, so they're trusted here too;
    # non-interactive callers need the elevated `comms:admin` scope.
    # `register_agent` enforces this only on first registration (a no-op
    # for the frozen re-registration path either way).
    is_shared_authorized = is_interactive_token(token) or "comms:admin" in scopes_for_token(token)

    async with get_session_factory()() as session, _map_service_errors():
        agent = await service.register_agent(
            session,
            sub=sub,
            owner_sub=owner_sub,
            owner_email=owner_email,
            display_name=display_name,
            accepted_types=accepted_types,
            min_schema_version=min_schema_version,
            max_schema_version=max_schema_version,
            is_shared=is_shared,
            is_shared_authorized=is_shared_authorized,
        )

    return {
        "agent_id": str(agent.id),
        "sub": agent.sub,
        "display_name": agent.display_name,
        "accepted_types": list(agent.accepted_types),
        "status": agent.status,
        "owner_email": agent.owner_email,
        "is_shared": agent.is_shared,
        "min_schema_version": agent.min_schema_version,
        "max_schema_version": agent.max_schema_version,
    }


@comms_server.tool
async def set_agent_shared(agent_id: str, is_shared: bool) -> dict[str, Any]:
    """Admin override of an existing agent's ``is_shared`` value.

    ``comms_register`` freezes ``is_shared`` at first registration on
    purpose (DESIGN.md §5/§9): it is an admission-decision input, so letting
    an agent silently escalate its own boundary-crossing privileges via
    re-registration would defeat the freeze. This tool is the one
    supported way to correct the value afterwards — for example, an agent
    self-registered with ``is_shared=False`` but is actually a shared
    bot spanning multiple owners, or the reverse.

    Requires the caller's token to carry the ``comms:admin`` scope (or be
    an interactive/Okta caller) — same gate as first-registration
    ``is_shared=True``. A caller without it gets the standard
    anti-enumeration ``access_denied`` error (the specific reason,
    ``denied.set_shared_requires_elevated_scope``, is recorded only in the
    audit log).

    - ``agent_id``: UUID string from ``comms_list_agents``.
    - ``is_shared``: the corrected value.
    """
    token = _require_token()
    actor_sub = _require_identity(token)
    is_shared_authorized = is_interactive_token(token) or "comms:admin" in scopes_for_token(token)
    target_id = _parse_uuid("agent_id", agent_id)

    async with get_session_factory()() as session, _map_service_errors():
        agent = await service.set_agent_shared(
            session,
            actor_sub=actor_sub,
            agent_id=target_id,
            is_shared=is_shared,
            is_shared_authorized=is_shared_authorized,
        )

    return {
        "agent_id": str(agent.id),
        "sub": agent.sub,
        "display_name": agent.display_name,
        "is_shared": agent.is_shared,
    }


@comms_server.tool
async def list_agents(limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
    """List the board directory (paginated, keyset on ``sub``).

    Internal domain — enumeration is acceptable per DESIGN.md §10. Pass the
    returned ``next_cursor`` back as ``cursor`` to page forward.

    TECH-5703: a registry-retired agent is dropped from ``agents`` (its row
    still exists -- retirement never deletes conversation history -- it's
    just excluded from this listing). ``total_count`` still reflects every
    board-registered agent regardless of retirement status. Retirement is
    filtered AFTER pagination is computed from the raw rows, so a page can
    return fewer than ``limit`` agents (including zero) while ``has_more``
    is still ``true`` -- page until ``has_more`` is ``false``, not until
    ``agents`` is empty. See ``plugins.ActiveChecker``.
    """
    _require_token()
    async with get_session_factory()() as session:
        return await service.list_agents(
            session,
            limit=limit,
            cursor=cursor,
            active_checker=plugins.get_active_checker(),
        )


@comms_server.tool
async def lookup_agent_by_email(owner_email: str) -> dict[str, Any]:
    """Directory lookup: is ``owner_email`` bound to a board-active agent?

    Returns ``{"agent": {...same per-agent shape as comms_list_agents'
    "agents" entries...}, "found": True}`` on a match, or
    ``{"agent": None, "found": False}`` otherwise -- an explicit empty
    state, never a bare ``None`` (this module's own contract, rule 5).
    Case-insensitive; never raises on a malformed, empty, or over-length
    (see ``service.MAX_LOOKUP_EMAIL_LENGTH``) ``owner_email`` -- resolves
    to the not-found shape instead (see ``service.lookup_agent_by_email``).

    Same internal-domain trust posture as ``comms_list_agents`` (DESIGN.md
    §10) -- pure directory read, no ``agent_key`` needed.

    A match means an agent *claims* to be represented by ``owner_email``,
    not that ownership of that email has been verified -- ``owner_email``
    is a caller-supplied, unverified registration claim (see
    ``service.lookup_agent_by_email``). Treat this as "who currently
    claims this email", not "who is proven to own it".

    TECH-5703: a registry-retired agent resolves to the same not-found
    shape as an unregistered email -- see ``service.lookup_agent_by_email``.
    """
    _require_token()
    async with get_session_factory()() as session:
        agent = await service.lookup_agent_by_email(
            session, owner_email=owner_email, active_checker=plugins.get_active_checker()
        )
    return {"agent": agent, "found": agent is not None}


# --- Conversation lifecycle ---------------------------------------------------------


@comms_server.tool
async def start_conversation(
    conversation_type: str,
    target_agent_ids: list[str],
    initial_message: dict[str, Any],
    message_type: str = "availability_request",
    expires_at: str | None = None,
    schema_version: Literal[1] = 1,
    agent_key: str | None = None,
) -> dict[str, Any]:
    """Open a conversation with N other agents, posting the seq-1 message.

    Parameters:

    - ``conversation_type``: one of ``internal``, ``asymmetric``, ``open``.
    - ``target_agent_ids``: UUID strings from ``comms_list_agents``; max 50.
      Caller becomes ``owner``; each target starts as ``invited`` (invisible
      until they call ``comms_accept``). A target whose registry reports it
      retired (TECH-5703) raises a specific "agent retired" error instead
      of the uniform unknown-agent denial. If the retirement check itself
      fails (e.g. registry timeout), the board fails open -- the target is
      treated as active, so a registry outage never blocks conversation
      admission, only temporarily suspends retirement enforcement.
    - ``message_type``: type of the opening message. Default:
      ``availability_request``. All valid types: ``availability_request``,
      ``availability_response``, ``counter_proposal``, ``confirm``,
      ``decline``, ``needs_clarification``, ``note``, ``task_assign``,
      ``task_report``, ``task_complete``, ``task_decline``, ``task_cancel``.
      See ``comms_post_message`` for payload shapes per type.
    - ``initial_message``: payload dict for the opening message. Must match
      the schema for ``message_type`` (see ``comms_post_message``).
    - ``expires_at``: timezone-aware ISO 8601 datetime; omit for the
      per-``conversation_type`` default TTL (7/14/30 days). Capped at 90
      days from now (``MAX_CONVERSATION_TTL``) -- a later value is
      rejected. A PAST value is accepted (the conversation is immediately
      expired).
    - ``schema_version``: ADVISORY ONLY (capability negotiation).
      The board computes the actual wire version to use as the highest
      version every participant (you + every named target) mutually
      supports, per each agent's ``comms_register``-time
      ``min_schema_version``/``max_schema_version``, clamped to the
      highest version this board itself implements — and uses THAT value
      for the opening message regardless of what you pass here (returned
      as ``schema_version`` in the response, so the negotiated pin is
      discoverable). If no version is inside every participant's
      supported range, the call is refused entirely (no
      conversation/message is created). ``comms_invite`` re-checks any
      later-added participant against this same pinned version.

    If the opening ``message_type``/``initial_message`` would cross an
    ownership boundary (e.g. a ``note`` under ``open``), the conversation is
    still created — with a service-synthesized ``conversation_opened``
    marker as its seq-1 message — and your actual content is held for
    human approval instead of denied. The response then additionally has
    ``held_for_approval: true``, ``hold_id``, ``hold_status``,
    ``risk_reason``, ``hold_expires_at``, ``hold_created_at``; poll
    ``comms_get_hold_status`` with ``hold_id`` for the outcome. Once
    approved, your content posts as seq 2 under its original type.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    if len(target_agent_ids) > MAX_PARTICIPANTS_PER_CONVERSATION:
        raise ToolError(
            "invalid_request: target_agent_ids exceeds the participant cap "
            f"({MAX_PARTICIPANTS_PER_CONVERSATION})"
        )
    target_uuids = _parse_uuids("target_agent_ids", target_agent_ids)
    expires_dt = _parse_expires_at(expires_at)
    # Proactive tool-layer check, same pattern as the participant cap above
    # (Argus round-1 BLOCKING catch): without this, a too-far-future
    # expires_at fell through to service.start_conversation's ValueError,
    # which _map_service_errors collapses into the generic
    # "invalid_request: the request could not be processed" -- no
    # indication a ceiling exists at all, let alone which field caused it.
    # The service layer keeps its own check too (defense-in-depth for
    # direct, non-MCP callers), so this duplicates the comparison but not
    # the source of truth: service.MAX_CONVERSATION_TTL is read here, not
    # redeclared.
    if expires_dt is not None and expires_dt - datetime.now(UTC) > service.MAX_CONVERSATION_TTL:
        raise ToolError(
            "invalid_request: expires_at may not be more than "
            f"{service.MAX_CONVERSATION_TTL} from now"
        )

    owner_sub_claim = token.claims.get("owner_sub")

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            conversation = await service.start_conversation(
                session,
                actor_sub=sub,
                initiator_agent_id=caller.id,
                conversation_type=conversation_type,
                target_agent_ids=target_uuids,
                initial_message=initial_message,
                ownership_client=service.get_ownership_client_factory()(session),
                risk_scorer=plugins.get_risk_scorer(),
                auto_approver=plugins.get_auto_approver(),
                notifier=plugins.get_approval_notifier(),
                active_checker=plugins.get_active_checker(),
                message_type=message_type,
                expires_at=expires_dt,
                schema_version=schema_version,
                owner_sub_claim=owner_sub_claim,
            )

    result: dict[str, Any] = {
        "conversation_id": str(conversation.id),
        "type": conversation.type,
        "state": conversation.state,
        "created_by": str(conversation.created_by),
        "target_agent_ids": [str(t) for t in target_uuids],
        "expires_at": _iso(conversation.expires_at),
        "created_at": _iso(conversation.created_at),
        # The actually-negotiated version (see
        # service.start_conversation's transient
        # `conversation.negotiated_schema_version` attribute), NOT
        # necessarily the caller-supplied `schema_version` above.
        "schema_version": conversation.negotiated_schema_version,  # type: ignore[attr-defined]
    }
    # Diverted opener (TECH-5389 PR2 §6): the conversation was created with
    # a `conversation_opened` seq-1 marker in the initiator's place, and the
    # actual opening content is held for approval -- see
    # `service.start_conversation`'s transient `conversation.pending_hold`
    # attribute (mirrors `negotiated_schema_version`'s own convention).
    pending_hold = conversation.pending_hold  # type: ignore[attr-defined]
    if pending_hold is not None:
        result["held_for_approval"] = True
        result["hold_id"] = str(pending_hold.id)
        # Prefixed (unlike post_message's/comms_get_hold_status's bare
        # `status`/`expires_at`/`created_at`) because this response already
        # has unprefixed top-level fields of those exact names for the
        # CONVERSATION (see above) -- the hold's own values would silently
        # collide and overwrite them otherwise.
        result["hold_status"] = pending_hold.status
        result["risk_reason"] = pending_hold.risk_reason
        result["hold_expires_at"] = _iso(pending_hold.expires_at)
        result["hold_created_at"] = _iso(pending_hold.created_at)
    return result


@comms_server.tool
async def post_message(
    conversation_id: str,
    message_type: str,
    payload: dict[str, Any],
    schema_version: Literal[1] = 1,
    agent_key: str | None = None,
) -> dict[str, Any]:
    """Post a typed, schema-validated message to an active conversation.

    Caller must be an ``active`` participant (uniform denial otherwise).

    ``message_type`` and required ``payload`` fields:

    - ``availability_request``: ``window`` (``{start, end}`` aware ISO 8601),
      ``duration_min`` (int 5-480), ``modality`` (video/phone/in_person),
      ``priority`` (low/normal/high); optional ``constraints`` list (up to 10,
      values: mornings_only/afternoons_only/avoid_fridays/buffer_15min).
    - ``availability_response``: either ``slots`` (list of
      ``{start, end, preference 0..1}``, max 10) OR ``none_available=True``
      + ``reason`` (no_overlap/window_too_narrow/owner_unavailable).
    - ``counter_proposal``: ``slots`` (1-10 slot dicts, same shape as above).
    - ``confirm``: ``slot`` (``{start, end}`` aware ISO 8601). Marks
      conversation complete.
    - ``decline``: ``reason`` (owner_declined/no_availability/expired/other).
      May cancel the conversation if all members have declined.
    - ``needs_clarification``: ``about_seq`` (int ≥ 1, references a prior
      message seq).
    - ``note``: ``text`` (str 1-4000 chars). Boundary-sensitive: posts
      immediately in ``internal`` conversations, or in ``asymmetric``
      conversations where it doesn't cross an ownership boundary for the
      sender. Where it WOULD cross a boundary (including always under
      ``open``), it is held for human approval instead of denied — the
      response has ``held_for_approval: true`` (no ``seq``); poll
      ``comms_get_hold_status`` with the returned ``hold_id``.
    - ``task_assign``: ``action`` enum:
      gather_availability/schedule_meeting/reschedule_meeting/cancel_meeting/
      confirm_slot/report_status. ``gather_availability``,
      ``schedule_meeting``, ``reschedule_meeting`` require ``window`` +
      ``duration_min``; ``confirm_slot`` requires ``window``. Optional:
      ``counterparty_agent_ids``, ``related_conversation_id``, ``modality``,
      ``priority``, ``due_at``, ``constraints``.
    - ``task_report``: ``status`` (in_progress/blocked); optional
      ``about_seq`` (int ≥ 1).
    - ``task_complete``: optional ``about_seq`` (int ≥ 1).
    - ``task_decline``: ``reason``
      (no_longer_needed/unable_to_complete/expired/other).
    - ``task_cancel``: ``reason``
      (no_longer_needed/unable_to_complete/expired/other).

    ``schema_version``: only ``1`` exists today.

    Two response shapes (check ``held_for_approval`` — this is a distinct
    shape, not an error):

    - Not high-risk (the common case): posted-message shape, unchanged --
      ``conversation_id``, ``seq``, ``type``, ``schema_version``,
      ``payload``, ``created_at``. If a (test-injected or future)
      auto-approver cleared a high-risk post inline, this same shape gains
      ``auto_approved: true`` and ``hold_id``.
    - High-risk, escalated (v1's default outcome for a crossing ``note``):
      ``{"held_for_approval": true, "hold_id", "conversation_id",
      "status", "risk_reason", "expires_at", "created_at"}`` — no ``seq``,
      keep ``hold_id`` and poll ``comms_get_hold_status``.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    conv_id = _parse_uuid("conversation_id", conversation_id)

    owner_sub_claim = token.claims.get("owner_sub")

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            result = await service.post_message(
                session,
                actor_sub=sub,
                sender_agent_id=caller.id,
                conversation_id=conv_id,
                message_type=message_type,
                payload=payload,
                ownership_client=service.get_ownership_client_factory()(session),
                risk_scorer=plugins.get_risk_scorer(),
                auto_approver=plugins.get_auto_approver(),
                notifier=plugins.get_approval_notifier(),
                schema_version=schema_version,
                owner_sub_claim=owner_sub_claim,
            )

    if isinstance(result, ApprovalHold):
        return {
            "held_for_approval": True,
            "hold_id": str(result.id),
            "conversation_id": conversation_id,
            "status": result.status,
            "risk_reason": result.risk_reason,
            "expires_at": _iso(result.expires_at),
            "created_at": _iso(result.created_at),
        }
    message = result
    response: dict[str, Any] = {
        "conversation_id": conversation_id,
        "seq": message.seq,
        "type": message.type,
        "schema_version": message.schema_version,
        "payload": message.payload,
        "created_at": _iso(message.created_at),
    }
    auto_approved_hold_id = getattr(message, "auto_approved_hold_id", None)
    if auto_approved_hold_id is not None:
        response["auto_approved"] = True
        response["hold_id"] = str(auto_approved_hold_id)
    return response


@comms_server.tool
async def get_hold_status(hold_id: str, agent_key: str | None = None) -> dict[str, Any]:
    """Poll the status of a message OR invite held for human approval.

    Sender-only: the caller's resolved agent must equal the hold's own
    sender (for an invite hold — TECH-5735 — this is the INVITER, not the
    agent being invited). An unknown ``hold_id`` and someone else's hold
    both raise the identical uniform ``access_denied`` error (the audit
    trail alone distinguishes the two causes).

    Returns ``{hold_id, conversation_id, kind, status, risk_reason,
    created_at, expires_at}`` (``kind`` is ``"message"`` or ``"invite"``)
    plus, once decided: ``decided_at``/``decision_reason`` (the human's
    optional free-text why — present on either approval or rejection) and,
    once resolved (``approved``/``auto_approved``): for a ``message`` hold,
    ``message_id``/``message_seq`` so you can correlate with
    ``comms_get_conversation``; for an ``invite`` hold,
    ``target_agent_id``/``participant_status``. ``status`` is one of
    ``pending_auto``, ``pending_human``, ``auto_approved``, ``approved``,
    ``rejected``, ``expired``. There is no push notification for a
    decision — poll this tool with the ``hold_id`` from a held
    ``comms_post_message``/``comms_start_conversation``/``comms_invite``
    response.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    hold_uuid = _parse_uuid("hold_id", hold_id)

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            return await service.get_hold_status(
                session,
                actor_sub=sub,
                caller_agent_id=caller.id,
                hold_id=hold_uuid,
            )


@comms_server.tool
async def get_conversation(
    conversation_id: str, since_seq: int = 0, agent_key: str | None = None
) -> dict[str, Any]:
    """Combined read: conversation + participants + messages since ``since_seq``.

    Returns ``conversation``, ``participants``, ``messages``, ``invited``,
    ``has_more``, and either ``invited_by`` (only for an ``invited``
    caller) or ``messages_returned``, ``page_max_seq``, ``last_read_seq``
    (only for a non-``invited`` caller).

    An ``invited`` (not yet accepted) caller gets metadata only — no
    message content, ``since_seq`` is ignored, and ``has_more`` is always
    ``False``. An ``active`` caller gets up to 500 messages
    (``MAX_MESSAGES_PER_GET_CONVERSATION``) from ``since_seq`` onward, and
    their read cursor advances. ``since_seq`` must be non-negative — a
    negative value would silently widen the result window in an
    unintended way.

    **Pagination**: when ``has_more`` is ``True``, re-call with
    ``since_seq=page_max_seq`` from THIS response — NOT
    ``since_seq=last_read_seq``. ``last_read_seq`` is your persisted read
    cursor across all calls, which can already be ahead of a page you're
    re-reading (e.g. you deliberately pass a low ``since_seq`` to revisit
    older history); re-calling with it instead of ``page_max_seq`` can
    silently skip messages between this page's end and that cursor.

    The returned ``messages_returned`` count is the size of the returned
    (post-``since_seq``-filter, capped) slice, NOT the conversation's total
    message count — deliberately not named ``total_count`` to avoid
    implying otherwise.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    conv_id = _parse_uuid("conversation_id", conversation_id)
    if since_seq < 0:
        raise ToolError("invalid_request: since_seq must be >= 0")

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            result = await service.get_conversation(
                session,
                actor_sub=sub,
                caller_agent_id=caller.id,
                conversation_id=conv_id,
                since_seq=since_seq,
            )

    if "messages_in_page" in result:
        result["messages_returned"] = result.pop("messages_in_page")
    return result


@comms_server.tool
async def inbox(agent_key: str | None = None) -> dict[str, Any]:
    """Return the caller's unread active conversations plus pending invites.

    Always returns the same five keys, even when both lists are empty --
    an explicit "nothing needs your attention" rather than an ambiguous
    bare empty list:

    - ``unread``: up to 100 (``MAX_UNREAD_CONVERSATIONS_PER_INBOX``)
      conversations with unread messages, most-recently-active first.
    - ``unread_has_more``: ``True`` if more unread conversations exist
      beyond that cap.
    - ``pending_invites``: up to 100 (``MAX_PENDING_INVITES_PER_INBOX``)
      pending invites, most-recently-invited first.
    - ``pending_invites_has_more``: ``True`` if more pending invites exist
      beyond that cap.
    - ``total_count``: the TRUE total across both lists, unaffected by
      either cap above (a real count, not a page size).

    **No cursor/pagination for this tool**: if either ``*_has_more`` flag
    is ``True``, there is no way to page through the remainder from
    ``comms_inbox`` itself. ``comms_list_conversations`` pages through
    every conversation you're a participant in (its own ``state`` filter
    is the CONVERSATION's state -- active/completed/canceled/expired --
    not your participant status), so it does NOT isolate just the
    overflowed ``unread``/``pending_invites`` set either; it's a way to
    browse your full conversation history, not a targeted fix for this
    cap. There is currently no tool-level way to see unread conversations
    or pending invites beyond these caps.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        return await service.inbox(session, caller_agent_id=caller.id)


@comms_server.tool
async def list_conversations(
    role: str | None = None,
    type: str | None = None,
    state: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    agent_key: str | None = None,
) -> dict[str, Any]:
    """Return a paginated list of conversations the caller participates in.

    Optional filters (combinable):
    - ``role``: ``"owner"`` or ``"member"`` (default: any role).
    - ``type``: conversation type — ``"open"``, ``"internal"``, or
      ``"asymmetric"`` (default: any type).
    - ``state``: ``"active"``, ``"completed"``, ``"canceled"``, or
      ``"expired"`` (default: any state).

    Results are ordered newest-first. Pass ``next_cursor`` from a prior
    response to get the next page. Both ``invited`` and ``active``
    participant statuses are included — declined and left are not.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)

    if role is not None and role not in PARTICIPANT_ROLES:
        raise ToolError(f"invalid_request: role must be one of {sorted(PARTICIPANT_ROLES)}")
    if type is not None and type not in CONVERSATION_TYPES:
        raise ToolError(f"invalid_request: type must be one of {sorted(CONVERSATION_TYPES)}")
    if state is not None and state not in CONVERSATION_STATES:
        raise ToolError(f"invalid_request: state must be one of {sorted(CONVERSATION_STATES)}")

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            return await service.list_conversations(
                session,
                caller_agent_id=caller.id,
                role=role,
                conversation_type=type,
                state=state,
                limit=limit,
                cursor=cursor,
            )


@comms_server.tool
async def accept(conversation_id: str, agent_key: str | None = None) -> dict[str, Any]:
    """Accept a pending invite: flips the caller's status ``invited`` → ``active``.

    Grants full history read and posting rights from this point forward.
    Requires the caller to currently be ``invited`` on this conversation
    (uniform denial otherwise).
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    conv_id = _parse_uuid("conversation_id", conversation_id)

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            participant = await service.accept_invite(
                session,
                actor_sub=sub,
                agent_id=caller.id,
                conversation_id=conv_id,
            )

    return {
        "conversation_id": conversation_id,
        "agent_id": str(participant.agent_id),
        "status": participant.status,
        "role": participant.role,
        "joined_at": _iso(participant.joined_at),
    }


@comms_server.tool
async def decline_invite(conversation_id: str, agent_key: str | None = None) -> dict[str, Any]:
    """Decline a pending invite. Terminal — no access is ever granted.

    Requires the caller to currently be ``invited`` on this conversation
    (uniform denial otherwise). Distinct from ``comms_leave``, which covers
    already-``active`` members, so the audit trail keeps the two actions
    separate.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    conv_id = _parse_uuid("conversation_id", conversation_id)

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            await service.decline_invite(
                session,
                actor_sub=sub,
                agent_id=caller.id,
                conversation_id=conv_id,
            )

    return {"conversation_id": conversation_id, "agent_id": str(caller.id), "status": "declined"}


@comms_server.tool
async def invite(
    conversation_id: str, target_agent_id: str, agent_key: str | None = None
) -> dict[str, Any]:
    """Invite another board agent into an active conversation.

    Caller must be ``active``. Any active member may invite (not just owner).

    - ``target_agent_id``: UUID string from ``comms_list_agents``. Target
      must be board-active and have no existing participant row (any status).
      For ``internal``/``asymmetric`` conversations, target must share the
      conversation's owner set (``internal`` additionally never admits a
      shared agent — TECH-5735). If the target's registry reports it
      retired (TECH-5703), this raises a specific "agent retired" error
      rather than the uniform unknown-agent denial. If the retirement check
      itself fails (e.g. registry timeout), the board fails open -- the
      target is treated as active, so a registry outage never blocks the
      invite, only temporarily suspends retirement enforcement.

    Two response shapes (check ``held_for_approval`` — this is a distinct
    shape, not an error), same convention as ``comms_post_message``:

    - No existing free-text history (the common case): admitted
      immediately -- ``conversation_id``, ``target_agent_id``, ``status``,
      ``invited_by``, plus (only when an ``AutoApprover`` cleared an
      invite hold inline rather than this being the ordinary no-hold path)
      ``auto_approved: true`` and ``hold_id``, mirroring
      ``comms_post_message``'s equivalent fields.
    - The conversation already has ``note`` history (TECH-5735): admitting
      a new participant would grant it full retroactive read access to
      that history the moment it accepts, so the invite is held for human
      approval instead -- ``{"held_for_approval": true, "hold_id",
      "conversation_id", "status", "risk_reason", "expires_at",
      "created_at"}``. Poll ``comms_get_hold_status`` with ``hold_id``;
      once decided, its response carries ``participant_status``.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    conv_id = _parse_uuid("conversation_id", conversation_id)
    target_id = _parse_uuid("target_agent_id", target_agent_id)

    owner_sub_claim = _string_claim(token, "owner_sub")

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            result = await service.invite(
                session,
                actor_sub=sub,
                inviter_agent_id=caller.id,
                conversation_id=conv_id,
                target_agent_id=target_id,
                ownership_client=service.get_ownership_client_factory()(session),
                active_checker=plugins.get_active_checker(),
                auto_approver=plugins.get_auto_approver(),
                notifier=plugins.get_approval_notifier(),
                owner_sub_claim=owner_sub_claim,
            )

    if isinstance(result, ApprovalHold):
        return {
            "held_for_approval": True,
            "hold_id": str(result.id),
            "conversation_id": conversation_id,
            "status": result.status,
            "risk_reason": result.risk_reason,
            "expires_at": _iso(result.expires_at),
            "created_at": _iso(result.created_at),
        }
    participant = result
    response: dict[str, Any] = {
        "conversation_id": conversation_id,
        "target_agent_id": str(participant.agent_id),
        "status": participant.status,
        "invited_by": str(participant.invited_by) if participant.invited_by else None,
    }
    auto_approved_hold_id = getattr(participant, "auto_approved_hold_id", None)
    if auto_approved_hold_id is not None:
        response["auto_approved"] = True
        response["hold_id"] = str(auto_approved_hold_id)
    return response


@comms_server.tool
async def leave(conversation_id: str, agent_key: str | None = None) -> dict[str, Any]:
    """Leave a conversation: caller's participant status → ``left``.

    Requires the caller to currently be ``active``. Pure exit bookkeeping —
    to decline a negotiation with cascade-to-``canceled`` semantics, post a
    ``decline`` message via ``comms_post_message`` instead.
    """
    token = _require_token()
    base_sub = _require_identity(token)
    agent_key = _validate_agent_key(agent_key)
    sub = _compose_sub(base_sub, agent_key)
    conv_id = _parse_uuid("conversation_id", conversation_id)

    async with get_session_factory()() as session:
        caller = await _resolve_caller_agent(session, sub, token)
        async with _map_service_errors():
            await service.leave(
                session,
                actor_sub=sub,
                agent_id=caller.id,
                conversation_id=conv_id,
            )

    return {"conversation_id": conversation_id, "agent_id": str(caller.id), "status": "left"}
