"""Exceptions raised by the comms service layer (``service.py``).

Stage 3 (the not-yet-built MCP tools layer) catches these and maps them to
``fastmcp.exceptions.ToolError`` messages. These shapes cross the
service/tools boundary:

- ``AccessDeniedError``: the uniform "not authorized for this resource"
  denial (DESIGN.md §4/§8's anti-enumeration rule), covering both
  conversation-membership denials and task-admission denials
  (``denied.not_same_owner``/``denied.ownership_unverified``).
  ``str()`` of every ``AccessDeniedError`` instance is the *same constant
  string*, regardless of cause — not a participant, invited-but-not-
  accepted, left/declined, an unknown/inactive target agent, a target
  that doesn't accept the conversation type, or an unadmitted task
  assignment. The specific cause is available to server-side code only
  via the ``reason`` attribute (mirrored 1:1 into the audit log's
  ``action`` column by ``service._deny``); it must never be interpolated
  into a client-visible message.

  Unknown-agent and type-not-accepted during ``start_conversation``/
  ``invite`` are deliberately folded into this SAME uniform shape rather
  than given their own specific message. DESIGN.md's uniform-denial rule is
  stated in terms of conversations, not agents, but this service leans
  toward not leaking agent existence either: whether a given sub is a
  board agent at all is exactly the kind of fact an internal-trust-domain
  service should not need to confirm to a caller who guesses at it, and
  unifying costs nothing (the caller already knows which agents it named).

- ``AgentRetiredError`` (TECH-5703): a ``start_conversation``/``invite``
  target IS a real, board-active agent, but its owning registry reports it
  retired. Deliberately carved OUT of the uniform ``AccessDeniedError``
  shape above -- see that class's own docstring for why this one case gets
  a specific, actionable message instead.

- ``InvalidConversationStateError``: a message type is not legal given the
  conversation's current state (state-machine violation — posting after
  completion/cancellation/expiry). Kept distinct and specific: the caller
  is already an authorized member with legitimate access to the current
  state via ``get_conversation``, so there is nothing to enumerate here.

- ``RateLimitExceededError``: a sender exceeded a per-hour cap. Specific by
  design — DESIGN.md does not treat rate limiting as an enumeration risk.

- ``UnknownConversationTypeError``: ``accepted_types`` (at ``comms_register``)
  or ``conversation_type`` (at ``comms_start_conversation``) named a value
  outside ``schemas.CONVERSATION_TYPES``. Specific and lists the valid set
  by design: unlike ``AccessDeniedError``'s targets, ``CONVERSATION_TYPES``
  is not per-caller secret state — it's the same fixed, small, public
  capability list every legitimate caller needs to function at all (and
  would otherwise have to learn by trial and error, one guess per tool
  call). Enumerating it is not an enumeration *risk* in DESIGN.md's sense;
  that rule is about not letting a caller infer facts about *other
  agents/conversations*, not about hiding this service's own fixed
  vocabulary. Contrast ``display_name``/other bare-``ValueError`` cases
  below, which stay generic because their valid range is unbounded or
  already stated in the tool's own docstring — there's nothing to usefully
  enumerate.

- ``SchemaVersionMismatchError``: at ``comms_start_conversation`` (and
  ``comms_invite``'s re-check against an already-pinned conversation), no
  wire schema version falls inside every participant's declared
  ``[min_schema_version, max_schema_version]`` capability range. Distinct
  from the uniform ``AccessDeniedError`` because THAT a mismatch occurred is
  not an enumeration risk — the caller already named every participant in
  the request and knows a negotiation was attempted. UNLIKE
  ``UnknownConversationTypeError``'s ``CONVERSATION_TYPES``, though, a
  specific agent's registered ``[min, max]`` range IS per-caller state, not
  a fixed public vocabulary — so ``str()`` of this exception deliberately
  does NOT include the actual floor/ceiling values that were compared:
  an initiator who controls their own declared range could
  otherwise bisect a target's exact range by varying it across repeated
  calls. The specific numbers are still recorded in the audit log's
  ``detail`` (server-side only) via ``service._deny_schema_version_mismatch``.

Payload/schema validation failures are NOT redefined here: they reuse
``schemas.PayloadValidationError`` directly, which is already a distinct,
specific exception type.

Everything else the service layer raises as a bare ``ValueError`` (empty
``sub``/``display_name``, length/count caps, malformed UUIDs, etc.) is
deliberately mapped to a single generic, non-leaking message at the
tools boundary — see ``providers/comms.py``'s ``_map_service_errors``.
"""

from __future__ import annotations

_ACCESS_DENIED_MESSAGE = "access_denied: not authorized for this resource"


class AccessDeniedError(Exception):
    """Uniform denial for every conversation/agent authorization failure.

    ``str(exc)`` is always the fixed ``_ACCESS_DENIED_MESSAGE`` string. The
    ``reason`` attribute (matches the audit log's ``action`` for this
    denial) is for server-side logging only.
    """

    def __init__(self, *, reason: str) -> None:
        super().__init__(_ACCESS_DENIED_MESSAGE)
        self.reason = reason


class InvalidConversationStateError(Exception):
    """A state-machine transition is not legal in the current state — either
    a message type disallowed by the conversation's state, or a
    task-status transition attempted from a terminal status."""


class RateLimitExceededError(Exception):
    """A sender exceeded a per-hour rate limit. Message is specific by design."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class HoldAlreadyDecidedError(Exception):
    """The decide endpoint (``POST /approvals/{hold_id}/decide``, main.py)
    targeted a hold no longer ``pending_human`` (already ``approved``/
    ``rejected``/``auto_approved``/``expired``). Maps to HTTP 409. Carries
    the hold's current ``status`` for the response body — this is a
    non-MCP HTTP surface, gated on interactive-token + owner_sub match
    (already narrow), so the specific status is not the kind of
    enumeration risk ``AccessDeniedError`` guards against."""

    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(f"hold is no longer decidable (status={status!r})")


class HoldAwaitingAutoReviewError(Exception):
    """The decide endpoint targeted a hold still ``pending_auto`` —
    unreachable in v1 (``EscalateAllAutoApprover`` always transitions
    inline within the same transaction), specified now for a future async
    auto-approver. Maps to HTTP 409 ``{"error": "awaiting_auto_review"}``."""


class HoldExpiredError(Exception):
    """The decide endpoint targeted a hold that lazily expired on this
    touch. Maps to HTTP 410."""


class UnknownConversationTypeError(Exception):
    """``accepted_types``/``conversation_type`` named a value outside
    ``schemas.CONVERSATION_TYPES``. Message is specific by design — see the
    module docstring for why enumerating this fixed, public vocabulary is
    not an enumeration risk."""


class SchemaVersionMismatchError(Exception):
    """No wire schema version is inside every participant's declared
    ``[min_schema_version, max_schema_version]`` range (at
    ``comms_start_conversation`` or ``comms_invite``). The fact of a
    mismatch is client-visible by design, but the message deliberately
    omits the actual range values compared — see the module docstring."""


class AgentRetiredError(Exception):
    """A ``start_conversation``/``invite`` target is a board-active agent
    whose owning registry has reported it retired (TECH-5703) -- deliberately
    NOT folded into the uniform ``AccessDeniedError`` shape despite the
    module docstring's general anti-enumeration stance on unknown/inactive
    targets. Retirement is not the same category of fact as "does this
    agent_id exist": the caller already possesses a real, previously-valid
    agent_id (from a prior ``comms_list_agents``/conversation, not a guess),
    so confirming it belonged to a now-retired agent leaks nothing new about
    agent existence — it just tells the caller their invite target is gone,
    which is the specific, actionable signal this ticket calls for
    ("a clear 'agent retired' error"). Contrast the STILL-uniform case of an
    unknown/board-suspended target, which stays folded into
    ``AccessDeniedError`` exactly as before."""

    def __init__(self, *, reason: str) -> None:
        super().__init__("agent retired: this agent has been retired and is no longer reachable")
        self.reason = reason


class SiblingIdentityExistsError(Exception):
    """``register_agent`` would create a NEW row for a ``base_sub`` that
    already has at least one board identity under a DIFFERENT
    ``agent_key`` (TECH-5736) -- the silent-identity-fork failure mode a
    live incident actually hit: a caller that omits or typos
    ``agent_key`` on a later call does not re-bind an existing identity,
    it creates an entirely separate one, invisibly to the caller (the
    board is working exactly as documented -- "absent" is a distinct key
    from any named one -- which is precisely what makes this dangerous).

    Specific and client-safe by design, unlike ``AccessDeniedError``: this
    only ever describes the CALLING ``base_sub``'s own other
    registrations, never another caller's data -- similar non-enumeration
    reasoning to ``UnknownConversationTypeError``'s fixed public
    vocabulary (module docstring above), just scoped to one caller's own
    history instead of a global fixed list.

    Not fail-closed in the security sense -- ``register_agent`` accepts an
    explicit ``confirm_new_identity=True`` to proceed anyway, since a
    caller legitimately running multiple agents under one token (the
    documented purpose of ``agent_key``) must still be able to register a
    genuinely new sibling identity on purpose.

    ``existing_agent_keys`` is deliberately excluded from ``str(exc)`` --
    same treatment ``DisplayNameCollisionError.existing_subs`` got in
    round 1 (see that class's docstring), applied here for the analogous
    reason: a ``comms:write``-only caller can trigger this error
    repeatedly (it's on the write path, not gated behind ``comms:read``)
    and would otherwise be able to enumerate its own sibling agent_keys
    purely from the client-facing message. It remains a plain attribute
    on the exception for server-side callers (audit logging) only, never
    surfaced across the service/tools boundary.
    """

    def __init__(self, *, base_sub: str, existing_agent_keys: list[str | None]) -> None:
        super().__init__(
            f"identity_fork_detected: {base_sub!r} already has at least one other "
            "registered agent -- pass confirm_new_identity=True to register a "
            "genuinely separate identity, or pass the matching agent_key to re-bind "
            "the existing one instead"
        )
        self.base_sub = base_sub
        self.existing_agent_keys = existing_agent_keys


class DisplayNameCollisionError(Exception):
    """``register_agent`` would create a NEW row whose ``display_name``
    matches an already board-``active`` agent's ``display_name``
    (TECH-5736). ``display_name`` is not a board-enforced identity key --
    ``sub`` is -- but a live incident showed downstream consumers (a site
    agent's message whitelist) treat it as one in practice, so two
    simultaneously-active, identically-named agents is a real hazard
    worth rejecting at creation time rather than silently allowing.

    Specific and client-safe: ``display_name`` is already public via
    ``comms_list_agents``, so naming which ``sub`` already holds it is not
    a new disclosure -- the caller could already learn the same fact by
    listing the directory.

    Only checked on FIRST registration (a new row being created), not on
    every re-registration of an existing row -- see ``register_agent``'s
    own docstring for why re-registration is deliberately exempt.

    Round-1 Argus review (TECH-5736) flagged the original message as a sub-
    enumeration path: a token scoped only to ``comms:write`` (sufficient to
    call ``comms_register``) cannot call ``comms_list_agents``
    (``comms:read``), yet could otherwise learn a target agent's ``sub`` by
    probing display names and reading it off this error. The
    ``comms_list_agents`` justification above holds only when the caller
    already has ``comms:read`` too, which ``TOOL_SCOPES`` does not
    guarantee. ``existing_subs`` is therefore no longer part of ``str(exc)``
    -- it remains an attribute for server-side callers (audit logging) only,
    never surfaced across the service/tools boundary.
    """

    def __init__(self, *, display_name: str, existing_subs: list[str]) -> None:
        super().__init__(
            f"display_name_collision: {display_name!r} is already used by an active "
            "agent -- choose a distinct display_name"
        )
        self.display_name = display_name
        self.existing_subs = existing_subs


class AgentSuspendedError(Exception):
    """``register_agent`` was called for a ``sub`` currently
    ``status="suspended"`` (TECH-5736) -- deliberately NOT silently
    reactivated.

    ``comms_deregister_agent`` is documented as one-directional (no
    reactivate tool, by design -- see its own docstring). Before this
    check, the idempotent re-registration branch unconditionally reset
    ``status`` back to ``"active"`` on any subsequent ``comms_register``
    call, which silently reverted every deregistration the moment the
    same caller (often the exact misbehaving caller a deregistration was
    meant to stop) called ``comms_register`` again -- undermining the
    entire feature this ticket added. There is intentionally no bypass
    parameter here (unlike ``confirm_new_identity``/``is_shared_authorized``):
    reactivation has no supported path yet; add one as its own change, with
    its own authorization gate, if that need arises.

    Specific and client-safe: this only describes the calling ``sub``'s own
    state, never another caller's data, the same non-enumeration reasoning
    as ``SiblingIdentityExistsError``.
    """

    def __init__(self, *, sub: str) -> None:
        super().__init__(
            f"agent_suspended: {sub!r} has been deregistered (status=suspended) and "
            "cannot be re-registered -- there is no reactivation path"
        )
        self.sub = sub


__all__ = [
    "AccessDeniedError",
    "AgentRetiredError",
    "AgentSuspendedError",
    "DisplayNameCollisionError",
    "HoldAlreadyDecidedError",
    "HoldAwaitingAutoReviewError",
    "HoldExpiredError",
    "InvalidConversationStateError",
    "RateLimitExceededError",
    "SchemaVersionMismatchError",
    "SiblingIdentityExistsError",
    "UnknownConversationTypeError",
]
