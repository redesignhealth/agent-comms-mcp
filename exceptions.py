"""Exceptions raised by the comms service layer (``service.py``).

Stage 3 (the not-yet-built MCP tools layer) catches these and maps them to
``fastmcp.exceptions.ToolError`` messages. Only three shapes ever cross the
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


__all__ = [
    "AccessDeniedError",
    "InvalidConversationStateError",
    "RateLimitExceededError",
    "SchemaVersionMismatchError",
    "UnknownConversationTypeError",
]
