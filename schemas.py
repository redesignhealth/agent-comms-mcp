"""Versioned Pydantic payload schemas for typed board messages.

Every message posted to the board must validate against the schema
registered for ``(message_type, schema_version)`` — there is no free text
anywhere in v1 outside the explicitly-marked ``note`` type (DESIGN.md §6,
§9). Validation rules:

- ``extra="forbid"`` on every model (strict — unknown fields rejected).
- All datetimes are timezone-aware ISO 8601 (``AwareDatetime``); naive
  datetimes are rejected.
- Enumerated string fields are closed ``Literal`` sets. No free-text
  fields anywhere — every field is a bounded numeric/datetime/enum value
  or a bounded list of them.

Discriminator field: every top-level message model also carries a
``type: Literal[...]`` field matching the DB ``messages.type`` column
value, defaulted to that same literal. It is optional on input (callers
that only pass the ``message_type`` service-layer argument need not repeat
it in the payload) but always present in the normalized/dumped form, and
if a caller *does* include it, it must match — a defense-in-depth check
against a payload accidentally validated against the wrong schema class,
independent of the ``message.type`` lookup that selects the schema in the
first place.

The registry (``MESSAGE_SCHEMAS``, accessed via ``get_schema``) is the
single source of truth for every message type in the system, keyed by
``(message_type, schema_version)`` — deliberately independent of
``conversations.type`` (DESIGN.md §9's "two axes, not a new conversation
type per scenario"): which message types a conversation may legally carry
is a function of ``conversations.type`` and ``boundary_safe`` (see
``MessageSchema`` below and ``state_machine.py``), not of the registry key.
Adding a message type or a new ``schema_version`` is a code change here
plus (nothing else) — old versions stay registered so historical payloads
remain validatable.

Design note — ``availability_response``'s either/or shape (DESIGN.md §6:
"slots[...] max 10, OR none_available+reason"): modeled as a *single*
Pydantic model (``AvailabilityResponseV1``) with both branches' fields
optional, plus a ``model_validator(mode="after")`` enforcing exactly one
branch is populated, rather than a ``Union``/discriminated-union of two
model classes. Rationale: ``get_schema()`` returns a single
``type[BaseModel]`` per registry key so the (not-yet-built) service layer
can call ``schema_cls.model_validate(payload)`` uniformly for every
message type without special-casing a ``Union`` vs. a bare model class at
the call site. A discriminated union would need its own discriminator
field threaded through a ``TypeAdapter`` instead, which buys nothing here
once mutual exclusivity is enforced by the validator.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Literal, NamedTuple, get_args
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

# Conversation types known to the board:
# admission policy only, decoupled from which message types a conversation
# carries (see MESSAGE_SCHEMAS below). Used to validate ``conversations.type``
# at start time.
#
#   internal   — every participant's verified owner set identical; owner set
#                frozen at creation.
#   asymmetric — verified owner sets intersect; standard invite->accept;
#                owner set frozen at creation.
#   open       — unrestricted (the v1 "scheduling.availability" rule,
#                renamed here since it's no longer the only type); standard
#                invite->accept.
CONVERSATION_TYPES: frozenset[str] = frozenset({"internal", "asymmetric", "open"})

# Shared size/count limits (DESIGN.md §8 "message size caps" invariant).
# Defined once here so the tool boundary (providers/comms.py), the service
# layer (service.py), and the DB model (models.py) all reference the same
# values rather than three independently-drifting literals.
MAX_PARTICIPANTS_PER_CONVERSATION = 50
MAX_DISPLAY_NAME_LENGTH = 255
MAX_ACCEPTED_TYPES = 20
# Per-entry length cap for a single accepted_types string:
# MAX_ACCEPTED_TYPES bounds the LIST length, but nothing
# previously bounded each entry's own length -- a caller could submit 20
# arbitrarily large strings, all pass the count check, then get echoed
# back verbatim in UnknownConversationTypeError's message. Every real
# MESSAGE_TYPES value is under 30 characters; 100 is a generous margin.
MAX_ACCEPTED_TYPE_LENGTH = 100
MAX_PAYLOAD_BYTES = 65536

# Caller-supplied suffix a caller may append to its own verified identity to
# register multiple distinct agent rows under one token (providers/comms.py
# `register`'s `agent_key` param) -- see the comment there for
# why this exists and why it's a stopgap. Same generous-margin sizing
# rationale as MAX_ACCEPTED_TYPE_LENGTH above.
MAX_AGENT_KEY_LENGTH = 100

# Message types known to the board. Mirrors the DB CHECK-free, code-owned
# open vocabulary described in models.py's module docstring. Each type's
# ``boundary_safe`` flag (see MessageSchema/MESSAGE_SCHEMAS below) governs
# whether it may cross an ownership boundary under an ``asymmetric``
# conversation, and whether it's legal at all under ``open``.
MessageType = Literal[
    "availability_request",
    "availability_response",
    "counter_proposal",
    "confirm",
    "decline",
    "needs_clarification",
    "note",
    "task_assign",
    "task_report",
    "task_complete",
    "task_decline",
    "task_cancel",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimeWindow(_StrictModel):
    """A timezone-aware [start, end) interval; end must be after start."""

    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def _end_after_start(self) -> TimeWindow:
        if self.end <= self.start:
            raise ValueError("end must be after start")
        return self


class Slot(_StrictModel):
    """A proposed meeting slot with a sender preference weight (0..1).

    This is the "judgment crosses the boundary" primitive (DESIGN.md §6):
    ``preference`` is a scored opinion, never raw calendar data — there is
    no field here for a raw calendar entry to travel in.
    """

    start: AwareDatetime
    end: AwareDatetime
    preference: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _end_after_start(self) -> Slot:
        if self.end <= self.start:
            raise ValueError("end must be after start")
        return self


_CONSTRAINTS = Literal["mornings_only", "afternoons_only", "avoid_fridays", "buffer_15min"]
_DECLINE_REASONS = Literal["owner_declined", "no_availability", "expired", "other"]
_NONE_AVAILABLE_REASONS = Literal["no_overlap", "window_too_narrow", "owner_unavailable"]


class AvailabilityRequestV1(_StrictModel):
    """availability_request / v1. Opens a scheduling negotiation."""

    type: Literal["availability_request"] = "availability_request"
    window: TimeWindow
    duration_min: int = Field(ge=5, le=480)
    modality: Literal["video", "phone", "in_person"]
    priority: Literal["low", "normal", "high"]
    constraints: list[_CONSTRAINTS] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _no_duplicate_constraints(self) -> AvailabilityRequestV1:
        if len(set(self.constraints)) != len(self.constraints):
            raise ValueError("constraints must not contain duplicates")
        return self


class AvailabilityResponseV1(_StrictModel):
    """availability_response / v1.

    Exactly one of two mutually-exclusive branches must be populated:

    - ``slots``: up to 10 candidate slots with sender preference weights.
    - ``none_available`` + ``reason``: no slots can be offered.

    See the module docstring for why this is one model with an
    exclusivity validator rather than a Union of two model classes.
    """

    type: Literal["availability_response"] = "availability_response"
    slots: list[Slot] | None = Field(default=None, max_length=10)
    none_available: Literal[True] | None = None
    reason: _NONE_AVAILABLE_REASONS | None = None

    @model_validator(mode="after")
    def _exactly_one_branch(self) -> AvailabilityResponseV1:
        has_slots = self.slots is not None
        has_none_available = self.none_available is not None
        if has_slots and has_none_available:
            raise ValueError("provide either 'slots' or 'none_available'+'reason', not both")
        if not has_slots and not has_none_available:
            raise ValueError("must provide either 'slots' or 'none_available'+'reason'")
        if has_slots and self.reason is not None:
            raise ValueError("'reason' is only valid alongside 'none_available'")
        if has_none_available and self.reason is None:
            raise ValueError("'reason' is required when 'none_available' is set")
        if has_slots and not self.slots:
            raise ValueError("'slots' must contain at least one slot when provided")
        return self


class CounterProposalV1(_StrictModel):
    """counter_proposal / v1.

    Same slots shape as ``AvailabilityResponseV1``'s slots branch — a
    fresh set of candidate slots offered in reply to a prior proposal.
    """

    type: Literal["counter_proposal"] = "counter_proposal"
    slots: list[Slot] = Field(min_length=1, max_length=10)


class ConfirmV1(_StrictModel):
    """confirm / v1.

    Confirms one slot (not a list); posting it transitions the
    conversation to 'completed'. Booking itself is EA-side.
    """

    type: Literal["confirm"] = "confirm"
    slot: TimeWindow


class DeclineV1(_StrictModel):
    """decline / v1.

    Sets the SENDER's participant status to 'declined'. If all non-owner
    participants have declined, the conversation state becomes 'canceled'
    (see ``state_machine.resulting_conversation_state``).
    """

    type: Literal["decline"] = "decline"
    reason: _DECLINE_REASONS


class NeedsClarificationV1(_StrictModel):
    """needs_clarification / v1.

    Points at a prior message by seq — no free-text questions in v1.
    ``about_seq`` must reference an existing message in the same
    conversation; that referential check lives in the service layer (it
    needs DB state), not here — this model only enforces ``>= 1``.
    """

    type: Literal["needs_clarification"] = "needs_clarification"
    about_seq: int = Field(ge=1)


class NoteV1(_StrictModel):
    """note / v1 — free text, ``boundary_safe=False``.

    The one deliberate exception to "no free text" (DESIGN.md §8 invariant
    3 is a leakage control under this model, not an injection control —
    see DESIGN.md §9): legal only where ``boundary_safe=False`` is allowed
    to travel (``internal`` always; ``asymmetric`` only when the post does
    not cross an ownership boundary for the sender; never under ``open``).
    ``text`` is stored verbatim — this is provisional pending the
    quarantine/review pipeline DESIGN.md §10 defers ("raw text stored for
    audit/human display but never enters a privileged agent's context");
    nothing in this schema enforces that downstream handling today.
    """

    type: Literal["note"] = "note"
    text: str = Field(min_length=1, max_length=4000)


_TASK_ACTIONS_REQUIRING_WINDOW_AND_DURATION = frozenset(
    {"gather_availability", "schedule_meeting", "reschedule_meeting"}
)
_TASK_CLOSE_REASONS = Literal["no_longer_needed", "unable_to_complete", "expired", "other"]
_TASK_REPORT_STATUSES = Literal["in_progress", "blocked"]


def _check_no_duplicates(values: Sequence[Any], field_name: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"{field_name} must not contain duplicates")


class TaskAssignV1(_StrictModel):
    """task_assign / v1 — opens a task-coordination conversation (DESIGN.md §9;
    supersedes the ``task_spec``/dedicated ``tasks``
    table). Posted as the seq-1 message of an ``internal``/``asymmetric``
    conversation between the assigning agent (participant ``role='owner'``)
    and the assignee (participant ``role='member'``).

    Machine-actionable coordinates only, never prose: an ``action`` enum
    plus structured scheduling parameters (reusing ``TimeWindow`` and the
    same constraint/modality/priority enums as the scheduling messages).
    Prose stays in the EA's own context (DESIGN.md §8 invariant 3) — there
    is no free-text field here for it to travel in.

    ``gather_availability``/``schedule_meeting``/``reschedule_meeting``
    require ``window`` and ``duration_min``; ``confirm_slot`` requires
    ``window``. ``report_status`` needs neither.
    """

    type: Literal["task_assign"] = "task_assign"
    action: Literal[
        "gather_availability",
        "schedule_meeting",
        "reschedule_meeting",
        "cancel_meeting",
        "confirm_slot",
        "report_status",
    ]
    counterparty_agent_ids: list[UUID] = Field(default_factory=list, max_length=10)
    related_conversation_id: UUID | None = None
    window: TimeWindow | None = None
    duration_min: int | None = Field(default=None, ge=5, le=480)
    modality: Literal["video", "phone", "in_person"] | None = None
    priority: Literal["low", "normal", "high"] = "normal"
    due_at: AwareDatetime | None = None
    constraints: list[_CONSTRAINTS] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _no_duplicates(self) -> TaskAssignV1:
        _check_no_duplicates(self.constraints, "constraints")
        _check_no_duplicates(self.counterparty_agent_ids, "counterparty_agent_ids")
        return self

    @model_validator(mode="after")
    def _required_fields_for_action(self) -> TaskAssignV1:
        if self.action in _TASK_ACTIONS_REQUIRING_WINDOW_AND_DURATION:
            if self.window is None or self.duration_min is None:
                raise ValueError(f"action '{self.action}' requires 'window' and 'duration_min'")
        elif self.action == "confirm_slot" and self.window is None:
            raise ValueError("action 'confirm_slot' requires 'window'")
        return self


class TaskReportV1(_StrictModel):
    """task_report / v1 — non-terminal, structured status update (either
    direction). ``about_seq``, if given, points at the ``task_assign`` (or
    an earlier ``task_report``) this update concerns — no free-text
    progress notes, per the same invariant as ``needs_clarification``."""

    type: Literal["task_report"] = "task_report"
    status: _TASK_REPORT_STATUSES
    about_seq: int | None = Field(default=None, ge=1)


class TaskCompleteV1(_StrictModel):
    """task_complete / v1 — terminal, transitions the conversation to
    ``completed`` (``state_machine.resulting_conversation_state``)."""

    type: Literal["task_complete"] = "task_complete"
    about_seq: int | None = Field(default=None, ge=1)


class TaskDeclineV1(_StrictModel):
    """task_decline / v1 — the assignee's consent/refusal mechanism;
    terminal, transitions the conversation to ``canceled``. Sender-role
    restricted to a non-owner participant (``service._require_message_sender_role``)."""

    type: Literal["task_decline"] = "task_decline"
    reason: _TASK_CLOSE_REASONS


class TaskCancelV1(_StrictModel):
    """task_cancel / v1 — the assigner's creator-side close; terminal,
    transitions the conversation to ``canceled``. Sender-role restricted to
    the conversation's owner participant."""

    type: Literal["task_cancel"] = "task_cancel"
    reason: _TASK_CLOSE_REASONS


class MessageSchema(NamedTuple):
    """A registered message type's validation model plus its boundary policy.

    ``boundary_safe`` (DESIGN.md §9 Axis 2) governs whether this message
    type may cross an ownership boundary: required unconditionally under
    ``open``; free under ``internal``; under ``asymmetric`` only when the
    specific post doesn't cross for the sender (see
    ``state_machine.is_boundary_crossing_safe``). It is a property of the
    message type, independent of which conversation type carries it.
    """

    model: type[BaseModel]
    boundary_safe: bool


# Registry: (message_type, schema_version) -> MessageSchema. Deliberately
# independent of conversation type — legality of
# a given message type under a given conversation type is decided by
# state_machine.py from ``boundary_safe`` + conversation type, not baked
# into this key. Every ``model`` is a concrete BaseModel subclass (never a
# Union/TypeAdapter), so callers can uniformly do
# ``get_schema(...).model_validate(payload)``.
MESSAGE_SCHEMAS: dict[tuple[str, int], MessageSchema] = {
    ("availability_request", 1): MessageSchema(AvailabilityRequestV1, boundary_safe=True),
    ("availability_response", 1): MessageSchema(AvailabilityResponseV1, boundary_safe=True),
    ("counter_proposal", 1): MessageSchema(CounterProposalV1, boundary_safe=True),
    ("confirm", 1): MessageSchema(ConfirmV1, boundary_safe=True),
    ("decline", 1): MessageSchema(DeclineV1, boundary_safe=True),
    ("needs_clarification", 1): MessageSchema(NeedsClarificationV1, boundary_safe=True),
    ("note", 1): MessageSchema(NoteV1, boundary_safe=False),
    ("task_assign", 1): MessageSchema(TaskAssignV1, boundary_safe=True),
    ("task_report", 1): MessageSchema(TaskReportV1, boundary_safe=True),
    ("task_complete", 1): MessageSchema(TaskCompleteV1, boundary_safe=True),
    ("task_decline", 1): MessageSchema(TaskDeclineV1, boundary_safe=True),
    ("task_cancel", 1): MessageSchema(TaskCancelV1, boundary_safe=True),
}


# All message types that have at least one registered schema version.
# Used to validate ``Agent.accepted_types`` entries:
# an agent declares which message types it will accept, not which
# conversation admission type, so the vocabulary is message-type-scoped.
MESSAGE_TYPES: frozenset[str] = frozenset(mt for mt, _ in MESSAGE_SCHEMAS)

# Drift guard (TECH-5377): ``MessageType`` above is a hand-maintained
# ``Literal`` -- nothing previously enforced that it actually lists the same
# types as MESSAGE_SCHEMAS's keys (which MESSAGE_TYPES is mechanically
# derived from). Adding a schema without updating the Literal, or vice
# versa, would silently drift: the Literal is only a static-typing aid for
# each schema's own `type` field, never consulted by validate_payload/
# get_schema at runtime, so nothing would fail until a type-checker run (or
# a confusing mismatch) caught it much later. Checked at import time via a
# real exception, not a bare ``assert`` -- an assert is stripped entirely
# under ``python -O``, which would silently disable this guard exactly
# where "silent drift" is the failure mode being guarded against.
_message_type_literal_values = frozenset(get_args(MessageType))
if _message_type_literal_values != MESSAGE_TYPES:
    raise RuntimeError(
        "MessageType Literal and MESSAGE_SCHEMAS have drifted out of sync -- "
        f"Literal-only: {_message_type_literal_values - MESSAGE_TYPES}, "
        f"schemas-only: {MESSAGE_TYPES - _message_type_literal_values}"
    )

# Highest schema_version this board's own code actually implements (today:
# 1, for every message type above). start_conversation's capability
# negotiation (service._negotiate_schema_version) clamps the
# highest version two agents mutually claim to support down to this value
# -- without the clamp, two agents that both (legitimately, per
# comms_register's own validation) declare max_schema_version=2 would
# negotiate to version 2, and the very next validate_payload call would
# fail with an "unknown message schema" PayloadValidationError instead of
# a clear capability-limit error, even though the mismatch is the BOARD's
# limitation, not theirs.
MAX_REGISTERED_SCHEMA_VERSION: int = max(v for _, v in MESSAGE_SCHEMAS)


class PayloadValidationError(ValueError):
    """Raised when a payload fails schema lookup or validation.

    Carries a client-safe summary (schema errors are not secret — the
    caller is already an authorized member when payloads are validated).
    """


def get_schema(message_type: str, schema_version: int) -> type[BaseModel]:
    """Look up the Pydantic model registered for this message type/version.

    This is the seam the service layer calls to resolve which schema
    governs an incoming payload, given the caller-supplied ``message_type``
    and ``schema_version`` (defaulting to 1 upstream). Always returns a
    concrete model class — never a ``Union`` or ``TypeAdapter`` — so the
    caller can do ``get_schema(...).model_validate(payload)`` uniformly.

    Raises ``PayloadValidationError`` (not ``KeyError``) for unknown
    combinations so callers can catch one exception type across lookup
    and validation failures.
    """
    entry = MESSAGE_SCHEMAS.get((message_type, schema_version))
    if entry is None:
        raise PayloadValidationError(
            f"unknown message schema: type '{message_type}' schema_version "
            f"{schema_version} is not registered"
        )
    return entry.model


def is_boundary_safe(message_type: str, schema_version: int) -> bool:
    """Whether this message type/version may cross an ownership boundary
    unconditionally (see ``MessageSchema.boundary_safe``).

    Raises ``PayloadValidationError`` for an unknown coordinate, same as
    ``get_schema``, so callers don't need a separate not-found path.
    """
    entry = MESSAGE_SCHEMAS.get((message_type, schema_version))
    if entry is None:
        raise PayloadValidationError(
            f"unknown message schema: type '{message_type}' schema_version "
            f"{schema_version} is not registered"
        )
    return entry.boundary_safe


def validate_payload(
    message_type: str,
    schema_version: int,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Validate ``payload`` against the registered schema and normalize it.

    Returns the JSON-mode dump of the validated model (datetimes as ISO
    strings) — this normalized form is what gets stored in
    ``messages.payload``.

    Enforces ``MAX_PAYLOAD_BYTES`` (DESIGN.md §8 "message size caps"
    security invariant) on both the raw input payload and the normalized
    dump — checked here, once, so every message type is covered uniformly
    without each schema class needing its own size validator.
    """
    _check_payload_size(payload)
    schema_cls = get_schema(message_type, schema_version)
    try:
        model = schema_cls.model_validate(payload)
    except ValidationError as exc:
        summary = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()[:5]
        )
        raise PayloadValidationError(f"payload failed schema validation: {summary}") from exc
    dumped: dict[str, Any] = model.model_dump(mode="json")
    _check_payload_size(dumped)
    return dumped


def _check_payload_size(payload: dict[str, Any]) -> None:
    """Raise ``PayloadValidationError`` if ``payload``'s JSON encoding exceeds
    ``MAX_PAYLOAD_BYTES``."""
    size = len(json.dumps(payload, default=str).encode("utf-8"))
    if size > MAX_PAYLOAD_BYTES:
        raise PayloadValidationError(
            f"payload failed schema validation: payload is {size} bytes, "
            f"exceeding the {MAX_PAYLOAD_BYTES}-byte cap"
        )


__all__ = [
    "CONVERSATION_TYPES",
    "MAX_ACCEPTED_TYPES",
    "MAX_ACCEPTED_TYPE_LENGTH",
    "MAX_DISPLAY_NAME_LENGTH",
    "MAX_PARTICIPANTS_PER_CONVERSATION",
    "MAX_PAYLOAD_BYTES",
    "MESSAGE_SCHEMAS",
    "MESSAGE_TYPES",
    "AvailabilityRequestV1",
    "AvailabilityResponseV1",
    "ConfirmV1",
    "CounterProposalV1",
    "DeclineV1",
    "MessageSchema",
    "MessageType",
    "NeedsClarificationV1",
    "NoteV1",
    "PayloadValidationError",
    "Slot",
    "TaskAssignV1",
    "TaskCancelV1",
    "TaskCompleteV1",
    "TaskDeclineV1",
    "TaskReportV1",
    "TimeWindow",
    "get_schema",
    "is_boundary_safe",
    "validate_payload",
]
