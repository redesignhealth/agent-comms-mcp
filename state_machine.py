"""Pure conversation state-machine rules for the comms board (DESIGN.md §6/§4).

Two independent, side-effect-free functions, deliberately typed with only
primitives (no ORM/DB objects) so the service layer can call them without
importing models.py:

- ``is_message_legal``: is this message type postable given the
  conversation's *current* state? (All message types are legal only while
  ``conversation.state == 'active'``.)
- ``resulting_conversation_state``: given that a message of this type was
  just legally posted, what new conversation state (if any) does it cause?
  The service layer supplies the one piece of context it alone has —
  whether every non-owner participant is now declined — via
  ``all_non_owners_declined``; this module never sees participant rows.

Neither function talks to the database, raises, or has side effects — both
are trivially unit-testable with plain strings/bools.

The ownership-boundary rule (DESIGN.md §9 Axis 2) formerly lived here as
``is_boundary_crossing_safe``; it has moved to
``plugins.BoundaryCrossingScorer`` (TECH-5389) as part of the pluggable
risk-scorer seam.
"""

from __future__ import annotations

from typing import get_args

from schemas import MessageType

# Conversation states, mirrored from models.CONVERSATION_STATES without
# importing models.py (kept decoupled per the "primitive inputs only"
# design goal — this module must not depend on the ORM layer).
ConversationState = str

_ACTIVE_STATE = "active"

# Known message types, kept in lock-step with schemas.MESSAGE_SCHEMAS'
# message-type axis (the MessageType Literal), so a future new message
# type is legal here the moment it's added to schemas.py.
_KNOWN_MESSAGE_TYPES: frozenset[str] = frozenset(get_args(MessageType))


def is_message_legal(conversation_state: str, message_type: str) -> bool:
    """Return whether ``message_type`` may be posted while the conversation
    is in ``conversation_state``.

    Per DESIGN.md §6, every message type in the registry is legal only
    when the conversation is ``active``; an unrecognized ``message_type``
    is never legal in any state.
    """
    if message_type not in _KNOWN_MESSAGE_TYPES:
        return False
    return conversation_state == _ACTIVE_STATE


def resulting_conversation_state(
    message_type: str,
    *,
    all_non_owners_declined: bool = False,
) -> str | None:
    """Return the new conversation state caused by posting ``message_type``,
    or ``None`` if posting it causes no conversation-state transition.

    - ``confirm`` -> always transitions to ``'completed'``.
    - ``decline`` -> transitions to ``'canceled'`` only when the caller
      reports (via ``all_non_owners_declined``) that every non-owner
      participant is now in the ``'declined'`` state; the sender's own
      participant-status update (to ``'declined'``) is a separate,
      participant-level effect the service layer applies itself — this
      function only reports the *conversation*-level transition.
    - ``task_complete`` -> always transitions to ``'completed'``
      ("tasks-as-conversations": unlike scheduling's ``decline``, a task
      conversation's ``task_decline``/``task_cancel`` transition
      unconditionally, not via the all-non-owners-declined cascade — see
      the module docstring and ``service._require_message_sender_role``
      for why: each is restricted to a single sender role, so one post is
      always decisive).
    - ``task_decline`` / ``task_cancel`` -> always transition to ``'canceled'``.
    - Every other message type (including ``task_report``) -> ``None``
      (no conversation-state effect).

    This function does not validate that ``message_type`` is legal in the
    first place — call ``is_message_legal`` first; that keeps the two
    concerns (legality vs. resulting transition) independently testable.
    """
    if message_type in ("confirm", "task_complete"):
        return "completed"
    if message_type == "decline":
        return "canceled" if all_non_owners_declined else None
    if message_type in ("task_decline", "task_cancel"):
        return "canceled"
    return None


__all__ = [
    "ConversationState",
    "is_message_legal",
    "resulting_conversation_state",
]
