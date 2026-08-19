"""Tests for the pure conversation state-machine rules (state_machine.py).

The ownership-boundary rule (formerly ``is_boundary_crossing_safe`` here)
moved to ``plugins.BoundaryCrossingScorer`` (TECH-5389) -- see
``tests/test_risk.py``."""

from __future__ import annotations

import pytest

from state_machine import (
    is_message_legal,
    resulting_conversation_state,
)

_MESSAGE_TYPES = [
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

_NON_ACTIVE_STATES = ["completed", "canceled", "expired"]


class TestIsMessageLegal:
    @pytest.mark.parametrize("message_type", _MESSAGE_TYPES)
    def test_every_known_type_legal_when_active(self, message_type: str) -> None:
        assert is_message_legal("active", message_type) is True

    @pytest.mark.parametrize("message_type", _MESSAGE_TYPES)
    @pytest.mark.parametrize("state", _NON_ACTIVE_STATES)
    def test_every_known_type_illegal_when_not_active(self, state: str, message_type: str) -> None:
        assert is_message_legal(state, message_type) is False

    def test_unknown_message_type_illegal_even_when_active(self) -> None:
        assert is_message_legal("active", "not_a_real_type") is False

    def test_unknown_conversation_state_illegal(self) -> None:
        assert is_message_legal("some_unexpected_state", "confirm") is False


class TestResultingConversationState:
    def test_confirm_completes_conversation(self) -> None:
        assert resulting_conversation_state("confirm") == "completed"

    def test_confirm_completes_regardless_of_decline_flag(self) -> None:
        # confirm's transition is unconditional — the decline-only kwarg
        # must not affect it either way.
        assert resulting_conversation_state("confirm", all_non_owners_declined=True) == (
            "completed"
        )

    def test_decline_with_all_non_owners_declined_cancels(self) -> None:
        assert resulting_conversation_state("decline", all_non_owners_declined=True) == "canceled"

    def test_decline_without_all_non_owners_declined_is_noop(self) -> None:
        assert resulting_conversation_state("decline", all_non_owners_declined=False) is None

    def test_decline_defaults_to_no_transition(self) -> None:
        assert resulting_conversation_state("decline") is None

    @pytest.mark.parametrize(
        "message_type",
        [
            "availability_request",
            "availability_response",
            "counter_proposal",
            "needs_clarification",
        ],
    )
    def test_other_types_never_transition(self, message_type: str) -> None:
        assert resulting_conversation_state(message_type) is None
        assert resulting_conversation_state(message_type, all_non_owners_declined=True) is None

    def test_unknown_message_type_is_noop(self) -> None:
        assert resulting_conversation_state("not_a_real_type") is None

    def test_task_complete_completes_conversation(self) -> None:
        assert resulting_conversation_state("task_complete") == "completed"

    def test_task_decline_cancels_unconditionally(self) -> None:
        # Unlike scheduling's `decline`, task_decline is role-restricted (member-only)
        # so a single post is always decisive — no all-non-owners cascade needed.
        assert resulting_conversation_state("task_decline") == "canceled"
        assert (
            resulting_conversation_state("task_decline", all_non_owners_declined=True) == "canceled"
        )
        assert (
            resulting_conversation_state("task_decline", all_non_owners_declined=False)
            == "canceled"
        )

    def test_task_cancel_cancels_conversation(self) -> None:
        assert resulting_conversation_state("task_cancel") == "canceled"

    def test_task_report_does_not_transition(self) -> None:
        assert resulting_conversation_state("task_report") is None
        assert resulting_conversation_state("task_report", all_non_owners_declined=True) is None

    def test_task_assign_does_not_transition(self) -> None:
        assert resulting_conversation_state("task_assign") is None
        assert resulting_conversation_state("task_assign", all_non_owners_declined=True) is None
