"""Tests for the pure conversation state-machine rules (state_machine.py)."""

from __future__ import annotations

import pytest

from state_machine import (
    is_boundary_crossing_safe,
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


_A = frozenset({"a"})
_B = frozenset({"b"})
_SHARED = frozenset({"a", "b"})
_EMPTY: frozenset[str] = frozenset()


class TestIsBoundaryCrossingSafe:
    def test_open_requires_boundary_safe(self) -> None:
        assert is_boundary_crossing_safe("open", True, _EMPTY, _EMPTY) is True
        assert is_boundary_crossing_safe("open", False, _EMPTY, _EMPTY) is False

    def test_open_ignores_owner_sets(self) -> None:
        # open has no ownership concept -- boundary_safe alone decides.
        assert is_boundary_crossing_safe("open", True, _A, _B) is True
        assert is_boundary_crossing_safe("open", False, _A, _A) is False

    def test_internal_always_safe(self) -> None:
        assert is_boundary_crossing_safe("internal", True, _A, _A) is True
        assert is_boundary_crossing_safe("internal", False, _A, _B) is True
        assert is_boundary_crossing_safe("internal", False, _EMPTY, _EMPTY) is True

    def test_asymmetric_boundary_safe_always_legal(self) -> None:
        assert is_boundary_crossing_safe("asymmetric", True, _A, _B) is True

    def test_asymmetric_single_owner_to_shared_crosses(self) -> None:
        # sender owns only {a}; other side (shared) has an owner {b}
        # outside the sender's set -- crosses, illegal.
        assert is_boundary_crossing_safe("asymmetric", False, _A, _SHARED) is False

    def test_asymmetric_shared_to_single_owner_does_not_cross(self) -> None:
        # sender is shared {a, b}; other side's owner {b} is already in the
        # sender's own set -- does not cross, legal.
        assert is_boundary_crossing_safe("asymmetric", False, _SHARED, _B) is True

    def test_asymmetric_same_single_owner_does_not_cross(self) -> None:
        assert is_boundary_crossing_safe("asymmetric", False, _A, _A) is True

    def test_asymmetric_disjoint_owners_crosses(self) -> None:
        assert is_boundary_crossing_safe("asymmetric", False, _A, _B) is False

    def test_unrecognized_type_denied_even_when_boundary_safe(self) -> None:
        # Default-deny for a type this function doesn't recognize (e.g. a
        # legacy pre-rename row) -- must not fall through to asymmetric's
        # more permissive handling.
        assert is_boundary_crossing_safe("scheduling.availability", True, _EMPTY, _EMPTY) is False
        assert is_boundary_crossing_safe("bogus", False, _A, _B) is False

    def test_every_registered_conversation_type_is_explicitly_handled(self) -> None:
        # state_machine.py already imports schemas.MessageType, but
        # deliberately doesn't import schemas.CONVERSATION_TYPES specifically
        # (is_boundary_crossing_safe's three branches are hardcoded, not
        # derived from that set), so this cross-check lives here rather than
        # as a runtime assertion inside is_boundary_crossing_safe itself --
        # a future CONVERSATION_TYPES addition that is_boundary_crossing_safe
        # doesn't yet special-case would otherwise silently fall through to
        # the default-deny branch instead of getting real handling.
        from schemas import CONVERSATION_TYPES

        for conversation_type in CONVERSATION_TYPES:
            assert conversation_type in ("open", "internal", "asymmetric"), (
                f"{conversation_type!r} is in schemas.CONVERSATION_TYPES but "
                "is_boundary_crossing_safe has no explicit branch for it"
            )
            # Also prove it's actually handled -- boundary_safe=True is
            # sufficient for legality in all three types (for "internal"
            # unconditionally, since the type itself decides there, not the
            # flag; for "open" because its branch requires boundary_safe
            # directly; for "asymmetric" via its own short-circuit, though
            # with the _EMPTY owner sets used here the subset check would
            # also pass boundary_safe=False -- test_asymmetric_boundary_safe_
            # always_legal, with non-empty disjoint sets, is what actually
            # pins the asymmetric short-circuit) -- not just membership in a
            # hardcoded tuple this test could drift from the real function's
            # own branches.
            assert is_boundary_crossing_safe(conversation_type, True, _EMPTY, _EMPTY) is True
