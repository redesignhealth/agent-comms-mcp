"""Unit tests for ``workflow_order.py`` -- pure, dependency-free logic, no
mocking required."""

from __future__ import annotations

from workflow_order import is_forward_transition


def _forward(current_type: str, current_name: str, target_type: str, target_name: str) -> bool:
    return is_forward_transition(
        current_type=current_type,
        current_name=current_name,
        target_type=target_type,
        target_name=target_name,
    )


class TestForwardAcrossTypes:
    def test_backlog_to_unstarted_is_forward(self) -> None:
        assert _forward("backlog", "Backlog", "unstarted", "Todo") is True

    def test_backlog_to_started_is_forward(self) -> None:
        assert _forward("backlog", "Backlog", "started", "In Progress") is True

    def test_backlog_to_completed_is_forward(self) -> None:
        assert _forward("backlog", "Backlog", "completed", "Done") is True

    def test_unstarted_to_started_is_forward(self) -> None:
        assert _forward("unstarted", "Todo", "started", "In Progress") is True

    def test_unstarted_to_completed_is_forward(self) -> None:
        assert _forward("unstarted", "Todo", "completed", "Done") is True

    def test_started_to_completed_is_forward(self) -> None:
        assert _forward("started", "In Progress", "completed", "Done") is True


class TestBackwardAcrossTypes:
    def test_unstarted_to_backlog_is_backward(self) -> None:
        assert _forward("unstarted", "Todo", "backlog", "Backlog") is False

    def test_started_to_backlog_is_backward(self) -> None:
        assert _forward("started", "In Progress", "backlog", "Backlog") is False

    def test_started_to_unstarted_is_backward(self) -> None:
        assert _forward("started", "In Progress", "unstarted", "Todo") is False

    def test_completed_to_backlog_is_backward(self) -> None:
        assert _forward("completed", "Done", "backlog", "Backlog") is False

    def test_completed_to_unstarted_is_backward(self) -> None:
        assert _forward("completed", "Done", "unstarted", "Todo") is False

    def test_completed_to_started_is_backward(self) -> None:
        assert _forward("completed", "Done", "started", "In Progress") is False


class TestEqualRankIsNotForward:
    def test_backlog_to_backlog_is_not_forward(self) -> None:
        assert _forward("backlog", "Backlog", "backlog", "Backlog") is False

    def test_unstarted_to_unstarted_is_not_forward(self) -> None:
        assert _forward("unstarted", "Todo", "unstarted", "Todo") is False

    def test_completed_to_completed_is_not_forward(self) -> None:
        assert _forward("completed", "Done", "completed", "Done") is False

    def test_in_progress_to_in_progress_is_not_forward(self) -> None:
        assert _forward("started", "In Progress", "started", "In Progress") is False


class TestStartedSubrankTiebreak:
    def test_in_progress_to_in_review_is_forward(self) -> None:
        assert _forward("started", "In Progress", "started", "In Review") is True

    def test_in_review_to_in_progress_is_backward(self) -> None:
        assert _forward("started", "In Review", "started", "In Progress") is False

    def test_case_insensitive_name_match_for_subrank(self) -> None:
        """The subrank lookup lowercases the name (Linear's display name
        casing is fixed, but this guards the lookup itself)."""
        assert _forward("started", "in progress", "started", "in review") is True


class TestUnknownStartedSubrankFailsClosed:
    def test_unknown_current_name_within_started_fails_closed(self) -> None:
        assert _forward("started", "Some Custom State", "started", "In Review") is False

    def test_unknown_target_name_within_started_fails_closed(self) -> None:
        assert _forward("started", "In Progress", "started", "Some Custom State") is False

    def test_unknown_current_name_within_started_fails_closed_across_types(self) -> None:
        assert _forward("started", "Some Custom State", "completed", "Done") is False

    def test_unknown_target_name_within_started_fails_closed_across_types(self) -> None:
        assert _forward("unstarted", "Todo", "started", "Some Custom State") is False


class TestUnknownTypeFailsClosed:
    def test_unknown_current_type_fails_closed(self) -> None:
        assert _forward("triage", "Triage", "started", "In Progress") is False

    def test_unknown_target_type_fails_closed(self) -> None:
        assert _forward("started", "In Progress", "duplicate", "Duplicate") is False

    def test_unknown_both_types_fails_closed(self) -> None:
        assert _forward("triage", "Triage", "duplicate", "Duplicate") is False


class TestCanceledFailsClosed:
    def test_canceled_as_current_fails_closed_even_if_target_would_be_forward(self) -> None:
        assert _forward("canceled", "Canceled", "started", "In Progress") is False

    def test_canceled_as_target_fails_closed_even_from_earlier_state(self) -> None:
        assert _forward("backlog", "Backlog", "canceled", "Canceled") is False

    def test_canceled_on_both_sides_fails_closed(self) -> None:
        assert _forward("canceled", "Canceled", "canceled", "Canceled") is False
