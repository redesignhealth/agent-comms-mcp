"""Unit tests for the TECH-5877 deterministic proposal judge.

``service.evaluate_linear_progress_update_judge`` is a pure function
(proposal ``action`` dict -> ``(status, decision_note)``), independent of
the HTTP layer and the DB -- these tests exercise it directly with no
Postgres fixture needed.
"""

from __future__ import annotations

from service import evaluate_linear_progress_update_judge


class TestOpenTicket:
    def test_open_ticket_with_source_message_url_is_approved(self) -> None:
        status, note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "approved"
        assert note is not None

    def test_open_ticket_without_citation_stays_pending(self) -> None:
        status, note = evaluate_linear_progress_update_judge(
            {"action_type": "open_ticket", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        assert note is None

    def test_open_ticket_with_only_confidence_is_not_sufficient(self) -> None:
        """A bare confidence score is explicitly NOT a valid substitute for
        a citable field (TECH-5877 spec)."""
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "confidence": "high",
                "rationale": "I am very sure this ticket should be opened.",
            }
        )
        assert status == "pending"

    def test_open_ticket_with_empty_string_citation_stays_pending(self) -> None:
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "",
            }
        )
        assert status == "pending"

    def test_open_ticket_with_resolving_pr_url_only_stays_pending(self) -> None:
        """resolving_pr_url is a CLOSE-ticket citation only -- it must not
        satisfy the open-ticket rule."""
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "resolving_pr_url": "https://github.com/org/repo/pull/1",
            }
        )
        assert status == "pending"


class TestCloseTicket:
    def test_close_ticket_with_source_message_url_is_approved(self) -> None:
        status, note = evaluate_linear_progress_update_judge(
            {
                "action_type": "close_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "approved"
        assert note is not None

    def test_close_ticket_with_resolving_pr_url_is_approved(self) -> None:
        status, note = evaluate_linear_progress_update_judge(
            {
                "action_type": "close_ticket",
                "target_id": "TECH-1234",
                "resolving_pr_url": "https://github.com/org/repo/pull/42",
            }
        )
        assert status == "approved"
        assert note is not None

    def test_close_ticket_without_either_citation_stays_pending(self) -> None:
        status, note = evaluate_linear_progress_update_judge(
            {"action_type": "close_ticket", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        assert note is None


class TestOtherActionTypes:
    def test_status_change_short_of_closing_stays_pending_even_with_citation(self) -> None:
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "update_status",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"

    def test_project_reassignment_stays_pending_even_with_citation(self) -> None:
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "reassign_project",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
                "resolving_pr_url": "https://github.com/org/repo/pull/42",
            }
        )
        assert status == "pending"

    def test_priority_change_stays_pending_even_with_citation(self) -> None:
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "change_priority",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"

    def test_missing_action_type_stays_pending(self) -> None:
        status, _note = evaluate_linear_progress_update_judge({"target_id": "TECH-1234"})
        assert status == "pending"
