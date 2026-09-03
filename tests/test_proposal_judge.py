"""Unit tests for the TECH-5877 deterministic proposal judge.

``service.evaluate_linear_progress_update_judge`` is a pure function
(proposal ``action`` dict -> ``(status, decision_note)``), independent of
the HTTP layer and the DB -- these tests exercise it directly with no
Postgres fixture needed.
"""

from __future__ import annotations

import pytest

from models import PROPOSAL_HOLD_LEVELS
from service import (
    _PROPOSAL_JUDGES,
    _derive_proposal_priority,
    evaluate_linear_progress_update_judge,
)

# Kind -> a representative ``action`` dict for that kind, used only to drive
# _derive_proposal_priority's branch for the kind (not the judge itself).
_REPRESENTATIVE_ACTIONS: dict[str, dict[str, object]] = {
    "linear_progress_update": {"action_type": "open_ticket", "target_id": "TECH-1234"},
}


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

    def test_open_ticket_with_whitespace_only_citation_stays_pending(self) -> None:
        """Argus review B4: a whitespace-shaped string must not be
        treated as a real citation -- presence of ANY non-empty string
        was the exact hole B4 closes."""
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "   ",
            }
        )
        assert status == "pending"

    def test_open_ticket_with_non_http_scheme_citation_stays_pending(self) -> None:
        """Argus review B4: a non-http(s) scheme (e.g. a bot writing its
        own internal ``bot://`` pointer) must not satisfy the citation
        check even though it is a well-formed, non-empty URL string."""
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "ftp://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"

    def test_open_ticket_with_non_allowlisted_host_citation_stays_pending(self) -> None:
        """Argus review B4: an http(s) URL on a host OUTSIDE the
        slack.com/github.com allowlist (e.g. a bot's own fully-controlled
        domain) must not satisfy the citation check -- this is the exact
        self-approval hole presence-only checking left open."""
        status, _note = evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "https://not-slack-or-github.example/p123",
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


class TestPriorityRegistryParity:
    """Argus review: guards against ``_PROPOSAL_JUDGES`` and
    ``_derive_proposal_priority`` drifting apart. Every ``kind`` registered
    as a judge must also have a working priority-derivation branch -- if a
    future kind is added to ``_PROPOSAL_JUDGES`` without a matching branch,
    this test fails immediately (via the ``AssertionError`` guard in
    ``_derive_proposal_priority``) instead of that gap surfacing as an
    unhandled 500 in production. Trivially passes today since only
    ``linear_progress_update`` is registered; a missing entry in
    ``_REPRESENTATIVE_ACTIONS`` for a new kind is itself a signal this test
    needs updating alongside the new registration."""

    @pytest.mark.parametrize("kind", sorted(_PROPOSAL_JUDGES.keys()))
    def test_every_registered_kind_derives_a_valid_priority(self, kind: str) -> None:
        action = _REPRESENTATIVE_ACTIONS[kind]
        priority = _derive_proposal_priority(kind, action)
        assert priority in PROPOSAL_HOLD_LEVELS
