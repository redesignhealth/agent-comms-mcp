"""Unit tests for the TECH-5877 deterministic proposal judge.

``service.evaluate_linear_progress_update_judge`` is a pure function
(proposal ``action`` dict -> ``(status, decision_note)``), independent of
the HTTP layer and the DB -- these tests exercise it directly with no
Postgres fixture needed.
"""

from __future__ import annotations

import pytest

# This test intentionally imports private (underscore-prefixed) symbols from
# ``service`` -- ``_PROPOSAL_JUDGES`` and ``_derive_proposal_priority`` --
# rather than only the public ``evaluate_linear_progress_update_judge``. The
# registry-parity check below needs to introspect the judge registry itself
# (not just exercise one judge's behavior), so there's no public API that
# would let it do that. If these symbols are ever renamed, this import must
# be updated to match -- expect that rename to surface only as a test-
# collection failure here, not a runtime error elsewhere.
from models import PROPOSAL_HOLD_LEVELS
from service import (
    _PROPOSAL_JUDGES,
    _derive_proposal_priority,
    evaluate_linear_progress_update_judge,
)

# Kind -> list of (representative ``action`` dict, expected priority) pairs
# for that kind, used only to drive/verify _derive_proposal_priority's
# branches for the kind (not the judge itself). Each entry should cover a
# DISTINCT branch of _derive_proposal_priority (e.g. open_ticket -> medium,
# close_ticket -> high, anything else -> low) so the parametrized test below
# exercises every branch, not just one.
#
# NOTE: adding a new ``kind`` to ``_PROPOSAL_JUDGES`` in service.py requires
# updating THREE places, only two of which are enforced by this test file's
# own failure modes:
#   1. ``_PROPOSAL_JUDGES`` (service.py) -- the judge registry itself.
#   2. The matching branch in ``_derive_proposal_priority`` (service.py) --
#      enforced by the ``AssertionError`` guard there.
#   3. ``_REPRESENTATIVE_ACTIONS`` below -- NOT enforced by that guard; a
#      missing entry here instead raises a ``KeyError`` at test-collection/
#      parametrization time (see ``test_every_registered_kind_derives_a_valid_priority``
#      below). Keep this dict in sync with every kind registered in
#      ``_PROPOSAL_JUDGES``.
_REPRESENTATIVE_ACTIONS: dict[str, list[tuple[dict[str, object], str]]] = {
    "linear_progress_update": [
        ({"action_type": "open_ticket", "target_id": "TECH-1234"}, "medium"),
        ({"action_type": "close_ticket", "target_id": "TECH-1234"}, "high"),
        ({"action_type": "reassign_project", "target_id": "TECH-1234"}, "low"),
    ],
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
    as a judge must also have a working, correctly-branching priority
    derivation. This test can fail in two distinct ways, deliberately kept
    separate so a contributor can tell which one they hit:

    1. A new ``kind`` is registered in ``_PROPOSAL_JUDGES`` but
       ``_REPRESENTATIVE_ACTIONS`` (this file) was never updated for it --
       this raises via the guarded lookup below (a ``pytest.fail`` with an
       explicit message), NOT via ``_derive_proposal_priority``. The dict
       lookup here happens BEFORE ``_derive_proposal_priority`` is even
       called, so the ``AssertionError`` guard described below never gets a
       chance to fire for this case.
    2. A new ``kind`` is registered in ``_PROPOSAL_JUDGES`` but
       ``_derive_proposal_priority`` has no matching priority branch for
       it -- this raises the ``AssertionError`` guard inside
       ``_derive_proposal_priority`` itself. This is the failure mode that
       actually needs ``_REPRESENTATIVE_ACTIONS`` to have an entry, since
       the guard can only fire once ``_derive_proposal_priority`` runs.

    Trivially passes today since only ``linear_progress_update`` is
    registered."""

    @pytest.mark.parametrize("kind", sorted(_PROPOSAL_JUDGES.keys()))
    def test_every_registered_kind_derives_a_valid_priority(self, kind: str) -> None:
        representative_actions = _REPRESENTATIVE_ACTIONS.get(kind)
        if representative_actions is None:
            pytest.fail(
                f"kind {kind!r} is registered in _PROPOSAL_JUDGES but has no entry in "
                "_REPRESENTATIVE_ACTIONS in this test file -- add one covering every "
                "branch of _derive_proposal_priority for this kind."
            )
        for action, expected_priority in representative_actions:
            priority = _derive_proposal_priority(kind, action)
            assert priority in PROPOSAL_HOLD_LEVELS
            assert priority == expected_priority, (
                f"kind={kind!r} action={action!r}: expected priority "
                f"{expected_priority!r}, got {priority!r} -- did the priority mapping "
                "in _derive_proposal_priority change?"
            )
