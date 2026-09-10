"""Unit tests for the TECH-5877 deterministic proposal judge.

``service.evaluate_linear_progress_update_judge`` is a thin async wrapper
(proposal ``action`` dict -> ``(status, decision_note)``) over the
``(kind, action_type)``-scoped async rule registry (``_PROPOSAL_RULES``/
``_PROPOSAL_KIND_DEFAULT_RULE``), independent of the HTTP layer and the DB
-- these tests exercise it directly with no Postgres fixture needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

import github_client
import identity_map
import linear_client
from github_client import GitHubAPIError

# This test intentionally imports private (underscore-prefixed) symbols from
# ``service`` -- ``_PROPOSAL_RULES``, ``_PROPOSAL_KIND_DEFAULT_RULE``,
# ``_rule_always_pending``, and ``_derive_proposal_priority`` -- rather than
# only the public ``evaluate_linear_progress_update_judge``. The
# registry-parity check below needs to introspect the rule registry itself
# (not just exercise one rule's behavior), so there's no public API that
# would let it do that. If these symbols are ever renamed, this import must
# be updated to match -- expect that rename to surface only as a test-
# collection failure here, not a runtime error elsewhere.
from linear_client import LinearAPIError
from models import PROPOSAL_HOLD_LEVELS
from service import (
    _PROPOSAL_KIND_DEFAULT_RULE,
    _PROPOSAL_RULES,
    _derive_proposal_priority,
    _pull_request_references_ticket,
    _rule_always_pending,
    evaluate_linear_progress_update_judge,
)

# Kind -> list of (representative ``action`` dict, expected priority) pairs
# for that kind, used only to drive/verify _derive_proposal_priority's
# branches for the kind (not any one rule's behavior). Each entry should
# cover a DISTINCT branch of _derive_proposal_priority (e.g. open_ticket ->
# medium, close_ticket -> high, anything else -> low) so the parametrized
# test below exercises every branch, not just one.
#
# NOTE: adding a new ``kind`` to ``_PROPOSAL_KIND_DEFAULT_RULE`` in
# service.py requires updating THREE places, only two of which are enforced
# by this test file's own failure modes:
#   1. ``_PROPOSAL_KIND_DEFAULT_RULE`` (service.py) -- the fallback-rule
#      registry itself (the single source of truth for supported kinds).
#   2. The matching branch in ``_derive_proposal_priority`` (service.py) --
#      enforced by the ``AssertionError`` guard there.
#   3. ``_REPRESENTATIVE_ACTIONS`` below -- NOT enforced by that guard; a
#      missing entry here instead raises a ``KeyError`` at test-collection/
#      parametrization time (see ``test_every_registered_kind_derives_a_valid_priority``
#      below). Keep this dict in sync with every kind registered in
#      ``_PROPOSAL_KIND_DEFAULT_RULE``.
_REPRESENTATIVE_ACTIONS: dict[str, list[tuple[dict[str, object], str]]] = {
    "linear_progress_update": [
        # TECH-5873 redefinition: open_ticket's target_id is the PR URL
        # that originated the proposal, not a pre-existing Linear issue id
        # (there is no pre-existing issue -- open_ticket creates one) --
        # see service._extract_proposal_target's docstring.
        (
            {"action_type": "open_ticket", "target_id": "https://github.com/org/repo/pull/1"},
            "medium",
        ),
        ({"action_type": "close_ticket", "target_id": "TECH-1234"}, "high"),
        # TECH-5877: the four new lanes -- review_ticket joins open_ticket
        # at "medium"; start_ticket/assign_ticket/label_ticket fall through
        # to the same "low" default as any other unrecognized action_type
        # (already covered by reassign_project below), but are listed
        # explicitly here per their own dedicated priority-derivation spec.
        ({"action_type": "review_ticket", "target_id": "TECH-1234"}, "medium"),
        ({"action_type": "start_ticket", "target_id": "TECH-1234"}, "low"),
        ({"action_type": "assign_ticket", "target_id": "TECH-1234"}, "low"),
        ({"action_type": "label_ticket", "target_id": "TECH-1234"}, "low"),
        ({"action_type": "reassign_project", "target_id": "TECH-1234"}, "low"),
    ],
}


class TestOpenTicket:
    async def test_open_ticket_with_citation_target_id_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``target_id`` IS the citation for ``open_ticket`` -- see
        ``service._rule_open_ticket``'s docstring for the dedup/citation
        unification this replaces (a previously-separate
        ``source_message_url`` field is no longer read at all).

        Requires ``title``/``team`` (the applier's required fields, Argus
        review: rule/applier precondition mismatch) and a real, existing
        cited PR (Argus review: PR-existence check) -- both added as
        preconditions for auto-approval in this round."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://github.com/org/repo/pull/1",
                "title": "New issue title",
                "team": "TECH",
            }
        )
        assert status == "approved"
        assert note is not None
        mock_fetch_pr.assert_awaited_once_with("org", "repo", 1)

    async def test_open_ticket_missing_title_stays_pending_without_fetching_pr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: rule/applier precondition mismatch --
        ``linear_client.apply_open_ticket`` requires ``title``, so a
        proposal missing it must never auto-approve. Checked before any
        network call."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_open_ticket_missing_team_stays_pending_without_fetching_pr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: rule/applier precondition mismatch --
        ``linear_client.apply_open_ticket`` requires ``team``, so a
        proposal missing it must never auto-approve. Checked before any
        network call."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://github.com/org/repo/pull/1",
                "title": "New issue title",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_open_ticket_nonexistent_pr_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: this rule previously approved on URL shape
        alone, never confirming the cited PR was real. A 404/not-found
        (or any other) ``GitHubAPIError`` propagates uncaught -- same
        fail-closed contract as ``_rule_start_ticket`` -- resolving to
        ``"pending"`` via ``create_proposal``'s own wrapper in
        production."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(side_effect=GitHubAPIError("404 Not Found")),
        )
        with pytest.raises(GitHubAPIError):
            await evaluate_linear_progress_update_judge(
                {
                    "action_type": "open_ticket",
                    "target_id": "https://github.com/org/repo/pull/1",
                    "title": "New issue title",
                    "team": "TECH",
                }
            )

    async def test_open_ticket_merged_pr_is_still_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``open_ticket`` deliberately does NOT gate on PR ``state``
        (unlike ``start_ticket``/``review_ticket``): its purpose is to
        document a SHIPPED PR, so a merged/closed PR is the plausible
        expected case, not just an open one."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"state": "closed", "merged": True}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://github.com/org/repo/pull/1",
                "title": "New issue title",
                "team": "TECH",
            }
        )
        assert status == "approved"

    async def test_open_ticket_with_target_state_stays_pending_without_fetching_pr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review round-3 B3: target/workflow state is deliberately
        not bot-controllable via the action payload in auto-approval. If
        a proposal specifies a target_state, it is held for human review
        (pending) instead of auto-approved. Checked before any network call."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://github.com/org/repo/pull/1",
                "title": "New issue title",
                "team": "TECH",
                "target_state": "Done",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_open_ticket_with_target_state_none_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit target_state=None behaves the same as omitting it --
        auto-created issues land in the team's default workflow state."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://github.com/org/repo/pull/1",
                "title": "New issue title",
                "team": "TECH",
                "target_state": None,
            }
        )
        assert status == "approved"
        assert note is not None
        mock_fetch_pr.assert_awaited_once_with("org", "repo", 1)

    async def test_open_ticket_slack_hosted_pr_shaped_url_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: host-confusion hole -- a Slack URL shaped like a
        GitHub PR path (``.../owner/repo/pull/123``) must not be treated
        as a real GitHub PR reference just because it matches that path
        shape."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://redesignhealth.slack.com/owner/repo/pull/1",
                "title": "New issue title",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_open_ticket_with_slack_only_citation_stays_pending(self) -> None:
        """Argus review: ``open_ticket``'s whole intent is to document a
        SHIPPED PR -- a Slack permalink, though a valid citation URL under
        the GENERAL allowlist (``_is_valid_citation_url``, which also
        accepts Slack for other action types), proves no such artifact
        and must not auto-approve creating a brand-new Linear issue."""
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"
        assert note is None

    async def test_open_ticket_without_citation_stays_pending(self) -> None:
        status, note = await evaluate_linear_progress_update_judge(
            {"action_type": "open_ticket", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        assert note is None

    async def test_open_ticket_with_only_confidence_is_not_sufficient(self) -> None:
        """A bare confidence score is explicitly NOT a valid substitute for
        a citable field (TECH-5877 spec)."""
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "confidence": "high",
                "rationale": "I am very sure this ticket should be opened.",
            }
        )
        assert status == "pending"

    async def test_open_ticket_with_empty_string_target_id_stays_pending(self) -> None:
        """``_extract_proposal_target`` rejects an empty-string
        ``target_id`` before the judge ever runs, but the judge must fail
        closed on one too (e.g. reached via a manual human approval path
        rather than ``create_proposal``)."""
        status, _note = await evaluate_linear_progress_update_judge(
            {"action_type": "open_ticket", "target_id": ""}
        )
        assert status == "pending"

    async def test_open_ticket_with_resolving_pr_url_field_alone_stays_pending(self) -> None:
        """``resolving_pr_url`` is a CLOSE-ticket citation field, not read
        by ``open_ticket`` at all -- a non-citation ``target_id`` must not
        be rescued by a valid citation sitting in a different field."""
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "TECH-1234",
                "resolving_pr_url": "https://github.com/org/repo/pull/1",
            }
        )
        assert status == "pending"

    async def test_open_ticket_with_whitespace_only_target_id_stays_pending(self) -> None:
        """Argus review B4: a whitespace-shaped string must not be
        treated as a real citation -- presence of ANY non-empty string
        was the exact hole B4 closes."""
        status, _note = await evaluate_linear_progress_update_judge(
            {"action_type": "open_ticket", "target_id": "   "}
        )
        assert status == "pending"

    async def test_open_ticket_with_non_http_scheme_target_id_stays_pending(self) -> None:
        """Argus review B4: a non-http(s) scheme (e.g. a bot writing its
        own internal ``bot://`` pointer) must not satisfy the citation
        check even though it is a well-formed, non-empty URL string."""
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "ftp://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"

    async def test_open_ticket_with_non_allowlisted_host_target_id_stays_pending(self) -> None:
        """Argus review B4: an http(s) URL on a host OUTSIDE the
        slack.com/github.com allowlist (e.g. a bot's own fully-controlled
        domain) must not satisfy the citation check -- this is the exact
        self-approval hole presence-only checking left open."""
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "https://not-slack-or-github.example/p123",
            }
        )
        assert status == "pending"

    async def test_open_ticket_bogus_non_url_target_id_never_approves_even_with_real_citation_elsewhere(  # noqa: E501
        self,
    ) -> None:
        """The exact exploit this fix closes: a bot can no longer stash a
        real, valid citation in an unrelated/legacy field
        (``source_message_url``) while submitting an arbitrary,
        non-citation ``target_id`` for dedup purposes. Since the judge now
        reads ONLY ``target_id``, a bogus ``target_id`` never approves
        regardless of what else is in the action payload."""
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "open_ticket",
                "target_id": "not-a-url-at-all",
                "source_message_url": "https://github.com/org/repo/pull/1",
            }
        )
        assert status == "pending"
        assert note is None


class TestCloseTicket:
    async def test_close_ticket_with_source_message_url_is_approved(self) -> None:
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "close_ticket",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "approved"
        assert note is not None

    async def test_close_ticket_with_resolving_pr_url_is_approved(self) -> None:
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "close_ticket",
                "target_id": "TECH-1234",
                "resolving_pr_url": "https://github.com/org/repo/pull/42",
            }
        )
        assert status == "approved"
        assert note is not None

    async def test_close_ticket_without_either_citation_stays_pending(self) -> None:
        status, note = await evaluate_linear_progress_update_judge(
            {"action_type": "close_ticket", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        assert note is None


_OPEN_PR = {"state": "open", "title": "Fix TECH-1234"}
_CLOSED_PR = {"state": "closed"}
_BACKLOG_STATE = {"id": "s0", "name": "Backlog", "type": "backlog"}
_IN_PROGRESS_STATE = {"id": "s1", "name": "In Progress", "type": "started"}
_DONE_STATE = {"id": "s2", "name": "Done", "type": "completed"}


class TestStartTicket:
    """``(kind="linear_progress_update", action_type="start_ticket")`` --
    target workflow state "In Progress". ``github_client.fetch_pull_request``
    and ``linear_client.fetch_issue`` are monkeypatched directly on the
    shared module objects (the same objects ``service.py``'s
    module-level ``import github_client``/``import linear_client`` bind
    to), same idiom as ``tests/test_linear_client.py``'s
    ``TestApplyOpenTicket``."""

    async def test_open_pr_and_backward_state_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(github_client, "fetch_pull_request", AsyncMock(return_value=_OPEN_PR))
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(return_value={"state": _BACKLOG_STATE})
        )
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "approved"
        assert note is not None

    async def test_without_citation_stays_pending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_fetch_pr = AsyncMock(return_value=_OPEN_PR)
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {"action_type": "start_ticket", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_non_allowlisted_host_citation_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_fetch_pr = AsyncMock(return_value=_OPEN_PR)
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://evil.example/org/repo/pull/1",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_slack_hosted_pr_shaped_url_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review round-3 S4: host-confusion hole -- a Slack URL shaped
        like a GitHub PR path must not be treated as a real GitHub PR
        reference just because it matches that path shape."""
        mock_fetch_pr = AsyncMock()
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://redesignhealth.slack.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_non_pr_shaped_github_url_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A valid, allowlisted ``github.com`` URL that isn't shaped like a
        PR URL (e.g. a branch URL) must not reach ``fetch_pull_request`` at
        all -- ``parse_pull_request_url`` returning ``None`` short-circuits
        first."""
        mock_fetch_pr = AsyncMock(return_value=_OPEN_PR)
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/tree/main",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_closed_pr_stays_pending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_fetch_issue = AsyncMock(return_value={"state": _BACKLOG_STATE})
        monkeypatch.setattr(github_client, "fetch_pull_request", AsyncMock(return_value=_CLOSED_PR))
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_issue.assert_not_awaited()

    async def test_open_pr_not_referencing_target_ticket_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An open PR that doesn't reference ``target_id`` anywhere in its
        ``head.ref``/``title``/``body`` must not justify advancing this
        ticket to In Progress -- otherwise any open PR on an unrelated
        ticket could be cited."""
        mock_fetch_issue = AsyncMock(return_value={"state": _BACKLOG_STATE})
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"state": "open", "title": "Fix something unrelated"}),
        )
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_issue.assert_not_awaited()

    async def test_missing_target_id_stays_pending_without_fetching_pr_or_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: the ``target_id`` presence/non-empty check must
        run BEFORE any network call, not after ``fetch_pull_request`` --
        an earlier version wasted a round-trip on a proposal that was
        always going to stay pending regardless of the PR fetch's
        result."""
        mock_fetch_pr = AsyncMock(return_value=_OPEN_PR)
        mock_fetch_issue = AsyncMock(return_value={"state": _BACKLOG_STATE})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()
        mock_fetch_issue.assert_not_awaited()

    async def test_missing_team_stays_pending_without_fetching_pr_or_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: rule/applier precondition mismatch --
        ``linear_client.apply_start_ticket`` requires ``team``, so a
        proposal missing it must never auto-approve. Checked before any
        network call."""
        mock_fetch_pr = AsyncMock(return_value=_OPEN_PR)
        mock_fetch_issue = AsyncMock(return_value={"state": _BACKLOG_STATE})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()
        mock_fetch_issue.assert_not_awaited()

    async def test_already_in_progress_state_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Equal-rank (no-op) transition -- universal forward-only rule."""
        monkeypatch.setattr(github_client, "fetch_pull_request", AsyncMock(return_value=_OPEN_PR))
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_state_past_in_progress_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backward transition (already Done) -- must never auto-approve
        moving a ticket "back" to In Progress."""
        monkeypatch.setattr(github_client, "fetch_pull_request", AsyncMock(return_value=_OPEN_PR))
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(return_value={"state": _DONE_STATE})
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "start_ticket",
                "target_id": "TECH-1234",
                "starting_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_github_api_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The rule itself must not swallow a GitHub API failure -- it
        propagates uncaught here (this file exercises the rule directly);
        ``create_proposal``'s own fail-closed wrapper (covered generically
        by ``tests/test_proposal_service.py::
        TestJudgeIntegration::test_rule_exception_fails_closed_to_pending``)
        is what turns that into a "pending" result in production."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(side_effect=GitHubAPIError("boom")),
        )
        with pytest.raises(GitHubAPIError):
            await evaluate_linear_progress_update_judge(
                {
                    "action_type": "start_ticket",
                    "target_id": "TECH-1234",
                    "starting_pr_url": "https://github.com/org/repo/pull/1",
                    "team": "TECH",
                }
            )

    async def test_linear_api_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(github_client, "fetch_pull_request", AsyncMock(return_value=_OPEN_PR))
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(side_effect=LinearAPIError("boom"))
        )
        with pytest.raises(LinearAPIError):
            await evaluate_linear_progress_update_judge(
                {
                    "action_type": "start_ticket",
                    "target_id": "TECH-1234",
                    "starting_pr_url": "https://github.com/org/repo/pull/1",
                    "team": "TECH",
                }
            )


class TestReviewTicket:
    """``(kind="linear_progress_update", action_type="review_ticket")`` --
    same overall shape as ``TestStartTicket`` above, but additionally
    requires review-requested on the cited PR, and targets "In Review"."""

    async def test_open_pr_with_reviewers_requested_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "state": "open",
                    "requested_reviewers": [{"login": "reviewer1"}],
                    "requested_teams": [],
                    "title": "Fix TECH-1234",
                }
            ),
        )
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        )
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "approved"
        assert note is not None

    async def test_open_pr_with_only_teams_requested_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``requested_reviewers`` OR ``requested_teams`` -- either alone
        is sufficient."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "state": "open",
                    "requested_reviewers": [],
                    "requested_teams": [{"slug": "team1"}],
                    "title": "Fix TECH-1234",
                }
            ),
        )
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "approved"

    async def test_open_pr_with_no_review_requested_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_fetch_issue = AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={"state": "open", "requested_reviewers": [], "requested_teams": []}
            ),
        )
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_issue.assert_not_awaited()

    async def test_slack_hosted_pr_shaped_url_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review round-3 S4: host-confusion hole -- a Slack URL shaped
        like a GitHub PR path must not be treated as a real GitHub PR
        reference just because it matches that path shape."""
        mock_fetch_pr = AsyncMock()
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://redesignhealth.slack.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_closed_pr_stays_pending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "state": "closed",
                    "requested_reviewers": [{"login": "reviewer1"}],
                    "requested_teams": [],
                }
            ),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_open_pr_with_review_requested_but_not_referencing_target_ticket_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An open PR with review requested that doesn't reference
        ``target_id`` anywhere in its ``head.ref``/``title``/``body``
        must not justify advancing this ticket to In Review -- otherwise
        any such PR on an unrelated ticket could be cited."""
        mock_fetch_issue = AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "state": "open",
                    "requested_reviewers": [{"login": "reviewer1"}],
                    "requested_teams": [],
                    "title": "Fix something unrelated",
                }
            ),
        )
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_issue.assert_not_awaited()

    async def test_without_citation_stays_pending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_fetch_pr = AsyncMock()
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {"action_type": "review_ticket", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_missing_target_id_stays_pending_without_fetching_pr_or_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: the ``target_id`` presence/non-empty check must
        run BEFORE any network call -- see the identical fix/test in
        ``TestStartTicket``."""
        mock_fetch_pr = AsyncMock(
            return_value={
                "state": "open",
                "requested_reviewers": [{"login": "reviewer1"}],
                "requested_teams": [],
            }
        )
        mock_fetch_issue = AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()
        mock_fetch_issue.assert_not_awaited()

    async def test_missing_team_stays_pending_without_fetching_pr_or_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: rule/applier precondition mismatch --
        ``linear_client.apply_review_ticket`` requires ``team``, so a
        proposal missing it must never auto-approve. Checked before any
        network call."""
        mock_fetch_pr = AsyncMock(
            return_value={
                "state": "open",
                "requested_reviewers": [{"login": "reviewer1"}],
                "requested_teams": [],
            }
        )
        mock_fetch_issue = AsyncMock(return_value={"state": _IN_PROGRESS_STATE})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()
        mock_fetch_issue.assert_not_awaited()

    async def test_already_in_review_state_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Equal-rank (no-op) transition."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "state": "open",
                    "requested_reviewers": [{"login": "reviewer1"}],
                    "requested_teams": [],
                }
            ),
        )
        monkeypatch.setattr(
            linear_client,
            "fetch_issue",
            AsyncMock(return_value={"state": {"id": "s3", "name": "In Review", "type": "started"}}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_state_past_in_review_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backward transition (already Done)."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "state": "open",
                    "requested_reviewers": [{"login": "reviewer1"}],
                    "requested_teams": [],
                }
            ),
        )
        monkeypatch.setattr(
            linear_client, "fetch_issue", AsyncMock(return_value={"state": _DONE_STATE})
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "review_ticket",
                "target_id": "TECH-1234",
                "review_pr_url": "https://github.com/org/repo/pull/1",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_github_api_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(side_effect=GitHubAPIError("boom")),
        )
        with pytest.raises(GitHubAPIError):
            await evaluate_linear_progress_update_judge(
                {
                    "action_type": "review_ticket",
                    "target_id": "TECH-1234",
                    "review_pr_url": "https://github.com/org/repo/pull/1",
                    "team": "TECH",
                }
            )


class TestPullRequestReferencesTicket:
    """Direct unit coverage of ``_pull_request_references_ticket`` (used by
    ``_rule_assign_ticket``) -- Argus review: identifier collision. A
    plain substring check let ``"TECH-1"`` match inside ``"TECH-10"``/
    ``"TECH-100"``/``"TECH-123"``; the fix is a word-boundary regex match
    instead."""

    def test_exact_match_in_title(self) -> None:
        pr = {"title": "Fix TECH-1", "body": None, "head": {"ref": "fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is True

    def test_case_insensitive_match_in_head_ref(self) -> None:
        pr = {"title": "Fix something", "body": None, "head": {"ref": "tech-1-fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is True

    def test_does_not_match_as_prefix_of_longer_identifier_in_body(self) -> None:
        """The exact collision this fix closes: ``"TECH-1"`` must NOT
        match a PR that references the unrelated ticket ``"TECH-10"``."""
        pr = {"title": "Fix something", "body": "Fixes TECH-10", "head": {"ref": "fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is False

    def test_does_not_match_as_prefix_of_TECH_100(self) -> None:  # noqa: N802
        pr = {"title": "Fix something", "body": "Fixes TECH-100", "head": {"ref": "fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is False

    def test_does_not_match_as_prefix_of_TECH_123(self) -> None:  # noqa: N802
        pr = {"title": "Fixes TECH-123", "body": None, "head": {"ref": "fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is False

    def test_no_reference_anywhere_returns_false(self) -> None:
        pr = {"title": "Unrelated", "body": "nothing here", "head": {"ref": "fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is False

    def test_matches_with_trailing_punctuation(self) -> None:
        pr = {"title": "Fixes TECH-1.", "body": None, "head": {"ref": "fix"}}
        assert _pull_request_references_ticket(pr, "TECH-1") is True


class TestAssignTicket:
    """``(kind="linear_progress_update", action_type="assign_ticket")`` --
    no workflow-state concept: the PR's ACTUAL author (never a bot-asserted
    claim) must be present in ``identity_map.GITHUB_LOGIN_TO_LINEAR_USER_ID``
    and map to the proposed ``assignee_id``, AND the cited PR must actually
    reference ``target_id`` (the ticket being assigned)."""

    async def test_mapped_author_matching_assignee_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            identity_map,
            "GITHUB_LOGIN_TO_LINEAR_USER_ID",
            {"octocat": "user-uuid-1"},
        )
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"user": {"login": "octocat"}, "title": "Fix TECH-1234"}),
        )
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "approved"
        assert note is not None

    async def test_unmapped_login_stays_pending_even_if_assignee_id_coincidentally_matches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exact self-approval hole this lane closes: the PR's real
        author ("someone-else") is NOT in the identity map, so a bot
        proposing ``assignee_id="user-uuid-1"`` (which happens to be some
        OTHER, mapped user's id) must never auto-approve on that
        coincidence alone."""
        monkeypatch.setattr(
            identity_map,
            "GITHUB_LOGIN_TO_LINEAR_USER_ID",
            {"octocat": "user-uuid-1"},
        )
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"user": {"login": "someone-else"}}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"

    async def test_mapped_login_with_mismatched_assignee_id_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            identity_map,
            "GITHUB_LOGIN_TO_LINEAR_USER_ID",
            {"octocat": "user-uuid-1"},
        )
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"user": {"login": "octocat"}}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-2",
            }
        )
        assert status == "pending"

    async def test_empty_identity_map_never_approves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression coverage for the placeholder/empty
        ``identity_map.GITHUB_LOGIN_TO_LINEAR_USER_ID`` this lane ships
        with today -- fails safe/inert by construction until populated."""
        monkeypatch.setattr(identity_map, "GITHUB_LOGIN_TO_LINEAR_USER_ID", {})
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"user": {"login": "octocat"}}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"

    async def test_without_citation_stays_pending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_fetch_pr = AsyncMock()
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_missing_target_id_stays_pending_without_fetching_pr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review round-3 S6: target_id presence/non-empty must be
        checked BEFORE any network call, not after fetch_pull_request."""
        mock_fetch_pr = AsyncMock()
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_slack_hosted_pr_shaped_url_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: host-confusion hole -- a Slack URL shaped like a
        GitHub PR path must not be treated as a real GitHub PR reference
        just because it matches that path shape."""
        mock_fetch_pr = AsyncMock()
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://redesignhealth.slack.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_missing_author_login_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            identity_map, "GITHUB_LOGIN_TO_LINEAR_USER_ID", {"octocat": "user-uuid-1"}
        )
        monkeypatch.setattr(
            github_client, "fetch_pull_request", AsyncMock(return_value={"user": None})
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"

    async def test_never_consults_workflow_order_or_fetches_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No workflow-state concept applies to a reassignment -- this
        rule must never fetch the Linear issue at all."""
        mock_fetch_issue = AsyncMock()
        monkeypatch.setattr(
            identity_map, "GITHUB_LOGIN_TO_LINEAR_USER_ID", {"octocat": "user-uuid-1"}
        )
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"user": {"login": "octocat"}, "title": "Fix TECH-1234"}),
        )
        monkeypatch.setattr(linear_client, "fetch_issue", mock_fetch_issue)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "approved"
        mock_fetch_issue.assert_not_awaited()

    async def test_pr_not_referencing_target_ticket_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The scope gap this check closes: a correctly-mapped author is
        NOT enough on its own -- the cited PR must also actually be ABOUT
        ``target_id``, or any PR by that author could justify assigning
        them to an unrelated ticket."""
        monkeypatch.setattr(
            identity_map, "GITHUB_LOGIN_TO_LINEAR_USER_ID", {"octocat": "user-uuid-1"}
        )
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "user": {"login": "octocat"},
                    "title": "Fix something unrelated",
                    "body": "no ticket reference here",
                    "head": {"ref": "octocat/unrelated-fix"},
                }
            ),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "pending"

    async def test_pr_referencing_target_ticket_in_head_ref_is_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reference check matches case-insensitively against
        ``head.ref`` too, not just ``title``/``body`` -- a branch name
        commonly lowercases the ticket id."""
        monkeypatch.setattr(
            identity_map, "GITHUB_LOGIN_TO_LINEAR_USER_ID", {"octocat": "user-uuid-1"}
        )
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(
                return_value={
                    "user": {"login": "octocat"},
                    "title": "Fix something",
                    "body": None,
                    "head": {"ref": "octocat/tech-1234-fix"},
                }
            ),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "assign_ticket",
                "target_id": "TECH-1234",
                "assignee_pr_url": "https://github.com/org/repo/pull/1",
                "assignee_id": "user-uuid-1",
            }
        )
        assert status == "approved"

    async def test_github_api_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(side_effect=GitHubAPIError("boom")),
        )
        with pytest.raises(GitHubAPIError):
            await evaluate_linear_progress_update_judge(
                {
                    "action_type": "assign_ticket",
                    "target_id": "TECH-1234",
                    "assignee_pr_url": "https://github.com/org/repo/pull/1",
                    "assignee_id": "user-uuid-1",
                }
            )


class TestLabelTicket:
    """``(kind="linear_progress_update", action_type="label_ticket")`` --
    citation-URL-shape derivation for the label match, PLUS a live
    ``fetch_pull_request`` existence check (Argus review: this rule
    previously approved with no GitHub API call at all, letting a bot
    construct a syntactically-matching label/PR-URL pair with zero real
    artifact behind it)."""

    async def test_matching_label_is_approved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_fetch_pr = AsyncMock(return_value={"state": "open", "title": "Fix TECH-1234"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "approved"
        assert note is not None
        mock_fetch_pr.assert_awaited_once_with("org", "my-repo", 5)

    async def test_label_for_a_different_repo_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                "label_name": "target:other-repo",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_arbitrary_label_name_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                "label_name": "bug",
                "team": "TECH",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_without_citation_stays_pending(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_non_allowlisted_host_citation_stays_pending(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://evil.example/org/my-repo/pull/5",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_slack_hosted_pr_shaped_url_stays_pending(self) -> None:
        """Argus review: host-confusion hole -- a Slack URL shaped like a
        GitHub PR path must not be treated as a real GitHub PR reference
        just because it matches that path shape."""
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://redesignhealth.slack.com/org/my-repo/pull/5",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_non_pr_shaped_github_url_stays_pending(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/tree/main",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "pending"

    async def test_missing_team_stays_pending_without_fetching_pr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: rule/applier precondition mismatch --
        ``linear_client.apply_label_ticket`` requires ``team``, so a
        proposal missing it must never auto-approve. Checked before any
        network call."""
        mock_fetch_pr = AsyncMock(return_value={"state": "open"})
        monkeypatch.setattr(github_client, "fetch_pull_request", mock_fetch_pr)
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                "label_name": "target:my-repo",
            }
        )
        assert status == "pending"
        mock_fetch_pr.assert_not_awaited()

    async def test_nonexistent_pr_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Argus review: this rule previously approved with no GitHub API
        call at all -- a fabricated PR URL for a nonexistent PR must not
        satisfy it. A ``GitHubAPIError`` propagates uncaught, same
        fail-closed contract as every other rule in this registry."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(side_effect=GitHubAPIError("404 Not Found")),
        )
        with pytest.raises(GitHubAPIError):
            await evaluate_linear_progress_update_judge(
                {
                    "action_type": "label_ticket",
                    "target_id": "TECH-1234",
                    "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                    "label_name": "target:my-repo",
                    "team": "TECH",
                }
            )

    async def test_closed_pr_is_still_approved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Deliberately does NOT gate on PR ``state`` -- labeling a
        ticket based on a PR that's since been merged/closed is still a
        legitimate artifact-backed case."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"state": "closed", "merged": True, "title": "Fix TECH-1234"}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "approved"

    async def test_pr_not_referencing_target_ticket_stays_pending(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A PR that exists and matches the ``target:<repo>`` label but
        doesn't reference ``target_id`` anywhere in its
        ``head.ref``/``title``/``body`` must not justify labeling this
        ticket -- otherwise any PR in a given repo could label any
        unrelated ticket with that repo's target label."""
        monkeypatch.setattr(
            github_client,
            "fetch_pull_request",
            AsyncMock(return_value={"state": "open", "title": "Fix something unrelated"}),
        )
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "label_ticket",
                "target_id": "TECH-1234",
                "labeling_pr_url": "https://github.com/org/my-repo/pull/5",
                "label_name": "target:my-repo",
                "team": "TECH",
            }
        )
        assert status == "pending"


class TestOtherActionTypes:
    async def test_status_change_short_of_closing_stays_pending_even_with_citation(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "update_status",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"

    async def test_project_reassignment_stays_pending_even_with_citation(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "reassign_project",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
                "resolving_pr_url": "https://github.com/org/repo/pull/42",
            }
        )
        assert status == "pending"

    async def test_priority_change_stays_pending_even_with_citation(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge(
            {
                "action_type": "change_priority",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p123",
            }
        )
        assert status == "pending"

    async def test_missing_action_type_stays_pending(self) -> None:
        status, _note = await evaluate_linear_progress_update_judge({"target_id": "TECH-1234"})
        assert status == "pending"


class TestPriorityRegistryParity:
    """Argus review: guards against ``_PROPOSAL_KIND_DEFAULT_RULE`` and
    ``_derive_proposal_priority`` drifting apart. Every ``kind`` registered
    with a default rule must also have a working, correctly-branching
    priority derivation. This test can fail in two distinct ways,
    deliberately kept separate so a contributor can tell which one they hit:

    1. A new ``kind`` is registered in ``_PROPOSAL_KIND_DEFAULT_RULE`` but
       ``_REPRESENTATIVE_ACTIONS`` (this file) was never updated for it --
       this raises via the guarded lookup below (a ``pytest.fail`` with an
       explicit message), NOT via ``_derive_proposal_priority``. The dict
       lookup here happens BEFORE ``_derive_proposal_priority`` is even
       called, so the ``AssertionError`` guard described below never gets a
       chance to fire for this case.
    2. A new ``kind`` is registered in ``_PROPOSAL_KIND_DEFAULT_RULE`` but
       ``_derive_proposal_priority`` has no matching priority branch for
       it -- this raises the ``AssertionError`` guard inside
       ``_derive_proposal_priority`` itself. This is the failure mode that
       actually needs ``_REPRESENTATIVE_ACTIONS`` to have an entry, since
       the guard can only fire once ``_derive_proposal_priority`` runs.

    Trivially passes today since only ``linear_progress_update`` is
    registered."""

    @pytest.mark.parametrize("kind", sorted(_PROPOSAL_KIND_DEFAULT_RULE.keys()))
    def test_every_registered_kind_derives_a_valid_priority(self, kind: str) -> None:
        representative_actions = _REPRESENTATIVE_ACTIONS.get(kind)
        if representative_actions is None:
            pytest.fail(
                f"kind {kind!r} is registered in _PROPOSAL_KIND_DEFAULT_RULE but has no "
                "entry in _REPRESENTATIVE_ACTIONS in this test file -- add one covering "
                "every branch of _derive_proposal_priority for this kind."
            )
        for action, expected_priority in representative_actions:
            priority = _derive_proposal_priority(kind, action)
            assert priority in PROPOSAL_HOLD_LEVELS
            assert priority == expected_priority, (
                f"kind={kind!r} action={action!r}: expected priority "
                f"{expected_priority!r}, got {priority!r} -- did the priority mapping "
                "in _derive_proposal_priority change?"
            )

    def test_every_registered_kind_action_type_pair_is_in_proposal_rules_or_has_default(
        self,
    ) -> None:
        """Registry-shape parity for ``_PROPOSAL_RULES`` itself (now keyed
        by ``(kind, action_type)``): every representative action's
        ``(kind, action_type)`` pair must resolve to SOME rule -- either a
        specific entry in ``_PROPOSAL_RULES``, or the per-kind fallback in
        ``_PROPOSAL_KIND_DEFAULT_RULE`` -- so this stays a meaningful
        safety net as new ``(kind, action_type)`` lanes are registered."""
        for kind, representative_actions in _REPRESENTATIVE_ACTIONS.items():
            for action, _expected_priority in representative_actions:
                action_type = action["action_type"]
                rule = _PROPOSAL_RULES.get((kind, action_type)) or _PROPOSAL_KIND_DEFAULT_RULE.get(
                    kind
                )
                assert rule is not None, (
                    f"(kind={kind!r}, action_type={action_type!r}) has no entry in "
                    "_PROPOSAL_RULES and no fallback in _PROPOSAL_KIND_DEFAULT_RULE"
                )


class TestRuleAlwaysPending:
    """Direct coverage of the ``_rule_always_pending`` fallback rule
    itself (registry refactor), independent of
    ``evaluate_linear_progress_update_judge``'s own dispatch (already
    covered indirectly by ``TestOtherActionTypes`` above)."""

    async def test_always_returns_pending_with_no_note(self) -> None:
        status, note = await _rule_always_pending(
            {"action_type": "reassign_project", "target_id": "TECH-1234"}
        )
        assert status == "pending"
        assert note is None

    async def test_ignores_citations(self) -> None:
        """Unlike _rule_open_ticket/_rule_close_ticket, this fallback never
        auto-approves regardless of what citation fields are present."""
        status, _note = await _rule_always_pending(
            {
                "action_type": "reassign_project",
                "target_id": "TECH-1234",
                "source_message_url": "https://redesignhealth.slack.com/archives/C1/p1",
                "resolving_pr_url": "https://github.com/org/repo/pull/1",
            }
        )
        assert status == "pending"
