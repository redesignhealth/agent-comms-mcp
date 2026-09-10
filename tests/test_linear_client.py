"""Unit tests for ``linear_client.py`` (TECH-5873 Argus review follow-up).

No real Postgres or Linear API is exercised -- httpx is monkeypatched at the
``httpx.AsyncClient.post`` level, same idiom as
``tests/test_plugins.py``'s ``TestWebhookNotifier``. ``asyncio_mode = "auto"``
(pyproject.toml) means async ``def test_*`` functions run without an
explicit ``pytest.mark.asyncio`` decorator.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

import linear_client
from linear_client import (
    LinearAPIError,
    LinearNotFoundError,
    LinearTokenMissingError,
    LinearTransportError,
    _post_graphql,
    _progress_comment_body,
    _require_api_token,
    add_issue_label,
    apply_assign_ticket,
    apply_label_ticket,
    apply_open_ticket,
    apply_progress_update,
    apply_review_ticket,
    apply_start_ticket,
    compute_target_fingerprint,
    create_ticket,
    fetch_current_fingerprint,
    fetch_issue,
    resolve_label_id,
    resolve_team_id,
    resolve_workflow_state_id,
    update_issue_assignee,
    update_issue_state,
)

_TOKEN_ENV_VAR = linear_client._LINEAR_API_TOKEN_ENV_VAR


def _set_fake_post(monkeypatch: pytest.MonkeyPatch, response: httpx.Response) -> None:
    async def _fake_post(
        self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
    ) -> httpx.Response:
        return response

    monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)


class TestRequireApiToken:
    def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Argus review round-7 suggestion: assert the typed subclass, not
        # just the base `LinearAPIError` -- `service._sanitize_apply_error`
        # dispatches on this exact type, so a regression back to a bare
        # `LinearAPIError` here would silently misclassify every
        # missing-token failure as the generic message.
        monkeypatch.delenv(_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(LinearTokenMissingError, match=_TOKEN_ENV_VAR):
            _require_api_token()

    def test_present_token_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        assert _require_api_token() == "tok123"


class TestPostGraphql:
    async def test_transport_error_wrapped_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")

        async def _fake_post(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            raise httpx.ConnectError("boom")

        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)
        # Argus review round-7 suggestion: assert the typed
        # `LinearTransportError` subclass -- see the same rationale on
        # `test_missing_token_raises` above.
        with pytest.raises(LinearTransportError):
            await _post_graphql("query {}", {})

    async def test_non_2xx_status_wrapped_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(500, request=httpx.Request("POST", linear_client._LINEAR_API_URL))
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearTransportError):
            await _post_graphql("query {}", {})

    async def test_json_decode_error_wrapped_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review B2: a 2xx response with a non-JSON body raises
        ``json.JSONDecodeError`` (a ``ValueError``), not an
        ``httpx.HTTPError`` -- this must still come out as a
        ``LinearAPIError``, not propagate uncaught."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=b"not json",
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearTransportError):
            await _post_graphql("query {}", {})

    async def test_graphql_errors_payload_extracts_message_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review S4: only the ``message`` field of each GraphQL
        error object should end up in the exception text -- not the raw
        error object (which may carry resolver/schema/id internals)."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        payload = {
            "errors": [
                {
                    "message": "Issue not found",
                    "extensions": {"code": "NOT_FOUND", "internalId": "secret-detail"},
                }
            ]
        }
        response = httpx.Response(
            200,
            content=json.dumps(payload).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError) as exc_info:
            await _post_graphql("query {}", {})
        message = str(exc_info.value)
        assert "Issue not found" in message
        assert "secret-detail" not in message
        assert "extensions" not in message

    async def test_missing_data_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=b"{}",
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="missing 'data'"):
            await _post_graphql("query {}", {})

    async def test_follow_redirects_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Argus review S10: SSRF-avoidance convention shared with
        ``plugins.py``'s webhook client -- ``follow_redirects=False``."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, object] = {}
        original_init = httpx.AsyncClient.__init__

        def _capturing_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)
            original_init(self, *args, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", _capturing_init)
        response = httpx.Response(
            200,
            content=json.dumps({"data": {}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        await _post_graphql("query {}", {})
        assert captured["follow_redirects"] is False


class TestComputeTargetFingerprint:
    def test_pinned_digest_for_fixed_input(self) -> None:
        """Argus review S5: pins the literal digest for a fixed input so
        any accidental change to the fingerprint scheme -- a cross-repo
        contract with whatever submits the original proposal -- breaks
        this test loudly instead of silently causing spurious 'stale'
        results everywhere. ``updatedAt`` is present in the input (a
        realistic Linear payload always carries it) but is NOT part of
        the digest (bug fix -- see ``compute_target_fingerprint``'s own
        docstring) -- this pinned value would be unaffected by changing
        it; see ``TestComputeTargetFingerprintFieldSensitivity`` below for
        that specific assertion."""
        issue = {
            "state": {"id": "state-1", "name": "In Progress"},
            "priority": 2,
            "assignee": {"id": "user-1"},
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        digest = compute_target_fingerprint(issue)
        assert digest == "cd8ec34e5c09e596c501942651f8a6f058d6153b911d714a1a7b8fa5d4be74c8"

    def test_missing_state_and_assignee_do_not_raise(self) -> None:
        digest = compute_target_fingerprint({"priority": None, "updatedAt": None})
        assert isinstance(digest, str)
        assert len(digest) == 64


class TestComputeTargetFingerprintFieldSensitivity:
    """End-to-end coverage against a realistic stubbed Linear issue
    payload (bug fix regression test): the digest must be deterministic
    and sensitive to each of the 4 fields that actually matter
    (state/priority/assignee), but -- the whole point of the
    ``updatedAt``-removal bug fix -- must NOT change when only
    ``updatedAt`` changes, since Linear bumps that on any touch to the
    issue, including this bot's own prior comment."""

    @staticmethod
    def _issue(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "id": "TECH-1234",
            "state": {"id": "state-1", "name": "In Progress"},
            "priority": 2,
            "assignee": {"id": "user-1"},
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        base.update(overrides)
        return base

    def test_deterministic_for_the_same_input(self) -> None:
        issue = self._issue()
        assert compute_target_fingerprint(issue) == compute_target_fingerprint(issue)

    def test_updated_at_alone_changing_does_not_change_digest(self) -> None:
        original = compute_target_fingerprint(self._issue())
        touched = compute_target_fingerprint(self._issue(updatedAt="2026-06-15T12:00:00.000Z"))
        assert touched == original

    def test_state_change_changes_digest(self) -> None:
        original = compute_target_fingerprint(self._issue())
        changed = compute_target_fingerprint(self._issue(state={"id": "state-2", "name": "Done"}))
        assert changed != original

    def test_priority_change_changes_digest(self) -> None:
        original = compute_target_fingerprint(self._issue())
        changed = compute_target_fingerprint(self._issue(priority=1))
        assert changed != original

    def test_assignee_change_changes_digest(self) -> None:
        original = compute_target_fingerprint(self._issue())
        changed = compute_target_fingerprint(self._issue(assignee={"id": "user-2"}))
        assert changed != original

    def test_state_type_field_does_not_affect_digest(self) -> None:
        """The GraphQL query fetches ``state.type`` (added for future judge
        rules that reason about workflow-state ordering -- see
        ``workflow_order.is_forward_transition``), but
        ``compute_target_fingerprint`` must remain fingerprint-neutral to
        that field: it reads only ``state["id"]``/``state["name"]`` out of
        ``state``, never ``state["type"]``. This asserts the digest is
        identical whether or not ``type`` is present in the fetched issue
        dict, for an otherwise-identical issue."""
        without_type = compute_target_fingerprint(
            self._issue(state={"id": "state-1", "name": "In Progress"})
        )
        with_type = compute_target_fingerprint(
            self._issue(state={"id": "state-1", "name": "In Progress", "type": "started"})
        )
        assert with_type == without_type
        # And it doesn't move the pinned digest either -- the value asserted
        # in `test_pinned_digest_for_fixed_input` above must hold regardless
        # of whether `state.type` is present in the input.
        pinned_input = {
            "state": {"id": "state-1", "name": "In Progress", "type": "started"},
            "priority": 2,
            "assignee": {"id": "user-1"},
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        assert (
            compute_target_fingerprint(pinned_input)
            == "cd8ec34e5c09e596c501942651f8a6f058d6153b911d714a1a7b8fa5d4be74c8"
        )


class TestFetchIssue:
    """``fetch_issue`` is the raw issue fetch that both
    ``fetch_current_fingerprint`` (below) and future judge rules build on."""

    async def test_returns_raw_issue_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        issue = {
            "id": "TECH-1234",
            "state": {"id": "s1", "name": "In Progress", "type": "started"},
            "priority": 1,
            "assignee": None,
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issue": issue}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        assert await fetch_issue("TECH-1234") == issue

    async def test_missing_issue_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issue": None}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="no issue"):
            await fetch_issue("TECH-1234")

    async def test_query_requests_state_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The GraphQL query sent by ``fetch_issue`` must request
        ``state.type`` -- future judge rules read it via
        ``workflow_order.is_forward_transition``."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["json"] = json
            body = (
                b'{"data": {"issue": {"state": {"id": "s1", "name": "Todo", "type": "unstarted"}}}}'
            )
            return httpx.Response(200, content=body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await fetch_issue("TECH-1234")
        assert "type" in captured["json"]["query"]


class TestFetchCurrentFingerprint:
    async def test_returns_fingerprint_for_found_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        issue = {
            "id": "TECH-1234",
            "state": {"id": "s1", "name": "Todo"},
            "priority": 1,
            "assignee": None,
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issue": issue}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        fingerprint = await fetch_current_fingerprint("TECH-1234")
        assert fingerprint == compute_target_fingerprint(issue)

    async def test_missing_issue_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issue": None}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="no issue"):
            await fetch_current_fingerprint("TECH-1234")

    async def test_unaffected_by_state_type_in_fetched_issue(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end version of
        ``TestComputeTargetFingerprintFieldSensitivity.test_state_type_field_does_not_affect_digest``:
        the fingerprint returned by ``fetch_current_fingerprint`` (which now
        fetches ``state.type`` via ``fetch_issue``) is identical to what a
        pre-``state.type`` fetch would have produced for the same
        underlying issue."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        issue_without_type = {
            "id": "TECH-1234",
            "state": {"id": "s1", "name": "In Progress"},
            "priority": 1,
            "assignee": None,
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        issue_with_type = {
            **issue_without_type,
            "state": {**issue_without_type["state"], "type": "started"},
        }

        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issue": issue_with_type}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        fingerprint_with_type = await fetch_current_fingerprint("TECH-1234")
        assert fingerprint_with_type == compute_target_fingerprint(issue_without_type)


class TestResolveTeamId:
    async def test_returns_id_for_found_team(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"teams": {"nodes": [{"id": "team-uuid-1"}]}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        assert await resolve_team_id("TECH") == "team-uuid-1"

    async def test_no_match_raises_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"teams": {"nodes": []}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearNotFoundError, match="TECH"):
            await resolve_team_id("TECH")

    async def test_multiple_matches_raises_defensively(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: same defensive multi-match guard as
        ``resolve_workflow_state_id`` -- was missing here."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {"data": {"teams": {"nodes": [{"id": "team-uuid-1"}, {"id": "team-uuid-2"}]}}}
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="expected exactly one"):
            await resolve_team_id("TECH")


class TestResolveWorkflowStateId:
    async def test_returns_id_for_found_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {"data": {"team": {"states": {"nodes": [{"id": "state-uuid-1"}]}}}}
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        assert await resolve_workflow_state_id("team-uuid-1", "In Progress") == "state-uuid-1"

    async def test_no_match_raises_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"team": {"states": {"nodes": []}}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearNotFoundError, match="In Progress"):
            await resolve_workflow_state_id("team-uuid-1", "In Progress")

    async def test_multiple_matches_raises_defensively(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus-style defensiveness: this resolver feeds a future
        auto-approve context where precision matters, so more than one
        match must raise rather than silently pick the first."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {
                    "data": {
                        "team": {
                            "states": {"nodes": [{"id": "state-uuid-1"}, {"id": "state-uuid-2"}]}
                        }
                    }
                }
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="expected exactly one"):
            await resolve_workflow_state_id("team-uuid-1", "In Progress")

    async def test_case_sensitive_no_folding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The query filters with an exact ``eq`` comparator -- a
        differently-cased request that Linear itself reports zero matches
        for must not be silently case-folded into a match here."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["variables"] = json["variables"]
            body = b'{"data": {"team": {"states": {"nodes": []}}}}'
            return httpx.Response(200, content=body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        with pytest.raises(LinearNotFoundError):
            await resolve_workflow_state_id("team-uuid-1", "in progress")
        assert captured["variables"]["name"] == "in progress"


class TestResolveLabelId:
    async def test_returns_id_for_found_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {"data": {"issueLabels": {"nodes": [{"id": "label-uuid-1"}]}}}
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        assert await resolve_label_id("team-uuid-1", "target:agent-comms-mcp") == "label-uuid-1"

    async def test_no_match_raises_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueLabels": {"nodes": []}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearNotFoundError, match="target:agent-comms-mcp"):
            await resolve_label_id("team-uuid-1", "target:agent-comms-mcp")

    async def test_multiple_matches_raises_defensively(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review: same defensive multi-match guard as
        ``resolve_workflow_state_id`` -- was missing here."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {
                    "data": {
                        "issueLabels": {"nodes": [{"id": "label-uuid-1"}, {"id": "label-uuid-2"}]}
                    }
                }
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="expected exactly one"):
            await resolve_label_id("team-uuid-1", "target:agent-comms-mcp")


_VALID_SOURCE_URL = "https://redesignhealth.slack.com/archives/C1/p123"
_VALID_PR_URL = "https://github.com/org/repo/pull/1"


class TestProgressCommentBody:
    def test_all_optional_fields_present(self) -> None:
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "source_message_url": _VALID_SOURCE_URL,
                "resolving_pr_url": _VALID_PR_URL,
            },
            "Shipped in the linked PR.",
        )
        assert "Progress update: close_ticket" in body
        assert "Shipped in the linked PR." in body
        assert f"Source: {_VALID_SOURCE_URL}" in body
        assert f"Resolved by: {_VALID_PR_URL}" in body

    def test_all_optional_fields_absent(self) -> None:
        body = _progress_comment_body({"action_type": "open_ticket"}, "")
        assert body == "Progress update: open_ticket"

    def test_default_action_type_when_missing(self) -> None:
        body = _progress_comment_body({}, "")
        assert body == "Progress update: update"

    def test_only_rationale_present(self) -> None:
        """Argus review round-5 B2: `rationale` is a top-level
        `ProposalHold` column threaded through as its own parameter, NOT
        read off the `action` dict -- a prior version of this test (and
        of the production code) incorrectly baked it into `action`."""
        body = _progress_comment_body({"action_type": "open_ticket"}, "Because.")
        assert body == "Progress update: open_ticket\n\nBecause."

    def test_only_source_message_url_present(self) -> None:
        body = _progress_comment_body(
            {"action_type": "open_ticket", "source_message_url": _VALID_SOURCE_URL}, ""
        )
        assert body == f"Progress update: open_ticket\n\nSource: {_VALID_SOURCE_URL}"

    def test_only_resolving_pr_url_present(self) -> None:
        body = _progress_comment_body(
            {"action_type": "close_ticket", "resolving_pr_url": _VALID_PR_URL}, ""
        )
        assert body == f"Progress update: close_ticket\n\nResolved by: {_VALID_PR_URL}"

    def test_non_allowlisted_source_url_on_open_ticket_raises(self) -> None:
        """Argus review S3 (re-validate) + round-3 S4 (scope the omit
        behavior to close_ticket only): open_ticket's judge rule requires
        exactly ONE field (`source_message_url`) to be valid with no
        OR-partner, so a proposal reaching here with an invalid one
        (necessarily via manual human approval, since the judge itself
        would never auto-approve this) must still raise -- there is no
        "the other field covered for it" story the way there is for
        close_ticket."""
        with pytest.raises(LinearAPIError):
            _progress_comment_body(
                {
                    "action_type": "open_ticket",
                    "source_message_url": "https://not-allowlisted.example/p123",
                },
                "",
            )

    def test_raise_path_does_not_leak_credentials_in_exception_text(self) -> None:
        """Argus review round-9 suggestion: the raise path (unlike the
        omit-and-continue path, covered by
        ``test_omit_path_warning_does_not_leak_query_string`` above) had
        no regression test proving it also redacts -- both paths call
        ``citation_urls.redact_url_for_logging`` on the SAME rejected
        value, so a future edit that redacted one path but not the other
        would only be caught here."""
        with pytest.raises(LinearAPIError) as exc_info:
            _progress_comment_body(
                {
                    "action_type": "open_ticket",
                    "source_message_url": "https://token:secret123@evil.example/p?x=y",
                },
                "",
            )
        text = str(exc_info.value)
        assert "token" not in text
        assert "secret123" not in text

    def test_malformed_ipv6_url_raises_linear_api_error_not_value_error(self) -> None:
        """Argus review round-11 suggestion: pins the no-stranding
        contract at the actual call site where the round-10 BLOCKING bug
        surfaced -- `citation_urls._safe_urlsplit` is unit-tested
        directly, but nothing at THIS seam proved that a malformed URL
        reaching `_progress_comment_body` (via `apply_progress_update`,
        called from `service._apply_or_finalize_proposal_hold`) comes out
        as a `LinearAPIError` for that function's `except
        linear_client.LinearAPIError`/`except asyncio.CancelledError`
        envelope to catch -- a bare `ValueError` escaping here is exactly
        what stranded holds at `"applying"` before round-10's fix."""
        with pytest.raises(LinearAPIError):
            _progress_comment_body(
                {
                    "action_type": "open_ticket",
                    "source_message_url": "https://[::1::2]/path",
                },
                "",
            )

    def test_non_allowlisted_source_url_on_close_ticket_is_omitted_not_raised(self) -> None:
        """Argus review round-2 B3 (skip, don't raise) for close_ticket
        specifically: a present-but-invalid field must not block the
        whole apply, since the judge's close-ticket rule only requires
        ONE of the two URL fields to be valid (OR), not both."""
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "source_message_url": "https://not-allowlisted.example/p123",
            },
            "",
        )
        assert "not-allowlisted.example" not in body
        assert body == "Progress update: close_ticket"

    def test_omit_path_warning_does_not_leak_query_string(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Argus review round-7/round-8: the omit-path warning must log a
        REDACTED form of the rejected URL (see
        `citation_urls.redact_url_for_logging`), not the raw value -- a
        query string on a URL that already failed the citation allowlist
        may carry a secret. `caplog` closes the gap Argus flagged: no
        prior test asserted anything about the log line's CONTENT, only
        about the comment body."""
        with caplog.at_level(logging.WARNING):
            body = _progress_comment_body(
                {
                    "action_type": "close_ticket",
                    "source_message_url": "https://not-allowlisted.example/p?token=secret123",
                },
                "",
            )
        assert body == "Progress update: close_ticket"
        assert any("Omitting" in r.message for r in caplog.records)
        for record in caplog.records:
            assert "token" not in record.message
            assert "secret123" not in record.message

    def test_non_allowlisted_resolving_pr_url_is_omitted_not_raised(self) -> None:
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "resolving_pr_url": "https://not-allowlisted.example/pull/1",
            },
            "",
        )
        assert "not-allowlisted.example" not in body
        assert body == "Progress update: close_ticket"

    def test_valid_source_url_kept_when_resolving_pr_url_is_invalid(self) -> None:
        """The exact round-2 B3 scenario: judge auto-approved on a valid
        `source_message_url` alone; `resolving_pr_url` is present but
        invalid. The invalid field must be dropped, not block the apply
        of the valid one."""
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "source_message_url": _VALID_SOURCE_URL,
                "resolving_pr_url": "https://not-allowlisted.example/pull/1",
            },
            "",
        )
        assert f"Source: {_VALID_SOURCE_URL}" in body
        assert "not-allowlisted.example" not in body

    def test_open_ticket_with_invalid_resolving_pr_url_is_omitted_not_raised(self) -> None:
        """Argus review round-5 B3: an earlier version of this omit-vs-raise
        decision was scoped per `action_type` alone (only close_ticket
        omitted; open_ticket always raised). That desynced from the judge
        for exactly this combination: open_ticket's judge rule never
        inspects `resolving_pr_url` at all, so an invalid one here must
        not block an otherwise judge-approved apply that only needed a
        valid `source_message_url`."""
        body = _progress_comment_body(
            {
                "action_type": "open_ticket",
                "source_message_url": _VALID_SOURCE_URL,
                "resolving_pr_url": "https://not-allowlisted.example/pull/1",
            },
            "",
        )
        assert f"Source: {_VALID_SOURCE_URL}" in body
        assert "not-allowlisted.example" not in body

    def test_both_citation_urls_invalid_on_close_ticket_omits_both(self) -> None:
        """Argus review round-3 S10: neither valid -- the resulting
        comment must carry zero citation fields, not silently keep one
        with an invalid value."""
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "source_message_url": "https://not-allowlisted.example/p123",
                "resolving_pr_url": "https://also-not-allowlisted.example/pull/1",
            },
            "",
        )
        assert "Source:" not in body
        assert "Resolved by:" not in body
        assert body == "Progress update: close_ticket"


class TestApplyProgressUpdate:
    async def test_success_true_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"commentCreate": {"success": True}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        await apply_progress_update(
            {
                "target_id": "TECH-1234",
                "action_type": "open_ticket",
                "source_message_url": _VALID_SOURCE_URL,
            },
            "Because.",
        )

    async def test_success_false_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Argus review B3: Linear's ``commentCreate.success: false`` must
        not be silently ignored."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"commentCreate": {"success": False}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="success=false"):
            await apply_progress_update(
                {
                    "target_id": "TECH-1234",
                    "action_type": "open_ticket",
                    "source_message_url": _VALID_SOURCE_URL,
                },
                "Because.",
            )

    async def test_invalid_url_on_close_ticket_is_omitted_write_still_proceeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review round-2 B3 + round-3 S4: the URL re-validation in
        ``_progress_comment_body`` OMITS a non-allowlisted URL for
        close_ticket, it does not block the write -- the judge's OR
        semantics mean the OTHER citation field (or, as here, no citation
        field at all if this is the only one and it's invalid) is what
        got this proposal approved, not this specific field. (open_ticket
        has no such OR-partner and raises instead -- see
        ``TestProgressCommentBody.test_non_allowlisted_source_url_on_open_ticket_raises``.)"""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}

        success_body = b'{"data": {"commentCreate": {"success": true}}}'

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["json"] = json
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await apply_progress_update(
            {
                "target_id": "TECH-1234",
                "action_type": "close_ticket",
                "source_message_url": "https://not-allowlisted.example/p123",
            },
            "",
        )
        assert "not-allowlisted.example" not in captured["json"]["variables"]["body"]

    async def test_rationale_reaches_the_comment_body(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review round-5 B2 regression coverage: `rationale` (a
        top-level `ProposalHold` column) must actually reach the posted
        Linear comment when threaded through as its own parameter, not
        silently dropped the way it was when the old code looked for it
        inside `action` (where it never lived in production)."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}
        success_body = b'{"data": {"commentCreate": {"success": true}}}'

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["json"] = json
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await apply_progress_update(
            {"target_id": "TECH-1234", "action_type": "open_ticket"},
            "This is the human-authored rationale.",
        )
        assert "This is the human-authored rationale." in captured["json"]["variables"]["body"]


_CREATED_ISSUE = {
    "id": "issue-uuid-1",
    "identifier": "TECH-999",
    "url": "https://linear.app/redesignhealth/issue/TECH-999",
}


class TestCreateTicket:
    """TECH-5873 redefinition: ``open_ticket`` creates a real Linear issue
    instead of commenting on an existing one -- this is the mutation that
    does it."""

    async def test_returns_id_identifier_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {"data": {"issueCreate": {"success": True, "issue": _CREATED_ISSUE}}}
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        result = await create_ticket(
            title="Fix the thing", description="Details.", team_id="team-uuid-1"
        )
        assert result == _CREATED_ISSUE

    async def test_required_fields_only_omits_optional_input_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}
        success_body = json.dumps(
            {"data": {"issueCreate": {"success": True, "issue": _CREATED_ISSUE}}}
        ).encode()

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["variables"] = json["variables"]
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await create_ticket(title="Fix the thing", description="Details.", team_id="team-uuid-1")
        assert captured["variables"]["input"] == {
            "teamId": "team-uuid-1",
            "title": "Fix the thing",
            "description": "Details.",
        }

    async def test_optional_fields_included_when_provided(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}
        success_body = json.dumps(
            {"data": {"issueCreate": {"success": True, "issue": _CREATED_ISSUE}}}
        ).encode()

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["variables"] = json["variables"]
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await create_ticket(
            title="Fix the thing",
            description="Details.",
            team_id="team-uuid-1",
            project_id="project-uuid-1",
            state_id="state-uuid-1",
        )
        assert captured["variables"]["input"] == {
            "teamId": "team-uuid-1",
            "title": "Fix the thing",
            "description": "Details.",
            "projectId": "project-uuid-1",
            "stateId": "state-uuid-1",
        }

    async def test_success_false_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueCreate": {"success": False}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="success=false"):
            await create_ticket(title="T", description="D", team_id="team-uuid-1")

    async def test_missing_issue_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {"data": {"issueCreate": {"success": True, "issue": None}}}
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="no issue"):
            await create_ticket(title="T", description="D", team_id="team-uuid-1")

    async def test_incomplete_issue_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The mutation reported success and returned an issue, but that
        issue is missing one of the three fields this function promises
        to return -- must raise rather than return a partial result."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps(
                {
                    "data": {
                        "issueCreate": {
                            "success": True,
                            "issue": {"id": "issue-uuid-1", "identifier": "TECH-999"},
                        }
                    }
                }
            ).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="incomplete issue"):
            await create_ticket(title="T", description="D", team_id="team-uuid-1")

    async def test_graphql_error_propagates_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"errors": [{"message": "Team not found"}]}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="Team not found"):
            await create_ticket(title="T", description="D", team_id="team-uuid-1")


class TestApplyOpenTicket:
    """TECH-5873 redefinition: ``apply_open_ticket`` is the applier
    ``service._apply_or_finalize_proposal_hold`` dispatches ``open_ticket``
    to. These tests mock ``resolve_team_id``/``resolve_workflow_state_id``/
    ``create_ticket`` directly (each already covered independently
    elsewhere in this file) to isolate this function's own field-reading
    and dispatch logic."""

    async def test_resolves_team_and_creates_ticket_with_no_optional_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock(return_value="team-uuid-1")
        mock_resolve_state = AsyncMock()
        mock_create_ticket = AsyncMock(return_value=_CREATED_ISSUE)
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        monkeypatch.setattr(linear_client, "resolve_workflow_state_id", mock_resolve_state)
        monkeypatch.setattr(linear_client, "create_ticket", mock_create_ticket)

        result = await apply_open_ticket(
            {
                "target_id": "https://github.com/org/repo/pull/1",
                "action_type": "open_ticket",
                "title": "Fix the thing",
                "team": "TECH",
            },
            "Because.",
        )

        mock_resolve_team.assert_awaited_once_with("TECH")
        mock_resolve_state.assert_not_awaited()
        mock_create_ticket.assert_awaited_once_with(
            title="Fix the thing",
            description="",
            team_id="team-uuid-1",
            project_id=None,
            state_id=None,
        )
        assert result == _CREATED_ISSUE

    async def test_resolves_workflow_state_when_target_state_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Passing ``target_state`` resolves it scoped to the ALREADY-
        resolved team id, then feeds the resolved state id into
        ``create_ticket`` -- letting a create-then-close proposal land the
        issue directly in its target state via ONE mutation."""
        mock_resolve_team = AsyncMock(return_value="team-uuid-1")
        mock_resolve_state = AsyncMock(return_value="state-uuid-1")
        mock_create_ticket = AsyncMock(return_value=_CREATED_ISSUE)
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        monkeypatch.setattr(linear_client, "resolve_workflow_state_id", mock_resolve_state)
        monkeypatch.setattr(linear_client, "create_ticket", mock_create_ticket)

        result = await apply_open_ticket(
            {
                "target_id": "https://github.com/org/repo/pull/1",
                "action_type": "open_ticket",
                "title": "Fix the thing",
                "description": "Details.",
                "team": "TECH",
                "project": "project-uuid-1",
                "target_state": "Done",
            },
            "Because.",
        )

        mock_resolve_team.assert_awaited_once_with("TECH")
        mock_resolve_state.assert_awaited_once_with("team-uuid-1", "Done")
        mock_create_ticket.assert_awaited_once_with(
            title="Fix the thing",
            description="Details.",
            team_id="team-uuid-1",
            project_id="project-uuid-1",
            state_id="state-uuid-1",
        )
        assert result == _CREATED_ISSUE

    async def test_missing_title_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="title"):
            await apply_open_ticket(
                {"target_id": "https://github.com/org/repo/pull/1", "team": "TECH"}, "r"
            )
        mock_resolve_team.assert_not_awaited()

    async def test_missing_team_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="team"):
            await apply_open_ticket(
                {"target_id": "https://github.com/org/repo/pull/1", "title": "Fix the thing"}, "r"
            )
        mock_resolve_team.assert_not_awaited()

    async def test_resolve_team_id_failure_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_create_ticket = AsyncMock()
        monkeypatch.setattr(
            linear_client, "resolve_team_id", AsyncMock(side_effect=LinearNotFoundError("no team"))
        )
        monkeypatch.setattr(linear_client, "create_ticket", mock_create_ticket)
        with pytest.raises(LinearNotFoundError, match="no team"):
            await apply_open_ticket(
                {
                    "target_id": "https://github.com/org/repo/pull/1",
                    "title": "Fix the thing",
                    "team": "TECH",
                },
                "r",
            )
        mock_create_ticket.assert_not_awaited()


class TestUpdateIssueState:
    """TECH-5877: moves an EXISTING issue to a new workflow state via
    ``issueUpdate(input: { stateId })``."""

    async def test_success_true_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueUpdate": {"success": True}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        await update_issue_state("issue-uuid-1", "state-uuid-1")

    async def test_sends_only_state_id_in_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}
        success_body = json.dumps({"data": {"issueUpdate": {"success": True}}}).encode()

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["variables"] = json["variables"]
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await update_issue_state("issue-uuid-1", "state-uuid-1")
        assert captured["variables"] == {"id": "issue-uuid-1", "input": {"stateId": "state-uuid-1"}}

    async def test_success_false_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueUpdate": {"success": False}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="success=false"):
            await update_issue_state("issue-uuid-1", "state-uuid-1")


class TestUpdateIssueAssignee:
    """TECH-5877: reassigns an EXISTING issue via
    ``issueUpdate(input: { assigneeId })`` -- same mutation as
    ``update_issue_state``, scoped to a different input field."""

    async def test_success_true_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueUpdate": {"success": True}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        await update_issue_assignee("issue-uuid-1", "user-uuid-1")

    async def test_sends_only_assignee_id_in_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}
        success_body = json.dumps({"data": {"issueUpdate": {"success": True}}}).encode()

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["variables"] = json["variables"]
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await update_issue_assignee("issue-uuid-1", "user-uuid-1")
        assert captured["variables"] == {
            "id": "issue-uuid-1",
            "input": {"assigneeId": "user-uuid-1"},
        }

    async def test_success_false_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueUpdate": {"success": False}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="success=false"):
            await update_issue_assignee("issue-uuid-1", "user-uuid-1")


class TestAddIssueLabel:
    """TECH-5877: adds a single label to an EXISTING issue via the
    DEDICATED ``issueAddLabel(id, labelId)`` mutation -- NOT
    ``issueUpdate(input: { labelIds })``, which REPLACES the issue's full
    label set (see ``linear_client._ISSUE_ADD_LABEL_MUTATION``'s own
    comment). This is the mechanism verified against Linear's real public
    schema for this task; these tests pin that the QUERY SENT is the
    dedicated mutation (not a ``labelIds``-based ``issueUpdate``), so a
    future edit can't silently regress back to a replace-all-labels call
    without failing here."""

    async def test_success_true_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueAddLabel": {"success": True}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        await add_issue_label("issue-uuid-1", "label-uuid-1")

    async def test_uses_dedicated_add_label_mutation_not_replace_all_labels(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, Any] = {}
        success_body = json.dumps({"data": {"issueAddLabel": {"success": True}}}).encode()

        async def _capture(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            captured["json"] = json
            return httpx.Response(200, content=success_body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _capture)
        await add_issue_label("issue-uuid-1", "label-uuid-1")
        assert "issueAddLabel" in captured["json"]["query"]
        assert "labelIds" not in captured["json"]["query"]
        assert captured["json"]["variables"] == {"id": "issue-uuid-1", "labelId": "label-uuid-1"}

    async def test_success_false_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=json.dumps({"data": {"issueAddLabel": {"success": False}}}).encode(),
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="success=false"):
            await add_issue_label("issue-uuid-1", "label-uuid-1")


class TestApplyStartTicket:
    """TECH-5877: applier for ``action_type="start_ticket"`` -- resolves
    team + "In Progress" state, then moves the issue there. Mocks
    ``resolve_team_id``/``resolve_workflow_state_id``/``update_issue_state``
    directly (each already covered independently elsewhere in this file),
    same idiom as ``TestApplyOpenTicket``."""

    async def test_resolves_team_and_in_progress_state_then_updates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock(return_value="team-uuid-1")
        mock_resolve_state = AsyncMock(return_value="state-uuid-1")
        mock_update_state = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        monkeypatch.setattr(linear_client, "resolve_workflow_state_id", mock_resolve_state)
        monkeypatch.setattr(linear_client, "update_issue_state", mock_update_state)

        await apply_start_ticket(
            {"target_id": "TECH-1234", "action_type": "start_ticket", "team": "TECH"}, "Because."
        )

        mock_resolve_team.assert_awaited_once_with("TECH")
        mock_resolve_state.assert_awaited_once_with("team-uuid-1", "In Progress")
        mock_update_state.assert_awaited_once_with("TECH-1234", "state-uuid-1")

    async def test_missing_target_id_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="target_id"):
            await apply_start_ticket({"action_type": "start_ticket", "team": "TECH"}, "r")
        mock_resolve_team.assert_not_awaited()

    async def test_missing_team_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="team"):
            await apply_start_ticket({"target_id": "TECH-1234", "action_type": "start_ticket"}, "r")
        mock_resolve_team.assert_not_awaited()

    async def test_resolve_workflow_state_id_failure_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_update_state = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", AsyncMock(return_value="team-uuid-1"))
        monkeypatch.setattr(
            linear_client,
            "resolve_workflow_state_id",
            AsyncMock(side_effect=LinearNotFoundError("no state")),
        )
        monkeypatch.setattr(linear_client, "update_issue_state", mock_update_state)
        with pytest.raises(LinearNotFoundError, match="no state"):
            await apply_start_ticket(
                {"target_id": "TECH-1234", "action_type": "start_ticket", "team": "TECH"}, "r"
            )
        mock_update_state.assert_not_awaited()


class TestApplyReviewTicket:
    """TECH-5877: applier for ``action_type="review_ticket"`` -- same
    shape as ``TestApplyStartTicket`` above, but resolves "In Review"."""

    async def test_resolves_team_and_in_review_state_then_updates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock(return_value="team-uuid-1")
        mock_resolve_state = AsyncMock(return_value="state-uuid-2")
        mock_update_state = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        monkeypatch.setattr(linear_client, "resolve_workflow_state_id", mock_resolve_state)
        monkeypatch.setattr(linear_client, "update_issue_state", mock_update_state)

        await apply_review_ticket(
            {"target_id": "TECH-1234", "action_type": "review_ticket", "team": "TECH"}, "Because."
        )

        mock_resolve_team.assert_awaited_once_with("TECH")
        mock_resolve_state.assert_awaited_once_with("team-uuid-1", "In Review")
        mock_update_state.assert_awaited_once_with("TECH-1234", "state-uuid-2")

    async def test_missing_target_id_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="target_id"):
            await apply_review_ticket({"action_type": "review_ticket", "team": "TECH"}, "r")
        mock_resolve_team.assert_not_awaited()

    async def test_missing_team_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="team"):
            await apply_review_ticket(
                {"target_id": "TECH-1234", "action_type": "review_ticket"}, "r"
            )
        mock_resolve_team.assert_not_awaited()


class TestApplyAssignTicket:
    """TECH-5877: applier for ``action_type="assign_ticket"`` -- reassigns
    directly using ``action["assignee_id"]``, already a Linear internal
    user id (no name resolution needed -- unlike team/state/label
    elsewhere in this module)."""

    async def test_updates_assignee_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_update_assignee = AsyncMock()
        monkeypatch.setattr(linear_client, "update_issue_assignee", mock_update_assignee)

        await apply_assign_ticket(
            {
                "target_id": "TECH-1234",
                "action_type": "assign_ticket",
                "assignee_id": "11111111-1111-1111-1111-111111111111",
            },
            "Because.",
        )

        mock_update_assignee.assert_awaited_once_with(
            "TECH-1234", "11111111-1111-1111-1111-111111111111"
        )

    async def test_missing_target_id_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_update_assignee = AsyncMock()
        monkeypatch.setattr(linear_client, "update_issue_assignee", mock_update_assignee)
        with pytest.raises(LinearAPIError, match="target_id"):
            await apply_assign_ticket(
                {
                    "action_type": "assign_ticket",
                    "assignee_id": "11111111-1111-1111-1111-111111111111",
                },
                "r",
            )
        mock_update_assignee.assert_not_awaited()

    async def test_missing_assignee_id_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_update_assignee = AsyncMock()
        monkeypatch.setattr(linear_client, "update_issue_assignee", mock_update_assignee)
        with pytest.raises(LinearAPIError, match="assignee_id"):
            await apply_assign_ticket(
                {"target_id": "TECH-1234", "action_type": "assign_ticket"}, "r"
            )
        mock_update_assignee.assert_not_awaited()

    async def test_non_canonical_uuid_assignee_id_is_normalized_before_linear_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_update_assignee = AsyncMock()
        monkeypatch.setattr(linear_client, "update_issue_assignee", mock_update_assignee)

        await apply_assign_ticket(
            {
                "target_id": "TECH-1234",
                "action_type": "assign_ticket",
                "assignee_id": "{11111111-1111-1111-1111-111111111111}",
            },
            "Because.",
        )

        mock_update_assignee.assert_awaited_once_with(
            "TECH-1234", "11111111-1111-1111-1111-111111111111"
        )

    async def test_invalid_uuid_assignee_id_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_update_assignee = AsyncMock()
        monkeypatch.setattr(linear_client, "update_issue_assignee", mock_update_assignee)
        with pytest.raises(LinearAPIError, match="assignee_id"):
            await apply_assign_ticket(
                {
                    "target_id": "TECH-1234",
                    "action_type": "assign_ticket",
                    "assignee_id": "not-a-uuid",
                },
                "r",
            )
        mock_update_assignee.assert_not_awaited()


class TestApplyLabelTicket:
    """TECH-5877: applier for ``action_type="label_ticket"`` -- resolves
    team + label name, then adds it via the dedicated add-only mutation
    (``add_issue_label``, NOT a replace-all-labels call)."""

    async def test_resolves_team_and_label_then_adds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_resolve_team = AsyncMock(return_value="team-uuid-1")
        mock_resolve_label = AsyncMock(return_value="label-uuid-1")
        mock_add_label = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        monkeypatch.setattr(linear_client, "resolve_label_id", mock_resolve_label)
        monkeypatch.setattr(linear_client, "add_issue_label", mock_add_label)

        await apply_label_ticket(
            {
                "target_id": "TECH-1234",
                "action_type": "label_ticket",
                "team": "TECH",
                "label_name": "target:agent-comms-mcp",
            },
            "Because.",
        )

        mock_resolve_team.assert_awaited_once_with("TECH")
        mock_resolve_label.assert_awaited_once_with("team-uuid-1", "target:agent-comms-mcp")
        mock_add_label.assert_awaited_once_with("TECH-1234", "label-uuid-1")

    async def test_missing_target_id_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="target_id"):
            await apply_label_ticket(
                {"action_type": "label_ticket", "team": "TECH", "label_name": "target:repo"}, "r"
            )
        mock_resolve_team.assert_not_awaited()

    async def test_missing_team_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        with pytest.raises(LinearAPIError, match="team"):
            await apply_label_ticket(
                {
                    "target_id": "TECH-1234",
                    "action_type": "label_ticket",
                    "label_name": "target:repo",
                },
                "r",
            )
        mock_resolve_team.assert_not_awaited()

    async def test_missing_label_name_raises_without_calling_linear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_resolve_team = AsyncMock(return_value="team-uuid-1")
        mock_resolve_label = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", mock_resolve_team)
        monkeypatch.setattr(linear_client, "resolve_label_id", mock_resolve_label)
        with pytest.raises(LinearAPIError, match="label_name"):
            await apply_label_ticket(
                {"target_id": "TECH-1234", "action_type": "label_ticket", "team": "TECH"}, "r"
            )
        mock_resolve_label.assert_not_awaited()

    async def test_resolve_label_id_failure_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_add_label = AsyncMock()
        monkeypatch.setattr(linear_client, "resolve_team_id", AsyncMock(return_value="team-uuid-1"))
        monkeypatch.setattr(
            linear_client,
            "resolve_label_id",
            AsyncMock(side_effect=LinearNotFoundError("no label")),
        )
        monkeypatch.setattr(linear_client, "add_issue_label", mock_add_label)
        with pytest.raises(LinearNotFoundError, match="no label"):
            await apply_label_ticket(
                {
                    "target_id": "TECH-1234",
                    "action_type": "label_ticket",
                    "team": "TECH",
                    "label_name": "target:agent-comms-mcp",
                },
                "r",
            )
        mock_add_label.assert_not_awaited()
