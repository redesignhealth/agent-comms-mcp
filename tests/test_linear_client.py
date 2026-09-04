"""Unit tests for ``linear_client.py`` (TECH-5873 Argus review follow-up).

No real Postgres or Linear API is exercised -- httpx is monkeypatched at the
``httpx.AsyncClient.post`` level, same idiom as
``tests/test_plugins.py``'s ``TestWebhookNotifier``. ``asyncio_mode = "auto"``
(pyproject.toml) means async ``def test_*`` functions run without an
explicit ``pytest.mark.asyncio`` decorator.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import linear_client
from linear_client import (
    LinearAPIError,
    _post_graphql,
    _progress_comment_body,
    _require_api_token,
    apply_progress_update,
    compute_target_fingerprint,
    fetch_current_fingerprint,
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
        monkeypatch.delenv(_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(LinearAPIError, match=_TOKEN_ENV_VAR):
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
        with pytest.raises(LinearAPIError):
            await _post_graphql("query {}", {})

    async def test_non_2xx_status_wrapped_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(500, request=httpx.Request("POST", linear_client._LINEAR_API_URL))
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError):
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
        with pytest.raises(LinearAPIError):
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
        results everywhere."""
        issue = {
            "state": {"id": "state-1", "name": "In Progress"},
            "priority": 2,
            "assignee": {"id": "user-1"},
            "updatedAt": "2026-01-01T00:00:00.000Z",
        }
        digest = compute_target_fingerprint(issue)
        assert digest == "20b5fc3acf309a4c67042819637b2a0244b0f6b8734e17b6f7a48aba0cea38b8"

    def test_missing_state_and_assignee_do_not_raise(self) -> None:
        digest = compute_target_fingerprint({"priority": None, "updatedAt": None})
        assert isinstance(digest, str)
        assert len(digest) == 64


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


_VALID_SOURCE_URL = "https://redesignhealth.slack.com/archives/C1/p123"
_VALID_PR_URL = "https://github.com/org/repo/pull/1"


class TestProgressCommentBody:
    def test_all_optional_fields_present(self) -> None:
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "rationale": "Shipped in the linked PR.",
                "source_message_url": _VALID_SOURCE_URL,
                "resolving_pr_url": _VALID_PR_URL,
            }
        )
        assert "Progress update: close_ticket" in body
        assert "Shipped in the linked PR." in body
        assert f"Source: {_VALID_SOURCE_URL}" in body
        assert f"Resolved by: {_VALID_PR_URL}" in body

    def test_all_optional_fields_absent(self) -> None:
        body = _progress_comment_body({"action_type": "open_ticket"})
        assert body == "Progress update: open_ticket"

    def test_default_action_type_when_missing(self) -> None:
        body = _progress_comment_body({})
        assert body == "Progress update: update"

    def test_only_rationale_present(self) -> None:
        body = _progress_comment_body({"action_type": "open_ticket", "rationale": "Because."})
        assert body == "Progress update: open_ticket\n\nBecause."

    def test_only_source_message_url_present(self) -> None:
        body = _progress_comment_body(
            {"action_type": "open_ticket", "source_message_url": _VALID_SOURCE_URL}
        )
        assert body == f"Progress update: open_ticket\n\nSource: {_VALID_SOURCE_URL}"

    def test_only_resolving_pr_url_present(self) -> None:
        body = _progress_comment_body(
            {"action_type": "close_ticket", "resolving_pr_url": _VALID_PR_URL}
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
                }
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
            }
        )
        assert "not-allowlisted.example" not in body
        assert body == "Progress update: close_ticket"

    def test_non_allowlisted_resolving_pr_url_is_omitted_not_raised(self) -> None:
        body = _progress_comment_body(
            {
                "action_type": "close_ticket",
                "resolving_pr_url": "https://not-allowlisted.example/pull/1",
            }
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
            }
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
            }
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
            }
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
                }
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
            }
        )
        assert "not-allowlisted.example" not in captured["json"]["variables"]["body"]
