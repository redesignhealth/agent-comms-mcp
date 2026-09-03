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


def _run(coro: object) -> object:
    import asyncio

    return asyncio.run(coro)  # type: ignore[arg-type]


class TestRequireApiToken:
    def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(LinearAPIError, match=_TOKEN_ENV_VAR):
            _require_api_token()

    def test_present_token_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        assert _require_api_token() == "tok123"


class TestPostGraphql:
    def test_transport_error_wrapped_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")

        async def _fake_post(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            raise httpx.ConnectError("boom")

        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)
        with pytest.raises(LinearAPIError):
            _run(_post_graphql("query {}", {}))

    def test_non_2xx_status_wrapped_as_linear_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(500, request=httpx.Request("POST", linear_client._LINEAR_API_URL))
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError):
            _run(_post_graphql("query {}", {}))

    def test_json_decode_error_wrapped_as_linear_api_error(
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
            _run(_post_graphql("query {}", {}))

    def test_graphql_errors_payload_extracts_message_only(
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
            _run(_post_graphql("query {}", {}))
        message = str(exc_info.value)
        assert "Issue not found" in message
        assert "secret-detail" not in message
        assert "extensions" not in message

    def test_missing_data_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=b"{}",
            request=httpx.Request("POST", linear_client._LINEAR_API_URL),
        )
        _set_fake_post(monkeypatch, response)
        with pytest.raises(LinearAPIError, match="missing 'data'"):
            _run(_post_graphql("query {}", {}))

    def test_follow_redirects_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
        _run(_post_graphql("query {}", {}))
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

    def test_non_allowlisted_source_url_raises(self) -> None:
        """Argus review S3: the citation-URL allowlist must be re-checked
        here too -- a proposal that skipped auto-approval (judge left it
        'pending') can still reach ``apply_progress_update`` via manual
        human approval, and an arbitrary URL must not silently land in a
        Linear comment."""
        with pytest.raises(LinearAPIError):
            _progress_comment_body(
                {
                    "action_type": "open_ticket",
                    "source_message_url": "https://not-allowlisted.example/p123",
                }
            )

    def test_non_allowlisted_resolving_pr_url_raises(self) -> None:
        with pytest.raises(LinearAPIError):
            _progress_comment_body(
                {
                    "action_type": "close_ticket",
                    "resolving_pr_url": "https://not-allowlisted.example/pull/1",
                }
            )


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

    async def test_invalid_url_prevents_the_write(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The URL re-validation in ``_progress_comment_body`` must run
        (and raise) BEFORE the GraphQL mutation is ever sent."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")

        async def _fail_if_called(
            self: httpx.AsyncClient, url: str, *, json: dict[str, object], headers: dict[str, str]
        ) -> httpx.Response:
            raise AssertionError("must not POST when the URL fails validation")

        monkeypatch.setattr(httpx.AsyncClient, "post", _fail_if_called)
        with pytest.raises(LinearAPIError):
            await apply_progress_update(
                {
                    "target_id": "TECH-1234",
                    "action_type": "open_ticket",
                    "source_message_url": "https://not-allowlisted.example/p123",
                }
            )
