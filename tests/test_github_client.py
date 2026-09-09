"""Unit tests for ``github_client.py``.

No real GitHub API is exercised -- httpx is monkeypatched at the
``httpx.AsyncClient.get`` level, same idiom as ``tests/test_linear_client.py``.
``asyncio_mode = "auto"`` (pyproject.toml) means async ``def test_*``
functions run without an explicit ``pytest.mark.asyncio`` decorator.
"""

from __future__ import annotations

import json

import httpx
import pytest

import github_client
from github_client import (
    GitHubAPIError,
    GitHubTokenMissingError,
    GitHubTransportError,
    fetch_branch,
    fetch_pull_request,
    parse_pull_request_url,
)

_TOKEN_ENV_VAR = github_client._GITHUB_TOKEN_ENV_VAR


def _set_fake_get(monkeypatch: pytest.MonkeyPatch, response: httpx.Response) -> None:
    async def _fake_get(
        self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
    ) -> httpx.Response:
        return response

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)


class TestRequireApiToken:
    def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(GitHubTokenMissingError, match=_TOKEN_ENV_VAR):
            github_client._require_api_token()

    def test_present_token_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        assert github_client._require_api_token() == "tok123"


class TestFetchPullRequest:
    async def test_successful_fetch_returns_expected_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        payload = {
            "state": "open",
            "user": {"login": "octocat"},
            "requested_reviewers": [{"login": "reviewer1"}],
            "requested_teams": [{"slug": "team1"}],
            "head": {"ref": "feature-branch"},
            "title": "My PR",
            "body": "PR description",
            "html_url": "https://github.com/org/repo/pull/1",
        }
        response = httpx.Response(
            200,
            content=json.dumps(payload).encode(),
            request=httpx.Request("GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/pulls/1"),
        )
        _set_fake_get(monkeypatch, response)
        result = await fetch_pull_request("org", "repo", 1)
        assert result["state"] == "open"
        assert result["user"]["login"] == "octocat"
        assert result["requested_reviewers"] == [{"login": "reviewer1"}]
        assert result["requested_teams"] == [{"slug": "team1"}]
        assert result["head"]["ref"] == "feature-branch"
        assert result["title"] == "My PR"
        assert result["body"] == "PR description"
        assert result["html_url"] == "https://github.com/org/repo/pull/1"

    async def test_non_2xx_status_raises_api_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            404,
            content=b'{"message": "Not Found"}',
            request=httpx.Request("GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/pulls/1"),
        )
        _set_fake_get(monkeypatch, response)
        with pytest.raises(GitHubAPIError) as exc_info:
            await fetch_pull_request("org", "repo", 1)
        # Not the transport-error subclass -- a well-formed non-2xx
        # response is an API error, not a network failure.
        assert not isinstance(exc_info.value, GitHubTransportError)
        assert "404" in str(exc_info.value)

    async def test_error_message_truncates_long_response_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review (log injection hygiene): an arbitrarily large
        response body must not blow up the exception message unbounded."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        long_body = "x" * 1000
        response = httpx.Response(
            500,
            content=long_body.encode(),
            request=httpx.Request("GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/pulls/1"),
        )
        _set_fake_get(monkeypatch, response)
        with pytest.raises(GitHubAPIError) as exc_info:
            await fetch_pull_request("org", "repo", 1)
        message = str(exc_info.value)
        assert "x" * 1000 not in message
        assert "...(truncated)" in message

    async def test_error_message_strips_control_characters_from_owner(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review (log injection hygiene): a crafted ``owner``/
        ``repo`` containing an embedded newline (e.g. from a decoded
        ``%0A`` in a URL path segment) must not be able to inject a
        fake-looking log line into the exception message."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            404,
            content=b'{"message": "Not Found"}',
            request=httpx.Request("GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/pulls/1"),
        )
        _set_fake_get(monkeypatch, response)
        with pytest.raises(GitHubAPIError) as exc_info:
            await fetch_pull_request("org\nFAKE LOG LINE injected", "repo", 1)
        assert "\n" not in str(exc_info.value)

    async def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(GitHubTokenMissingError):
            await fetch_pull_request("org", "repo", 1)

    async def test_transport_failure_raises_transport_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")

        async def _fake_get(
            self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
        ) -> httpx.Response:
            raise httpx.ConnectError("boom")

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
        with pytest.raises(GitHubTransportError):
            await fetch_pull_request("org", "repo", 1)

    async def test_non_json_body_raises_api_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            200,
            content=b"not json",
            request=httpx.Request("GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/pulls/1"),
        )
        _set_fake_get(monkeypatch, response)
        with pytest.raises(GitHubAPIError):
            await fetch_pull_request("org", "repo", 1)

    async def test_follow_redirects_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, object] = {}
        original_init = httpx.AsyncClient.__init__

        def _capturing_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
            captured.update(kwargs)
            original_init(self, *args, **kwargs)  # type: ignore[misc]

        monkeypatch.setattr(httpx.AsyncClient, "__init__", _capturing_init)
        response = httpx.Response(
            200,
            content=b'{"state": "open"}',
            request=httpx.Request("GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/pulls/1"),
        )
        _set_fake_get(monkeypatch, response)
        await fetch_pull_request("org", "repo", 1)
        assert captured["follow_redirects"] is False


class TestFetchBranch:
    async def test_successful_fetch_returns_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        payload = {"name": "main", "commit": {"sha": "abc123"}}
        response = httpx.Response(
            200,
            content=json.dumps(payload).encode(),
            request=httpx.Request(
                "GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/branches/main"
            ),
        )
        _set_fake_get(monkeypatch, response)
        result = await fetch_branch("org", "repo", "main")
        assert result == payload

    async def test_404_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            404,
            content=b'{"message": "Branch not found"}',
            request=httpx.Request(
                "GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/branches/nope"
            ),
        )
        _set_fake_get(monkeypatch, response)
        result = await fetch_branch("org", "repo", "nope")
        assert result is None

    async def test_non_404_non_2xx_still_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            500,
            content=b'{"message": "Internal Server Error"}',
            request=httpx.Request(
                "GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/branches/main"
            ),
        )
        _set_fake_get(monkeypatch, response)
        with pytest.raises(GitHubAPIError) as exc_info:
            await fetch_branch("org", "repo", "main")
        assert not isinstance(exc_info.value, GitHubTransportError)

    async def test_error_message_strips_control_characters_from_branch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Argus review (log injection hygiene): same as
        ``TestFetchPullRequest.test_error_message_strips_control_
        characters_from_owner``, but for ``fetch_branch``'s ``branch``
        parameter."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        response = httpx.Response(
            500,
            content=b'{"message": "Internal Server Error"}',
            request=httpx.Request(
                "GET", f"{github_client._GITHUB_API_URL}/repos/org/repo/branches/main"
            ),
        )
        _set_fake_get(monkeypatch, response)
        with pytest.raises(GitHubAPIError) as exc_info:
            await fetch_branch("org", "repo", "main\nFAKE LOG LINE injected")
        assert "\n" not in str(exc_info.value)

    async def test_transport_failure_raises_transport_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")

        async def _fake_get(
            self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
        ) -> httpx.Response:
            raise httpx.ConnectError("boom")

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
        with pytest.raises(GitHubTransportError):
            await fetch_branch("org", "repo", "main")

    async def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(GitHubTokenMissingError):
            await fetch_branch("org", "repo", "main")

    async def test_branch_name_with_slash_is_url_encoded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A branch name like ``feature/foo`` must not be treated as an
        extra path segment."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, object] = {}

        async def _fake_get(
            self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
        ) -> httpx.Response:
            captured["url"] = url
            return httpx.Response(
                200, content=b'{"name": "feature/foo"}', request=httpx.Request("GET", url)
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
        await fetch_branch("org", "repo", "feature/foo")
        expected_url = f"{github_client._GITHUB_API_URL}/repos/org/repo/branches/feature%2Ffoo"
        assert captured["url"] == expected_url

    async def test_branch_name_with_path_traversal_is_url_encoded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A branch name like ``../pulls/1`` must be URL-encoded and not
        interpreted as path traversal segments."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, object] = {}

        async def _fake_get(
            self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
        ) -> httpx.Response:
            captured["url"] = url
            return httpx.Response(
                200, content=b'{"name": "../pulls/1"}', request=httpx.Request("GET", url)
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
        await fetch_branch("org", "repo", "../pulls/1")
        expected_url = f"{github_client._GITHUB_API_URL}/repos/org/repo/branches/..%2Fpulls%2F1"
        assert captured["url"] == expected_url

    async def test_fetch_pull_request_with_path_traversal_owner(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An owner parameter like ``../other`` must be URL-encoded and not
        interpreted as path traversal."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, object] = {}

        async def _fake_get(
            self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
        ) -> httpx.Response:
            captured["url"] = url
            return httpx.Response(
                200,
                content=b'{"number": 42, "state": "open"}',
                request=httpx.Request("GET", url),
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
        await fetch_pull_request("../other", "repo", 42)
        expected_url = f"{github_client._GITHUB_API_URL}/repos/..%2Fother/repo/pulls/42"
        assert captured["url"] == expected_url

    async def test_fetch_pull_request_with_path_traversal_repo(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A repo parameter like ``../other`` must be URL-encoded and not
        interpreted as path traversal."""
        monkeypatch.setenv(_TOKEN_ENV_VAR, "tok123")
        captured: dict[str, object] = {}

        async def _fake_get(
            self: httpx.AsyncClient, url: str, *, headers: dict[str, str]
        ) -> httpx.Response:
            captured["url"] = url
            return httpx.Response(
                200,
                content=b'{"number": 42, "state": "open"}',
                request=httpx.Request("GET", url),
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
        await fetch_pull_request("owner", "../other", 42)
        expected_url = f"{github_client._GITHUB_API_URL}/repos/owner/..%2Fother/pulls/42"
        assert captured["url"] == expected_url


class TestParsePullRequestUrl:
    def test_valid_pr_url_parses(self) -> None:
        result = parse_pull_request_url("https://github.com/redesignhealth/agent-comms-mcp/pull/42")
        assert result == ("redesignhealth", "agent-comms-mcp", 42)

    def test_branch_url_returns_none(self) -> None:
        assert parse_pull_request_url("https://github.com/org/repo/tree/main") is None

    def test_malformed_url_returns_none(self) -> None:
        assert parse_pull_request_url("not-a-url") is None

    def test_different_path_shape_returns_none(self) -> None:
        # A URL with a different path shape (GitLab's merge-request format),
        # which doesn't match the "owner/repo/pull/number" structure this
        # function parses. The function rejects based on path structure, not
        # host validation.
        assert parse_pull_request_url("https://gitlab.com/org/repo/-/merge_requests/1") is None

    def test_untrusted_host_matching_path_shape_parses_successfully(self) -> None:
        # This function only validates path structure, not host/scheme
        # validity. Host validation is deliberately separate (the caller's
        # job via ``citation_urls.is_valid_citation_url``, which runs BEFORE
        # this function). A PR-shaped URL on an untrusted host like
        # ``evil.com`` successfully parses here, and the caller must verify
        # the host separately.
        result = parse_pull_request_url("https://evil.com/owner/repo/pull/123")
        assert result == ("owner", "repo", 123)

    def test_pr_subpage_returns_none(self) -> None:
        assert parse_pull_request_url("https://github.com/org/repo/pull/1/files") is None

    def test_non_numeric_pr_number_returns_none(self) -> None:
        assert parse_pull_request_url("https://github.com/org/repo/pull/abc") is None

    def test_malformed_ipv6_url_returns_none_not_raises(self) -> None:
        assert parse_pull_request_url("https://[::1::2]/org/repo/pull/1") is None
