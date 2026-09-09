"""Thin GitHub REST API client (no SDK) -- mirrors ``linear_client.py``'s
architecture for the auto-approve judge lanes that need to look at a pull
request or branch (e.g. "is this PR still open", "does this branch still
exist").

Wired into ``service.py``'s ``(kind, action_type)``-keyed rule registry:
``_rule_start_ticket``, ``_rule_review_ticket``, and ``_rule_assign_ticket``
each call ``fetch_pull_request``/``parse_pull_request_url`` here to verify
a cited PR before auto-approving.

Credential: ``GITHUB_TOKEN`` env var, read directly (same
"application code reads an env var" convention this repo already uses
for ``LINEAR_API_TOKEN``/``OKTA_CLIENT_SECRET``/``MCP_JWT_SECRET``/
``AGENT_JWT_SECRET`` -- see ``auth.py``'s ``require_env`` and
``.env.example``).

SECURITY (SSRF-adjacent): this module trusts its ``owner``/``repo``/
``number``/``branch`` arguments completely and does NO host/scheme
validation of its own -- it will happily issue a request to
``api.github.com`` for whatever repo coordinates it is given. Any future
caller that derives these from a URL supplied by an untrusted source
(e.g. a citation on a bot-submitted proposal) MUST validate that URL with
``citation_urls.is_valid_citation_url`` first -- ``parse_pull_request_url``
below only parses PR-URL *structure*, it does not check the URL's host or
scheme either.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

_GITHUB_API_URL = "https://api.github.com"
_GITHUB_TOKEN_ENV_VAR = "GITHUB_TOKEN"
_GITHUB_REQUEST_TIMEOUT_SECONDS = 10.0

# GitHub's REST API version header (pinned so a future GitHub-side default
# bump doesn't silently change response shapes under us).
_GITHUB_API_VERSION = "2022-11-28"

# Argus review: log-injection hygiene. A raw GitHub response body can be
# arbitrarily large (and, being attacker-influenced content, arbitrarily
# crafted) -- truncated before ever being embedded in an exception message.
_MAX_LOGGED_RESPONSE_TEXT_LENGTH = 200


def _truncated_response_text(response: httpx.Response) -> str:
    """``response.text``, truncated to ``_MAX_LOGGED_RESPONSE_TEXT_LENGTH``
    characters -- safe to embed in an exception message regardless of how
    large the real response body is."""
    text = response.text
    if len(text) > _MAX_LOGGED_RESPONSE_TEXT_LENGTH:
        return text[:_MAX_LOGGED_RESPONSE_TEXT_LENGTH] + "...(truncated)"
    return text


def _sanitize_for_log(value: str) -> str:
    """Strip non-printable characters (control characters, including an
    embedded newline) from a URL-derived value (``owner``/``repo``/
    ``branch``) before it is interpolated into any string that reaches a
    log line or exception message -- a crafted URL containing an encoded
    newline (``%0A``) in a path segment could otherwise inject
    fake-looking log lines once that segment is decoded."""
    return "".join(char for char in value if char.isprintable())


class GitHubAPIError(Exception):
    """Raised on any non-2xx response or malformed (non-JSON) response
    body from the GitHub REST API. Future callers should catch this to
    fail closed rather than let a raw exception escape the judge."""


class GitHubTokenMissingError(GitHubAPIError):
    """``GITHUB_TOKEN`` is unset. A typed subclass (same convention as
    ``linear_client.LinearTokenMissingError``), so callers can
    distinguish "not configured" from a genuine GitHub-side error."""


class GitHubTransportError(GitHubAPIError):
    """The HTTP request to GitHub itself failed (connection error,
    timeout) -- as opposed to a well-formed response GitHub returned with
    a non-2xx status. A typed subclass, same convention as
    ``linear_client.LinearTransportError``."""


def _require_api_token() -> str:
    token = os.environ.get(_GITHUB_TOKEN_ENV_VAR)
    if not token:
        raise GitHubTokenMissingError(f"{_GITHUB_TOKEN_ENV_VAR} is not configured")
    return token


async def _get(path: str) -> httpx.Response:
    """Issue a GET against the GitHub REST API and return the raw
    response. Raises ``GitHubTransportError`` on network failure, but
    deliberately does NOT call ``raise_for_status()`` -- callers decide
    how to handle a non-2xx status themselves (``fetch_branch`` treats
    404 as a normal "absent" case; ``fetch_pull_request`` treats every
    non-2xx as an error)."""
    token = _require_api_token()
    try:
        async with httpx.AsyncClient(
            timeout=_GITHUB_REQUEST_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            return await client.get(
                f"{_GITHUB_API_URL}{path}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": _GITHUB_API_VERSION,
                },
            )
    except httpx.HTTPError as exc:
        raise GitHubTransportError(f"GitHub API request failed: {exc}") from exc


def _parse_json_body(response: httpx.Response, *, context: str) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError as exc:
        raise GitHubAPIError(f"GitHub API returned non-JSON response {context}: {exc}") from exc
    if not isinstance(body, dict):
        raise GitHubAPIError(f"GitHub API returned unexpected response shape {context}")
    return body


async def fetch_pull_request(owner: str, repo: str, number: int) -> dict[str, Any]:
    """``GET /repos/{owner}/{repo}/pulls/{number}``.

    Returns the full parsed response body, which carries (among other
    fields) ``state``, ``user.login``, ``requested_reviewers``,
    ``requested_teams``, ``head.ref``, ``title``, ``body``, and
    ``html_url`` -- the fields future judge rules need.

    Raises ``GitHubAPIError`` on any non-2xx response, ``GitHubTransportError``
    on network failure, and ``GitHubTokenMissingError`` if ``GITHUB_TOKEN``
    isn't set. Never swallows errors -- callers need to see failures to
    fail closed."""
    context = f"fetching PR {_sanitize_for_log(owner)}/{_sanitize_for_log(repo)}#{number}"
    response = await _get(f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls/{number}")
    if not response.is_success:
        raise GitHubAPIError(
            f"GitHub API returned {response.status_code} {context}: "
            f"{_truncated_response_text(response)}"
        )
    return _parse_json_body(response, context=context)


async def fetch_branch(owner: str, repo: str, branch: str) -> dict[str, Any] | None:
    """``GET /repos/{owner}/{repo}/branches/{branch}``.

    Returns the parsed response body if the branch exists. Returns
    ``None`` specifically on a 404 -- a missing branch is a normal
    "absent" case, not an error. Any other non-2xx status, or a
    transport failure, still raises (same as ``fetch_pull_request``)."""
    context = (
        f"fetching branch {_sanitize_for_log(owner)}/{_sanitize_for_log(repo)}"
        f"@{_sanitize_for_log(branch)}"
    )
    response = await _get(
        f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/branches/{quote(branch, safe='')}"
    )
    if response.status_code == 404:
        return None
    if not response.is_success:
        raise GitHubAPIError(
            f"GitHub API returned {response.status_code} {context}: "
            f"{_truncated_response_text(response)}"
        )
    return _parse_json_body(response, context=context)


def parse_pull_request_url(url: str) -> tuple[str, str, int] | None:
    """Parse a ``github.com`` PR URL
    (``https://github.com/{owner}/{repo}/pull/{number}``) into
    ``(owner, repo, number)``. Returns ``None`` if ``url`` doesn't match
    that exact path shape (e.g. a branch URL, a PR sub-page like
    ``.../pull/1/files``, or anything unparseable).

    Does NOT validate the URL's host or scheme -- that's
    ``citation_urls.is_valid_citation_url``'s job, and future callers
    must run it BEFORE calling this function (see module docstring)."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 4 or parts[2] != "pull":
        return None
    owner, repo, _, number_str = parts
    if not number_str.isdigit():
        return None
    return owner, repo, int(number_str)


__all__ = [
    "GitHubAPIError",
    "GitHubTokenMissingError",
    "GitHubTransportError",
    "fetch_branch",
    "fetch_pull_request",
    "parse_pull_request_url",
]
