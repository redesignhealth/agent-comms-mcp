"""Direct unit tests for citation_urls.py (Argus review round-3 S5) --
previously only exercised indirectly via tests/test_proposal_judge.py and
tests/test_linear_client.py."""

from __future__ import annotations

import pytest

from citation_urls import is_allowed_citation_host, is_valid_citation_url


class TestIsAllowedCitationHost:
    def test_exact_github_com_allowed(self) -> None:
        assert is_allowed_citation_host("github.com") is True

    def test_slack_subdomain_allowed(self) -> None:
        assert is_allowed_citation_host("redesignhealth.slack.com") is True

    def test_bare_slack_com_not_allowed(self) -> None:
        """Only `*.slack.com` subdomains are allowlisted, not the bare
        apex domain -- a citation URL is always a workspace-scoped
        permalink, never a link to slack.com itself."""
        assert is_allowed_citation_host("slack.com") is False

    def test_evil_slack_com_suffix_bypass_blocked(self) -> None:
        """A naive `.endswith(".slack.com")` check with no leading dot
        would also match e.g. `evilslack.com` if not written carefully --
        confirm the actual allowlist logic doesn't fall for a
        similarly-shaped non-subdomain host."""
        assert is_allowed_citation_host("evil-slack.com") is False
        assert is_allowed_citation_host("notslack.com") is False

    def test_github_subdomain_not_allowed(self) -> None:
        """Only the exact `github.com` host is allowlisted, not arbitrary
        subdomains -- `raw.githubusercontent.com` or a lookalike must not
        pass."""
        assert is_allowed_citation_host("raw.githubusercontent.com") is False

    def test_case_insensitive(self) -> None:
        assert is_allowed_citation_host("GitHub.COM") is True
        assert is_allowed_citation_host("Redesignhealth.SLACK.com") is True

    def test_unrelated_host_not_allowed(self) -> None:
        assert is_allowed_citation_host("example.com") is False


class TestIsValidCitationUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/redesignhealth/rh-data-platform/pull/1",
            "http://github.com/foo/bar/pull/2",
            "https://redesignhealth.slack.com/archives/C1/p1",
        ],
    )
    def test_valid_urls(self, url: str) -> None:
        assert is_valid_citation_url(url) is True

    def test_none_input(self) -> None:
        assert is_valid_citation_url(None) is False

    def test_empty_string(self) -> None:
        assert is_valid_citation_url("") is False

    def test_whitespace_only_string(self) -> None:
        assert is_valid_citation_url("   ") is False

    def test_non_string_input(self) -> None:
        assert is_valid_citation_url(12345) is False
        assert is_valid_citation_url({"url": "https://github.com"}) is False

    def test_non_http_scheme_rejected(self) -> None:
        assert is_valid_citation_url("ftp://github.com/foo") is False
        assert is_valid_citation_url("javascript:alert(1)") is False

    def test_non_allowlisted_host_rejected(self) -> None:
        assert is_valid_citation_url("https://not-allowlisted.example/p123") is False

    def test_userinfo_embedded_host_still_validated_by_hostname_not_userinfo(self) -> None:
        """`urlsplit` parses the userinfo separately from the hostname --
        confirm a malicious userinfo component (a common URL-parsing
        confusion vector: `https://github.com@evil.example/`) is judged by
        the actual host (`evil.example`), not by whatever precedes the
        `@`."""
        assert is_valid_citation_url("https://github.com@evil.example/") is False
        assert is_valid_citation_url("https://evil.example@github.com/") is True

    def test_missing_hostname_rejected(self) -> None:
        assert is_valid_citation_url("https:///path-with-no-host") is False
