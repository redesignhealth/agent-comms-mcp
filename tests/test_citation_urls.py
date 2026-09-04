"""Direct unit tests for citation_urls.py (Argus review round-3 S5) --
previously only exercised indirectly via tests/test_proposal_judge.py and
tests/test_linear_client.py."""

from __future__ import annotations

import pytest

from citation_urls import is_allowed_citation_host, is_valid_citation_url, redact_url_for_logging


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

    def test_userinfo_embedded_url_rejected_even_with_allowlisted_host(self) -> None:
        """Argus review round-4 suggestion: userinfo is rejected outright,
        regardless of which host follows the `@` -- the full URL
        (userinfo included) is posted verbatim into the Linear comment,
        so an allowlisted host after the `@` doesn't make the userinfo
        component itself safe to display (a social-engineering vector:
        `https://click-here-for-a-refund@redesignhealth.slack.com/...`).
        This also covers the classic confusion vector where a malicious
        host masquerades as userinfo ahead of a real one
        (`https://github.com@evil.example/`) -- both shapes are rejected
        by the same blanket rule, not by hostname-parsing correctness
        alone."""
        assert is_valid_citation_url("https://github.com@evil.example/") is False
        assert is_valid_citation_url("https://evil.example@github.com/") is False

    def test_missing_hostname_rejected(self) -> None:
        assert is_valid_citation_url("https:///path-with-no-host") is False


class TestRedactUrlForLogging:
    """Argus review round-7/round-8: `redact_url_for_logging` is the
    barrier between a REJECTED citation URL (untrusted by definition) and
    every downstream log/exception/audit sink -- these tests are the
    regression net for that security property, not just a coverage
    checkbox (round-8 caught a real bug here: an earlier version used
    ``parsed.netloc``, which does NOT strip userinfo)."""

    def test_normal_url_keeps_scheme_host_path(self) -> None:
        assert (
            redact_url_for_logging("https://not-allowlisted.example/some/path")
            == "https://not-allowlisted.example/some/path"
        )

    def test_query_and_fragment_are_stripped(self) -> None:
        redacted = redact_url_for_logging(
            "https://not-allowlisted.example/path?token=secret123#frag"
        )
        assert redacted == "https://not-allowlisted.example/path"
        assert "token" not in redacted
        assert "secret123" not in redacted

    def test_userinfo_credentials_are_stripped(self) -> None:
        """Argus review round-8 BLOCKING: the exact bug this test guards
        against -- a prior version used `parsed.netloc`, which includes
        userinfo verbatim, so this would have logged the credential."""
        redacted = redact_url_for_logging("https://token:secret@evil.example/path")
        assert redacted == "https://evil.example/path"
        assert "token" not in redacted
        assert "secret" not in redacted

    def test_port_is_preserved_without_userinfo(self) -> None:
        redacted = redact_url_for_logging("https://user:pw@evil.example:8443/path")
        assert redacted == "https://evil.example:8443/path"
        assert "user" not in redacted
        assert "pw" not in redacted

    def test_unparseable_url_returns_placeholder(self) -> None:
        assert redact_url_for_logging("not-a-url-at-all") == "<unparseable-url>"
        assert redact_url_for_logging("https:///no-host") == "<unparseable-url>"
