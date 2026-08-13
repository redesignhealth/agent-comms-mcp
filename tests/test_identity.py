"""Tests for identity.py's agent-jwt-detection + email-resolution helpers.

Unit-tests ``try_resolve_email`` directly against constructed claims dicts
(no DB, no MCP tool stack), AND unit-tests the private ``_is_agent_jwt_token``
helper directly (``TestIsAgentJwtToken`` below) — mirroring
``tests/test_scopes.py``'s ``TestIsInteractiveToken`` pattern, which is the
scopes.py counterpart to the ``iss is None`` fail-closed guard tested here.
Direct coverage of ``_is_agent_jwt_token`` is deliberately kept alongside the
indirect ``try_resolve_email``-based coverage: this function is the
identity-routing gate that determines whether an ``email`` claim is trusted
as the caller's identity, and a future refactor of how ``try_resolve_email``
composes with it could otherwise silently break its own fail-closed
contract without either layer's tests catching it.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from identity import AGENT_JWT_ISSUER, _is_agent_jwt_token, try_resolve_email, validate_sub_shape


def _fake_token(claims: dict[str, object]) -> MagicMock:
    """Minimal stand-in for FastMCP's AccessToken (only ``.claims`` is used)."""
    token = MagicMock()
    token.claims = claims
    return token


class TestTryResolveEmail:
    def test_agent_jwt_token_resolves_via_sub_not_email(self) -> None:
        # agent-jwt's `email` claim is attacker-controlled (the JWT issuer
        # accepts arbitrary extra claims) — must never be trusted.
        token = _fake_token(
            {
                "iss": AGENT_JWT_ISSUER,
                "sub": "ea-agent-svc",
                "email": "forged@example.com",
            }
        )
        assert try_resolve_email(token) == "ea-agent-svc"

    def test_missing_iss_with_forged_email_resolves_via_sub(self) -> None:
        # The higher-stakes case from the docstring: no `iss` claim at all,
        # plus a forged `email` claim. Must resolve to the sub-derived
        # identity, never the forged email.
        token = _fake_token({"sub": "svc-account-1", "email": "forged@example.com"})
        assert try_resolve_email(token) == "svc-account-1"

    def test_explicit_none_iss_with_forged_email_resolves_via_sub(self) -> None:
        # Same fail-closed guard as the missing-iss case above, but with an
        # explicit `iss: None` claim rather than an absent key -- must not
        # fall through to trusting the forged `email` claim.
        token = _fake_token(
            {"iss": None, "sub": "svc-account-1", "email": "forged@example.com"}
        )
        assert try_resolve_email(token) == "svc-account-1"

    def test_interactive_token_trusts_email_claim(self) -> None:
        # Contrast case: a genuinely interactive (non-agent-jwt) token with an
        # Okta-like issuer SHOULD have its `email` claim trusted.
        token = _fake_token(
            {
                "iss": "https://example.okta.com/oauth2/default",
                "sub": "00u1234okta",
                "email": "person@example.com",
            }
        )
        assert try_resolve_email(token) == "person@example.com"

    def test_interactive_token_falls_back_to_preferred_username(self) -> None:
        token = _fake_token(
            {
                "iss": "https://example.okta.com/oauth2/default",
                "sub": "00u1234okta",
                "preferred_username": "person@example.com",
            }
        )
        assert try_resolve_email(token) == "person@example.com"

    def test_interactive_token_with_no_identity_claims_falls_back_to_sub(self) -> None:
        token = _fake_token(
            {"iss": "https://example.okta.com/oauth2/default", "sub": "00u1234okta"}
        )
        assert try_resolve_email(token) == "00u1234okta"

    def test_agent_jwt_token_missing_sub_returns_none(self) -> None:
        token = _fake_token({"iss": AGENT_JWT_ISSUER, "email": "forged@example.com"})
        assert try_resolve_email(token) is None

    def test_interactive_token_missing_all_identity_claims_returns_none(self) -> None:
        token = _fake_token({"iss": "https://example.okta.com/oauth2/default"})
        assert try_resolve_email(token) is None

    def test_email_shaped_sub_fails_closed_to_none(self) -> None:
        # `jwt issue --sub alice@example.com` impersonation
        # attempt: validate_sub_shape rejects it, try_resolve_email fails
        # open with None rather than raising or returning the impersonated
        # identity.
        token = _fake_token({"iss": AGENT_JWT_ISSUER, "sub": "alice@example.com"})
        assert try_resolve_email(token) is None

    def test_whitespace_sub_fails_closed_to_none(self) -> None:
        token = _fake_token({"iss": AGENT_JWT_ISSUER, "sub": "   "})
        assert try_resolve_email(token) is None


class TestIsAgentJwtToken:
    """Direct unit tests for the private ``_is_agent_jwt_token`` gate.

    Complements ``TestTryResolveEmail`` above (which exercises this
    function only indirectly through ``try_resolve_email``'s observable
    behavior): these tests pin down this function's own fail-closed
    contract in isolation, mirroring ``tests/test_scopes.py``'s
    ``TestIsInteractiveToken`` for the sibling ``is_interactive_token``.
    """

    def test_agent_jwt_issuer_is_agent_jwt_token(self) -> None:
        assert _is_agent_jwt_token({"iss": AGENT_JWT_ISSUER, "sub": "svc-1"}) is True

    def test_okta_issuer_is_not_agent_jwt_token(self) -> None:
        token_claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "sub": "00u1234okta",
        }
        assert _is_agent_jwt_token(token_claims) is False

    def test_missing_iss_claim_fails_closed_to_true(self) -> None:
        # No `iss` claim at all must NOT fall through to the "not agent-jwt"
        # (email-trusting) branch -- fail closed by treating it as agent-jwt.
        assert _is_agent_jwt_token({"sub": "svc-1"}) is True

    def test_explicit_none_iss_fails_closed_to_true(self) -> None:
        # Same fail-closed guard as the missing-key case above, but with an
        # explicit `iss: None` claim rather than an absent key.
        assert _is_agent_jwt_token({"iss": None, "sub": "svc-1"}) is True


class TestValidateSubShape:
    def test_missing_sub_is_permitted(self) -> None:
        validate_sub_shape({})  # must not raise

    def test_non_string_sub_is_stringified_before_validation(self) -> None:
        # An int sub has no "@" and isn't blank once stringified — permitted.
        validate_sub_shape({"sub": 12345})  # must not raise
