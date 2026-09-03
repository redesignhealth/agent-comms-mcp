"""Tests for the agent-comms-mcp scope registry."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import mint_token
from auth import AGENT_TOKEN_VERIFIER_CLAIM, DEFAULT_AGENT_TOKEN_VERIFIER
from scopes import (
    PROPOSAL_SUBMIT_SCOPE,
    TOOL_SCOPES,
    is_interactive_token,
    is_registry_backed_agent_token,
    required_scope_for,
    required_scope_for_resource,
    safe_client_id,
    scopes_for_token,
)

# Format: ``<service>:<verb>`` or ``<service>:<sub>:<verb>``. No wildcards —
# every scope is a concrete leaf.
_SCOPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?::[a-z][a-z0-9_]*){1,2}$")


def _fake_access_token(claims: dict[str, object], scopes: list[str] | None = None) -> MagicMock:
    """Minimal stand-in for ``fastmcp.server.auth.AccessToken``.

    ``scopes`` is an explicit parameter (not read from ``claims["scopes"]``)
    because the real JWTVerifier populates ``AccessToken.scopes`` only from
    the OAuth ``scope``/``scp`` claims — agent-jwt tokens leave it empty.
    """
    token = MagicMock()
    token.claims = claims
    token.scopes = scopes if scopes is not None else []
    return token


class TestToolScopesRegistry:
    def test_registry_non_empty(self) -> None:
        assert TOOL_SCOPES, "TOOL_SCOPES must list at least one tool"

    def test_every_scope_matches_pattern(self) -> None:
        bad = {
            tool: scope for tool, scope in TOOL_SCOPES.items() if not _SCOPE_PATTERN.match(scope)
        }
        assert not bad, f"scopes must match service:verb pattern: {bad}"

    def test_tool_names_use_mount_prefix(self) -> None:
        """Every key is the mount-prefixed form (``<namespace>_<tool>``)."""
        bare = [name for name in TOOL_SCOPES if "_" not in name]
        assert not bare, f"unprefixed tool names in registry: {bare}"

    def test_comms_admin_not_a_tool_scope(self) -> None:
        """``comms:admin`` gates a parameter (``is_shared=True`` on
        registration), not tool reachability -- it must never appear in
        TOOL_SCOPES, or it would invert the intended gate semantics."""
        assert "comms:admin" not in TOOL_SCOPES.values()

    def test_whoami_uses_comms_read(self) -> None:
        assert TOOL_SCOPES["comms_whoami"] == "comms:read"

    def test_every_defined_scope_constant_is_mintable(self) -> None:
        """Argus review B3: every scope constant this codebase defines
        (every TOOL_SCOPES value, plus the two standalone constants that
        gate something OTHER than a TOOL_SCOPES-enrolled tool --
        ``comms:admin`` and ``PROPOSAL_SUBMIT_SCOPE``) must be mintable via
        ``mint_token``'s CLI. A scope missing from ``mint_token._VALID_
        SCOPES`` can never legitimately be minted, making whatever it
        gates permanently unreachable by any agent-jwt caller -- this is
        exactly the hole B3 found for ``PROPOSAL_SUBMIT_SCOPE``."""
        every_defined_scope = set(TOOL_SCOPES.values()) | {"comms:admin", PROPOSAL_SUBMIT_SCOPE}
        missing = every_defined_scope - mint_token._VALID_SCOPES
        assert not missing, f"scope(s) defined but not mintable: {missing}"

    def test_get_hold_status_uses_comms_read(self) -> None:
        """TECH-5389 PR2: comms_get_hold_status is a pure read (sender-only
        poll of a held message's status), same scope as every other read."""
        assert TOOL_SCOPES["comms_get_hold_status"] == "comms:read"

    def test_archive_conversation_uses_comms_write(self) -> None:
        """TECH-5887: comms_archive_conversation is a mutating, symmetric-
        permission action (no elevated scope, no owner-only gate -- same
        as comms_leave), same scope as every other write."""
        assert TOOL_SCOPES["comms_archive_conversation"] == "comms:write"


class TestRequiredScopeFor:
    def test_known_tool(self) -> None:
        assert required_scope_for("comms_whoami") == "comms:read"

    def test_unmapped_tool_returns_none(self) -> None:
        assert required_scope_for("definitely_not_a_real_tool") is None

    def test_unmapped_resource_returns_none(self) -> None:
        # An unrecognized URI matches neither RESOURCE_SCOPES nor
        # RESOURCE_TEMPLATE_SCOPES and is therefore fail-closed for
        # agent-jwt callers.
        assert required_scope_for_resource("schema://anything") is None


class TestRequiredScopeForResource:
    def test_exact_match_static_resource(self) -> None:
        assert required_scope_for_resource("comms://comms/agents") == "comms:read"

    def test_template_match_concrete_conversation_uri(self) -> None:
        uri = "comms://comms/conversations/11111111-1111-1111-1111-111111111111"
        assert required_scope_for_resource(uri) == "comms:read"

    def test_template_match_concrete_inbox_uri(self) -> None:
        uri = "comms://comms/agents/22222222-2222-2222-2222-222222222222/inbox"
        assert required_scope_for_resource(uri) == "comms:read"

    def test_unknown_uri_returns_none(self) -> None:
        assert required_scope_for_resource("comms://comms/conversations") is None

    def test_template_does_not_match_across_path_segments(self) -> None:
        # The wildcard segment must not swallow a `/` — a URI with an extra
        # path component must not accidentally satisfy the template.
        uri = "comms://comms/conversations/abc/extra"
        assert required_scope_for_resource(uri) is None

    def test_every_registered_resource_scope_is_comms_read(self) -> None:
        """main.py's `_LIST_RESOURCES_REQUIRED_SCOPE` hardcodes a single
        flat `comms:read` requirement for resources/list and
        resources/templates/list (Argus round-1 SUGGESTION) on the
        assumption that every individually-enrolled resource ALSO requires
        `comms:read` — nothing else enforces that invariant, so check it
        explicitly here. If a future resource legitimately needs a
        different scope, `_gate_resource_listing` must become per-item
        filtering, not just a registry-table edit."""
        from scopes import RESOURCE_SCOPES, RESOURCE_TEMPLATE_SCOPES

        all_resource_scopes = set(RESOURCE_SCOPES.values()) | set(
            RESOURCE_TEMPLATE_SCOPES.values()
        )
        assert all_resource_scopes == {"comms:read"}


class TestIsInteractiveToken:
    def test_none_token_is_not_interactive(self) -> None:
        # None must fail closed — middleware rejects rather than bypassing.
        assert is_interactive_token(None) is False

    def test_agent_jwt_issuer_is_not_interactive(self) -> None:
        token = _fake_access_token({"iss": "agent-jwt", "sub": "bot-1"})
        assert is_interactive_token(token) is False

    def test_okta_issuer_is_interactive(self) -> None:
        # OIDCProxy mints tokens whose iss is the server's own URL.
        token = _fake_access_token({"iss": "https://agent-comms.example/mcp"})
        assert is_interactive_token(token) is True

    def test_missing_iss_claim_is_not_interactive(self) -> None:
        # A present token with no `iss` claim at all must fail closed rather
        # than falling through to the interactive (scope-bypass) branch.
        token = _fake_access_token({"sub": "bot-1"})
        assert is_interactive_token(token) is False

    def test_none_iss_claim_is_not_interactive(self) -> None:
        # Same guard, explicit `iss: None` rather than an absent key.
        token = _fake_access_token({"iss": None, "sub": "bot-1"})
        assert is_interactive_token(token) is False


class TestScopesForToken:
    """``scopes_for_token`` reads the agent-jwt ``scopes`` LIST claim."""

    def test_reads_scopes_claim_not_token_scopes(self) -> None:
        # token.scopes is deliberately different to prove the claim is the
        # source of truth, not the (empty, for agent-jwt) AccessToken.scopes.
        token = _fake_access_token(
            {"iss": "agent-jwt", "sub": "test-svc", "scopes": ["comms:read"]},
            scopes=["should-be-ignored"],
        )
        assert scopes_for_token(token) == ["comms:read"]

    def test_missing_scopes_claim_returns_empty(self) -> None:
        token = _fake_access_token({"iss": "agent-jwt", "sub": "test-svc"})
        assert scopes_for_token(token) == []

    def test_string_scalar_scopes_claim_returns_empty(self) -> None:
        # A string scalar must NOT be iterated char-by-char into bogus scopes.
        token = _fake_access_token({"iss": "agent-jwt", "sub": "test-svc", "scopes": "comms:read"})
        assert scopes_for_token(token) == []

    def test_non_agent_jwt_issuer_returns_empty(self) -> None:
        # Defense-in-depth issuer guard: even with a populated `scopes`
        # claim, a non-agent-jwt token yields no agent-jwt scopes.
        token = _fake_access_token(
            {"iss": "https://agent-comms.example/mcp", "scopes": ["comms:read"]}
        )
        assert scopes_for_token(token) == []

    def test_email_shaped_sub_fails_closed(self) -> None:
        # ``jwt issue --sub alice@example.com`` impersonation
        # shape — must yield no scopes.
        token = _fake_access_token(
            {
                "iss": "agent-jwt",
                "sub": "alice@example.com",
                "scopes": ["comms:read"],
            }
        )
        assert scopes_for_token(token) == []

    def test_missing_sub_fails_closed(self) -> None:
        token = _fake_access_token({"iss": "agent-jwt", "scopes": ["comms:read"]})
        assert scopes_for_token(token) == []

    def test_well_formed_sub_passes_guard(self) -> None:
        token = _fake_access_token(
            {"iss": "agent-jwt", "sub": "ea-agent-svc", "scopes": ["comms:read"]}
        )
        assert scopes_for_token(token) == ["comms:read"]


class TestSafeClientId:
    """client_id redaction + single emission point for auth_rejected."""

    def test_agent_jwt_email_shaped_sub_redacts_and_emits(self) -> None:
        token = _fake_access_token({"iss": "agent-jwt", "sub": "alice@example.com"})
        token.client_id = "alice@example.com"
        with patch("scopes.log_auth_rejected") as mock_emit:
            result = safe_client_id(token)
        assert result == "invalid_sub"
        mock_emit.assert_called_once_with(reason="sub_shape", issuer="agent-jwt")

    def test_agent_jwt_missing_sub_redacts_and_emits_sub_missing(self) -> None:
        token = _fake_access_token({"iss": "agent-jwt"})
        token.client_id = "unknown"
        with patch("scopes.log_auth_rejected") as mock_emit:
            result = safe_client_id(token)
        assert result == "invalid_sub"
        mock_emit.assert_called_once_with(reason="sub_missing", issuer="agent-jwt")

    def test_agent_jwt_well_formed_sub_passes_through_without_emit(self) -> None:
        # Legitimate denials must stay attributable, and legitimate
        # missing_scope denials must not inflate the auth_rejected counter.
        token = _fake_access_token({"iss": "agent-jwt", "sub": "ea-agent-svc"})
        token.client_id = "ea-agent-svc"
        with patch("scopes.log_auth_rejected") as mock_emit:
            result = safe_client_id(token)
        assert result == "ea-agent-svc"
        mock_emit.assert_not_called()

    def test_okta_token_passes_through_unchanged_without_emit(self) -> None:
        # Okta's client_id is a registered app id, not user-input sub —
        # and Okta subs are legitimately email-shaped.
        token = _fake_access_token(
            {
                "iss": "https://example.okta.com/oauth2/default",
                "sub": "alice@example.com",
            }
        )
        token.client_id = "0oa1234abc"
        with patch("scopes.log_auth_rejected") as mock_emit:
            result = safe_client_id(token)
        assert result == "0oa1234abc"
        mock_emit.assert_not_called()


class TestIsRegistryBackedAgentToken:
    """TECH-5593: whether ``owner_sub``/``owner_email`` claims are trusted
    for ownership write-through -- gated on which ``AGENT_TOKEN_VERIFIERS``
    plugin produced them, per ``auth.AGENT_TOKEN_VERIFIER_CLAIM``."""

    def test_none_token_returns_false(self) -> None:
        assert is_registry_backed_agent_token(None) is False

    def test_missing_verifier_claim_returns_false(self) -> None:
        token = _fake_access_token({"iss": "agent-jwt", "sub": "some-agent"})
        assert is_registry_backed_agent_token(token) is False

    def test_default_verifier_returns_false(self) -> None:
        token = _fake_access_token(
            {
                "iss": "agent-jwt",
                "sub": "some-agent",
                AGENT_TOKEN_VERIFIER_CLAIM: DEFAULT_AGENT_TOKEN_VERIFIER,
            }
        )
        assert is_registry_backed_agent_token(token) is False

    def test_non_default_verifier_returns_true(self) -> None:
        token = _fake_access_token(
            {
                "iss": "agent-jwt",
                "sub": "some-agent",
                AGENT_TOKEN_VERIFIER_CLAIM: "some_consumer.auth:build_custom_verifier",
            }
        )
        assert is_registry_backed_agent_token(token) is True

    def test_non_agent_jwt_issuer_returns_false_even_with_verifier_claim(self) -> None:
        """An interactive/Okta token was never routed through
        ``_NormalizingVerifier`` and so could not legitimately carry
        ``AGENT_TOKEN_VERIFIER_CLAIM`` -- if one somehow does (a forged or
        malformed claim), the ``iss`` guard must still fail closed rather
        than trust it."""
        token = _fake_access_token(
            {
                "iss": "https://agent-comms.example/mcp",
                AGENT_TOKEN_VERIFIER_CLAIM: "some_consumer.auth:build_custom_verifier",
            }
        )
        assert is_registry_backed_agent_token(token) is False
