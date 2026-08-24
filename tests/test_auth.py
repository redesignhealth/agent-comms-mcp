"""Tests for auth.py's ``OktaOIDCProxy``.

Mirrors ``tests/test_main.py``'s idiom: the OIDC discovery fetch is patched
out so tests never touch the network, and the required auth env vars are
provided (via ``_ENV_PATCH``, on top of ``conftest.py``'s autouse
``_auth_env`` fixture) so ``build_okta_provider()`` can construct a real
``OktaOIDCProxy`` without hitting Okta.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from fastmcp.server.auth import AccessToken, MultiAuth, TokenVerifier
from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthToken

from auth import (
    _ROTATION_MAX_HOPS,
    AGENT_TOKEN_VERIFIER_CLAIM,
    AGENT_TOKEN_VERIFIERS_ENV_VAR,
    TOKEN_VERIFIERS,
    OktaOIDCProxy,
    _expiry_violation,
    _NormalizingVerifier,
    _resolve_agent_token_verifiers,
    build_okta_provider,
)

_MOCK_OIDC_CONFIG = MagicMock()
_OIDC_PATCH = patch(
    "fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration",
    return_value=_MOCK_OIDC_CONFIG,
)
_ENV_PATCH = patch.dict(
    os.environ,
    {
        "OKTA_ISSUER_URL": "https://example.okta.com/oauth2/default",
        "OKTA_CLIENT_ID": "test-id",
        "OKTA_CLIENT_SECRET": "test-secret",
        "BASE_URL": "http://localhost:8080",
        "MCP_JWT_SECRET": "test-jwt-secret",
    },
)


def _build_proxy() -> OktaOIDCProxy:
    with _OIDC_PATCH, _ENV_PATCH:
        return build_okta_provider()


def _fake_id_token(payload: dict[str, object], alg: str = "RS256") -> str:
    """Build a well-formed-but-unsigned JWT string carrying ``payload``.

    ``_extract_upstream_claims`` decodes the id_token payload WITHOUT
    verifying its signature (safe only because the parent ``OIDCProxy`` has
    already verified it earlier in the OAuth exchange — see the comment
    added next to the real implementation), so the signature segment here
    is an arbitrary placeholder; only the header/payload base64 segments
    need to be well-formed.

    ``alg`` defaults to ``"RS256"`` (Okta's real signing algorithm) rather
    than ``"none"`` — the ``alg: none`` guard in ``_extract_upstream_claims``
    now rejects tokens outright, so the "happy path" fixtures need a
    realistic header. Pass ``alg="none"`` explicitly to exercise that guard.
    """

    def _b64(data: dict[str, object] | bytes) -> str:
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = _b64({"alg": alg, "typ": "JWT"})
    body = _b64(payload)
    return f"{header}.{body}.fake-signature"


class TestExtractUpstreamClaims:
    async def test_valid_id_token_extracts_expected_claims(self) -> None:
        proxy = _build_proxy()
        id_token = _fake_id_token(
            {
                "sub": "okta-sub-123",
                "email": "person@example.com",
                "preferred_username": "person@example.com",
                "name": "Person Name",
                "iat": 1700000000,
                "exp": 1700003600,
            }
        )

        claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims == {
            "sub": "okta-sub-123",
            "email": "person@example.com",
            "preferred_username": "person@example.com",
            "name": "Person Name",
        }

    async def test_id_token_with_only_some_expected_claims(self) -> None:
        proxy = _build_proxy()
        id_token = _fake_id_token({"sub": "okta-sub-456", "iat": 1700000000})

        claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims == {"sub": "okta-sub-456"}

    async def test_missing_id_token_key_returns_none(self) -> None:
        proxy = _build_proxy()

        assert await proxy._extract_upstream_claims({}) is None
        assert await proxy._extract_upstream_claims({"access_token": "irrelevant"}) is None

    async def test_empty_id_token_value_returns_none(self) -> None:
        proxy = _build_proxy()

        assert await proxy._extract_upstream_claims({"id_token": ""}) is None

    async def test_malformed_id_token_returns_none_and_logs_error(self) -> None:
        proxy = _build_proxy()

        with patch("auth.logger") as mock_logger:
            claims = await proxy._extract_upstream_claims({"id_token": "not-a-jwt-at-all"})

        assert claims is None
        mock_logger.error.assert_called_once()

    async def test_truncated_base64_payload_returns_none(self) -> None:
        proxy = _build_proxy()
        # Well-formed, valid-JSON header (so the alg=none guard's JSON
        # parse succeeds and execution reaches the payload-decode step),
        # but the payload segment is not valid base64/JSON once decoded.
        valid_header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
            .decode()
            .rstrip("=")
        )
        truncated = f"{valid_header}.not-valid-base64-json!!!.sig"

        with patch("auth.logger") as mock_logger:
            claims = await proxy._extract_upstream_claims({"id_token": truncated})

        assert claims is None
        mock_logger.error.assert_called_once()

    async def test_non_dict_header_returns_none_and_logs_error(self) -> None:
        # A header segment that base64-decodes to valid-but-non-dict JSON
        # (e.g. a JSON array) must not reach `header.get(...)` — that would
        # raise an unhandled AttributeError instead of failing closed.
        proxy = _build_proxy()
        non_dict_header = (
            base64.urlsafe_b64encode(json.dumps(["alg", "RS256"]).encode()).decode().rstrip("=")
        )
        id_token = f"{non_dict_header}.eyJzdWIiOiJ4In0.sig"

        with patch("auth.logger") as mock_logger:
            claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims is None
        mock_logger.error.assert_called_once()

    async def test_non_dict_payload_returns_none_and_logs_error(self) -> None:
        # A payload segment that base64-decodes to valid-but-non-dict JSON
        # (e.g. a JSON array) must not reach `payload[k]`-style dict access
        # -- that would raise instead of failing closed. Mirrors the header
        # guard's ``test_non_dict_header_returns_none_and_logs_error`` above.
        proxy = _build_proxy()
        valid_header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
            .decode()
            .rstrip("=")
        )
        non_dict_payload = (
            base64.urlsafe_b64encode(json.dumps(["sub", "x"]).encode()).decode().rstrip("=")
        )
        id_token = f"{valid_header}.{non_dict_payload}.sig"

        with patch("auth.logger") as mock_logger:
            claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims is None
        mock_logger.error.assert_called_once()

    async def test_alg_none_id_token_returns_none_and_logs_error(self) -> None:
        # Defense-in-depth guard: even though signature verification is the
        # parent OIDCProxy's job, an alg=none header must be rejected here
        # rather than have its claims extracted and trusted.
        proxy = _build_proxy()
        id_token = _fake_id_token({"sub": "attacker-controlled"}, alg="none")

        with patch("auth.logger") as mock_logger:
            claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims is None
        mock_logger.error.assert_called_once()

    async def test_alg_none_case_insensitive_returns_none(self) -> None:
        proxy = _build_proxy()
        id_token = _fake_id_token({"sub": "attacker-controlled"}, alg="None")

        claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims is None

    async def test_id_token_with_no_recognized_claims_returns_none(self) -> None:
        """Every claim key present but none of them in ``_UPSTREAM_CLAIM_KEYS``
        — the ``claims or None`` fallback must turn an empty dict into ``None``,
        not an empty-but-truthy-shaped dict."""
        proxy = _build_proxy()
        id_token = _fake_id_token({"iat": 1700000000, "exp": 1700003600, "aud": "test-id"})

        claims = await proxy._extract_upstream_claims({"id_token": id_token})

        assert claims is None


def _refresh_token(token: str) -> RefreshToken:
    return RefreshToken(token=token, client_id="test-client", scopes=["openid"])


class TestAuthFlowEventEmission:
    """The rotation-grace tests below assert log_auth_flow at each of their
    own call sites explicitly -- these two do the same for the two
    pre-existing call sites, so deleting either wouldn't go unnoticed."""

    async def test_exchange_authorization_code_emits_new_auth(self) -> None:
        proxy = _build_proxy()
        with (
            patch(
                "fastmcp.server.auth.oidc_proxy.OIDCProxy.exchange_authorization_code",
                AsyncMock(return_value=OAuthToken(access_token="tok", token_type="bearer")),
            ),
            patch("auth.log_auth_flow") as mock_log_auth_flow,
        ):
            await proxy.exchange_authorization_code(MagicMock(), MagicMock())

        mock_log_auth_flow.assert_called_once_with("new_auth")

    async def test_exchange_refresh_token_emits_token_refresh(self) -> None:
        proxy = _build_proxy()
        old = _refresh_token("some-old-token")
        with (
            patch(
                "fastmcp.server.auth.oidc_proxy.OIDCProxy.exchange_refresh_token",
                AsyncMock(return_value=OAuthToken(access_token="tok", token_type="bearer")),
            ),
            patch("auth.log_auth_flow") as mock_log_auth_flow,
        ):
            await proxy.exchange_refresh_token(MagicMock(), old, ["openid"])

        mock_log_auth_flow.assert_called_once_with("token_refresh")


class TestRefreshTokenRotationGrace:
    """A concurrent connection presenting a just-rotated (one-time-use)
    refresh token must transparently follow it to its successor within the
    grace window, rather than forcing a full re-auth.

    TTL expiry itself (a rotation entry becoming unreadable after
    ``_ROTATION_GRACE_SECONDS``) is NOT covered here -- that guarantee is
    owned by ``key_value.aio.stores.filetree.FileTreeStore``'s own TTL
    implementation, not by this class's logic, and asserting it here would
    mean either mocking time (fragile against that library's internal
    clock source) or a real 5-minute sleep in the test suite. Trusted as
    the dependency's own tested behavior.
    """

    async def test_load_refresh_token_returns_directly_when_found(self) -> None:
        proxy = _build_proxy()
        found = _refresh_token("still-valid")
        with patch(
            "fastmcp.server.auth.oidc_proxy.OIDCProxy.load_refresh_token",
            AsyncMock(return_value=found),
        ):
            result = await proxy.load_refresh_token(MagicMock(), "still-valid")

        assert result is found

    async def test_load_refresh_token_follows_rotation_on_miss(self) -> None:
        proxy = _build_proxy()
        successor = _refresh_token("new-token")

        async def fake_super_lookup(_client: object, token: str) -> RefreshToken | None:
            return successor if token == "new-token" else None

        with (
            patch(
                "fastmcp.server.auth.oidc_proxy.OIDCProxy.load_refresh_token",
                AsyncMock(side_effect=fake_super_lookup),
            ),
            patch("auth.log_auth_flow") as mock_log_auth_flow,
        ):
            await proxy._rotation_store.put(
                collection="mcp-refresh-token-rotations",
                key=hashlib.sha256(b"old-token").hexdigest(),
                value={"new_token": "new-token"},
                ttl=300,
            )
            result = await proxy.load_refresh_token(MagicMock(), "old-token")

        assert result is successor
        mock_log_auth_flow.assert_called_once_with("refresh_token_grace_redirect")

    async def test_load_refresh_token_returns_none_when_no_rotation_entry(self) -> None:
        proxy = _build_proxy()
        with (
            patch(
                "fastmcp.server.auth.oidc_proxy.OIDCProxy.load_refresh_token",
                AsyncMock(return_value=None),
            ),
            patch("auth.log_auth_flow") as mock_log_auth_flow,
        ):
            result = await proxy.load_refresh_token(MagicMock(), "never-issued")

        assert result is None
        mock_log_auth_flow.assert_called_once_with("refresh_token_miss")

    async def test_load_refresh_token_resolves_full_hop_chain(self) -> None:
        """A chain of exactly _ROTATION_MAX_HOPS hops (the guard is
        evaluated at hops == 0, 1, ..., _ROTATION_MAX_HOPS - 1, never
        reaching _ROTATION_MAX_HOPS itself here) must resolve successfully
        -- guards against an off-by-one that caps the chain too early.

        This does NOT by itself pin whether the guard's comparison is
        strict `<` or `<=` against _ROTATION_MAX_HOPS -- the hop counter
        never reaches _ROTATION_MAX_HOPS in this chain, so both operators
        would pass it. test_load_refresh_token_caps_hop_chain is the one
        that actually discriminates: it forces the guard to evaluate AT
        hops == _ROTATION_MAX_HOPS, where `<` denies and `<=` would not.
        Don't remove that test on the assumption this one covers it."""
        proxy = _build_proxy()
        final_token = _refresh_token("token-final")

        async def fake_super_lookup(_client: object, token: str) -> RefreshToken | None:
            return final_token if token == "token-final" else None

        with (
            patch(
                "fastmcp.server.auth.oidc_proxy.OIDCProxy.load_refresh_token",
                AsyncMock(side_effect=fake_super_lookup),
            ),
            patch("auth.log_auth_flow") as mock_log_auth_flow,
        ):
            # token-0 -> token-1 -> ... -> token-final, exactly
            # _ROTATION_MAX_HOPS hops (0 through _ROTATION_MAX_HOPS - 1).
            chain = [f"token-{i}" for i in range(_ROTATION_MAX_HOPS)] + ["token-final"]
            for old, new in itertools.pairwise(chain):
                await proxy._rotation_store.put(
                    collection="mcp-refresh-token-rotations",
                    key=hashlib.sha256(old.encode()).hexdigest(),
                    value={"new_token": new},
                    ttl=300,
                )
            result = await proxy.load_refresh_token(MagicMock(), "token-0")

        assert result is final_token
        expected_calls = [call("refresh_token_grace_redirect")] * _ROTATION_MAX_HOPS
        assert mock_log_auth_flow.call_args_list == expected_calls

    async def test_load_refresh_token_caps_hop_chain(self) -> None:
        """A chain longer than _ROTATION_MAX_HOPS must not be followed
        indefinitely -- each hop's own token is itself immediately
        rotated again, one hop too many."""
        proxy = _build_proxy()
        with (
            patch(
                "fastmcp.server.auth.oidc_proxy.OIDCProxy.load_refresh_token",
                AsyncMock(return_value=None),
            ),
            patch("auth.log_auth_flow") as mock_log_auth_flow,
            patch("auth.logger") as mock_logger,
        ):
            # token-0 -> token-1 -> token-2 -> token-3: _ROTATION_MAX_HOPS
            # == 3 hops (0, 1, 2) are followed; the 4th lookup (hop 3) hits
            # the cap. range(_ROTATION_MAX_HOPS + 1) seeds exactly the
            # entries this chain actually consumes, no unreachable extras.
            for i in range(_ROTATION_MAX_HOPS + 1):
                await proxy._rotation_store.put(
                    collection="mcp-refresh-token-rotations",
                    key=hashlib.sha256(f"token-{i}".encode()).hexdigest(),
                    value={"new_token": f"token-{i + 1}"},
                    ttl=300,
                )
            result = await proxy.load_refresh_token(MagicMock(), "token-0")

        assert result is None
        # _ROTATION_MAX_HOPS hops followed (grace_redirect each time)
        # before the cap kills the next one, ending in exactly one
        # terminal hop_cap_exceeded -- not one per exhausted hop, and
        # distinct from a genuine refresh_token_miss (own auth_type).
        expected_calls = [call("refresh_token_grace_redirect")] * _ROTATION_MAX_HOPS
        expected_calls.append(call("refresh_token_hop_cap_exceeded"))
        assert mock_log_auth_flow.call_args_list == expected_calls
        mock_logger.warning.assert_called_once_with(
            "Refresh token rotation-grace hop cap exceeded",
            extra={"hops": _ROTATION_MAX_HOPS},
        )

    async def test_exchange_refresh_token_records_rotation_mapping(self) -> None:
        proxy = _build_proxy()
        old = _refresh_token("old-token")
        new_oauth_token = OAuthToken(
            access_token="new-access", token_type="bearer", refresh_token="new-token"
        )
        with patch(
            "fastmcp.server.auth.oidc_proxy.OIDCProxy.exchange_refresh_token",
            AsyncMock(return_value=new_oauth_token),
        ):
            result = await proxy.exchange_refresh_token(MagicMock(), old, ["openid"])

        assert result is new_oauth_token
        entry = await proxy._rotation_store.get(
            collection="mcp-refresh-token-rotations",
            key=hashlib.sha256(b"old-token").hexdigest(),
        )
        assert entry == {"new_token": "new-token"}

    async def test_exchange_refresh_token_records_nothing_when_no_new_refresh_token(self) -> None:
        proxy = _build_proxy()
        old = _refresh_token("old-token-2")
        new_oauth_token = OAuthToken(access_token="new-access", token_type="bearer")
        with patch(
            "fastmcp.server.auth.oidc_proxy.OIDCProxy.exchange_refresh_token",
            AsyncMock(return_value=new_oauth_token),
        ):
            await proxy.exchange_refresh_token(MagicMock(), old, ["openid"])

        entry = await proxy._rotation_store.get(
            collection="mcp-refresh-token-rotations",
            key=hashlib.sha256(b"old-token-2").hexdigest(),
        )
        assert entry is None


# --- AGENT_TOKEN_VERIFIERS: registry resolution + normalized-claims contract


def _access_token(
    *,
    iss: str | object = "agent-jwt",
    sub: object = "test-agent",
    scopes: object = ("comms:read",),
    owner_sub: str | None = None,
    exp: object = None,
    nbf: object = None,
    expires_at: int | None = None,
) -> AccessToken:
    """Build an ``AccessToken`` with the given claims (``iss``/``sub`` may be
    omitted entirely by passing ``None`` explicitly for that argument)."""
    claims: dict[str, object] = {}
    if iss is not None:
        claims["iss"] = iss
    if sub is not None:
        claims["sub"] = sub
    if scopes is not None:
        claims["scopes"] = list(scopes) if isinstance(scopes, (list, tuple)) else scopes
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    if exp is not None:
        claims["exp"] = exp
    if nbf is not None:
        claims["nbf"] = nbf
    return AccessToken(
        token="tok", client_id="test-agent", scopes=[], claims=claims, expires_at=expires_at
    )


class _FakeVerifier(TokenVerifier):
    """Minimal ``TokenVerifier`` returning a fixed result -- a stand-in for
    a consumer's own verifier, used to test the seam's resolution/adapter
    logic without depending on a real JWT."""

    def __init__(self, result: AccessToken | None) -> None:
        super().__init__()
        self._result = result

    async def verify_token(self, token: str) -> AccessToken | None:
        return self._result


# Import-path-resolvable module-level factories (referenced by dotted path
# in AGENT_TOKEN_VERIFIERS, mirroring test_plugins.py's
# "tests.test_plugins:_FakeScorer" convention).
def _fake_failing_verifier_factory() -> TokenVerifier:
    return _FakeVerifier(None)


def _fake_succeeding_verifier_factory() -> TokenVerifier:
    return _FakeVerifier(_access_token(sub="ok-agent"))


class TestResolveAgentTokenVerifiersRegistry:
    def test_default_env_resolves_to_agent_jwt_hs256(self) -> None:
        verifiers = _resolve_agent_token_verifiers()
        assert len(verifiers) == 1
        assert isinstance(verifiers[0], _NormalizingVerifier)

    def test_registry_contains_agent_jwt_hs256(self) -> None:
        assert "agent_jwt_hs256" in TOKEN_VERIFIERS

    def test_empty_value_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(AGENT_TOKEN_VERIFIERS_ENV_VAR, "")
        with pytest.raises(RuntimeError, match=AGENT_TOKEN_VERIFIERS_ENV_VAR):
            _resolve_agent_token_verifiers()

    def test_unknown_registry_name_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(AGENT_TOKEN_VERIFIERS_ENV_VAR, "not_a_registered_name")
        with pytest.raises(RuntimeError, match="unknown plugin"):
            _resolve_agent_token_verifiers()

    def test_bad_import_path_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(AGENT_TOKEN_VERIFIERS_ENV_VAR, "not_a_real_module:Whatever")
        with pytest.raises(RuntimeError, match="failed to import plugin"):
            _resolve_agent_token_verifiers()


class TestAgentTokenVerifierCoexistenceAndReplacement:
    async def test_coexistence_order_first_fails_second_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            AGENT_TOKEN_VERIFIERS_ENV_VAR,
            "tests.test_auth:_fake_failing_verifier_factory,"
            "tests.test_auth:_fake_succeeding_verifier_factory",
        )
        verifiers = _resolve_agent_token_verifiers()
        assert len(verifiers) == 2

        multi = MultiAuth(verifiers=verifiers)
        result = await multi.verify_token("whatever")

        assert result is not None
        assert result.claims is not None
        assert result.claims["sub"] == "ok-agent"

    def test_full_replacement_does_not_require_agent_jwt_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A lone import path (no ``agent_jwt_hs256``) fully replaces the
        default, so ``AGENT_JWT_SECRET`` must not be required."""
        monkeypatch.setenv(
            AGENT_TOKEN_VERIFIERS_ENV_VAR, "tests.test_auth:_fake_succeeding_verifier_factory"
        )
        monkeypatch.delenv("AGENT_JWT_SECRET", raising=False)

        verifiers = _resolve_agent_token_verifiers()

        assert len(verifiers) == 1


class TestNormalizingVerifierContract:
    """The adapter's normalized-claims contract: bad iss, invalid sub shape,
    and non-list scopes must each be treated as verification FAILURE (None),
    not passed through -- fail-closed, per auth.py's ``_NormalizingVerifier``
    docstring."""

    async def test_passes_through_a_valid_normalized_token(self) -> None:
        token = _access_token(iss="agent-jwt", sub="good-agent", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        result = await verifier.verify_token("whatever")

        assert result is token

    async def test_passes_through_a_none_result_unchanged(self) -> None:
        verifier = _NormalizingVerifier(_FakeVerifier(None), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_optional_owner_sub_is_allowed(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=[], owner_sub="human@example.com"
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is token

    async def test_rejects_wrong_issuer(self) -> None:
        token = _access_token(iss="acme", sub="good-agent", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        with patch("auth.logger") as mock_logger:
            result = await verifier.verify_token("whatever")

        assert result is None
        mock_logger.warning.assert_called_once()

    async def test_rejects_email_shaped_sub(self) -> None:
        token = _access_token(iss="agent-jwt", sub="alice@example.com", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_missing_sub(self) -> None:
        token = _access_token(iss="agent-jwt", sub=None, scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_empty_sub(self) -> None:
        token = _access_token(iss="agent-jwt", sub="   ", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_non_list_scopes(self) -> None:
        token = _access_token(iss="agent-jwt", sub="good-agent", scopes="comms:read")
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_non_string_sub(self) -> None:
        token = _access_token(iss="agent-jwt", sub=12345, scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_non_string_scopes_elements(self) -> None:
        token = _access_token(iss="agent-jwt", sub="good-agent", scopes=[1, 2])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_expired_via_access_token_expires_at(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], expires_at=1
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_expired_via_exp_claim(self) -> None:
        token = _access_token(iss="agent-jwt", sub="good-agent", scopes=["comms:read"], exp=1)
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_not_yet_valid_via_nbf_claim(self) -> None:
        far_future = 9999999999
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], nbf=far_future
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_non_numeric_exp_claim(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], exp="not-a-number"
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_boolean_exp_claim_as_expired(self) -> None:
        """``exp=True`` coerces to ``float(1.0)`` (1970-01-01), so it's
        rejected as expired rather than as a type error -- correct outcome,
        pinning the actual code path taken."""
        token = _access_token(iss="agent-jwt", sub="good-agent", scopes=["comms:read"], exp=True)
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_nan_exp_claim(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], exp=float("nan")
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_infinite_exp_claim(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], exp=float("inf")
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_nan_nbf_claim(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], nbf=float("nan")
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_rejects_infinite_nbf_claim(self) -> None:
        token = _access_token(
            iss="agent-jwt", sub="good-agent", scopes=["comms:read"], nbf=float("inf")
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is None

    async def test_accepts_nbf_within_clock_skew_leeway(self) -> None:
        """An ``nbf`` a few seconds in the future (well under the 60s leeway) must
        still pass -- this is exactly the ordinary-clock-drift case the leeway
        exists for (e.g. ``nbf == iat`` on a host whose clock runs slightly
        ahead of this one)."""
        now = time.time()
        token = _access_token(iss="agent-jwt", sub="good-agent", scopes=["comms:read"], nbf=now + 5)
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is token

    def test_expiry_violation_rejects_nonfinite_expires_at_directly(self) -> None:
        """AccessToken.expires_at is a pydantic int field that rejects NaN/inf at
        construction time via normal validation, so this path can't be exercised
        through a real AccessToken -- test _expiry_violation directly instead, the
        same way an honest-but-buggy plugin using model_construct() to skip
        validation could still reach this code."""
        assert _expiry_violation(float("nan"), {}) is not None
        assert _expiry_violation(float("inf"), {}) is not None
        assert _expiry_violation(int(time.time()) + 3600, {}) is None

    async def test_accepts_future_exp_and_past_nbf(self) -> None:
        far_future = 9999999999
        token = _access_token(
            iss="agent-jwt",
            sub="good-agent",
            scopes=["comms:read"],
            exp=far_future,
            nbf=1,
            expires_at=far_future,
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="fake")

        assert await verifier.verify_token("whatever") is token


class TestPluginVerifiedTokenMatchesDefaultDownstream:
    """A normalized plugin-verified token must be indistinguishable from a
    default-verified one to scopes.py/identity.py -- the whole point of the
    contract."""

    def test_scopes_for_token_reads_the_scopes_claim(self) -> None:
        from scopes import scopes_for_token

        token = _access_token(
            iss="agent-jwt", sub="plugin-agent", scopes=["comms:read", "comms:write"]
        )
        assert scopes_for_token(token) == ["comms:read", "comms:write"]

    def test_is_interactive_token_is_false(self) -> None:
        from scopes import is_interactive_token

        token = _access_token(iss="agent-jwt", sub="plugin-agent", scopes=["comms:read"])
        assert is_interactive_token(token) is False

    def test_try_resolve_email_resolves_via_sub(self) -> None:
        from identity import try_resolve_email

        token = _access_token(iss="agent-jwt", sub="plugin-agent", scopes=[])
        assert try_resolve_email(token) == "plugin-agent"


class TestNormalizingVerifierStampsVerifierClaim:
    """TECH-5593: ``_NormalizingVerifier`` tags every token it passes
    through with which configured verifier produced it, so
    ``scopes.is_registry_backed_agent_token`` can tell a plugin's claims
    apart from the built-in default's."""

    async def test_stamps_plugin_name_on_success(self) -> None:
        token = _access_token(iss="agent-jwt", sub="plugin-agent", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="my_plugin")

        result = await verifier.verify_token("whatever")

        assert result is token
        assert result.claims[AGENT_TOKEN_VERIFIER_CLAIM] == "my_plugin"

    async def test_stamps_default_verifier_name(self) -> None:
        token = _access_token(iss="agent-jwt", sub="default-agent", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="agent_jwt_hs256")

        result = await verifier.verify_token("whatever")

        assert result.claims[AGENT_TOKEN_VERIFIER_CLAIM] == "agent_jwt_hs256"

    async def test_rejected_token_is_not_stamped(self) -> None:
        """A violation must still return None -- confirms the stamp is
        applied strictly after both contract checks pass, never as a side
        effect that could leak into a rejected token's claims dict."""
        token = _access_token(iss="wrong-issuer", sub="plugin-agent", scopes=["comms:read"])
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="my_plugin")

        result = await verifier.verify_token("whatever")

        assert result is None
        assert AGENT_TOKEN_VERIFIER_CLAIM not in token.claims

    async def test_overwrites_a_claim_the_inner_verifier_already_set(self) -> None:
        """Forgery-prevention regression: an inner verifier (honest-but-
        buggy, or a malicious one within the operator-trust threat model
        auth.py's own module docstring accepts) that already sets
        AGENT_TOKEN_VERIFIER_CLAIM on the claims it returns must NOT be
        able to make its token masquerade as coming from a DIFFERENT
        configured verifier -- this adapter always overwrites it with the
        actual ``plugin_name`` it was constructed with, never trusting
        whatever the inner verifier already put there."""
        token = AccessToken(
            token="tok",
            client_id="forger-agent",
            scopes=[],
            claims={
                "iss": "agent-jwt",
                "sub": "forger-agent",
                "scopes": ["comms:read"],
                AGENT_TOKEN_VERIFIER_CLAIM: "a_different_trusted_plugin",
            },
        )
        verifier = _NormalizingVerifier(_FakeVerifier(token), plugin_name="the_real_plugin_name")

        result = await verifier.verify_token("whatever")

        assert result is not None
        assert result.claims[AGENT_TOKEN_VERIFIER_CLAIM] == "the_real_plugin_name"
