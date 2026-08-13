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
from unittest.mock import AsyncMock, MagicMock, call, patch

from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthToken

from auth import _ROTATION_MAX_HOPS, OktaOIDCProxy, build_okta_provider

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
