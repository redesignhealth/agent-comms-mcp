"""Okta OIDC + agent-jwt JWT authentication for agent-comms-mcp.

Auth paths
----------
Interactive users (Claude Code, Claude Desktop, browser):
    Okta OIDC via FastMCP ``OIDCProxy``. Uses ``verify_id_token=True`` so
    FastMCP validates the Okta id_token (which carries identity claims like
    ``email`` and ``preferred_username``) and makes those claims available
    to tools via ``get_access_token().claims``.

Programmatic callers (agents, services, CI jobs):
    agent-jwt HS256 Bearer token. FastMCP ``MultiAuth`` composes the Okta
    OIDC provider with a ``JWTVerifier`` keyed to ``AGENT_JWT_SECRET``.
    Both humans and machines POST to the same ``/mcp`` endpoint.

Health check (``/health``):
    Unauthenticated — handled by FastMCP before auth middleware runs.

Refresh-token rotation grace (``_ROTATION_*``): FastMCP rotates refresh
tokens on every use (one-time use). A second concurrent connection
presenting the just-consumed old token would otherwise fail hard and force
a full Okta re-auth. We record a short-lived old-token-hash -> new-token
mapping in the same persistent store on every rotation; a subsequent "miss"
checks this mapping first and transparently follows it before declaring a
real miss.

The hop counter is deliberately NOT a parameter of the public
``load_refresh_token`` override (see that method's own docstring) to close
a cap-reset weakness in a more permissive design.

Emitting ``refresh_token_miss`` / ``refresh_token_hop_cap_exceeded`` on
paths that previously logged nothing means a broad ``$.event = "auth_flow"``
log filter now also counts failed refresh lookups as auth activity — add
dedicated metric filters as needed (see observability.py's docstring).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from fastmcp.server.auth import MultiAuth
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.filetree import (
    FileTreeStore,
    FileTreeV1CollectionSanitizationStrategy,
    FileTreeV1KeySanitizationStrategy,
)
from mcp.server.auth.provider import AuthorizationCode, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from identity import AGENT_JWT_ISSUER
from observability import log_auth_flow

logger = logging.getLogger(__name__)

# Claims to extract from the Okta ID token into the FastMCP JWT.
_UPSTREAM_CLAIM_KEYS = ["sub", "email", "preferred_username", "name"]

_DEFAULT_TOKEN_STORAGE_PATH = "/data/fastmcp-tokens"

_ROTATION_GRACE_SECONDS = 5 * 60
_ROTATION_MAX_HOPS = 3
_ROTATION_COLLECTION = "mcp-refresh-token-rotations"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_env(name: str) -> str:
    """Return a required environment variable, failing fast if missing/empty.

    No silent defaults for secrets (RH security standard + the
    secret-loading-fallback-consistency failure mode): a missing required
    value must crash at startup, not surface later as a broken auth path.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is not set. "
            "See .env.example for the full list of required configuration."
        )
    return value


class OktaOIDCProxy(OIDCProxy):
    """OIDC proxy configured for Okta SSO.

    ``_extract_upstream_claims`` embeds the Okta id_token identity claims in
    the FastMCP JWT as a fallback for code paths that read from there; with
    ``verify_id_token=True`` the claims are also available directly. Emits
    structured ``auth_flow`` observability events.
    """

    def __init__(self, *, client_storage: AsyncKeyValue, **kwargs: Any) -> None:
        self._rotation_store = client_storage
        super().__init__(client_storage=client_storage, **kwargs)

    async def _extract_upstream_claims(self, idp_tokens: dict[str, Any]) -> dict[str, Any] | None:
        """Decode the Okta ID token and extract identity claims.

        SECURITY (call-ordering dependency): this decodes the id_token
        payload WITHOUT verifying its signature. That is safe ONLY because
        the parent ``OIDCProxy`` has already verified the token earlier in
        the OAuth exchange (this hook runs downstream of that verification,
        not before it) — if that call ordering ever changes, this becomes a
        forgeable trust boundary (an attacker-controlled payload would be
        trusted as identity claims).

        Defense-in-depth only (does not replace the ordering dependency
        above): reject ``alg: none`` tokens outright rather than extracting
        claims from them. This protects a misconfigured dev/test
        environment where the parent-class verification hasn't actually
        run yet — it is not a substitute for that verification.
        """
        id_token = idp_tokens.get("id_token")
        if not id_token:
            return None
        try:
            header_b64 = id_token.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)  # base64 padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            if not isinstance(header, dict):
                logger.error("Rejecting Okta id_token with non-object header")
                return None
            if str(header.get("alg", "")).lower() == "none":
                logger.error("Rejecting Okta id_token with alg=none")
                return None
            # Decode the JWT payload without verification — the upstream
            # provider already validated the token during the auth flow.
            payload_b64 = id_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)  # base64 padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if not isinstance(payload, dict):
                logger.error("Rejecting Okta id_token with non-object payload")
                return None
            claims = {k: payload[k] for k in _UPSTREAM_CLAIM_KEYS if k in payload}
            return claims or None
        except (IndexError, json.JSONDecodeError, ValueError):
            logger.error("Failed to decode Okta id_token for upstream claims")
            return None

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Exchange authorization code and emit a ``new_auth`` event."""
        result = await super().exchange_authorization_code(client, authorization_code)
        log_auth_flow("new_auth")
        return result

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Look up a refresh token, following a rotation-grace redirect on miss.

        FastMCP rotates refresh tokens on every use (one-time use). A second
        concurrent connection presenting the just-consumed old token would
        otherwise fail hard here and force a full Okta re-auth. Before
        declaring a real miss, check whether this token was rotated recently
        and, if so, transparently follow it to its successor (capped at
        ``_ROTATION_MAX_HOPS`` to bound a pathological chain).

        No hop counter in this signature on purpose: it's the base class's
        override point (FastMCP calls it positionally), so a public
        ``_hops`` parameter would let any caller reset the cap. Hop-tracking
        lives in the name-mangled ``__follow_rotation_grace`` instead.
        """
        result = await super().load_refresh_token(client, refresh_token)
        if result is not None:
            return result
        return await self.__follow_rotation_grace(client, refresh_token, hops=0)

    async def __follow_rotation_grace(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
        *,
        hops: int,
    ) -> RefreshToken | None:
        """Recursive hop-following helper for ``load_refresh_token``.

        Double-underscore (name-mangled to ``_OktaOIDCProxy__follow_rotation_grace``)
        rather than single, mainly to avoid an accidental same-name collision
        in a subclass -- NOT an access-control guarantee. Name mangling is
        trivially bypassable (``self._OktaOIDCProxy__follow_rotation_grace(...,
        hops=0)`` from a subclass, or simply overriding ``load_refresh_token``
        itself), so it does not by itself defend against a malicious
        subclass. The actual hardening that closed the original weakness is
        that ``hops`` is not a parameter of the PUBLIC ``load_refresh_token``
        override point FastMCP calls -- an ordinary caller (not a subclass
        author deliberately reaching for the mangled name) has no way to
        supply it at all.
        """
        entry = await self._rotation_store.get(
            collection=_ROTATION_COLLECTION, key=_hash_token(refresh_token)
        )
        successor = entry.get("new_token") if entry is not None else None
        if successor and hops < _ROTATION_MAX_HOPS:
            logger.info("Refresh token reuse detected: redirecting to rotated successor")
            log_auth_flow("refresh_token_grace_redirect")
            result = await super().load_refresh_token(client, successor)
            if result is not None:
                return result
            return await self.__follow_rotation_grace(client, successor, hops=hops + 1)
        if successor:
            # A dedicated auth_type, not folded into refresh_token_miss:
            # the chain kept going past the cap, which is a structurally
            # different condition from "no rotation entry at all" and
            # needs its own CloudWatch signal for on-call triage. hops is
            # not sensitive; the token/its hash is deliberately NOT
            # included here (observability.py's never-log-tokens policy).
            logger.warning("Refresh token rotation-grace hop cap exceeded", extra={"hops": hops})
            log_auth_flow("refresh_token_hop_cap_exceeded")
            return None
        log_auth_flow("refresh_token_miss")
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token, emit a ``token_refresh`` event, and record
        the old->new rotation mapping for the grace window."""
        old_token = refresh_token.token
        result = await super().exchange_refresh_token(client, refresh_token, scopes)
        log_auth_flow("token_refresh")
        if result.refresh_token:
            # SECURITY: the stored value is the live successor refresh
            # token in plaintext, not a hash -- the hashed KEY only
            # prevents reverse-lookup of the just-consumed OLD token, it
            # does not protect the new one. Accepted posture: this collection
            # lives in the same EFS-backed, task-role-scoped store as the primary
            # token store, which already holds live refresh tokens
            # unencrypted (see build_okta_provider's client_storage). Anyone
            # who can read one collection can read the other.
            await self._rotation_store.put(
                collection=_ROTATION_COLLECTION,
                key=_hash_token(old_token),
                value={"new_token": result.refresh_token},
                ttl=_ROTATION_GRACE_SECONDS,
            )
        return result


def _build_client_storage(storage_path: str) -> FileTreeStore:
    """Build a FileTreeStore with standard V1 sanitization for CIMD-safe keys.

    The stock ``FileTreeV1`` strategies hash any key or collection name
    containing filesystem-unsafe characters, so URL-style client IDs are
    stored safely on the persistent volume. The directory is created if
    missing (the sanitization strategies require an existing path).
    """
    storage_root = Path(storage_path)
    storage_root.mkdir(parents=True, exist_ok=True)
    return FileTreeStore(
        data_directory=storage_path,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(storage_root),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(storage_root),
    )


def build_okta_provider() -> OktaOIDCProxy:
    """Build an OktaOIDCProxy from environment variables.

    Required environment variables (fail-fast if missing):
        OKTA_ISSUER_URL: Okta authorization server issuer URL
        OKTA_CLIENT_ID: Okta application client ID
        OKTA_CLIENT_SECRET: Okta application client secret
        MCP_JWT_SECRET: Stable JWT signing secret (provisioned by Terraform,
            injected via SSM)

    Optional environment variables (non-secret, documented defaults):
        BASE_URL: Public URL of this MCP server
            (default: http://localhost:8080, for local dev)
        MCP_TOKEN_STORAGE_PATH: Directory for persistent OAuth token storage
            (default: /data/fastmcp-tokens, EFS-backed on ECS)
    """
    issuer_url = require_env("OKTA_ISSUER_URL")
    config_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    storage_path = os.environ.get("MCP_TOKEN_STORAGE_PATH", _DEFAULT_TOKEN_STORAGE_PATH)

    return OktaOIDCProxy(
        config_url=config_url,
        client_id=require_env("OKTA_CLIENT_ID"),
        client_secret=require_env("OKTA_CLIENT_SECRET"),
        base_url=os.environ.get("BASE_URL", "http://localhost:8080"),
        # offline_access is required for Okta to issue a refresh_token;
        # without it clients must do a full re-auth every ~1 hour.
        required_scopes=["openid", "email", "profile", "offline_access"],
        jwt_signing_key=require_env("MCP_JWT_SECRET"),
        client_storage=_build_client_storage(storage_path),
        verify_id_token=True,
        # FastMCP's CIMD redirect_uri validation rejects Claude Code's
        # dynamic-port loopback callbacks.
        enable_cimd=False,
    )


def build_auth_provider() -> MultiAuth:
    """Compose Okta OIDC + agent-jwt JWT verification via FastMCP MultiAuth.

    MultiAuth tries the Okta OIDCProxy first (interactive users), then the
    JWTVerifier (programmatic agent-jwt tokens). The two paths are fully
    independent.

    Required environment variables:
        AGENT_JWT_SECRET: Shared HS256 secret for verifying agent-jwt tokens.
        (Plus everything required by ``build_okta_provider``.)
    """
    return MultiAuth(
        server=build_okta_provider(),
        verifiers=[
            JWTVerifier(
                public_key=require_env("AGENT_JWT_SECRET"),
                algorithm="HS256",
                issuer=AGENT_JWT_ISSUER,
            ),
        ],
        # CRITICAL: do NOT inherit the Okta provider's
        # required_scopes (["openid", "email", "profile", "offline_access"]).
        # MultiAuth's bearer middleware enforces required_scopes against
        # EVERY verified token — including agent-jwt M2M JWTs, which never
        # carry `openid`. Inheriting them silently rejects all agent-jwt
        # tokens with `insufficient_scope` even after a valid signature.
        # Authorization for agent-jwt callers is handled per-tool by
        # ScopeEnforcementMiddleware, so the provider-level gate must be
        # empty.
        required_scopes=[],
    )
