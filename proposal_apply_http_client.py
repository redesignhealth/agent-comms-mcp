"""Board-side HTTP client for the proposal apply endpoint (TECH-6213 PR-B1).

Calls ``agent-comms-approvals``' own ``POST /actions/proposals/apply``
(``proposal_action_api/app.py``, TECH-6213 PR-A2) instead of executing Linear
writes in-process.

This module finalizes the architectural boundary established by TECH-6213:
the board holds ZERO Linear credentials and executes ZERO Linear code paths.
- Judgment (``classify``, ``fingerprint``, ``judge``) remains an in-process plugin
  via ``RHProposalJudge``, with reads proxied via ``linear_read_http_client``
  (TECH-6213 PR-A3).
- Action (``apply``) calls this module, dispatching mutations over HTTP to
  ``agent-comms-approvals``' isolated deployment.

Contract:
- ``apply_proposal()`` satisfies the ``ProposalJudge.apply()`` protocol signature:
  it takes a ``ProposalContext`` and returns a ``ProposalApplyOutcome``.
- Unlike the read client (which raises on failure), this client MUST NEVER RAISE
  for transport errors, HTTP errors, timeouts, or malformed responses: any such
  failure is mapped to a safe ``applied=False`` outcome with a caller-safe
  error message and logged at appropriate severity. ``asyncio.CancelledError``
  is re-raised so task cancellation propagates cleanly to the board's
  recovery guards.
- Idempotency is keyed server-side on ``hold_id`` (stored in the
  ``proposal_apply_attempts`` table).

Env vars:
    PROPOSAL_APPLY_URL: base URL of ``agent-comms-approvals``' proposal
        action API mount point, e.g.
        ``https://comms-approvals.<tailnet>.ts.net/actions`` (prod) or
        ``https://comms-approvals-dev.<tailnet>.ts.net/actions`` (dev) --
        this client appends ``/proposals/apply`` itself. Required; must start
        with ``https://``.
    PROPOSAL_APPLY_TOKEN: bearer token carrying the ``proposals:apply`` scope
        (see ``ownership_api.auth.require_scope``). Required.
    PROPOSAL_APPLY_TLS_SNI_HOST: optional ``*.<tailnet>.ts.net`` MagicDNS
        hostname to validate TLS against while dialing ``PROPOSAL_APPLY_URL``'s
        own private-zone hostname (TECH-5400).
    PROPOSAL_APPLY_TIMEOUT_SECONDS: optional per-call HTTP timeout, default
        ``DEFAULT_TIMEOUT_SECONDS`` (15.0s) -- matching
        ``linear_read_http_client``'s timeout to provide headroom over the
        inner Linear write call.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import math
import os
import re
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, cast

import httpx

from plugins import (
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalContext,
    ProposalFingerprint,
    ProposalVerdict,
)

logger = logging.getLogger(__name__)

PROPOSAL_APPLY_URL_ENV_VAR = "PROPOSAL_APPLY_URL"
PROPOSAL_APPLY_TOKEN_ENV_VAR = "PROPOSAL_APPLY_TOKEN"
PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR = "PROPOSAL_APPLY_TLS_SNI_HOST"
PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR = "PROPOSAL_APPLY_TIMEOUT_SECONDS"

DEFAULT_TIMEOUT_SECONDS = 15.0
_PROPOSAL_APPLY_PATH = "/proposals/apply"

_MAX_LOG_FIELD_LENGTH = 200

# Hostname-shaped regex matching TECH-5400 / rh_comms_plugins.tls pattern.
_HOSTNAME_RE = re.compile(
    r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\Z"
)


def _sanitize_log_field(value: Any) -> str:
    """Cap length and strip newlines/carriage returns from a value before
    embedding in log lines or outcome fields.
    """
    text = value if isinstance(value, str) else repr(value)
    return text[:_MAX_LOG_FIELD_LENGTH].replace("\n", " ").replace("\r", " ")


def _read_env(name: str, fallback_name: str | None = None) -> str:
    """Read an env var with an optional fallback name."""
    val = os.environ.get(name, "")
    if not val and fallback_name:
        val = os.environ.get(fallback_name, "")
    return val


def _read_timeout_seconds() -> float:
    raw = os.environ.get(PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR)
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"{PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR} is not a number: {raw!r}"
        ) from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(
            f"{PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR} must be a finite, positive number: {raw!r}"
        )
    return timeout


def _sni_override_hook(sni_host: str) -> Callable[[httpx.Request], Awaitable[None]]:
    async def _hook(request: httpx.Request) -> None:
        request.headers["host"] = sni_host
        request.extensions["sni_hostname"] = sni_host

    return _hook


def _build_apply_client(timeout_seconds: float, tls_sni_host: str | None) -> httpx.AsyncClient:
    """Construct an httpx.AsyncClient with TLS SNI/Host override if configured.

    Tests can monkeypatch this function to inject a MockTransport-backed client.
    """
    if tls_sni_host is not None:
        if not _HOSTNAME_RE.fullmatch(tls_sni_host):
            raise ValueError(
                f"{PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR} is not a bare hostname: {tls_sni_host!r}"
            )
        event_hooks = {"request": [_sni_override_hook(tls_sni_host)]}
    else:
        event_hooks = None

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,
        event_hooks=event_hooks,
    )
    client.follow_redirects = False
    return client


def _extract_detail(response: httpx.Response) -> str | None:
    try:
        data = response.json()
        if isinstance(data, dict):
            detail = data.get("detail")
            if isinstance(detail, str):
                return detail
            if isinstance(detail, list):
                return json.dumps(detail)
    except Exception:
        pass
    return None


async def apply_proposal(ctx: ProposalContext) -> ProposalApplyOutcome:
    """Apply an approved proposal via HTTP call to agent-comms-approvals.

    Satisfies ProposalJudge.apply() contract. Never raises (except on
    cancellation).
    """
    if ctx.hold_id is None:
        logger.warning("apply_proposal called with hold_id=None; cannot apply over HTTP")
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="cannot apply proposal without a hold_id",
            log_detail="hold_id is None; proposal cannot be applied over HTTP",
        )

    base_url = _read_env(PROPOSAL_APPLY_URL_ENV_VAR, "PROPOSAL_ACTION_URL").rstrip("/")
    if not base_url:
        logger.error("%s environment variable is not set", PROPOSAL_APPLY_URL_ENV_VAR)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"{PROPOSAL_APPLY_URL_ENV_VAR} environment variable is not set",
        )
    if not base_url.startswith("https://"):
        logger.error("%s must be an https:// URL, got %r", PROPOSAL_APPLY_URL_ENV_VAR, base_url)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"{PROPOSAL_APPLY_URL_ENV_VAR} must be an https:// URL, got {base_url!r}",
        )

    token = _read_env(PROPOSAL_APPLY_TOKEN_ENV_VAR, "PROPOSAL_ACTION_TOKEN")
    if not token:
        logger.error("%s environment variable is not set", PROPOSAL_APPLY_TOKEN_ENV_VAR)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"{PROPOSAL_APPLY_TOKEN_ENV_VAR} environment variable is not set",
        )

    try:
        timeout_seconds = _read_timeout_seconds()
    except ValueError as exc:
        safe_exc = _sanitize_log_field(str(exc))
        logger.error("invalid proposal apply timeout: %s", safe_exc)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=safe_exc,
        )

    tls_sni_host = (
        _read_env(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, "PROPOSAL_ACTION_TLS_SNI_HOST") or None
    )

    try:
        client = _build_apply_client(timeout_seconds, tls_sni_host)
    except Exception as exc:
        safe_exc = _sanitize_log_field(str(exc))
        logger.error("failed to build proposal apply HTTP client: %s", safe_exc)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"failed to build HTTP client: {safe_exc}",
        )

    url = f"{base_url}{_PROPOSAL_APPLY_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "kind": ctx.kind,
        "action": ctx.action,
        "target_id": ctx.target_id,
        "action_type": ctx.action_type,
        "rationale": ctx.rationale,
        "proposed_by_bot_id": ctx.proposed_by_bot_id,
        "owner_sub": ctx.owner_sub,
        "hold_id": str(ctx.hold_id),
    }

    try:
        async with client:
            response = await client.post(url, json=payload, headers=headers)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        safe_exc = _sanitize_log_field(str(exc))
        logger.warning(
            "proposal apply proxy unreachable calling %s for hold_id=%s: %s",
            url,
            ctx.hold_id,
            safe_exc,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service unreachable",
            log_detail=f"proposal apply proxy unreachable: {safe_exc}",
        )

    if response.status_code in (401, 403):
        logger.warning(
            "proposal apply proxy rejected our credentials (status %s) calling %s -- check %s",
            response.status_code,
            url,
            PROPOSAL_APPLY_TOKEN_ENV_VAR,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"proposal apply proxy rejected credentials (status {response.status_code})",
        )

    if response.status_code == 409:
        detail = _extract_detail(response)
        safe_detail = _sanitize_log_field(detail or "conflict")
        logger.warning(
            "proposal apply conflict (status 409) calling %s for hold_id=%s: %s",
            url,
            ctx.hold_id,
            safe_detail,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error=f"proposal apply conflict: {safe_detail}",
            log_detail=f"proposal apply conflict: {safe_detail}",
        )

    if response.status_code == 422:
        detail = _extract_detail(response)
        safe_detail = _sanitize_log_field(detail or "unprocessable entity")
        logger.warning(
            "proposal apply rejected as malformed (status 422) calling %s for hold_id=%s: %s",
            url,
            ctx.hold_id,
            safe_detail,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply request was rejected as malformed",
            log_detail=f"proposal apply rejected (422): {safe_detail}",
        )

    if response.status_code >= 500:
        logger.warning(
            "proposal apply proxy returned server error (status %s) calling %s for hold_id=%s",
            response.status_code,
            url,
            ctx.hold_id,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service unavailable",
            log_detail=(
                f"proposal apply proxy returned server error (status {response.status_code})"
            ),
        )

    if response.status_code != 200:
        logger.warning(
            "proposal apply proxy returned unexpected status %s calling %s for hold_id=%s",
            response.status_code,
            url,
            ctx.hold_id,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned unexpected status",
            log_detail=f"proposal apply proxy returned unexpected status {response.status_code}",
        )

    try:
        body = response.json()
    except Exception as exc:
        safe_exc = _sanitize_log_field(str(exc))
        logger.warning(
            "proposal apply proxy returned non-JSON response for hold_id=%s: %s",
            ctx.hold_id,
            safe_exc,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response body was not valid JSON: {safe_exc}",
        )

    if not isinstance(body, dict):
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response JSON was not an object: {type(body).__name__}",
        )

    applied = body.get("applied")
    if not isinstance(applied, bool):
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response applied field is not a bool: {applied!r}",
        )

    result = body.get("result")
    if result is not None and not isinstance(result, dict):
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response result field is not a dict: {type(result).__name__}",
        )

    caller_error = body.get("caller_error")
    if caller_error is not None and not isinstance(caller_error, str):
        caller_error = str(caller_error)

    if applied:
        return ProposalApplyOutcome(
            applied=True,
            result=result,
            caller_error=None,
            log_detail=None,
        )
    return ProposalApplyOutcome(
        applied=False,
        result=None,
        caller_error=caller_error or "apply failed",
        log_detail=f"proposal apply outcome was applied=false: {caller_error}",
    )


def _load_rh_proposal_judge() -> Any:
    """Dynamically import and instantiate RHProposalJudge from rh_comms_plugins."""
    try:
        mod = importlib.import_module("rh_comms_plugins.proposal_judge")
        factory = mod.build_rh_proposal_judge
        return factory()
    except Exception as exc:
        raise RuntimeError(f"failed to load rh_comms_plugins.proposal_judge: {exc}") from exc


class HttpApplyProposalJudge:
    """ProposalJudge wrapper that delegates judgment to an underlying judge
    (e.g. RHProposalJudge) and overrides apply() to call the HTTP applier client.

    This ensures that RHProposalJudge.apply()'s deprecated shim is NEVER
    invoked by the board process, guaranteeing that rh_comms_plugins.linear_client
    and proposal_apply_service are never loaded into sys.modules.
    """

    def __init__(
        self,
        delegate: Any | None = None,
        *,
        applier: Callable[[ProposalContext], Coroutine[Any, Any, ProposalApplyOutcome]]
        | None = None,
    ) -> None:
        resolved_delegate: Any = delegate if delegate is not None else _load_rh_proposal_judge()
        self._delegate: Any = resolved_delegate
        self._applier = applier or apply_proposal

    @property
    def delegate(self) -> Any:
        return self._delegate

    def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
        return cast(ProposalClassification, self._delegate.classify(kind, action))

    async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
        return cast(ProposalFingerprint, await self._delegate.fingerprint(ctx))

    async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
        return cast(ProposalVerdict, await self._delegate.judge(ctx))

    async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
        return await self._applier(ctx)


def build_rh_proposal_judge() -> HttpApplyProposalJudge:
    """Factory for the board's PROPOSAL_JUDGE seam.

    Returns an HttpApplyProposalJudge wrapping Redesign Health's
    RHProposalJudge (from rh_comms_plugins.proposal_judge) for judgment,
    with apply() calling the approvals service over HTTP via
    proposal_apply_http_client.
    """
    return HttpApplyProposalJudge()


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR",
    "PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR",
    "PROPOSAL_APPLY_TOKEN_ENV_VAR",
    "PROPOSAL_APPLY_URL_ENV_VAR",
    "HttpApplyProposalJudge",
    "apply_proposal",
    "build_rh_proposal_judge",
]
