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
- Ambiguous transport failures (ReadTimeout, 409 conflict, 5xx, or disconnects)
  are retried with exponential backoff and jitter under a wall-clock budget.
  If retries exhaust, an ambiguous outcome returns ``indeterminate=True`` so the
  board leaves the hold at ``status="applying"`` rather than minting a fresh
  hold_id on resubmission, preventing duplicate external writes.

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
    PROPOSAL_APPLY_MAX_ATTEMPTS: optional integer 1..10 (default 3), maximum
        number of attempts for ambiguous failures.
    PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS: optional initial backoff in seconds
        (default 0.5s), exponential with full jitter capped at 4.0s.
    PROPOSAL_APPLY_RETRY_BUDGET_SECONDS: optional wall-clock ceiling in seconds
        (default 45.0s) for the entire apply operation.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import math
import os
import random
import re
import time
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, cast
from urllib.parse import urlparse

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
PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR = "PROPOSAL_APPLY_MAX_ATTEMPTS"
PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR = "PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS"
PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR = "PROPOSAL_APPLY_RETRY_BUDGET_SECONDS"

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BACKOFF_SECONDS = 0.5
DEFAULT_RETRY_BUDGET_SECONDS = 45.0
MAX_BACKOFF_SLEEP_SECONDS = 4.0
MIN_REMAINING_BUDGET_FOR_RETRY_SECONDS = 2.0

_PROPOSAL_APPLY_PATH = "/proposals/apply"
_MAX_LOG_FIELD_LENGTH = 200

# Hostname-shaped regex matching TECH-5400 / rh_comms_plugins.tls pattern.
_HOSTNAME_RE = re.compile(
    r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\Z"
)

# Failure disposition categories for the retry loop
_DISPOSITION_DECIDED = "DECIDED"
_DISPOSITION_DEFINITE_CLEAN = "DEFINITE_CLEAN"
_DISPOSITION_DEFINITE_TERMINAL = "DEFINITE_TERMINAL"
_DISPOSITION_AMBIGUOUS = "AMBIGUOUS"


def _sanitize_log_field(value: Any) -> str:
    """Cap length and strip newlines/carriage returns from a value before
    embedding in log lines or outcome fields.
    """
    text = value if isinstance(value, str) else repr(value)
    return text[:_MAX_LOG_FIELD_LENGTH].replace("\n", " ").replace("\r", " ")


def _read_env(name: str) -> str:
    """Read an env var."""
    return os.environ.get(name, "")


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


def _read_max_attempts() -> int:
    raw = os.environ.get(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR)
    if not raw:
        return DEFAULT_MAX_ATTEMPTS
    try:
        val = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR} must be an integer between 1 and 10: {raw!r}"
        ) from exc
    if not (1 <= val <= 10):
        raise ValueError(
            f"{PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR} must be an integer between 1 and 10: {raw!r}"
        )
    return val


def _read_retry_backoff_seconds() -> float:
    raw = os.environ.get(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR)
    if not raw:
        return DEFAULT_RETRY_BACKOFF_SECONDS
    try:
        val = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"{PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR} must be a finite, "
            f"positive number: {raw!r}"
        ) from exc
    if not math.isfinite(val) or val <= 0:
        raise ValueError(
            f"{PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR} must be a finite, "
            f"positive number: {raw!r}"
        )
    return val


def _read_retry_budget_seconds() -> float:
    raw = os.environ.get(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR)
    if not raw:
        return DEFAULT_RETRY_BUDGET_SECONDS
    try:
        val = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"{PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR} must be a finite, "
            f"positive number: {raw!r}"
        ) from exc
    if not math.isfinite(val) or val < MIN_REMAINING_BUDGET_FOR_RETRY_SECONDS:
        raise ValueError(
            f"{PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR} must be a finite number "
            f"at least {MIN_REMAINING_BUDGET_FOR_RETRY_SECONDS}: {raw!r}"
        )
    return val


def _read_tls_sni_host() -> str | None:
    host = _read_env(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR) or None
    if host is not None and not _HOSTNAME_RE.fullmatch(host):
        raise ValueError(f"{PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR} is not a bare hostname: {host!r}")
    return host


def validate_proposal_apply_configuration() -> None:
    """Validate configuration required by HttpApplyProposalJudge. Hard-fails
    at boot (raises RuntimeError) if required configuration is missing or malformed.
    """
    base_url = _read_env(PROPOSAL_APPLY_URL_ENV_VAR).rstrip("/")
    if not base_url:
        raise RuntimeError(
            f"{PROPOSAL_APPLY_URL_ENV_VAR} is required for HttpApplyProposalJudge but is not set"
        )
    if not base_url.startswith("https://"):
        scheme = urlparse(base_url).scheme or "unknown"
        raise RuntimeError(
            f"{PROPOSAL_APPLY_URL_ENV_VAR} must be an https:// URL, got scheme={scheme!r}"
        )

    token = _read_env(PROPOSAL_APPLY_TOKEN_ENV_VAR)
    if not token:
        raise RuntimeError(
            f"{PROPOSAL_APPLY_TOKEN_ENV_VAR} is required for HttpApplyProposalJudge but is not set"
        )

    try:
        _read_timeout_seconds()
        _read_max_attempts()
        _read_retry_backoff_seconds()
        _read_retry_budget_seconds()
        _read_tls_sni_host()
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


def _sni_override_hook(sni_host: str) -> Callable[[httpx.Request], Awaitable[None]]:
    async def _hook(request: httpx.Request) -> None:
        # TECH-5400 / rh_comms_plugins.tls precedent: Tailscale Serve on ECS Fargate
        # validates the *.ts.net hostname in both SNI and Host header. Both are set
        # here to ensure parity with ownership_client.py and decision_page/tls.py.
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

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,
        event_hooks=event_hooks,
    )


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


def _classify_exception(exc: Exception, url: str, hold_id: Any) -> tuple[str, ProposalApplyOutcome]:
    """Classify an HTTP transport exception into DEFINITE_CLEAN vs AMBIGUOUS."""
    safe_exc = _sanitize_log_field(str(exc))

    # DEFINITE-CLEAN: request never reached server (DNS, connect, TLS handshake, URL errors)
    if isinstance(
        exc,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.PoolTimeout,
            httpx.UnsupportedProtocol,
            httpx.LocalProtocolError,
            httpx.InvalidURL,
            httpx.ProxyError,
        ),
    ):
        logger.warning(
            "proposal apply connection failed calling %s for hold_id=%s: %s",
            url,
            hold_id,
            safe_exc,
        )
        return _DISPOSITION_DEFINITE_CLEAN, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service unreachable",
            log_detail=f"connection failed: {safe_exc}",
            indeterminate=False,
        )

    # AMBIGUOUS: request may have been sent/processed (ReadTimeout, WriteTimeout, resets)
    logger.warning(
        "proposal apply transport failure (ambiguous) calling %s for hold_id=%s: %s",
        url,
        hold_id,
        safe_exc,
    )
    return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
        applied=False,
        result=None,
        caller_error="proposal apply service unreachable",
        log_detail=f"transport failure (ambiguous): {safe_exc}",
        indeterminate=True,
    )


def _classify_response(
    response: httpx.Response, url: str, hold_id: Any
) -> tuple[str, ProposalApplyOutcome]:
    """Classify an HTTP response into DECIDED, DEFINITE_TERMINAL, or AMBIGUOUS."""
    if response.status_code in (401, 403):
        logger.warning(
            "proposal apply proxy rejected our credentials (status %s) calling %s -- check %s",
            response.status_code,
            url,
            PROPOSAL_APPLY_TOKEN_ENV_VAR,
        )
        return _DISPOSITION_DEFINITE_TERMINAL, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"proposal apply proxy rejected credentials (status {response.status_code})",
            indeterminate=False,
        )

    if response.status_code == 422:
        detail = _extract_detail(response)
        safe_detail = _sanitize_log_field(detail or "unprocessable entity")
        logger.warning(
            "proposal apply rejected as malformed (status 422) calling %s for hold_id=%s: %s",
            url,
            hold_id,
            safe_detail,
        )
        return _DISPOSITION_DEFINITE_TERMINAL, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply request was rejected as malformed",
            log_detail=f"proposal apply rejected (422): {safe_detail}",
            indeterminate=False,
        )

    if response.status_code == 409:
        detail = _extract_detail(response)
        safe_detail = _sanitize_log_field(detail or "conflict")
        logger.error(
            "proposal apply conflict (status 409) calling %s for hold_id=%s: %s",
            url,
            hold_id,
            safe_detail,
        )
        return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error=f"proposal apply conflict: {safe_detail}",
            log_detail=f"proposal apply conflict: {safe_detail}",
            indeterminate=True,
        )

    if response.status_code >= 500:
        logger.warning(
            "proposal apply proxy returned server error (status %s) calling %s for hold_id=%s",
            response.status_code,
            url,
            hold_id,
        )
        return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service unavailable",
            log_detail=(
                f"proposal apply proxy returned server error (status {response.status_code})"
            ),
            indeterminate=True,
        )

    if response.status_code != 200:
        logger.warning(
            "proposal apply proxy returned unexpected status %s calling %s for hold_id=%s",
            response.status_code,
            url,
            hold_id,
        )
        return _DISPOSITION_DEFINITE_TERMINAL, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned unexpected status",
            log_detail=f"proposal apply proxy returned unexpected status {response.status_code}",
            indeterminate=False,
        )

    # Status is 200: parse body
    try:
        body = response.json()
    except Exception as exc:
        safe_exc = _sanitize_log_field(str(exc))
        logger.warning(
            "proposal apply proxy returned non-JSON 200 response for hold_id=%s: %s",
            hold_id,
            safe_exc,
        )
        # 200 received but unparseable body -> write likely occurred; ambiguous
        return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response body was not valid JSON: {safe_exc}",
            indeterminate=True,
        )

    if not isinstance(body, dict):
        return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response JSON was not an object: {type(body).__name__}",
            indeterminate=True,
        )

    applied = body.get("applied")
    if not isinstance(applied, bool):
        return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response applied field is not a bool: {applied!r}",
            indeterminate=True,
        )

    result = body.get("result")
    if result is not None and not isinstance(result, dict):
        return _DISPOSITION_AMBIGUOUS, ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="proposal apply service returned malformed response",
            log_detail=f"response result field is not a dict: {type(result).__name__}",
            indeterminate=True,
        )

    caller_error = body.get("caller_error")
    if caller_error is not None:
        caller_error = _sanitize_log_field(str(caller_error))

    if applied:
        return _DISPOSITION_DECIDED, ProposalApplyOutcome(
            applied=True,
            result=result,
            caller_error=None,
            log_detail=None,
            indeterminate=False,
        )
    return _DISPOSITION_DECIDED, ProposalApplyOutcome(
        applied=False,
        result=None,
        caller_error=caller_error or "apply failed",
        log_detail=f"proposal apply outcome was applied=false: {caller_error}",
        indeterminate=False,
    )


async def apply_proposal(ctx: ProposalContext) -> ProposalApplyOutcome:
    """Apply an approved proposal via HTTP call to agent-comms-approvals.

    Satisfies ProposalJudge.apply() contract. Never raises (except on
    cancellation). Retries ambiguous transport/server errors with backoff
    under an overall wall-clock budget.
    """
    if ctx.hold_id is None:
        logger.warning("apply_proposal called with hold_id=None; cannot apply over HTTP")
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="cannot apply proposal without a hold_id",
            log_detail="hold_id is None; proposal cannot be applied over HTTP",
            indeterminate=False,
        )

    base_url = _read_env(PROPOSAL_APPLY_URL_ENV_VAR).rstrip("/")
    if not base_url:
        logger.error("%s environment variable is not set", PROPOSAL_APPLY_URL_ENV_VAR)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"{PROPOSAL_APPLY_URL_ENV_VAR} environment variable is not set",
            indeterminate=False,
        )
    if not base_url.startswith("https://"):
        scheme = urlparse(base_url).scheme or "unknown"
        logger.error(
            "%s must be an https:// URL, got scheme=%r",
            PROPOSAL_APPLY_URL_ENV_VAR,
            scheme,
        )
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=(
                f"{PROPOSAL_APPLY_URL_ENV_VAR} must be an https:// URL, got scheme={scheme!r}"
            ),
            indeterminate=False,
        )

    token = _read_env(PROPOSAL_APPLY_TOKEN_ENV_VAR)
    if not token:
        logger.error("%s environment variable is not set", PROPOSAL_APPLY_TOKEN_ENV_VAR)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=f"{PROPOSAL_APPLY_TOKEN_ENV_VAR} environment variable is not set",
            indeterminate=False,
        )

    try:
        timeout_seconds = _read_timeout_seconds()
        max_attempts = _read_max_attempts()
        backoff_base = _read_retry_backoff_seconds()
        retry_budget_seconds = _read_retry_budget_seconds()
        tls_sni_host = _read_tls_sni_host()
    except ValueError as exc:
        safe_exc = _sanitize_log_field(str(exc))
        logger.error("invalid proposal apply configuration: %s", safe_exc)
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error="server configuration error",
            log_detail=safe_exc,
            indeterminate=False,
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
            indeterminate=False,
        )

    url = f"{base_url}{_PROPOSAL_APPLY_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # Built ONCE and reused across all retries to guarantee request-digest determinism
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

    start_time = time.monotonic()
    deadline = start_time + retry_budget_seconds
    saw_ambiguous = False
    last_outcome: ProposalApplyOutcome | None = None
    attempts_made = 0

    async with client:
        for attempt in range(1, max_attempts + 1):
            now = time.monotonic()
            remaining_budget = deadline - now
            if remaining_budget <= 0 or (
                attempt > 1 and remaining_budget < MIN_REMAINING_BUDGET_FOR_RETRY_SECONDS
            ):
                logger.warning(
                    "proposal apply retry budget exhausted (remaining=%.2fs) for hold_id=%s",
                    remaining_budget,
                    ctx.hold_id,
                )
                break
            attempts_made = attempt

            # Enforce true wall-clock ceiling via asyncio.timeout(remaining_budget)
            # and clamp attempt_timeout to remaining_budget without overshooting.
            attempt_timeout = min(timeout_seconds, remaining_budget)

            try:
                async with asyncio.timeout(remaining_budget):
                    response = await client.post(
                        url, json=payload, headers=headers, timeout=attempt_timeout
                    )
            except TimeoutError as exc:
                disposition, outcome = _classify_exception(
                    httpx.ReadTimeout(f"wall-clock retry budget expired: {exc}"),
                    url,
                    ctx.hold_id,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                disposition, outcome = _classify_exception(exc, url, ctx.hold_id)
            else:
                disposition, outcome = _classify_response(response, url, ctx.hold_id)

            last_outcome = outcome

            if disposition == _DISPOSITION_DECIDED:
                return outcome

            if disposition in (_DISPOSITION_DEFINITE_TERMINAL, _DISPOSITION_DEFINITE_CLEAN):
                if not saw_ambiguous:
                    return outcome
                # Critical invariant: once ambiguous, always ambiguous
                return ProposalApplyOutcome(
                    applied=False,
                    result=None,
                    caller_error=(
                        f"apply outcome could not be confirmed after {attempt} attempts; "
                        "awaiting manual reconciliation"
                    ),
                    log_detail=(
                        f"initial attempt was ambiguous; subsequent attempt failed with: "
                        f"{outcome.caller_error} ({outcome.log_detail})"
                    ),
                    indeterminate=True,
                )

            if disposition == _DISPOSITION_AMBIGUOUS:
                saw_ambiguous = True
                if attempt < max_attempts:
                    now = time.monotonic()
                    remaining_budget = deadline - now
                    if remaining_budget < MIN_REMAINING_BUDGET_FOR_RETRY_SECONDS:
                        logger.warning(
                            "proposal apply retry budget exhausted before sleep "
                            "(remaining=%.2fs) for hold_id=%s",
                            remaining_budget,
                            ctx.hold_id,
                        )
                        break
                    base_sleep = min(backoff_base * (2 ** (attempt - 1)), MAX_BACKOFF_SLEEP_SECONDS)
                    jittered_sleep = random.uniform(0.0, base_sleep)
                    sleep_time = min(
                        jittered_sleep,
                        max(0.0, remaining_budget - MIN_REMAINING_BUDGET_FOR_RETRY_SECONDS),
                    )
                    logger.info(
                        "proposal apply attempt %d was ambiguous for hold_id=%s; "
                        "sleeping %.2fs before retry",
                        attempt,
                        ctx.hold_id,
                        sleep_time,
                    )
                    await asyncio.sleep(sleep_time)

    if attempts_made == 0:
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error=(
                "apply outcome could not be confirmed; retry budget expired before request "
                "could be made"
            ),
            log_detail="retry budget expired before attempt could be started",
            indeterminate=True,
        )

    if saw_ambiguous:
        return ProposalApplyOutcome(
            applied=False,
            result=None,
            caller_error=(
                f"apply outcome could not be confirmed after {attempts_made} attempts; "
                "awaiting manual reconciliation"
            ),
            log_detail=(
                f"retry loop exhausted after {attempts_made} attempts (saw_ambiguous=True); "
                f"last error: {last_outcome.caller_error} ({last_outcome.log_detail})"
                if last_outcome
                else "retry loop exhausted after 0 attempts"
            ),
            indeterminate=True,
        )

    return last_outcome or ProposalApplyOutcome(
        applied=False,
        result=None,
        caller_error="proposal apply failed",
        log_detail="retry loop exhausted without attempts",
        indeterminate=False,
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
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_RETRY_BACKOFF_SECONDS",
    "DEFAULT_RETRY_BUDGET_SECONDS",
    "DEFAULT_TIMEOUT_SECONDS",
    "PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR",
    "PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR",
    "PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR",
    "PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR",
    "PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR",
    "PROPOSAL_APPLY_TOKEN_ENV_VAR",
    "PROPOSAL_APPLY_URL_ENV_VAR",
    "HttpApplyProposalJudge",
    "apply_proposal",
    "build_rh_proposal_judge",
    "validate_proposal_apply_configuration",
]
