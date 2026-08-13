"""Structured JSON logging and observability events for agent-comms-mcp.

Uses ``structlog`` configured for JSON output to stdout. The event schema is
designed to be compatible with log query tools that filter on
``$.event = "tool_call"``, ``$.event = "scope_denial"``, etc. Note:
``refresh_token_hop_cap_exceeded`` is a service-local addition not in the
base schema.

Event schema
------------
tool_call:
    {"event": "tool_call", "service": "agent-comms-mcp", "tool": "<name>",
     "duration_ms": 42.1, "success": true}
    On failure, adds ``"error_type": "<ExcClassName>"``. When identity is
    available, adds ``"user_id": "<local-part|service-slug>"``.

auth_flow:
    {"event": "auth_flow", "service": "...",
     "auth_type": "new_auth|token_refresh|refresh_token_grace_redirect|
                   refresh_token_miss|refresh_token_hop_cap_exceeded"}
    ``refresh_token_grace_redirect`` and ``refresh_token_miss`` are ported
    from the rotation-grace mechanism in auth.py;
    ``refresh_token_hop_cap_exceeded`` is an additional value not covered by
    the base mechanism (see auth.py). All three are emitted on paths that
    previously logged nothing at all. A ``$.event = "auth_flow"`` filter that
    doesn't discriminate on ``auth_type`` now also counts failed
    refresh-token lookups as auth activity. ``refresh_token_miss`` and
    ``refresh_token_hop_cap_exceeded`` are deliberately SEPARATE values, not
    one conflated "failed" bucket: a genuine miss (token never issued or long
    expired) and a rotation chain exceeding ``_ROTATION_MAX_HOPS`` (token IS
    being actively rotated, just faster than the chain can be followed) are
    different operational conditions. No metric filter exists for either value
    yet — add dedicated filters before alerting to distinguish the two.

auth_rejected:
    {"event": "auth_rejected", "service": "...",
     "reason": "sub_missing|sub_shape", "issuer": "agent-jwt"}

scope_denial:
    {"event": "scope_denial", "service": "...", "tool": "<name>",
     "reason": "missing_token|tool_not_enrolled|missing_scope",
     "client_id": "<bot subject>", "required_scope": "<scope>"}
    ``required_scope`` present on the missing_scope branch only — kept
    server-side; the client-facing error never reveals it.

user_active:
    {"event": "user_active", "service": "...", "user_id": "<local-part|slug>"}

Notes
-----
* Never log message content, tokens, or attacker-controlled claim values.
* ``user_id`` is the email local-part for humans, or the agent-jwt service
  slug for M2M callers (see ``hash_user``).
* Every ``log_*`` helper swallows its own failures — observability must
  never break the caller (same contract as the shared module).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Literal

import structlog

SERVICE_NAME = "agent-comms-mcp"

# Fallback logger for observability helpers' own failure paths, and for
# ``_resolve_log_level`` (structlog isn't configured yet at that point).
_fallback_logger = logging.getLogger(__name__)


def _resolve_log_level() -> int:
    """Resolve the numeric logging level from ``LOG_LEVEL`` (default ``INFO``).

    Extracted into its own function so both ``logging.basicConfig`` and
    structlog's filtering wrapper use the SAME computed level (previously
    only ``logging.basicConfig`` read ``LOG_LEVEL``; structlog's
    ``make_filtering_bound_logger`` was hardcoded to ``logging.INFO``, so
    ``LOG_LEVEL=DEBUG`` silently had no effect on structlog output). Falls
    back to ``INFO`` for an unset or invalid value rather than raising, and
    logs a warning (via the module-scoped ``_fallback_logger`` — structlog
    isn't configured yet at this point, and the bare ``logging.warning()``
    convenience function must NOT be used here: it implicitly calls
    ``logging.basicConfig()`` the first time it's invoked if the root
    logger has no handlers yet, which would make the real,
    intentional ``logging.basicConfig(level=level)`` call in
    ``configure_logging`` a no-op) so a typo'd env var doesn't silently
    produce the wrong level with no diagnostic trail.

    ``NOTSET`` (``logging.NOTSET == 0``) is treated as invalid too: it's an
    ``isinstance(level, int)``-passing integer, but it's a sentinel meaning
    "no filtering" rather than a real threshold, and
    ``structlog.make_filtering_bound_logger(0)`` would let every log level
    through unconditionally. That's not a sensible interpretation of a
    ``LOG_LEVEL`` env var, so it falls back to ``INFO`` like any other
    invalid value.
    """
    name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, name, None)
    if not isinstance(level, int) or level == logging.NOTSET:
        _fallback_logger.warning(
            "Invalid LOG_LEVEL=%r; falling back to INFO", os.environ.get("LOG_LEVEL")
        )
        return logging.INFO
    return level


def configure_logging() -> None:
    """Configure stdlib + structlog for JSON output to stdout.

    Idempotent — safe to call from both ``main`` and tests.
    """
    level = _resolve_log_level()
    logging.basicConfig(level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
    )


# Bound logger for structured observability events. structlog's JSONRenderer
# emits the positional message under the ``event`` key, matching the fleet's
# ``$.event = "<name>"`` Metric Filter contract.
obs_log = structlog.get_logger(service=SERVICE_NAME)


def hash_user(email: str) -> str:
    """Return the email local-part (before ``@``) for log attribution.

    Agent-jwt service slugs (no ``@``) pass through whole; human email
    local-parts are returned as-is.
    """
    return email.strip().split("@")[0]


def log_tool_call(
    tool: str,
    duration_ms: float,
    success: bool,
    error_type: str | None = None,
    email: str | None = None,
) -> None:
    """Emit a ``tool_call`` observability event."""
    try:
        fields: dict[str, Any] = {
            "tool": tool,
            "duration_ms": round(duration_ms, 1),
            "success": success,
        }
        if error_type is not None:
            fields["error_type"] = error_type
        if email and email.strip():
            fields["user_id"] = hash_user(email)
        obs_log.info("tool_call", **fields)
    except Exception:
        _fallback_logger.warning("log_tool_call failed to emit event", exc_info=True)


def log_user_active(email: str) -> None:
    """Emit a ``user_active`` event for unique-user counting."""
    try:
        obs_log.info("user_active", user_id=hash_user(email))
    except Exception:
        _fallback_logger.warning("log_user_active failed to emit event", exc_info=True)


def log_auth_flow(
    auth_type: Literal[
        "new_auth",
        "token_refresh",
        "refresh_token_grace_redirect",
        "refresh_token_miss",
        "refresh_token_hop_cap_exceeded",
    ],
) -> None:
    """Emit an ``auth_flow`` event (browser auth completed / token refreshed)."""
    try:
        obs_log.info("auth_flow", auth_type=auth_type)
    except Exception:
        _fallback_logger.warning("log_auth_flow failed to emit event", exc_info=True)


def log_auth_rejected(
    reason: Literal["sub_missing", "sub_shape"],
    issuer: str | None = None,
) -> None:
    """Emit an ``auth_rejected`` event for a post-signature guard hit.

    Deliberately does NOT log the rejected ``sub`` — the sub of a forged
    agent-jwt token IS the attacker's payload; logging it would turn the
    metric stream into an attacker-writable side channel.
    """
    try:
        fields: dict[str, Any] = {"reason": reason}
        if issuer is not None:
            fields["issuer"] = issuer
        obs_log.info("auth_rejected", **fields)
    except Exception:
        _fallback_logger.warning("log_auth_rejected failed to emit event", exc_info=True)


def log_scope_denial(
    *,
    tool: str,
    reason: str,
    client_id: str,
    required_scope: str | None = None,
) -> None:
    """Emit a ``scope_denial`` event.

    structlog's JSONRenderer escapes the user-controlled ``tool`` value, so
    crafted tool names cannot inject log lines. ``required_scope`` is
    included only on the ``missing_scope`` branch (server-side debugging);
    the client-facing denial message never reveals it (anti-enumeration).
    """
    try:
        fields: dict[str, Any] = {
            "tool": tool,
            "reason": reason,
            "client_id": client_id,
        }
        if required_scope is not None:
            fields["required_scope"] = required_scope
        obs_log.info("scope_denial", **fields)
    except Exception:
        _fallback_logger.warning("log_scope_denial failed to emit event", exc_info=True)


__all__ = [
    "SERVICE_NAME",
    "configure_logging",
    "hash_user",
    "log_auth_flow",
    "log_auth_rejected",
    "log_scope_denial",
    "log_tool_call",
    "log_user_active",
    "obs_log",
]
