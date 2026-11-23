"""Admin storage of an agent's wake target (TECH-9908).

A wake target is the HTTPS address an agent system registers so the board can
deliver signed wake events for one agent (docs/WAKE-EVENTS.md, "Registration").
This module holds validation and the set/remove storage functions behind the
``comms_admin_wake_target_set`` / ``comms_admin_wake_target_remove`` tools.
Delivery is separate work and lives elsewhere.

Security boundary: the board may only post to operator-controlled destinations.
The operator lists allowed hosts in ``WAKE_TARGET_ALLOWED_HOSTS`` and a
registration whose URL host is not covered is refused. An empty or unset
setting refuses every registration (fail closed).

Secrets are encrypted before storage (``wake_secrets``). Nothing here logs,
audits or returns a secret, a ciphertext or a URL query string.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import uuid
from datetime import datetime
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import InvalidWakeTargetError, WakeTargetMisconfiguredError
from models import WakeTarget
from service import _audit, _deny, _find_agent_by_id
from wake_secrets import encrypt_secret

WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR: Final = "WAKE_TARGET_ALLOWED_HOSTS"

MAX_URL_LENGTH: Final = 2048
MAX_SYSTEM_LENGTH: Final = 32
SECRET_PREFIX: Final = "whsec_"
MIN_SECRET_BYTES: Final = 24
MAX_SECRET_BYTES: Final = 64
# 64 bytes of base64 is 88 characters; anything longer cannot be valid.
_MAX_SECRET_LENGTH: Final = len(SECRET_PREFIX) + 88

_SYSTEM_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_LABEL_PATTERN: Final = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _is_well_formed_host(host: str) -> bool:
    """Dot-separated DNS labels: no empty label (so no leading, trailing or doubled dot)."""
    return bool(host) and all(_LABEL_PATTERN.match(label) for label in host.split("."))


def parse_allowed_hosts(raw: str | None) -> list[str]:
    """Parse the allowlist setting into lowercase host patterns.

    Each entry is an exact host (``wake.example.net``) or ``*.suffix``. Entries
    that are neither (``*``, ``*.``, ``foo*``) are dropped, so a typo can never
    widen the list.
    """
    patterns: list[str] = []
    for entry in (raw or "").split(","):
        pattern = entry.strip().lower()
        host = pattern[2:] if pattern.startswith("*.") else pattern
        if _is_well_formed_host(host):
            patterns.append(pattern)
    return patterns


def host_is_allowed(host: str, patterns: list[str]) -> bool:
    """True if ``host`` matches an exact pattern, or is a subdomain of a ``*.suffix`` one.

    A malformed host (empty label, trailing dot, characters outside DNS labels) never
    matches. A wildcard matches only on a whole-label boundary, with at least one label
    before the suffix.
    """
    host = host.lower()
    if not _is_well_formed_host(host):
        return False
    for pattern in patterns:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):  # keeps the leading dot: "xts.net" never matches
                return True
        elif host == pattern:
            return True
    return False


def validate_url(url: str) -> str:
    """Validate ``url`` against the format rules and the operator allowlist; return its host."""
    patterns = parse_allowed_hosts(os.environ.get(WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR))
    if not patterns:
        raise WakeTargetMisconfiguredError(
            f"no hosts are allowed: {WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR} is empty or unset, "
            "so wake targets cannot be registered"
        )
    if not url or len(url) > MAX_URL_LENGTH:
        raise InvalidWakeTargetError(f"url must be 1 to {MAX_URL_LENGTH} characters")
    if not url.isascii() or any(ch.isspace() or ord(ch) < 32 or ch == "\\" for ch in url):
        raise InvalidWakeTargetError(
            "url must be plain ASCII with no whitespace, control characters or backslashes"
        )
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 -- raises ValueError on a malformed port
    except ValueError:
        raise InvalidWakeTargetError("url is not a valid URL") from None
    if parts.scheme != "https":
        raise InvalidWakeTargetError("url must use https")
    if not host:
        raise InvalidWakeTargetError("url must include a host")
    if "@" in parts.netloc:
        raise InvalidWakeTargetError("url must not contain credentials")
    if "#" in url:
        raise InvalidWakeTargetError("url must not contain a fragment")
    if not _is_well_formed_host(host.lower()):
        raise InvalidWakeTargetError("url host is not a valid hostname")
    if not host_is_allowed(host, patterns):
        raise InvalidWakeTargetError(
            f"host {host!r} is not on the allowed host list ({WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR})"
        )
    return host


def validate_secret(secret: str) -> None:
    """Require ``whsec_`` + base64 that decodes to 24 to 64 bytes. Never echoes the value."""
    message = (
        f"secret must be '{SECRET_PREFIX}' followed by base64 that decodes to "
        f"{MIN_SECRET_BYTES} to {MAX_SECRET_BYTES} bytes"
    )
    if not secret.startswith(SECRET_PREFIX) or len(secret) > _MAX_SECRET_LENGTH:
        raise InvalidWakeTargetError(message)
    try:
        decoded = base64.b64decode(secret[len(SECRET_PREFIX) :], validate=True)
    except (binascii.Error, ValueError):
        raise InvalidWakeTargetError(message) from None
    if not MIN_SECRET_BYTES <= len(decoded) <= MAX_SECRET_BYTES:
        raise InvalidWakeTargetError(message)


def validate_system(system: str) -> None:
    if len(system) > MAX_SYSTEM_LENGTH or not _SYSTEM_PATTERN.match(system):
        raise InvalidWakeTargetError(
            f"system must be 1 to {MAX_SYSTEM_LENGTH} characters: lowercase letters, digits, "
            "'.', '_' or '-', starting with a letter or digit"
        )


def _host_of_stored_url(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _iso(value: datetime) -> str:
    return value.isoformat()


async def _get_row(session: AsyncSession, agent_id: uuid.UUID) -> WakeTarget | None:
    return (
        await session.execute(select(WakeTarget).where(WakeTarget.agent_id == agent_id))
    ).scalar_one_or_none()


async def set_wake_target(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    agent_id: uuid.UUID,
    url: str,
    secret: str,
    system: str,
) -> dict[str, Any]:
    """Create or replace ``agent_id``'s wake target (replacing is how a secret is rotated).

    Returns a confirmation that never includes the secret or ciphertext.
    Raises ``AccessDeniedError`` for a non-admin caller (checked first) or an
    unknown agent, ``InvalidWakeTargetError`` for a rejected value and
    ``WakeTargetMisconfiguredError`` if the encryption key is missing or malformed
    (nothing is stored in either case).
    """
    if not admin_authorized:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.wake_target_requires_elevated_scope",
            detail={"target_agent_id": str(agent_id)},
        )
    agent = await _find_agent_by_id(session, agent_id)
    if agent is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_agent",
            detail={"target_agent_id": str(agent_id)},
        )
    host = validate_url(url)
    validate_secret(secret)
    validate_system(system)
    ciphertext = encrypt_secret(secret)

    row = await _get_row(session, agent_id)
    replaced = row is not None
    if row is None:
        row = WakeTarget(
            agent_id=agent_id, url=url, secret_ciphertext=ciphertext, system_label=system
        )
        try:
            # Savepoint: a concurrent first-time set for the same agent can win the
            # primary-key race. Treat the loser as a replace instead of failing.
            async with session.begin_nested():
                session.add(row)
        except IntegrityError:
            row = await _get_row(session, agent_id)
            if row is None:
                raise
            replaced = True
    if replaced:
        row.url = url
        row.secret_ciphertext = ciphertext
        row.system_label = system
    await session.flush()
    await session.refresh(row)
    _audit(
        session,
        actor_sub=actor_sub,
        action="wake_target.replaced" if replaced else "wake_target.created",
        agent_id=agent_id,
        detail={"system": system, "host": host},
    )
    await session.commit()
    return {
        "agent_id": str(agent_id),
        "system": system,
        "host": host,
        "result": "replaced" if replaced else "created",
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


async def remove_wake_target(
    session: AsyncSession,
    *,
    actor_sub: str,
    admin_authorized: bool,
    agent_id: uuid.UUID,
) -> dict[str, Any]:
    """Remove ``agent_id``'s wake target. Removing one that does not exist is a no-op."""
    if not admin_authorized:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.wake_target_requires_elevated_scope",
            detail={"target_agent_id": str(agent_id)},
        )
    if await _find_agent_by_id(session, agent_id) is None:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.unknown_agent",
            detail={"target_agent_id": str(agent_id)},
        )
    row = await _get_row(session, agent_id)
    detail: dict[str, Any] = {"removed": row is not None}
    if row is not None:
        detail["system"] = row.system_label
        detail["host"] = _host_of_stored_url(row.url)
        await session.delete(row)
    _audit(
        session,
        actor_sub=actor_sub,
        action="wake_target.removed" if row is not None else "wake_target.remove_noop",
        agent_id=agent_id,
        detail=detail,
    )
    await session.commit()
    return {"agent_id": str(agent_id), "removed": row is not None}


__all__ = [
    "WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR",
    "host_is_allowed",
    "parse_allowed_hosts",
    "remove_wake_target",
    "set_wake_target",
    "validate_secret",
    "validate_system",
    "validate_url",
]
