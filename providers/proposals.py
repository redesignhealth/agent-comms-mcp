"""Proposals provider — the bot-facing MCP tool surface over the
``proposal_holds`` domain (``service.py``, DESIGN.md's "proposal submission
pipeline" section) -- TECH-6018 follow-up.

Every bot-initiated proposal action -- submit, poll a single one, list its
own pending ones, list its own already-actioned (decided/withdrawn) ones,
and withdraw one -- is a tool here, mounted as ``namespace="proposals"``
(``proposals_submit``, ``proposals_get``, ``proposals_list_pending``,
``proposals_list_history``, ``proposals_withdraw``), the same way every
bot-initiated comms action is a ``comms_*`` tool. These do NOT replace the
existing ``POST /proposals`` / ``GET /proposals/{id}`` / ``GET
/proposals/pending`` / ``POST /proposals/{id}/withdraw`` HTTP routes in
``main.py`` -- both surfaces call the exact same ``service.py`` functions,
so they cannot drift, and removing the HTTP routes would break the
``linear-progress-bot`` integration and the ``provision-agent`` runbook
docs that currently point at raw HTTP.

``decide`` (approve/reject a proposal) has NO tool counterpart here, and
never will: it requires an Okta-interactive caller
(``agent-comms-approvals``'s ``decision_page``, a Starlette web app that
calls the HTTP route directly via ``httpx`` -- never an MCP client at all)
and is structurally unreachable by a bot's agent-jwt token (see
``service.decide_proposal``'s own docstring: a bot can never reach that
gate, by construction, not by convention).

Each tool below follows the SAME 5-step shape ``providers/comms.py``'s own
module docstring documents, with one deliberate difference: NO
``service.get_agent_by_sub``/board-``Agent`` resolution step. A proposing
bot has never been required to be a board-registered ``Agent`` at all (see
``main._authenticate_proposal_submitter``'s own docstring) -- adding that
requirement here would be a real behavior regression, not just a transport
change. Identity is resolved directly from the verified token via
``identity.try_resolve_email`` (the exact resolver ``main.py``'s HTTP
routes already use for ``bot_sub``), never through an ``Agent`` row.

Registration reminder (fail-closed ``TOOL_SCOPES``, see scopes.py): every
tool added here MUST be enrolled in ``scopes.TOOL_SCOPES`` under its
mounted name (``proposals_<tool>``) in the same change, or agent-jwt
callers can never reach it.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token

import service
from db import get_session_factory
from exceptions import AccessDeniedError, HoldAlreadyDecidedError, RateLimitExceededError
from identity import try_resolve_email

proposals_server: FastMCP[Any] = FastMCP("proposals")


def _require_bot_sub() -> str:
    """Resolve the calling bot's own ``sub`` from the verified access
    token -- same resolver ``main.py``'s HTTP proposal routes already use
    for ``bot_sub`` (``identity.try_resolve_email``), so a given bot's
    identity is IDENTICAL whether it calls a tool here or the equivalent
    raw HTTP route. Deliberately does NOT resolve a board ``Agent`` row
    (see this module's own docstring) -- a proposing bot need not be
    registered on the board at all.
    """
    token = get_access_token()
    if token is None:
        raise ToolError("no access token provided")
    bot_sub = try_resolve_email(token)
    if bot_sub is None:
        raise ToolError("unable to resolve caller identity from token claims")
    return bot_sub


@asynccontextmanager
async def _map_proposal_errors() -> AsyncIterator[None]:
    """Translate the service layer's proposal exception shapes into
    ``ToolError``.

    ``AccessDeniedError``'s message is the fixed, uniform, anti-
    enumeration string (exceptions.py) and is passed through verbatim --
    same posture ``providers.comms``'s own error mapper uses. Unlike that
    mapper, a bare ``ValueError`` here IS passed through verbatim too,
    not genericized: ``service.create_proposal``'s ``ValueError``s are
    caller-input-shape problems (missing ``action.target_id``, an
    unsupported ``kind``, ...) that ``main.py``'s existing HTTP route
    already surfaces to the caller unwrapped
    (``except ValueError as exc: ... "detail": str(exc)``) -- matching
    that established, client-safe precedent for the SAME underlying
    function, not comms.py's different call sites' different risk
    profile. ``RateLimitExceededError`` (TECH-5875, per-bot submission
    rate limit) and ``HoldAlreadyDecidedError`` (a withdraw racing an
    already-claimed hold) are both specific-by-design (see their own
    docstrings in exceptions.py) and pass through unwrapped too.
    """
    try:
        yield
    except AccessDeniedError as exc:
        raise ToolError(str(exc)) from None
    except (RateLimitExceededError, HoldAlreadyDecidedError, ValueError) as exc:
        raise ToolError(str(exc)) from None


def _parse_proposal_id(proposal_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(proposal_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ToolError(
            f"invalid_request: proposal_id is not a valid UUID: {proposal_id!r}"
        ) from exc


@proposals_server.tool
async def submit(
    kind: str,
    action: dict[str, Any],
    rationale: str,
    confidence: str,
    importance: str,
    impact: str,
    target_fingerprint: str,
) -> dict[str, Any]:
    """Submit a proposal for a bot-initiated action needing human (or
    TECH-5877 auto-judge) approval before it takes effect. Same body shape
    and validation as ``POST /proposals`` -- see ``service.create_proposal``.

    ``action`` must contain ``target_id`` and ``action_type`` (both
    strings) -- these are the create-time dedup key, together with
    ``kind`` and the calling bot's own identity: resubmitting with the
    SAME ``(kind, target_id, action_type)`` updates the existing pending
    row in place rather than creating a duplicate. A different bot
    proposing the identical ``(kind, target_id, action_type)`` gets its
    own separate row.

    ``confidence``/``importance``/``impact`` must each be ``"low"``,
    ``"medium"``, or ``"high"``. ``priority`` is always server-derived --
    there is no caller-supplied priority. Rate-limited per bot (TECH-5875).
    Immediately judged by the TECH-5877 kind-scoped deterministic rules
    engine -- a proposal that clears it resolves synchronously in this
    call's own response (``status`` will already be a terminal one, e.g.
    ``"applied"``), not left sitting at ``"pending"``.
    """
    bot_sub = _require_bot_sub()
    if not isinstance(action, dict):
        raise ToolError("invalid_request: action must be an object")
    if len(json.dumps(action)) > service.MAX_PROPOSAL_ACTION_BYTES:
        raise ToolError(
            f"invalid_request: action exceeds {service.MAX_PROPOSAL_ACTION_BYTES} bytes serialized"
        )
    try:
        kind = service.validate_proposal_string_field(
            "kind", kind, max_length=service.MAX_PROPOSAL_KIND_LENGTH
        )
        rationale = service.validate_proposal_string_field("rationale", rationale)
        target_fingerprint = service.validate_proposal_string_field(
            "target_fingerprint", target_fingerprint
        )
        for action_field in ("target_id", "action_type"):
            if action_field in action:
                service.validate_proposal_string_field(
                    f"action.{action_field}",
                    action.get(action_field),
                    max_length=service.MAX_PROPOSAL_ACTION_FIELD_LENGTH,
                )
        for level_name, level_value in (
            ("confidence", confidence),
            ("importance", importance),
            ("impact", impact),
        ):
            if not isinstance(level_value, str):
                raise ValueError(f"{level_name} must be a string")
            service.validate_hold_level(level_value, level_name)
    except ValueError as exc:
        raise ToolError(f"invalid_request: {exc}") from None

    token = get_access_token()
    owner_sub = service.resolve_proposal_owner_sub(token) if token is not None else None
    async with get_session_factory()() as session:
        if owner_sub is None:
            agent = await service.get_agent_by_sub(session, bot_sub)
            owner_sub = agent.owner_sub if agent is not None else None
        if owner_sub is None:
            raise ToolError(
                "owner_sub_unresolvable: no owner_sub claim on the bot's token, and no "
                "registered board agent to fall back to"
            )
        async with _map_proposal_errors():
            return await service.create_proposal(
                session,
                kind=kind,
                proposed_by_bot_id=bot_sub,
                owner_sub=owner_sub,
                action=action,
                rationale=rationale,
                confidence=confidence,
                importance=importance,
                impact=impact,
                target_fingerprint=target_fingerprint,
            )


@proposals_server.tool
async def get(proposal_id: str) -> dict[str, Any]:
    """Poll a single proposal's current status/decision outcome by id --
    the synchronous ``proposals_submit`` response is otherwise the only
    place a bot ever learns what happened to its own proposal (e.g. if a
    human decided it later). Sender-only: an unknown ``proposal_id`` and
    one that exists but belongs to a DIFFERENT bot both raise the same
    uniform ``access_denied`` error. Omits ``decided_by_actor_id`` when
    the proposal was decided by a human -- that reviewer's identity is
    never disclosed to the submitting bot.
    """
    bot_sub = _require_bot_sub()
    hold_id = _parse_proposal_id(proposal_id)
    async with get_session_factory()() as session, _map_proposal_errors():
        return await service.get_proposal_for_bot(
            session, hold_id=hold_id, requesting_bot_sub=bot_sub
        )


@proposals_server.tool
async def list_pending(limit: int = 50) -> dict[str, Any]:
    """List the calling bot's OWN still-``pending`` proposals, oldest
    first. Scoped to proposals THIS bot submitted -- never another bot's.
    ``limit`` is clamped to [1, 200]; ``has_more`` is ``True`` if more
    pending proposals exist beyond the returned page.
    """
    bot_sub = _require_bot_sub()
    async with get_session_factory()() as session, _map_proposal_errors():
        return await service.list_proposals_for_bot(
            session, requesting_bot_sub=bot_sub, statuses=("pending",), limit=limit
        )


@proposals_server.tool
async def list_history(limit: int = 50) -> dict[str, Any]:
    """List the calling bot's OWN already-actioned proposals -- every one
    that has left ``pending``/the transient ``applying`` state for good
    (``applied``, ``apply_failed``, ``rejected``, ``stale``, or
    ``withdrawn``), oldest first. Scoped to proposals THIS bot submitted --
    never another bot's. Omits ``decided_by_actor_id`` on any row decided
    by a human -- that reviewer's identity is never disclosed to the
    submitting bot. ``limit`` is clamped to [1, 200]; ``has_more`` is
    ``True`` if more actioned proposals exist beyond the returned page.
    """
    bot_sub = _require_bot_sub()
    async with get_session_factory()() as session, _map_proposal_errors():
        return await service.list_proposals_for_bot(
            session,
            requesting_bot_sub=bot_sub,
            statuses=service.PROPOSAL_TERMINAL_STATUSES,
            limit=limit,
        )


@proposals_server.tool
async def withdraw(proposal_id: str, reason: str | None = None) -> dict[str, Any]:
    """Retract the calling bot's own still-``pending`` proposal, most
    useful when the bot has since determined it's stale or simply wrong
    and wants it retracted before a human (or the TECH-5877 auto-judge)
    can decide it -- NOT for freeing up the create-time dedup key (a
    resubmission for the same target already updates the existing pending
    row in place; see ``service.withdraw_proposal``'s own docstring).
    Sender-only, same uniform ``access_denied`` posture as
    ``proposals_get``. Only a ``pending`` proposal can be withdrawn -- any
    other status (including the transient ``applying``, meaning a decide
    or the auto-judge has already claimed it) raises an error naming the
    hold's current status.
    """
    bot_sub = _require_bot_sub()
    hold_id = _parse_proposal_id(proposal_id)
    if reason is not None:
        if not isinstance(reason, str):
            raise ToolError("invalid_request: reason must be a string")
        if len(reason) > service.MAX_DECISION_REASON_LENGTH:
            raise ToolError(
                f"invalid_request: reason exceeds {service.MAX_DECISION_REASON_LENGTH} characters"
            )
    async with get_session_factory()() as session, _map_proposal_errors():
        return await service.withdraw_proposal(
            session, hold_id=hold_id, requesting_bot_sub=bot_sub, reason=reason
        )
