"""Wake rule storage and rule evaluation (TECH-9905).

Per-agent wake rules decide whether a delivered board message should wake
the recipient (``wake``) or leave it for the recipient to poll (``poll``).
This module holds only the rule storage functions and the pure
"which rule wins" function; hooking message delivery, MCP tools and the
delivery task are separate work.

Storage invariants:
- There is NO function here that deletes rules or replaces an agent's
  rules in bulk. A rule is retired by setting ``enabled = false``.
- Every agent has at most one catch-all rule (``wake``, priority 0,
  enabled, no match fields), created lazily by ``ensure_catch_all``. The
  catch-all can only have its ``action`` changed.
- Every add and update writes an ``audit_log`` row recording old and new
  values.

Who commits: ``add_wake_rule`` and ``update_wake_rule`` commit (each is its own
unit of work). ``ensure_catch_all``, ``list_wake_rules`` and
``list_wake_rules_for_agents`` never commit, so they are safe inside another
operation's transaction; the caller commits. ``evaluate_wake_rules`` is pure.
"""

from __future__ import annotations

import typing
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import AccessDeniedError, InvalidWakeRuleError
from models import WAKE_RULE_ACTIONS, AuditLog, WakeRule
from schemas import MESSAGE_TYPES, TaskAssignV1

# Deliberately no import of ``service`` here: service.py is expected to import
# this module, and a module-level import back would be circular. The audit rows
# below are plain ``AuditLog`` inserts, same shape ``service._audit`` writes.

_TASK_ACTIONS: Final[frozenset[str]] = frozenset(
    typing.get_args(TaskAssignV1.model_fields["action"].annotation)
)
_MESSAGE_PRIORITIES: Final[frozenset[str]] = frozenset(
    typing.get_args(TaskAssignV1.model_fields["priority"].annotation)
)

# Invites are evaluated as a message of this type (no task action, no priority).
INVITE_MESSAGE_TYPE: Final = "invite"
_MATCHABLE_MESSAGE_TYPES: Final[frozenset[str]] = MESSAGE_TYPES | {INVITE_MESSAGE_TYPE}

_RULE_FIELDS: Final = (
    "match_conversation_id",
    "match_sender_agent_id",
    "match_message_type",
    "match_task_action",
    "match_message_priority",
    "action",
    "priority",
    "enabled",
)


class _Unset:
    """Type of ``UNSET``: "argument not given". ``None`` is meaningful for match fields (clear)."""

    def __repr__(self) -> str:
        return "UNSET"


UNSET: Final = _Unset()


_NEWEST: Final = datetime.max.replace(tzinfo=UTC)


@dataclass(frozen=True)
class WakeMessage:
    """What the rules are matched against.

    ``task_action`` and ``message_priority`` come from the message payload
    (``payload["action"]`` / ``payload["priority"]`` on ``task_assign``);
    they are ``None`` for message types that do not carry them (and for
    invites, passed as ``message_type="invite"``). A rule that sets a match
    field never matches a ``None`` value for it.
    """

    conversation_id: uuid.UUID
    sender_agent_id: uuid.UUID
    message_type: str
    task_action: str | None = None
    message_priority: str | None = None


@dataclass(frozen=True)
class WakeDecision:
    rule: WakeRule
    action: str


def _snapshot(rule: WakeRule) -> dict[str, Any]:
    return {
        name: str(value) if isinstance(value := getattr(rule, name), uuid.UUID) else value
        for name in _RULE_FIELDS
    }


def _validate_fields(
    *,
    match_conversation_id: uuid.UUID | None,
    match_sender_agent_id: uuid.UUID | None,
    match_message_type: str | None,
    match_task_action: str | None,
    match_message_priority: str | None,
    action: str,
    priority: int,
    enabled: bool,
) -> None:
    del match_conversation_id, match_sender_agent_id  # typed UUIDs; nothing further to check
    if action not in WAKE_RULE_ACTIONS:
        raise InvalidWakeRuleError(f"action must be one of {WAKE_RULE_ACTIONS}")
    if match_message_type is not None and match_message_type not in _MATCHABLE_MESSAGE_TYPES:
        raise InvalidWakeRuleError("match_message_type is not a known message type")
    if match_task_action is not None and match_task_action not in _TASK_ACTIONS:
        raise InvalidWakeRuleError("match_task_action is not a known task action")
    if match_message_priority is not None and match_message_priority not in _MESSAGE_PRIORITIES:
        raise InvalidWakeRuleError("match_message_priority is not a known message priority")
    if isinstance(priority, bool) or not isinstance(priority, int) or priority < 1:
        raise InvalidWakeRuleError("priority must be an integer >= 1")
    if not isinstance(enabled, bool):
        raise InvalidWakeRuleError("enabled must be a boolean")


def _audit(
    session: AsyncSession,
    *,
    actor_sub: str,
    action: str,
    agent_id: uuid.UUID,
    detail: dict[str, Any],
) -> None:
    session.add(AuditLog(actor_sub=actor_sub, action=action, agent_id=agent_id, detail=detail))


def _catch_all_values(agent_id: uuid.UUID) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "is_catch_all": True,
        "action": "wake",
        "priority": 0,
        "enabled": True,
    }


async def _select_catch_all(session: AsyncSession, agent_id: uuid.UUID) -> WakeRule | None:
    return (
        await session.execute(
            select(WakeRule).where(WakeRule.agent_id == agent_id, WakeRule.is_catch_all)
        )
    ).scalar_one_or_none()


async def ensure_catch_all(session: AsyncSession, *, agent_id: uuid.UUID) -> WakeRule:
    """Return the agent's catch-all rule, creating it (``wake``, priority 0) if missing.

    Idempotent and safe under concurrent calls: the insert is ``INSERT ... ON
    CONFLICT DO NOTHING`` against the partial unique index
    ``uq_wake_rules_agent_id_catch_all``. Never commits: any row it creates
    is part of the caller's open transaction, so it is safe to call from
    inside another operation's transaction (for example message posting) and
    the CALLER commits.
    """
    existing = await _select_catch_all(session, agent_id)
    if existing is not None:
        return existing
    await session.execute(
        pg_insert(WakeRule).values(**_catch_all_values(agent_id)).on_conflict_do_nothing()
    )
    created = await _select_catch_all(session, agent_id)
    assert created is not None  # inserted above, or inserted by a concurrent committer
    return created


async def add_wake_rule(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    action: str,
    match_conversation_id: uuid.UUID | None = None,
    match_sender_agent_id: uuid.UUID | None = None,
    match_message_type: str | None = None,
    match_task_action: str | None = None,
    match_message_priority: str | None = None,
    priority: int | None = None,
    enabled: bool = True,
) -> WakeRule:
    """Add a rule. Without ``priority`` the rule goes on top (highest existing + 1).

    Validates before writing anything, so invalid input leaves no rows behind.
    COMMITS: this is its own unit of work (like the other tool-level service
    functions); do not call it from inside another operation's transaction.
    """
    _validate_fields(
        match_conversation_id=match_conversation_id,
        match_sender_agent_id=match_sender_agent_id,
        match_message_type=match_message_type,
        match_task_action=match_task_action,
        match_message_priority=match_message_priority,
        action=action,
        priority=1 if priority is None else priority,
        enabled=enabled,
    )
    await ensure_catch_all(session, agent_id=agent_id)
    if priority is None:
        highest = (
            await session.execute(
                select(WakeRule.priority)
                .where(WakeRule.agent_id == agent_id)
                .order_by(WakeRule.priority.desc())
                .limit(1)
            )
        ).scalar_one()
        priority = highest + 1
    rule = WakeRule(
        agent_id=agent_id,
        is_catch_all=False,
        match_conversation_id=match_conversation_id,
        match_sender_agent_id=match_sender_agent_id,
        match_message_type=match_message_type,
        match_task_action=match_task_action,
        match_message_priority=match_message_priority,
        action=action,
        priority=priority,
        enabled=enabled,
    )
    session.add(rule)
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="wake_rule.add",
        agent_id=agent_id,
        detail={"rule_id": str(rule.id), "old": None, "new": _snapshot(rule)},
    )
    await session.commit()
    return rule


async def update_wake_rule(
    session: AsyncSession,
    *,
    actor_sub: str,
    agent_id: uuid.UUID,
    rule_id: uuid.UUID,
    match_conversation_id: uuid.UUID | None | _Unset = UNSET,
    match_sender_agent_id: uuid.UUID | None | _Unset = UNSET,
    match_message_type: str | None | _Unset = UNSET,
    match_task_action: str | None | _Unset = UNSET,
    match_message_priority: str | None | _Unset = UNSET,
    action: str | _Unset = UNSET,
    priority: int | _Unset = UNSET,
    enabled: bool | _Unset = UNSET,
) -> WakeRule:
    """Change the given fields of one rule; omitted fields are left alone.

    Passing ``None`` for a match field clears it (matches anything). The row
    is locked by ``id`` AND ``agent_id`` in one query, so a rule that does not
    exist or belongs to another agent never makes the caller wait on another
    agent's row; it gets the uniform access denial, audited as
    ``denied.wake_rule_not_found`` (the audit row is committed before raising).
    The catch-all accepts only an ``action`` change. A validation failure rolls
    back (releasing the row lock) before raising ``InvalidWakeRuleError``.
    COMMITS on success: this is its own unit of work.
    """
    changes = {
        name: value
        for name, value in {
            "match_conversation_id": match_conversation_id,
            "match_sender_agent_id": match_sender_agent_id,
            "match_message_type": match_message_type,
            "match_task_action": match_task_action,
            "match_message_priority": match_message_priority,
            "action": action,
            "priority": priority,
            "enabled": enabled,
        }.items()
        if not isinstance(value, _Unset)
    }
    rule = (
        await session.execute(
            select(WakeRule)
            .where(WakeRule.id == rule_id, WakeRule.agent_id == agent_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if rule is None:
        _audit(
            session,
            actor_sub=actor_sub,
            action="denied.wake_rule_not_found",
            agent_id=agent_id,
            detail={"rule_id": str(rule_id)},
        )
        await session.commit()
        raise AccessDeniedError(reason="denied.wake_rule_not_found")
    old = _snapshot(rule)
    try:
        if rule.is_catch_all:
            if set(changes) - {"action"}:
                raise InvalidWakeRuleError("the catch-all rule only allows changing its action")
            if "action" in changes and changes["action"] not in WAKE_RULE_ACTIONS:
                raise InvalidWakeRuleError(f"action must be one of {WAKE_RULE_ACTIONS}")
        else:
            _validate_fields(**{**{k: getattr(rule, k) for k in _RULE_FIELDS}, **changes})
    except InvalidWakeRuleError:
        await session.rollback()
        raise
    for name, value in changes.items():
        setattr(rule, name, value)
    await session.flush()
    _audit(
        session,
        actor_sub=actor_sub,
        action="wake_rule.update",
        agent_id=agent_id,
        detail={"rule_id": str(rule.id), "old": old, "new": _snapshot(rule)},
    )
    await session.commit()
    return rule


def _order(stmt: Any) -> Any:
    return stmt.order_by(WakeRule.priority.desc(), WakeRule.created_at.desc(), WakeRule.id)


async def list_wake_rules(
    session: AsyncSession, *, agent_id: uuid.UUID, include_disabled: bool = False
) -> list[WakeRule]:
    """The agent's rules in the order they apply: priority descending, newer first.

    Read-only unless the agent has no catch-all yet, in which case it creates
    one (the lazy backfill). Never commits: if it created the catch-all, the
    caller's commit persists it.
    """
    return (
        await list_wake_rules_for_agents(
            session, agent_ids=[agent_id], include_disabled=include_disabled
        )
    )[agent_id]


async def list_wake_rules_for_agents(
    session: AsyncSession, *, agent_ids: Sequence[uuid.UUID], include_disabled: bool = False
) -> dict[uuid.UUID, list[WakeRule]]:
    """Load rules for many agents in one query (the delivery hot path).

    Every requested agent appears in the result, each list in the order the
    rules apply (priority descending, newer first). Agents that lack a
    catch-all get one created, for all of them in a single INSERT, followed by
    a reload; when every agent already has one this is a single read. Never
    commits: if it created catch-alls, the caller's commit persists them.
    """
    ids = list(dict.fromkeys(agent_ids))
    if not ids:
        return {}
    stmt = select(WakeRule).where(WakeRule.agent_id.in_(ids))
    if not include_disabled:
        stmt = stmt.where(WakeRule.enabled)
    rules = list((await session.execute(_order(stmt))).scalars())
    have_catch_all = {r.agent_id for r in rules if r.is_catch_all}
    missing = [i for i in ids if i not in have_catch_all]
    if missing:
        await session.execute(
            pg_insert(WakeRule)
            .values([_catch_all_values(i) for i in missing])
            .on_conflict_do_nothing()
        )
        rules = list((await session.execute(_order(stmt))).scalars())
    result: dict[uuid.UUID, list[WakeRule]] = {i: [] for i in ids}
    for rule in rules:
        result[rule.agent_id].append(rule)
    return result


def _matches(rule: WakeRule, message: WakeMessage) -> bool:
    return all(
        wanted is None or wanted == actual
        for wanted, actual in (
            (rule.match_conversation_id, message.conversation_id),
            (rule.match_sender_agent_id, message.sender_agent_id),
            (rule.match_message_type, message.message_type),
            (rule.match_task_action, message.task_action),
            (rule.match_message_priority, message.message_priority),
        )
    )


def evaluate_wake_rules(rules: Sequence[WakeRule], message: WakeMessage) -> WakeDecision:
    """Pick the winning rule for ``message``. Pure: no database access.

    ``rules`` is the agent's already-loaded rules (use ``list_wake_rules``,
    which guarantees the catch-all is present). Among enabled rules whose
    non-null match columns all equal the message's values, the highest
    ``priority`` wins; on a tie the newer ``created_at`` wins. Raises
    ``ValueError`` if nothing matches, which only happens when the
    catch-all is missing from ``rules``.
    """
    matching = [r for r in rules if r.enabled and _matches(r, message)]
    if not matching:
        raise ValueError("no matching rule: the agent's catch-all rule is missing from rules")
    # An unflushed rule has no created_at yet; it is the newest by definition.
    winner = max(matching, key=lambda r: (r.priority, r.created_at or _NEWEST))
    return WakeDecision(rule=winner, action=winner.action)


__all__ = [
    "INVITE_MESSAGE_TYPE",
    "UNSET",
    "WakeDecision",
    "WakeMessage",
    "add_wake_rule",
    "ensure_catch_all",
    "evaluate_wake_rules",
    "list_wake_rules",
    "list_wake_rules_for_agents",
    "update_wake_rule",
]
