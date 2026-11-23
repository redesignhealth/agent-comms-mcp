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
"""

from __future__ import annotations

import typing
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from exceptions import InvalidWakeRuleError
from models import WAKE_RULE_ACTIONS, WakeRule
from schemas import MESSAGE_TYPES, TaskAssignV1
from service import _audit, _deny

_TASK_ACTIONS: Final[frozenset[str]] = frozenset(
    typing.get_args(TaskAssignV1.model_fields["action"].annotation)
)
_MESSAGE_PRIORITIES: Final[frozenset[str]] = frozenset(
    typing.get_args(TaskAssignV1.model_fields["priority"].annotation)
)

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


@dataclass(frozen=True)
class WakeMessage:
    """What the rules are matched against.

    ``task_action`` and ``message_priority`` come from the message payload
    (``payload["action"]`` / ``payload["priority"]`` on ``task_assign``);
    they are ``None`` for message types that do not carry them.
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
    if match_message_type is not None and match_message_type not in MESSAGE_TYPES:
        raise InvalidWakeRuleError("match_message_type is not a known message type")
    if match_task_action is not None and match_task_action not in _TASK_ACTIONS:
        raise InvalidWakeRuleError("match_task_action is not a known task action")
    if match_message_priority is not None and match_message_priority not in _MESSAGE_PRIORITIES:
        raise InvalidWakeRuleError("match_message_priority is not a known message priority")
    if isinstance(priority, bool) or not isinstance(priority, int) or priority < 1:
        raise InvalidWakeRuleError("priority must be an integer >= 1")
    if not isinstance(enabled, bool):
        raise InvalidWakeRuleError("enabled must be a boolean")


async def ensure_catch_all(session: AsyncSession, *, agent_id: uuid.UUID) -> WakeRule:
    """Return the agent's catch-all rule, creating it (``wake``, priority 0) if missing.

    Idempotent and safe under concurrent calls: the insert relies on the
    partial unique index ``uq_wake_rules_agent_id_catch_all`` via
    ``ON CONFLICT DO NOTHING``. Commits only when it actually created the
    row (the caller's session may hold other staged state otherwise).
    """
    result = await session.execute(
        pg_insert(WakeRule)
        .values(agent_id=agent_id, is_catch_all=True, action="wake", priority=0, enabled=True)
        .on_conflict_do_nothing(index_elements=["agent_id"], index_where=text("is_catch_all"))
        .returning(WakeRule.id)
    )
    if result.first() is not None:
        await session.commit()
    return (
        await session.execute(
            select(WakeRule).where(WakeRule.agent_id == agent_id, WakeRule.is_catch_all)
        )
    ).scalar_one()


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
    """Add a rule. Without ``priority`` the rule goes on top (highest existing + 1)."""
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
    _validate_fields(
        match_conversation_id=match_conversation_id,
        match_sender_agent_id=match_sender_agent_id,
        match_message_type=match_message_type,
        match_task_action=match_task_action,
        match_message_priority=match_message_priority,
        action=action,
        priority=priority,
        enabled=enabled,
    )
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

    Passing ``None`` for a match field clears it (matches anything). A rule
    that does not exist or belongs to another agent gets the uniform access
    denial. The catch-all accepts only an ``action`` change.
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
        await session.execute(select(WakeRule).where(WakeRule.id == rule_id).with_for_update())
    ).scalar_one_or_none()
    if rule is None or rule.agent_id != agent_id:
        await _deny(
            session,
            actor_sub=actor_sub,
            action="denied.wake_rule_not_found",
            agent_id=agent_id,
            detail={"rule_id": str(rule_id)},
        )
    if rule.is_catch_all and set(changes) - {"action"}:
        raise InvalidWakeRuleError("the catch-all rule only allows changing its action")
    old = _snapshot(rule)
    if rule.is_catch_all:
        if "action" in changes and changes["action"] not in WAKE_RULE_ACTIONS:
            raise InvalidWakeRuleError(f"action must be one of {WAKE_RULE_ACTIONS}")
    else:
        _validate_fields(**{**{k: getattr(rule, k) for k in _RULE_FIELDS}, **changes})
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


async def list_wake_rules(
    session: AsyncSession, *, agent_id: uuid.UUID, include_disabled: bool = False
) -> list[WakeRule]:
    """The agent's rules in the order they apply: priority descending, newer first."""
    await ensure_catch_all(session, agent_id=agent_id)
    stmt = select(WakeRule).where(WakeRule.agent_id == agent_id)
    if not include_disabled:
        stmt = stmt.where(WakeRule.enabled)
    stmt = stmt.order_by(WakeRule.priority.desc(), WakeRule.created_at.desc(), WakeRule.id)
    return list((await session.execute(stmt)).scalars())


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
    winner = max(matching, key=lambda r: (r.priority, r.created_at))
    return WakeDecision(rule=winner, action=winner.action)


__all__ = [
    "UNSET",
    "WakeDecision",
    "WakeMessage",
    "add_wake_rule",
    "ensure_catch_all",
    "evaluate_wake_rules",
    "list_wake_rules",
    "update_wake_rule",
]
