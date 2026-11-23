"""Tests for TECH-9905: wake tables, rule storage and rule evaluation.

Real Postgres only (shared fixtures in ``tests/conftest.py``). The
evaluation tests build ``WakeRule`` objects in memory: ``evaluate_wake_rules``
is pure and never touches the database.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from exceptions import AccessDeniedError, InvalidWakeRuleError
from models import Agent, AuditLog, WakeRule
from schemas import MESSAGE_TYPES
from service import register_agent
from tests.conftest import SERVICE_ROOT
from wake_rules import (
    WakeMessage,
    add_wake_rule,
    ensure_catch_all,
    evaluate_wake_rules,
    list_wake_rules,
    update_wake_rule,
)

pytestmark = pytest.mark.usefixtures("_migrated_schema")

_WAKE_TABLES = ("wake_rules", "wake_sessions", "wake_events", "wake_targets")
_PREVIOUS_HEAD = "c9214f2a6b38"


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE wake_targets, wake_events, wake_sessions, wake_rules, "
                "audit_log, messages, participants, conversations, agents RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def _agent(session: AsyncSession, sub: str) -> Agent:
    return await register_agent(
        session,
        sub=sub,
        base_sub=sub,
        owner_sub=f"owner-{sub}",
        owner_email=f"{sub}@example.com",
        display_name=sub,
        accepted_types=sorted(MESSAGE_TYPES),
        is_shared_authorized=True,
    )


# --- Migration -----------------------------------------------------------------


async def _existing_wake_tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = ANY(:names)"
            ),
            {"names": list(_WAKE_TABLES)},
        )
        return {row.table_name for row in result}


async def test_migration_downgrade_then_upgrade_round_trip(
    engine: AsyncEngine, database_url: str
) -> None:
    env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}

    def alembic(*args: str) -> None:
        res = subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=SERVICE_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr

    assert await _existing_wake_tables(engine) == set(_WAKE_TABLES)
    try:
        alembic("downgrade", _PREVIOUS_HEAD)
        assert await _existing_wake_tables(engine) == set()
    finally:
        alembic("upgrade", "head")
    assert await _existing_wake_tables(engine) == set(_WAKE_TABLES)


async def test_schema_constraints_reject_bad_rows(session: AsyncSession) -> None:
    agent = await _agent(session, "agent-a")
    await ensure_catch_all(session, agent_id=agent.id)
    bad: list[dict[str, Any]] = [
        # unknown action
        {"is_catch_all": False, "action": "ring", "priority": 1},
        # non-catch-all must have priority >= 1
        {"is_catch_all": False, "action": "wake", "priority": 0},
        # second catch-all for the same agent
        {"is_catch_all": True, "action": "wake", "priority": 0},
        # catch-all with a match column
        {"is_catch_all": True, "action": "wake", "priority": 0, "match_message_type": "note"},
    ]
    for fields in bad:
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(WakeRule(agent_id=agent.id, **fields))
                await session.flush()
    await session.rollback()


# --- Evaluation ----------------------------------------------------------------

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
_CONV = uuid.uuid4()
_SENDER = uuid.uuid4()


def _rule(**kwargs: Any) -> WakeRule:
    kwargs.setdefault("agent_id", uuid.uuid4())
    kwargs.setdefault("is_catch_all", False)
    kwargs.setdefault("action", "wake")
    kwargs.setdefault("priority", 1)
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("created_at", _T0)
    kwargs.setdefault("id", uuid.uuid4())
    return WakeRule(**kwargs)


def _catch_all(action: str = "wake") -> WakeRule:
    return _rule(is_catch_all=True, priority=0, action=action)


def _message(**kwargs: Any) -> WakeMessage:
    kwargs.setdefault("conversation_id", _CONV)
    kwargs.setdefault("sender_agent_id", _SENDER)
    kwargs.setdefault("message_type", "task_assign")
    return WakeMessage(**kwargs)


class TestEvaluate:
    def test_higher_priority_beats_lower(self) -> None:
        low = _rule(priority=1, action="poll")
        high = _rule(priority=5, action="wake")
        decision = evaluate_wake_rules([_catch_all(), low, high], _message())
        assert decision.rule is high
        assert decision.action == "wake"

    def test_newer_wins_a_tie(self) -> None:
        older = _rule(priority=3, action="poll", created_at=_T0)
        newer = _rule(priority=3, action="wake", created_at=_T0 + timedelta(minutes=1))
        assert evaluate_wake_rules([_catch_all(), newer, older], _message()).rule is newer
        assert evaluate_wake_rules([older, newer, _catch_all()], _message()).rule is newer

    def test_disabled_rule_is_ignored(self) -> None:
        off = _rule(priority=9, action="poll", enabled=False)
        catch_all = _catch_all()
        assert evaluate_wake_rules([catch_all, off], _message()).rule is catch_all

    def test_unset_match_fields_match_anything(self) -> None:
        rule = _rule(priority=2, action="poll")
        decision = evaluate_wake_rules(
            [_catch_all(), rule],
            _message(message_type="note", task_action=None, message_priority=None),
        )
        assert decision.rule is rule

    def test_two_match_fields_need_both(self) -> None:
        rule = _rule(
            priority=4,
            action="poll",
            match_message_type="task_assign",
            match_task_action="send_email",
        )
        catch_all = _catch_all()
        rules = [catch_all, rule]
        both = _message(task_action="send_email")
        assert evaluate_wake_rules(rules, both).rule is rule
        wrong_action = _message(task_action="cancel_meeting")
        assert evaluate_wake_rules(rules, wrong_action).rule is catch_all
        wrong_type = _message(message_type="note", task_action="send_email")
        assert evaluate_wake_rules(rules, wrong_type).rule is catch_all

    @pytest.mark.parametrize(
        ("field", "value", "miss"),
        [
            ("match_conversation_id", _CONV, {"conversation_id": uuid.uuid4()}),
            ("match_sender_agent_id", _SENDER, {"sender_agent_id": uuid.uuid4()}),
            ("match_message_type", "task_assign", {"message_type": "note"}),
            ("match_task_action", "send_email", {"task_action": "cancel_meeting"}),
            ("match_message_priority", "high", {"message_priority": "low"}),
        ],
    )
    def test_every_match_field_is_compared(
        self, field: str, value: Any, miss: dict[str, Any]
    ) -> None:
        rule = _rule(priority=2, **{field: value})
        catch_all = _catch_all()
        hit = _message(task_action="send_email", message_priority="high")
        assert evaluate_wake_rules([catch_all, rule], hit).rule is rule
        missed = _message(**{"task_action": "send_email", "message_priority": "high", **miss})
        assert evaluate_wake_rules([catch_all, rule], missed).rule is catch_all

    def test_catch_all_applies_when_nothing_else_matches(self) -> None:
        catch_all = _catch_all(action="poll")
        other = _rule(priority=7, match_message_type="note")
        decision = evaluate_wake_rules([other, catch_all], _message())
        assert decision.rule is catch_all
        assert decision.action == "poll"

    def test_missing_catch_all_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="catch-all"):
            evaluate_wake_rules([], _message())


# --- Storage -------------------------------------------------------------------


class TestStorage:
    async def test_new_rule_lands_on_top_by_default(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        first = await add_wake_rule(session, actor_sub="s", agent_id=agent.id, action="poll")
        second = await add_wake_rule(session, actor_sub="s", agent_id=agent.id, action="wake")
        assert (first.priority, second.priority) == (1, 2)
        rules = await list_wake_rules(session, agent_id=agent.id)
        assert [r.id for r in rules] == [second.id, first.id, rules[-1].id]
        assert rules[-1].is_catch_all

    async def test_explicit_priority_is_respected(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        top = await add_wake_rule(
            session, actor_sub="s", agent_id=agent.id, action="wake", priority=10
        )
        low = await add_wake_rule(
            session, actor_sub="s", agent_id=agent.id, action="poll", priority=2
        )
        assert (top.priority, low.priority) == (10, 2)
        default = await add_wake_rule(session, actor_sub="s", agent_id=agent.id, action="poll")
        assert default.priority == 11

    async def test_add_validates_fields(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        for kwargs in (
            {"action": "ring"},
            {"action": "wake", "priority": 0},
            {"action": "wake", "match_message_type": "not_a_type"},
            {"action": "wake", "match_task_action": "not_an_action"},
            {"action": "wake", "match_message_priority": "urgent"},
        ):
            with pytest.raises(InvalidWakeRuleError):
                await add_wake_rule(session, actor_sub="s", agent_id=agent.id, **kwargs)

    async def test_update_changes_only_the_one_rule(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        a = await add_wake_rule(
            session, actor_sub="s", agent_id=agent.id, action="wake", match_message_type="note"
        )
        b = await add_wake_rule(session, actor_sub="s", agent_id=agent.id, action="wake")
        updated = await update_wake_rule(
            session,
            actor_sub="s",
            agent_id=agent.id,
            rule_id=a.id,
            action="poll",
            enabled=False,
            match_message_type=None,
            match_message_priority="high",
        )
        assert updated.action == "poll"
        assert updated.enabled is False
        assert updated.match_message_type is None
        assert updated.match_message_priority == "high"
        assert updated.priority == a.priority
        fresh_b = (await session.execute(select(WakeRule).where(WakeRule.id == b.id))).scalar_one()
        assert (fresh_b.action, fresh_b.enabled, fresh_b.priority) == ("wake", True, b.priority)
        assert [r.id for r in await list_wake_rules(session, agent_id=agent.id)] == [
            b.id,
            (await ensure_catch_all(session, agent_id=agent.id)).id,
        ]
        with_off = await list_wake_rules(session, agent_id=agent.id, include_disabled=True)
        assert a.id in {r.id for r in with_off}

    async def test_cross_agent_update_is_rejected(self, session: AsyncSession) -> None:
        owner = await _agent(session, "agent-a")
        other = await _agent(session, "agent-b")
        rule = await add_wake_rule(session, actor_sub="s", agent_id=owner.id, action="wake")
        with pytest.raises(AccessDeniedError):
            await update_wake_rule(
                session, actor_sub="s", agent_id=other.id, rule_id=rule.id, action="poll"
            )
        with pytest.raises(AccessDeniedError):
            await update_wake_rule(
                session, actor_sub="s", agent_id=other.id, rule_id=uuid.uuid4(), action="poll"
            )
        fresh = (await session.execute(select(WakeRule).where(WakeRule.id == rule.id))).scalar_one()
        assert fresh.action == "wake"

    async def test_catch_all_only_allows_action_change(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        catch_all = await ensure_catch_all(session, agent_id=agent.id)
        for kwargs in (
            {"enabled": False},
            {"priority": 5},
            {"match_message_type": "note"},
            {"match_conversation_id": uuid.uuid4()},
        ):
            with pytest.raises(InvalidWakeRuleError):
                await update_wake_rule(
                    session, actor_sub="s", agent_id=agent.id, rule_id=catch_all.id, **kwargs
                )
        flipped = await update_wake_rule(
            session, actor_sub="s", agent_id=agent.id, rule_id=catch_all.id, action="poll"
        )
        assert flipped.action == "poll"
        assert (flipped.priority, flipped.enabled, flipped.is_catch_all) == (0, True, True)

    async def test_update_validates_fields(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        rule = await add_wake_rule(session, actor_sub="s", agent_id=agent.id, action="wake")
        for kwargs in ({"action": "ring"}, {"priority": 0}, {"match_message_type": "bogus"}):
            with pytest.raises(InvalidWakeRuleError):
                await update_wake_rule(
                    session, actor_sub="s", agent_id=agent.id, rule_id=rule.id, **kwargs
                )

    async def test_ensure_catch_all_is_idempotent(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        first = await ensure_catch_all(session, agent_id=agent.id)
        second = await ensure_catch_all(session, agent_id=agent.id)
        assert first.id == second.id
        assert (first.action, first.priority, first.enabled, first.is_catch_all) == (
            "wake",
            0,
            True,
            True,
        )
        count = (
            await session.execute(
                select(func.count()).select_from(WakeRule).where(WakeRule.agent_id == agent.id)
            )
        ).scalar_one()
        assert count == 1

    async def test_ensure_catch_all_is_safe_under_concurrency(
        self, session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        agent = await _agent(session, "agent-a")

        async def call() -> uuid.UUID:
            async with session_factory() as s:
                return (await ensure_catch_all(s, agent_id=agent.id)).id

        ids = await asyncio.gather(*(call() for _ in range(8)))
        assert len(set(ids)) == 1

    async def test_list_creates_catch_all_lazily(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        rules = await list_wake_rules(session, agent_id=agent.id)
        assert len(rules) == 1
        assert rules[0].is_catch_all

    async def test_add_and_update_write_audit_rows(self, session: AsyncSession) -> None:
        agent = await _agent(session, "agent-a")
        rule = await add_wake_rule(
            session,
            actor_sub="actor-1",
            agent_id=agent.id,
            action="wake",
            match_message_type="note",
        )
        await update_wake_rule(
            session, actor_sub="actor-2", agent_id=agent.id, rule_id=rule.id, action="poll"
        )
        rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action.like("wake_rule.%"))
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )
        assert [r.action for r in rows] == ["wake_rule.add", "wake_rule.update"]
        add_row, update_row = rows
        assert (add_row.actor_sub, add_row.agent_id) == ("actor-1", agent.id)
        assert add_row.detail is not None
        assert add_row.detail["old"] is None
        assert add_row.detail["new"]["action"] == "wake"
        assert add_row.detail["rule_id"] == str(rule.id)
        assert (update_row.actor_sub, update_row.agent_id) == ("actor-2", agent.id)
        assert update_row.detail is not None
        assert update_row.detail["old"]["action"] == "wake"
        assert update_row.detail["new"]["action"] == "poll"
