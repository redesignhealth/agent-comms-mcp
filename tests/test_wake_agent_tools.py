"""Tests for TECH-9881: agent tools for wake rules and open conversations.

Real Postgres (shared fixtures in ``tests/conftest.py``). Tool calls go through
the real mounted server, as in ``tests/test_wake_targets.py``.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from fastmcp.exceptions import ToolError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from models import AuditLog, WakeEvent, WakeRule, WakeSession, WakeTarget
from scopes import TOOL_SCOPES
from tests.test_comms_tools import _availability_request, _call, _import_main, _register, _token
from wake_events import WAKE_SESSION_WINDOW_SECONDS

pytestmark = pytest.mark.usefixtures("_migrated_schema")

DENIED = re.escape("access_denied: not authorized for this resource")
RULES = "comms_wake_rules_list"
ADD = "comms_wake_rule_add"
UPDATE = "comms_wake_rule_update"
SESSIONS = "comms_wake_sessions_list"
CLOSE = "comms_wake_session_close"


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
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


class _Agent:
    def __init__(self, main: Any, factory: Any, sub: str, agent_id: str) -> None:
        self.main, self.factory, self.sub, self.id = main, factory, sub, agent_id

    async def call(self, tool: str, args: dict[str, Any] | None = None) -> Any:
        return await _call(self.main, self.factory, _token(self.sub), tool, args)


async def _agent(main: Any, factory: Any, sub: str) -> _Agent:
    return _Agent(main, factory, sub, str((await _register(main, factory, sub))["agent_id"]))


async def _conversation(a: _Agent, b: _Agent) -> str:
    started = await a.call(
        "comms_start_conversation",
        {
            "conversation_type": "open",
            "target_agent_ids": [b.id],
            "initial_message": _availability_request(),
        },
    )
    return str(started["conversation_id"])


async def _open_session(
    factory: Any, agent: _Agent, conversation_id: str, *, age_seconds: int = 0
) -> None:
    now = datetime.now(UTC) - timedelta(seconds=age_seconds)
    async with factory() as s:
        s.add(
            WakeSession(
                agent_id=uuid.UUID(agent.id),
                conversation_id=uuid.UUID(conversation_id),
                opened_at=now,
                last_activity_at=now,
            )
        )
        await s.commit()


async def _audit_actions(factory: Any) -> list[str]:
    async with factory() as s:
        rows = (await s.execute(select(AuditLog.action).order_by(AuditLog.at, AuditLog.id))).all()
    return [r[0] for r in rows]


class TestScopes:
    def test_every_tool_has_a_scope(self) -> None:
        assert TOOL_SCOPES[RULES] == "comms:read"
        assert TOOL_SCOPES[SESSIONS] == "comms:read"
        assert TOOL_SCOPES[ADD] == "comms:write"
        assert TOOL_SCOPES[UPDATE] == "comms:write"
        assert TOOL_SCOPES[CLOSE] == "comms:write"


class TestRulesList:
    async def test_new_agent_sees_only_catch_all(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        rules = (await a.call(RULES))["rules"]
        assert len(rules) == 1
        assert rules[0]["is_catch_all"] is True
        assert rules[0]["action"] == "wake"
        assert rules[0]["priority"] == 0
        assert rules[0]["enabled"] is True

    async def test_disabled_rules_only_on_request(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        await a.call(UPDATE, {"rule_id": rule["rule_id"], "enabled": False})
        assert [r["rule_id"] for r in (await a.call(RULES))["rules"]].count(rule["rule_id"]) == 0
        shown = (await a.call(RULES, {"include_disabled": True}))["rules"]
        assert rule["rule_id"] in [r["rule_id"] for r in shown]

    async def test_lists_in_priority_order(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        low = await a.call(ADD, {"action": "poll", "message_type": "note", "priority": 2})
        high = await a.call(ADD, {"action": "poll", "message_type": "decline", "priority": 9})
        order = [r["rule_id"] for r in (await a.call(RULES))["rules"]]
        assert order[:2] == [high["rule_id"], low["rule_id"]]
        assert (await a.call(RULES))["rules"][-1]["is_catch_all"] is True


class TestAdd:
    async def test_goes_on_top_by_default(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        first = await a.call(ADD, {"action": "poll", "message_type": "note"})
        second = await a.call(ADD, {"action": "wake", "message_type": "task_assign"})
        assert first["priority"] == 1
        assert second["priority"] == 2
        assert (await a.call(RULES))["rules"][0]["rule_id"] == second["rule_id"]

    async def test_explicit_priority_and_all_match_fields(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        conv = await _conversation(a, b)
        rule = await a.call(
            ADD,
            {
                "action": "poll",
                "priority": 7,
                "conversation_id": conv,
                "sender_agent_id": b.id,
                "message_type": "task_assign",
                "task_action": "report_status",
                "message_priority": "high",
            },
        )
        assert rule["priority"] == 7
        assert rule["match_conversation_id"] == conv
        assert rule["match_sender_agent_id"] == b.id
        assert rule["match_message_type"] == "task_assign"
        assert rule["match_task_action"] == "report_status"
        assert rule["match_message_priority"] == "high"
        assert rule["enabled"] is True
        assert rule["is_catch_all"] is False

    @pytest.mark.parametrize(
        "args",
        [
            {"action": "sleep", "message_type": "note"},
            {"action": "poll", "message_type": "gossip"},
            {"action": "poll", "task_action": "juggle"},
            {"action": "poll", "message_priority": "whenever"},
            {"action": "poll", "message_type": "note", "priority": 0},
            {"action": "poll", "message_type": "note", "priority": 2**31},
            {"action": "poll", "conversation_id": "not-a-uuid"},
            {"action": "poll"},  # no match field at all
            {"action": "poll", "message_type": "note", "bogus_field": "x"},
        ],
    )
    async def test_invalid_input_rejected_and_writes_no_rule(
        self, main: Any, test_session_factory: Any, args: dict[str, Any]
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        with pytest.raises(ToolError):
            await a.call(ADD, args)
        assert len((await a.call(RULES, {"include_disabled": True}))["rules"]) == 1

    async def test_error_message_says_what_to_fix(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        with pytest.raises(ToolError, match="invalid_request: match_message_type"):
            await a.call(ADD, {"action": "poll", "message_type": "gossip"})

    async def test_audited(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        async with test_session_factory() as s:
            row = (
                await s.execute(select(AuditLog).where(AuditLog.action == "wake_rule.add"))
            ).scalar_one()
        assert row.actor_sub == "a"
        assert row.agent_id == uuid.UUID(a.id)
        assert row.detail["rule_id"] == rule["rule_id"]


class TestUpdate:
    async def test_turn_off_and_on(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        off = await a.call(UPDATE, {"rule_id": rule["rule_id"], "enabled": False})
        assert off["enabled"] is False
        on = await a.call(UPDATE, {"rule_id": rule["rule_id"], "enabled": True})
        assert on["enabled"] is True
        assert on["match_message_type"] == "note"  # untouched fields stay

    async def test_change_action_priority_and_match(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(
            ADD, {"action": "poll", "message_type": "note", "message_priority": "high"}
        )
        updated = await a.call(
            UPDATE,
            {
                "rule_id": rule["rule_id"],
                "action": "wake",
                "priority": 5,
                "message_type": "task_assign",
                "message_priority": "",  # empty string clears a match field
            },
        )
        assert updated["action"] == "wake"
        assert updated["priority"] == 5
        assert updated["match_message_type"] == "task_assign"
        assert updated["match_message_priority"] is None

    async def test_invalid_value_rejected_and_rule_unchanged(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        with pytest.raises(ToolError, match="invalid_request"):
            await a.call(UPDATE, {"rule_id": rule["rule_id"], "message_type": "gossip"})
        with pytest.raises(ToolError, match="invalid_request"):
            await a.call(UPDATE, {"rule_id": rule["rule_id"], "action": "sleep"})
        with pytest.raises(ToolError, match="nothing to change"):
            await a.call(UPDATE, {"rule_id": rule["rule_id"]})
        current = next(r for r in (await a.call(RULES))["rules"] if r["rule_id"] == rule["rule_id"])
        assert current == rule

    async def test_cannot_clear_the_last_match_field(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        with pytest.raises(ToolError, match="at least one match field"):
            await a.call(UPDATE, {"rule_id": rule["rule_id"], "message_type": ""})
        # Clearing one field while another is set is fine.
        both = await a.call(
            ADD, {"action": "poll", "message_type": "note", "message_priority": "high"}
        )
        cleared = await a.call(UPDATE, {"rule_id": both["rule_id"], "message_priority": ""})
        assert cleared["match_message_priority"] is None
        assert cleared["match_message_type"] == "note"

    async def test_priority_above_the_cap_is_rejected(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        with pytest.raises(ToolError, match="invalid_request: priority"):
            await a.call(UPDATE, {"rule_id": rule["rule_id"], "priority": 2**31 - 1})

    async def test_catch_all_action_can_flip_but_nothing_else(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        catch_all = (await a.call(RULES))["rules"][0]
        flipped = await a.call(UPDATE, {"rule_id": catch_all["rule_id"], "action": "poll"})
        assert flipped["action"] == "poll"
        assert flipped["enabled"] is True
        back = await a.call(UPDATE, {"rule_id": catch_all["rule_id"], "action": "wake"})
        assert back["action"] == "wake"
        for bad in (
            {"enabled": False},
            {"priority": 5},
            {"message_type": "note"},
            {"conversation_id": str(uuid.uuid4())},
        ):
            with pytest.raises(ToolError, match="catch-all"):
                await a.call(UPDATE, {"rule_id": catch_all["rule_id"], **bad})
        assert (await a.call(RULES))["rules"][-1] == back

    async def test_audited_with_old_and_new(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        await a.call(UPDATE, {"rule_id": rule["rule_id"], "enabled": False})
        async with test_session_factory() as s:
            row = (
                await s.execute(select(AuditLog).where(AuditLog.action == "wake_rule.update"))
            ).scalar_one()
        assert row.detail["old"]["enabled"] is True
        assert row.detail["new"]["enabled"] is False


class TestOwnRulesOnly:
    async def test_lists_are_separate(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        rule = await a.call(ADD, {"action": "poll", "message_type": "note"})
        b_ids = [r["rule_id"] for r in (await b.call(RULES, {"include_disabled": True}))["rules"]]
        assert rule["rule_id"] not in b_ids
        assert len(b_ids) == 1

    async def test_add_lands_on_caller_only(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        await b.call(ADD, {"action": "poll", "message_type": "note"})
        async with test_session_factory() as s:
            owners = {
                r.agent_id
                for r in (await s.execute(select(WakeRule).where(~WakeRule.is_catch_all))).scalars()
            }
        assert owners == {uuid.UUID(b.id)}
        assert a.id not in {str(o) for o in owners}

    async def test_update_of_another_agents_rule_gets_uniform_denial(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        b_rule = await b.call(ADD, {"action": "poll", "message_type": "note"})
        b_catch_all = (await b.call(RULES))["rules"][-1]
        with pytest.raises(ToolError, match=DENIED):
            await a.call(UPDATE, {"rule_id": b_rule["rule_id"], "enabled": False})
        with pytest.raises(ToolError, match=DENIED):
            await a.call(UPDATE, {"rule_id": b_catch_all["rule_id"], "action": "poll"})
        # An id that exists nowhere is indistinguishable from someone else's.
        with pytest.raises(ToolError, match=DENIED):
            await a.call(UPDATE, {"rule_id": str(uuid.uuid4()), "enabled": False})
        assert (await b.call(RULES))["rules"][0] == b_rule
        assert (await b.call(RULES))["rules"][-1] == b_catch_all
        assert "denied.wake_rule_not_found" in await _audit_actions(test_session_factory)

    async def test_no_agent_parameter_exists(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        for tool, args in (
            (RULES, {}),
            (ADD, {"action": "poll", "message_type": "note"}),
            (SESSIONS, {}),
        ):
            with pytest.raises(ToolError):
                await a.call(tool, {**args, "agent_id": b.id})


class TestSessions:
    async def test_lists_only_open_own_sessions(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        c = await _agent(main, test_session_factory, "c")
        open_conv = await _conversation(a, b)
        stale_conv = await _conversation(a, b)
        closed_conv = await _conversation(a, b)
        await _open_session(test_session_factory, a, open_conv)
        await _open_session(
            test_session_factory, a, stale_conv, age_seconds=WAKE_SESSION_WINDOW_SECONDS + 5
        )
        await _open_session(test_session_factory, a, closed_conv)
        await a.call(CLOSE, {"conversation_id": closed_conv})
        await _open_session(test_session_factory, b, open_conv)

        sessions = (await a.call(SESSIONS))["sessions"]
        assert [s["conversation_id"] for s in sessions] == [open_conv]
        assert set(sessions[0]) == {"conversation_id", "opened_at", "last_activity_at", "closes_at"}
        assert (await c.call(SESSIONS))["sessions"] == []
        assert [s["conversation_id"] for s in (await b.call(SESSIONS))["sessions"]] == [open_conv]

    async def test_close_marks_agent_closed_and_is_idempotent(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        conv = await _conversation(a, b)
        await _open_session(test_session_factory, a, conv)
        await _open_session(test_session_factory, b, conv)

        first = await a.call(CLOSE, {"conversation_id": conv})
        assert first == {"conversation_id": conv, "closed": True}
        second = await a.call(CLOSE, {"conversation_id": conv})
        assert second == {"conversation_id": conv, "closed": False}

        async with test_session_factory() as s:
            rows = {
                r.agent_id: r
                for r in (
                    await s.execute(
                        select(WakeSession).where(WakeSession.conversation_id == uuid.UUID(conv))
                    )
                ).scalars()
            }
        assert rows[uuid.UUID(a.id)].closed_reason == "agent_closed"
        assert rows[uuid.UUID(a.id)].closed_at is not None
        # The other agent's session is untouched.
        assert rows[uuid.UUID(b.id)].closed_at is None
        assert (await a.call(SESSIONS))["sessions"] == []

    async def test_close_audited_once(self, main: Any, test_session_factory: Any) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        conv = await _conversation(a, b)
        await _open_session(test_session_factory, a, conv)
        await a.call(CLOSE, {"conversation_id": conv})
        await a.call(CLOSE, {"conversation_id": conv})
        actions = await _audit_actions(test_session_factory)
        assert actions.count("wake_session.close") == 1

    async def test_close_unknown_or_foreign_conversation_is_a_quiet_noop(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        conv = await _conversation(a, b)
        await _open_session(test_session_factory, b, conv)
        for target in (conv, str(uuid.uuid4())):
            assert (await a.call(CLOSE, {"conversation_id": target}))["closed"] is False
        assert len((await b.call(SESSIONS))["sessions"]) == 1


class TestCallerState:
    @pytest.mark.parametrize(
        ("tool", "args"),
        [
            (RULES, {}),
            (ADD, {"action": "poll", "message_type": "note"}),
            (UPDATE, {"rule_id": str(uuid.uuid4()), "enabled": False}),
            (SESSIONS, {}),
            (CLOSE, {"conversation_id": str(uuid.uuid4())}),
        ],
    )
    async def test_not_registered_is_refused(
        self, main: Any, test_session_factory: Any, tool: str, args: dict[str, Any]
    ) -> None:
        with pytest.raises(ToolError, match="not_registered"):
            await _call(main, test_session_factory, _token("ghost"), tool, args)

    @pytest.mark.parametrize(
        ("tool", "args"),
        [
            (RULES, {}),
            (ADD, {"action": "poll", "message_type": "note"}),
            (UPDATE, {"rule_id": str(uuid.uuid4()), "enabled": False}),
            (SESSIONS, {}),
            (CLOSE, {"conversation_id": str(uuid.uuid4())}),
        ],
    )
    async def test_suspended_is_refused(
        self, main: Any, test_session_factory: Any, tool: str, args: dict[str, Any]
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        admin = _token("admin", scopes=["comms:read", "comms:write", "comms:admin"])
        await _call(main, test_session_factory, admin, "comms_deregister_agent", {"agent_id": a.id})
        with pytest.raises(ToolError, match="agent_suspended"):
            await a.call(tool, args)

    async def test_read_scope_alone_cannot_mutate(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        read_only = _token("a", scopes=["comms:read"])
        assert (await _call(main, test_session_factory, read_only, RULES))["rules"]
        with pytest.raises(ToolError):
            await _call(
                main,
                test_session_factory,
                read_only,
                ADD,
                {"action": "poll", "message_type": "note"},
            )
        assert a.id


class TestEndToEnd:
    """The ticket's "done when" behaviour, through real posts."""

    async def test_poll_rule_off_on_and_session_close(
        self, main: Any, test_session_factory: Any
    ) -> None:
        a = await _agent(main, test_session_factory, "a")
        b = await _agent(main, test_session_factory, "b")
        conv = await _conversation(a, b)
        await b.call("comms_accept", {"conversation_id": conv})
        async with test_session_factory() as s:
            s.add(
                WakeTarget(
                    agent_id=uuid.UUID(b.id),
                    url="https://x.example/wake",
                    secret_ciphertext=b"s",
                    system_label="test",
                )
            )
            await s.commit()

        async def post(message_type: str, payload: dict[str, Any]) -> int:
            result = await a.call(
                "comms_post_message",
                {"conversation_id": conv, "message_type": message_type, "payload": payload},
            )
            return int(result["seq"])

        async def woken(seq: int) -> bool:
            async with test_session_factory() as s:
                rows = (
                    await s.execute(
                        select(WakeEvent).where(
                            WakeEvent.recipient_agent_id == uuid.UUID(b.id), WakeEvent.seq == seq
                        )
                    )
                ).scalars()
                return any(True for _ in rows)

        rule = await b.call(ADD, {"action": "poll", "message_type": "availability_request"})
        assert not await woken(await post("availability_request", _availability_request()))
        task_seq = await post("task_assign", {"action": "report_status"})
        assert await woken(task_seq)  # still woken by task_assign

        # The wake opened a session, so close it to get judged by the rules again.
        assert [s["conversation_id"] for s in (await b.call(SESSIONS))["sessions"]] == [conv]
        await b.call(CLOSE, {"conversation_id": conv})
        assert not await woken(await post("availability_request", _availability_request()))

        await b.call(UPDATE, {"rule_id": rule["rule_id"], "enabled": False})
        seq = await post("availability_request", _availability_request())
        assert await woken(seq)  # old behaviour is back
        await b.call(CLOSE, {"conversation_id": conv})

        await b.call(UPDATE, {"rule_id": rule["rule_id"], "enabled": True})
        assert not await woken(await post("availability_request", _availability_request()))
