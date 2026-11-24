"""Tests for TECH-9890: the wake delivery pause switch.

Real Postgres (shared fixtures in ``tests/conftest.py``), real mounted tools,
a real ``WakeDelivery`` against a mock receiver.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastmcp.exceptions import ToolError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import wake_secrets
import wake_targets
from models import AuditLog
from tests.test_comms_tools import _call, _import_main, _token
from tests.test_wake_delivery import ACCEPTED, _event, _fresh_room, _get
from wake_delivery import WakeDelivery

pytestmark = pytest.mark.usefixtures("_migrated_schema")

DENIED = re.escape("access_denied: not authorized for this resource")
ADMIN_SCOPES = ["comms:read", "comms:write", "comms:admin"]


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE wake_delivery_state, wake_targets, wake_events, wake_sessions, "
                "wake_rules, audit_log, messages, participants, conversations, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest.fixture(autouse=True)
def _operator_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, "*.ts.net")
    monkeypatch.setenv(wake_secrets.WAKE_TARGET_SECRET_KEY_ENV_VAR, Fernet.generate_key().decode())
    yield


@pytest.fixture
def factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


def _admin() -> Any:
    return _token("wake-admin", scopes=ADMIN_SCOPES)


def _plain() -> Any:
    return _token("not-admin", scopes=["comms:read", "comms:write"])


async def _tool(main: Any, factory: Any, name: str, token: Any = None, **args: Any) -> Any:
    return await _call(main, factory, token or _admin(), f"comms_admin_wake_delivery_{name}", args)


async def _audit_rows(factory: Any, action: str) -> list[AuditLog]:
    async with factory() as s:
        return list((await s.execute(select(AuditLog).where(AuditLog.action == action))).scalars())


class TestTools:
    async def test_status_defaults_to_not_paused(self, main: Any, factory: Any) -> None:
        assert await _tool(main, factory, "status") == {
            "paused": False, "paused_at": None, "paused_by": None, "reason": None,
        }  # fmt: skip

    async def test_pause_resume_and_idempotency(self, main: Any, factory: Any) -> None:
        first = await _tool(main, factory, "pause", reason="receiver down")
        assert first["paused"] is True
        assert first["paused_by"] == "wake-admin"
        assert first["reason"] == "receiver down"
        # A second pause keeps who, when and why.
        again = await _tool(main, factory, "pause", token=_token("other", scopes=ADMIN_SCOPES))
        assert again == first
        assert await _tool(main, factory, "status") == first

        resumed = await _tool(main, factory, "resume")
        assert resumed == {"paused": False, "paused_at": None, "paused_by": None, "reason": None}
        assert await _tool(main, factory, "resume") == resumed

        paused_rows = await _audit_rows(factory, "wake_delivery.paused")
        assert len(paused_rows) == 2
        assert paused_rows[0].detail["previous"]["paused"] is False
        assert paused_rows[0].detail["changed"] is True
        assert paused_rows[1].detail["previous"]["paused"] is True
        assert paused_rows[1].detail["changed"] is False
        resumed_rows = await _audit_rows(factory, "wake_delivery.resumed")
        assert len(resumed_rows) == 2
        assert resumed_rows[0].detail["previous"]["reason"] == "receiver down"
        assert resumed_rows[0].actor_sub == "wake-admin"

    async def test_reason_too_long(self, main: Any, factory: Any) -> None:
        with pytest.raises(ToolError, match="invalid_request"):
            await _tool(main, factory, "pause", reason="x" * 201)

    @pytest.mark.parametrize("name", ["status", "pause", "resume"])
    async def test_non_admin_refused(self, main: Any, factory: Any, name: str) -> None:
        with pytest.raises(ToolError, match=DENIED):
            await _tool(main, factory, name, token=_plain())
        assert (await _tool(main, factory, "status"))["paused"] is False


class TestDelivery:
    async def test_pause_stops_claims_resume_delivers_backlog(
        self, main: Any, factory: Any
    ) -> None:
        calls: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json=ACCEPTED)

        async with factory() as s:
            room = await _fresh_room(s)
            fresh = await _event(s, room.active, room.conversation_id, room.sender, 1)
            old = await _event(
                s, room.invited, room.conversation_id, room.sender, 1,
                age=timedelta(hours=25),
            )  # fmt: skip
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        delivery = WakeDelivery(session_factory=lambda: factory, client=client, send_timeout=1.0)

        await _tool(main, factory, "pause")
        assert await delivery.tick() == 0
        await delivery.drain()
        assert calls == []
        async with factory() as s:
            row = await _get(s, fresh)
            assert (row.status, row.attempt_count) == ("pending", 0)
            # Expiry still runs while paused.
            assert (await _get(s, old)).status == "dead"

        await _tool(main, factory, "resume")
        assert await delivery.tick() == 1
        await delivery.drain()
        await client.aclose()
        assert len(calls) == 1
        async with factory() as s:
            assert (await _get(s, fresh)).status == "delivered"
