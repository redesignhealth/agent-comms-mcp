"""Tests for TECH-9908: admin tools to register and remove an agent's wake address.

Real Postgres (shared fixtures in ``tests/conftest.py``). Tool calls go through
the real mounted server, as in ``tests/test_comms_tools.py``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastmcp.exceptions import ToolError
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import wake_secrets
import wake_targets
from exceptions import WakeTargetMisconfiguredError
from models import AuditLog, WakeTarget
from tests.test_comms_tools import _call, _import_main, _register, _token

pytestmark = pytest.mark.usefixtures("_migrated_schema")

ADMIN_SCOPES = ["comms:read", "comms:write", "comms:admin"]
GOOD_URL = "https://wake.example.ts.net/hooks/wake?token=query-secret-value"
GOOD_SECRET = "whsec_" + base64.b64encode(bytes(range(32))).decode()
OTHER_SECRET = "whsec_" + base64.b64encode(bytes(range(64, 96))).decode()
DENIED = re.escape("access_denied: not authorized for this resource")


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


@pytest.fixture(autouse=True)
def _operator_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, "*.ts.net,wake.example.org")
    monkeypatch.setenv(wake_secrets.WAKE_TARGET_SECRET_KEY_ENV_VAR, Fernet.generate_key().decode())
    yield


def _admin() -> Any:
    return _token("wake-admin", scopes=ADMIN_SCOPES)


async def _set(main: Any, factory: Any, agent_id: str, **overrides: Any) -> Any:
    args = {"agent_id": agent_id, "url": GOOD_URL, "secret": GOOD_SECRET, "system": "paperclip"}
    args.update(overrides)
    return await _call(main, factory, _admin(), "comms_admin_wake_target_set", args)


async def _agent(main: Any, factory: Any, sub: str = "wake-agent") -> str:
    return str((await _register(main, factory, sub))["agent_id"])


async def _row(factory: Any, agent_id: str) -> WakeTarget | None:
    async with factory() as s:
        return (
            await s.execute(select(WakeTarget).where(WakeTarget.agent_id == uuid.UUID(agent_id)))
        ).scalar_one_or_none()


async def _count(factory: Any) -> int:
    async with factory() as s:
        return int((await s.execute(select(func.count()).select_from(WakeTarget))).scalar_one())


class TestSetAndRemove:
    async def test_set_creates_then_replace_rotates(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        created = await _set(main, test_session_factory, agent_id)
        assert created["result"] == "created"
        assert created["agent_id"] == agent_id
        assert created["system"] == "paperclip"
        assert created["host"] == "wake.example.ts.net"
        first = await _row(test_session_factory, agent_id)
        assert first is not None
        assert first.url == GOOD_URL
        assert first.secret_ciphertext != GOOD_SECRET.encode()

        replaced = await _set(
            main, test_session_factory, agent_id, secret=OTHER_SECRET, system="other-sys"
        )
        assert replaced["result"] == "replaced"
        assert replaced["created_at"] == created["created_at"]
        assert replaced["updated_at"] > created["updated_at"]
        second = await _row(test_session_factory, agent_id)
        assert second is not None
        assert second.secret_ciphertext != first.secret_ciphertext
        assert second.updated_at > first.updated_at
        assert second.system_label == "other-sys"
        assert await _count(test_session_factory) == 1
        assert wake_secrets.decrypt_secret(second.secret_ciphertext) == OTHER_SECRET

    async def test_remove_and_remove_missing_is_noop(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        await _set(main, test_session_factory, agent_id)
        removed = await _call(
            main, test_session_factory, _admin(), "comms_admin_wake_target_remove",
            {"agent_id": agent_id},
        )  # fmt: skip
        assert removed == {"agent_id": agent_id, "removed": True}
        assert await _row(test_session_factory, agent_id) is None

        again = await _call(
            main, test_session_factory, _admin(), "comms_admin_wake_target_remove",
            {"agent_id": agent_id},
        )  # fmt: skip
        assert again == {"agent_id": agent_id, "removed": False}
        async with test_session_factory() as s:
            actions = (
                (
                    await s.execute(
                        select(AuditLog.action).where(AuditLog.action.like("wake_target.%"))
                    )
                )
                .scalars()
                .all()
            )
        assert sorted(actions) == [
            "wake_target.created",
            "wake_target.remove_noop",
            "wake_target.removed",
        ]

    async def test_round_trip_decrypt(self, main: Any, test_session_factory: Any) -> None:
        agent_id = await _agent(main, test_session_factory)
        await _set(main, test_session_factory, agent_id)
        row = await _row(test_session_factory, agent_id)
        assert row is not None
        assert wake_secrets.decrypt_secret(row.secret_ciphertext) == GOOD_SECRET


class TestAuthorization:
    async def test_non_admin_refused_on_both_tools(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        plain = _token("not-admin", scopes=["comms:read", "comms:write"])
        with pytest.raises(ToolError, match=DENIED):
            await _call(
                main, test_session_factory, plain, "comms_admin_wake_target_set",
                {"agent_id": agent_id, "url": GOOD_URL, "secret": GOOD_SECRET, "system": "p"},
            )  # fmt: skip
        with pytest.raises(ToolError, match=DENIED):
            await _call(
                main, test_session_factory, plain, "comms_admin_wake_target_remove",
                {"agent_id": agent_id},
            )  # fmt: skip
        assert await _count(test_session_factory) == 0
        async with test_session_factory() as s:
            reasons = (
                (await s.execute(select(AuditLog.action).where(AuditLog.action.like("denied.%"))))
                .scalars()
                .all()
            )
        assert reasons == ["denied.wake_target_requires_elevated_scope"] * 2

    async def test_non_admin_remove_does_not_delete(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        await _set(main, test_session_factory, agent_id)
        plain = _token("not-admin", scopes=["comms:read", "comms:write"])
        with pytest.raises(ToolError, match=DENIED):
            await _call(
                main, test_session_factory, plain, "comms_admin_wake_target_remove",
                {"agent_id": agent_id},
            )  # fmt: skip
        assert await _row(test_session_factory, agent_id) is not None

    async def test_unknown_agent(self, main: Any, test_session_factory: Any) -> None:
        with pytest.raises(ToolError, match=DENIED):
            await _set(main, test_session_factory, str(uuid.uuid4()))
        with pytest.raises(ToolError, match=DENIED):
            await _call(
                main, test_session_factory, _admin(), "comms_admin_wake_target_remove",
                {"agent_id": str(uuid.uuid4())},
            )  # fmt: skip

    async def test_bad_agent_id(self, main: Any, test_session_factory: Any) -> None:
        with pytest.raises(ToolError, match="invalid_request"):
            await _set(main, test_session_factory, "not-a-uuid")


class TestUrlRules:
    @pytest.mark.parametrize(
        ("url", "fragment"),
        [
            ("http://wake.example.ts.net/x", "must use https"),
            ("https://user:pw@wake.example.ts.net/x", "credentials"),
            ("https://user@wake.example.ts.net/x", "credentials"),
            ("https://wake.example.ts.net/x#frag", "fragment"),
            ("https://wake.example.ts.net/x#", "fragment"),
            ("https:///x", "include a host"),
            ("ftp://wake.example.ts.net/x", "must use https"),
            ("https://wake.example.ts.net:notaport/x", "not a valid URL"),
            ("https://wake.example.ts.net/x y", "plain ASCII"),
            ("https://evil.com\\@wake.example.ts.net/x", "plain ASCII"),
            ("https://wake.example.ts.net/" + "a" * 2100, "characters"),
            ("", "characters"),
        ],
    )
    async def test_bad_urls_refused(
        self, main: Any, test_session_factory: Any, url: str, fragment: str
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match=fragment):
            await _set(main, test_session_factory, agent_id, url=url)
        assert await _count(test_session_factory) == 0

    async def test_host_not_on_allowlist(self, main: Any, test_session_factory: Any) -> None:
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match="not on the allowed host list"):
            await _set(main, test_session_factory, agent_id, url="https://other.example.com/x")
        assert await _count(test_session_factory) == 0

    @pytest.mark.parametrize("value", [None, "", "  ,  ", "*", "*."])
    async def test_empty_allowlist_refuses_everything(
        self,
        main: Any,
        test_session_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
        value: str | None,
    ) -> None:
        if value is None:
            monkeypatch.delenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR)
        else:
            monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, value)
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match=r"misconfigured: .*no hosts are allowed"):
            await _set(main, test_session_factory, agent_id)
        assert await _count(test_session_factory) == 0

    async def test_allowlist_is_case_insensitive_and_exact_host_matches(
        self, main: Any, test_session_factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(wake_targets.WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, " Wake.Example.ORG ")
        agent_id = await _agent(main, test_session_factory)
        result = await _set(
            main, test_session_factory, agent_id, url="https://WAKE.example.org:8443/x"
        )
        assert result["host"] == "wake.example.org"

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("a.ts.net", True),
            ("A.B.TS.NET", True),
            ("evil-example.ts.net.attacker.com", False),
            ("xts.net", False),
            ("ts.net", False),
            ("ts.net.evil.com", False),
            ("a.ts.net.", False),
            (".ts.net", False),
            ("a..ts.net", False),
            ("..ts.net", False),
            ("-a.ts.net", False),
            ("a_b.ts.net", False),
            ("a.ts.net..", False),
            ("", False),
            ("a ts.net", False),
        ],
    )
    def test_wildcard_suffix_matching(self, host: str, expected: bool) -> None:
        assert (
            wake_targets.host_is_allowed(host, wake_targets.parse_allowed_hosts("*.ts.net"))
            is expected
        )

    def test_malformed_patterns_are_dropped(self) -> None:
        assert wake_targets.parse_allowed_hosts("*.,*.a..b,.ts.net,a..b,*,ts.net.,*.ok.net") == [
            "*.ok.net"
        ]

    @pytest.mark.parametrize("host", [".ts.net", "a..ts.net", "a.ts.net."])
    async def test_malformed_host_refused_end_to_end(
        self, main: Any, test_session_factory: Any, host: str
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError):
            await _set(main, test_session_factory, agent_id, url=f"https://{host}/x")
        assert await _count(test_session_factory) == 0

    def test_exact_pattern_does_not_match_subdomain(self) -> None:
        patterns = wake_targets.parse_allowed_hosts("wake.example.org")
        assert wake_targets.host_is_allowed("wake.example.org", patterns)
        assert not wake_targets.host_is_allowed("a.wake.example.org", patterns)
        assert not wake_targets.host_is_allowed("xwake.example.org", patterns)

    async def test_userinfo_trick_cannot_smuggle_host(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match="credentials"):
            await _set(
                main, test_session_factory, agent_id,
                url="https://wake.example.ts.net@evil.com/x",
            )  # fmt: skip


class TestSecretAndSystemRules:
    @pytest.mark.parametrize(
        "secret",
        [
            "",
            "nope",
            "whsec_",
            "whsec_not base64!",
            "whsec_" + base64.b64encode(bytes(23)).decode(),
            "whsec_" + base64.b64encode(bytes(65)).decode(),
            "whsec_" + base64.b64encode(bytes(32)).decode().rstrip("="),
            base64.b64encode(bytes(32)).decode(),
            "WHSEC_" + base64.b64encode(bytes(32)).decode(),
        ],
    )
    async def test_bad_secret_refused_without_echo(
        self, main: Any, test_session_factory: Any, secret: str
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match="secret must be") as excinfo:
            await _set(main, test_session_factory, agent_id, secret=secret)
        if len(secret) > len(wake_targets.SECRET_PREFIX):
            assert secret not in str(excinfo.value)
        assert await _count(test_session_factory) == 0

    @pytest.mark.parametrize("size", [24, 64])
    async def test_secret_length_bounds_accepted(
        self, main: Any, test_session_factory: Any, size: int
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        secret = "whsec_" + base64.b64encode(bytes(range(size))).decode()
        await _set(main, test_session_factory, agent_id, secret=secret)
        row = await _row(test_session_factory, agent_id)
        assert row is not None
        assert wake_secrets.decrypt_secret(row.secret_ciphertext) == secret

    @pytest.mark.parametrize("system", ["", "Paperclip", "has space", "-lead", "x" * 33, "a/b"])
    async def test_bad_system_refused(
        self, main: Any, test_session_factory: Any, system: str
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match="system must be"):
            await _set(main, test_session_factory, agent_id, system=system)
        assert await _count(test_session_factory) == 0


class TestEncryptionKey:
    @pytest.mark.parametrize("key", [None, "", "not-a-fernet-key", "c2hvcnQ="])
    async def test_missing_or_malformed_key_fails_closed(
        self, main: Any, test_session_factory: Any, monkeypatch: pytest.MonkeyPatch, key: str | None
    ) -> None:
        if key is None:
            monkeypatch.delenv(wake_secrets.WAKE_TARGET_SECRET_KEY_ENV_VAR)
        else:
            monkeypatch.setenv(wake_secrets.WAKE_TARGET_SECRET_KEY_ENV_VAR, key)
        agent_id = await _agent(main, test_session_factory)
        with pytest.raises(ToolError, match="misconfigured: WAKE_TARGET_SECRET_KEY") as excinfo:
            await _set(main, test_session_factory, agent_id)
        if key:
            assert key not in str(excinfo.value)
        assert await _count(test_session_factory) == 0

    def test_decrypt_with_wrong_key_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ciphertext = wake_secrets.encrypt_secret(GOOD_SECRET)
        monkeypatch.setenv(
            wake_secrets.WAKE_TARGET_SECRET_KEY_ENV_VAR, Fernet.generate_key().decode()
        )
        with pytest.raises(WakeTargetMisconfiguredError):
            wake_secrets.decrypt_secret(ciphertext)

    def test_encrypt_is_not_deterministic(self) -> None:
        assert wake_secrets.encrypt_secret("x") != wake_secrets.encrypt_secret("x")


class TestNoSecretLeaks:
    async def test_responses_audit_and_logs_hold_no_secret_or_ciphertext(
        self,
        main: Any,
        test_session_factory: Any,
        caplog: pytest.LogCaptureFixture,
        capfd: pytest.CaptureFixture[str],
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        with caplog.at_level("DEBUG"):
            created = await _set(main, test_session_factory, agent_id)
            first_row = await _row(test_session_factory, agent_id)
            assert first_row is not None
            ciphertext = first_row.secret_ciphertext.decode()
            replaced = await _set(main, test_session_factory, agent_id, secret=OTHER_SECRET)
            removed = await _call(
                main, test_session_factory, _admin(), "comms_admin_wake_target_remove",
                {"agent_id": agent_id},
            )  # fmt: skip
            with pytest.raises(ToolError):
                await _set(main, test_session_factory, agent_id, secret="whsec_bad-secret-value")
        async with test_session_factory() as s:
            audit = [
                json.dumps(r, default=str)
                for r in (await s.execute(select(AuditLog.action, AuditLog.detail))).all()
            ]
        out = capfd.readouterr()
        haystack = "\n".join(
            [json.dumps([created, replaced, removed]), *audit, caplog.text, out.out, out.err]
        )
        for needle in (
            GOOD_SECRET,
            GOOD_SECRET.removeprefix("whsec_"),
            OTHER_SECRET,
            OTHER_SECRET.removeprefix("whsec_"),
            "whsec_bad-secret-value",
            "query-secret-value",
            ciphertext,
        ):
            assert needle not in haystack
        assert "gAAAA" not in haystack  # Fernet token prefix
        assert set(created) == {"agent_id", "system", "host", "result", "created_at", "updated_at"}

    async def test_audit_records_agent_system_and_host_only(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        await _set(main, test_session_factory, agent_id)
        async with test_session_factory() as s:
            row = (
                await s.execute(select(AuditLog).where(AuditLog.action == "wake_target.created"))
            ).scalar_one()
        assert row.actor_sub == "wake-admin"
        assert str(row.agent_id) == agent_id
        assert row.detail == {"system": "paperclip", "host": "wake.example.ts.net"}


class TestConcurrentFirstSet:
    async def _service_set(self, factory: Any, agent_id: str, secret: str) -> dict[str, Any]:
        async with factory() as session:
            return await wake_targets.set_wake_target(
                session,
                actor_sub="wake-admin",
                admin_authorized=True,
                agent_id=uuid.UUID(agent_id),
                url=GOOD_URL,
                secret=secret,
                system="paperclip",
            )

    async def test_losing_the_insert_race_becomes_a_replace(
        self, main: Any, test_session_factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        await _set(main, test_session_factory, agent_id)  # the "winner" commits first
        real_get_row = wake_targets._get_row
        calls = 0

        async def stale_first_read(session: AsyncSession, aid: uuid.UUID) -> WakeTarget | None:
            nonlocal calls
            calls += 1
            return None if calls == 1 else await real_get_row(session, aid)

        monkeypatch.setattr(wake_targets, "_get_row", stale_first_read)
        result = await self._service_set(test_session_factory, agent_id, OTHER_SECRET)
        assert result["result"] == "replaced"
        row = await _row(test_session_factory, agent_id)
        assert row is not None
        assert wake_secrets.decrypt_secret(row.secret_ciphertext) == OTHER_SECRET
        assert await _count(test_session_factory) == 1

    async def test_parallel_first_time_sets_both_succeed(
        self, main: Any, test_session_factory: Any
    ) -> None:
        agent_id = await _agent(main, test_session_factory)
        results = await asyncio.gather(
            *(self._service_set(test_session_factory, agent_id, GOOD_SECRET) for _ in range(5))
        )
        assert sorted(r["result"] for r in results).count("created") == 1
        assert await _count(test_session_factory) == 1
