"""Service-layer tests for the comms domain (service.py) — real Postgres only.

Mirrors ``tests/test_db_models.py``'s idiom: never mocks the database, runs
the full Alembic migration chain once per module against a live Postgres,
and skips the entire module (with a clear reason) if Postgres is
unreachable — there is no in-memory/sqlite fallback.

Every test exercises ``service.py`` through its public functions only
(``register_agent``, ``start_conversation``, ``accept_invite``, ...) —
never by poking ORM rows directly — except for a handful of assertions
that read back rows (``participants``, ``audit_log``) to verify side
effects the return values don't expose.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import plugins
import service as _service
from exceptions import (
    AccessDeniedError,
    AgentRetiredError,
    InvalidConversationStateError,
    RateLimitExceededError,
    SchemaVersionMismatchError,
    UnknownConversationTypeError,
)
from models import Agent, ApprovalHold, AuditLog, Conversation, Message, Participant
from schemas import (
    MAX_ACCEPTED_TYPE_LENGTH,
    MAX_PAYLOAD_BYTES,
    MAX_REGISTERED_SCHEMA_VERSION,
    MESSAGE_TYPES,
    PayloadValidationError,
)
from service import (
    CONVERSATION_TTL,
    MAX_APPROVAL_HOLDS_PER_HOUR,
    MAX_CONVERSATION_STARTS_PER_HOUR,
    MAX_CONVERSATION_TTL,
    MAX_MESSAGES_PER_CONVERSATION_PER_HOUR,
    MAX_MESSAGES_PER_GET_CONVERSATION,
    MAX_MESSAGES_PER_SENDER_PER_HOUR,
    MAX_PENDING_INVITES_PER_INBOX,
    MAX_UNREAD_CONVERSATIONS_PER_INBOX,
    AgentTableOwnershipClient,
    OwnershipClient,
    accept_invite,
    decline_invite,
    get_conversation,
    inbox,
    leave,
    list_conversations,
    reconcile_agent_ownership,
    register_agent,
    set_agent_shared,
    write_through_ownership,
)

# Coverage for MESSAGE_TYPES fitting within MAX_ACCEPTED_TYPES (a precondition
# for sorted(MESSAGE_TYPES) as a default accepted_types below) lives in
# tests/test_schemas.py as a collected test, not a module-level assert here.


async def start_conversation(
    session: AsyncSession,
    *,
    ownership_client: OwnershipClient | None = None,
    risk_scorer: plugins.RiskScorer | None = None,
    auto_approver: plugins.AutoApprover | None = None,
    notifier: plugins.ApprovalNotifier | None = None,
    active_checker: plugins.ActiveChecker | None = None,
    **kwargs: Any,
) -> Any:
    """Thin wrapper defaulting ``ownership_client``/``risk_scorer``/
    ``auto_approver``/``notifier``/``active_checker`` so every pre-existing
    call site in this file keeps working unchanged — tests that care about
    ownership/risk/approval/retirement behavior pass their own fake
    explicitly."""
    return await _service.start_conversation(
        session,
        ownership_client=ownership_client or AgentTableOwnershipClient(session),
        risk_scorer=risk_scorer or plugins.BoundaryCrossingScorer(),
        auto_approver=auto_approver or plugins.EscalateAllAutoApprover(),
        notifier=notifier or plugins.LogOnlyNotifier(),
        active_checker=active_checker or plugins.AlwaysActiveChecker(),
        **kwargs,
    )


async def invite(
    session: AsyncSession,
    *,
    ownership_client: OwnershipClient | None = None,
    active_checker: plugins.ActiveChecker | None = None,
    **kwargs: Any,
) -> Any:
    return await _service.invite(
        session,
        ownership_client=ownership_client or AgentTableOwnershipClient(session),
        active_checker=active_checker or plugins.AlwaysActiveChecker(),
        **kwargs,
    )


async def list_agents(
    session: AsyncSession, *, active_checker: plugins.ActiveChecker | None = None, **kwargs: Any
) -> Any:
    return await _service.list_agents(
        session, active_checker=active_checker or plugins.AlwaysActiveChecker(), **kwargs
    )


async def lookup_agent_by_email(
    session: AsyncSession, *, active_checker: plugins.ActiveChecker | None = None, **kwargs: Any
) -> Any:
    return await _service.lookup_agent_by_email(
        session, active_checker=active_checker or plugins.AlwaysActiveChecker(), **kwargs
    )


async def post_message(
    session: AsyncSession,
    *,
    ownership_client: OwnershipClient | None = None,
    risk_scorer: plugins.RiskScorer | None = None,
    auto_approver: plugins.AutoApprover | None = None,
    notifier: plugins.ApprovalNotifier | None = None,
    **kwargs: Any,
) -> Any:
    return await _service.post_message(
        session,
        ownership_client=ownership_client or AgentTableOwnershipClient(session),
        risk_scorer=risk_scorer or plugins.BoundaryCrossingScorer(),
        auto_approver=auto_approver or plugins.EscalateAllAutoApprover(),
        notifier=notifier or plugins.LogOnlyNotifier(),
        **kwargs,
    )


SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"


def _test_database_url() -> str:
    url = os.environ.get("DATABASE_URL", _DEFAULT_TEST_DATABASE_URL)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def _can_connect(url: str) -> bool:
    try:
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return True
    except Exception:  # any connection failure just means "skip this module"
        return False


@pytest.fixture(scope="module")
def database_url() -> str:
    url = _test_database_url()
    if not asyncio.run(_can_connect(url)):
        pytest.skip(
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise the real-database service-layer tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
    """Run the full Alembic chain (downgrade base -> upgrade head) once per module."""
    env = {**os.environ, "DATABASE_URL": database_url.replace("+asyncpg", "")}
    for args in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=SERVICE_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )


@pytest_asyncio.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    """Function-scoped (NOT module-scoped): asyncpg connections cannot be
    reused across the distinct event loops pytest-asyncio spins up per test
    function (``asyncio_mode = "auto"``), so a fresh engine per test is
    required — same idiom as ``tests/test_db_models.py``. The Alembic
    migration chain itself still runs only once per module (see
    ``_migrated_schema``, a sync subprocess with no engine to reuse)."""
    eng = create_async_engine(database_url)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    """Truncate every domain table before each test — tests share one engine
    (module-scoped, since re-running the Alembic chain per test is slow) but
    must not see each other's rows."""
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE audit_log, messages, participants, conversations, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


# --- Test data helpers -----------------------------------------------------


async def _register(session: AsyncSession, sub: str, **overrides: Any) -> Agent:
    kwargs: dict[str, Any] = {
        "sub": sub,
        "owner_sub": f"owner-{sub}",
        "owner_email": f"{sub}@example.com",
        "display_name": sub,
        # Permissive default so tests unrelated to the accepted_types
        # capability gate (TestMessageTypeAccepted) don't need to opt in
        # per-type; those tests narrow this explicitly via overrides.
        "accepted_types": sorted(MESSAGE_TYPES),
        # register_agent's own default is False (fail-closed) so a future
        # caller that omits the kwarg doesn't silently grant shared-agent
        # privileges. This test helper is the one place
        # that convenience default belongs instead -- most service-layer
        # tests here call `_register(..., is_shared=True)` directly and
        # aren't testing the scope gate itself (that's TestRegisterAgent's
        # dedicated denial test), so they need this to keep working.
        "is_shared_authorized": True,
    }
    kwargs.update(overrides)
    return await register_agent(session, **kwargs)


class _FakeActiveChecker:
    """TECH-5703 test double: reports every sub in ``inactive_subs`` as
    retired, everything else active -- the shape a real registry-backed
    ``ActiveChecker`` would report for a confirmed deactivation."""

    def __init__(self, inactive_subs: set[str]) -> None:
        self._inactive_subs = inactive_subs

    async def is_active(self, sub: str) -> bool:
        return sub not in self._inactive_subs


def _request_payload(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "window": {"start": now.isoformat(), "end": (now + timedelta(hours=2)).isoformat()},
        "duration_min": 30,
        "modality": "video",
        "priority": "normal",
        "constraints": [],
    }
    payload.update(overrides)
    return payload


def _task_assign_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"action": "report_status"}
    payload.update(overrides)
    return payload


def _decline_payload(reason: str = "owner_declined") -> dict[str, Any]:
    return {"reason": reason}


def _confirm_payload() -> dict[str, Any]:
    now = datetime.now(UTC)
    return {"slot": {"start": now.isoformat(), "end": (now + timedelta(hours=1)).isoformat()}}


def _counter_proposal_payload() -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "slots": [
            {
                "start": now.isoformat(),
                "end": (now + timedelta(hours=1)).isoformat(),
                "preference": 0.5,
            }
        ]
    }


def _needs_clarification_payload(about_seq: int) -> dict[str, Any]:
    return {"about_seq": about_seq}


async def _audit_actions(session: AsyncSession, conversation_id: uuid.UUID) -> list[str]:
    rows = (
        (
            await session.execute(
                select(AuditLog.action).where(AuditLog.conversation_id == conversation_id)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


# --- register_agent ----------------------------------------------------------


class TestRegisterAgent:
    async def test_idempotent_upsert(self, session: AsyncSession) -> None:
        first = await _register(session, "agent-a", display_name="A v1")
        second = await _register(session, "agent-a", display_name="A v2")

        assert first.id == second.id
        assert second.display_name == "A v2"

        rows = (await session.execute(select(Agent).where(Agent.sub == "agent-a"))).scalars().all()
        assert len(rows) == 1

    async def test_display_name_over_max_length_rejected(self, session: AsyncSession) -> None:
        """A display_name over ``schemas.MAX_DISPLAY_NAME_LENGTH`` (255, the
        DB column's ``VARCHAR`` cap) must be rejected here as a clean
        ``ValueError`` — never allowed to reach the DB write and surface as
        an unmapped ``DataError``/``StringDataRightTruncation``."""
        with pytest.raises(ValueError, match="display_name exceeds 255 characters"):
            await _register(session, "agent-long-name", display_name="x" * 256)

        # Exactly at the cap is still accepted.
        agent = await _register(session, "agent-max-name", display_name="x" * 255)
        assert len(agent.display_name) == 255

    async def test_accepted_types_over_max_count_rejected(self, session: AsyncSession) -> None:
        """More than ``schemas.MAX_ACCEPTED_TYPES`` (20) entries in
        ``accepted_types`` is rejected outright, even if every entry is a
        known, valid conversation type (v1 has only one)."""
        with pytest.raises(ValueError, match="accepted_types exceeds 20 entries"):
            await _register(
                session,
                "agent-too-many-types",
                accepted_types=["availability_request"] * 21,
            )

    async def test_accepted_types_at_max_count_accepted(self, session: AsyncSession) -> None:
        """Exactly ``schemas.MAX_ACCEPTED_TYPES`` (20) entries is still
        accepted — the inclusive boundary of the ``len() > 20`` check in
        ``register_agent``. The count check runs against the raw list
        (before dedup), so 20 repeats of a valid message type exercise
        this boundary without tripping the "unknown type" check;
        ``register_agent`` then dedupes/sorts, so the persisted
        ``accepted_types`` collapses to a single entry."""
        agent = await _register(
            session,
            "agent-max-types",
            accepted_types=["availability_request"] * 20,
        )
        assert agent.accepted_types == ["availability_request"]

    async def test_oversized_accepted_types_of_unknown_values_still_hits_count_cap(
        self, session: AsyncSession
    ) -> None:
        """The ``MAX_ACCEPTED_TYPES`` count check runs before the
        unknown-type check: an oversized list of
        entirely-unknown type strings must still be rejected by the count
        cap, not have every entry echoed back verbatim in an
        ``UnknownConversationTypeError`` message with no size bound of its
        own."""
        with pytest.raises(ValueError, match="accepted_types exceeds 20 entries"):
            await _register(
                session,
                "agent-oversized-unknown-types",
                accepted_types=[f"bogus-{i}" for i in range(21)],
            )

    async def test_empty_accepted_types_raises_plain_value_error(
        self, session: AsyncSession
    ) -> None:
        """An empty ``accepted_types`` list is a distinct failure from
        "contains an unknown type": there is no unknown
        value to usefully enumerate, so this stays a bare ``ValueError``
        rather than ``UnknownConversationTypeError`` -- the prior behavior
        raised the latter with the confusing message
        ``"... (got unknown: [])"``, naming zero unknown values while still
        claiming something was unknown."""
        with pytest.raises(ValueError, match="accepted_types must be non-empty"):
            await _register(
                session,
                "agent-empty-types",
                accepted_types=[],
            )

    async def test_oversized_single_accepted_type_entry_rejected(
        self, session: AsyncSession
    ) -> None:
        """The per-entry length cap: a single
        oversized string must be rejected before it can be echoed back
        verbatim in an ``UnknownConversationTypeError`` message -- the count
        cap alone does not bound how long any one entry is."""
        with pytest.raises(
            ValueError,
            match=f"accepted_types entries must not exceed {MAX_ACCEPTED_TYPE_LENGTH} characters",
        ):
            await _register(
                session,
                "agent-oversized-single-type",
                accepted_types=["x" * (MAX_ACCEPTED_TYPE_LENGTH + 1)],
            )

    async def test_accepted_type_entry_at_max_length_succeeds(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Boundary-value test: an entry exactly at
        MAX_ACCEPTED_TYPE_LENGTH must be accepted. No real MESSAGE_TYPES
        value is anywhere near 100 characters, so this monkeypatches the
        known-types set with a synthetic entry at exactly the cap -- the
        point is isolating the length check from the separate
        known-type-membership check, not exercising a real type name."""
        boundary_type = "x" * MAX_ACCEPTED_TYPE_LENGTH
        monkeypatch.setattr(_service, "MESSAGE_TYPES", _service.MESSAGE_TYPES | {boundary_type})
        agent = await _register(
            session,
            "agent-at-cap",
            accepted_types=[boundary_type],
        )
        assert agent.accepted_types == [boundary_type]

    async def test_empty_or_whitespace_sub_raises_plain_value_error(
        self, session: AsyncSession
    ) -> None:
        for bad_sub in ("", "   "):
            with pytest.raises(ValueError, match="sub must be non-empty"):
                await _register(session, bad_sub)

    async def test_unknown_accepted_type_raises_specific_error(self, session: AsyncSession) -> None:
        """An ``accepted_types`` entry outside ``schemas.MESSAGE_TYPES``
        raises ``UnknownConversationTypeError`` (not a bare ``ValueError``),
        with a message naming the unknown value and the actual valid set --
        this is deliberately specific/client-safe, unlike the uniform
        ``AccessDeniedError`` shape (see exceptions.py's module docstring)."""
        with pytest.raises(UnknownConversationTypeError, match=r"got unknown: \['bogus'\]"):
            await _register(
                session,
                "agent-unknown-type",
                accepted_types=["bogus"],
            )

    async def test_unknown_accepted_type_mixed_with_valid_reports_only_unknown(
        self, session: AsyncSession
    ) -> None:
        """A mix of one valid and one unknown type still rejects the whole
        call (accepted_types must be entirely valid), and the error names
        only the unknown entry, not the valid one alongside it."""
        with pytest.raises(UnknownConversationTypeError, match=r"got unknown: \['bogus'\]"):
            await _register(
                session,
                "agent-mixed-types",
                accepted_types=["availability_request", "bogus"],
            )

    async def test_schema_version_defaults_to_one_one(self, session: AsyncSession) -> None:
        """Schema-version capability negotiation: min/max_schema_version
        default to 1/1 (today's only wire schema version) when not supplied."""
        agent = await _register(session, "agent-schema-default")
        assert agent.min_schema_version == 1
        assert agent.max_schema_version == 1

    async def test_schema_version_range_persisted(self, session: AsyncSession) -> None:
        agent = await _register(
            session, "agent-schema-range", min_schema_version=1, max_schema_version=2
        )
        assert agent.min_schema_version == 1
        assert agent.max_schema_version == 2

    async def test_min_schema_version_over_max_rejected(self, session: AsyncSession) -> None:
        """min_schema_version > max_schema_version is a plain
        input-validation failure (not an authorization decision), same
        posture as the other malformed-input ``ValueError`` cases above."""
        with pytest.raises(ValueError, match="min_schema_version must be <= max_schema_version"):
            await _register(
                session,
                "agent-bad-schema-range",
                min_schema_version=3,
                max_schema_version=2,
            )

    async def test_min_schema_version_below_one_rejected(self, session: AsyncSession) -> None:
        """A 0 or negative min_schema_version
        passed the original min<=max check alone and routed straight into a
        broken negotiation (no schema registered below version 1) -- this
        is the dedicated lower-bound guard closing that gap."""
        for bad_min in (0, -1):
            with pytest.raises(ValueError, match="min_schema_version must be >= 1"):
                await _register(
                    session,
                    "agent-schema-below-one",
                    min_schema_version=bad_min,
                    max_schema_version=bad_min,
                )

    async def test_schema_version_reset_on_reregister_when_omitted(
        self, session: AsyncSession
    ) -> None:
        """Documented behavior: omitting both
        range params on a re-registration resets to 1/1, the same default a
        fresh registration gets -- even if a wider range was declared
        before. This is intentional (see register_agent's docstring): safe
        by construction, since a narrowed range can only make negotiation
        MORE conservative, never admit a version this agent can't handle."""
        first = await _register(
            session, "agent-schema-reset", min_schema_version=1, max_schema_version=3
        )
        assert first.max_schema_version == 3

        second = await _register(session, "agent-schema-reset")
        assert second.min_schema_version == 1
        assert second.max_schema_version == 1

    async def test_is_shared_frozen_on_reregister(self, session: AsyncSession) -> None:
        """``is_shared`` is frozen at first registration -- re-registering with
        a different value must not overwrite it (same freeze semantics as
        ``owner_sub``: both are admission-decision inputs)."""
        first = await _register(session, "shared-freeze", is_shared=False)
        assert first.is_shared is False

        second = await _register(session, "shared-freeze", is_shared=True)
        assert second.id == first.id
        assert second.is_shared is False

    async def test_is_shared_frozen_on_reregister_downgrade(self, session: AsyncSession) -> None:
        """The freeze is bidirectional: a re-registration cannot downgrade
        ``is_shared`` from ``True`` to ``False`` either -- the same
        admission-decision-input rationale as the upgrade direction above
        applies regardless of which way the requested value moves."""
        first = await _register(session, "shared-freeze-downgrade", is_shared=True)
        assert first.is_shared is True

        second = await _register(session, "shared-freeze-downgrade", is_shared=False)
        assert second.id == first.id
        assert second.is_shared is True

        rows = (
            await session.execute(
                select(AuditLog.detail).where(
                    AuditLog.actor_sub == "shared-freeze-downgrade",
                    AuditLog.action == "agent.reregister_is_shared_ignored",
                )
            )
        ).all()
        assert len(rows) == 1
        (detail,) = rows[0]
        assert detail["is_shared_requested"] is False
        assert detail["is_shared_effective"] is True
        assert detail["is_shared_authorized"] is True

    async def test_is_shared_frozen_on_unauthorized_downgrade_attempt(
        self, session: AsyncSession
    ) -> None:
        """The freeze holds even when the re-registering caller explicitly
        lacks `comms:admin` authorization for the change they're
        requesting -- downgrade doesn't require authorization to attempt,
        only to succeed, and it never succeeds regardless."""
        first = await _register(session, "shared-freeze-downgrade-unauth", is_shared=True)
        assert first.is_shared is True

        second = await _register(
            session,
            "shared-freeze-downgrade-unauth",
            is_shared=False,
            is_shared_authorized=False,
        )
        assert second.id == first.id
        assert second.is_shared is True

        rows = (
            await session.execute(
                select(AuditLog.detail).where(
                    AuditLog.actor_sub == "shared-freeze-downgrade-unauth",
                    AuditLog.action == "agent.reregister_is_shared_ignored",
                )
            )
        ).all()
        assert len(rows) == 1
        (detail,) = rows[0]
        assert detail["is_shared_requested"] is False
        assert detail["is_shared_effective"] is True
        assert detail["is_shared_authorized"] is False

    async def test_reregister_is_shared_mismatch_is_audited(self, session: AsyncSession) -> None:
        """A re-registration that requests a different ``is_shared`` value
        than the frozen row has no effect on the row (see the freeze tests
        above), but must still leave an audit trail of the mismatch --
        otherwise repeated probing of this escalation vector (or an
        accidental downgrade attempt) goes unnoticed."""
        first = await _register(
            session, "shared-mismatch-audit", is_shared=False, is_shared_authorized=True
        )
        assert first.is_shared is False

        second = await _register(
            session, "shared-mismatch-audit", is_shared=True, is_shared_authorized=False
        )
        assert second.id == first.id
        assert second.is_shared is False

        rows = (
            await session.execute(
                select(AuditLog.action, AuditLog.detail).where(
                    AuditLog.actor_sub == "shared-mismatch-audit",
                    AuditLog.action == "agent.reregister_is_shared_ignored",
                )
            )
        ).all()
        assert len(rows) == 1
        _, detail = rows[0]
        assert detail["is_shared_requested"] is True
        assert detail["is_shared_effective"] is False
        assert detail["is_shared_authorized"] is False

    async def test_register_audit_detail_is_shared_effective_vs_requested(
        self, session: AsyncSession
    ) -> None:
        """The ``agent.register`` audit detail's ``is_shared`` key holds the
        effective/persisted value, while ``is_shared_requested`` holds
        whatever the caller passed -- these diverge on a re-registration
        that requests a different value than what's already frozen."""
        first = await _register(
            session, "register-audit-detail", is_shared=True, is_shared_authorized=True
        )
        assert first.is_shared is True

        rows = (
            await session.execute(
                select(AuditLog.detail).where(
                    AuditLog.actor_sub == "register-audit-detail",
                    AuditLog.action == "agent.register",
                )
            )
        ).all()
        assert len(rows) == 1
        (first_detail,) = rows[0]
        assert first_detail["created"] is True
        assert first_detail["is_shared"] is True
        assert first_detail["is_shared_requested"] is True

        second = await _register(
            session, "register-audit-detail", is_shared=False, is_shared_authorized=False
        )
        assert second.id == first.id
        assert second.is_shared is True

        rows = (
            await session.execute(
                select(AuditLog.detail)
                .where(
                    AuditLog.actor_sub == "register-audit-detail",
                    AuditLog.action == "agent.register",
                )
                .order_by(AuditLog.id)
            )
        ).all()
        assert len(rows) == 2
        (second_detail,) = rows[1]
        assert second_detail["created"] is False
        assert second_detail["is_shared"] is True
        assert second_detail["is_shared_requested"] is False

    async def test_is_shared_true_denied_without_authorization(self, session: AsyncSession) -> None:
        """First registration with ``is_shared=True`` and
        ``is_shared_authorized=False`` (the fail-closed default) is denied
        with the specific audited reason, and no ``Agent`` row is created."""
        with pytest.raises(AccessDeniedError) as exc_info:
            await register_agent(
                session,
                sub="shared-unauthorized",
                owner_sub="owner-shared-unauthorized",
                owner_email="shared-unauthorized@example.com",
                display_name="Shared Unauthorized",
                accepted_types=sorted(MESSAGE_TYPES),
                is_shared=True,
                is_shared_authorized=False,
            )
        assert exc_info.value.reason == "denied.is_shared_requires_elevated_scope"

        no_row = (
            await session.execute(select(Agent).where(Agent.sub == "shared-unauthorized"))
        ).scalar_one_or_none()
        assert no_row is None

        actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.actor_sub == "shared-unauthorized")
                )
            )
            .scalars()
            .all()
        )
        assert "denied.is_shared_requires_elevated_scope" in actions

    async def test_shared_sender_can_post_note_in_asymmetric(self, session: AsyncSession) -> None:
        """A sender registered with ``is_shared=True`` bypasses the
        boundary-crossing check for ``note`` in an ``asymmetric``
        conversation — exercises the real ``AgentTableOwnershipClient``
        rather than a fake, verifying the full stack: migration column →
        ORM model → service freeze → ownership client → enforce path."""
        shared = await _register(
            session, "shared-note-sender", owner_sub="shared-owner", is_shared=True
        )
        solo = await _register(session, "solo-note-target", owner_sub="solo-owner", is_shared=False)
        # Conversation open: asymmetric normally requires pairwise ownership
        # overlap, but _authorize_conversation_open bypasses that check
        # entirely for a shared initiator (`shared` here). The separate
        # post-message bypass in _enforce_boundary_crossing (for the `note`
        # send below) is exercised after the conversation is open.
        conversation = await start_conversation(
            session,
            actor_sub=shared.sub,
            initiator_agent_id=shared.id,
            conversation_type="asymmetric",
            target_agent_ids=[solo.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=solo.sub, agent_id=solo.id, conversation_id=conversation.id
        )
        message = await post_message(
            session,
            actor_sub=shared.sub,
            sender_agent_id=shared.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "hello from shared bot"},
        )
        assert message.type == "note"

        rows = (
            await session.execute(
                select(AuditLog.agent_id, AuditLog.conversation_id, AuditLog.detail).where(
                    AuditLog.action == "risk.shared_sender_bypass",
                )
            )
        ).all()
        assert len(rows) == 1
        agent_id, conversation_id, detail = rows[0]
        assert agent_id == shared.id
        assert conversation_id == conversation.id
        assert detail["message_type"] == "note"


# --- set_agent_shared ----------------------------------------------------------


class TestSetAgentShared:
    async def test_admin_override_flips_is_shared(self, session: AsyncSession) -> None:
        """An authorized caller can correct an agent's ``is_shared`` even
        though ``register_agent`` itself freezes the field against the
        agent's own re-registration."""
        agent = await _register(session, "wrongly-not-shared", is_shared=False)

        updated = await set_agent_shared(
            session,
            actor_sub="admin-operator",
            agent_id=agent.id,
            is_shared=True,
            is_shared_authorized=True,
        )

        assert updated.is_shared is True
        row = (await session.execute(select(Agent).where(Agent.id == agent.id))).scalar_one()
        assert row.is_shared is True

        rows = (
            await session.execute(
                select(AuditLog.agent_id, AuditLog.detail).where(
                    AuditLog.action == "agent.set_shared"
                )
            )
        ).all()
        assert len(rows) == 1
        audited_agent_id, detail = rows[0]
        assert audited_agent_id == agent.id
        assert detail == {"is_shared": True, "previous": False}

    async def test_admin_override_flips_true_to_false(self, session: AsyncSession) -> None:
        """The reverse direction of the correction: an agent wrongly
        registered as shared can be corrected back to not-shared."""
        agent = await _register(session, "wrongly-shared", is_shared=True)

        updated = await set_agent_shared(
            session,
            actor_sub="admin-operator",
            agent_id=agent.id,
            is_shared=False,
            is_shared_authorized=True,
        )

        assert updated.is_shared is False
        row = (await session.execute(select(Agent).where(Agent.id == agent.id))).scalar_one()
        assert row.is_shared is False

        rows = (
            await session.execute(
                select(AuditLog.agent_id, AuditLog.detail).where(
                    AuditLog.action == "agent.set_shared"
                )
            )
        ).all()
        assert len(rows) == 1
        audited_agent_id, detail = rows[0]
        assert audited_agent_id == agent.id
        assert detail == {"is_shared": False, "previous": True}

    async def test_denied_without_authorization(self, session: AsyncSession) -> None:
        agent = await _register(session, "override-unauthorized", is_shared=False)

        with pytest.raises(AccessDeniedError) as exc_info:
            await set_agent_shared(
                session,
                actor_sub="unauthorized-operator",
                agent_id=agent.id,
                is_shared=True,
                is_shared_authorized=False,
            )
        assert exc_info.value.reason == "denied.set_shared_requires_elevated_scope"

        row = (await session.execute(select(Agent).where(Agent.id == agent.id))).scalar_one()
        assert row.is_shared is False

        rows = (
            await session.execute(
                select(AuditLog.action, AuditLog.agent_id, AuditLog.detail).where(
                    AuditLog.actor_sub == "unauthorized-operator"
                )
            )
        ).all()
        assert len(rows) == 1
        action, audited_agent_id, detail = rows[0]
        assert action == "denied.set_shared_requires_elevated_scope"
        # No agent lookup happens before this denial (see the auth-ordering
        # regression test below) -- the audit row can't reference a row ID,
        # but still preserves the attempted target for operator visibility.
        assert audited_agent_id is None
        assert detail == {"target_agent_id": str(agent.id), "requested_is_shared": True}

    async def test_denied_unknown_agent(self, session: AsyncSession) -> None:
        bogus_id = uuid.uuid4()
        with pytest.raises(AccessDeniedError) as exc_info:
            await set_agent_shared(
                session,
                actor_sub="admin-operator",
                agent_id=bogus_id,
                is_shared=True,
                is_shared_authorized=True,
            )
        assert exc_info.value.reason == "denied.unknown_agent"

        rows = (
            await session.execute(
                select(AuditLog.action, AuditLog.agent_id, AuditLog.detail).where(
                    AuditLog.actor_sub == "admin-operator"
                )
            )
        ).all()
        assert len(rows) == 1
        action, audited_agent_id, detail = rows[0]
        assert action == "denied.unknown_agent"
        assert audited_agent_id is None
        assert detail == {"target_agent_id": str(bogus_id)}

    async def test_denied_without_authorization_and_unknown_agent_reports_authorization_reason(
        self, session: AsyncSession
    ) -> None:
        """Regression for the auth-check ordering: an unauthorized caller
        targeting a non-existent agent must be audited as the authorization
        failure (``denied.set_shared_requires_elevated_scope``), not
        ``denied.unknown_agent`` -- the authorization check must run before
        the existence lookup so the audit trail reflects the actual reason
        access was denied, independent of whether ``agent_id`` happens to be
        valid."""
        bogus_id = uuid.uuid4()
        with pytest.raises(AccessDeniedError) as exc_info:
            await set_agent_shared(
                session,
                actor_sub="unauthorized-operator-2",
                agent_id=bogus_id,
                is_shared=True,
                is_shared_authorized=False,
            )
        assert exc_info.value.reason == "denied.set_shared_requires_elevated_scope"

        rows = (
            await session.execute(
                select(AuditLog.action, AuditLog.agent_id, AuditLog.detail).where(
                    AuditLog.actor_sub == "unauthorized-operator-2"
                )
            )
        ).all()
        assert len(rows) == 1
        action, audited_agent_id, detail = rows[0]
        assert action == "denied.set_shared_requires_elevated_scope"
        assert audited_agent_id is None
        assert detail == {"target_agent_id": str(bogus_id), "requested_is_shared": True}

    async def test_admin_correction_takes_effect_retroactively_on_open_conversation(
        self, session: AsyncSession
    ) -> None:
        """Integration test locking in DESIGN.md's retroactive-effect claim
        for the boundary-crossing check specifically (not conversation-open
        admission or the invite gate, which this same DESIGN.md passage
        explicitly scopes the guarantee away from): a sender wrongly
        registered as ``is_shared=True`` is admitted into an asymmetric
        conversation via the shared-initiator bypass and can post
        non-``boundary_safe`` messages there. Correcting it back to
        ``False`` via ``set_agent_shared`` -- with NO change to the
        already-open conversation itself -- immediately makes the next such
        post fail the ordinary ownership-boundary check, proving
        ``_enforce_boundary_crossing`` reads the live row rather than a
        value pinned at conversation-open time."""
        wrongly_shared = await _register(
            session, "wrongly-shared-retro", owner_sub="retro-owner-a", is_shared=True
        )
        target = await _register(
            session, "retro-target", owner_sub="retro-owner-b", is_shared=False
        )
        conversation = await start_conversation(
            session,
            actor_sub=wrongly_shared.sub,
            initiator_agent_id=wrongly_shared.id,
            conversation_type="asymmetric",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )

        # Bypass still applies: is_shared is still True at this point.
        first_message = await post_message(
            session,
            actor_sub=wrongly_shared.sub,
            sender_agent_id=wrongly_shared.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "before correction"},
        )
        assert first_message.type == "note"

        await set_agent_shared(
            session,
            actor_sub="admin-operator-retro",
            agent_id=wrongly_shared.id,
            is_shared=False,
            is_shared_authorized=True,
        )

        # Same open conversation, no re-opening or re-accepting -- the
        # correction alone flips the outcome of the identical operation.
        # TECH-5389 PR2: the ordinary ownership-boundary check no longer
        # denies a genuine crossing -- it diverts to a hold instead.
        result = await post_message(
            session,
            actor_sub=wrongly_shared.sub,
            sender_agent_id=wrongly_shared.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "after correction"},
        )
        assert isinstance(result, ApprovalHold)
        assert result.status == "pending_human"
        assert result.risk_reason == "boundary_crossing"


# --- start_conversation --------------------------------------------------------


class TestStartConversation:
    async def test_happy_path(self, session: AsyncSession) -> None:
        owner = await _register(session, "owner-1")
        target = await _register(session, "target-1")

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        assert conversation.state == "active"
        assert conversation.created_by == owner.id

        owner_row = await session.get(Participant, (conversation.id, owner.id))
        target_row = await session.get(Participant, (conversation.id, target.id))
        assert owner_row is not None and owner_row.role == "owner" and owner_row.status == "active"
        assert target_row is not None and target_row.role == "member"
        assert target_row.status == "invited"
        assert target_row.joined_at is None

        messages = (
            await session.execute(
                text("SELECT seq, type FROM messages WHERE conversation_id = :cid"),
                {"cid": conversation.id},
            )
        ).all()
        assert [(m.seq, m.type) for m in messages] == [(1, "availability_request")]

    async def test_unknown_conversation_type_raises_specific_error(
        self, session: AsyncSession
    ) -> None:
        """A ``conversation_type`` outside ``schemas.CONVERSATION_TYPES``
        raises ``UnknownConversationTypeError`` (not the uniform
        ``AccessDeniedError``) naming the unsupported value and the actual
        valid set -- checked before any target/admission lookup, so this
        does not depend on or reveal anything about the named targets."""
        owner = await _register(session, "owner-unknown-type")
        target = await _register(session, "target-unknown-type")

        with pytest.raises(
            UnknownConversationTypeError, match=r"unknown conversation_type 'bogus'"
        ):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="bogus",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
            )

    async def test_unknown_target_denied(self, session: AsyncSession) -> None:
        owner = await _register(session, "owner-2")
        bogus_target_id = uuid.uuid4()

        with pytest.raises(AccessDeniedError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[bogus_target_id],
                initial_message=_request_payload(),
            )

        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.unknown_agent" in actions

    async def test_registry_retired_target_gets_specific_error(self, session: AsyncSession) -> None:
        """TECH-5703: a target that EXISTS and is board-active, but whose
        registry reports it retired, gets the specific AgentRetiredError --
        deliberately not folded into the uniform denial above."""
        owner = await _register(session, "owner-retired-target")
        target = await _register(session, "target-retired")

        with pytest.raises(AgentRetiredError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                active_checker=_FakeActiveChecker(inactive_subs={target.sub}),
            )
        assert exc_info.value.reason == "denied.target_agent_retired"

        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.target_agent_retired" in actions

    async def test_open_note_as_initial_message_diverted_to_hold(
        self, session: AsyncSession
    ) -> None:
        """TECH-5389 PR2 §6 (ratified decision 1): a high-risk seq-1 opener
        no longer denies -- the conversation is created anyway, with a
        service-synthesized ``conversation_opened`` marker as its seq-1
        message, and the real content is diverted into a hold exactly like
        any other high-risk post."""
        owner = await _register(session, "owner-open-note")
        target = await _register(session, "target-open-note")

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message={"text": "hello"},
            message_type="note",
        )
        assert conversation.state == "active"
        hold = conversation.pending_hold
        assert isinstance(hold, ApprovalHold)
        assert hold.status == "pending_human"
        assert hold.risk_reason == "boundary_crossing"
        assert hold.message_type == "note"
        assert hold.payload == {"type": "note", "text": "hello"}

        # The conversation's own seq-1 message is the synthesized marker,
        # not the held note -- the real content has no seq yet.
        rows = (
            (
                await session.execute(
                    select(Message).where(Message.conversation_id == conversation.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].seq == 1
        assert rows[0].type == "conversation_opened"
        assert rows[0].payload == {"type": "conversation_opened", "reason": "pending_approval"}

        message_post_rows = (
            (
                await session.execute(
                    select(AuditLog.detail).where(
                        AuditLog.action == "message.post",
                        AuditLog.conversation_id == conversation.id,
                    )
                )
            )
            .scalars()
            .all()
        )
        assert any(
            d.get("system_synthesized") is True and d.get("hold_id") == str(hold.id)
            for d in message_post_rows
        )
        hold_actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.conversation_id == conversation.id)
                )
            )
            .scalars()
            .all()
        )
        assert "approval.hold" in hold_actions
        assert "approval.escalate" in hold_actions
        assert "denied.boundary_crossing" not in hold_actions

    async def test_task_decline_as_initial_message_denied(self, session: AsyncSession) -> None:
        """``task_decline`` is member-role-restricted, but the initiator's
        role is always "owner" for the seq-1 message -- exactly the
        mismatch that would go uncaught if ``_require_message_sender_role``
        weren't wired into ``start_conversation``."""
        owner = await _register(session, "owner-task-decline")
        target = await _register(session, "target-task-decline")

        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message={"reason": "no_longer_needed"},
                message_type="task_decline",
            )
        assert exc_info.value.reason == "denied.wrong_sender_role"
        rows = (
            (await session.execute(select(Conversation).where(Conversation.created_by == owner.id)))
            .scalars()
            .all()
        )
        assert rows == []

    async def test_terminal_initial_message_transitions_state(self, session: AsyncSession) -> None:
        """A terminal type as the OPENING message must apply the same
        state transition post_message applies for a later message --
        otherwise the conversation is left "active" forever holding only
        a terminal message."""
        owner = await _register(session, "owner-terminal-initial")
        target = await _register(session, "target-terminal-initial")

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message={"reason": "no_longer_needed"},
            message_type="task_cancel",
        )
        assert conversation.state == "canceled"


class TestSchemaVersionNegotiation:
    """Schema-version capability negotiation at ``start_conversation``.

    Computed generically via ``min``/``max`` of the registered ranges
    rather than hardcoding ``1`` everywhere, so these assertions would
    still hold if a future agent registered e.g. ``[1, 2]``.
    """

    async def test_overlapping_ranges_negotiate_to_common_max(self, session: AsyncSession) -> None:
        owner = await _register(
            session, "owner-schema-ok", min_schema_version=1, max_schema_version=1
        )
        target = await _register(
            session, "target-schema-ok", min_schema_version=1, max_schema_version=1
        )
        expected_negotiated = min(owner.max_schema_version, target.max_schema_version)
        assert max(owner.min_schema_version, target.min_schema_version) <= expected_negotiated

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        assert conversation.state == "active"
        message = (
            await session.execute(
                text(
                    "SELECT schema_version FROM messages WHERE conversation_id = :cid AND seq = 1"
                ),
                {"cid": conversation.id},
            )
        ).scalar_one()
        assert message == expected_negotiated

    async def test_non_overlapping_ranges_refused_and_atomic(self, session: AsyncSession) -> None:
        """No version is inside both participants' ranges -- the board
        refuses to open the conversation at all, and (transactionally) no
        conversation/participant/message row is left behind."""
        owner = await _register(
            session, "owner-schema-mismatch", min_schema_version=1, max_schema_version=1
        )
        target = await _register(
            session, "target-schema-mismatch", min_schema_version=2, max_schema_version=2
        )

        with pytest.raises(SchemaVersionMismatchError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
            )

        conversation_rows = (
            (await session.execute(select(Conversation).where(Conversation.created_by == owner.id)))
            .scalars()
            .all()
        )
        assert conversation_rows == []
        message_rows = (await session.execute(text("SELECT * FROM messages"))).mappings().all()
        assert message_rows == []
        # This test asserts atomicity
        # for Participant rows too, not just Conversation/Message, matching
        # the docstring's broader "conversation/participant/message" claim
        # -- Participant rows for both the owner (role=owner) and target
        # (role=member) are exactly what start_conversation would have
        # inserted between the Conversation row and the seq-1 Message, so
        # they're the most likely place a partial-rollback bug would
        # actually surface.
        # Filtered by the two agents actually involved,
        # matching conversation_rows' defensive pattern above rather than
        # asserting on the whole table.
        participant_rows = (
            (
                await session.execute(
                    select(Participant).where(Participant.agent_id.in_([owner.id, target.id]))
                )
            )
            .scalars()
            .all()
        )
        assert participant_rows == []
        audit_rows = (
            await session.execute(
                select(AuditLog.action, AuditLog.detail).where(AuditLog.agent_id == owner.id)
            )
        ).all()
        actions = [row.action for row in audit_rows]
        # Verify the renamed audit detail keys
        # (required_min/available_max, not the old common_floor/
        # common_ceiling parameter names) actually land in the audit row,
        # not just that SOME denial happened.
        mismatch_row = next(
            row for row in audit_rows if row.action == "denied.schema_version_mismatch"
        )
        assert mismatch_row.detail is not None
        assert mismatch_row.detail["required_min"] == 2
        assert mismatch_row.detail["available_max"] == 1
        assert "denied.schema_version_mismatch" in actions

    async def test_negotiation_clamps_to_board_max(self, session: AsyncSession) -> None:
        """Two agents that both legitimately
        declare a max above what this board's own code implements must
        degrade to the board's own max, not negotiate to a version nothing
        can validate payloads against."""
        above_board_max = MAX_REGISTERED_SCHEMA_VERSION + 1
        owner = await _register(
            session,
            "owner-schema-clamp",
            min_schema_version=1,
            max_schema_version=above_board_max,
        )
        target = await _register(
            session,
            "target-schema-clamp",
            min_schema_version=1,
            max_schema_version=above_board_max,
        )
        assert min(owner.max_schema_version, target.max_schema_version) > (
            MAX_REGISTERED_SCHEMA_VERSION
        )

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        assert conversation.state == "active"
        message_schema_version = (
            await session.execute(
                text(
                    "SELECT schema_version FROM messages WHERE conversation_id = :cid AND seq = 1"
                ),
                {"cid": conversation.id},
            )
        ).scalar_one()
        assert message_schema_version == MAX_REGISTERED_SCHEMA_VERSION

    async def test_negotiation_refused_when_clamp_drops_below_required_floor(
        self, session: AsyncSession
    ) -> None:
        """Both agents requiring a version above
        the board's own max must be refused with SchemaVersionMismatchError
        -- clamping the candidate down must not let it silently satisfy a
        min-version floor the pre-clamp candidate no longer meets."""
        above_board_max = MAX_REGISTERED_SCHEMA_VERSION + 1
        owner = await _register(
            session,
            "owner-schema-clamp-refuse",
            min_schema_version=above_board_max,
            max_schema_version=above_board_max,
        )
        target = await _register(
            session,
            "target-schema-clamp-refuse",
            min_schema_version=above_board_max,
            max_schema_version=above_board_max,
        )
        with pytest.raises(SchemaVersionMismatchError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
            )


class TestInviteSchemaVersionRecheck:
    """comms_invite must re-check a new
    participant against the version this conversation was already pinned
    to, closing the gap where invite could otherwise admit an incompatible
    participant with no re-check at all."""

    async def test_invite_incompatible_target_refused(self, session: AsyncSession) -> None:
        owner = await _register(
            session, "owner-invite-schema", min_schema_version=1, max_schema_version=1
        )
        member = await _register(
            session, "member-invite-schema", min_schema_version=1, max_schema_version=1
        )
        incompatible = await _register(
            session,
            "incompatible-invite-schema",
            min_schema_version=MAX_REGISTERED_SCHEMA_VERSION + 1,
            max_schema_version=MAX_REGISTERED_SCHEMA_VERSION + 1,
        )

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[member.id],
            initial_message=_request_payload(),
        )

        with pytest.raises(SchemaVersionMismatchError):
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=incompatible.id,
            )

        participant_row = await session.get(Participant, (conversation.id, incompatible.id))
        assert participant_row is None
        audit_rows = (
            await session.execute(
                select(AuditLog.action, AuditLog.detail).where(AuditLog.agent_id == owner.id)
            )
        ).all()
        actions = [row.action for row in audit_rows]
        assert "denied.schema_version_mismatch" in actions
        # Mirror start_conversation's equivalent assertion
        # (TestSchemaVersionNegotiation) so the invite-path required_min/
        # available_max assignment is guarded against regression too, not
        # just the action string.
        mismatch_row = next(
            row for row in audit_rows if row.action == "denied.schema_version_mismatch"
        )
        assert mismatch_row.detail is not None
        assert mismatch_row.detail["required_min"] == MAX_REGISTERED_SCHEMA_VERSION + 1
        assert mismatch_row.detail["available_max"] == MAX_REGISTERED_SCHEMA_VERSION

    async def test_invite_compatible_target_succeeds(self, session: AsyncSession) -> None:
        owner = await _register(
            session, "owner-invite-schema-ok", min_schema_version=1, max_schema_version=1
        )
        member = await _register(
            session, "member-invite-schema-ok", min_schema_version=1, max_schema_version=1
        )
        compatible = await _register(
            session, "compatible-invite-schema-ok", min_schema_version=1, max_schema_version=1
        )

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[member.id],
            initial_message=_request_payload(),
        )
        participant = await invite(
            session,
            actor_sub=owner.sub,
            inviter_agent_id=owner.id,
            conversation_id=conversation.id,
            target_agent_id=compatible.id,
        )
        assert participant.status == "invited"

    async def test_invite_raises_runtime_error_if_seq_one_message_missing(
        self, session: AsyncSession
    ) -> None:
        """_conversation_pinned_schema_version's
        internal-invariant guard. This state (a conversation with no seq-1
        message) should never occur via any public code path -- reproduced
        here only by deleting the row directly -- but if it ever did,
        invite must fail with a diagnosable RuntimeError rather than an
        unmapped NoResultFound leaking out of scalar_one()."""
        owner = await _register(
            session, "owner-invite-no-seq1", min_schema_version=1, max_schema_version=1
        )
        member = await _register(
            session, "member-invite-no-seq1", min_schema_version=1, max_schema_version=1
        )
        other = await _register(
            session, "other-invite-no-seq1", min_schema_version=1, max_schema_version=1
        )

        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[member.id],
            initial_message=_request_payload(),
        )
        # audit_log.message_id FKs to messages.id -- clear the referencing
        # audit rows first, or the DELETE below violates that constraint.
        await session.execute(
            text(
                "DELETE FROM audit_log WHERE message_id IN "
                "(SELECT id FROM messages WHERE conversation_id = :cid AND seq = 1)"
            ),
            {"cid": conversation.id},
        )
        await session.execute(
            text("DELETE FROM messages WHERE conversation_id = :cid AND seq = 1"),
            {"cid": conversation.id},
        )
        await session.commit()

        with pytest.raises(RuntimeError, match="no seq-1 message"):
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=other.id,
            )


class _FakeOwnershipClient:
    """Test double for ``service.OwnershipClient`` — an in-memory owners map,
    keyed by agent id, same shape as ``tests/test_tasks.py``'s fake."""

    def __init__(self, owners_by_agent_id: dict[uuid.UUID, dict[str, Any]]) -> None:
        self._owners_by_agent_id = owners_by_agent_id

    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        if agent_id not in self._owners_by_agent_id:
            raise LookupError(f"unknown agent {agent_id}")
        return self._owners_by_agent_id[agent_id]


class _FailingOwnershipClient:
    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        raise RuntimeError("platform unreachable")


class TestConversationOwnershipAdmission:
    """N-party admission for ``internal``/``asymmetric`` conversations
    (DESIGN.md §9) — every pair must independently satisfy the type's
    predicate; ``open`` never touches the ownership client."""

    async def test_internal_identical_owner_sets_admitted(self, session: AsyncSession) -> None:
        owner = await _register(session, "int-owner-1")
        target = await _register(session, "int-target-1")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["dan"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="internal",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        assert conversation.state == "active"
        assert conversation.owner_snapshot == {"owners": ["dan"]}

    async def test_internal_different_owner_sets_denied(self, session: AsyncSession) -> None:
        owner = await _register(session, "int-owner-2")
        target = await _register(session, "int-target-2")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["priya"]},
            }
        )
        with pytest.raises(AccessDeniedError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="internal",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                ownership_client=client,
            )
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.not_same_owner" in actions

    async def test_internal_shared_initiator_does_not_bypass_owner_equality(
        self, session: AsyncSession
    ) -> None:
        """The shared-initiator bypass (DESIGN.md §9) applies only to
        ``asymmetric`` conversations. A shared initiator must NOT be able to
        open an ``internal`` conversation across disjoint owner sets --
        ``internal``'s "every participant shares one owner set by
        construction" invariant has no shared-initiator exception."""
        owner = await _register(session, "int-owner-shared")
        target = await _register(session, "int-target-disjoint")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": True, "owners": ["dan", "priya"]},
                target.id: {"is_shared": False, "owners": ["priya"]},
            }
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="internal",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.not_same_owner"

    async def test_asymmetric_intersecting_owner_sets_admitted(self, session: AsyncSession) -> None:
        owner = await _register(session, "asym-owner-1")
        target = await _register(session, "asym-target-1")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": True, "owners": ["dan", "priya"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="asymmetric",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        assert set(conversation.owner_snapshot["owners"]) == {"dan", "priya"}

    async def test_asymmetric_disjoint_owner_sets_denied(self, session: AsyncSession) -> None:
        owner = await _register(session, "asym-owner-2")
        target = await _register(session, "asym-target-2")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["priya"]},
            }
        )
        with pytest.raises(AccessDeniedError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="asymmetric",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                ownership_client=client,
            )
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.no_owner_overlap" in actions

    async def test_asymmetric_shared_initiator_bypass_is_audited(
        self, session: AsyncSession
    ) -> None:
        """A shared initiator (``is_shared=True``) opening an ``asymmetric``
        conversation with a disjoint-owner target skips the pairwise
        ownership check via ``_authorize_conversation_open``'s
        shared-initiator bypass -- and that bypass must emit an
        ``agent.conversation_open_bypassed_shared`` audit row, mirroring
        the analogous ``agent.boundary_check_bypassed_shared`` audit for
        the post-message bypass in ``_enforce_boundary_crossing``."""
        owner = await _register(session, "asym-owner-shared-bypass")
        target = await _register(session, "asym-target-disjoint-bypass")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": True, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["priya"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="asymmetric",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        assert conversation.state == "active"

        rows = (
            await session.execute(
                select(AuditLog.agent_id, AuditLog.detail).where(
                    AuditLog.action == "agent.conversation_open_bypassed_shared",
                )
            )
        ).all()
        assert len(rows) == 1
        agent_id, detail = rows[0]
        assert agent_id == owner.id
        assert detail["conversation_type"] == "asymmetric"

    async def test_asymmetric_shared_target_does_not_bypass_for_nonshared_initiator(
        self, session: AsyncSession
    ) -> None:
        """The shared-initiator bypass (DESIGN.md §9) keys off the
        INITIATOR's ``is_shared`` flag only. A shared TARGET must not grant
        the same free pass -- a non-shared initiator with disjoint owners
        from a shared target is still denied the normal pairwise way."""
        owner = await _register(session, "asym-owner-nonshared-initiator")
        target = await _register(session, "asym-target-shared-not-initiator")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": True, "owners": ["priya", "sam"]},
            }
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="asymmetric",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.no_owner_overlap"

    async def test_asymmetric_no_star_topology_exception(self, session: AsyncSession) -> None:
        """A(dan) - B(dan,priya) - C(priya): A-B and B-C each intersect, but
        A-C does not -- every PAIR must independently satisfy the
        predicate, not just a chain through an intermediary."""
        a = await _register(session, "asym-a")
        b = await _register(session, "asym-b")
        c = await _register(session, "asym-c")
        client = _FakeOwnershipClient(
            {
                a.id: {"is_shared": False, "owners": ["dan"]},
                b.id: {"is_shared": True, "owners": ["dan", "priya"]},
                c.id: {"is_shared": False, "owners": ["priya"]},
            }
        )
        with pytest.raises(AccessDeniedError):
            await start_conversation(
                session,
                actor_sub=a.sub,
                initiator_agent_id=a.id,
                conversation_type="asymmetric",
                target_agent_ids=[b.id, c.id],
                initial_message=_request_payload(),
                ownership_client=client,
            )

    async def test_open_never_touches_ownership_client(self, session: AsyncSession) -> None:
        owner = await _register(session, "open-owner-1")
        target = await _register(session, "open-target-1")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=_FailingOwnershipClient(),
        )
        assert conversation.owner_snapshot is None

    async def test_ownership_lookup_failure_fails_closed(self, session: AsyncSession) -> None:
        owner = await _register(session, "int-owner-fail")
        target = await _register(session, "int-target-fail")
        with pytest.raises(AccessDeniedError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="internal",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                ownership_client=_FailingOwnershipClient(),
            )
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.ownership_unverified" in actions

    async def test_empty_owner_set_soft_fail_denied(self, session: AsyncSession) -> None:
        """An ownership_client that soft-fails to ``{"owners": []}`` instead
        of raising must not admit two unverified agents to ``internal`` just
        because two empty sets compare equal."""
        owner = await _register(session, "int-owner-empty")
        target = await _register(session, "int-target-empty")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": []},
                target.id: {"is_shared": False, "owners": []},
            }
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="internal",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.ownership_unverified"

    async def test_asymmetric_empty_owner_set_soft_fail_denied(self, session: AsyncSession) -> None:
        """Same soft-fail posture for ``asymmetric`` -- an ownership_client
        returning ``{"owners": []}`` must not admit two unverified agents,
        regardless of whether the empty-set guard that catches it in
        practice is ``_authorize_conversation_open``'s (admission runs
        first) or ``_enforce_boundary_crossing``'s (both exist and agree)."""
        owner = await _register(session, "asym-owner-empty")
        target = await _register(session, "asym-target-empty")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": []},
                target.id: {"is_shared": False, "owners": []},
            }
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="asymmetric",
                target_agent_ids=[target.id],
                initial_message={"text": "hello"},
                message_type="note",
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.ownership_unverified"


# --- accept_invite / decline_invite -------------------------------------------


class TestAcceptDeclineInvite:
    async def _start(self, session: AsyncSession, owner_sub: str, target_sub: str) -> Any:
        owner = await _register(session, owner_sub)
        target = await _register(session, target_sub)
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        return owner, target, conversation

    async def test_accept_happy_path(self, session: AsyncSession) -> None:
        _, target, conversation = await self._start(session, "acc-owner-1", "acc-target-1")
        participant = await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        assert participant.status == "active"
        assert participant.joined_at is not None

    async def test_wrong_state_rejections_share_message_distinct_actions(
        self, session: AsyncSession
    ) -> None:
        _, target, conversation = await self._start(session, "acc-owner-2", "acc-target-2")

        # Baseline: happy-path acceptance message, for string comparison below.
        with pytest.raises(AccessDeniedError) as not_participant_exc:
            await accept_invite(
                session,
                actor_sub="ghost",
                agent_id=uuid.uuid4(),
                conversation_id=conversation.id,
            )

        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        with pytest.raises(AccessDeniedError) as already_active_exc:
            await accept_invite(
                session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
            )

        _, target2, conversation2 = await self._start(session, "acc-owner-3", "acc-target-3")
        await decline_invite(
            session,
            actor_sub=target2.sub,
            agent_id=target2.id,
            conversation_id=conversation2.id,
        )
        with pytest.raises(AccessDeniedError) as declined_exc:
            await accept_invite(
                session,
                actor_sub=target2.sub,
                agent_id=target2.id,
                conversation_id=conversation2.id,
            )

        _, target3, conversation3 = await self._start(session, "acc-owner-4", "acc-target-4")
        await accept_invite(
            session,
            actor_sub=target3.sub,
            agent_id=target3.id,
            conversation_id=conversation3.id,
        )
        await leave(
            session,
            actor_sub=target3.sub,
            agent_id=target3.id,
            conversation_id=conversation3.id,
        )
        with pytest.raises(AccessDeniedError) as left_exc:
            await accept_invite(
                session,
                actor_sub=target3.sub,
                agent_id=target3.id,
                conversation_id=conversation3.id,
            )

        messages = {
            str(not_participant_exc.value),
            str(already_active_exc.value),
            str(declined_exc.value),
            str(left_exc.value),
        }
        assert len(messages) == 1, "all four denials must share the identical uniform string"

        reasons = {
            not_participant_exc.value.reason,
            already_active_exc.value.reason,
            declined_exc.value.reason,
            left_exc.value.reason,
        }
        assert reasons == {
            "denied.not_member",
            "denied.wrong_state.active",
            "denied.wrong_state.declined",
            "denied.wrong_state.left",
        }

    async def test_decline_grants_no_access(self, session: AsyncSession) -> None:
        _, target, conversation = await self._start(session, "dec-owner-1", "dec-target-1")
        await decline_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )

        with pytest.raises(AccessDeniedError) as exc_info:
            await get_conversation(
                session,
                actor_sub=target.sub,
                caller_agent_id=target.id,
                conversation_id=conversation.id,
            )

        with pytest.raises(AccessDeniedError) as nonmember_exc:
            await get_conversation(
                session,
                actor_sub="ghost",
                caller_agent_id=uuid.uuid4(),
                conversation_id=conversation.id,
            )
        assert str(exc_info.value) == str(nonmember_exc.value)

    @pytest.mark.parametrize(
        ("message_type", "initial_message", "expected_state"),
        [
            ("task_cancel", {"reason": "no_longer_needed"}, "canceled"),
            ("task_complete", {}, "completed"),
            ("confirm", _confirm_payload(), "completed"),
        ],
    )
    async def test_accept_denied_after_terminal_opening_message(
        self,
        session: AsyncSession,
        message_type: str,
        initial_message: dict[str, Any],
        expected_state: str,
    ) -> None:
        """A target invited by a terminal-opener (task_cancel/task_complete/
        confirm) must not be able to accept into the now-completed/canceled
        conversation -- that would leave them a permanent zombie member,
        unable to post since is_message_legal requires "active"."""
        owner = await _register(session, f"acc-owner-terminal-{message_type}")
        target = await _register(session, f"acc-target-terminal-{message_type}")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=initial_message,
            message_type=message_type,
        )
        assert conversation.state == expected_state

        with pytest.raises(AccessDeniedError) as exc_info:
            await accept_invite(
                session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
            )
        assert exc_info.value.reason == f"denied.wrong_state.{expected_state}"


# --- invite --------------------------------------------------------------------


class TestInvite:
    async def _active_owner_and_conversation(
        self, session: AsyncSession, owner_sub: str, target_sub: str
    ) -> Any:
        owner = await _register(session, owner_sub)
        target = await _register(session, target_sub)
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        return owner, target, conversation

    async def test_happy_path(self, session: AsyncSession) -> None:
        owner, _target, conversation = await self._active_owner_and_conversation(
            session, "inv-owner-1", "inv-target-1"
        )
        new_agent = await _register(session, "inv-new-1")

        participant = await invite(
            session,
            actor_sub=owner.sub,
            inviter_agent_id=owner.id,
            conversation_id=conversation.id,
            target_agent_id=new_agent.id,
        )
        assert participant.status == "invited"
        assert participant.role == "member"
        assert participant.invited_by == owner.id

        row = await session.get(Participant, (conversation.id, new_agent.id))
        assert row is not None
        assert row.status == "invited"

    async def test_denied_already_participant_declined_row_not_overridable(
        self, session: AsyncSession
    ) -> None:
        """DESIGN.md §4: a declined row must never be overridable by
        another member — re-inviting a previously-declined agent is
        rejected, not silently reset to a fresh invite."""
        owner, target, conversation = await self._active_owner_and_conversation(
            session, "inv-owner-2", "inv-target-2"
        )
        await decline_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )

        with pytest.raises(AccessDeniedError) as exc_info:
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=target.id,
            )
        assert str(exc_info.value) == "access_denied: not authorized for this resource"
        assert exc_info.value.reason == "denied.already_participant"

        actions = await _audit_actions(session, conversation.id)
        assert "denied.already_participant" in actions

        # The declined row itself must be untouched by the rejected attempt.
        row = await session.get(Participant, (conversation.id, target.id))
        assert row is not None
        assert row.status == "declined"

    async def test_registry_retired_target_gets_specific_error(self, session: AsyncSession) -> None:
        """TECH-5703: same specific error as start_conversation's target
        check -- see that test's docstring."""
        owner, _target, conversation = await self._active_owner_and_conversation(
            session, "inv-owner-retired", "inv-target-retired"
        )
        new_agent = await _register(session, "inv-new-retired")

        with pytest.raises(AgentRetiredError) as exc_info:
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=new_agent.id,
                active_checker=_FakeActiveChecker(inactive_subs={new_agent.sub}),
            )
        assert exc_info.value.reason == "denied.target_agent_retired"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.target_agent_retired" in actions

    async def test_denied_unknown_agent(self, session: AsyncSession) -> None:
        owner, _target, conversation = await self._active_owner_and_conversation(
            session, "inv-owner-3", "inv-target-3"
        )
        bogus_target_id = uuid.uuid4()

        with pytest.raises(AccessDeniedError) as exc_info:
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=bogus_target_id,
            )
        assert exc_info.value.reason == "denied.unknown_agent"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.unknown_agent" in actions

    async def test_denied_bad_state_when_conversation_not_active(
        self, session: AsyncSession
    ) -> None:
        owner, _target, conversation = await self._active_owner_and_conversation(
            session, "inv-owner-5", "inv-target-5"
        )
        await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="confirm",
            payload=_confirm_payload(),
        )
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "completed"

        new_agent = await _register(session, "inv-new-5")
        with pytest.raises(InvalidConversationStateError):
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=new_agent.id,
            )
        actions = await _audit_actions(session, conversation.id)
        assert "denied.bad_state" in actions


class TestInviteOwnerFreeze:
    """An ``internal``/``asymmetric`` conversation's owner set is frozen at
    creation — an invite that would introduce an outside owner is rejected,
    not silently merged in."""

    async def test_open_conversation_skips_owner_freeze_check(self, session: AsyncSession) -> None:
        owner = await _register(session, "freeze-open-owner")
        target = await _register(session, "freeze-open-target")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        new_agent = await _register(session, "freeze-open-new")
        participant = await invite(
            session,
            actor_sub=owner.sub,
            inviter_agent_id=owner.id,
            conversation_id=conversation.id,
            target_agent_id=new_agent.id,
            ownership_client=_FailingOwnershipClient(),
        )
        assert participant.status == "invited"

    async def test_internal_invite_within_frozen_set_admitted(self, session: AsyncSession) -> None:
        owner = await _register(session, "freeze-int-owner")
        target = await _register(session, "freeze-int-target")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["dan"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="internal",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        new_agent = await _register(session, "freeze-int-new")
        client._owners_by_agent_id[new_agent.id] = {"is_shared": False, "owners": ["dan"]}
        participant = await invite(
            session,
            actor_sub=owner.sub,
            inviter_agent_id=owner.id,
            conversation_id=conversation.id,
            target_agent_id=new_agent.id,
            ownership_client=client,
        )
        assert participant.status == "invited"

    async def test_internal_invite_expanding_owner_set_denied(self, session: AsyncSession) -> None:
        owner = await _register(session, "freeze-int-owner-2")
        target = await _register(session, "freeze-int-target-2")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["dan"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="internal",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        outsider = await _register(session, "freeze-int-outsider-2")
        client._owners_by_agent_id[outsider.id] = {"is_shared": False, "owners": ["priya"]}

        with pytest.raises(AccessDeniedError) as exc_info:
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=outsider.id,
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.owner_set_frozen"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.owner_set_frozen" in actions

        # The frozen snapshot itself must be untouched by the rejected attempt.
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.owner_snapshot == {"owners": ["dan"]}

    async def test_ownership_lookup_failure_on_invite_fails_closed(
        self, session: AsyncSession
    ) -> None:
        owner = await _register(session, "freeze-fail-owner")
        target = await _register(session, "freeze-fail-target")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["dan"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="internal",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        new_agent = await _register(session, "freeze-fail-new")
        with pytest.raises(AccessDeniedError) as exc_info:
            await invite(
                session,
                actor_sub=owner.sub,
                inviter_agent_id=owner.id,
                conversation_id=conversation.id,
                target_agent_id=new_agent.id,
                ownership_client=_FailingOwnershipClient(),
            )
        assert exc_info.value.reason == "denied.ownership_unverified"


# --- get_conversation ----------------------------------------------------------


class TestGetConversation:
    async def _start(self, session: AsyncSession, owner_sub: str, target_sub: str) -> Any:
        owner = await _register(session, owner_sub)
        target = await _register(session, target_sub)
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        return owner, target, conversation

    async def test_invited_caller_gets_metadata_only(self, session: AsyncSession) -> None:
        _, target, conversation = await self._start(session, "gc-owner-1", "gc-target-1")
        result = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
        )
        assert result["invited"] is True
        # Documented shape: an empty list, never omitted, never message content.
        assert result["messages"] == []
        # has_more must be present (Argus round-1 BLOCKING catch) even on
        # this early-return path, so a caller accessing result["has_more"]
        # without first checking result["invited"] never hits a KeyError.
        assert result["has_more"] is False
        assert "conversation" in result
        assert "participants" in result
        # Argus round-3 SUGGESTION: invited_by is a documented key on this
        # path (providers/comms.py's docstring); target was named directly
        # in start_conversation's target_agent_ids, so it's the owner who
        # invited them.
        assert result["invited_by"] == str(conversation.created_by)

        row = await session.get(Participant, (conversation.id, target.id))
        assert row is not None
        assert row.last_read_seq == 0, "invited-only reads must not advance last_read_seq"

    async def test_invited_by_comms_invite_names_the_actual_inviter(
        self, session: AsyncSession
    ) -> None:
        """Argus round-4 SUGGESTION: the prior invited_by test only covered
        the start_conversation path (invited_by=the conversation's
        initiator); this covers the other documented path -- a participant
        added later via comms_invite, where invited_by is that later
        inviter, not necessarily the conversation's original owner.

        Argus round-5 SUGGESTION: the first version of this test passed
        the OWNER as the inviter, who is also conversation.created_by --
        numerically identical to the existing start_conversation-path
        test, so a bug that always returned created_by regardless of the
        actual inviter would have passed unnoticed. first_target accepts
        and does the inviting here instead, forcing the two IDs to
        diverge and actually proving invited_by reflects the real
        comms_invite caller."""
        owner, first_target, conversation = await self._start(
            session, "gc-invite-owner", "gc-invite-first-target"
        )
        await accept_invite(
            session,
            actor_sub=first_target.sub,
            agent_id=first_target.id,
            conversation_id=conversation.id,
        )
        later_target = await _register(session, "gc-invite-later-target")
        await invite(
            session,
            actor_sub=first_target.sub,
            inviter_agent_id=first_target.id,
            conversation_id=conversation.id,
            target_agent_id=later_target.id,
        )

        result = await get_conversation(
            session,
            actor_sub=later_target.sub,
            caller_agent_id=later_target.id,
            conversation_id=conversation.id,
        )
        assert result["invited"] is True
        assert result["invited_by"] == str(first_target.id)
        assert result["invited_by"] != str(conversation.created_by)
        assert conversation.created_by == owner.id

    async def test_active_caller_gets_full_history_and_advances_last_read_seq(
        self, session: AsyncSession
    ) -> None:
        _owner, target, conversation = await self._start(session, "gc-owner-2", "gc-target-2")
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        result = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
        )
        assert result["invited"] is False
        assert [m["seq"] for m in result["messages"]] == [1]
        assert result["last_read_seq"] == 1

        row = await session.get(Participant, (conversation.id, target.id))
        assert row is not None
        assert row.last_read_seq == 1

    async def test_former_member_denied_same_as_nonmember(self, session: AsyncSession) -> None:
        _owner, target, conversation = await self._start(session, "gc-owner-3", "gc-target-3")
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        await leave(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )

        with pytest.raises(AccessDeniedError) as left_exc:
            await get_conversation(
                session,
                actor_sub=target.sub,
                caller_agent_id=target.id,
                conversation_id=conversation.id,
            )
        with pytest.raises(AccessDeniedError) as nonmember_exc:
            await get_conversation(
                session,
                actor_sub="ghost",
                caller_agent_id=uuid.uuid4(),
                conversation_id=conversation.id,
            )
        assert str(left_exc.value) == str(nonmember_exc.value)

    async def test_messages_page_is_capped_with_has_more(self, session: AsyncSession) -> None:
        """TECH-5377: get_conversation previously returned every message
        since since_seq with no ceiling. Bulk-inserts Message rows directly
        (bypassing post_message's rate limits, which real traffic would
        never clear at this volume) purely to exercise the read-side cap."""
        owner, target, conversation = await self._start(session, "gc-page-owner", "gc-page-target")
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        # Conversation already has seq=1 from start_conversation; add enough
        # more that the total exceeds one page.
        extra = MAX_MESSAGES_PER_GET_CONVERSATION + 10
        session.add_all(
            Message(
                conversation_id=conversation.id,
                seq=seq,
                sender_id=owner.id,
                type="note",
                schema_version=1,
                payload={"type": "note", "text": "x"},
            )
            for seq in range(2, extra + 2)
        )
        await session.commit()

        result = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
        )
        assert len(result["messages"]) == MAX_MESSAGES_PER_GET_CONVERSATION
        assert result["messages_in_page"] == MAX_MESSAGES_PER_GET_CONVERSATION
        assert result["has_more"] is True
        assert result["messages"][-1]["seq"] == MAX_MESSAGES_PER_GET_CONVERSATION
        assert result["page_max_seq"] == MAX_MESSAGES_PER_GET_CONVERSATION
        # last_read_seq only advances to what was actually returned in THIS
        # page, never to a later seq that exists but wasn't sent back.
        assert result["last_read_seq"] == MAX_MESSAGES_PER_GET_CONVERSATION

        row = await session.get(Participant, (conversation.id, target.id))
        assert row is not None
        assert row.last_read_seq == MAX_MESSAGES_PER_GET_CONVERSATION

        # Continuation uses page_max_seq, not last_read_seq (Argus round-1
        # BLOCKING catch -- see test below for the case where those two
        # values actually diverge).
        next_page = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
            since_seq=result["page_max_seq"],
        )
        assert next_page["has_more"] is False
        # Total messages = seq 1 (from start_conversation) + `extra` more.
        assert len(next_page["messages"]) == 1 + extra - MAX_MESSAGES_PER_GET_CONVERSATION
        assert next_page["messages"][0]["seq"] == MAX_MESSAGES_PER_GET_CONVERSATION + 1

    async def test_backfill_re_read_does_not_skip_messages(self, session: AsyncSession) -> None:
        """Argus round-1 BLOCKING catch: a caller with a persisted
        last_read_seq ahead of a page it just re-read (a deliberate
        since_seq below its own cursor) must continue from THIS page's own
        max seq, not the unrelated, already-larger persisted cursor --
        continuing from the cursor would silently skip every message
        between the page's actual end and that cursor."""
        owner, target, conversation = await self._start(
            session, "gc-backfill-owner", "gc-backfill-target"
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        total = MAX_MESSAGES_PER_GET_CONVERSATION + 100
        session.add_all(
            Message(
                conversation_id=conversation.id,
                seq=seq,
                sender_id=owner.id,
                type="note",
                schema_version=1,
                payload={"type": "note", "text": "x"},
            )
            for seq in range(2, total + 1)
        )
        await session.commit()

        # Advance the persisted cursor to the very end by reading forward
        # normally first.
        caught_up = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
            since_seq=total - 1,
        )
        assert caught_up["last_read_seq"] == total

        # Now re-read from the very beginning (since_seq=0) -- a legitimate
        # history re-read below the persisted cursor. The page is capped
        # well short of that cursor.
        reread = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
            since_seq=0,
        )
        assert reread["page_max_seq"] == MAX_MESSAGES_PER_GET_CONVERSATION
        # last_read_seq never regresses -- still reports the prior cursor.
        assert reread["last_read_seq"] == total
        assert reread["has_more"] is True

        # Continuing with page_max_seq (not last_read_seq) picks up exactly
        # where this re-read page left off, with no gap.
        continued = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
            since_seq=reread["page_max_seq"],
        )
        assert continued["messages"][0]["seq"] == MAX_MESSAGES_PER_GET_CONVERSATION + 1

    async def test_empty_page_past_the_cursor_does_not_advance_last_read_seq(
        self, session: AsyncSession
    ) -> None:
        """Argus round-2 BLOCKING catch: page_max_seq defaults to since_seq
        on an EMPTY page. If a caller passes since_seq ahead of its own
        persisted cursor with no new messages actually returned, that
        default must NOT drive the last_read_seq write -- otherwise it
        would permanently hide any messages between the persisted cursor
        and the passed-in since_seq from this caller's inbox (`HAVING
        max(seq) > last_read_seq`)."""
        _owner, target, conversation = await self._start(
            session, "gc-empty-page-owner", "gc-empty-page-target"
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        # Only seq=1 exists (from start_conversation). last_read_seq is 0.
        result = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
            # Ahead of the persisted cursor (0) AND ahead of the only real
            # message (seq=1) -- the query returns zero rows.
            since_seq=10,
        )
        assert result["messages"] == []
        assert result["page_max_seq"] == 10  # the no-op-safe response value
        # The DB write must NOT have advanced to 10 -- seq=1 was never
        # actually delivered to this caller.
        assert result["last_read_seq"] == 0

        row = await session.get(Participant, (conversation.id, target.id))
        assert row is not None
        assert row.last_read_seq == 0

        # The real message (seq=1) is still visible on a normal read.
        follow_up = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
            since_seq=0,
        )
        assert [m["seq"] for m in follow_up["messages"]] == [1]


# --- post_message --------------------------------------------------------------


class TestPostMessage:
    async def _active_pair(self, session: AsyncSession, owner_sub: str, target_sub: str) -> Any:
        owner = await _register(session, owner_sub)
        target = await _register(session, target_sub)
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        return owner, target, conversation

    async def test_non_member_denied(self, session: AsyncSession) -> None:
        _owner, _target, conversation = await self._active_pair(
            session, "pm-owner-1", "pm-target-1"
        )
        outsider = await _register(session, "pm-outsider-1")
        with pytest.raises(AccessDeniedError):
            await post_message(
                session,
                actor_sub=outsider.sub,
                sender_agent_id=outsider.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )

    async def test_invited_not_accepted_denied_same_message_as_non_member(
        self, session: AsyncSession
    ) -> None:
        owner = await _register(session, "pm-owner-2")
        target = await _register(session, "pm-target-2")
        outsider = await _register(session, "pm-outsider-2")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )

        with pytest.raises(AccessDeniedError) as invited_exc:
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        with pytest.raises(AccessDeniedError) as outsider_exc:
            await post_message(
                session,
                actor_sub=outsider.sub,
                sender_agent_id=outsider.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        assert str(invited_exc.value) == str(outsider_exc.value)

    async def test_state_machine_violation_after_completion(self, session: AsyncSession) -> None:
        owner, target, conversation = await self._active_pair(session, "pm-owner-3", "pm-target-3")
        await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="confirm",
            payload=_confirm_payload(),
        )
        with pytest.raises(InvalidConversationStateError):
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )

    async def test_confirm_transitions_to_completed(self, session: AsyncSession) -> None:
        owner, _target, conversation = await self._active_pair(session, "pm-owner-4", "pm-target-4")
        message = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="confirm",
            payload=_confirm_payload(),
        )
        assert message.type == "confirm"
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "completed"

    async def test_decline_cascades_when_all_non_owners_decline(
        self, session: AsyncSession
    ) -> None:
        owner = await _register(session, "pm-owner-5")
        member_a = await _register(session, "pm-member-5a")
        member_b = await _register(session, "pm-member-5b")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[member_a.id, member_b.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=member_a.sub, agent_id=member_a.id, conversation_id=conversation.id
        )
        await accept_invite(
            session, actor_sub=member_b.sub, agent_id=member_b.id, conversation_id=conversation.id
        )

        await post_message(
            session,
            actor_sub=member_a.sub,
            sender_agent_id=member_a.id,
            conversation_id=conversation.id,
            message_type="decline",
            payload=_decline_payload(),
        )
        mid = await session.get(type(conversation), conversation.id)
        assert mid is not None
        assert mid.state == "active", "one of two non-owners declining must NOT cascade"

        await post_message(
            session,
            actor_sub=member_b.sub,
            sender_agent_id=member_b.id,
            conversation_id=conversation.id,
            message_type="decline",
            payload=_decline_payload(),
        )
        final = await session.get(type(conversation), conversation.id)
        assert final is not None
        assert final.state == "canceled", "all non-owners declining must cascade to canceled"

    async def test_needs_clarification_out_of_range_about_seq_denied(
        self, session: AsyncSession
    ) -> None:
        """``about_seq`` must reference a prior message in the SAME
        conversation — an ``about_seq`` >= the next seq to be assigned
        (i.e. not yet posted) fails the referential check in the service
        layer (schemas.py only enforces ``>= 1``)."""
        owner, target, conversation = await self._active_pair(session, "nc-owner-1", "nc-target-1")
        # Only seq 1 (the initial availability_request) exists so far —
        # the next message to be posted would be seq 2, so about_seq=2 is
        # out of range (references a message that doesn't exist yet).
        with pytest.raises(PayloadValidationError) as exc_info:
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="needs_clarification",
                payload=_needs_clarification_payload(about_seq=2),
            )
        assert "does not reference a prior message in this conversation" in str(exc_info.value)

        actions = await _audit_actions(session, conversation.id)
        assert "denied.bad_schema" in actions

        # about_seq=1 (the actual prior message) is accepted.
        message = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="needs_clarification",
            payload=_needs_clarification_payload(about_seq=1),
        )
        assert message.seq == 2
        assert message.payload["about_seq"] == 1

    async def test_payload_exceeding_max_bytes_denied(self, session: AsyncSession) -> None:
        """A payload whose JSON encoding exceeds ``schemas.MAX_PAYLOAD_BYTES``
        (65536) is rejected with ``PayloadValidationError`` before schema
        validation even runs — ``_check_payload_size`` is the first check
        ``validate_payload`` performs."""
        owner, target, conversation = await self._active_pair(session, "sz-owner-1", "sz-target-1")
        oversized_payload = {"reason": "owner_declined", "padding": "x" * (MAX_PAYLOAD_BYTES + 100)}

        with pytest.raises(PayloadValidationError) as exc_info:
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="decline",
                payload=oversized_payload,
            )
        assert "exceeding the 65536-byte cap" in str(exc_info.value)

        actions = await _audit_actions(session, conversation.id)
        assert "denied.bad_schema" in actions

        # A conforming payload well under the cap still succeeds.
        message = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="decline",
            payload=_decline_payload(),
        )
        assert message.type == "decline"


class TestPostMessageBoundaryCrossing:
    """DESIGN.md §9 Axis 2: ``asymmetric`` conversations reject a
    non-``boundary_safe`` message (``note``) that would cross an ownership
    boundary for the sender; ``open``/``internal`` are decided without any
    ownership lookup at all."""

    async def _asymmetric_pair(
        self, session: AsyncSession, owner_owners: list[str], target_owners: list[str]
    ) -> Any:
        owner = await _register(session, f"bc-owner-{'-'.join(owner_owners)}")
        target = await _register(session, f"bc-target-{'-'.join(target_owners)}")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": len(owner_owners) > 1, "owners": owner_owners},
                target.id: {"is_shared": len(target_owners) > 1, "owners": target_owners},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="asymmetric",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        return owner, target, conversation, client

    async def test_note_from_single_owner_to_shared_crosses_diverted_to_hold(
        self, session: AsyncSession
    ) -> None:
        owner, _target, conversation, client = await self._asymmetric_pair(
            session, ["dan"], ["dan", "priya"]
        )
        result = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "hello"},
            ownership_client=client,
        )
        assert isinstance(result, ApprovalHold)
        assert result.status == "pending_human"
        assert result.risk_reason == "boundary_crossing"
        assert result.sender_agent_id == owner.id
        assert result.conversation_id == conversation.id
        # No messages row exists for the held content -- it has no seq.
        msg_rows = (
            (
                await session.execute(
                    select(Message).where(Message.conversation_id == conversation.id)
                )
            )
            .scalars()
            .all()
        )
        assert all(m.type != "note" for m in msg_rows)
        actions = await _audit_actions(session, conversation.id)
        assert "approval.hold" in actions
        assert "approval.escalate" in actions
        assert "denied.boundary_crossing" not in actions

    async def test_second_lookup_failure_denied(self, session: AsyncSession) -> None:
        """The sender's own ownership lookup succeeds, but a later
        participant's lookup raises -- this exercises
        ``_enforce_boundary_crossing``'s SECOND ``except`` block (the loop
        over ``other_agent_ids``), distinct from the sender-lookup failure
        covered by ``test_note_from_single_owner_to_shared_crosses_denied``
        and friends. This except
        block must reset ``sender_owners`` back to empty before denying, or
        a `_deny` that failed to raise would fall through to
        ``is_boundary_crossing_safe`` with a non-empty ``sender_owners``
        and an empty ``other_owners`` -- and an empty set is a subset of
        any set, so the crossing would be silently admitted."""
        owner, _target, conversation, _client = await self._asymmetric_pair(
            session, ["dan"], ["dan", "priya"]
        )
        sender_only_client = _FakeOwnershipClient(
            {owner.id: {"is_shared": False, "owners": ["dan"]}}
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
                ownership_client=sender_only_client,
            )
        assert exc_info.value.reason == "denied.risk_unscored"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.risk_unscored" in actions

    async def test_empty_owner_set_soft_fail_denied(self, session: AsyncSession) -> None:
        """A post-admission ownership_client that soft-fails to
        ``{"owners": []}`` (rather than raising) must not let
        ``frozenset() <= frozenset()`` silently pass the boundary check."""
        owner, target, conversation, _client = await self._asymmetric_pair(
            session, ["dan"], ["dan", "priya"]
        )
        soft_failing_client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": []},
                target.id: {"is_shared": False, "owners": []},
            }
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
                ownership_client=soft_failing_client,
            )
        assert exc_info.value.reason == "denied.risk_unscored"

    async def test_note_from_shared_to_single_owner_does_not_cross(
        self, session: AsyncSession
    ) -> None:
        owner, _target, conversation, client = await self._asymmetric_pair(
            session, ["dan", "priya"], ["priya"]
        )
        message = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "hello"},
            ownership_client=client,
        )
        assert message.type == "note"

    async def test_boundary_safe_message_never_checked_against_ownership(
        self, session: AsyncSession
    ) -> None:
        # dan/{dan,priya} intersect (so admission succeeds) but a note
        # from dan would cross (priya is outside dan's set) -- proving
        # boundary_safe=True (counter_proposal) skips the crossing check
        # entirely rather than happening to pass it.
        owner, _target, conversation, _client = await self._asymmetric_pair(
            session, ["dan"], ["dan", "priya"]
        )
        message = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="counter_proposal",
            payload=_counter_proposal_payload(),
            ownership_client=_FailingOwnershipClient(),
        )
        assert message.type == "counter_proposal"

    async def test_open_note_diverted_to_hold_unconditionally(self, session: AsyncSession) -> None:
        owner, _target, conversation = await self._active_pair_open(
            session, "bc-open-owner", "bc-open-target"
        )
        result = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "hello"},
            # No ownership lookup for `open` -- a raising client here would
            # never actually be invoked (proving that), so this test would
            # pass for the wrong reason if the diversion changed that.
            ownership_client=_FailingOwnershipClient(),
        )
        assert isinstance(result, ApprovalHold)
        assert result.status == "pending_human"
        assert result.risk_reason == "boundary_crossing"

    async def _active_pair_open(
        self, session: AsyncSession, owner_sub: str, target_sub: str
    ) -> Any:
        owner = await _register(session, owner_sub)
        target = await _register(session, target_sub)
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        return owner, target, conversation

    async def test_internal_note_never_checked_against_ownership(
        self, session: AsyncSession
    ) -> None:
        owner = await _register(session, "bc-int-owner")
        target = await _register(session, "bc-int-target")
        client = _FakeOwnershipClient(
            {
                owner.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": False, "owners": ["dan"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="internal",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        message = await post_message(
            session,
            actor_sub=owner.sub,
            sender_agent_id=owner.id,
            conversation_id=conversation.id,
            message_type="note",
            payload={"text": "hello"},
            ownership_client=_FailingOwnershipClient(),
        )
        assert message.type == "note"

    async def test_unrecognized_conversation_type_denied_with_own_audit_action(
        self, session: AsyncSession
    ) -> None:
        """A row with a conversation_type this process doesn't recognize
        (e.g. a legacy pre-rename row the backfill migration missed) must
        hard-deny via denied.risk_unscored (detail.cause=
        unknown_conversation_type), never divert to a hold -- an unscorable
        message must not flood the human approval queue -- and even a
        boundary-safe message is denied, since the scorer's default-deny
        path for unknown types doesn't special-case it."""
        owner = await _register(session, "bc-legacy-owner")
        target = await _register(session, "bc-legacy-target")
        conversation = Conversation(
            type="scheduling.availability",
            state="active",
            created_by=owner.id,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        session.add(conversation)
        await session.flush()
        session.add(
            Participant(
                conversation_id=conversation.id,
                agent_id=owner.id,
                role="owner",
                status="active",
                joined_at=datetime.now(UTC),
            )
        )
        session.add(
            Participant(
                conversation_id=conversation.id,
                agent_id=target.id,
                role="member",
                status="active",
                joined_at=datetime.now(UTC),
            )
        )
        await session.commit()

        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
                # A no-op client, not _FailingOwnershipClient: the
                # unrecognized-type check short-circuits before any lookup
                # is attempted (the lookup is gated on conversation_type
                # == "asymmetric"), so a raising client here would never
                # actually be invoked and this test would pass for the
                # wrong reason.
                ownership_client=_FakeOwnershipClient({}),
            )
        assert exc_info.value.reason == "denied.risk_unscored"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.risk_unscored" in actions
        assert "denied.boundary_crossing" not in actions
        assert "approval.hold" not in actions

    async def test_asymmetric_ownership_lookup_failure_fails_closed(
        self, session: AsyncSession
    ) -> None:
        """The genuine exception path (not the soft-fail-to-empty-set one
        covered elsewhere): a raising ownership_client on an asymmetric
        conversation's non-boundary_safe message hard-denies with
        denied.risk_unscored (an unscorable message never diverts to a
        hold -- only a GENUINE crossing verdict does)."""
        owner, _target, conversation, _client = await self._asymmetric_pair(
            session, ["dan"], ["dan", "priya"]
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
                ownership_client=_FailingOwnershipClient(),
            )
        assert exc_info.value.reason == "denied.risk_unscored"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.risk_unscored" in actions
        assert "denied.boundary_crossing" not in actions
        assert "approval.hold" not in actions


class TestMessageTypeAcceptedCapability:
    """accepted_types is a capability gate, not a trust boundary (DESIGN.md
    §9's Capability gate section): applies universally, including to
    ``internal`` same-owner traffic that the boundary-crossing check itself
    always allows."""

    async def test_start_conversation_denied_when_target_has_not_declared_type(
        self, session: AsyncSession
    ) -> None:
        initiator = await _register(session, "cap-start-initiator")
        target = await _register(session, "cap-start-target", accepted_types=["confirm"])
        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=initiator.sub,
                initiator_agent_id=initiator.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                message_type="availability_request",
            )
        assert exc_info.value.reason == "denied.message_type_not_accepted"
        # No conversation row exists on this denial path (checked before
        # session.add(conversation)), so _audit_actions' conversation_id
        # filter can't be reused here -- query by agent_id instead.
        actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.agent_id == initiator.id)
                )
            )
            .scalars()
            .all()
        )
        assert "denied.message_type_not_accepted" in actions

    async def test_start_conversation_allowed_when_target_declared_type(
        self, session: AsyncSession
    ) -> None:
        initiator = await _register(session, "cap-start-ok-initiator")
        target = await _register(
            session, "cap-start-ok-target", accepted_types=["availability_request"]
        )
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            message_type="availability_request",
        )
        assert conversation.type == "open"

    async def test_post_message_denied_when_recipient_has_not_declared_type(
        self, session: AsyncSession
    ) -> None:
        # initiator's accepted_types is deliberately narrow -- it's the
        # RECIPIENT of the counter_proposal posted below, not the sender of
        # it, so its declared set is what's actually under test here.
        initiator = await _register(
            session, "cap-post-initiator", accepted_types=["availability_request"]
        )
        other = await _register(session, "cap-post-other")
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[other.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=other.sub, agent_id=other.id, conversation_id=conversation.id
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=other.sub,
                sender_agent_id=other.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        assert exc_info.value.reason == "denied.message_type_not_accepted"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.message_type_not_accepted" in actions

    async def test_post_message_applies_even_within_internal_conversation(
        self, session: AsyncSession
    ) -> None:
        """The one case that distinguishes this from boundary_safe's own
        crossing check: internal (identical owner sets) is unconditionally
        legal for boundary-crossing purposes, but must still be denied here
        -- a missing handler is a missing handler regardless of ownership."""
        owner_sub = "cap-internal-shared-owner"
        # initiator's narrow accepted_types is what's under test -- it's
        # the RECIPIENT of the note posted below.
        initiator = await _register(
            session,
            "cap-internal-initiator",
            owner_sub=owner_sub,
            accepted_types=["availability_request"],
        )
        other = await _register(session, "cap-internal-other", owner_sub=owner_sub)
        client = _FakeOwnershipClient(
            {
                initiator.id: {"is_shared": False, "owners": [owner_sub]},
                other.id: {"is_shared": False, "owners": [owner_sub]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="internal",
            target_agent_ids=[other.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        await accept_invite(
            session, actor_sub=other.sub, agent_id=other.id, conversation_id=conversation.id
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=other.sub,
                sender_agent_id=other.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.message_type_not_accepted"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.message_type_not_accepted" in actions

    async def test_senders_own_accepted_types_is_not_consulted(self, session: AsyncSession) -> None:
        """Only the RECIPIENT's accepted_types gates a send -- a sender
        with a narrow declaration that doesn't include the type it's
        sending must not be denied for its own lack of a declaration."""
        initiator = await _register(session, "cap-sender-invariant-initiator")
        # "confirm" deliberately absent -- other is about to SEND that type,
        # and a sender's own accepted_types must not gate its own sends.
        # "availability_request" is present so other can still receive the
        # conversation-opening message below.
        other = await _register(
            session, "cap-sender-invariant-other", accepted_types=["availability_request"]
        )
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[other.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=other.sub, agent_id=other.id, conversation_id=conversation.id
        )
        # other's own accepted_types does NOT include "confirm" -- but it's
        # sending, not receiving, this message. initiator's broad default
        # accepts it; other's own declaration is irrelevant to a message
        # IT sends, only to messages sent TO it.
        message = await post_message(
            session,
            actor_sub=other.sub,
            sender_agent_id=other.id,
            conversation_id=conversation.id,
            message_type="confirm",
            payload=_confirm_payload(),
        )
        assert message.type == "confirm"

    async def test_multi_target_denied_when_any_target_has_not_declared_type(
        self, session: AsyncSession
    ) -> None:
        """One non-accepting target among several is enough to deny the
        whole send -- not an any-accepts-it-passes aggregation."""
        initiator = await _register(session, "cap-multi-initiator")
        accepting = await _register(
            session, "cap-multi-accepting", accepted_types=["availability_request"]
        )
        non_accepting = await _register(
            session, "cap-multi-non-accepting", accepted_types=["confirm"]
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=initiator.sub,
                initiator_agent_id=initiator.id,
                conversation_type="open",
                target_agent_ids=[accepting.id, non_accepting.id],
                initial_message=_request_payload(),
                message_type="availability_request",
            )
        assert exc_info.value.reason == "denied.message_type_not_accepted"

    async def test_invite_does_not_retroactively_block_existing_members(
        self, session: AsyncSession
    ) -> None:
        """Regression: inviting a narrow-capability agent into an ongoing
        conversation must not block the already-ACTIVE members from
        continuing to exchange types the new invitee simply hasn't
        accepted (and hasn't been asked to accept) yet -- the capability
        gate only applies to a participant once they're active themselves."""
        initiator = await _register(session, "cap-invite-initiator")
        member = await _register(session, "cap-invite-member")
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[member.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=member.sub, agent_id=member.id, conversation_id=conversation.id
        )
        narrow_invitee = await _register(
            session, "cap-invite-narrow-invitee", accepted_types=["confirm"]
        )
        await invite(
            session,
            actor_sub=member.sub,
            inviter_agent_id=member.id,
            conversation_id=conversation.id,
            target_agent_id=narrow_invitee.id,
        )
        # member and initiator keep exchanging counter_proposal (neither
        # declares "confirm" as their ONLY type -- both have the
        # permissive default) even though narrow_invitee, still merely
        # invited, hasn't declared support for it.
        message = await post_message(
            session,
            actor_sub=member.sub,
            sender_agent_id=member.id,
            conversation_id=conversation.id,
            message_type="counter_proposal",
            payload=_counter_proposal_payload(),
        )
        assert message.type == "counter_proposal"

    async def test_capability_gate_applies_once_invitee_accepts(
        self, session: AsyncSession
    ) -> None:
        """The other half of the invite-poisoning fix: excluding invited
        participants only DEFERS the check, it doesn't skip it forever --
        once narrow_invitee accepts and becomes active, an existing
        member's send of a type narrow_invitee doesn't accept IS denied."""
        initiator = await _register(session, "cap-post-accept-initiator")
        member = await _register(session, "cap-post-accept-member")
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[member.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=member.sub, agent_id=member.id, conversation_id=conversation.id
        )
        narrow_invitee = await _register(
            session, "cap-post-accept-narrow-invitee", accepted_types=["confirm"]
        )
        await invite(
            session,
            actor_sub=member.sub,
            inviter_agent_id=member.id,
            conversation_id=conversation.id,
            target_agent_id=narrow_invitee.id,
        )
        await accept_invite(
            session,
            actor_sub=narrow_invitee.sub,
            agent_id=narrow_invitee.id,
            conversation_id=conversation.id,
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=member.sub,
                sender_agent_id=member.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        assert exc_info.value.reason == "denied.message_type_not_accepted"

    async def test_pre_accept_bypass_is_a_deliberate_asymmetry_not_a_general_hole(
        self, session: AsyncSession
    ) -> None:
        """Pins the intentional scope of the invite-poisoning fix: the
        capability gate is a no-op ONLY because the sole other participant
        is still merely invited (never yet active) -- this is not a
        general "capability gate doesn't apply pre-accept" rule that would
        also cover an ALREADY-active member sending to the SAME
        conversation; it's specific to accepted_types not yet being
        something the not-yet-active party has actually agreed to be
        checked against."""
        initiator = await _register(session, "cap-preaccept-initiator")
        narrow_target = await _register(
            session, "cap-preaccept-narrow-target", accepted_types=["availability_request"]
        )
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[narrow_target.id],
            initial_message=_request_payload(),
        )
        # narrow_target is still merely "invited" -- capability_others is
        # empty, so this send is NOT gated by narrow_target's declared
        # types at all, even though counter_proposal isn't among them.
        message = await post_message(
            session,
            actor_sub=initiator.sub,
            sender_agent_id=initiator.id,
            conversation_id=conversation.id,
            message_type="counter_proposal",
            payload=_counter_proposal_payload(),
        )
        assert message.type == "counter_proposal"

    async def test_post_message_allowed_when_recipient_declared_type(
        self, session: AsyncSession
    ) -> None:
        initiator = await _register(
            session,
            "cap-post-ok-initiator",
            accepted_types=["availability_request", "counter_proposal"],
        )
        other = await _register(session, "cap-post-ok-other")
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[other.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=other.sub, agent_id=other.id, conversation_id=conversation.id
        )
        message = await post_message(
            session,
            actor_sub=other.sub,
            sender_agent_id=other.id,
            conversation_id=conversation.id,
            message_type="counter_proposal",
            payload=_counter_proposal_payload(),
        )
        assert message.type == "counter_proposal"

    async def test_lifecycle_coherence_is_not_validated_a_narrow_agent_can_strand_a_conversation(
        self, session: AsyncSession
    ) -> None:
        """Pins a documented (DESIGN.md §9 "Known consequence") design
        gap, not a bug: nothing validates that a participant's
        accepted_types includes any lifecycle/consent type, so an agent
        registered with only "availability_request" can become active and
        then have every confirm/decline sent to it denied -- the
        conversation can never legally resolve via those types. Callers
        are responsible for choosing lifecycle-coherent declared sets."""
        initiator = await _register(session, "cap-strand-initiator")
        narrow = await _register(
            session, "cap-strand-narrow", accepted_types=["availability_request"]
        )
        conversation = await start_conversation(
            session,
            actor_sub=initiator.sub,
            initiator_agent_id=initiator.id,
            conversation_type="open",
            target_agent_ids=[narrow.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=narrow.sub, agent_id=narrow.id, conversation_id=conversation.id
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=initiator.sub,
                sender_agent_id=initiator.id,
                conversation_id=conversation.id,
                message_type="confirm",
                payload=_confirm_payload(),
            )
        assert exc_info.value.reason == "denied.message_type_not_accepted"


class TestTaskLifecycleMessages:
    """ "tasks-as-conversations": task_assign opens a conversation (assigner
    = owner participant, assignee = member participant); task_report is
    non-terminal; task_complete/task_decline/task_cancel are terminal and
    sender-role-restricted."""

    def _task_assign_payload(self, **overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {"action": "report_status"}
        payload.update(overrides)
        return payload

    async def _assigned_task(
        self, session: AsyncSession, assigner_sub: str, assignee_sub: str
    ) -> Any:
        assigner = await _register(session, assigner_sub)
        assignee = await _register(session, assignee_sub)
        client = _FakeOwnershipClient(
            {
                assigner.id: {"is_shared": False, "owners": ["dan"]},
                assignee.id: {"is_shared": False, "owners": ["dan"]},
            }
        )
        conversation = await start_conversation(
            session,
            actor_sub=assigner.sub,
            initiator_agent_id=assigner.id,
            conversation_type="internal",
            target_agent_ids=[assignee.id],
            initial_message=self._task_assign_payload(),
            message_type="task_assign",
            ownership_client=client,
        )
        await accept_invite(
            session, actor_sub=assignee.sub, agent_id=assignee.id, conversation_id=conversation.id
        )
        return assigner, assignee, conversation, client

    async def test_task_assign_opens_conversation(self, session: AsyncSession) -> None:
        assigner, assignee, conversation, _client = await self._assigned_task(
            session, "task-assigner-1", "task-assignee-1"
        )
        assert conversation.type == "internal"
        assert conversation.state == "active"
        owner_row = await session.get(Participant, (conversation.id, assigner.id))
        member_row = await session.get(Participant, (conversation.id, assignee.id))
        assert owner_row is not None and owner_row.role == "owner"
        assert member_row is not None and member_row.role == "member"

    async def test_task_report_is_non_terminal(self, session: AsyncSession) -> None:
        _assigner, assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-2", "task-assignee-2"
        )
        message = await post_message(
            session,
            actor_sub=assignee.sub,
            sender_agent_id=assignee.id,
            conversation_id=conversation.id,
            message_type="task_report",
            payload={"status": "in_progress"},
            ownership_client=client,
        )
        assert message.type == "task_report"
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "active"

    async def test_task_complete_from_either_party_completes(self, session: AsyncSession) -> None:
        assigner, _assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-3", "task-assignee-3"
        )
        await post_message(
            session,
            actor_sub=assigner.sub,
            sender_agent_id=assigner.id,
            conversation_id=conversation.id,
            message_type="task_complete",
            payload={},
            ownership_client=client,
        )
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "completed"

    async def test_task_decline_from_assignee_cancels(self, session: AsyncSession) -> None:
        _assigner, assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-4", "task-assignee-4"
        )
        await post_message(
            session,
            actor_sub=assignee.sub,
            sender_agent_id=assignee.id,
            conversation_id=conversation.id,
            message_type="task_decline",
            payload={"reason": "unable_to_complete"},
            ownership_client=client,
        )
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "canceled"

    async def test_task_decline_from_assigner_denied(self, session: AsyncSession) -> None:
        assigner, _assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-5", "task-assignee-5"
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=assigner.sub,
                sender_agent_id=assigner.id,
                conversation_id=conversation.id,
                message_type="task_decline",
                payload={"reason": "unable_to_complete"},
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.wrong_sender_role"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.wrong_sender_role" in actions
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "active"

    async def test_task_cancel_from_assigner_cancels(self, session: AsyncSession) -> None:
        assigner, _assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-6", "task-assignee-6"
        )
        await post_message(
            session,
            actor_sub=assigner.sub,
            sender_agent_id=assigner.id,
            conversation_id=conversation.id,
            message_type="task_cancel",
            payload={"reason": "no_longer_needed"},
            ownership_client=client,
        )
        refreshed = await session.get(type(conversation), conversation.id)
        assert refreshed is not None
        assert refreshed.state == "canceled"

    async def test_task_cancel_from_assignee_denied(self, session: AsyncSession) -> None:
        _assigner, assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-7", "task-assignee-7"
        )
        with pytest.raises(AccessDeniedError) as exc_info:
            await post_message(
                session,
                actor_sub=assignee.sub,
                sender_agent_id=assignee.id,
                conversation_id=conversation.id,
                message_type="task_cancel",
                payload={"reason": "no_longer_needed"},
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.wrong_sender_role"

    async def test_no_transition_out_of_completed(self, session: AsyncSession) -> None:
        assigner, _assignee, conversation, client = await self._assigned_task(
            session, "task-assigner-8", "task-assignee-8"
        )
        await post_message(
            session,
            actor_sub=assigner.sub,
            sender_agent_id=assigner.id,
            conversation_id=conversation.id,
            message_type="task_complete",
            payload={},
            ownership_client=client,
        )
        with pytest.raises(InvalidConversationStateError):
            await post_message(
                session,
                actor_sub=assigner.sub,
                sender_agent_id=assigner.id,
                conversation_id=conversation.id,
                message_type="task_cancel",
                payload={"reason": "no_longer_needed"},
                ownership_client=client,
            )


# --- seq race-safety -----------------------------------------------------------


class TestSeqRaceSafety:
    async def test_concurrent_posts_get_distinct_contiguous_seqs(
        self, session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        owner = await _register(session, "race-owner-1")
        members = [await _register(session, f"race-member-{i}") for i in range(4)]
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[m.id for m in members],
            initial_message=_request_payload(),
        )
        for member in members:
            await accept_invite(
                session, actor_sub=member.sub, agent_id=member.id, conversation_id=conversation.id
            )

        async def _post(member: Agent) -> int:
            async with session_factory() as sess:
                message = await post_message(
                    sess,
                    actor_sub=member.sub,
                    sender_agent_id=member.id,
                    conversation_id=conversation.id,
                    message_type="counter_proposal",
                    payload=_counter_proposal_payload(),
                )
                return int(message.seq)

        seqs = await asyncio.gather(*[_post(member) for member in members])
        assert sorted(seqs) == [2, 3, 4, 5]
        assert len(set(seqs)) == len(seqs)


# --- rate limits -----------------------------------------------------------------


class TestRateLimits:
    async def test_message_rate_limit(self, session: AsyncSession) -> None:
        owner = await _register(session, "rl-owner-1")
        target = await _register(session, "rl-target-1")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        for _ in range(MAX_MESSAGES_PER_CONVERSATION_PER_HOUR):
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        with pytest.raises(RateLimitExceededError):
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        actions = await _audit_actions(session, conversation.id)
        assert "denied.rate_limited" in actions

    async def test_conversation_start_rate_limit(self, session: AsyncSession) -> None:
        owner = await _register(session, "rl-owner-2")
        for i in range(MAX_CONVERSATION_STARTS_PER_HOUR):
            target = await _register(session, f"rl-target-2-{i}")
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
            )
        overflow_target = await _register(session, "rl-target-2-overflow")
        with pytest.raises(RateLimitExceededError):
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[overflow_target.id],
                initial_message=_request_payload(),
            )
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.rate_limited" in actions

    async def test_sender_global_rate_limit_spans_many_conversations(
        self, session: AsyncSession
    ) -> None:
        """MAX_MESSAGES_PER_SENDER_PER_HOUR caps a sender's TOTAL
        message volume across ALL conversations combined — defense-in-depth
        against a sender staying under MAX_MESSAGES_PER_CONVERSATION_PER_HOUR
        in each of many DIFFERENT conversations while flooding in aggregate.
        """
        owner = await _register(session, "rl-owner-3")
        flooder = await _register(session, "rl-flooder-3")

        # Spread MAX_MESSAGES_PER_SENDER_PER_HOUR messages across enough
        # distinct conversations that no single conversation ever
        # approaches MAX_MESSAGES_PER_CONVERSATION_PER_HOUR -- isolating
        # the global limit from the per-conversation one.
        num_conversations = 5
        per_conversation = MAX_MESSAGES_PER_SENDER_PER_HOUR // num_conversations
        assert per_conversation < MAX_MESSAGES_PER_CONVERSATION_PER_HOUR
        assert per_conversation * num_conversations == MAX_MESSAGES_PER_SENDER_PER_HOUR

        for _ in range(num_conversations):
            conversation = await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[flooder.id],
                initial_message=_request_payload(),
            )
            await accept_invite(
                session,
                actor_sub=flooder.sub,
                agent_id=flooder.id,
                conversation_id=conversation.id,
            )
            for _ in range(per_conversation):
                await post_message(
                    session,
                    actor_sub=flooder.sub,
                    sender_agent_id=flooder.id,
                    conversation_id=conversation.id,
                    message_type="counter_proposal",
                    payload=_counter_proposal_payload(),
                )

        # One more conversation, brand new (0 prior messages there), so the
        # per-conversation check alone would pass -- only the global,
        # cross-conversation cap should fire here.
        overflow_conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[flooder.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session,
            actor_sub=flooder.sub,
            agent_id=flooder.id,
            conversation_id=overflow_conversation.id,
        )
        with pytest.raises(RateLimitExceededError):
            await post_message(
                session,
                actor_sub=flooder.sub,
                sender_agent_id=flooder.id,
                conversation_id=overflow_conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == flooder.id)))
            .scalars()
            .all()
        )
        assert "denied.rate_limited" in actions

        # A DIFFERENT sender in the same window is entirely unaffected.
        other_sender = await _register(session, "rl-other-3")
        other_conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[other_sender.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session,
            actor_sub=other_sender.sub,
            agent_id=other_sender.id,
            conversation_id=other_conversation.id,
        )
        message = await post_message(
            session,
            actor_sub=other_sender.sub,
            sender_agent_id=other_sender.id,
            conversation_id=other_conversation.id,
            message_type="counter_proposal",
            payload=_counter_proposal_payload(),
        )
        assert message.seq == 2

    async def test_sender_global_rate_limit_also_blocks_start_conversation(
        self, session: AsyncSession
    ) -> None:
        """start_conversation inserts its seq-1
        message via a separate code path from post_message (see the
        comment in service.start_conversation) -- this exercises that
        second call site directly, not just post_message's."""
        owner = await _register(session, "rl-owner-4")
        flooder = await _register(session, "rl-flooder-4")

        num_conversations = 5
        per_conversation = MAX_MESSAGES_PER_SENDER_PER_HOUR // num_conversations
        assert per_conversation < MAX_MESSAGES_PER_CONVERSATION_PER_HOUR

        for _ in range(num_conversations):
            conversation = await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[flooder.id],
                initial_message=_request_payload(),
            )
            await accept_invite(
                session,
                actor_sub=flooder.sub,
                agent_id=flooder.id,
                conversation_id=conversation.id,
            )
            for _ in range(per_conversation):
                await post_message(
                    session,
                    actor_sub=flooder.sub,
                    sender_agent_id=flooder.id,
                    conversation_id=conversation.id,
                    message_type="counter_proposal",
                    payload=_counter_proposal_payload(),
                )

        # flooder is now at the global cap purely from post_message calls;
        # flooder's OWN MAX_CONVERSATION_STARTS_PER_HOUR budget is untouched
        # (all starts above were owner's), so this failure can only be the
        # global sender rate limit firing inside start_conversation itself.
        new_target = await _register(session, "rl-new-target-4")
        with pytest.raises(RateLimitExceededError):
            await start_conversation(
                session,
                actor_sub=flooder.sub,
                initiator_agent_id=flooder.id,
                conversation_type="open",
                target_agent_ids=[new_target.id],
                initial_message=_request_payload(),
            )
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == flooder.id)))
            .scalars()
            .all()
        )
        assert "denied.rate_limited" in actions
        # No orphaned conversation/participant/message from the refused call.
        conversation_rows = (
            (
                await session.execute(
                    select(Conversation).where(Conversation.created_by == flooder.id)
                )
            )
            .scalars()
            .all()
        )
        assert conversation_rows == []

    async def test_approval_hold_rate_limit_under_limit_creates_holds(
        self, session: AsyncSession
    ) -> None:
        """MAX_APPROVAL_HOLDS_PER_HOUR (Argus round-1: no coverage existed
        for this rate limit at all). Every `note` posted into an `open`
        conversation diverts unconditionally (boundary_crossing), so each
        call below creates one more approval_holds row for the same
        sender."""
        owner = await _register(session, "rl-hold-owner-1")
        target = await _register(session, "rl-hold-target-1")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        for _ in range(MAX_APPROVAL_HOLDS_PER_HOUR):
            result = await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
            )
            assert isinstance(result, ApprovalHold)
        holds = (
            (
                await session.execute(
                    select(ApprovalHold).where(ApprovalHold.sender_agent_id == owner.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(holds) == MAX_APPROVAL_HOLDS_PER_HOUR

    async def test_approval_hold_rate_limit_over_limit_denied(self, session: AsyncSession) -> None:
        owner = await _register(session, "rl-hold-owner-2")
        target = await _register(session, "rl-hold-target-2")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        for _ in range(MAX_APPROVAL_HOLDS_PER_HOUR):
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
            )
        with pytest.raises(RateLimitExceededError):
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "one too many"},
            )
        # The hold-rate-limit denial audits with conversation_id=None (it
        # counts approval_holds across all of the sender's conversations,
        # not one) -- query by agent_id, not conversation_id, to see it.
        agent_actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.agent_id == owner.id)))
            .scalars()
            .all()
        )
        assert "denied.rate_limited" in agent_actions
        holds = (
            (
                await session.execute(
                    select(ApprovalHold).where(ApprovalHold.sender_agent_id == owner.id)
                )
            )
            .scalars()
            .all()
        )
        # The refused call must not have created an (MAX_APPROVAL_HOLDS_PER_HOUR + 1)th hold.
        assert len(holds) == MAX_APPROVAL_HOLDS_PER_HOUR


# --- list_pending_approval_holds ---------------------------------------------------


class TestListPendingApprovalHolds:
    async def test_all_expired_page_reports_has_more_false(self, session: AsyncSession) -> None:
        """Argus round-1 BLOCKING catch, regression coverage (round-2 SUGGESTION):
        has_more is computed from the raw fetched-row count BEFORE lazy expiry runs.
        If every fetched row expires during that pass, the naive count would leave
        {"holds": [], "has_more": True} -- and this API has no cursor/offset, so
        that combination would trap a polling client into retrying forever for a
        "next page" that doesn't exist."""
        owner = await _register(session, "lp-owner-1")
        target = await _register(session, "lp-target-1")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        # Two holds, then fetch with limit=1 so the raw query overfetches
        # (limit + 1 = 2 rows) exactly like the real has_more computation does.
        for _ in range(2):
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
            )
        holds = (
            (
                await session.execute(
                    select(ApprovalHold).where(ApprovalHold.sender_agent_id == owner.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(holds) == 2
        for hold in holds:
            hold.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

        result = await _service.list_pending_approval_holds(
            session, owner_sub=owner.owner_sub, limit=1
        )

        assert result == {"holds": [], "has_more": False}

    async def test_partial_expiry_transiently_suppresses_still_pending_hold(
        self, session: AsyncSession
    ) -> None:
        """Argus round-3 SUGGESTION: the untested half of the has_more fix above.
        With limit=1 and rows [expired, still-pending] (oldest first), the overfetch
        sees 2 rows, slices to the first 1 (the expired one), that one hold expires
        during the loop, `holds` ends up empty, and `has_more` is forced to False --
        so the still-pending SECOND hold is transiently invisible to this call. This
        self-heals on the next poll (it's not past the raw fetch's overfetch window
        anymore once the expired hold is gone), but is a real, documented gap: a
        one-shot caller can miss a genuinely pending hold on this page."""
        owner = await _register(session, "lp-owner-2")
        target = await _register(session, "lp-target-2")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        for _ in range(2):
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="note",
                payload={"text": "hello"},
            )
        holds = (
            (
                await session.execute(
                    select(ApprovalHold)
                    .where(ApprovalHold.sender_agent_id == owner.id)
                    .order_by(ApprovalHold.created_at.asc())
                )
            )
            .scalars()
            .all()
        )
        assert len(holds) == 2
        oldest, newest = holds
        oldest.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

        result = await _service.list_pending_approval_holds(
            session, owner_sub=owner.owner_sub, limit=1
        )

        # The still-pending `newest` hold exists but is not surfaced this call.
        assert result == {"holds": [], "has_more": False}
        assert newest.status == "pending_human"


# --- expiry -----------------------------------------------------------------------


class TestExpiry:
    async def test_lazy_expiry_flip_and_write_rejection(self, session: AsyncSession) -> None:
        owner = await _register(session, "exp-owner-1")
        target = await _register(session, "exp-target-1")
        already_expired = datetime.now(UTC) - timedelta(seconds=1)
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            expires_at=already_expired,
        )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )

        result = await get_conversation(
            session,
            actor_sub=target.sub,
            caller_agent_id=target.id,
            conversation_id=conversation.id,
        )
        assert result["conversation"]["state"] == "expired"

        with pytest.raises(InvalidConversationStateError):
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )


# --- audit completeness ------------------------------------------------------------


class TestAuditCompleteness:
    async def test_success_and_denial_paths_are_all_audited(self, session: AsyncSession) -> None:
        owner = await _register(session, "audit-owner-1")
        target = await _register(session, "audit-target-1")
        conversation = await start_conversation(
            session,
            actor_sub=owner.sub,
            initiator_agent_id=owner.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        actions = set(await _audit_actions(session, conversation.id))
        assert "conversation.start" in actions
        assert "message.post" in actions

        outsider_id = uuid.uuid4()
        with pytest.raises(AccessDeniedError):
            await get_conversation(
                session,
                actor_sub="ghost-1",
                caller_agent_id=outsider_id,
                conversation_id=conversation.id,
            )
        with pytest.raises(PayloadValidationError):
            await post_message(
                session,
                actor_sub=owner.sub,
                sender_agent_id=owner.id,
                conversation_id=conversation.id,
                message_type="confirm",
                payload={"slot": "not-a-valid-shape"},
            )
        await accept_invite(
            session, actor_sub=target.sub, agent_id=target.id, conversation_id=conversation.id
        )
        for _ in range(MAX_MESSAGES_PER_CONVERSATION_PER_HOUR):
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )
        with pytest.raises(RateLimitExceededError):
            await post_message(
                session,
                actor_sub=target.sub,
                sender_agent_id=target.id,
                conversation_id=conversation.id,
                message_type="counter_proposal",
                payload=_counter_proposal_payload(),
            )

        final_actions = set(await _audit_actions(session, conversation.id))
        assert "denied.not_member" in final_actions
        assert "denied.bad_schema" in final_actions
        assert "denied.rate_limited" in final_actions
        assert "message.post" in final_actions


# --- list_agents -------------------------------------------------------------------


class TestListAgents:
    async def test_pagination_cursor_and_has_more(self, session: AsyncSession) -> None:
        for i in range(5):
            await _register(session, f"la-agent-{i:02d}")

        first_page = await list_agents(session, limit=2)
        assert len(first_page["agents"]) == 2
        assert first_page["has_more"] is True
        assert first_page["next_cursor"] == first_page["agents"][-1]["sub"]
        # total_count reflects the real row COUNT(*), not the trimmed page.
        assert first_page["total_count"] == 5

        second_page = await list_agents(session, limit=2, cursor=first_page["next_cursor"])
        assert len(second_page["agents"]) == 2
        assert second_page["has_more"] is True
        assert second_page["total_count"] == 5

        third_page = await list_agents(session, limit=2, cursor=second_page["next_cursor"])
        assert len(third_page["agents"]) == 1
        assert third_page["has_more"] is False
        assert third_page["next_cursor"] is None
        assert third_page["total_count"] == 5

        all_subs = {a["sub"] for a in first_page["agents"]}
        all_subs |= {a["sub"] for a in second_page["agents"]}
        all_subs |= {a["sub"] for a in third_page["agents"]}
        assert all_subs == {f"la-agent-{i:02d}" for i in range(5)}

    async def test_total_count_is_real_count_not_page_length(self, session: AsyncSession) -> None:
        for i in range(3):
            await _register(session, f"la-count-{i}")

        page = await list_agents(session, limit=1)
        assert len(page["agents"]) == 1
        assert page["total_count"] == 3

    async def test_registry_retired_agent_excluded_but_still_counted(
        self, session: AsyncSession
    ) -> None:
        """TECH-5703: a registry-retired agent's row still exists (no
        history/audit is destroyed) but is dropped from the listing --
        total_count still reflects the raw table, since that's the DB's
        actual row count, not this listing's visibility."""
        await _register(session, "la-active")
        await _register(session, "la-retired")

        page = await list_agents(
            session, active_checker=_FakeActiveChecker(inactive_subs={"la-retired"})
        )
        assert {a["sub"] for a in page["agents"]} == {"la-active"}
        assert page["total_count"] == 2

    async def test_registry_retirement_does_not_disturb_cursor_pagination(
        self, session: AsyncSession
    ) -> None:
        """The has_more/next_cursor computation is based on the raw DB
        rows, not the post-filter visible list -- a retired agent sitting
        in the middle of keyset order must not cause the next page to
        skip (or re-return) its neighbor."""
        for i in range(3):
            await _register(session, f"lp-agent-{i:02d}")

        checker = _FakeActiveChecker(inactive_subs={"lp-agent-01"})
        first_page = await list_agents(session, limit=2, active_checker=checker)
        # DB fetched agent-00 and agent-01 for this page; agent-01 is
        # filtered, so only agent-00 is visible, but next_cursor must still
        # be agent-01's sub (the last DB row actually examined).
        assert [a["sub"] for a in first_page["agents"]] == ["lp-agent-00"]
        assert first_page["has_more"] is True
        assert first_page["next_cursor"] == "lp-agent-01"

        second_page = await list_agents(
            session, limit=2, cursor=first_page["next_cursor"], active_checker=checker
        )
        assert [a["sub"] for a in second_page["agents"]] == ["lp-agent-02"]
        assert second_page["has_more"] is False


class TestLookupAgentByEmail:
    async def test_found(self, session: AsyncSession) -> None:
        await _register(session, "lae-agent", owner_email="Dan@Example.com")
        result = await lookup_agent_by_email(session, owner_email="  dan@example.com\t")
        assert result is not None
        assert result["sub"] == "lae-agent"
        assert result["owner_email"] == "Dan@Example.com"

    async def test_not_found(self, session: AsyncSession) -> None:
        assert await lookup_agent_by_email(session, owner_email="nobody@example.com") is None

    async def test_empty_and_non_string_fail_closed(self, session: AsyncSession) -> None:
        assert await lookup_agent_by_email(session, owner_email="   ") is None
        assert await lookup_agent_by_email(session, owner_email=None) is None  # type: ignore[arg-type]

    async def test_over_length_fails_closed(self, session: AsyncSession) -> None:
        # One over MAX_LOOKUP_EMAIL_LENGTH -- never reaches the query, so no
        # matching row is required for this to prove the guard fires rather
        # than a legitimate not-found.
        from service import MAX_LOOKUP_EMAIL_LENGTH

        over_length = "a" * (MAX_LOOKUP_EMAIL_LENGTH + 1)
        assert await lookup_agent_by_email(session, owner_email=over_length) is None

    async def test_status_filter_excludes_non_active_agent(self, session: AsyncSession) -> None:
        agent = await _register(session, "lae-suspended", owner_email="suspend@example.com")
        agent.status = "suspended"
        await session.flush()
        await session.commit()
        assert await lookup_agent_by_email(session, owner_email="suspend@example.com") is None

    async def test_registry_retired_agent_resolves_to_not_found(
        self, session: AsyncSession
    ) -> None:
        """TECH-5703: a registry-retired agent resolves to the SAME
        not-found shape as an unregistered email -- no distinguishable
        signal, matching this lookup's existing anti-enumeration posture."""
        await _register(session, "lae-retired", owner_email="retired@example.com")
        result = await lookup_agent_by_email(
            session,
            owner_email="retired@example.com",
            active_checker=_FakeActiveChecker(inactive_subs={"lae-retired"}),
        )
        assert result is None

    async def test_tie_break_prefers_most_recently_bound(self, session: AsyncSession) -> None:
        # Same owner_email, two distinct subs -- an anticipated state (see
        # lookup_agent_by_email's docstring): the agent_key mechanism lets
        # one owner run multiple board-active agents under one email.
        # bound_at is set explicitly (not relied on via real-time gaps
        # between the two _register calls, which could tie down to the
        # microsecond) so the ordering this test asserts
        # is deterministic regardless of wall-clock timing.
        old = await _register(session, "lae-old", owner_email="multi@example.com")
        new = await _register(session, "lae-new", owner_email="multi@example.com")
        old.bound_at = new.bound_at - timedelta(hours=1)
        await session.flush()
        await session.commit()
        result = await lookup_agent_by_email(session, owner_email="multi@example.com")
        assert result is not None
        assert result["sub"] == "lae-new"

    async def test_tie_break_falls_through_to_id_on_equal_bound_at_and_created_at(
        self, session: AsyncSession
    ) -> None:
        # The documented equal-bound_at case: two agents
        # sharing bound_at AND created_at (both explicitly forced equal
        # here, not merely left to same-transaction chance) must still
        # resolve deterministically via the id tiebreaker, not arbitrarily.
        first = await _register(session, "lae-tie-a", owner_email="tie@example.com")
        second = await _register(session, "lae-tie-b", owner_email="tie@example.com")
        second.bound_at = first.bound_at
        second.created_at = first.created_at
        await session.flush()
        await session.commit()
        # Agent.id.asc() -- the smaller id sorts first and wins the tie.
        expected_sub = first.sub if first.id < second.id else second.sub
        result = await lookup_agent_by_email(session, owner_email="tie@example.com")
        assert result is not None
        assert result["sub"] == expected_sub


# --- inbox -------------------------------------------------------------------------


class TestInbox:
    async def test_empty_state_shape(self, session: AsyncSession) -> None:
        agent = await _register(session, "inbox-empty-1")
        result = await inbox(session, caller_agent_id=agent.id)
        assert result == {
            "unread": [],
            "unread_has_more": False,
            "pending_invites": [],
            "pending_invites_has_more": False,
            "total_count": 0,
        }

    async def test_unread_across_multiple_conversations(self, session: AsyncSession) -> None:
        agent = await _register(session, "inbox-unread-1")
        senders = [await _register(session, f"inbox-sender-{i}") for i in range(2)]
        conversation_ids = []
        for sender in senders:
            conversation = await start_conversation(
                session,
                actor_sub=sender.sub,
                initiator_agent_id=sender.id,
                conversation_type="open",
                target_agent_ids=[agent.id],
                initial_message=_request_payload(),
            )
            await accept_invite(
                session, actor_sub=agent.sub, agent_id=agent.id, conversation_id=conversation.id
            )
            conversation_ids.append(conversation.id)

        result = await inbox(session, caller_agent_id=agent.id)
        assert result["pending_invites"] == []
        assert {u["conversation_id"] for u in result["unread"]} == {
            str(cid) for cid in conversation_ids
        }
        assert all(u["unread_count"] == 1 for u in result["unread"])
        assert result["total_count"] == 2

    async def test_pending_invite_only(self, session: AsyncSession) -> None:
        agent = await _register(session, "inbox-pending-1")
        sender = await _register(session, "inbox-pending-sender-1")
        conversation = await start_conversation(
            session,
            actor_sub=sender.sub,
            initiator_agent_id=sender.id,
            conversation_type="open",
            target_agent_ids=[agent.id],
            initial_message=_request_payload(),
        )

        result = await inbox(session, caller_agent_id=agent.id)
        assert result["unread"] == []
        assert len(result["pending_invites"]) == 1
        assert result["pending_invites"][0]["conversation_id"] == str(conversation.id)
        assert result["total_count"] == 1

    async def test_pending_invite_reflects_expired_state(self, session: AsyncSession) -> None:
        """inbox() reads _conversation_dict too -- a past-expiry
        conversation must project state="expired" here exactly as it does
        in list_conversations, not the stale raw column value."""
        agent = await _register(session, "inbox-expired-1")
        sender = await _register(session, "inbox-expired-sender-1")
        already_expired = datetime.now(UTC) - timedelta(seconds=1)
        conversation = await start_conversation(
            session,
            actor_sub=sender.sub,
            initiator_agent_id=sender.id,
            conversation_type="open",
            target_agent_ids=[agent.id],
            initial_message=_request_payload(),
            expires_at=already_expired,
        )

        result = await inbox(session, caller_agent_id=agent.id)
        assert len(result["pending_invites"]) == 1
        assert result["pending_invites"][0]["conversation_id"] == str(conversation.id)
        assert result["pending_invites"][0]["state"] == "expired"

    async def test_unread_reflects_expired_state(self, session: AsyncSession) -> None:
        """Same reconciliation as above, but through the `unread` branch
        (accepted membership) rather than `pending_invites` -- both branches
        go through _conversation_dict, but only one was previously covered.

        Expiry is pushed into the past AFTER accept_invite() returns, not
        passed to start_conversation() up front: accept_invite() calls
        _maybe_expire(), which would otherwise flip the stored column to
        "expired" and commit it before inbox() ever runs, making this test
        pass even if _conversation_dict's own reconciliation were deleted
        (as test_service.py's test_pending_invite_reflects_expired_state
        does not exercise, since accept_invite() is never called there)."""
        agent = await _register(session, "inbox-expired-2")
        sender = await _register(session, "inbox-expired-sender-2")
        conversation = await start_conversation(
            session,
            actor_sub=sender.sub,
            initiator_agent_id=sender.id,
            conversation_type="open",
            target_agent_ids=[agent.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session, actor_sub=agent.sub, agent_id=agent.id, conversation_id=conversation.id
        )
        # Safe to keep using the `conversation` object post-commit: this
        # module's session fixture is built with expire_on_commit=False, so
        # accept_invite()'s commit doesn't expire it out from under us.
        conversation.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

        result = await inbox(session, caller_agent_id=agent.id)
        assert len(result["unread"]) == 1
        assert result["unread"][0]["conversation_id"] == str(conversation.id)
        assert result["unread"][0]["state"] == "expired"

    async def test_both_unread_and_pending_invite(self, session: AsyncSession) -> None:
        agent = await _register(session, "inbox-both-1")
        active_sender = await _register(session, "inbox-both-active-sender")
        pending_sender = await _register(session, "inbox-both-pending-sender")

        active_conversation = await start_conversation(
            session,
            actor_sub=active_sender.sub,
            initiator_agent_id=active_sender.id,
            conversation_type="open",
            target_agent_ids=[agent.id],
            initial_message=_request_payload(),
        )
        await accept_invite(
            session,
            actor_sub=agent.sub,
            agent_id=agent.id,
            conversation_id=active_conversation.id,
        )

        pending_conversation = await start_conversation(
            session,
            actor_sub=pending_sender.sub,
            initiator_agent_id=pending_sender.id,
            conversation_type="open",
            target_agent_ids=[agent.id],
            initial_message=_request_payload(),
        )

        result = await inbox(session, caller_agent_id=agent.id)
        assert len(result["unread"]) == 1
        assert result["unread"][0]["conversation_id"] == str(active_conversation.id)
        assert len(result["pending_invites"]) == 1
        assert result["pending_invites"][0]["conversation_id"] == str(pending_conversation.id)
        assert result["total_count"] == 2

    async def _seed_unread_conversation(
        self, session: AsyncSession, *, sender: Agent, agent: Agent, created_at: datetime
    ) -> None:
        """Bulk-creates one active conversation with one unread message,
        bypassing start_conversation's per-hour rate limits -- real traffic
        would never clear MAX_UNREAD_CONVERSATIONS_PER_INBOX conversations
        in an hour, so this exists purely to exercise inbox()'s read-side
        cap, not the write path."""
        conversation = Conversation(
            type="open",
            state="active",
            created_by=sender.id,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        session.add(conversation)
        await session.flush()
        session.add_all(
            [
                Participant(
                    conversation_id=conversation.id,
                    agent_id=sender.id,
                    role="owner",
                    status="active",
                    joined_at=created_at,
                ),
                Participant(
                    conversation_id=conversation.id,
                    agent_id=agent.id,
                    role="member",
                    status="active",
                    joined_at=created_at,
                ),
                Message(
                    conversation_id=conversation.id,
                    seq=1,
                    sender_id=sender.id,
                    type="note",
                    schema_version=1,
                    payload={"type": "note", "text": "x"},
                    created_at=created_at,
                ),
            ]
        )

    async def test_unread_list_is_capped_with_has_more(self, session: AsyncSession) -> None:
        agent = await _register(session, "inbox-page-agent")
        sender = await _register(session, "inbox-page-sender")
        extra = MAX_UNREAD_CONVERSATIONS_PER_INBOX + 5
        base = datetime.now(UTC)
        for i in range(extra):
            await self._seed_unread_conversation(
                session, sender=sender, agent=agent, created_at=base - timedelta(seconds=i)
            )
        await session.commit()

        result = await inbox(session, caller_agent_id=agent.id)
        assert len(result["unread"]) == MAX_UNREAD_CONVERSATIONS_PER_INBOX
        assert result["unread_has_more"] is True
        assert result["pending_invites_has_more"] is False
        # Argus round-2 SUGGESTION: this is the only assertion that
        # actually distinguishes the round-1 true-COUNT(*) fix from the
        # reverted len(unread)+len(pending) behavior -- every other
        # total_count assertion in this file uses 0-2 rows, where both
        # implementations agree.
        assert result["total_count"] == extra

    async def test_pending_invites_list_is_capped_with_has_more(
        self, session: AsyncSession
    ) -> None:
        agent = await _register(session, "inbox-pending-page-agent")
        senders = [
            await _register(session, f"inbox-pending-page-sender-{i}")
            for i in range(MAX_PENDING_INVITES_PER_INBOX + 5)
        ]
        for sender in senders:
            conversation = Conversation(
                type="open",
                state="active",
                created_by=sender.id,
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
            session.add(conversation)
            await session.flush()
            session.add_all(
                [
                    Participant(
                        conversation_id=conversation.id,
                        agent_id=sender.id,
                        role="owner",
                        status="active",
                        joined_at=datetime.now(UTC),
                    ),
                    Participant(
                        conversation_id=conversation.id,
                        agent_id=agent.id,
                        role="member",
                        status="invited",
                    ),
                ]
            )
        await session.commit()

        result = await inbox(session, caller_agent_id=agent.id)
        assert len(result["pending_invites"]) == MAX_PENDING_INVITES_PER_INBOX
        assert result["pending_invites_has_more"] is True
        assert result["unread_has_more"] is False
        assert result["total_count"] == MAX_PENDING_INVITES_PER_INBOX + 5


# --- accepted_types message-type vocabulary -----------------------------------


class TestAcceptedTypesMessageVocabulary:
    async def test_message_type_string_is_valid(self, session: AsyncSession) -> None:
        agent = await _register(session, "vocab-ok", accepted_types=["task_assign", "note"])
        assert "task_assign" in agent.accepted_types
        assert "note" in agent.accepted_types

    async def test_conversation_type_string_now_invalid(self, session: AsyncSession) -> None:
        """Conversation type strings ('open', 'internal', 'asymmetric') are no
        longer valid accepted_types values — message type strings are."""
        with pytest.raises(UnknownConversationTypeError, match=r"got unknown: \['open'\]"):
            await _register(session, "vocab-conv-type", accepted_types=["open"])

    async def test_all_registered_message_types_accepted(self, session: AsyncSession) -> None:
        from schemas import MESSAGE_TYPES

        agent = await _register(session, "vocab-all", accepted_types=sorted(MESSAGE_TYPES)[:5])
        assert agent.accepted_types


# --- per-type TTL -------------------------------------------------------------


class TestPerTypeTTL:
    async def test_open_gets_7_day_ttl(self, session: AsyncSession) -> None:
        creator = await _register(session, "ttl-open-creator")
        target = await _register(session, "ttl-open-target")
        before = datetime.now(UTC)
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        delta = conv.expires_at - before
        assert abs(delta.total_seconds() - CONVERSATION_TTL["open"].total_seconds()) < 5

    async def test_internal_gets_30_day_ttl(self, session: AsyncSession) -> None:
        owner_sub = "owner-ttl-internal@example.com"
        creator = await _register(session, "ttl-internal-creator", owner_sub=owner_sub)
        target = await _register(session, "ttl-internal-target", owner_sub=owner_sub)
        before = datetime.now(UTC)
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="internal",
            target_agent_ids=[target.id],
            initial_message=_task_assign_payload(),
            message_type="task_assign",
        )
        delta = conv.expires_at - before
        assert abs(delta.total_seconds() - CONVERSATION_TTL["internal"].total_seconds()) < 5

    async def test_asymmetric_gets_14_day_ttl(self, session: AsyncSession) -> None:
        creator = await _register(session, "ttl-asymmetric-creator")
        target = await _register(session, "ttl-asymmetric-target")
        client = _FakeOwnershipClient(
            {
                creator.id: {"is_shared": False, "owners": ["dan"]},
                target.id: {"is_shared": True, "owners": ["dan", "priya"]},
            }
        )
        before = datetime.now(UTC)
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="asymmetric",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            ownership_client=client,
        )
        delta = conv.expires_at - before
        assert abs(delta.total_seconds() - CONVERSATION_TTL["asymmetric"].total_seconds()) < 5

    async def test_explicit_expires_at_overrides_ttl(self, session: AsyncSession) -> None:
        creator = await _register(session, "ttl-override-creator")
        target = await _register(session, "ttl-override-target")
        custom = datetime.now(UTC) + timedelta(hours=3)
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            expires_at=custom,
        )
        assert abs((conv.expires_at - custom).total_seconds()) < 1

    async def test_expires_at_beyond_max_ttl_is_rejected(self, session: AsyncSession) -> None:
        creator = await _register(session, "ttl-ceiling-creator")
        target = await _register(session, "ttl-ceiling-target")
        too_far = datetime.now(UTC) + MAX_CONVERSATION_TTL + timedelta(seconds=1)
        with pytest.raises(ValueError, match="expires_at"):
            await start_conversation(
                session,
                actor_sub=creator.sub,
                initiator_agent_id=creator.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                expires_at=too_far,
            )

    async def test_expires_at_at_exactly_max_ttl_is_accepted(self, session: AsyncSession) -> None:
        creator = await _register(session, "ttl-ceiling-ok-creator")
        target = await _register(session, "ttl-ceiling-ok-target")
        at_ceiling = datetime.now(UTC) + MAX_CONVERSATION_TTL
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            expires_at=at_ceiling,
        )
        assert abs((conv.expires_at - at_ceiling).total_seconds()) < 1

    async def test_already_expired_expires_at_still_accepted(self, session: AsyncSession) -> None:
        """The ceiling is a max, deliberately not a min -- already-expired
        overrides remain valid test tooling (see CONVERSATION_TTL's own
        docstring), not something TECH-5377's ceiling should start rejecting."""
        creator = await _register(session, "ttl-past-creator")
        target = await _register(session, "ttl-past-target")
        already_expired = datetime.now(UTC) - timedelta(seconds=1)
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            expires_at=already_expired,
        )
        assert abs((conv.expires_at - already_expired).total_seconds()) < 1

    async def test_naive_expires_at_rejected_with_a_clear_error(
        self, session: AsyncSession
    ) -> None:
        """Argus round-2 SUGGESTION: without this guard, a naive datetime
        raises a raw TypeError from the ceiling arithmetic (offset-naive
        minus offset-aware) instead of a clear validation error."""
        creator = await _register(session, "ttl-naive-creator")
        target = await _register(session, "ttl-naive-target")
        with pytest.raises(ValueError, match="timezone-aware"):
            await start_conversation(
                session,
                actor_sub=creator.sub,
                initiator_agent_id=creator.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message=_request_payload(),
                expires_at=datetime(2030, 1, 1),
            )


# --- list_conversations -------------------------------------------------------


class TestListConversations:
    async def test_empty_returns_empty_list(self, session: AsyncSession) -> None:
        agent = await _register(session, "listconv-empty")
        result = await list_conversations(session, caller_agent_id=agent.id)
        assert result["conversations"] == []
        assert result["has_more"] is False
        assert result["next_cursor"] is None

    async def test_returns_own_conversations(self, session: AsyncSession) -> None:
        creator = await _register(session, "listconv-creator")
        target = await _register(session, "listconv-target")
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        result = await list_conversations(session, caller_agent_id=creator.id)
        ids = [c["conversation_id"] for c in result["conversations"]]
        assert str(conv.id) in ids

    async def test_invited_participant_sees_conversation(self, session: AsyncSession) -> None:
        creator = await _register(session, "listconv-inviter")
        invited = await _register(session, "listconv-invited")
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[invited.id],
            initial_message=_request_payload(),
        )
        result = await list_conversations(session, caller_agent_id=invited.id)
        ids = [c["conversation_id"] for c in result["conversations"]]
        assert str(conv.id) in ids

    async def test_filter_by_type(self, session: AsyncSession) -> None:
        creator = await _register(session, "listconv-filter-creator")
        target = await _register(session, "listconv-filter-target")
        open_conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        result = await list_conversations(
            session, caller_agent_id=creator.id, conversation_type="open"
        )
        assert any(c["conversation_id"] == str(open_conv.id) for c in result["conversations"])
        # filtering by internal returns nothing (no internal conv created)
        result2 = await list_conversations(
            session, caller_agent_id=creator.id, conversation_type="internal"
        )
        assert result2["conversations"] == []

    async def test_filter_by_state(self, session: AsyncSession) -> None:
        creator = await _register(session, "listconv-state-creator")
        target = await _register(session, "listconv-state-target")
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        result_active = await list_conversations(
            session, caller_agent_id=creator.id, state="active"
        )
        assert any(c["conversation_id"] == str(conv.id) for c in result_active["conversations"])

        result_completed = await list_conversations(
            session, caller_agent_id=creator.id, state="completed"
        )
        assert result_completed["conversations"] == []

    async def test_filter_by_state_reconciles_lazy_expiry(self, session: AsyncSession) -> None:
        """A conversation past ``expires_at`` is still stored as ``state=
        "active"`` until the next lazy-expiry touch -- ``state="active"``
        must exclude it and ``state="expired"`` must include it, not just
        match the raw (stale) column value."""
        creator = await _register(session, "listconv-expiry-creator")
        target = await _register(session, "listconv-expiry-target")
        already_expired = datetime.now(UTC) - timedelta(seconds=1)
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
            expires_at=already_expired,
        )
        assert conv.state == "active"  # stored value is stale, not yet flipped

        result_active = await list_conversations(
            session, caller_agent_id=creator.id, state="active"
        )
        assert not any(c["conversation_id"] == str(conv.id) for c in result_active["conversations"])

        result_expired = await list_conversations(
            session, caller_agent_id=creator.id, state="expired"
        )
        matches = [
            c for c in result_expired["conversations"] if c["conversation_id"] == str(conv.id)
        ]
        assert len(matches) == 1
        # The projected "state" must be reconciled too, not just the row
        # selection -- a caller filtering on state="expired" must not get
        # back a JSON object that still says "active".
        assert matches[0]["state"] == "expired"

    async def test_filter_by_role_owner(self, session: AsyncSession) -> None:
        creator = await _register(session, "listconv-role-owner")
        target = await _register(session, "listconv-role-target-2")
        conv = await start_conversation(
            session,
            actor_sub=creator.sub,
            initiator_agent_id=creator.id,
            conversation_type="open",
            target_agent_ids=[target.id],
            initial_message=_request_payload(),
        )
        # creator is owner
        result = await list_conversations(session, caller_agent_id=creator.id, role="owner")
        assert any(c["conversation_id"] == str(conv.id) for c in result["conversations"])
        # target is member (invited) — owner filter should exclude them
        result2 = await list_conversations(session, caller_agent_id=target.id, role="owner")
        assert not any(c["conversation_id"] == str(conv.id) for c in result2["conversations"])

    async def test_does_not_leak_other_agents_conversations(self, session: AsyncSession) -> None:
        a = await _register(session, "listconv-a")
        b = await _register(session, "listconv-b")
        c = await _register(session, "listconv-c")
        await start_conversation(
            session,
            actor_sub=a.sub,
            initiator_agent_id=a.id,
            conversation_type="open",
            target_agent_ids=[b.id],
            initial_message=_request_payload(),
        )
        # c was never involved
        result = await list_conversations(session, caller_agent_id=c.id)
        assert result["conversations"] == []

    async def test_pagination(self, session: AsyncSession) -> None:
        creator = await _register(session, "listconv-paginate-creator")
        targets = [await _register(session, f"listconv-paginate-target-{i}") for i in range(3)]
        for t in targets:
            await start_conversation(
                session,
                actor_sub=creator.sub,
                initiator_agent_id=creator.id,
                conversation_type="open",
                target_agent_ids=[t.id],
                initial_message=_request_payload(),
            )
        page1 = await list_conversations(session, caller_agent_id=creator.id, limit=2)
        assert len(page1["conversations"]) == 2
        assert page1["has_more"] is True
        assert page1["next_cursor"] is not None

        page2 = await list_conversations(
            session, caller_agent_id=creator.id, limit=2, cursor=page1["next_cursor"]
        )
        assert len(page2["conversations"]) == 1
        assert page2["has_more"] is False

        all_ids = {c["conversation_id"] for c in page1["conversations"] + page2["conversations"]}
        assert len(all_ids) == 3


# --- OwnershipClient pluggable seam (TECH-5396 open question 1) -------------------
#
# Pure-Python resolution/validation tests (no DB dependency) live in
# tests/test_plugins.py instead of here, since this module's autouse fixture
# skips everything when Postgres is unreachable -- matching where the other
# three seams' equivalent tests already live.


class _FakeLiveOwnershipClient:
    """Stand-in for a live-resolving OwnershipClient plugin (e.g. a consumer's
    own ownership registry) -- stateless and reusable, ignores any session
    argument, matching the shape a real HTTP-backed implementation would have."""

    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        return {
            "is_shared": False,
            "owners": ["live-resolved@example.com"],
        }


_fake_live_ownership_client_instance = _FakeLiveOwnershipClient()


def _fake_live_ownership_client_factory() -> _service.OwnershipClientFactory:
    return lambda session: _fake_live_ownership_client_instance


class TestOwnershipClientSeamDbBacked:
    """The one DB-dependent test for this seam -- everything else lives in
    tests/test_plugins.py's TestOwnershipClientRegistry /
    TestGetOwnershipClientFactoryAndValidateConfiguration."""

    def setup_method(self) -> None:
        _service._ownership_client_factory = None

    def teardown_method(self) -> None:
        _service._ownership_client_factory = None

    async def test_import_path_plugin_resolves_and_is_used(
        self, monkeypatch: pytest.MonkeyPatch, session: AsyncSession
    ) -> None:
        monkeypatch.setenv(
            _service.OWNERSHIP_CLIENT_ENV_VAR,
            "tests.test_service:_fake_live_ownership_client_factory",
        )
        factory = _service.get_ownership_client_factory()
        client = factory(session)
        owner = await _register(session, "live-ownership-agent")
        result = await client.get_agent_owners(owner.id)
        assert result == {"is_shared": False, "owners": ["live-resolved@example.com"]}


class TestWriteThroughOwnership:
    """TECH-5593 item 1: bounded-staleness ownership write-through.

    Trust-gating (``scopes.is_registry_backed_agent_token``) is the tools
    layer's job, not this function's -- these tests call it directly, the
    same way ``register_agent``'s freeze is tested at this layer, not by
    round-tripping through an actual token."""

    async def test_updates_owner_sub_and_owner_email_and_audits(
        self, session: AsyncSession
    ) -> None:
        agent = await _register(session, "write-through-agent")

        await write_through_ownership(
            session, agent, owner_sub="new-owner-sub", owner_email="new@example.com"
        )

        assert agent.owner_sub == "new-owner-sub"
        assert agent.owner_email == "new@example.com"
        row = (
            await session.execute(select(Agent).where(Agent.sub == "write-through-agent"))
        ).scalar_one()
        assert row.owner_sub == "new-owner-sub"
        assert row.owner_email == "new@example.com"

        detail = (
            await session.execute(
                select(AuditLog.detail).where(
                    AuditLog.actor_sub == "write-through-agent",
                    AuditLog.action == "agent.ownership_write_through",
                )
            )
        ).scalar_one()
        assert detail == {
            "owner_sub": {"old": "owner-write-through-agent", "new": "new-owner-sub"},
            "owner_email": {
                "old": "write-through-agent@example.com",
                "new": "new@example.com",
            },
        }

    async def test_no_op_and_no_audit_row_when_values_unchanged(
        self, session: AsyncSession
    ) -> None:
        agent = await _register(session, "write-through-noop")

        await write_through_ownership(
            session,
            agent,
            owner_sub=agent.owner_sub,
            owner_email=agent.owner_email,
        )

        count = (
            await session.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.actor_sub == "write-through-noop",
                    AuditLog.action == "agent.ownership_write_through",
                )
            )
        ).scalar_one()
        assert count == 0

    async def test_no_op_when_both_claims_are_none(self, session: AsyncSession) -> None:
        agent = await _register(session, "write-through-none")
        original_owner_sub = agent.owner_sub
        original_owner_email = agent.owner_email

        await write_through_ownership(session, agent, owner_sub=None, owner_email=None)

        assert agent.owner_sub == original_owner_sub
        assert agent.owner_email == original_owner_email

    async def test_updates_only_owner_sub_when_owner_email_is_none(
        self, session: AsyncSession
    ) -> None:
        agent = await _register(session, "write-through-partial")
        original_owner_email = agent.owner_email

        await write_through_ownership(session, agent, owner_sub="partial-new-sub", owner_email=None)

        assert agent.owner_sub == "partial-new-sub"
        assert agent.owner_email == original_owner_email

    async def test_overwrites_owner_sub_unlike_register_agent_reregistration(
        self, session: AsyncSession
    ) -> None:
        """The one place ``agents.owner_sub`` is allowed to change after
        first registration -- proving this deliberately breaks
        ``register_agent``'s own freeze, which is the entire point (that
        freeze exists to block UNTRUSTED claims; this function is only
        ever reached with claims the caller already confirmed are
        trusted)."""
        agent = await _register(session, "write-through-vs-freeze")
        reregistered = await register_agent(
            session,
            sub="write-through-vs-freeze",
            owner_sub="attempted-forged-owner",
            owner_email="attempted-forged-owner@example.com",
            display_name="write-through-vs-freeze",
            accepted_types=sorted(MESSAGE_TYPES),
            is_shared_authorized=True,
        )
        assert reregistered.owner_sub == agent.owner_sub  # frozen, as documented

        await write_through_ownership(
            session, reregistered, owner_sub="trusted-new-owner", owner_email=None
        )

        assert reregistered.owner_sub == "trusted-new-owner"


class TestReconcileAgentOwnership:
    """TECH-5593 item 4: out-of-band backstop for agents that never make a
    further verified request after registration (so write-through above
    never fires for them)."""

    async def test_updates_drifted_owner_sub_and_audits(self, session: AsyncSession) -> None:
        agent = await _register(session, "reconcile-drifted")
        client = _FakeOwnershipClient({agent.id: {"is_shared": False, "owners": ["new-owner"]}})

        result = await reconcile_agent_ownership(session, ownership_client=client)

        assert result == {"checked": 1, "updated": 1, "skipped_shared": 0, "errors": 0}
        row = (
            await session.execute(select(Agent).where(Agent.sub == "reconcile-drifted"))
        ).scalar_one()
        assert row.owner_sub == "new-owner"

        detail = (
            await session.execute(
                select(AuditLog.detail).where(
                    AuditLog.actor_sub == "reconcile-drifted",
                    AuditLog.action == "agent.ownership_reconciled",
                )
            )
        ).scalar_one()
        assert detail == {"owner_sub": {"old": "owner-reconcile-drifted", "new": "new-owner"}}

    async def test_no_update_when_owner_sub_already_matches(self, session: AsyncSession) -> None:
        agent = await _register(session, "reconcile-matching")
        client = _FakeOwnershipClient({agent.id: {"is_shared": False, "owners": [agent.owner_sub]}})

        result = await reconcile_agent_ownership(session, ownership_client=client)

        assert result == {"checked": 1, "updated": 0, "skipped_shared": 0, "errors": 0}

    async def test_skips_shared_agents(self, session: AsyncSession) -> None:
        await _register(session, "reconcile-shared", is_shared=True, is_shared_authorized=True)
        # A raising client here proves the shared agent is skipped BEFORE
        # any lookup is attempted, not merely that its result is discarded.
        result = await reconcile_agent_ownership(
            session, ownership_client=_FailingOwnershipClient()
        )

        assert result == {"checked": 0, "updated": 0, "skipped_shared": 1, "errors": 0}

    async def test_shared_agents_do_not_consume_batch_slots(self, session: AsyncSession) -> None:
        """Argus round-1 BLOCKING fix: shared agents are excluded at the SQL
        level, before LIMIT, not filtered out in Python after -- so a
        shared agent sorting first (never reconciled) must not consume the
        single available slot and starve the real, actionable agent behind
        it. A raising client for the shared agent's id would fail this test
        if it were ever looked up."""
        shared = await _register(
            session, "reconcile-shared-no-slot", is_shared=True, is_shared_authorized=True
        )
        real = await _register(session, "reconcile-real-agent")
        client = _FakeOwnershipClient(
            {
                shared.id: {"is_shared": True, "owners": ["a", "b"]},
                real.id: {"is_shared": False, "owners": ["new-owner"]},
            }
        )

        result = await reconcile_agent_ownership(session, ownership_client=client, limit=1)

        assert result == {"checked": 1, "updated": 1, "skipped_shared": 1, "errors": 0}
        row = (
            await session.execute(select(Agent).where(Agent.sub == "reconcile-real-agent"))
        ).scalar_one()
        assert row.owner_sub == "new-owner"

    async def test_lookup_failure_counted_as_error_and_does_not_abort_run(
        self, session: AsyncSession
    ) -> None:
        await _register(session, "reconcile-good")
        # _register with a different sub than _FailingOwnershipClient covers
        # -- use a mixed client: good agent resolves, bad agent raises.
        bad = await _register(session, "reconcile-bad")

        class _MixedClient:
            async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
                if agent_id == bad.id:
                    raise RuntimeError("platform unreachable")
                return {"is_shared": False, "owners": ["still-owner-reconcile-good"]}

        result = await reconcile_agent_ownership(session, ownership_client=_MixedClient())

        assert result == {"checked": 2, "updated": 1, "skipped_shared": 0, "errors": 1}
        row = (
            await session.execute(select(Agent).where(Agent.sub == "reconcile-bad"))
        ).scalar_one()
        assert row.owner_sub == "owner-reconcile-bad"  # untouched

    async def test_multi_owner_result_for_non_shared_agent_counted_as_error(
        self, session: AsyncSession
    ) -> None:
        agent = await _register(session, "reconcile-multi-owner")
        client = _FakeOwnershipClient(
            {agent.id: {"is_shared": False, "owners": ["owner-a", "owner-b"]}}
        )

        result = await reconcile_agent_ownership(session, ownership_client=client)

        assert result == {"checked": 1, "updated": 0, "skipped_shared": 0, "errors": 1}
        row = (
            await session.execute(select(Agent).where(Agent.sub == "reconcile-multi-owner"))
        ).scalar_one()
        assert row.owner_sub == "owner-reconcile-multi-owner"  # untouched

    async def test_zero_owner_result_for_non_shared_agent_counted_as_error(
        self, session: AsyncSession
    ) -> None:
        agent = await _register(session, "reconcile-zero-owner")
        client = _FakeOwnershipClient({agent.id: {"is_shared": False, "owners": []}})

        result = await reconcile_agent_ownership(session, ownership_client=client)

        assert result == {"checked": 1, "updated": 0, "skipped_shared": 0, "errors": 1}

    async def test_never_reconciled_sorts_before_already_reconciled(
        self, session: AsyncSession
    ) -> None:
        """Ordering is by ``owner_reconciled_at`` ASC NULLS FIRST, not
        ``bound_at`` (Argus round-1 BLOCKING fix) -- an agent that has
        never been reconciled must be picked over one already reconciled,
        regardless of which registered first."""
        already_reconciled = await _register(session, "reconcile-already-done")
        never_reconciled = await _register(session, "reconcile-never-done")
        already_reconciled.owner_reconciled_at = datetime.now(UTC)
        await session.commit()
        client = _FakeOwnershipClient(
            {never_reconciled.id: {"is_shared": False, "owners": ["new-owner"]}}
        )

        result = await reconcile_agent_ownership(session, ownership_client=client, limit=1)

        assert result == {"checked": 1, "updated": 1, "skipped_shared": 0, "errors": 0}
        row = (
            await session.execute(select(Agent).where(Agent.sub == "reconcile-never-done"))
        ).scalar_one()
        assert row.owner_sub == "new-owner"

    async def test_repeated_calls_make_forward_progress_across_the_table(
        self, session: AsyncSession
    ) -> None:
        """The bug this fixes: without a cursor that actually advances,
        ``limit=1`` would re-process the SAME agent on every call forever.
        Two calls with ``limit=1`` against two never-reconciled agents must
        reach BOTH of them, not the same one twice."""
        first_agent = await _register(session, "reconcile-progress-a")
        second_agent = await _register(session, "reconcile-progress-b")
        client = _FakeOwnershipClient(
            {
                first_agent.id: {"is_shared": False, "owners": ["owner-a-new"]},
                second_agent.id: {"is_shared": False, "owners": ["owner-b-new"]},
            }
        )

        first_result = await reconcile_agent_ownership(session, ownership_client=client, limit=1)
        second_result = await reconcile_agent_ownership(session, ownership_client=client, limit=1)

        assert first_result == {"checked": 1, "updated": 1, "skipped_shared": 0, "errors": 0}
        assert second_result == {"checked": 1, "updated": 1, "skipped_shared": 0, "errors": 0}
        rows = (
            await session.execute(
                select(Agent.sub, Agent.owner_sub).where(
                    Agent.sub.in_(["reconcile-progress-a", "reconcile-progress-b"])
                )
            )
        ).all()
        assert dict(rows) == {
            "reconcile-progress-a": "owner-a-new",
            "reconcile-progress-b": "owner-b-new",
        }

    async def test_tied_owner_reconciled_at_breaks_ties_by_id_deterministically(
        self, session: AsyncSession
    ) -> None:
        """Argus round-2 SUGGESTION, treated as load-bearing: every agent
        processed within ONE call shares the identical stamped
        ``owner_reconciled_at`` (read once per call, not once per row).
        With three agents tied at the same timestamp and a batch size
        smaller than the tie group, repeated ``limit=2`` calls must return
        a DETERMINISTIC subset each time (ordered by ``id``) -- not an
        arbitrary one that could silently skip an agent in the tied group
        forever, which is exactly the starvation bug this whole cursor
        column exists to prevent."""
        tied_at = datetime.now(UTC)
        agents = [await _register(session, f"reconcile-tied-{i}") for i in range(3)]
        for agent in agents:
            agent.owner_reconciled_at = tied_at
        await session.commit()
        by_id = sorted(agents, key=lambda a: a.id)
        client = _FakeOwnershipClient(
            {agent.id: {"is_shared": False, "owners": [agent.owner_sub]} for agent in agents}
        )

        first_result = await reconcile_agent_ownership(session, ownership_client=client, limit=2)

        assert first_result["checked"] == 2
        # Re-read owner_reconciled_at to see which two agents advanced past
        # `tied_at` on this one call -- must be the two LOWEST ids in the
        # tied group, deterministically, not an arbitrary pair.
        refreshed = (
            await session.execute(
                select(Agent.sub, Agent.owner_reconciled_at).where(
                    Agent.id.in_([a.id for a in agents])
                )
            )
        ).all()
        advanced = {sub for sub, ts in refreshed if ts > tied_at}
        assert advanced == {by_id[0].sub, by_id[1].sub}

    async def test_owner_reconciled_at_is_stamped_even_when_lookup_fails(
        self, session: AsyncSession
    ) -> None:
        """A failing lookup still advances the cursor for that agent (at
        the cost of only retrying it once per full sweep rather than every
        call, per the function's own docstring) -- otherwise a single
        persistently-broken agent would permanently block the front of the
        queue and no other agent could ever be reached."""
        agent = await _register(session, "reconcile-cursor-on-error")

        result = await reconcile_agent_ownership(
            session, ownership_client=_FailingOwnershipClient(), limit=1
        )

        assert result == {"checked": 1, "updated": 0, "skipped_shared": 0, "errors": 1}
        await session.refresh(agent)
        assert agent.owner_reconciled_at is not None

    async def test_limit_is_clamped_to_at_least_one(self, session: AsyncSession) -> None:
        agent = await _register(session, "reconcile-clamped-low")
        client = _FakeOwnershipClient({agent.id: {"is_shared": False, "owners": ["new-owner"]}})

        result = await reconcile_agent_ownership(session, ownership_client=client, limit=0)

        assert result == {"checked": 1, "updated": 1, "skipped_shared": 0, "errors": 0}

    async def test_limit_is_clamped_to_the_max_batch_size(self, session: AsyncSession) -> None:
        agent = await _register(session, "reconcile-clamped-high")
        client = _FakeOwnershipClient({agent.id: {"is_shared": False, "owners": ["new-owner"]}})

        result = await reconcile_agent_ownership(
            session, ownership_client=client, limit=_service.MAX_RECONCILIATION_BATCH_SIZE + 1000
        )

        assert result == {"checked": 1, "updated": 1, "skipped_shared": 0, "errors": 0}
