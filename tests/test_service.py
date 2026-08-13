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
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import service as _service
from exceptions import (
    AccessDeniedError,
    InvalidConversationStateError,
    RateLimitExceededError,
    UnknownConversationTypeError,
)
from models import Agent, AuditLog, Conversation, Participant
from schemas import (
    MAX_ACCEPTED_TYPE_LENGTH,
    MAX_PAYLOAD_BYTES,
    MESSAGE_TYPES,
    PayloadValidationError,
)
from service import (
    CONVERSATION_TTL,
    MAX_CONVERSATION_STARTS_PER_HOUR,
    MAX_MESSAGES_PER_CONVERSATION_PER_HOUR,
    AgentTableOwnershipClient,
    OwnershipClient,
    accept_invite,
    decline_invite,
    get_conversation,
    inbox,
    leave,
    list_agents,
    list_conversations,
    register_agent,
)

# Coverage for MESSAGE_TYPES fitting within MAX_ACCEPTED_TYPES (a precondition
# for sorted(MESSAGE_TYPES) as a default accepted_types below) lives in
# tests/test_schemas.py as a collected test, not a module-level assert here.


async def start_conversation(
    session: AsyncSession, *, ownership_client: OwnershipClient | None = None, **kwargs: Any
) -> Any:
    """Thin wrapper defaulting ``ownership_client`` so every pre-existing
    call site in this file keeps working unchanged — tests that care about
    ownership behavior pass their own fake client explicitly."""
    return await _service.start_conversation(
        session, ownership_client=ownership_client or AgentTableOwnershipClient(session), **kwargs
    )


async def invite(
    session: AsyncSession, *, ownership_client: OwnershipClient | None = None, **kwargs: Any
) -> Any:
    return await _service.invite(
        session, ownership_client=ownership_client or AgentTableOwnershipClient(session), **kwargs
    )


async def post_message(
    session: AsyncSession, *, ownership_client: OwnershipClient | None = None, **kwargs: Any
) -> Any:
    return await _service.post_message(
        session, ownership_client=ownership_client or AgentTableOwnershipClient(session), **kwargs
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
    }
    kwargs.update(overrides)
    return await register_agent(session, **kwargs)


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
        unknown-type check (Argus round 1, security): an oversized list of
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
        "contains an unknown type" (Argus round 1): there is no unknown
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
        """The per-entry length cap (Argus round 2, security): a single
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
        """Boundary-value test (Argus round 3): an entry exactly at
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

    async def test_open_note_as_initial_message_denied(self, session: AsyncSession) -> None:
        """DESIGN.md §9 Axis 2: ``open`` requires boundary_safe=True
        unconditionally, and that must hold for the seq-1 message exactly
        like every later one -- not just messages posted after accept."""
        owner = await _register(session, "owner-open-note")
        target = await _register(session, "target-open-note")

        with pytest.raises(AccessDeniedError) as exc_info:
            await start_conversation(
                session,
                actor_sub=owner.sub,
                initiator_agent_id=owner.id,
                conversation_type="open",
                target_agent_ids=[target.id],
                initial_message={"text": "hello"},
                message_type="note",
            )
        assert exc_info.value.reason == "denied.boundary_crossing"
        # The boundary check runs before any row is created -- a denial
        # here must not leave an orphaned conversation/participant pair
        # with no message (see _enforce_boundary_crossing's docstring).
        rows = (
            (await session.execute(select(Conversation).where(Conversation.created_by == owner.id)))
            .scalars()
            .all()
        )
        assert rows == []

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
        assert "conversation" in result
        assert "participants" in result

        row = await session.get(Participant, (conversation.id, target.id))
        assert row is not None
        assert row.last_read_seq == 0, "invited-only reads must not advance last_read_seq"

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

    async def test_note_from_single_owner_to_shared_crosses_denied(
        self, session: AsyncSession
    ) -> None:
        owner, _target, conversation, client = await self._asymmetric_pair(
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
                ownership_client=client,
            )
        assert exc_info.value.reason == "denied.boundary_crossing"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.boundary_crossing" in actions

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
        assert exc_info.value.reason == "denied.ownership_unverified"

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

    async def test_open_note_denied_unconditionally(self, session: AsyncSession) -> None:
        owner, _target, conversation = await self._active_pair_open(
            session, "bc-open-owner", "bc-open-target"
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
        assert exc_info.value.reason == "denied.boundary_crossing"

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
        be denied via its own denied.unknown_conversation_type action, not
        the misleading denied.boundary_crossing label -- and even a
        boundary_safe message is denied, since is_boundary_crossing_safe's
        default-deny path doesn't special-case boundary_safe for unknown
        types."""
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
        assert exc_info.value.reason == "denied.unknown_conversation_type"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.unknown_conversation_type" in actions
        assert "denied.boundary_crossing" not in actions

    async def test_asymmetric_ownership_lookup_failure_fails_closed(
        self, session: AsyncSession
    ) -> None:
        """The genuine exception path (not the soft-fail-to-empty-set one
        covered elsewhere): a raising ownership_client on an asymmetric
        conversation's non-boundary_safe message denies with
        denied.ownership_unverified, distinct from denied.boundary_crossing."""
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
        assert exc_info.value.reason == "denied.ownership_unverified"
        actions = await _audit_actions(session, conversation.id)
        assert "denied.ownership_unverified" in actions
        assert "denied.boundary_crossing" not in actions


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
    """"tasks-as-conversations": task_assign opens a conversation (assigner
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


# --- inbox -------------------------------------------------------------------------


class TestInbox:
    async def test_empty_state_shape(self, session: AsyncSession) -> None:
        agent = await _register(session, "inbox-empty-1")
        result = await inbox(session, caller_agent_id=agent.id)
        assert result == {"unread": [], "pending_invites": [], "total_count": 0}

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
