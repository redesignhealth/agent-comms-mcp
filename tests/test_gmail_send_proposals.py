"""TECH-8951: board side of the ``gmail_send`` proposal kind.

* An open (pending/applying) ``gmail_send`` row is never edited in place by a
  resubmission: an identical retry returns it unchanged, a changed one is a
  409 ``proposal_immutable``. A resubmission after a decision inserts a new row.
* ``GET /proposals/{hold_id}/apply-record`` returns ``owner_email`` and can be
  granted to a kind-scoped reader (``PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS``)
  that sees only ``gmail_send`` records.
* ``gmail_send`` keeps the default 16 KiB action cap.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import pytest_asyncio
from fastmcp.exceptions import ToolError
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.applications import Starlette
from starlette.routing import Route

import plugins
import service
from exceptions import ProposalImmutableError
from models import AuditLog, ProposalHold
from plugins import ProposalApplyOutcome, ProposalVerdict
from scopes import PROPOSAL_APPLY_RECORD_SCOPE
from tests.proposal_judge_fakes import FakeProposalJudge
from tests.test_proposal_endpoint import (
    _ENV_PATCH,
    _OIDC_PATCH,
    _agent_jwt_token,
    _FakeAuthProvider,
    _import_main,
    _interactive_token,
)

pytestmark = pytest.mark.usefixtures("_migrated_schema")

_OWNER = "owner-a@example.com"
_BOT = "paperclip-agent-1"
_GMAIL_ACTION: dict[str, Any] = {
    "target_id": "gmail:followup-acme-1",
    "action_type": "send_email",
    "to": ["pat@acme.example"],
    "cc": [],
    "bcc": [],
    "subject": "Following up",
    "body": "Hi Pat,\n\nThanks for the call.\n",
    "attachments": [{"drive_file_id": "1AbCdEf"}],
}


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE TABLE proposal_holds, proposal_bot_log_seq, audit_log, agents "
                "RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def _gmail_action(**overrides: Any) -> dict[str, Any]:
    return {**_GMAIL_ACTION, **overrides}


async def _submit(
    session: AsyncSession,
    *,
    kind: str = "gmail_send",
    action: dict[str, Any] | None = None,
    rationale: str = "send the follow-up",
    labels: dict[str, str] | None = None,
    judge: FakeProposalJudge | None = None,
) -> dict[str, Any]:
    return await service.create_proposal(
        session,
        kind=kind,
        proposed_by_bot_id=_BOT,
        owner_sub=_OWNER,
        action=action if action is not None else _gmail_action(),
        rationale=rationale,
        confidence="medium",
        importance="medium",
        impact="medium",
        judge=judge if judge is not None else FakeProposalJudge(),
        target_fingerprint="ignored",
        labels=labels,
    )


async def _rows(session: AsyncSession) -> list[ProposalHold]:
    session.expire_all()
    return list(
        (await session.execute(select(ProposalHold).order_by(ProposalHold.created_at)))
        .scalars()
        .all()
    )


class TestGmailSendResubmission:
    async def test_identical_resubmission_returns_the_same_row(self, session: AsyncSession) -> None:
        first = await _submit(session)
        second = await _submit(session)
        assert second["proposal_id"] == first["proposal_id"]
        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].action == _GMAIL_ACTION

    @pytest.mark.parametrize(
        "change",
        [
            {"action": _gmail_action(to=["attacker@evil.example"])},
            {"action": _gmail_action(bcc=["attacker@evil.example"])},
            {"action": _gmail_action(body="different body")},
            {"action": _gmail_action(attachments=[{"drive_file_id": "other"}])},
            {"rationale": "a different rationale"},
            {"labels": {"lane": "other"}},
        ],
    )
    async def test_changed_resubmission_of_pending_row_is_rejected(
        self, session: AsyncSession, change: dict[str, Any]
    ) -> None:
        first = await _submit(session)
        with pytest.raises(ProposalImmutableError) as excinfo:
            await _submit(session, **change)
        assert excinfo.value.hold_id == first["proposal_id"]
        assert excinfo.value.status == "pending"
        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].action == _GMAIL_ACTION
        assert rows[0].rationale == "send the follow-up"
        assert rows[0].labels is None

    async def test_changed_resubmission_of_applying_row_is_rejected(
        self, session: AsyncSession
    ) -> None:
        first = await _submit(session)
        hold = (await _rows(session))[0]
        hold.status = "applying"
        hold.decision_source = "human"
        hold.decided_by_actor_id = _OWNER
        hold.decided_at = datetime.now(UTC)
        await session.commit()

        with pytest.raises(ProposalImmutableError) as excinfo:
            await _submit(session, action=_gmail_action(to=["attacker@evil.example"]))
        assert excinfo.value.status == "applying"
        # An identical retry during the claim window still just returns the row.
        retry = await _submit(session)
        assert retry["proposal_id"] == first["proposal_id"]
        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].action == _GMAIL_ACTION

    async def test_resubmission_after_reject_creates_a_new_row(self, session: AsyncSession) -> None:
        first = await _submit(session)
        await service.decide_proposal(
            session,
            approver_sub=_OWNER,
            hold_id=uuid.UUID(first["proposal_id"]),
            decision="reject",
            decision_note="no",
            judge=FakeProposalJudge(),
        )
        second = await _submit(session, action=_gmail_action(body="v2"))
        assert second["proposal_id"] != first["proposal_id"]
        rows = await _rows(session)
        assert [r.status for r in rows] == ["rejected", "pending"]
        assert rows[0].action == _GMAIL_ACTION

    async def test_resubmission_after_approval_creates_a_new_row(
        self, session: AsyncSession
    ) -> None:
        """The approved (``applied``, ``sent: False``) row is the one
        rh-google-mcp reads; a later resubmission must never touch it."""
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=True, result={"sent": False}, caller_error=None, log_detail=None
            )
        )
        first = await _submit(session, judge=judge)
        decided = await service.decide_proposal(
            session,
            approver_sub=_OWNER,
            hold_id=uuid.UUID(first["proposal_id"]),
            decision="approve",
            decision_note=None,
            judge=judge,
        )
        assert decided["status"] == "applied"

        second = await _submit(session, action=_gmail_action(to=["attacker@evil.example"]))
        assert second["proposal_id"] != first["proposal_id"]
        rows = await _rows(session)
        assert [r.status for r in rows] == ["applied", "pending"]
        assert rows[0].action == _GMAIL_ACTION

    async def test_withdraw_then_resubmit_creates_a_new_row(self, session: AsyncSession) -> None:
        first = await _submit(session)
        await service.withdraw_proposal(
            session,
            hold_id=uuid.UUID(first["proposal_id"]),
            requesting_bot_sub=_BOT,
            reason="changing recipients",
        )
        second = await _submit(session, action=_gmail_action(to=["new@acme.example"]))
        assert second["proposal_id"] != first["proposal_id"]
        rows = await _rows(session)
        assert rows[0].action == _GMAIL_ACTION
        assert rows[1].action["to"] == ["new@acme.example"]

    async def test_auto_approve_verdict_on_identical_retry_still_needs_matching_payload(
        self, session: AsyncSession
    ) -> None:
        """An identical retry re-runs the judge on the unchanged row, exactly
        like any other dedup match; the board never edited the payload."""
        first = await _submit(session)
        judge = FakeProposalJudge(judge_result=ProposalVerdict(approved=False, decision_note=None))
        second = await _submit(session, judge=judge)
        assert second["proposal_id"] == first["proposal_id"]
        assert len(judge.judge_calls) == 1

    async def test_integrity_race_against_changed_payload_is_rejected(
        self,
        session: AsyncSession,
        session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The IntegrityError fallback (a concurrent INSERT won the dedup
        index) applies the same immutability rule as the common path."""
        winner: dict[str, Any] = {}
        real_flush = session.flush
        calls = {"n": 0}

        async def _flush_raising_once() -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                async with session_factory() as other:
                    winner.update(await _submit(other))
                cause = Exception()
                cause.constraint_name = "idx_proposal_holds_pending_dedup"  # type: ignore[attr-defined]
                orig = Exception()
                orig.__cause__ = cause
                raise IntegrityError("duplicate key", params=None, orig=orig)
            await real_flush()

        monkeypatch.setattr(session, "flush", AsyncMock(side_effect=_flush_raising_once))
        with pytest.raises(ProposalImmutableError) as excinfo:
            await _submit(session, action=_gmail_action(to=["attacker@evil.example"]))
        assert excinfo.value.hold_id == winner["proposal_id"]
        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].action == _GMAIL_ACTION

    async def test_other_kinds_still_update_in_place(self, session: AsyncSession) -> None:
        action = {"action_type": "close_ticket", "target_id": "TECH-1"}
        first = await _submit(session, kind="linear_progress_update", action=action)
        second = await _submit(
            session, kind="linear_progress_update", action=action, rationale="changed"
        )
        assert second["proposal_id"] == first["proposal_id"]
        assert (await _rows(session))[0].rationale == "changed"


class TestGmailSendActionCap:
    def test_gmail_send_uses_the_default_16_kib_cap(self) -> None:
        assert "gmail_send" not in service.DOCUMENT_PROPOSAL_KINDS
        assert service.max_proposal_action_bytes("gmail_send") == 16_384
        assert service.MAX_PROPOSAL_ACTION_BYTES == 16_384


class TestProposalOwnerEmail:
    def test_email_shaped_owner_sub_is_the_email(self) -> None:
        assert service.proposal_owner_email("Owner-A@Example.com") == "Owner-A@Example.com"

    def test_non_email_owner_sub_has_no_email(self) -> None:
        assert service.proposal_owner_email("self-owned-bot") is None


class TestMcpErrorMapping:
    async def test_immutable_error_passes_through_as_tool_error(self) -> None:
        from providers.proposals import _map_proposal_errors

        with pytest.raises(ToolError, match="withdraw it and submit a new proposal"):
            async with _map_proposal_errors():
                raise ProposalImmutableError("abc", "pending")


# --- HTTP routes ---------------------------------------------------------------


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest.fixture
def judge(monkeypatch: pytest.MonkeyPatch) -> FakeProposalJudge:
    fake = FakeProposalJudge()
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: fake)
    return fake


@pytest_asyncio.fixture
async def client(
    main: Any, session_factory: async_sessionmaker[AsyncSession], judge: FakeProposalJudge
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    fake_provider = _FakeAuthProvider()
    app = Starlette(
        routes=[
            Route("/proposals", main.submit_proposal, methods=["POST"]),
            Route(
                "/proposals/{hold_id}/apply-record",
                main.get_proposal_apply_record_route,
                methods=["GET"],
            ),
        ]
    )
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(main, "_auth_provider", fake_provider),
        patch.object(main, "_okta_provider", fake_provider.server),
        patch("main.get_session_factory", return_value=session_factory),
    ):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            fake_provider.tokens["bot"] = _agent_jwt_token(
                _BOT, scopes=["comms:proposals:write"], owner_sub=_OWNER
            )
            yield http_client, fake_provider


def _body(**action_overrides: Any) -> dict[str, Any]:
    return {
        "kind": "gmail_send",
        "action": _gmail_action(**action_overrides),
        "rationale": "send the follow-up",
        "confidence": "medium",
        "importance": "medium",
        "impact": "medium",
    }


async def _post(http_client: httpx.AsyncClient, body: dict[str, Any]) -> httpx.Response:
    return await http_client.post("/proposals", json=body, headers={"Authorization": "Bearer bot"})


async def _get_record(
    http_client: httpx.AsyncClient, hold_id: uuid.UUID | str, token: str
) -> httpx.Response:
    return await http_client.get(
        f"/proposals/{hold_id}/apply-record", headers={"Authorization": f"Bearer {token}"}
    )


async def _seed(
    session: AsyncSession,
    *,
    kind: str = "gmail_send",
    owner_sub: str = _OWNER,
    status: str = "applied",
    action: dict[str, Any] | None = None,
) -> ProposalHold:
    hold = ProposalHold(
        kind=kind,
        proposed_by_bot_id=_BOT,
        owner_sub=owner_sub,
        action=action if action is not None else dict(_GMAIL_ACTION),
        rationale="send the follow-up",
        confidence="medium",
        importance="medium",
        impact="medium",
        priority="medium",
        target_fingerprint="n/a:no-pre-existing-target",
        status=status,
    )
    if status != "pending":
        hold.decision_source = "human"
        hold.decided_by_actor_id = owner_sub
        hold.decided_at = datetime.now(UTC)
    session.add(hold)
    await session.commit()
    await session.refresh(hold)
    return hold


def _svc(sub: str, scopes: list[str] | None = None) -> Any:
    return _agent_jwt_token(sub, scopes=[PROPOSAL_APPLY_RECORD_SCOPE] if scopes is None else scopes)


async def _audited(session: AsyncSession, action: str) -> list[str]:
    return list(
        (await session.execute(select(AuditLog.action).where(AuditLog.action == action)))
        .scalars()
        .all()
    )


class TestSubmitRoute:
    async def test_changed_resubmission_is_409_proposal_immutable(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, _ = client
        first = await _post(http_client, _body())
        assert first.status_code == 200
        hold_id = first.json()["proposal_id"]

        retry = await _post(http_client, _body())
        assert retry.status_code == 200
        assert retry.json()["proposal_id"] == hold_id

        changed = await _post(http_client, _body(to=["attacker@evil.example"]))
        assert changed.status_code == 409
        payload = changed.json()
        assert payload["error"] == "proposal_immutable"
        assert payload["hold_id"] == hold_id
        assert payload["status"] == "pending"
        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].action["to"] == ["pat@acme.example"]

    async def test_action_over_16_kib_is_422(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider]
    ) -> None:
        http_client, _ = client
        resp = await _post(http_client, _body(body="x" * 16_384))
        assert resp.status_code == 422
        assert "exceeds 16384 bytes" in resp.json()["detail"]


class TestApplyRecordForGmailSend:
    async def test_approvals_service_sees_owner_email_and_full_shape(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["approvals"] = _svc("agent-comms-approvals")
        hold = await _seed(session)
        resp = await _get_record(http_client, hold.id, "approvals")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {
            "hold_id": str(hold.id),
            "status": "applied",
            "kind": "gmail_send",
            "proposed_by_bot_id": _BOT,
            "owner_sub": _OWNER,
            "owner_email": _OWNER,
            "action": _GMAIL_ACTION,
            "target_id": "gmail:followup-acme-1",
            "action_type": "send_email",
            "rationale": "send the follow-up",
            "decision_source": "human",
            "decided_by_actor_id": _OWNER,
            "decided_at": body["decided_at"],
            "cross_brain": None,
            "approvals": [],
        }
        assert body["decided_at"] is not None

    async def test_non_email_owner_sub_has_null_owner_email(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["approvals"] = _svc("agent-comms-approvals")
        hold = await _seed(session, owner_sub="self-owned-bot", status="pending")
        body = (await _get_record(http_client, hold.id, "approvals")).json()
        assert body["owner_sub"] == "self-owned-bot"
        assert body["owner_email"] is None

    async def test_kind_scoped_sub_reads_only_gmail_send(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv("PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS", "rh-google-mcp=gmail_send")
        provider.tokens["google"] = _svc("rh-google-mcp")
        provider.tokens["approvals"] = _svc("agent-comms-approvals")
        gmail = await _seed(session)
        other = await _seed(
            session,
            kind="arcana_source_add",
            action={"action_type": "source_add", "target_id": "arcana-source:doc-1"},
        )

        ok = await _get_record(http_client, gmail.id, "google")
        assert ok.status_code == 200
        assert ok.json()["owner_email"] == _OWNER

        denied = await _get_record(http_client, other.id, "google")
        assert denied.status_code == 404
        unknown = await _get_record(http_client, uuid.uuid4(), "google")
        assert unknown.status_code == 404
        assert denied.json() == unknown.json()
        assert await _audited(session, "denied.proposal_apply_record_kind_not_allowed")

        # The approvals service keeps reading every kind.
        assert (await _get_record(http_client, other.id, "approvals")).status_code == 200

    async def test_kind_scoped_sub_without_the_scope_is_403(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv("PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS", "rh-google-mcp=gmail_send")
        provider.tokens["google"] = _svc("rh-google-mcp", scopes=["comms:proposals:write"])
        hold = await _seed(session)
        assert (await _get_record(http_client, hold.id, "google")).status_code == 403

    async def test_kind_scoped_sub_is_not_a_reader_by_default(
        self, client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
    ) -> None:
        http_client, provider = client
        provider.tokens["google"] = _svc("rh-google-mcp")
        hold = await _seed(session)
        assert (await _get_record(http_client, hold.id, "google")).status_code == 403

    async def test_kind_restriction_wins_over_the_full_allowlist(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv(
            "PROPOSAL_APPLY_RECORD_ALLOWED_SUBS", "agent-comms-approvals,rh-google-mcp"
        )
        monkeypatch.setenv("PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS", "rh-google-mcp=gmail_send")
        provider.tokens["google"] = _svc("rh-google-mcp")
        other = await _seed(
            session,
            kind="arcana_source_add",
            action={"action_type": "source_add", "target_id": "arcana-source:doc-1"},
        )
        assert (await _get_record(http_client, other.id, "google")).status_code == 404

    async def test_multiple_kinds_per_sub_and_malformed_entries(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv(
            "PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS",
            "svc-a=gmail_send, svc-a=arcana_source_add, svc-b, svc-c=, =gmail_send, svc-d=x=y",
        )
        for sub in ("svc-a", "svc-b", "svc-c", "svc-d"):
            provider.tokens[sub] = _svc(sub)
        gmail = await _seed(session)
        other = await _seed(
            session,
            kind="arcana_source_add",
            action={"action_type": "source_add", "target_id": "arcana-source:doc-1"},
        )
        assert (await _get_record(http_client, gmail.id, "svc-a")).status_code == 200
        assert (await _get_record(http_client, other.id, "svc-a")).status_code == 200
        for sub in ("svc-b", "svc-c", "svc-d"):
            assert (await _get_record(http_client, gmail.id, sub)).status_code == 403

    async def test_interactive_token_never_reads(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, provider = client
        monkeypatch.setenv("PROPOSAL_APPLY_RECORD_KIND_SCOPED_SUBS", f"{_OWNER}=gmail_send")
        provider.tokens["human"] = _interactive_token(_OWNER)
        hold = await _seed(session)
        assert (await _get_record(http_client, hold.id, "human")).status_code == 401
