"""Tests for 1 MiB proposal actions, 4 MiB transport limit, and SQL projection elision (TECH-7720).

Covers:
- REST 5 MiB request stream limit with 413 request_too_large and no side effects,
  across Content-Length variants: missing (chunked), malformed (ignored ->
  actual bytes govern), deceptive undersize (actual bytes govern), deceptive
  oversize (static early 413), and the exact 5 MiB / 5 MiB + 1 cap boundary
- 4 MiB serialized action limit for document proposal kinds (arcana_source_add/revise)
  vs 16 KiB limit for non-document proposal kinds in both REST and MCP, including
  multi-byte content boundary vectors under the default ``ensure_ascii``
  serialization (an "é"/"中" counts 6 serialized chars, an emoji 12 -- the
  SERIALIZED length is what is measured, never the content's UTF-8 byte size)
- kind-field validation still PRECEDES the per-kind action-size check in both
  REST and MCP (an invalid kind surfaces the kind error, never the action
  error), and a 16 KiB + 1 serialized action is rejected for a non-document
  kind but ACCEPTED for an arcana kind in the same MCP tool
- Bulk memory SQL projection elision:
  - Arcana rows with UTF-8 byte count > 16384 elide action content and add elided_action_fields
  - Arcana rows <= 16384 bytes and non-Arcana rows remain byte-identical and unelided
  - Correct UTF-8 byte and character counts at the exact multi-byte threshold
    (é/中/emoji at exactly 16384 UTF-8 bytes vs one character over)
  - raiseload=True proof: ProposalHold.action is not loaded into Python memory
  - elision still comes from the SQL projection when the session's ORM identity
    map already holds the fully loaded action (the projected column value is
    what the lists return, never the ORM attribute state)
  - REST owner list routes and MCP bot list tools surface the same elided shape
- Single GET (get_proposal_for_bot / proposals_get) and get_proposal_apply_record
  retain the full action and content, with the returned content's sha256 still
  matching the stored digest
- Pagination ordering and has_more flag consistency with elided rows
- Cross-repo (optional, sibling-checkout gated): the REAL agent-comms-approvals
  RHProposalJudge rejects a > 1 MiB UTF-8 content action with
  InvalidProposalActionError field ("content", "too_long") before any hold row
  or audit side effect exists
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from fastmcp import Client
from sqlalchemy import event, select, text
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import defer
from starlette.applications import Starlette
from starlette.routing import Route

import plugins
import service
from exceptions import InvalidProposalActionError
from models import AuditLog, ProposalHold
from plugins import (
    FINGERPRINT_DIGEST,
    ProposalApplyOutcome,
    ProposalFingerprint,
    ProposalVerdict,
)
from scopes import PROPOSAL_APPLY_RECORD_SCOPE
from tests.proposal_judge_fakes import FakeProposalJudge

pytestmark = pytest.mark.usefixtures("_migrated_schema")


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE TABLE proposal_holds, audit_log, agents RESTART IDENTITY CASCADE")
        )
    yield


@pytest.fixture
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture(autouse=True)
def _default_proposal_judge(monkeypatch: pytest.MonkeyPatch) -> FakeProposalJudge:
    fake = FakeProposalJudge(
        supported_proposal_kinds=frozenset(
            {"arcana_source_add", "arcana_source_revise", "linear_progress_update"}
        ),
        fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="fp-test"),
        judge_result=ProposalVerdict(approved=False, decision_note=None),
    )
    monkeypatch.setattr(plugins, "get_proposal_judge", lambda: fake)
    return fake


_MOCK_OIDC_CONFIG = MagicMock()
_OIDC_PATCH = patch(
    "fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration",
    return_value=_MOCK_OIDC_CONFIG,
)
_ENV_PATCH = patch.dict(
    os.environ,
    {
        "OKTA_ISSUER_URL": "https://example.okta.com/oauth2/default",
        "OKTA_CLIENT_ID": "test-id",
        "OKTA_CLIENT_SECRET": "test-secret",
        "BASE_URL": "http://localhost:8080",
        "MCP_JWT_SECRET": "test-jwt-secret",
        "AGENT_JWT_SECRET": "test-agent-jwt-secret-long-enough-for-hs256",
    },
)


def _import_main() -> Any:
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


class _FakeAccessToken:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims


class _FakeAgentOnlyVerifier:
    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") != "agent-jwt":
            return None
        return found


class _FakeInteractiveOnlyProvider:
    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") == "agent-jwt":
            return None
        return found


class _FakeAuthProvider:
    def __init__(self) -> None:
        self.tokens: dict[str, _FakeAccessToken] = {}
        self.server = _FakeInteractiveOnlyProvider(self)
        self.verifiers = [_FakeAgentOnlyVerifier(self)]

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        return self.tokens.get(token)


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest_asyncio.fixture
async def client(
    main: Any, test_session_factory: async_sessionmaker[AsyncSession]
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    fake_provider = _FakeAuthProvider()
    app = Starlette(
        routes=[
            Route("/proposals", main.submit_proposal, methods=["POST"]),
            Route("/proposals/pending", main.list_pending_proposals, methods=["GET"]),
            Route("/proposals/history", main.list_proposal_history, methods=["GET"]),
            Route("/proposals/{proposal_id}", main.get_proposal, methods=["GET"]),
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
        patch("main.get_session_factory", return_value=test_session_factory),
    ):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            yield http_client, fake_provider


def _sha(text_val: str) -> str:
    return hashlib.sha256(text_val.encode("utf-8")).hexdigest()


# ======================================================================
# 0. Unit: service.max_proposal_action_bytes
# ======================================================================


@pytest.mark.parametrize("kind", ["arcana_source_add", "arcana_source_revise"])
def test_max_proposal_action_bytes_document_kinds_get_the_4mib_limit(kind: str) -> None:
    assert service.max_proposal_action_bytes(kind) == 4 * 1024 * 1024
    assert service.max_proposal_action_bytes(kind) == service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES


@pytest.mark.parametrize(
    "kind",
    [
        "linear_progress_update",
        "unknown_kind",
        "",
        "Arcana_Source_Add",  # kinds are matched exactly, case-sensitively
        " arcana_source_add",
        None,
        123,
        b"arcana_source_add",
        ["arcana_source_add"],  # unhashable: must not raise
        {"kind": "arcana_source_add"},
    ],
)
def test_max_proposal_action_bytes_everything_else_keeps_the_16kib_limit(kind: Any) -> None:
    assert service.max_proposal_action_bytes(kind) == service.MAX_PROPOSAL_ACTION_BYTES == 16_384


# ======================================================================
# 1. REST Stream Size and 413 Behavior
# ======================================================================


async def test_rest_stream_size_413_content_length(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    http_client, fake_provider = client
    token_str = "tok-bot-1"
    fake_provider.tokens[token_str] = _FakeAccessToken(
        {
            "iss": "agent-jwt",
            "sub": "bot-1",
            "scopes": ["comms:proposals:write"],
            "owner_sub": "owner-1",
        }
    )
    oversized = 5 * 1024 * 1024 + 1
    resp = await http_client.post(
        "/proposals",
        headers={
            "Authorization": f"Bearer {token_str}",
            "Content-Length": str(oversized),
            "Content-Type": "application/json",
        },
        content=b"{}",
    )
    assert resp.status_code == 413
    assert resp.json() == {"error": "request_too_large"}

    # No side effects: no proposal hold created
    count = (await session.execute(select(ProposalHold))).scalars().all()
    assert len(count) == 0


async def test_rest_stream_size_413_chunked_streaming(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    http_client, fake_provider = client
    token_str = "tok-bot-1"
    fake_provider.tokens[token_str] = _FakeAccessToken(
        {
            "iss": "agent-jwt",
            "sub": "bot-1",
            "scopes": ["comms:proposals:write"],
            "owner_sub": "owner-1",
        }
    )

    chunk_size = 1024 * 1024
    num_chunks = 6  # 6 MiB > 5 MiB

    async def stream_gen() -> AsyncIterator[bytes]:
        for _ in range(num_chunks):
            yield b"a" * chunk_size

    resp = await http_client.post(
        "/proposals",
        headers={
            "Authorization": f"Bearer {token_str}",
            "Content-Type": "application/json",
        },
        content=stream_gen(),
    )
    assert resp.status_code == 413
    assert resp.json() == {"error": "request_too_large"}

    count = (await session.execute(select(ProposalHold))).scalars().all()
    assert len(count) == 0


# ======================================================================
# 2. REST & MCP Action Serialized Limits (16 KiB vs 4 MiB)
# ======================================================================


async def test_rest_action_serialized_limits(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
) -> None:
    http_client, fake_provider = client
    token_str = "tok-bot-1"
    fake_provider.tokens[token_str] = _FakeAccessToken(
        {
            "iss": "agent-jwt",
            "sub": "bot-1",
            "scopes": ["comms:proposals:write"],
            "owner_sub": "owner-1",
        }
    )
    headers = {"Authorization": f"Bearer {token_str}"}

    # Non-arcana: exactly 16384 bytes
    prefix = '{"target_id": "T-1", "action_type": "update", "padding": "'
    suffix = '"}'
    pad_len_16k = 16_384 - len(prefix) - len(suffix)
    action_16k = {"target_id": "T-1", "action_type": "update", "padding": "x" * pad_len_16k}
    assert service.proposal_action_serialized_bytes(action_16k) == 16_384

    resp = await http_client.post(
        "/proposals",
        headers=headers,
        json={
            "kind": "linear_progress_update",
            "action": action_16k,
            "rationale": "r",
            "confidence": "high",
            "importance": "high",
            "impact": "high",
        },
    )
    assert resp.status_code == 200

    # Non-arcana: 16385 bytes -> 422
    action_16k_plus_1 = {
        "target_id": "T-1",
        "action_type": "update",
        "padding": "x" * (pad_len_16k + 1),
    }
    assert service.proposal_action_serialized_bytes(action_16k_plus_1) == 16_385
    resp = await http_client.post(
        "/proposals",
        headers=headers,
        json={
            "kind": "linear_progress_update",
            "action": action_16k_plus_1,
            "rationale": "r",
            "confidence": "high",
            "importance": "high",
            "impact": "high",
        },
    )
    assert resp.status_code == 422
    assert (
        resp.json()["detail"]
        == f"action exceeds {service.MAX_PROPOSAL_ACTION_BYTES} bytes serialized"
    )

    # Arcana: exactly 4 MiB (4_194_304 bytes)
    pad_len_4m = service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES - len(prefix) - len(suffix)
    action_4m = {"target_id": "T-1", "action_type": "update", "padding": "x" * pad_len_4m}
    assert service.proposal_action_serialized_bytes(action_4m) == 4_194_304
    resp = await http_client.post(
        "/proposals",
        headers=headers,
        json={
            "kind": "arcana_source_add",
            "action": action_4m,
            "rationale": "r",
            "confidence": "high",
            "importance": "high",
            "impact": "high",
        },
    )
    assert resp.status_code == 200

    # Arcana: 4 MiB + 1 byte -> 422
    action_4m_plus_1 = {
        "target_id": "T-1",
        "action_type": "update",
        "padding": "x" * (pad_len_4m + 1),
    }
    assert service.proposal_action_serialized_bytes(action_4m_plus_1) == 4_194_305
    resp = await http_client.post(
        "/proposals",
        headers=headers,
        json={
            "kind": "arcana_source_add",
            "action": action_4m_plus_1,
            "rationale": "r",
            "confidence": "high",
            "importance": "high",
            "impact": "high",
        },
    )
    assert resp.status_code == 422
    assert (
        resp.json()["detail"]
        == f"action exceeds {service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES} bytes serialized"
    )


async def _call_mcp_tool(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: Any,
    tool_name: str,
    args: dict[str, Any] | None = None,
) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.proposals.get_access_token", return_value=token),
        patch("providers.proposals.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data


async def test_mcp_action_serialized_limits(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    token = MagicMock()
    token.claims = {
        "iss": "agent-jwt",
        "sub": "bot-1",
        "scopes": ["comms:proposals:write"],
        "owner_sub": "owner-1",
    }
    token.scopes = ["comms:proposals:write"]
    token.client_id = "bot-1"

    prefix = '{"target_id": "T-1", "action_type": "update", "padding": "'
    suffix = '"}'
    pad_len_16k = 16_384 - len(prefix) - len(suffix)
    action_16k = {"target_id": "T-1", "action_type": "update", "padding": "x" * pad_len_16k}
    action_16k_plus_1 = {
        "target_id": "T-1",
        "action_type": "update",
        "padding": "x" * (pad_len_16k + 1),
    }

    pad_len_4m = service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES - len(prefix) - len(suffix)
    action_4m = {"target_id": "T-1", "action_type": "update", "padding": "x" * pad_len_4m}
    action_4m_plus_1 = {
        "target_id": "T-1",
        "action_type": "update",
        "padding": "x" * (pad_len_4m + 1),
    }

    # Non-arcana 16k passes
    res = await _call_mcp_tool(
        main,
        test_session_factory,
        token,
        "proposals_submit",
        {
            "kind": "linear_progress_update",
            "action": action_16k,
            "rationale": "r",
            "confidence": "high",
            "importance": "high",
            "impact": "high",
        },
    )
    assert "proposal_id" in res

    # Non-arcana 16k + 1 fails
    with pytest.raises(Exception) as exc_info:
        await _call_mcp_tool(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "linear_progress_update",
                "action": action_16k_plus_1,
                "rationale": "r",
                "confidence": "high",
                "importance": "high",
                "impact": "high",
            },
        )
    assert (
        f"invalid_request: action exceeds {service.MAX_PROPOSAL_ACTION_BYTES} bytes serialized"
        in str(exc_info.value)
    )

    # Arcana 4M passes
    res = await _call_mcp_tool(
        main,
        test_session_factory,
        token,
        "proposals_submit",
        {
            "kind": "arcana_source_add",
            "action": action_4m,
            "rationale": "r",
            "confidence": "high",
            "importance": "high",
            "impact": "high",
        },
    )
    assert "proposal_id" in res

    # Arcana 4M + 1 fails
    with pytest.raises(Exception) as exc_info:
        await _call_mcp_tool(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "arcana_source_add",
                "action": action_4m_plus_1,
                "rationale": "r",
                "confidence": "high",
                "importance": "high",
                "impact": "high",
            },
        )
    assert (
        "invalid_request: action exceeds "
        f"{service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES} bytes serialized" in str(exc_info.value)
    )


# ======================================================================
# 3. Bulk Memory SQL Projection Elision & Threshold Tests
# ======================================================================


async def test_bulk_memory_elision_across_listings(session: AsyncSession) -> None:
    bot_sub = "bot-elide-test"
    owner_sub = "owner-elide@example.com"

    # Row 1: Non-Arcana with > 16384 byte content -> unelided
    hold_non_arcana = ProposalHold(
        id=uuid.uuid4(),
        kind="linear_progress_update",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={"target_id": "TECH-1", "action_type": "update", "content": "a" * 20000},
        rationale="r1",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp1",
    )

    # Row 2: Arcana with exact 16384 bytes -> unelided
    content_exact_16k = "x" * 16384
    hold_arcana_exact_16k = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_add",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={
            "target_id": "arcana-source:doc-exact",
            "logical_id": "doc-exact",
            "filename": "f.md",
            "audience": "private",
            "sha256": _sha(content_exact_16k),
            "content": content_exact_16k,
        },
        rationale="r2",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp2",
    )

    # Row 3: Arcana with 16385 bytes -> elided
    content_16k_plus_1 = "x" * 16385
    hold_arcana_16k_plus_1 = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_add",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={
            "target_id": "arcana-source:doc-elided",
            "logical_id": "doc-elided",
            "filename": "f.md",
            "audience": "private",
            "sha256": _sha(content_16k_plus_1),
            "content": content_16k_plus_1,
        },
        rationale="r3",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp3",
    )

    # Row 4: Arcana with multi-byte Unicode: 10,000 'é' = 20,000 bytes, 10,000 chars -> elided
    content_unicode = "é" * 10000
    assert len(content_unicode.encode("utf-8")) == 20000
    assert len(content_unicode) == 10000
    hold_arcana_unicode = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_revise",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={
            "target_id": "arcana-source:doc-uni",
            "logical_id": "doc-uni",
            "filename": "f.md",
            "audience": "private",
            "sha256": _sha(content_unicode),
            "content": content_unicode,
        },
        rationale="r4",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp4",
    )

    session.add_all(
        [hold_non_arcana, hold_arcana_exact_16k, hold_arcana_16k_plus_1, hold_arcana_unicode]
    )
    await session.commit()
    session.expunge_all()

    # Test 1: list_pending_proposal_holds
    pending_res = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=10)
    proposals_by_id = {p["proposal_id"]: p for p in pending_res["proposals"]}

    # Non-arcana: full content preserved, elided_action_fields absent
    p1 = proposals_by_id[str(hold_non_arcana.id)]
    assert p1["action"]["content"] == "a" * 20000
    assert "elided_action_fields" not in p1

    # Arcana exact 16384: content preserved, elided_action_fields absent
    p2 = proposals_by_id[str(hold_arcana_exact_16k.id)]
    assert p2["action"]["content"] == content_exact_16k
    assert "elided_action_fields" not in p2

    # Arcana 16385: content elided, all other keys preserved, elided_action_fields populated
    p3 = proposals_by_id[str(hold_arcana_16k_plus_1.id)]
    assert "content" not in p3["action"]
    assert p3["action"]["target_id"] == "arcana-source:doc-elided"
    assert p3["action"]["sha256"] == _sha(content_16k_plus_1)
    assert p3["elided_action_fields"] == {"content": {"utf8_bytes": 16385, "chars": 16385}}

    # Arcana Unicode: content elided, exact byte count and char count reported
    p4 = proposals_by_id[str(hold_arcana_unicode.id)]
    assert "content" not in p4["action"]
    assert p4["action"]["target_id"] == "arcana-source:doc-uni"
    assert p4["action"]["sha256"] == _sha(content_unicode)
    assert p4["elided_action_fields"] == {"content": {"utf8_bytes": 20000, "chars": 10000}}

    # Test 2: list_proposals_for_bot (bot-facing)
    bot_res = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=10
    )
    bot_by_id = {p["proposal_id"]: p for p in bot_res["proposals"]}
    bp3 = bot_by_id[str(hold_arcana_16k_plus_1.id)]
    assert "content" not in bp3["action"]
    assert bp3["elided_action_fields"] == {"content": {"utf8_bytes": 16385, "chars": 16385}}
    bp4 = bot_by_id[str(hold_arcana_unicode.id)]
    assert "content" not in bp4["action"]
    assert bp4["elided_action_fields"] == {"content": {"utf8_bytes": 20000, "chars": 10000}}

    # Test 3: list_proposal_history_for_owner (transition rows to rejected)
    for h in [hold_non_arcana, hold_arcana_exact_16k, hold_arcana_16k_plus_1, hold_arcana_unicode]:
        h_row = await session.get(ProposalHold, h.id)
        assert h_row is not None
        h_row.status = "rejected"
        h_row.decision_source = "human"
        h_row.decided_by_actor_id = "reviewer@example.com"
        h_row.decided_at = service._now()
    await session.commit()
    session.expunge_all()

    hist_res = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=10)
    hist_by_id = {p["proposal_id"]: p for p in hist_res["proposals"]}
    hp3 = hist_by_id[str(hold_arcana_16k_plus_1.id)]
    assert "content" not in hp3["action"]
    assert hp3["elided_action_fields"] == {"content": {"utf8_bytes": 16385, "chars": 16385}}
    hp4 = hist_by_id[str(hold_arcana_unicode.id)]
    assert "content" not in hp4["action"]
    assert hp4["elided_action_fields"] == {"content": {"utf8_bytes": 20000, "chars": 10000}}


# ======================================================================
# 4. Proof of raiseload=True: No Full Content Fetched into Python Memory
# ======================================================================


async def test_raiseload_proof_on_listed_orm_objects(session: AsyncSession) -> None:
    hold = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_add",
        proposed_by_bot_id="bot-proof",
        owner_sub="owner-proof@example.com",
        action={"target_id": "arcana-source:doc", "content": "x" * 20000},
        rationale="proof",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fpproof",
    )
    session.add(hold)
    await session.commit()
    session.expunge_all()

    # Query with defer(ProposalHold.action, raiseload=True)
    subq = select(ProposalHold.id.label("id")).where(ProposalHold.id == hold.id).subquery()
    projected_action, elided_bytes, elided_chars = service._proposal_projected_columns()
    stmt = (
        select(ProposalHold, projected_action, elided_bytes, elided_chars)
        .options(defer(ProposalHold.action, raiseload=True))
        .join(subq, ProposalHold.id == subq.c.id)
    )
    row = (await session.execute(stmt)).one()
    orm_hold, proj_act, elided_b, elided_c = row

    # The projected action has content stripped
    assert "content" not in proj_act
    assert elided_b == 20000
    assert elided_c == 20000

    # Accessing orm_hold.action directly raises InvalidRequestError due to raiseload=True
    with pytest.raises(InvalidRequestError) as exc_info:
        _ = orm_hold.action
    assert "'ProposalHold.action' is not available due to raiseload=True" in str(exc_info.value)


# ======================================================================
# 5. Single Retrieval & Apply Record Retain Full Unelided Content
# ======================================================================


async def test_single_get_and_apply_record_retain_full_content(session: AsyncSession) -> None:
    large_content = "y" * 25000
    sha_val = _sha(large_content)
    hold = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_add",
        proposed_by_bot_id="bot-single",
        owner_sub="owner-single@example.com",
        action={
            "target_id": "arcana-source:doc-single",
            "action_type": "source_add",
            "logical_id": "doc-single",
            "filename": "file.md",
            "audience": "private",
            "content": large_content,
            "sha256": sha_val,
        },
        rationale="single-get",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp-single",
    )
    session.add(hold)
    await session.commit()
    session.expunge_all()

    # 1. get_proposal_for_bot
    bot_dict = await service.get_proposal_for_bot(
        session, hold_id=hold.id, requesting_bot_sub="bot-single"
    )
    assert bot_dict["action"]["content"] == large_content
    assert bot_dict["action"]["sha256"] == sha_val
    assert "elided_action_fields" not in bot_dict

    # 2. get_proposal_apply_record
    apply_record = await service.get_proposal_apply_record(
        session, hold_id=hold.id, requesting_sub="service-applier"
    )
    assert apply_record["action"]["content"] == large_content
    assert apply_record["action"]["sha256"] == sha_val
    assert apply_record["target_id"] == "arcana-source:doc-single"


# ======================================================================
# 6. Pagination Ordering and has_more
# ======================================================================


async def test_pagination_ordering_and_has_more(session: AsyncSession) -> None:
    owner_sub = "owner-page@example.com"
    bot_sub = "bot-page"

    # Create 3 proposals with distinct timestamps
    for i in range(3):
        h = ProposalHold(
            id=uuid.uuid4(),
            kind="arcana_source_add",
            proposed_by_bot_id=bot_sub,
            owner_sub=owner_sub,
            action={"target_id": f"arcana-source:doc-{i}", "content": "c"},
            rationale=f"r-{i}",
            confidence="low",
            importance="low",
            impact="low",
            priority="low",
            status="pending",
            target_fingerprint=f"fp-{i}",
        )
        session.add(h)
        await session.commit()

    # Query with limit=2 -> has_more=True, returns 2 rows
    res = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=2)
    assert len(res["proposals"]) == 2
    assert res["has_more"] is True
    assert res["proposals"][0]["action"]["target_id"] == "arcana-source:doc-0"
    assert res["proposals"][1]["action"]["target_id"] == "arcana-source:doc-1"

    # Query with limit=3 -> has_more=False, returns 3 rows
    res3 = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=3)
    assert len(res3["proposals"]) == 3
    assert res3["has_more"] is False


# ======================================================================
# 7. REST Stream Gate: Content-Length variants and the static 5 MiB cap
# ======================================================================


def _bot_claims(sub: str = "bot-1", owner_sub: str = "owner-1") -> dict[str, Any]:
    return {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": ["comms:proposals:write"],
        "owner_sub": owner_sub,
    }


def _register_bot_token(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    token_str: str = "tok-bot-1",
    claims: dict[str, Any] | None = None,
) -> None:
    _http_client, fake_provider = client
    fake_provider.tokens[token_str] = _FakeAccessToken(claims or _bot_claims())


def _valid_proposal_body(kind: str, action: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "action": action,
        "rationale": "r",
        "confidence": "high",
        "importance": "high",
        "impact": "high",
    }


async def _count_rows(session: AsyncSession, model: Any) -> int:
    return len((await session.execute(select(model))).scalars().all())


async def test_rest_stream_malformed_content_length_is_ignored(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """A Content-Length header that is not an integer is deliberately ignored
    (``int()`` -> ``ValueError`` -> fall through), so a small body streams
    through the actual-byte-count gate and is processed normally -- the
    header is an early-exit optimization only, never a trust boundary."""
    _register_bot_token(client)
    http_client, _provider = client
    resp = await http_client.post(
        "/proposals",
        headers={
            "Authorization": "Bearer tok-bot-1",
            "Content-Length": "not-a-number",
            "Content-Type": "application/json",
        },
        json=_valid_proposal_body(
            "linear_progress_update", {"action_type": "close_ticket", "target_id": "TECH-1"}
        ),
    )
    assert resp.status_code == 200
    assert await _count_rows(session, ProposalHold) == 1


async def test_rest_stream_malformed_content_length_with_oversize_body_is_413(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """An unparseable Content-Length is ignored by the header gate, so the
    actual-byte-count loop must still stop a body over 5 MiB: 413, static
    body, nothing persisted or audited."""
    _register_bot_token(client)
    http_client, _provider = client
    resp = await http_client.post(
        "/proposals",
        headers={
            "Authorization": "Bearer tok-bot-1",
            "Content-Length": "not-a-number",
            "Content-Type": "application/json",
        },
        content=b"a" * (5 * 1024 * 1024 + 1),
    )
    assert resp.status_code == 413
    assert resp.json() == {"error": "request_too_large"}
    assert await _count_rows(session, ProposalHold) == 0
    assert await _count_rows(session, AuditLog) == 0


async def test_rest_stream_deceptive_undersize_content_length_governs_actual_bytes(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """A Content-Length header claiming 10 bytes while the stream delivers
    6 MiB is stopped by the actual-byte-count loop, never by the header --
    the static 5 MiB cap holds against a lying header."""
    _register_bot_token(client)
    http_client, _provider = client
    resp = await http_client.post(
        "/proposals",
        headers={
            "Authorization": "Bearer tok-bot-1",
            "Content-Length": "10",
            "Content-Type": "application/json",
        },
        content=b"a" * (6 * 1024 * 1024),
    )
    assert resp.status_code == 413
    assert resp.json() == {"error": "request_too_large"}
    assert await _count_rows(session, ProposalHold) == 0
    assert await _count_rows(session, AuditLog) == 0


@pytest.mark.parametrize("over_by", [1, 1024 * 1024])
async def test_rest_stream_oversize_content_length_is_a_static_early_413(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    session: AsyncSession,
    over_by: int,
) -> None:
    """A Content-Length header alone over the 5 MiB cap is rejected before a
    single body byte is read, whatever the actual body size -- and nothing
    is persisted or audited."""
    _register_bot_token(client)
    http_client, _provider = client
    resp = await http_client.post(
        "/proposals",
        headers={
            "Authorization": "Bearer tok-bot-1",
            "Content-Length": str(5 * 1024 * 1024 + over_by),
            "Content-Type": "application/json",
        },
        content=b"{}",
    )
    assert resp.status_code == 413
    assert resp.json() == {"error": "request_too_large"}
    assert await _count_rows(session, ProposalHold) == 0
    assert await _count_rows(session, AuditLog) == 0


async def test_rest_stream_exactly_5mib_passes_the_header_gate(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """Exactly 5 MiB (header path) is NOT over the cap: the request streams
    through both gates and fails ordinary body validation instead -- the
    boundary is exclusive (``>``, never ``>=``)."""
    _register_bot_token(client)
    http_client, _provider = client
    # A JSON object padded with trailing whitespace to exactly 5 MiB parses
    # fine, then fails the ordinary kind-field validation.
    body = b"{}" + b" " * (5 * 1024 * 1024 - 2)
    assert len(body) == 5 * 1024 * 1024
    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        content=body,
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_request"
    assert await _count_rows(session, ProposalHold) == 0


async def test_rest_stream_chunked_exactly_5mib_passes_and_one_over_fails(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """The stream-loop gate (no Content-Length header at all, chunked body)
    uses the same exclusive 5 MiB boundary: exactly 5 MiB streams through,
    one byte over is a 413 with no side effects."""
    _register_bot_token(client)
    http_client, _provider = client

    async def exact() -> AsyncIterator[bytes]:
        yield b"{}"
        yield b" " * (5 * 1024 * 1024 - 2)

    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        content=exact(),
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_request"

    async def one_over() -> AsyncIterator[bytes]:
        yield b"{}"
        yield b" " * (5 * 1024 * 1024 - 1)

    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        content=one_over(),
    )
    assert resp.status_code == 413
    assert resp.json() == {"error": "request_too_large"}
    assert await _count_rows(session, ProposalHold) == 0
    assert await _count_rows(session, AuditLog) == 0


# ======================================================================
# 8. REST & MCP parity: kind-first validation order, per-kind limits,
#    and multi-byte serialized boundary vectors
# ======================================================================


@pytest.mark.parametrize(
    "kind",
    ["k" * (service.MAX_PROPOSAL_KIND_LENGTH + 1), "", 12345],
)
async def test_rest_kind_validation_precedes_the_per_kind_action_limit(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    session: AsyncSession,
    kind: Any,
) -> None:
    """A request with BOTH an invalid kind and an over-16 KiB action surfaces
    the KIND error, never the action error -- the kind field is validated
    before the per-kind action-size limit is even computed (the exact order
    the pre-change route already had, now pinned so the per-kind refactor
    cannot reorder it)."""
    _register_bot_token(client)
    http_client, _provider = client
    action = {"action_type": "close_ticket", "target_id": "TECH-1", "padding": "x" * 16_384}
    assert service.proposal_action_serialized_bytes(action) > service.MAX_PROPOSAL_ACTION_BYTES
    body = _valid_proposal_body("linear_progress_update", action)
    body["kind"] = kind
    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        json=body,
    )
    # The kind error must win over the action-size error:
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "kind" in detail
    assert "action exceeds" not in detail
    assert await _count_rows(session, ProposalHold) == 0


async def test_mcp_kind_validation_precedes_the_per_kind_action_limit(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Same order pin for the MCP tool: kind is validated BEFORE the action
    size is checked against the kind's limit. Pre-TECH-7720 the tool checked
    the (single) action limit first, so this request used to fail with the
    action error; the per-kind refactor moved kind first -- REST parity."""
    token = MagicMock()
    token.claims = _bot_claims()
    token.scopes = ["comms:proposals:write"]
    token.client_id = "bot-1"
    action = {"action_type": "close_ticket", "target_id": "TECH-1", "padding": "x" * 16_384}
    assert service.proposal_action_serialized_bytes(action) > service.MAX_PROPOSAL_ACTION_BYTES
    with pytest.raises(Exception) as exc_info:
        await _call_mcp_tool(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            {
                "kind": "k" * (service.MAX_PROPOSAL_KIND_LENGTH + 1),
                "action": action,
                "rationale": "r",
                "confidence": "high",
                "importance": "high",
                "impact": "high",
            },
        )
    assert f"kind exceeds {service.MAX_PROPOSAL_KIND_LENGTH} characters" in str(exc_info.value)
    assert "action exceeds" not in str(exc_info.value)


async def test_mcp_action_limit_is_per_kind(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The SAME 16,385-byte serialized action is rejected for
    ``linear_progress_update`` (16 KiB limit) and ACCEPTED for
    ``arcana_source_add`` (4 MiB document-kind limit) -- the per-kind
    relaxation is live in the MCP tool, not just the REST route."""
    token = MagicMock()
    token.claims = _bot_claims()
    token.scopes = ["comms:proposals:write"]
    token.client_id = "bot-1"
    content = "x" * 17_000  # serialized ~17 KB: over 16 KiB, well under 4 MiB
    action = {
        "target_id": "arcana-source:doc-per-kind",
        "action_type": "source_add",
        "logical_id": "doc-per-kind",
        "filename": "f.md",
        "audience": "private",
        "sha256": _sha(content),
        "content": content,
    }
    serialized = service.proposal_action_serialized_bytes(action)
    assert serialized > service.MAX_PROPOSAL_ACTION_BYTES
    assert serialized <= service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES

    with pytest.raises(Exception) as exc_info:
        await _call_mcp_tool(
            main,
            test_session_factory,
            token,
            "proposals_submit",
            _valid_proposal_body("linear_progress_update", action),
        )
    assert f"action exceeds {service.MAX_PROPOSAL_ACTION_BYTES} bytes serialized" in str(
        exc_info.value
    )

    res = await _call_mcp_tool(
        main,
        test_session_factory,
        token,
        "proposals_submit",
        _valid_proposal_body("arcana_source_add", action),
    )
    assert "proposal_id" in res


def _serialized_boundary_action(char: str, per_char_serialized: int, target: int) -> dict[str, Any]:
    """An action whose ``json.dumps`` (default ``ensure_ascii=True``) length is
    EXACTLY ``target`` bytes, padded with ``char`` (each of which serializes
    to ``per_char_serialized`` ASCII characters) plus an ASCII tail for the
    residue -- multi-byte characters serialize as ``\\uXXXX`` escapes, so an
    "é"/"中" counts 6 and an emoji 12 serialized bytes, never their UTF-8
    byte sizes."""
    assert len(char.encode("utf-8")) > 1, "boundary padding char must be multi-byte"
    base = {"target_id": "T-1", "action_type": "update", "padding": ""}
    base_len = len(json.dumps(base))
    payload = target - base_len
    assert payload > 0
    n, residue = divmod(payload, per_char_serialized)
    action = {
        "target_id": "T-1",
        "action_type": "update",
        "padding": (char * n) + ("x" * residue),
    }
    assert service.proposal_action_serialized_bytes(action) == target
    return action


@pytest.mark.parametrize(
    ("char", "per_char_serialized"),
    [("é", 6), ("中", 6), ("😀", 12)],
)
async def test_rest_arcana_serialized_boundary_multibyte(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    char: str,
    per_char_serialized: int,
) -> None:
    """The 4 MiB document-kind limit is measured on the SERIALIZED
    (``ensure_ascii``) action, where a multi-byte character costs 6/12
    ASCII escape bytes -- exactly 4 MiB serialized is accepted and one byte
    over is rejected with the 4 MiB detail, for é, 中 and emoji padding."""
    _register_bot_token(client)
    http_client, _provider = client

    exact = _serialized_boundary_action(char, per_char_serialized, 4 * 1024 * 1024)
    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        json=_valid_proposal_body("arcana_source_add", exact),
    )
    assert resp.status_code == 200

    over = dict(exact)
    over["padding"] = over["padding"] + "x"
    assert service.proposal_action_serialized_bytes(over) == 4 * 1024 * 1024 + 1
    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        json=_valid_proposal_body("arcana_source_add", over),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == (
        f"action exceeds {service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES} bytes serialized"
    )


async def test_rest_arcana_1mib_utf8_content_fits_the_4mib_serialized_budget(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    session: AsyncSession,
) -> None:
    """The motivating case end to end: an action carrying EXACTLY 1 MiB of
    UTF-8 content in the worst case (emoji, 4 bytes per character) plus the
    real arcana metadata fields serializes well under the 4 MiB document
    budget, is accepted, and the full content round-trips through the single
    GET route byte-exactly with its digest intact."""
    _register_bot_token(client)
    http_client, _provider = client
    content = "😀" * 262_144
    assert len(content.encode("utf-8")) == 1_048_576
    action = {
        "target_id": "arcana-source:doc-emoji",
        "action_type": "source_add",
        "logical_id": "doc-emoji",
        "filename": "doc.md",
        "audience": "private",
        "sha256": _sha(content),
        "content": content,
    }
    serialized = service.proposal_action_serialized_bytes(action)
    assert serialized > service.MAX_PROPOSAL_ACTION_BYTES
    assert serialized <= service.MAX_DOCUMENT_PROPOSAL_ACTION_BYTES

    resp = await http_client.post(
        "/proposals",
        headers={"Authorization": "Bearer tok-bot-1"},
        json=_valid_proposal_body("arcana_source_add", action),
    )
    assert resp.status_code == 200
    proposal_id = resp.json()["proposal_id"]

    # Full single GET: unelided, byte-exact content, digest intact.
    get_resp = await http_client.get(
        f"/proposals/{proposal_id}", headers={"Authorization": "Bearer tok-bot-1"}
    )
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["action"]["content"] == content
    assert body["action"]["sha256"] == _sha(content)
    assert hashlib.sha256(body["action"]["content"].encode("utf-8")).hexdigest() == _sha(content)
    assert "elided_action_fields" not in body


# ======================================================================
# 9. REST + MCP list surfaces: same elided shape as the service lists
# ======================================================================


def _register_interactive_token(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    token_str: str,
    owner_email: str,
) -> None:
    _http_client, fake_provider = client
    fake_provider.tokens[token_str] = _FakeAccessToken(
        {"iss": "https://agent-comms.example/mcp", "email": owner_email}
    )


def _seed_arcana_row(
    session: AsyncSession,
    *,
    bot_sub: str,
    owner_sub: str,
    content: str,
    logical_id: str,
    status: str = "pending",
) -> ProposalHold:
    hold = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_add",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={
            "target_id": f"arcana-source:{logical_id}",
            "action_type": "source_add",
            "logical_id": logical_id,
            "filename": "doc.md",
            "audience": "private",
            "sha256": _sha(content),
            "content": content,
        },
        rationale="seed",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status=status,
        target_fingerprint=f"fp-{logical_id}",
    )
    session.add(hold)
    return hold


async def _transition_to_rejected(session: AsyncSession, hold_id: uuid.UUID) -> None:
    row = await session.get(ProposalHold, hold_id)
    assert row is not None
    row.status = "rejected"
    row.decision_source = "human"
    row.decided_by_actor_id = "reviewer@example.com"
    row.decided_at = service._now()
    await session.commit()
    session.expunge_all()


async def test_rest_owner_list_routes_surface_elision_and_single_get_does_not(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """REST parity for the two human-facing list routes: the elided shape the
    service lists produce is what the routes return, while the bot-facing
    single GET route keeps returning the full unelided action."""
    http_client, _provider = client
    owner_sub = "owner-rest@example.com"
    bot_sub = "bot-rest"
    content = "é" * 8_193  # 16,386 UTF-8 bytes, 8,193 chars -> elided
    hold = _seed_arcana_row(
        session, bot_sub=bot_sub, owner_sub=owner_sub, content=content, logical_id="doc-rest"
    )
    await session.commit()
    session.expunge_all()
    _register_interactive_token(client, "tok-human", owner_sub)

    resp = await http_client.get(
        "/proposals/pending", headers={"Authorization": "Bearer tok-human"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["has_more"] is False
    assert len(body["proposals"]) == 1
    proposal = body["proposals"][0]
    assert "content" not in proposal["action"]
    assert proposal["action"]["logical_id"] == "doc-rest"
    assert proposal["elided_action_fields"] == {"content": {"utf8_bytes": 16_386, "chars": 8_193}}

    # The bot-facing single GET route is NOT elided (full action + digest).
    _register_bot_token(client, "tok-bot-rest", _bot_claims(sub=bot_sub, owner_sub=owner_sub))
    get_resp = await http_client.get(
        f"/proposals/{hold.id}", headers={"Authorization": "Bearer tok-bot-rest"}
    )
    assert get_resp.status_code == 200
    get_body = get_resp.json()
    assert get_body["action"]["content"] == content
    assert get_body["action"]["sha256"] == _sha(content)
    assert "elided_action_fields" not in get_body

    # The history route elides terminal rows the same way.
    await _transition_to_rejected(session, hold.id)
    resp = await http_client.get(
        "/proposals/history", headers={"Authorization": "Bearer tok-human"}
    )
    assert resp.status_code == 200
    hist = resp.json()["proposals"]
    assert len(hist) == 1
    assert "content" not in hist[0]["action"]
    assert hist[0]["elided_action_fields"] == {"content": {"utf8_bytes": 16_386, "chars": 8_193}}


async def test_mcp_bot_list_tools_surface_elision_and_get_does_not(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    session: AsyncSession,
) -> None:
    """MCP parity for the bot-facing surfaces: ``proposals_list_pending``
    returns the elided shape; ``proposals_list_history`` elides terminal rows;
    ``proposals_get`` returns the full unelided action."""
    bot_sub = "bot-mcp-list"
    owner_sub = "owner-mcp-list@example.com"
    content = "😀" * 4_097  # 16,388 UTF-8 bytes, 4,097 chars -> elided
    hold = _seed_arcana_row(
        session, bot_sub=bot_sub, owner_sub=owner_sub, content=content, logical_id="doc-mcp"
    )
    await session.commit()
    session.expunge_all()

    token = MagicMock()
    token.claims = _bot_claims(sub=bot_sub, owner_sub=owner_sub)
    token.scopes = ["comms:proposals:write"]
    token.client_id = bot_sub

    pending = await _call_mcp_tool(
        main, test_session_factory, token, "proposals_list_pending", {"limit": 50}
    )
    assert len(pending["proposals"]) == 1
    proposal = pending["proposals"][0]
    assert "content" not in proposal["action"]
    assert proposal["elided_action_fields"] == {"content": {"utf8_bytes": 16_388, "chars": 4_097}}

    single = await _call_mcp_tool(
        main, test_session_factory, token, "proposals_get", {"proposal_id": str(hold.id)}
    )
    assert single["action"]["content"] == content
    assert single["action"]["sha256"] == _sha(content)
    assert "elided_action_fields" not in single

    await _transition_to_rejected(session, hold.id)
    history = await _call_mcp_tool(
        main, test_session_factory, token, "proposals_list_history", {"limit": 50}
    )
    assert len(history["proposals"]) == 1
    assert "content" not in history["proposals"][0]["action"]
    assert history["proposals"][0]["elided_action_fields"] == {
        "content": {"utf8_bytes": 16_388, "chars": 4_097}
    }


# ======================================================================
# 10. Exact multi-byte elision threshold: 16384 bytes is the boundary
# ======================================================================


async def test_elision_threshold_matrix_multibyte_across_all_three_lists(
    session: AsyncSession,
) -> None:
    """The SQL elision boundary is OCTETS of the content string, not
    characters: exactly 16,384 UTF-8 bytes (however many characters that is)
    stays unelided, one character over elides with exact byte AND character
    counts -- for é (2 bytes), 中 (3 bytes) and emoji (4 bytes), across all
    three list functions, with the single getters still returning the full
    content whose digest matches."""
    vectors: list[tuple[str, tuple[int, int] | None]] = [
        ("é" * 8_192, None),  # exactly 16,384 bytes -> unelided
        ("é" * 8_193, (16_386, 8_193)),
        ("中" * 5_461 + "a", None),  # 5,461*3 + 1 = exactly 16,384 bytes
        ("中" * 5_462, (16_386, 5_462)),
        ("😀" * 4_096, None),  # exactly 16,384 bytes
        ("😀" * 4_097, (16_388, 4_097)),
    ]
    bot_sub = "bot-threshold"
    owner_sub = "owner-threshold@example.com"
    holds: list[ProposalHold] = []
    for i, (content, _expected) in enumerate(vectors):
        holds.append(
            _seed_arcana_row(
                session,
                bot_sub=bot_sub,
                owner_sub=owner_sub,
                content=content,
                logical_id=f"doc-thr-{i}",
            )
        )
    await session.commit()
    session.expunge_all()

    def _assert_shape(
        proposal: dict[str, Any], content: str, expected: tuple[int, int] | None
    ) -> None:
        if expected is None:
            assert proposal["action"]["content"] == content
            assert "elided_action_fields" not in proposal
        else:
            assert "content" not in proposal["action"]
            assert proposal["action"]["sha256"] == _sha(content)
            assert proposal["elided_action_fields"] == {
                "content": {"utf8_bytes": expected[0], "chars": expected[1]}
            }

    pending = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=50)
    pending_by_id = {p["proposal_id"]: p for p in pending["proposals"]}
    assert len(pending_by_id) == len(vectors)
    bot_listed = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=50
    )
    bot_by_id = {p["proposal_id"]: p for p in bot_listed["proposals"]}
    assert len(bot_by_id) == len(vectors)
    for hold, (content, expected) in zip(holds, vectors, strict=True):
        _assert_shape(pending_by_id[str(hold.id)], content, expected)
        _assert_shape(bot_by_id[str(hold.id)], content, expected)

    for hold in holds:
        await _transition_to_rejected(session, hold.id)
    history = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=50)
    history_by_id = {p["proposal_id"]: p for p in history["proposals"]}
    assert len(history_by_id) == len(vectors)
    for hold, (content, expected) in zip(holds, vectors, strict=True):
        _assert_shape(history_by_id[str(hold.id)], content, expected)

    # Full getters: every elided row still reads back byte-exactly, digest intact.
    for hold, (content, expected) in zip(holds, vectors, strict=True):
        if expected is None:
            continue
        apply_record = await service.get_proposal_apply_record(
            session, hold_id=hold.id, requesting_sub="service-applier"
        )
        assert apply_record["action"]["content"] == content
        assert apply_record["action"]["sha256"] == _sha(content)
        round_trip = apply_record["action"]["content"]
        assert hashlib.sha256(round_trip.encode("utf-8")).hexdigest() == _sha(content)
        bot_get = await service.get_proposal_for_bot(
            session, hold_id=hold.id, requesting_bot_sub=bot_sub
        )
        assert bot_get["action"]["content"] == content
        assert bot_get["action"]["sha256"] == _sha(content)
        assert "elided_action_fields" not in bot_get


async def test_elision_survives_a_fully_loaded_orm_identity_map(
    session: AsyncSession,
) -> None:
    """The lists' elided output must come from the SQL projection, never from
    ORM attribute state. A session whose identity map ALREADY holds the fully
    loaded ``action`` is exactly the state in which a raiseload-based proof is
    a false positive (a loaded attribute does not raise on access), so the
    pin has to be on the returned dict: all three list functions, called in
    that same session, still return the elided action + counts."""
    bot_sub = "bot-identity"
    owner_sub = "owner-identity@example.com"
    elided_content = "é" * 8_193
    small_content = "x" * 100
    elided_hold = _seed_arcana_row(
        session,
        bot_sub=bot_sub,
        owner_sub=owner_sub,
        content=elided_content,
        logical_id="doc-im-elided",
    )
    small_hold = _seed_arcana_row(
        session,
        bot_sub=bot_sub,
        owner_sub=owner_sub,
        content=small_content,
        logical_id="doc-im-small",
    )
    await session.commit()
    session.expunge_all()

    # Load BOTH rows fully into this session's identity map first.
    full_elided = await session.get(ProposalHold, elided_hold.id)
    full_small = await session.get(ProposalHold, small_hold.id)
    assert full_elided is not None and full_small is not None
    assert full_elided.action["content"] == elided_content  # identity map holds the FULL action
    assert full_small.action["content"] == small_content

    pending = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=50)
    pending_by_id = {p["proposal_id"]: p for p in pending["proposals"]}
    p = pending_by_id[str(elided_hold.id)]
    assert "content" not in p["action"]
    assert p["elided_action_fields"] == {"content": {"utf8_bytes": 16_386, "chars": 8_193}}
    assert pending_by_id[str(small_hold.id)]["action"]["content"] == small_content
    assert "elided_action_fields" not in pending_by_id[str(small_hold.id)]

    # A second list call in the same (now busier) session is stable.
    pending_again = await service.list_pending_proposal_holds(
        session, owner_sub=owner_sub, limit=50
    )
    assert pending_again == pending

    bot_listed = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=50
    )
    bot_by_id = {p["proposal_id"]: p for p in bot_listed["proposals"]}
    assert "content" not in bot_by_id[str(elided_hold.id)]["action"]
    assert bot_by_id[str(elided_hold.id)]["elided_action_fields"] == {
        "content": {"utf8_bytes": 16_386, "chars": 8_193}
    }

    for hold in (elided_hold, small_hold):
        await _transition_to_rejected(session, hold.id)
    history = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=50)
    history_by_id = {p["proposal_id"]: p for p in history["proposals"]}
    assert "content" not in history_by_id[str(elided_hold.id)]["action"]
    assert history_by_id[str(elided_hold.id)]["elided_action_fields"] == {
        "content": {"utf8_bytes": 16_386, "chars": 8_193}
    }
    assert history_by_id[str(small_hold.id)]["action"]["content"] == small_content


# ======================================================================
# 11. Pagination with elided rows
# ======================================================================


async def test_pagination_with_elided_rows(session: AsyncSession) -> None:
    """``has_more``/ordering stay correct when every row on the page is
    elided: the limit+1 keyset subquery drives the flag, the projected
    columns ride along, and neither the flag nor the ordering can tell an
    elided page from an unelided one."""
    bot_sub = "bot-page-elided"
    owner_sub = "owner-page-elided@example.com"
    holds: list[ProposalHold] = []
    for i in range(3):
        holds.append(
            _seed_arcana_row(
                session,
                bot_sub=bot_sub,
                owner_sub=owner_sub,
                content="é" * (8_193 + i),  # every row elided, distinct sizes
                logical_id=f"doc-page-{i}",
            )
        )
        await session.commit()  # distinct created_at per row

    res = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=2)
    assert res["has_more"] is True
    assert len(res["proposals"]) == 2
    assert [p["action"]["logical_id"] for p in res["proposals"]] == ["doc-page-0", "doc-page-1"]
    for p in res["proposals"]:
        assert "content" not in p["action"]
        assert "elided_action_fields" in p

    res3 = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=3)
    assert res3["has_more"] is False
    assert len(res3["proposals"]) == 3

    bot_res = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=2
    )
    assert bot_res["has_more"] is True
    assert len(bot_res["proposals"]) == 2
    assert all("elided_action_fields" in p for p in bot_res["proposals"])

    for hold in holds:
        await _transition_to_rejected(session, hold.id)
    hist = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=2)
    assert hist["has_more"] is True
    assert len(hist["proposals"]) == 2
    # History is newest-first.
    assert [p["action"]["logical_id"] for p in hist["proposals"]] == ["doc-page-2", "doc-page-1"]
    assert all("elided_action_fields" in p for p in hist["proposals"])
    hist3 = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=3)
    assert hist3["has_more"] is False
    assert len(hist3["proposals"]) == 3


async def _seed_tied_rows(
    session: AsyncSession,
    *,
    bot_sub: str,
    owner_sub: str,
    ids: list[uuid.UUID],
    created_at: Any,
) -> None:
    """Insert one elided Arcana row per id, in the given insertion order, all
    sharing the SAME explicit ``created_at`` so only the ``id`` tie-breaker can
    order them."""
    for hold_id in ids:
        hold = _seed_arcana_row(
            session,
            bot_sub=bot_sub,
            owner_sub=owner_sub,
            content="é" * 8_193,
            logical_id=f"doc-tie-{hold_id.int}",
        )
        hold.id = hold_id
        hold.created_at = created_at
    await session.commit()
    session.expunge_all()


def _logical_ids(res: dict[str, Any]) -> list[str]:
    return [p["action"]["logical_id"] for p in res["proposals"]]


async def test_equal_created_at_orders_by_id_in_pending_and_bot_lists(
    session: AsyncSession,
) -> None:
    """Rows with an identical ``created_at`` page deterministically, ``id``
    ascending (the same direction as the ``created_at`` ascending order), in
    both the ``limit + 1`` subquery and the outer query -- so a short page is
    always a prefix of the full order and ``has_more`` is consistent."""
    bot_sub, owner_sub = "bot-tie-asc", "owner-tie-asc@example.com"
    ids = [uuid.UUID(int=n) for n in (1, 2, 3, 4)]
    tie_ts = service._now()
    # Insert in DESCENDING id order, so heap/insertion order disagrees with the
    # expected order.
    await _seed_tied_rows(
        session, bot_sub=bot_sub, owner_sub=owner_sub, ids=ids[::-1], created_at=tie_ts
    )
    expected = [f"doc-tie-{i.int}" for i in ids]

    for lister in (
        lambda limit: service.list_pending_proposal_holds(
            session, owner_sub=owner_sub, limit=limit
        ),
        lambda limit: service.list_proposals_for_bot(
            session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=limit
        ),
    ):
        full = await lister(4)
        assert _logical_ids(full) == expected
        assert full["has_more"] is False
        page = await lister(2)
        assert _logical_ids(page) == expected[:2]
        assert page["has_more"] is True
        page3 = await lister(3)
        assert _logical_ids(page3) == expected[:3]
        assert page3["has_more"] is True


async def test_equal_created_at_orders_by_id_descending_in_history_list(
    session: AsyncSession,
) -> None:
    """History is newest-first, so the tie-breaker is ``id`` DESCENDING in both
    the ``limit + 1`` subquery and the outer query."""
    bot_sub, owner_sub = "bot-tie-desc", "owner-tie-desc@example.com"
    ids = [uuid.UUID(int=n) for n in (1, 2, 3, 4)]
    tie_ts = service._now()
    # Insert in ASCENDING id order (the opposite of the expected order).
    await _seed_tied_rows(session, bot_sub=bot_sub, owner_sub=owner_sub, ids=ids, created_at=tie_ts)
    for hold_id in ids:
        await _transition_to_rejected(session, hold_id)
    expected = [f"doc-tie-{i.int}" for i in ids[::-1]]

    full = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=4)
    assert _logical_ids(full) == expected
    assert full["has_more"] is False
    page = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=2)
    assert _logical_ids(page) == expected[:2]
    assert page["has_more"] is True
    page3 = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=3)
    assert _logical_ids(page3) == expected[:3]
    assert page3["has_more"] is True


async def test_elision_threshold_is_its_own_constant_not_the_validation_limit(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The projection threshold is ``DOCUMENT_PROPOSAL_CONTENT_ELISION_BYTES``
    (16,384), decoupled from ``MAX_PROPOSAL_ACTION_BYTES``: moving the
    validation limit does not move where listings start eliding."""
    assert service.DOCUMENT_PROPOSAL_CONTENT_ELISION_BYTES == 16_384
    monkeypatch.setattr(service, "MAX_PROPOSAL_ACTION_BYTES", 100)
    bot_sub, owner_sub = "bot-const", "owner-const@example.com"
    at_threshold = _seed_arcana_row(
        session, bot_sub=bot_sub, owner_sub=owner_sub, content="a" * 16_384, logical_id="doc-at"
    )
    over_threshold = _seed_arcana_row(
        session, bot_sub=bot_sub, owner_sub=owner_sub, content="a" * 16_385, logical_id="doc-over"
    )
    await session.commit()
    session.expunge_all()
    res = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=10)
    by_id = {p["proposal_id"]: p for p in res["proposals"]}
    assert by_id[str(at_threshold.id)]["action"]["content"] == "a" * 16_384
    assert "elided_action_fields" not in by_id[str(at_threshold.id)]
    assert "content" not in by_id[str(over_threshold.id)]["action"]
    assert by_id[str(over_threshold.id)]["elided_action_fields"] == {
        "content": {"utf8_bytes": 16_385, "chars": 16_385}
    }


# ======================================================================
# 12. Cross-repo: the REAL agent-comms-approvals judge (optional,
#     gated on a sibling checkout of that repo)
# ======================================================================


def _aca_checkout_root() -> Path | None:
    """The sibling agent-comms-approvals worktree this test was authored
    against (e.g. ``aca-tech7720``), or ``None`` when no sibling checkout
    exists (CI on this repo alone)."""
    repos_dir = Path(__file__).resolve().parents[2]
    for name in ("aca-tech7720", "aca"):
        candidate = repos_dir / name
        if (candidate / "rh_comms_plugins" / "proposal_judge.py").is_file():
            return candidate
    return None


@pytest.fixture
def aca_overlay(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Overlay a sibling agent-comms-approvals checkout onto ``sys.path`` for
    ONE test, then fully undo it. ``sys.path`` is replaced through
    ``monkeypatch`` (restored on teardown) and the checkout is APPENDED, never
    prepended, so this repo's own root keeps winning for shared top-level
    module names; every ``rh_comms_plugins*`` module imported through the
    overlay is evicted afterwards so nothing leaks into other tests. Skips
    when no sibling checkout exists (CI on this repo alone)."""
    aca_root = _aca_checkout_root()
    if aca_root is None:
        pytest.skip(
            "no sibling agent-comms-approvals checkout (e.g. aca-tech7720) found -- "
            "cross-repo real-judge test unavailable in this environment"
        )
    monkeypatch.setattr(sys, "path", [*sys.path, str(aca_root)])
    importlib.invalidate_caches()
    already_imported = {n for n in sys.modules if n.split(".")[0] == "rh_comms_plugins"}
    yield aca_root
    for name in [n for n in sys.modules if n.split(".")[0] == "rh_comms_plugins"]:
        if name not in already_imported:
            del sys.modules[name]


async def test_real_judge_oversize_content_rejected_before_any_side_effect(
    session: AsyncSession, aca_overlay: Path
) -> None:
    """The real judge (agent-comms-approvals' ``RHProposalJudge``, no fakes)
    rejects a > 1 MiB UTF-8 content action through the board's own
    ``create_proposal`` with ``InvalidProposalActionError`` field
    ``("content", "too_long")`` -- BEFORE the rate-limit attempt marker is
    audited and before any hold row is inserted, so there is no side effect
    at all. Uses a byte-boundary vector (524,289 code points, 1,048,577
    UTF-8 bytes) that passes the contracts' cheap code-point Field max, so
    it is specifically the byte-ceiling validator that fires."""
    proposal_judge = importlib.import_module("rh_comms_plugins.proposal_judge")
    judge = proposal_judge.RHProposalJudge()

    oversize = "é" * 524_288 + "a"
    assert len(oversize.encode("utf-8")) == 1_048_577
    assert len(oversize) < 1_048_576  # under the cheap code-point Field max
    action = {
        "action_type": "source_add",
        "logical_id": "doc-real",
        "target_id": "arcana-source:doc-real",
        "audience": "private",
        "filename": "doc.md",
        "content": oversize,
        "sha256": "0" * 64,
    }

    with pytest.raises(InvalidProposalActionError) as exc_info:
        await service.create_proposal(
            session,
            kind="arcana_source_add",
            proposed_by_bot_id="bot-real",
            owner_sub="owner-real@example.com",
            action=action,
            rationale="r",
            confidence="high",
            importance="high",
            impact="high",
            judge=judge,
            target_fingerprint="",
        )

    assert exc_info.value.field_errors == (("content", "too_long"),)
    assert str(exc_info.value) == "invalid arcana_source_add action: content: too_long"
    # classify() runs before the rate-limit marker is audited and before
    # any insert: zero holds, zero audit rows.
    assert await _count_rows(session, ProposalHold) == 0
    assert await _count_rows(session, AuditLog) == 0

    # The exactly-1 MiB vector classifies cleanly through the same real
    # judge -- side-effect-free, server-derived priority.
    exact = "é" * 524_288
    assert len(exact.encode("utf-8")) == 1_048_576
    exact_action = {
        "action_type": "source_add",
        "logical_id": "doc-real",
        "target_id": "arcana-source:doc-real",
        "audience": "private",
        "filename": "doc.md",
        "content": exact,
        "sha256": _sha(exact),
    }
    classification = judge.classify("arcana_source_add", exact_action)
    assert classification.priority == "medium"


# ======================================================================
# 13. Scoping: the projection's keyset join does not widen visibility
# ======================================================================


async def test_lists_stay_owner_and_bot_scoped_with_elided_rows(session: AsyncSession) -> None:
    """TECH-7720 swapped each list's single-query select for a keyset
    subquery JOIN riding next to the projected columns -- this pins that the
    join did not widen scope: an owner who is neither the hold's owner nor a
    cross-brain required owner sees ZERO rows in both owner-facing lists, a
    different bot sees ZERO rows in the bot-facing list, while the owning
    owner/bot still see their elided row."""
    owner_a = "owner-scope-a@example.com"
    owner_b = "owner-scope-b@example.com"
    bot_a = "bot-scope-a"
    bot_b = "bot-scope-b"
    elided_hold = _seed_arcana_row(
        session,
        bot_sub=bot_a,
        owner_sub=owner_a,
        content="é" * 8_193,  # 16,386 UTF-8 bytes, 8,193 chars -> elided
        logical_id="doc-scope-a",
    )
    other_hold = _seed_arcana_row(
        session,
        bot_sub=bot_b,
        owner_sub=owner_b,
        content="x" * 100,  # unelided
        logical_id="doc-scope-b",
    )
    await session.commit()
    session.expunge_all()

    a_pending = await service.list_pending_proposal_holds(session, owner_sub=owner_a, limit=50)
    assert [p["proposal_id"] for p in a_pending["proposals"]] == [str(elided_hold.id)]
    assert "content" not in a_pending["proposals"][0]["action"]
    assert a_pending["proposals"][0]["elided_action_fields"] == {
        "content": {"utf8_bytes": 16_386, "chars": 8_193}
    }

    b_pending = await service.list_pending_proposal_holds(session, owner_sub=owner_b, limit=50)
    assert [p["proposal_id"] for p in b_pending["proposals"]] == [str(other_hold.id)]
    assert b_pending["proposals"][0]["action"]["content"] == "x" * 100
    assert "elided_action_fields" not in b_pending["proposals"][0]

    a_bot = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_a, statuses=["pending"], limit=50
    )
    assert [p["proposal_id"] for p in a_bot["proposals"]] == [str(elided_hold.id)]
    b_bot = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_b, statuses=["pending"], limit=50
    )
    assert [p["proposal_id"] for p in b_bot["proposals"]] == [str(other_hold.id)]

    for hold in (elided_hold, other_hold):
        await _transition_to_rejected(session, hold.id)
    a_hist = await service.list_proposal_history_for_owner(session, owner_sub=owner_a, limit=50)
    assert [p["proposal_id"] for p in a_hist["proposals"]] == [str(elided_hold.id)]
    assert "content" not in a_hist["proposals"][0]["action"]
    assert a_hist["proposals"][0]["elided_action_fields"] == {
        "content": {"utf8_bytes": 16_386, "chars": 8_193}
    }
    b_hist = await service.list_proposal_history_for_owner(session, owner_sub=owner_b, limit=50)
    assert [p["proposal_id"] for p in b_hist["proposals"]] == [str(other_hold.id)]


# ======================================================================
# 14. The is_string guard: non-string content is never elided
# ======================================================================


async def test_arcana_rows_with_non_string_content_are_never_elided(session: AsyncSession) -> None:
    """The SQL elision condition requires ``jsonb_typeof(action->'content')
    = 'string'``: an Arcana-kind row whose action has NO content key (NULL
    under ``->``/``->>``), or a non-string content value (a JSON number),
    passes through UNELIDED with no ``elided_action_fields`` -- the
    ``is_string``/NULL guards keep the ``octet_length`` condition from
    mis-firing on those shapes, and the projection must not crash on either,
    across all three lists."""
    bot_sub = "bot-nonstring"
    owner_sub = "owner-nonstring@example.com"
    missing = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_add",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={"target_id": "arcana-source:doc-missing", "sha256": "0" * 64},
        rationale="missing",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp-missing",
    )
    numeric = ProposalHold(
        id=uuid.uuid4(),
        kind="arcana_source_revise",
        proposed_by_bot_id=bot_sub,
        owner_sub=owner_sub,
        action={"target_id": "arcana-source:doc-numeric", "content": 12345},
        rationale="numeric",
        confidence="high",
        importance="high",
        impact="high",
        priority="high",
        status="pending",
        target_fingerprint="fp-numeric",
    )
    session.add_all([missing, numeric])
    await session.commit()
    session.expunge_all()

    pending = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=50)
    pending_by_id = {p["proposal_id"]: p for p in pending["proposals"]}
    assert len(pending_by_id) == 2
    p_missing = pending_by_id[str(missing.id)]
    assert "content" not in p_missing["action"]  # no content key at all
    assert "elided_action_fields" not in p_missing
    p_numeric = pending_by_id[str(numeric.id)]
    assert p_numeric["action"]["content"] == 12345  # non-string value passes through intact
    assert "elided_action_fields" not in p_numeric

    bot_listed = await service.list_proposals_for_bot(
        session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=50
    )
    bot_by_id = {p["proposal_id"]: p for p in bot_listed["proposals"]}
    assert len(bot_by_id) == 2
    assert "elided_action_fields" not in bot_by_id[str(missing.id)]
    assert bot_by_id[str(numeric.id)]["action"]["content"] == 12345
    assert "elided_action_fields" not in bot_by_id[str(numeric.id)]

    for hold in (missing, numeric):
        await _transition_to_rejected(session, hold.id)
    history = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=50)
    hist_by_id = {p["proposal_id"]: p for p in history["proposals"]}
    assert len(hist_by_id) == 2
    assert "elided_action_fields" not in hist_by_id[str(missing.id)]
    assert hist_by_id[str(numeric.id)]["action"]["content"] == 12345
    assert "elided_action_fields" not in hist_by_id[str(numeric.id)]


# ======================================================================
# 15. Production SQL observation (team-review Medium 2): the three list
#     functions never SELECT the unprojected action column
# ======================================================================


def _top_level_select_items(sql: str) -> list[str]:
    """The outer statement's SELECT list as whitespace-normalized items, split
    on commas at parenthesis depth 0 (so commas inside function calls, ``IN``
    lists, and CASE expressions never split an item). Independent of SQL line
    wrapping, indentation, and column order."""
    norm = " ".join(sql.split())
    start = norm.index("SELECT ") + len("SELECT ")
    items: list[str] = []
    depth = 0
    current_start = start
    i = start
    while i < len(norm):
        ch = norm[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and norm.startswith(" FROM ", i):
            break
        elif depth == 0 and ch == ",":
            items.append(norm[current_start:i].strip())
            current_start = i + 1
        i += 1
    items.append(norm[current_start:i].strip())
    return items


def _assert_projected_list_sql(sql: str) -> None:
    """Assert a captured statement IS one of the three production list
    queries, carries the three projection columns, and never selects the
    unprojected full ``action`` column. Structural, not textual: the outer
    SELECT list is parsed into items (see ``_top_level_select_items``), so
    this does not depend on whitespace, column order, or where the bare
    column would be positioned. The ORM-level raiseload assertions in the
    caller remain the real guarantee that ``action`` is never loaded."""
    norm = " ".join(sql.split())
    # The ID-only keyset subquery joined back to the outer query.
    assert re.search(r"JOIN \( ?SELECT proposal_holds\.id AS id\b", norm)
    items = _top_level_select_items(sql)
    for label in ("projected_action", "elided_utf8_bytes", "elided_chars"):
        assert sum(bool(re.search(rf"\bAS {label}$", item)) for item in items) == 1, label
    # The projection reads action via ``->`` (type check), ``->>`` (content
    # text), and ``-`` (key removal) -- all inside labelled CASE items.
    projected = [i for i in items if re.search(r"\bAS (projected_action|elided_\w+)$", i)]
    joined = " ".join(projected)
    assert re.search(r"proposal_holds\.action\s*->(?!>)", joined)
    assert re.search(r"proposal_holds\.action\s*->>", joined)
    assert re.search(r"proposal_holds\.action\s*-(?!>)", joined)
    # No select item is the bare, unprojected column.
    assert "proposal_holds.action" not in items


async def test_production_list_sql_never_selects_the_unprojected_action_column(
    session: AsyncSession, engine: AsyncEngine
) -> None:
    """The projection proof observes the SQL the THREE PRODUCTION list functions
    actually emit. Each production call must emit exactly ONE statement (no lazy-load
    follow-up), that statement must carry the projected columns and NO bare
    ``proposal_holds.action`` select item, and the production call must query column
    tuples rather than loading ORM entities into the identity map (mapper load event
    is never fired). A negative control proves that ``_assert_projected_list_sql``
    would fail if the bare ``proposal_holds.action`` column were ever selected."""
    owner_sub = "owner-sqlcap@example.com"
    bot_sub = "bot-sqlcap"
    elided_hold = _seed_arcana_row(
        session,
        bot_sub=bot_sub,
        owner_sub=owner_sub,
        content="é" * 8_193,  # 16,386 UTF-8 bytes, 8,193 chars -> elided
        logical_id="doc-sqlcap-elided",
    )
    small_hold = _seed_arcana_row(
        session,
        bot_sub=bot_sub,
        owner_sub=owner_sub,
        content="x" * 100,  # unelided branch, same captured statement
        logical_id="doc-sqlcap-small",
    )
    await session.commit()
    session.expunge_all()

    sql_captured: list[str] = []
    orm_captured: list[ProposalHold] = []

    def _capture_sql(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
    ) -> None:
        sql_captured.append(statement)

    def _capture_orm_load(target: ProposalHold, context: Any) -> None:
        orm_captured.append(target)

    event.listen(engine.sync_engine, "before_cursor_execute", _capture_sql)
    # The production call now queries column tuples directly, bypassing ORM
    # entity loading. Capture mapper loads to prove ProposalHold is never loaded.
    event.listen(ProposalHold, "load", _capture_orm_load)
    try:
        session.expunge_all()
        sql_captured.clear()
        orm_captured.clear()
        pending = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=50)
        assert len(sql_captured) == 1  # exactly the list statement, no lazy-load follow-up
        _assert_projected_list_sql(sql_captured[0])
        # Negative control: verify _assert_projected_list_sql fails if bare action were selected
        bad_sql = sql_captured[0].replace(
            "SELECT proposal_holds.id,",
            "SELECT proposal_holds.action, proposal_holds.id,",
        )
        with pytest.raises(AssertionError):
            _assert_projected_list_sql(bad_sql)

        pending_by_id = {p["proposal_id"]: p for p in pending["proposals"]}
        assert "content" not in pending_by_id[str(elided_hold.id)]["action"]
        assert pending_by_id[str(small_hold.id)]["action"]["content"] == "x" * 100
        # Column projection: no ORM entities were loaded into identity map
        assert len(orm_captured) == 0
        assert len(session.identity_map) == 0

        session.expunge_all()
        sql_captured.clear()
        orm_captured.clear()
        bot_listed = await service.list_proposals_for_bot(
            session, requesting_bot_sub=bot_sub, statuses=["pending"], limit=50
        )
        assert len(sql_captured) == 1
        _assert_projected_list_sql(sql_captured[0])
        assert {p["proposal_id"] for p in bot_listed["proposals"]} == {
            str(elided_hold.id),
            str(small_hold.id),
        }
        assert len(orm_captured) == 0
        assert len(session.identity_map) == 0

        for hold in (elided_hold, small_hold):
            await _transition_to_rejected(session, hold.id)

        session.expunge_all()
        sql_captured.clear()
        orm_captured.clear()
        history = await service.list_proposal_history_for_owner(
            session, owner_sub=owner_sub, limit=50
        )
        assert len(sql_captured) == 1
        _assert_projected_list_sql(sql_captured[0])
        hist_by_id = {p["proposal_id"]: p for p in history["proposals"]}
        assert "content" not in hist_by_id[str(elided_hold.id)]["action"]
        assert "content" in hist_by_id[str(small_hold.id)]["action"]
        assert len(orm_captured) == 0
        assert len(session.identity_map) == 0
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _capture_sql)
        event.remove(ProposalHold, "load", _capture_orm_load)


# ======================================================================
# 16. Full-action retrieval stays intact: HTTP apply-record + the real
#     service decide/withdraw lifecycle for a ~1 MiB action
# ======================================================================

_ONE_MIB_CONTENT = "\u4e2d" * 349_525  # 3 UTF-8 bytes each -> 1,048,575 bytes (just under 1 MiB)
_SERVICE_SUB = "agent-comms-approvals"  # the apply-record route's default allowlisted subject


def _service_token_claims(
    sub: str = _SERVICE_SUB, scopes: list[str] | None = None
) -> dict[str, Any]:
    return {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": [PROPOSAL_APPLY_RECORD_SCOPE] if scopes is None else scopes,
    }


def _arcana_action(logical_id: str, content: str) -> dict[str, Any]:
    return {
        "target_id": f"arcana-source:{logical_id}",
        "action_type": "source_add",
        "logical_id": logical_id,
        "filename": "doc.md",
        "audience": "private",
        "sha256": _sha(content),
        "content": content,
    }


async def test_apply_record_route_returns_full_large_action_with_matching_digest(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider], session: AsyncSession
) -> None:
    """Through the REAL route (service-token auth, scope + subject allowlist),
    the approvals service gets the whole ~1 MiB action: never elided, and the
    returned content's SHA-256 equals the digest the board stored -- while the
    same row IS elided in a listing."""
    http_client, provider = client
    assert len(_ONE_MIB_CONTENT.encode("utf-8")) <= 1_048_576
    hold = _seed_arcana_row(
        session,
        bot_sub="bot-apply-rec",
        owner_sub="owner-apply-rec@example.com",
        content=_ONE_MIB_CONTENT,
        logical_id="doc-apply-rec",
    )
    hold.status = "applying"
    hold.decision_source = "human"
    hold.decided_by_actor_id = "owner-apply-rec@example.com"
    hold.decided_at = service._now()
    await session.commit()
    session.expunge_all()
    provider.tokens["svc"] = _FakeAccessToken(_service_token_claims())

    resp = await http_client.get(
        f"/proposals/{hold.id}/apply-record", headers={"Authorization": "Bearer svc"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"]["content"] == _ONE_MIB_CONTENT
    assert "elided_action_fields" not in body
    assert (
        hashlib.sha256(body["action"]["content"].encode("utf-8")).hexdigest()
        == body["action"]["sha256"]
        == _sha(_ONE_MIB_CONTENT)
    )
    assert body["target_id"] == "arcana-source:doc-apply-rec"

    listed = await service.list_proposals_for_bot(
        session, requesting_bot_sub="bot-apply-rec", statuses=["applying"], limit=10
    )
    assert "content" not in listed["proposals"][0]["action"]
    assert listed["proposals"][0]["elided_action_fields"]["content"]["utf8_bytes"] == len(
        _ONE_MIB_CONTENT.encode("utf-8")
    )


@pytest.mark.parametrize(
    ("token_claims", "expected_status"),
    [
        (None, 401),  # no credential at all
        (_service_token_claims(sub="some-other-service"), 403),  # right scope, wrong subject
        (_service_token_claims(scopes=["comms:proposals:write"]), 403),  # right sub, wrong scope
        (_service_token_claims(sub="bot-1", scopes=["comms:proposals:write"]), 403),  # a bot
    ],
)
async def test_apply_record_route_refuses_unauthorised_callers_without_leaking_content(
    client: tuple[httpx.AsyncClient, _FakeAuthProvider],
    session: AsyncSession,
    token_claims: dict[str, Any] | None,
    expected_status: int,
) -> None:
    http_client, provider = client
    hold = _seed_arcana_row(
        session,
        bot_sub="bot-apply-rec-denied",
        owner_sub="owner-apply-rec-denied@example.com",
        content="secret-document-body-" + "x" * 20_000,
        logical_id="doc-apply-rec-denied",
    )
    await session.commit()
    headers: dict[str, str] = {}
    if token_claims is not None:
        provider.tokens["tok"] = _FakeAccessToken(token_claims)
        headers["Authorization"] = "Bearer tok"
    resp = await http_client.get(f"/proposals/{hold.id}/apply-record", headers=headers)
    assert resp.status_code == expected_status
    assert "secret-document-body" not in resp.text


async def test_large_action_survives_real_decide_and_withdraw_lifecycle(
    session: AsyncSession, _default_proposal_judge: FakeProposalJudge
) -> None:
    """Real ``create_proposal`` / ``decide_proposal`` / ``withdraw_proposal``
    (only the judge is the shared fake) on ~1 MiB actions: lists elide, but
    approve hands the applier the FULL content, and the decide / withdraw /
    reject responses and the stored rows all keep the whole, hash-equal action
    (no elision marker) -- nothing on the lifecycle path reads the projected
    list shape."""
    judge = _default_proposal_judge
    judge.apply_result = ProposalApplyOutcome(
        applied=True, result={"ok": True}, caller_error=None, log_detail=None
    )
    bot_sub, owner_sub = "bot-life", "owner-life@example.com"
    ids: dict[str, str] = {}
    for name in ("approve", "reject", "withdraw"):
        created = await service.create_proposal(
            session,
            kind="arcana_source_add",
            proposed_by_bot_id=bot_sub,
            owner_sub=owner_sub,
            action=_arcana_action(f"doc-life-{name}", _ONE_MIB_CONTENT),
            rationale="r",
            confidence="high",
            importance="high",
            impact="high",
            judge=judge,
            target_fingerprint="",
        )
        assert created["status"] == "pending"
        ids[name] = created["proposal_id"]

    listed = await service.list_pending_proposal_holds(session, owner_sub=owner_sub, limit=10)
    assert len(listed["proposals"]) == 3
    assert all("content" not in p["action"] for p in listed["proposals"])
    assert all("elided_action_fields" in p for p in listed["proposals"])

    def _assert_full(proposal: dict[str, Any]) -> None:
        assert proposal["action"]["content"] == _ONE_MIB_CONTENT
        assert (
            hashlib.sha256(proposal["action"]["content"].encode("utf-8")).hexdigest()
            == proposal["action"]["sha256"]
        )
        assert "elided_action_fields" not in proposal

    approved = await service.decide_proposal(
        session,
        approver_sub=owner_sub,
        hold_id=uuid.UUID(ids["approve"]),
        decision="approve",
        decision_note=None,
        judge=judge,
    )
    assert approved["status"] == "applied"
    _assert_full(approved)
    assert len(judge.apply_calls) == 1
    applied_action = judge.apply_calls[0].action
    assert applied_action["content"] == _ONE_MIB_CONTENT
    assert applied_action["sha256"] == _sha(_ONE_MIB_CONTENT)

    rejected = await service.decide_proposal(
        session,
        approver_sub=owner_sub,
        hold_id=uuid.UUID(ids["reject"]),
        decision="reject",
        decision_note="no",
        judge=judge,
    )
    assert rejected["status"] == "rejected"
    _assert_full(rejected)

    withdrawn = await service.withdraw_proposal(
        session,
        hold_id=uuid.UUID(ids["withdraw"]),
        requesting_bot_sub=bot_sub,
        reason="changed my mind",
    )
    assert withdrawn["status"] == "withdrawn"
    _assert_full(withdrawn)

    for name in ("approve", "reject", "withdraw"):
        record = await service.get_proposal_apply_record(
            session, hold_id=uuid.UUID(ids[name]), requesting_sub=_SERVICE_SUB
        )
        _assert_full(record)
        single = await service.get_proposal_for_bot(
            session, hold_id=uuid.UUID(ids[name]), requesting_bot_sub=bot_sub
        )
        _assert_full(single)

    history = await service.list_proposal_history_for_owner(session, owner_sub=owner_sub, limit=10)
    assert len(history["proposals"]) == 3
    assert all("content" not in p["action"] for p in history["proposals"])
    assert all("elided_action_fields" in p for p in history["proposals"])
