"""End-to-end TECH-9595 regression: oversized comms history stays reachable
through byte-budgeted ``comms_get_conversation`` pagination.

All content here is synthetic fixture markdown -- never a real note. The
scenario: an ``internal`` conversation carries 9 consecutive large ``note``
messages at seq 6-14, each a ~46k-char near-realistic markdown document
(headings, bullets, a JSON code fence with quote/backslash escapes, a table,
and a deliberately multilingual mix of accented Latin / CJK / emoji so JSON
``ensure_ascii`` escaping inflates the serialized size). The 9-message
aggregate is sized so that the single UNBOUNDED ``comms_get_conversation``
response FastMCP would emit -- TextContent plus structuredContent inside one
JSON-RPC envelope -- exceeds Paperclip's hard 1,000,000-byte cap on remote
MCP tool responses, while each individual message stays under the 256 KiB
serialized page budget (``service.MAX_BYTES_PER_GET_CONVERSATION``), so the
budget packs multi-message page prefixes rather than singletons (a single
message above the wire cap is a known limitation of the fix, explicitly out
of scope for this regression).

What is pinned, end to end through the REAL mounted server (auth middleware,
scope enforcement, tool/resource dispatch -- never the raw service functions):

- The production pagination idiom from main.py's server instructions: start
  at the reader's persisted cursor (``since_seq=5``, established by a prior
  catch-up read of seq 1-5), then re-call with ``since_seq=page_max_seq``
  from each response while ``has_more``.
- Every message arrives exactly once, in ascending seq order 6-14 -- no
  gaps, no duplicates -- with each payload byte-identical to the posted
  markdown (escapes and non-ASCII round-trip intact through Postgres, the
  service projection, and FastMCP's TextContent + structuredContent).
- Every page's reconstructed JSON-RPC response envelope -- measured from the
  pinned FastMCP/MCP result objects, exactly as the SDK transports serialize
  them, TextContent AND structuredContent both included -- stays below
  Paperclip's cap.
- ``page_truncated_by_bytes``/``has_more``/``page_max_seq``/``last_read_seq``
  behave as documented on every page, and the tool path advances the read
  cursor page by page.
- The ``comms://comms/conversations/{id}`` resource applies the same byte
  budget (its page is truncated, ``has_more=True`` -- the URI has no paging
  parameter, so the tool is the only way past it) yet never advances the
  caller's read cursor (``mark_read=False``), checked against the
  participants row, the response's own ``last_read_seq``, and ``comms_inbox``.

Mirrors ``tests/test_comms_tools.py``'s real-Postgres idiom (module-scoped
Alembic chain, function-scoped engine/session, autouse truncate, skip the
whole module with a clear reason if Postgres is unreachable) combined with
``tests/test_main.py``'s in-memory ``fastmcp.Client`` end-to-end idiom.
Service-unit coverage of the packing rules themselves (singleton rule,
leftover context budget, ``max_bytes`` validation) already lives in
``tests/test_service.py``; this module deliberately does not repeat it.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import mcp.types as mcp_types
import pytest
import pytest_asyncio
from fastmcp import Client
from pydantic_core import to_json
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import service
from models import Participant
from schemas import MESSAGE_TYPES

SERVICE_ROOT = Path(__file__).parent.parent
_DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:55432/agent_comms"

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
    """Import a fresh ``main`` module under the OIDC/env patches."""
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


# --- Database fixtures (mirrors tests/test_comms_tools.py) -------------------------


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
    except Exception:
        return False


@pytest.fixture(scope="module")
def database_url() -> str:
    url = _test_database_url()
    if not asyncio.run(_can_connect(url)):
        pytest.skip(
            f"Postgres unreachable at {url!r} — run `docker compose up -d postgres` "
            "(or set DATABASE_URL) to exercise this module's real-database tests."
        )
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated_schema(database_url: str) -> None:
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
    eng = create_async_engine(database_url)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
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
def test_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def main() -> Any:
    return _import_main()


# --- MCP client helpers -------------------------------------------------------------


def _token(sub: str, *, owner_sub: str | None = None) -> MagicMock:
    """A minimal agent-jwt-shaped ``AccessToken`` stand-in for ``sub``."""
    claims: dict[str, Any] = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": ["comms:read", "comms:write"],
    }
    if owner_sub is not None:
        claims["owner_sub"] = owner_sub
    token = MagicMock()
    token.claims = claims
    token.scopes = []
    token.client_id = sub
    return token


async def _call(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    tool_name: str,
    args: dict[str, Any] | None = None,
) -> Any:
    """Call a tool through the real mounted server; return its decoded data."""
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.comms.get_access_token", return_value=token),
        patch("providers.comms.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data


async def _call_tool_mcp(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    tool_name: str,
    args: dict[str, Any],
) -> mcp_types.CallToolResult:
    """Call a tool through the real mounted server; return the pinned MCP
    protocol result (``content`` blocks + ``structuredContent``) rather than
    the decoded data -- the exact object whose JSON-RPC envelope a remote
    transport writes on the wire, and what a byte-capped gateway would see."""
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.comms.get_access_token", return_value=token),
        patch("providers.comms.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            return await client.call_tool_mcp(tool_name, args)


async def _read_resource_mcp(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    token: MagicMock,
    uri: str,
) -> mcp_types.ReadResourceResult:
    """Read a resource through the real mounted server; return the pinned MCP
    protocol result (``contents`` blocks), same rationale as ``_call_tool_mcp``."""
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token),
        patch("providers.comms.get_access_token", return_value=token),
        patch("providers.comms.get_session_factory", return_value=test_session_factory),
    ):
        async with Client(main.mcp) as client:
            return await client.read_resource_mcp(uri)


async def _register(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    sub: str,
    *,
    owner_sub: str | None = None,
) -> dict[str, Any]:
    token = _token(sub, owner_sub=owner_sub)
    result: dict[str, Any] = await _call(
        main,
        test_session_factory,
        token,
        "comms_register",
        {"display_name": sub, "accepted_types": sorted(MESSAGE_TYPES)},
    )
    return result


# --- Wire-size measurement ---------------------------------------------------------


def _wire_envelope_bytes(result: mcp_types.Result) -> int:
    """UTF-8 byte size of the JSON-RPC response envelope carrying ``result``.

    Rebuilds, from the pinned client-side result object, the exact envelope
    the MCP SDK's transports serialize: every transport writes
    ``SessionMessage.message.model_dump_json(by_alias=True, exclude_none=True)``
    (stdio writes those bytes verbatim; streamable_http embeds the same JSON
    in a ``[...]`` array body two bytes larger), and the server side builds
    that message from ``JSONRPCResponse(jsonrpc="2.0", id=<id>, result=<result
    >.model_dump(by_alias=True, mode="json", exclude_none=True))`` (mcp's
    ``BaseSession._send_response``). ``id=1`` stands in for the request's id;
    a JSON-RPC id contributes O(1) bytes and every assertion below keeps far
    more margin than that. TextContent AND structuredContent are both inside
    ``result``'s dump, so the FastMCP duplication is fully counted.
    """
    response = mcp_types.JSONRPCResponse(
        jsonrpc="2.0",
        id=1,
        result=result.model_dump(by_alias=True, mode="json", exclude_none=True),
    )
    envelope = mcp_types.JSONRPCMessage(response).model_dump_json(by_alias=True, exclude_none=True)
    return len(envelope.encode("utf-8"))


# --- TECH-9595 scenario constants and synthetic fixture content ---------------------


# Paperclip's hard wire cap on remote MCP tool responses -- the reason
# service.MAX_BYTES_PER_GET_CONVERSATION exists (see its comment). Measured
# here against the full JSON-RPC response envelope, not just the payload,
# because that envelope -- with FastMCP's TextContent + structuredContent
# duplication -- is what the remote gateway actually caps.
PAPERCLIP_REMOTE_MCP_RESPONSE_CAP_BYTES = 1_000_000

# The 9 oversized notes sit at seq 6-14, behind an opener note (seq 1) and
# four small filler notes (seq 2-5) the reader has already consumed, so the
# production pagination loop starts from a genuine persisted cursor of 5.
FIRST_OVERSIZED_SEQ = 6
LAST_OVERSIZED_SEQ = 14
NOTE_COUNT = LAST_OVERSIZED_SEQ - FIRST_OVERSIZED_SEQ + 1
PAGINATION_START_SINCE_SEQ = 5
_TOTAL_MESSAGES = LAST_OVERSIZED_SEQ  # opener + 4 fillers + 9 oversized

# 40 section blocks lands each note at ~46k chars / ~101k bytes in the
# service's ``ensure_ascii`` serialization: comfortably under NoteV1's
# 50,000-char cap and under the 256 KiB page budget (two notes per page),
# while nine of them together tower over both the page budget and
# Paperclip's wire cap. The assertions below measure the real bytes rather
# than trusting these estimates, so fixture drift fails loudly instead of
# silently under-sizing.
_NOTE_SECTION_BLOCKS = 40


def _note_section(note_index: int, section: int) -> str:
    """One synthetic markdown section: heading, bullets, a JSON code fence
    with quote/backslash escapes, and a table -- deliberately multilingual
    (accented Latin, CJK, emoji) so ``ensure_ascii`` escaping inflates the
    serialized size exactly the way real multilingual notes do.

    Long content lines are assembled from adjacent string fragments purely
    to keep every SOURCE line under ruff's 100-char bar; the joined runtime
    text is the near-realistic long line the fixture wants."""
    day = section % 28 + 1
    lines = [
        # A realistic long heading mixing scripts.
        f"## §{section} Agenda item {section}: 「議題 {note_index}-{section}」"
        " — café discussion über availability",
        "",
        "- Attendee: María Fernández (maria.fernandez@example.invalid)"
        " — **région**: EMEA / Nordamerika / 日本",
        f"- Status: ✅ draft / ⚠️ review / 📅 scheduled 2026-11-{day:02d}",
        # Escapes a JSON round trip must not mangle: quotes, doubled
        # backslashes, a Windows path, and a literal backslash-n.
        f'- Escapes: `\\"quoted\\"`, `\\\\backslash\\\\`,'
        f" `C:\\\\Users\\\\dev\\\\notes_{note_index}.md`, literal `\\n` stays literal",
        f"- Point {section}.1: the proposal covers Naïve Bayes vs."
        " Großbritannien benchmarks; Skål!",
        f"- Point {section}.2: follow-up with 陈伟 and 小林 on 会議室 booking"
        f" (第{section}会議室), 15:00 JST",
        f"- Point {section}.3: measure «throughput» at 5,000 req/s — Δ latency p99 ≤ 250 ms",
        # CJK-dense lines: the main ensure_ascii inflation driver.
        f"- 用語集 {section}: 利用可能時間の調整 availability negotiation"
        " — 優先度 高/中/低 — 状態 承認済/保留中/差し戻し中"
        " — 次のステップ 確定/共有/再調整"
        " — 期限 2026-11-30 まで、遅延時は即時報告のこと",
        f"- 注意事項 {section}: 情報資産の取り扱いには十分注意し、"
        "対象の所有権境界を越える共有は禁止。"
        "確定済みの内容は変更不可、変更が必要な場合は新しい議題を起票すること。",
        f"- 補足 {section}: 会議の時間帯は参加者の暫定回答を元に自動調整される。"
        "agent 側は提案された候補の可否を明示的に返答すること(暗黙の承認は無効)。",
        "",
        "```json",
        f'{{"seq": {section}, "note": {note_index}, "owner": "são-paulo-team",'
        f' "tags": ["会議", "café", "über"], "escaped": "tab\\there",'
        f' "path": "C:\\\\Users\\\\dev\\\\fixture_{note_index}_{section}.json"}}',
        "```",
        "",
        "| 担当 | 項目 | Status | 备注 |",
        "|---|---|---|---|",
        f"| María | agenda {section} | ✅ | listo |",
        f"| Björn | analytics {section} | ⚠️ | nicht fertig |",
        f"| 田中 | follow-up {section} | 📅 | 保留 |",
        "",
    ]
    return "\n".join(lines)


def _oversized_note_markdown(note_index: int) -> str:
    """The full synthetic note text for oversized note ``note_index`` (1-9).

    Deterministic and distinct per note (the index is embedded in every
    section), so byte-for-byte payload comparisons can pin exactly which
    note each seq should carry.
    """
    header = (
        f"# Synthetic meeting digest — note {note_index} of 9 "
        "(TECH-9595 regression fixture)\n\n"
        f"*Synthetic content only, never a real note. "
        f"Marker: 2026-11-21T00:{note_index:02d}:00Z.*\n\n"
    )
    body = "\n".join(_note_section(note_index, section) for section in range(_NOTE_SECTION_BLOCKS))
    footer = (
        f"\n---\n\n*End of synthetic note {note_index}/9. "
        '\\"quotes\\", \\\\backslashes\\\\, and `backticks` round-trip intact.*\n'
    )
    text = header + body + footer
    # Keep the fixture honest against NoteV1's 50,000-char text cap (and
    # above a floor where the aggregate assertions below stop meaning
    # anything): a drifted generator fails here, not somewhere downstream
    # with a confusing size mismatch.
    assert 40_000 <= len(text) <= 50_000
    return text


def _expected_note_payload(note_index: int) -> dict[str, Any]:
    """The exact payload dict seq (FIRST_OVERSIZED_SEQ + note_index - 1) must
    carry back: NoteV1's normalized model dump, text byte-for-byte."""
    return {"type": "note", "text": _oversized_note_markdown(note_index)}


def _hypothetical_unbounded_page(
    first_page_body: dict[str, Any],
    messages: list[dict[str, Any]],
) -> mcp_types.CallToolResult:
    """The ``comms_get_conversation`` result the server WOULD have returned
    for these messages with no byte budget: the real first page's envelope
    (conversation/participants/cursor fields) with the full message list
    spliced in. Its TextContent is produced with the same serializer FastMCP
    itself uses for tool results (``pydantic_core.to_json``, fastmcp's
    ``default_serializer``), so the envelope measured off it is the bytes a
    remote caller would actually have received pre-TECH-9595."""
    hypothetical = dict(first_page_body)
    hypothetical["messages"] = messages
    hypothetical["messages_returned"] = len(messages)
    hypothetical["has_more"] = False
    hypothetical["page_truncated_by_bytes"] = False
    hypothetical["page_max_seq"] = messages[-1]["seq"]
    hypothetical["last_read_seq"] = messages[-1]["seq"]
    return mcp_types.CallToolResult(
        content=[
            mcp_types.TextContent(type="text", text=to_json(hypothetical, fallback=str).decode())
        ],
        structuredContent=hypothetical,
    )


async def _seed_oversized_conversation(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    *,
    tag: str,
    reader_pre_reads: bool,
) -> dict[str, str]:
    """Register a same-owner agent pair, open an ``internal`` conversation
    (opener note = seq 1), post filler notes seq 2-5, optionally have the
    reader consume seq 1-5 (pinning its persisted cursor at 5, the
    production pagination start), then post the 9 oversized notes at
    seq 6-14. Notes post immediately in an internal conversation (no
    ownership boundary to cross), so no hold shapes appear."""
    human_owner = f"bytepage-{tag}-human@example.invalid"
    owner_sub = f"bytepage-{tag}-owner"
    target_sub = f"bytepage-{tag}-target"
    await _register(main, test_session_factory, owner_sub, owner_sub=human_owner)
    target = await _register(main, test_session_factory, target_sub, owner_sub=human_owner)
    owner_token = _token(owner_sub, owner_sub=human_owner)
    target_token = _token(target_sub, owner_sub=human_owner)

    started = await _call(
        main,
        test_session_factory,
        owner_token,
        "comms_start_conversation",
        {
            "conversation_type": "internal",
            "target_agent_ids": [target["agent_id"]],
            "initial_message": {"text": f"opener note for the {tag} byte-pagination fixture"},
            "message_type": "note",
        },
    )
    conversation_id = started["conversation_id"]

    await _call(
        main,
        test_session_factory,
        target_token,
        "comms_accept",
        {"conversation_id": conversation_id},
    )

    for seq in range(2, PAGINATION_START_SINCE_SEQ + 1):
        posted = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "note",
                "payload": {"text": f"filler note {seq} of the {tag} fixture"},
            },
        )
        assert posted["seq"] == seq

    if reader_pre_reads:
        consumed = await _call(
            main,
            test_session_factory,
            target_token,
            "comms_get_conversation",
            {"conversation_id": conversation_id, "since_seq": 0},
        )
        assert [m["seq"] for m in consumed["messages"]] == [
            1,
            2,
            3,
            4,
            5,
        ]
        assert consumed["has_more"] is False
        # The persisted cursor the pagination loop below starts from.
        assert consumed["last_read_seq"] == PAGINATION_START_SINCE_SEQ

    for seq in range(FIRST_OVERSIZED_SEQ, LAST_OVERSIZED_SEQ + 1):
        note_index = seq - FIRST_OVERSIZED_SEQ + 1
        note_text = _oversized_note_markdown(note_index)
        posted = await _call(
            main,
            test_session_factory,
            owner_token,
            "comms_post_message",
            {
                "conversation_id": conversation_id,
                "message_type": "note",
                "payload": {"text": note_text},
            },
        )
        # Internal same-owner note: posted immediately, never held.
        assert "held_for_approval" not in posted
        assert posted["seq"] == seq
        # Write-side round-trip: the stored payload echoes the fixture intact.
        assert posted["payload"] == {"type": "note", "text": note_text}

    return {
        "conversation_id": conversation_id,
        "owner_sub": owner_sub,
        "target_sub": target_sub,
        "target_agent_id": target["agent_id"],
    }


class TestOversizedNotePaginationTool:
    """The main TECH-9595 regression: 9 oversized notes (seq 6-14) whose
    unbounded aggregate would blow Paperclip's wire cap are still fully
    retrievable, intact and in order, through the documented
    ``since_seq=page_max_seq`` pagination loop, with every page's real
    JSON-RPC envelope under the cap."""

    async def test_nine_oversized_notes_page_intact_under_wire_cap(
        self, main: Any, test_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        seeded = await _seed_oversized_conversation(
            main, test_session_factory, tag="tool", reader_pre_reads=True
        )
        reader_token = _token(seeded["target_sub"])

        collected: list[dict[str, Any]] = []
        messages_per_page: list[int] = []
        page_envelope_bytes: list[int] = []
        first_page_body: dict[str, Any] | None = None
        since_seq = PAGINATION_START_SINCE_SEQ
        pages = 0

        # The production catch-up loop from main.py's server instructions:
        # page with since_seq=page_max_seq from THIS response while has_more.
        while True:
            pages += 1
            assert pages <= 2 * _TOTAL_MESSAGES, "pagination failed to converge"
            raw = await _call_tool_mcp(
                main,
                test_session_factory,
                reader_token,
                "comms_get_conversation",
                {"conversation_id": seeded["conversation_id"], "since_seq": since_seq},
            )
            assert raw.isError is False
            body = raw.structuredContent
            assert isinstance(body, dict)

            messages = body["messages"]
            seqs = [m["seq"] for m in messages]
            assert seqs == sorted(seqs), "page messages must be ascending by seq"
            assert all(s > since_seq for s in seqs), "page must start past since_seq"
            assert body["messages_returned"] == len(messages)
            # Explicit since_seq is the continuation path: no defaulted
            # window, and never a context band on top of the page.
            assert body["since_was_defaulted"] is False
            assert all("context" not in m for m in messages)

            # The pinned result duplicates the page in TextContent AND
            # structuredContent -- the duplication the 256 KiB budget's
            # headroom under the 1 MB cap exists for.
            assert len(raw.content) == 1
            assert isinstance(raw.content[0], mcp_types.TextContent)
            assert json.loads(raw.content[0].text) == body
            envelope_bytes = _wire_envelope_bytes(raw)
            assert envelope_bytes < PAPERCLIP_REMOTE_MCP_RESPONSE_CAP_BYTES
            page_envelope_bytes.append(envelope_bytes)

            # Byte-budget packing: the in-window prefix never exceeds the
            # page budget (no fixture message is individually over budget),
            # and truncation is flagged byte-driven while has_more holds.
            packed_bytes = sum(len(json.dumps(m, ensure_ascii=True)) for m in messages)
            assert packed_bytes <= service.MAX_BYTES_PER_GET_CONVERSATION
            assert body["last_read_seq"] == body["page_max_seq"]
            if body["has_more"]:
                assert body["page_truncated_by_bytes"] is True
            else:
                assert body["page_truncated_by_bytes"] is False

            if first_page_body is None:
                first_page_body = body
            collected.extend(messages)
            messages_per_page.append(len(messages))
            if not body["has_more"]:
                break
            since_seq = body["page_max_seq"]

        assert first_page_body is not None

        # Multi-page, multi-message packing: the byte budget (not the 500
        # count cap -- 9 messages total never touches it) split the history
        # into pages carrying more than one oversized note each.
        assert pages >= 2
        assert max(messages_per_page) >= 2
        assert sum(messages_per_page) == NOTE_COUNT
        assert min(page_envelope_bytes) > 100_000  # pages really carry the bulk

        # Exact ordered retrieval: seq 6-14, once each, no gaps or duplicates.
        assert [m["seq"] for m in collected] == list(
            range(FIRST_OVERSIZED_SEQ, LAST_OVERSIZED_SEQ + 1)
        )

        # Payloads intact byte-for-byte: the full synthetic markdown, escapes
        # and non-ASCII included, survives Postgres, the service projection,
        # and FastMCP's TextContent + structuredContent round trip.
        for message in collected:
            note_index = message["seq"] - FIRST_OVERSIZED_SEQ + 1
            assert message["type"] == "note"
            assert message["schema_version"] == 1
            assert message["sender_sub"] == seeded["owner_sub"]
            assert message["payload"] == _expected_note_payload(note_index)

        # The scenario premise, measured on the real objects: without the
        # byte budget, this single response would have exceeded Paperclip's
        # cap. (The last page already proved the budgeted form stays under
        # it; this reconstructs the pre-fix unbounded shape.)
        serialized_sizes = [len(json.dumps(m, ensure_ascii=True)) for m in collected]
        assert sum(serialized_sizes) > 3 * service.MAX_BYTES_PER_GET_CONVERSATION
        # The out-of-scope boundary: no single message is over the page
        # budget, so this regression exercises prefix packing, never the
        # singleton escape hatch.
        assert max(serialized_sizes) <= service.MAX_BYTES_PER_GET_CONVERSATION
        unbounded = _hypothetical_unbounded_page(first_page_body, collected)
        assert _wire_envelope_bytes(unbounded) > PAPERCLIP_REMOTE_MCP_RESPONSE_CAP_BYTES, (
            "fixture drift: aggregate no longer exceeds the gateway cap"
        )


class TestConversationResourceUnderByteBudget:
    """The ``comms://comms/conversations/{id}`` resource shares the tool's
    byte budget but must never advance the read cursor -- even when its page
    is byte-truncated with unread messages beyond it."""

    async def test_resource_page_is_byte_truncated_and_never_marks_read(
        self,
        main: Any,
        test_session_factory: async_sessionmaker[AsyncSession],
        session: AsyncSession,
    ) -> None:
        seeded = await _seed_oversized_conversation(
            main, test_session_factory, tag="resource", reader_pre_reads=False
        )
        reader_token = _token(seeded["target_sub"])
        uri = f"comms://comms/conversations/{seeded['conversation_id']}"

        inbox_before = await _call(main, test_session_factory, reader_token, "comms_inbox")
        assert any(
            c["conversation_id"] == seeded["conversation_id"] for c in inbox_before["unread"]
        )

        # Read the resource twice, as a refetching client would. Each read:
        # a byte-truncated page (has_more=True -- the URI template has no
        # paging parameter, so the tool is the only way past this point),
        # an ascending no-gap/no-duplicate prefix that reaches INTO the
        # oversized notes, under the wire cap, and with the caller's
        # last_read_seq still reported as 0.
        for _ in range(2):
            raw = await _read_resource_mcp(main, test_session_factory, reader_token, uri)
            assert len(raw.contents) == 1
            assert isinstance(raw.contents[0], mcp_types.TextResourceContents)
            body = json.loads(raw.contents[0].text)
            assert isinstance(body, dict)
            assert body["invited"] is False
            assert body["has_more"] is True
            assert body["page_truncated_by_bytes"] is True
            assert body["last_read_seq"] == 0
            seqs = [m["seq"] for m in body["messages"]]
            assert seqs == list(range(1, len(seqs) + 1))
            assert body["messages_returned"] == len(seqs)
            # Truncated well before the conversation's 14 messages, but the
            # page reaches past the five small messages into the oversized
            # notes (byte truncation among the big notes, not before them).
            assert PAGINATION_START_SINCE_SEQ < len(seqs) < _TOTAL_MESSAGES
            trailing_note_index = len(seqs) - PAGINATION_START_SINCE_SEQ
            assert body["messages"][-1]["payload"] == _expected_note_payload(trailing_note_index)
            assert _wire_envelope_bytes(raw) < PAPERCLIP_REMOTE_MCP_RESPONSE_CAP_BYTES

        # mark_read=False, confirmed structurally: the participants row is
        # untouched by either truncated resource read.
        participant = (
            await session.execute(
                select(Participant).where(
                    Participant.conversation_id == uuid.UUID(seeded["conversation_id"]),
                    Participant.agent_id == uuid.UUID(seeded["target_agent_id"]),
                )
            )
        ).scalar_one()
        assert participant.last_read_seq == 0

        # ...and behaviorally: comms_inbox still lists the conversation as
        # unread, exactly as before the resource reads.
        inbox_after = await _call(main, test_session_factory, reader_token, "comms_inbox")
        assert inbox_after == inbox_before
