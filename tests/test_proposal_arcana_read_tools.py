"""``proposals_arcana_source_metadata`` / ``proposals_arcana_source_span``
(TECH-7170): a bot reads back ITS OWN stored private-brain source through the
board. Identity is the verified token's sub only; the Arcana-facing client is
the approvals package's ``arcana_read_http_client``, faked here."""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp.exceptions import ToolError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_proposal_tools import _call, _token, main  # noqa: F401

_TOOLS = ("proposals_arcana_source_metadata", "proposals_arcana_source_span")
_FULL_METADATA = {
    "brain_id": "b",
    "logical_id": "src-1",
    "revision_id": "rev-1",
    "sha256": "ab",
    "filename": "f.md",
    "status": "pending",
    "created_at": "2026-10-06T00:00:00Z",
}
_SPAN_ARGS = {"revision_id": "rev-1", "offset": 0, "length": 5}


class _Fake:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.metadata: Any = None
        self.error: Exception | None = None

    async def fetch_source_metadata(self, bot_id: str, logical_id: str) -> Any:
        self.calls.append(("metadata", (bot_id, logical_id)))
        if self.error:
            raise self.error
        return self.metadata

    async def fetch_source_span(self, bot_id: str, revision_id: str, offset: int, length: int):
        self.calls.append(("span", (bot_id, revision_id, offset, length)))
        if self.error:
            raise self.error
        return types.SimpleNamespace(
            brain_id="brain-x", revision_id=revision_id, offset=offset, length=length, text="Hello"
        )


@pytest.fixture
def test_session_factory() -> Any:
    """These tools never touch the database; ``_call`` only needs something to patch in."""
    return MagicMock()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> _Fake:
    fake = _Fake()
    package = types.ModuleType("rh_comms_plugins")
    package.arcana_read_http_client = fake  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "rh_comms_plugins", package)
    monkeypatch.setitem(sys.modules, "rh_comms_plugins.arcana_read_http_client", fake)  # type: ignore[arg-type]
    return fake


async def test_tools_are_mounted_and_scope_enrolled(main: Any) -> None:  # noqa: F811
    from scopes import PROPOSAL_SUBMIT_SCOPE, TOOL_SCOPES

    mounted = {t.name for t in await main.mcp.list_tools()}
    assert set(_TOOLS) <= mounted
    assert all(TOOL_SCOPES[name] == PROPOSAL_SUBMIT_SCOPE for name in _TOOLS)


async def test_identity_is_the_verified_sub_and_nothing_else(
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    token = _token("pclip-dev-brain-pilot-01")
    out = await _call(main, test_session_factory, token, "proposals_arcana_source_span", _SPAN_ARGS)
    assert out["text"] == "Hello"
    assert fake.calls == [("span", ("pclip-dev-brain-pilot-01", "rev-1", 0, 5))]

    # No tool accepts a bot/brain/company argument: extras are rejected.
    for tool, base in (
        ("proposals_arcana_source_span", _SPAN_ARGS),
        ("proposals_arcana_source_metadata", {"logical_id": "s"}),
    ):
        for extra in ("bot_id", "brain_id", "company_id"):
            with pytest.raises(ToolError):
                await _call(main, test_session_factory, token, tool, {**base, extra: "other"})
    assert len(fake.calls) == 1


async def test_response_is_an_allowlist_and_exists_cannot_be_overridden(
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    fake.metadata = types.SimpleNamespace(
        **_FULL_METADATA, exists=False, internal_secret="nope", owner_bot_id="x"
    )
    out = await _call(
        main,
        test_session_factory,
        _token("bot-a"),
        "proposals_arcana_source_metadata",
        {"logical_id": "s"},
    )
    assert out["exists"] is True and out["revision_id"] == "rev-1"
    assert "internal_secret" not in out and "owner_bot_id" not in out


@pytest.mark.parametrize("bad", ["", "   "])
async def test_empty_identifiers_are_rejected_before_any_read(
    bad: str,
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    for tool, args in (
        ("proposals_arcana_source_metadata", {"logical_id": bad}),
        ("proposals_arcana_source_span", {**_SPAN_ARGS, "revision_id": bad}),
    ):
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(main, test_session_factory, _token("bot-a"), tool, args)
    assert fake.calls == []


async def test_failure_is_logged_for_the_operator_not_the_bot(
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING", logger="providers.proposals")
    fake.error = RuntimeError("upstream exploded")
    for tool, args in (
        ("proposals_arcana_source_span", _SPAN_ARGS),
        ("proposals_arcana_source_metadata", {"logical_id": "s"}),
    ):
        caplog.clear()
        with pytest.raises(ToolError) as caught:
            await _call(main, test_session_factory, _token("bot-a"), tool, args)
        assert "exploded" not in str(caught.value)
        assert any(r.exc_info and "upstream exploded" in str(r.exc_info[1]) for r in caplog.records)


async def test_span_response_is_an_allowlist_and_missing_fields_fail_closed(
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, tool = _token("bot-a"), "proposals_arcana_source_span"
    out = await _call(main, test_session_factory, token, tool, _SPAN_ARGS)
    assert set(out) == {"brain_id", "revision_id", "offset", "length", "text"}

    async def _short(bot_id: str, revision_id: str, offset: int, length: int) -> Any:
        return types.SimpleNamespace(revision_id=revision_id, text="x")  # drifted client

    monkeypatch.setattr(fake, "fetch_source_span", _short)
    with pytest.raises(ToolError, match="not available"):
        await _call(main, test_session_factory, token, tool, _SPAN_ARGS)


async def test_metadata_absent_and_present(
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    token = _token("bot-a")
    args = {"logical_id": "src-1"}
    absent = await _call(
        main, test_session_factory, token, "proposals_arcana_source_metadata", args
    )
    assert absent == {"exists": False}

    fake.metadata = types.SimpleNamespace(**_FULL_METADATA)
    present = await _call(
        main, test_session_factory, token, "proposals_arcana_source_metadata", args
    )
    assert present == {"exists": True, **_FULL_METADATA}
    assert [c[1][0] for c in fake.calls] == ["bot-a", "bot-a"]


@pytest.mark.parametrize("tool", _TOOLS)
async def test_upstream_failure_never_leaks_detail(
    tool: str,
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    fake.error = RuntimeError("https://arcana.internal/secret token=abc")
    args = {"logical_id": "s"} if tool.endswith("metadata") else _SPAN_ARGS
    with pytest.raises(ToolError) as caught:
        await _call(main, test_session_factory, _token("bot-a"), tool, args)
    assert "not available" in str(caught.value)
    assert "secret" not in str(caught.value) and "arcana.internal" not in str(caught.value)


@pytest.mark.parametrize("tool", _TOOLS)
async def test_base_image_without_the_plugin_fails_closed(
    tool: str,
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "rh_comms_plugins", None)
    with pytest.raises(ToolError, match="not available"):
        await _call(
            main,
            test_session_factory,
            _token("bot-a"),
            tool,
            {"logical_id": "s"} if tool.endswith("metadata") else _SPAN_ARGS,
        )


@pytest.mark.parametrize("tool", _TOOLS)
async def test_scope_and_interactive_callers_are_denied(
    tool: str,
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    args = {"logical_id": "s"} if tool.endswith("metadata") else _SPAN_ARGS
    with pytest.raises(ToolError, match="requires elevated permissions"):
        await _call(main, test_session_factory, _token("bot-a", scopes=[]), tool, args)

    human = MagicMock()
    human.claims = {"iss": "https://example.okta.com/oauth2/default", "email": "h@example.com"}
    human.scopes = []
    human.client_id = "h@example.com"
    with pytest.raises(ToolError, match="bot"):
        await _call(main, test_session_factory, human, tool, args)
    assert fake.calls == []


@pytest.mark.parametrize(
    ("offset", "length"),
    [(-1, 5), (0, 0), (0, 100_001), (10_000_001, 5)],
)
async def test_span_bounds_are_validated_before_any_read(
    offset: int,
    length: int,
    main: Any,  # noqa: F811
    test_session_factory: async_sessionmaker[AsyncSession],
    fake: _Fake,
) -> None:
    with pytest.raises(ToolError, match="invalid_request"):
        await _call(
            main,
            test_session_factory,
            _token("bot-a"),
            "proposals_arcana_source_span",
            {"revision_id": "r", "offset": offset, "length": length},
        )
    assert fake.calls == []
