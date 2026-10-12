"""Unit tests for comms_request_owner_reassignment tool (TECH-7389)."""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError

from models import Agent, AuditLog
from providers.comms import request_owner_reassignment as _request_owner_reassignment


@asynccontextmanager
async def _dummy_session(session_mock: Any) -> Any:
    yield session_mock


def _make_agent(
    *,
    agent_id: uuid.UUID | None = None,
    sub: str = "bot-sub-1",
    owner_email: str = "alice@redesignhealth.com",
    status: str = "active",
    is_shared: bool = False,
) -> Agent:
    agent = MagicMock(spec=Agent)
    agent.id = agent_id or uuid.uuid4()
    agent.sub = sub
    agent.owner_email = owner_email
    agent.status = status
    agent.is_shared = is_shared
    return agent


def _admin_token() -> MagicMock:
    token = MagicMock()
    token.claims = {
        "iss": "agent-jwt",
        "sub": "admin-caller",
        "scopes": ["comms:read", "comms:write", "comms:admin"],
    }
    return token


def _unauthorized_token() -> MagicMock:
    token = MagicMock()
    token.claims = {
        "iss": "agent-jwt",
        "sub": "normal-caller",
        "scopes": ["comms:read", "comms:write"],
    }
    return token


def _interactive_token() -> MagicMock:
    token = MagicMock()
    token.claims = {
        "iss": "https://example.okta.com/oauth2/default",
        "email": "admin-human@redesignhealth.com",
        "sub": "00u1234567890",
    }
    return token


def _mock_session_with_agent(target_agent: Agent | None) -> AsyncMock:
    session = AsyncMock()
    session.add = MagicMock()
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = target_agent
    session.execute = AsyncMock(return_value=exec_result)
    return session


class TestRequestOwnerReassignmentUnit:
    def test_admin_scope_returns_approval_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        target_agent = _make_agent(
            agent_id=agent_id,
            sub="test-sub-1",
            owner_email="alice@redesignhealth.com",
        )

        session = _mock_session_with_agent(target_agent)

        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )

        assert result["requires_human_approval"] is True
        assert result["key_unchanged"] is True
        assert result["is_shared"] is False
        assert result["classification_unchanged"] is True
        assert "This changes the registered owner only" in result["note"]
        assert result["sub"] == "test-sub-1"
        assert result["current_owner_email"] == "alice@redesignhealth.com"
        assert result["new_owner_email"] == "bob@redesignhealth.com"
        assert result["approval_url"] == (
            "https://decisions.example.com/ownership/reassign?"
            "sub=test-sub-1&new_owner_email=bob%40redesignhealth.com"
        )

        # Verify audit row was added and committed
        session.add.assert_called_once()
        added_audit = session.add.call_args[0][0]
        assert isinstance(added_audit, AuditLog)
        assert added_audit.action == "agent.owner_reassignment_requested"
        assert added_audit.agent_id == agent_id
        # Round-2 shape: the audit detail records the credential-wide scope.
        assert added_audit.detail == {
            "target_sub": "test-sub-1",
            "credential_sub": "test-sub-1",
            "affected_board_identities": ["test-sub-1"],
            "current_owner_email": "alice@redesignhealth.com",
            "new_owner_email": "bob@redesignhealth.com",
        }
        session.commit.assert_awaited_once()

        # Round-2 response fields: the credential subject and the exact set
        # of board identities the human approval will affect.
        assert result["credential_sub"] == "test-sub-1"
        assert result["affected_board_identities"] == ["test-sub-1"]
        assert result["sub"] == "test-sub-1"

    def test_interactive_caller_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        target_agent = _make_agent(agent_id=agent_id)

        session = _mock_session_with_agent(target_agent)

        with (
            patch("providers.comms.get_access_token", return_value=_interactive_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )

        assert result["requires_human_approval"] is True

    def test_unauthorized_token_raises_access_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        session = _mock_session_with_agent(None)

        with (
            patch("providers.comms.get_access_token", return_value=_unauthorized_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="access_denied"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_unknown_agent_raises_access_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        session = _mock_session_with_agent(None)

        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="access_denied"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_suspended_agent_raises_access_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        suspended_agent = _make_agent(agent_id=agent_id, status="suspended")

        session = _mock_session_with_agent(suspended_agent)

        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="access_denied"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(agent_id),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_shared_agent_allowed_and_is_shared_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TECH-7389: Shared agents are eligible for reassignment, and their
        is_shared flag remains unchanged (never flipped)."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        shared_agent = _make_agent(agent_id=agent_id, is_shared=True)

        session = _mock_session_with_agent(shared_agent)

        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )

        assert result["requires_human_approval"] is True
        assert result["key_unchanged"] is True
        assert result["is_shared"] is True
        assert result["classification_unchanged"] is True
        assert "This changes the registered owner only" in result["note"]
        assert shared_agent.is_shared is True  # Preserved unchanged!

    def test_human_identity_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        human_agent = _make_agent(agent_id=agent_id, sub="user@redesignhealth.com")

        session = _mock_session_with_agent(human_agent)

        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(
                ToolError,
                match="invalid_request: cannot reassign owner of a human identity",
            ):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(agent_id),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_invalid_new_owner_email_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Round 2: email validation lives in the SERVICE layer (after the
        agent lookup), so the session must be mocked to reach it; the mapped
        error carries the strict helper's reason."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(_make_agent(agent_id=agent_id, sub="email-val-sub"))
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(
                ToolError,
                match=r"invalid_request: new_owner_email must be a valid @redesignhealth\.com",
            ):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(agent_id),
                        new_owner_email="attacker@external.com",
                    )
                )

    @pytest.mark.parametrize(
        "bad_email",
        [
            "a@b@redesignhealth.com",  # multiple @
            "@redesignhealth.com",  # empty local part
            ".a@redesignhealth.com",  # leading dot edge
            "a.@redesignhealth.com",  # trailing dot edge
            "a..b@redesignhealth.com",  # consecutive dots
            "a@sub.redesignhealth.com",  # cross-host sub-domain
            "a\x00b@redesignhealth.com",  # control character
            "a" * 65 + "@redesignhealth.com",  # local part over 64 chars
        ],
    )
    def test_strict_email_shapes_rejected(
        self, monkeypatch: pytest.MonkeyPatch, bad_email: str
    ) -> None:
        """The shared strict corporate-email helper is wired into the service
        layer: every shape the old endswith-only check waved through is now
        rejected (round-2 regression for the formal review's email finding)."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(_make_agent(agent_id=agent_id, sub="strict-shape-sub"))
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(
                ToolError,
                match=r"invalid_request: new_owner_email must be a valid @redesignhealth\.com",
            ):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(agent_id),
                        new_owner_email=bad_email,
                    )
                )

    @pytest.mark.parametrize(
        "bad_base",
        [
            "https://decisions.example.com/?x=1",  # query
            "https://decisions.example.com#frag",  # fragment
            "https://user:pass@decisions.example.com",  # userinfo
        ],
    )
    def test_malformed_base_url_shapes_rejected(
        self, monkeypatch: pytest.MonkeyPatch, bad_base: str
    ) -> None:
        """Round 2: the board side parses DECISION_PAGE_BASE_URL strictly
        (https-only, no query/fragment/userinfo) instead of the old bare
        startswith check -- the round-1 userinfo/query observation is closed."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", bad_base)
        session = _mock_session_with_agent(None)
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="misconfigured:"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_missing_decision_page_base_url_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DECISION_PAGE_BASE_URL", raising=False)
        session = _mock_session_with_agent(None)
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(
                ToolError, match="misconfigured: DECISION_PAGE_BASE_URL is not configured"
            ):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_http_decision_page_base_url_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "http://insecure.example.com")
        session = _mock_session_with_agent(None)
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(
                ToolError, match="misconfigured: DECISION_PAGE_BASE_URL must be an https:// URL"
            ):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_base_url_without_scheme_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A scheme-less value fails the same https:// guard as an explicit
        http:// one -- no accidental "startswith" acceptance of a bare host."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "decisions.example.com")
        session = _mock_session_with_agent(None)
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(
                ToolError, match="misconfigured: DECISION_PAGE_BASE_URL must be an https:// URL"
            ):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_base_url_trailing_slash_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A trailing slash on the configured base URL must not produce a
        double slash (or a broken path) in the approval URL."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com/")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(
            _make_agent(agent_id=agent_id, sub="slash-sub", owner_email="a@redesignhealth.com")
        )
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )
        assert result["approval_url"].startswith(
            "https://decisions.example.com/ownership/reassign?"
        )
        assert "//ownership" not in result["approval_url"]

    def test_new_owner_email_canonicalized_lowercase_and_trimmed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mixed-case, padded corporate input canonicalizes to the trimmed
        lowercase form in BOTH the result payload and the approval URL."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(
            _make_agent(agent_id=agent_id, sub="canon-sub", owner_email="a@redesignhealth.com")
        )
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="  Bob.Owner@RedesignHealth.COM ",
                )
            )
        assert result["new_owner_email"] == "bob.owner@redesignhealth.com"
        assert "new_owner_email=bob.owner%40redesignhealth.com" in result["approval_url"]

    def test_agent_key_composes_actor_sub_in_audit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A keyed caller identity is recorded in the audit trail under its
        FULL composed sub (base::key), matching every other tool's
        actor-subject convention."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(
            _make_agent(agent_id=agent_id, sub="target-sub", owner_email="a@redesignhealth.com")
        )
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                    agent_key="ops",
                )
            )
        added_audit = session.add.call_args[0][0]
        assert isinstance(added_audit, AuditLog)
        assert added_audit.actor_sub == "admin-caller::ops"

    def test_result_shape_carries_no_privileged_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The tool's response is documentation + a link, nothing more: no
        scope grants, no flag mutations, no token material -- the exact key
        set is pinned so a future field sneaks in only deliberately."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(
            _make_agent(agent_id=agent_id, sub="shape-sub", owner_email="a@redesignhealth.com")
        )
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )
        assert set(result.keys()) == {
            "approval_url",
            "sub",
            "credential_sub",
            "affected_board_identities",
            "current_owner_email",
            "new_owner_email",
            "is_shared",
            "classification_unchanged",
            "requires_human_approval",
            "key_unchanged",
            "note",
        }

    def test_tool_makes_no_http_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """TECH-7389's board-side invariant: generating the link is pure
        string-building -- no registry HTTP, no token minting, no
        set_agent_shared. Any httpx client construction during the call
        fails this test (a regression guard for a future registry
        write-back sneaking in here)."""
        import httpx

        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "https://decisions.example.com")
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(
            _make_agent(agent_id=agent_id, sub="no-http-sub", owner_email="a@redesignhealth.com")
        )

        def _explode(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("reassignment tool must not construct an HTTP client")

        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
            patch.object(httpx.Client, "__init__", _explode),
            patch.object(httpx.AsyncClient, "__init__", _explode),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )
        assert result["requires_human_approval"] is True
        # And the only DB touch was the audit row.
        session.add.assert_called_once()
        assert isinstance(session.add.call_args[0][0], AuditLog)

    @pytest.mark.parametrize(
        "prefixed_base",
        [
            "https://decisions.example.com/approvals",
            "https://decisions.example.com/approvals/",
            "https://decisions.example.com/approvals//",
        ],
        ids=["no-trailing-slash", "trailing-slash", "double-trailing-slash"],
    )
    def test_prefixed_base_url_produces_working_approval_url(
        self, monkeypatch: pytest.MonkeyPatch, prefixed_base: str
    ) -> None:
        """USER contract (round-2 URL finding): under a path-prefixed
        deployment the approval URL must carry the operator's prefix EXACTLY
        ONCE. A dropped prefix sends the operator to a failing link (or a
        different service's destination -- hijack); a doubled prefix 404s.
        These are the pre-source-fix RED cases for that contract."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", prefixed_base)
        agent_id = uuid.uuid4()
        session = _mock_session_with_agent(
            _make_agent(agent_id=agent_id, sub="prefix-sub", owner_email="a@redesignhealth.com")
        )
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            result = asyncio.run(
                _request_owner_reassignment(
                    agent_id=str(agent_id),
                    new_owner_email="bob@redesignhealth.com",
                )
            )
        url = result["approval_url"]
        assert url.startswith("https://decisions.example.com/approvals/ownership/reassign?")
        # Exactly once: no doubled prefix, no dropped prefix.
        assert "/approvals/approvals" not in url
        assert "//ownership" not in url

    def test_board_side_rejects_http_even_loopback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """BOARD-side URL policy: no http:// at all -- unlike the approvals
        service's loopback-dev allowance, the board emits operator-facing
        approval links and must be https-only, loopback included."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", "http://127.0.0.1")
        session = _mock_session_with_agent(None)
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="misconfigured:"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    @pytest.mark.parametrize(
        "raw_base",
        [
            "https://decisions.example.com\n",  # terminal LF
            "https://decisions.example.com\r",  # terminal CR
            "https://decisions.example.com\t",  # terminal tab
            " https://decisions.example.com",  # leading normal space
            "https:// decisions.example.com",  # internal space
            "https://decisions.example.com/\n",  # trailing LF after the slash
        ],
        ids=["lf", "cr", "tab", "leading-space", "internal-space", "slash-lf"],
    )
    def test_raw_whitespace_base_url_rejected_not_trimmed(
        self, monkeypatch: pytest.MonkeyPatch, raw_base: str
    ) -> None:
        """Round-2 edge fix: the board tool validates the RAW env value before
        any trim -- whitespace anywhere rejects, never a silent trim into a
        'working' operator link (a trimmed base would change the destination
        the operator configured)."""
        monkeypatch.setenv("DECISION_PAGE_BASE_URL", raw_base)
        session = _mock_session_with_agent(None)
        with (
            patch("providers.comms.get_access_token", return_value=_admin_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="misconfigured:"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(uuid.uuid4()),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )

    def test_unauthorized_token_denied_at_handler_before_config_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-admin callers are denied before config parsing: missing or invalid
        DECISION_PAGE_BASE_URL still raises access_denied, not misconfigured."""
        monkeypatch.delenv("DECISION_PAGE_BASE_URL", raising=False)
        session = _mock_session_with_agent(None)
        agent_id = uuid.uuid4()

        with (
            patch("providers.comms.get_access_token", return_value=_unauthorized_token()),
            patch(
                "providers.comms.get_session_factory",
                return_value=lambda: _dummy_session(session),
            ),
        ):
            with pytest.raises(ToolError, match="access_denied"):
                asyncio.run(
                    _request_owner_reassignment(
                        agent_id=str(agent_id),
                        new_owner_email="bob@redesignhealth.com",
                    )
                )
        session.add.assert_called_once()
        denial_audit = session.add.call_args[0][0]
        assert isinstance(denial_audit, AuditLog)
        assert denial_audit.action == "denied.owner_reassignment_requires_elevated_scope"
        assert denial_audit.detail == {"target_agent_id": str(agent_id)}
