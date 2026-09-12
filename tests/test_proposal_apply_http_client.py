"""Tests for proposal_apply_http_client (TECH-6213 PR-B1).

Covers:
- HTTP client POST /actions/proposals/apply request serialization and headers
- Success paths (applied=True with result, applied=False with caller_error)
- Never-raise behavior: network errors, HTTP errors (401, 403, 409, 422, 5xx),
  malformed responses, missing env vars, and validation errors all map to safe
  ProposalApplyOutcome instances
- Cancellation propagation: asyncio.CancelledError is re-raised
- TLS SNI override hook behavior
- HttpApplyProposalJudge wrapper delegation and zero Linear code reachability
- plugins.get_proposal_judge wrapping of RHProposalJudge
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from typing import Any

import httpx
import pytest

import plugins
import proposal_apply_http_client
from plugins import (
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalContext,
    ProposalFingerprint,
    ProposalVerdict,
)
from proposal_apply_http_client import (
    PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR,
    PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR,
    PROPOSAL_APPLY_TOKEN_ENV_VAR,
    PROPOSAL_APPLY_URL_ENV_VAR,
    HttpApplyProposalJudge,
    apply_proposal,
    build_rh_proposal_judge,
)

_URL = "https://comms-approvals.example.ts.net/actions"
_TOKEN = "test-proposal-apply-token"


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, _URL)
    monkeypatch.setenv(PROPOSAL_APPLY_TOKEN_ENV_VAR, _TOKEN)
    monkeypatch.delenv(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, raising=False)
    monkeypatch.delenv(PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR, raising=False)
    monkeypatch.delenv("PROPOSAL_ACTION_URL", raising=False)
    monkeypatch.delenv("PROPOSAL_ACTION_TOKEN", raising=False)
    monkeypatch.delenv("PROPOSAL_ACTION_TLS_SNI_HOST", raising=False)


def _patch_transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    def fake_build_apply_client(
        timeout_seconds: float, tls_sni_host: str | None
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(proposal_apply_http_client, "_build_apply_client", fake_build_apply_client)


def _ctx(
    *,
    hold_id: uuid.UUID | None = None,
    kind: str = "linear_progress_update",
    action: dict[str, Any] | None = None,
    target_id: str = "TECH-1234",
    action_type: str = "update_status",
    rationale: str = "starting work on ticket",
    proposed_by_bot_id: str = "bot-alpha",
    owner_sub: str = "user-123",
) -> ProposalContext:
    return ProposalContext(
        kind=kind,
        action=action if action is not None else {"status": "In Progress"},
        target_id=target_id,
        action_type=action_type,
        rationale=rationale,
        proposed_by_bot_id=proposed_by_bot_id,
        owner_sub=owner_sub,
        hold_id=hold_id if hold_id is not None else uuid.uuid4(),
    )


class TestApplyProposalSuccess:
    async def test_returns_applied_true_with_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/actions/proposals/apply"
            return httpx.Response(200, json={"applied": True, "result": {"ticket_id": "TECH-1234"}})

        _patch_transport(monkeypatch, handler)
        ctx = _ctx()
        outcome = await apply_proposal(ctx)
        assert outcome.applied is True
        assert outcome.result == {"ticket_id": "TECH-1234"}
        assert outcome.caller_error is None
        assert outcome.log_detail is None

    async def test_returns_applied_true_with_none_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": True, "result": None})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is True
        assert outcome.result is None
        assert outcome.caller_error is None

    async def test_returns_applied_false_with_caller_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"applied": False, "caller_error": "ticket is already in closed state"},
            )

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.result is None
        assert outcome.caller_error == "ticket is already in closed state"
        assert "applied=false" in (outcome.log_detail or "")

    async def test_returns_applied_false_with_default_caller_error_when_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": False, "caller_error": None})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.result is None
        assert outcome.caller_error == "apply failed"

    async def test_sends_exact_request_shape_and_auth_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        seen: dict[str, Any] = {}
        fixed_hold_id = uuid.uuid4()

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = dict(request.headers)
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"applied": True, "result": None})

        _patch_transport(monkeypatch, handler)
        ctx = _ctx(
            hold_id=fixed_hold_id,
            kind="linear_open_ticket",
            action={"title": "Fix bug", "team_id": "T1"},
            target_id="PR-999",
            action_type="open_ticket",
            rationale="closing ticket after merge",
            proposed_by_bot_id="agent-007",
            owner_sub="user-dan",
        )
        await apply_proposal(ctx)

        assert seen["headers"].get("authorization") == f"Bearer {_TOKEN}"
        assert seen["headers"].get("content-type") == "application/json"
        assert seen["body"] == {
            "kind": "linear_open_ticket",
            "action": {"title": "Fix bug", "team_id": "T1"},
            "target_id": "PR-999",
            "action_type": "open_ticket",
            "rationale": "closing ticket after merge",
            "proposed_by_bot_id": "agent-007",
            "owner_sub": "user-dan",
            "hold_id": str(fixed_hold_id),
        }


class TestApplyProposalValidation:
    async def test_returns_safe_outcome_when_hold_id_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        network_called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal network_called
            network_called = True
            return httpx.Response(200, json={"applied": True})

        _patch_transport(monkeypatch, handler)
        ctx = ProposalContext(
            kind="k",
            action={},
            target_id="t",
            action_type="a",
            rationale="r",
            proposed_by_bot_id="b",
            owner_sub="s",
            hold_id=None,
        )
        outcome = await apply_proposal(ctx)
        assert outcome.applied is False
        assert outcome.caller_error == "cannot apply proposal without a hold_id"
        assert not network_called

    async def test_missing_proposal_apply_url_fails_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.delenv(PROPOSAL_APPLY_URL_ENV_VAR)
        monkeypatch.delenv("PROPOSAL_ACTION_URL", raising=False)

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert "PROPOSAL_APPLY_URL environment variable is not set" in (outcome.log_detail or "")

    async def test_non_https_url_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, "http://insecure.example.com/actions")

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert "must be an https:// URL" in (outcome.log_detail or "")

    async def test_missing_proposal_apply_token_fails_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.delenv(PROPOSAL_APPLY_TOKEN_ENV_VAR)
        monkeypatch.delenv("PROPOSAL_ACTION_TOKEN", raising=False)

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert "PROPOSAL_APPLY_TOKEN environment variable is not set" in (outcome.log_detail or "")

    async def test_invalid_timeout_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        for bad_val in ("not-a-number", "-1.0", "0", "nan", "inf"):
            monkeypatch.setenv(PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR, bad_val)
            outcome = await apply_proposal(_ctx())
            assert outcome.applied is False
            assert outcome.caller_error == "server configuration error"

    async def test_invalid_sni_host_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, "invalid host with spaces")
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert "not a bare hostname" in (outcome.log_detail or "")

    async def test_fallback_env_vars_used_when_primary_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(PROPOSAL_APPLY_URL_ENV_VAR, raising=False)
        monkeypatch.delenv(PROPOSAL_APPLY_TOKEN_ENV_VAR, raising=False)
        monkeypatch.delenv(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, raising=False)
        monkeypatch.setenv("PROPOSAL_ACTION_URL", _URL)
        monkeypatch.setenv("PROPOSAL_ACTION_TOKEN", _TOKEN)
        monkeypatch.setenv("PROPOSAL_ACTION_TLS_SNI_HOST", "comms-approvals.example.ts.net")

        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={"applied": True})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is True
        assert seen["url"] == f"{_URL}/proposals/apply"
        assert seen["auth"] == f"Bearer {_TOKEN}"


class TestApplyProposalNetworkAndHttpErrors:
    async def test_connect_error_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service unreachable"
        assert "Connection refused" in (outcome.log_detail or "")

    async def test_timeout_error_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Read timed out")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service unreachable"
        assert "Read timed out" in (outcome.log_detail or "")

    async def test_invalid_url_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, "https://invalid url with spaces.com")
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service unreachable"

    async def test_http_401_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"detail": "invalid token"})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert "status 401" in (outcome.log_detail or "")

    async def test_http_403_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"detail": "forbidden: scope missing"})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert "status 403" in (outcome.log_detail or "")

    async def test_http_409_conflict_includes_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                409,
                json={"detail": "an apply for this proposal is already in progress"},
            )

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert (
            outcome.caller_error
            == "proposal apply conflict: an apply for this proposal is already in progress"
        )
        assert (
            outcome.log_detail
            == "proposal apply conflict: an apply for this proposal is already in progress"
        )

    async def test_http_422_unprocessable_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                422,
                json={"detail": [{"loc": ["body", "target_id"], "msg": "field required"}]},
            )

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply request was rejected as malformed"
        assert "422" in (outcome.log_detail or "")

    async def test_http_500_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal server error")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service unavailable"
        assert "status 500" in (outcome.log_detail or "")

    async def test_http_503_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="service unavailable")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service unavailable"
        assert "status 503" in (outcome.log_detail or "")

    async def test_http_404_unexpected_status_fails_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="not found")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service returned unexpected status"
        assert "status 404" in (outcome.log_detail or "")

    async def test_non_json_200_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not-valid-json")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service returned malformed response"
        assert "not valid JSON" in (outcome.log_detail or "")

    async def test_non_object_json_200_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=["applied", True])

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service returned malformed response"
        assert "not an object" in (outcome.log_detail or "")

    async def test_non_bool_applied_200_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": "true"})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service returned malformed response"
        assert "not a bool" in (outcome.log_detail or "")

    async def test_non_dict_result_200_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": True, "result": "not-a-dict"})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service returned malformed response"
        assert "not a dict" in (outcome.log_detail or "")


class TestApplyProposalCancellation:
    async def test_cancelled_error_is_reraised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        _patch_transport(monkeypatch, handler)
        with pytest.raises(asyncio.CancelledError):
            await apply_proposal(_ctx())


class TestTlsSniOverride:
    async def test_sni_hook_sets_headers_and_extension(self) -> None:
        sni_host = "custom-peer.example.ts.net"
        client = proposal_apply_http_client._build_apply_client(10.0, sni_host)
        assert client.follow_redirects is False

        request = client.build_request("GET", "https://10.0.0.1/actions/proposals/apply")
        for hook in client.event_hooks.get("request", []):
            await hook(request)

        assert request.headers["host"] == sni_host
        assert request.extensions.get("sni_hostname") == sni_host


class _MockJudgeDelegate:
    """Mock delegate representing RHProposalJudge."""

    def __init__(self) -> None:
        self.classify_called = False
        self.fingerprint_called = False
        self.judge_called = False
        self.apply_called = False

    def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
        self.classify_called = True
        return ProposalClassification(priority="medium")

    async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
        self.fingerprint_called = True
        return ProposalFingerprint(status="digest", digest="sha256:abc")

    async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
        self.judge_called = True
        return ProposalVerdict(approved=True, decision_note="looks good")

    async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
        self.apply_called = True
        # Simulate loading forbidden modules if called:
        raise AssertionError("delegate.apply() MUST NEVER BE CALLED by the board!")


class TestHttpApplyProposalJudgeWrapper:
    def test_classify_delegates_to_underlying_judge(self) -> None:
        delegate = _MockJudgeDelegate()
        judge = HttpApplyProposalJudge(delegate)
        res = judge.classify("kind", {"foo": "bar"})
        assert delegate.classify_called is True
        assert res.priority == "medium"

    async def test_fingerprint_delegates_to_underlying_judge(self) -> None:
        delegate = _MockJudgeDelegate()
        judge = HttpApplyProposalJudge(delegate)
        ctx = _ctx()
        res = await judge.fingerprint(ctx)
        assert delegate.fingerprint_called is True
        assert res.status == "digest"
        assert res.digest == "sha256:abc"

    async def test_judge_delegates_to_underlying_judge(self) -> None:
        delegate = _MockJudgeDelegate()
        judge = HttpApplyProposalJudge(delegate)
        ctx = _ctx()
        res = await judge.judge(ctx)
        assert delegate.judge_called is True
        assert res.approved is True
        assert res.decision_note == "looks good"

    async def test_apply_routes_to_http_client_and_never_calls_delegate_apply(
        self,
    ) -> None:
        delegate = _MockJudgeDelegate()
        applier_called = False
        expected_outcome = ProposalApplyOutcome(
            applied=True, result={"applied_via": "http"}, caller_error=None, log_detail=None
        )

        async def fake_applier(ctx: ProposalContext) -> ProposalApplyOutcome:
            nonlocal applier_called
            applier_called = True
            return expected_outcome

        judge = HttpApplyProposalJudge(delegate, applier=fake_applier)
        ctx = _ctx()
        outcome = await judge.apply(ctx)

        assert outcome is expected_outcome
        assert applier_called is True
        # Confirm delegate.apply() was NEVER invoked
        assert delegate.apply_called is False

    async def test_zero_linear_modules_reachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Confirm that calling HttpApplyProposalJudge.apply() does NOT load
        rh_comms_plugins.linear_client or rh_comms_plugins.proposal_apply_service.
        """
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": True, "result": {"ok": True}})

        _patch_transport(monkeypatch, handler)

        delegate = _MockJudgeDelegate()
        judge = HttpApplyProposalJudge(delegate)
        outcome = await judge.apply(_ctx())

        assert outcome.applied is True
        assert delegate.apply_called is False

        forbidden = {
            "rh_comms_plugins.linear_client",
            "rh_comms_plugins.proposal_apply_service",
        }
        loaded = forbidden & set(sys.modules.keys())
        assert not loaded, f"Forbidden Linear modules loaded: {loaded}"


class TestProposalJudgeWiring:
    def test_get_proposal_judge_wraps_rh_proposal_judge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class RHProposalJudge:
            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                return ProposalClassification(priority="low")

            async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
                return ProposalFingerprint(status="no_target")

            async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
                return ProposalVerdict(approved=False, decision_note=None)

            async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
                raise AssertionError("shim must not be called")

        plugins._proposal_judge = None
        monkeypatch.setitem(plugins.PROPOSAL_JUDGES, "fake_rh", lambda: RHProposalJudge())
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "fake_rh")

        resolved = plugins.get_proposal_judge()
        assert isinstance(resolved, HttpApplyProposalJudge)
        assert isinstance(resolved.delegate, RHProposalJudge)

    def test_get_proposal_judge_does_not_wrap_escalate_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        plugins._proposal_judge = None
        monkeypatch.delenv(plugins.PROPOSAL_JUDGE_ENV_VAR, raising=False)

        resolved = plugins.get_proposal_judge()
        assert isinstance(resolved, plugins.EscalateAllProposalJudge)
        assert not isinstance(resolved, HttpApplyProposalJudge)

    def test_build_rh_proposal_judge_constructs_http_apply_judge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeRH:
            pass

        monkeypatch.setattr(proposal_apply_http_client, "_load_rh_proposal_judge", lambda: FakeRH())
        judge = build_rh_proposal_judge()
        assert isinstance(judge, HttpApplyProposalJudge)
        assert isinstance(judge.delegate, FakeRH)

    def test_validate_configuration_warns_when_apply_url_missing_for_custom_judge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        plugins._proposal_judge = None
        monkeypatch.setitem(
            plugins.PROPOSAL_JUDGES,
            "custom_judge",
            lambda: plugins.EscalateAllProposalJudge(),
        )
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "custom_judge")
        monkeypatch.delenv(PROPOSAL_APPLY_URL_ENV_VAR, raising=False)
        monkeypatch.delenv("PROPOSAL_ACTION_URL", raising=False)

        # Should not raise, validate_configuration completes
        plugins.validate_configuration()
