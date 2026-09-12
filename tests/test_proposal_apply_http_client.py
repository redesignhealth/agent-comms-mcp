"""Tests for proposal_apply_http_client (TECH-6213 PR-B1).

Covers:
- HTTP client POST /actions/proposals/apply request serialization and headers
- Success paths (applied=True with result, applied=False with caller_error)
- Failure taxonomy (DEFINITE_CLEAN vs DEFINITE_TERMINAL vs AMBIGUOUS)
- Retry loop with saw_ambiguous stickiness, jittered backoff, budget deadline, and attempt cap
- Never-raise behavior: network errors, HTTP errors (401, 403, 409, 422, 5xx),
  malformed responses, missing env vars, and validation errors all map to safe
  ProposalApplyOutcome instances
- Indeterminate outcomes: transport timeouts, 409 conflicts, and 5xx errors return
  indeterminate=True on exhaustion to prevent duplicate external writes
- Cancellation propagation: asyncio.CancelledError is re-raised (not retried)
- TLS SNI override hook behavior
- Hard-fail config validation in validate_configuration() for HttpApplyProposalJudge (FIX 2)
- Subclass bypass prevention in plugins.get_proposal_judge() (FIX 1)
- Real package integration test verifying zero Linear modules reachable (FIX 3)
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path
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
    PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR,
    PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR,
    PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR,
    PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR,
    PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR,
    PROPOSAL_APPLY_TOKEN_ENV_VAR,
    PROPOSAL_APPLY_URL_ENV_VAR,
    HttpApplyProposalJudge,
    apply_proposal,
    build_rh_proposal_judge,
    validate_proposal_apply_configuration,
)

_URL = "https://comms-approvals.example.ts.net/actions"
_TOKEN = "test-proposal-apply-token"


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, _URL)
    monkeypatch.setenv(PROPOSAL_APPLY_TOKEN_ENV_VAR, _TOKEN)
    monkeypatch.delenv(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, raising=False)
    monkeypatch.delenv(PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR, raising=False)
    monkeypatch.delenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, raising=False)
    monkeypatch.delenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, raising=False)
    monkeypatch.delenv(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR, raising=False)
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
        assert outcome.indeterminate is False

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
        assert outcome.indeterminate is False

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
        assert outcome.indeterminate is False

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
        assert outcome.indeterminate is False

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
        assert outcome.indeterminate is False
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
        assert outcome.indeterminate is False
        assert "PROPOSAL_APPLY_URL environment variable is not set" in (outcome.log_detail or "")

    async def test_non_https_url_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, "http://insecure.example.com/actions")

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert outcome.indeterminate is False
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
        assert outcome.indeterminate is False
        assert "PROPOSAL_APPLY_TOKEN environment variable is not set" in (outcome.log_detail or "")

    async def test_invalid_timeout_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        for bad_val in ("not-a-number", "-1.0", "0", "nan", "inf"):
            monkeypatch.setenv(PROPOSAL_APPLY_TIMEOUT_SECONDS_ENV_VAR, bad_val)
            outcome = await apply_proposal(_ctx())
            assert outcome.applied is False
            assert outcome.caller_error == "server configuration error"
            assert outcome.indeterminate is False

    async def test_invalid_max_attempts_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        for bad_val in ("0", "-1", "11", "not-an-int"):
            monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, bad_val)
            outcome = await apply_proposal(_ctx())
            assert outcome.applied is False
            assert outcome.caller_error == "server configuration error"
            assert outcome.indeterminate is False

    async def test_invalid_backoff_seconds_fails_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        for bad_val in ("0", "-0.5", "nan", "inf", "abc"):
            monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, bad_val)
            outcome = await apply_proposal(_ctx())
            assert outcome.applied is False
            assert outcome.caller_error == "server configuration error"
            assert outcome.indeterminate is False

    async def test_invalid_budget_seconds_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        for bad_val in ("0", "-10", "nan", "inf", "abc"):
            monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR, bad_val)
            outcome = await apply_proposal(_ctx())
            assert outcome.applied is False
            assert outcome.caller_error == "server configuration error"
            assert outcome.indeterminate is False

    async def test_invalid_sni_host_fails_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, "invalid host with spaces")
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.caller_error == "server configuration error"
        assert outcome.indeterminate is False
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


class TestFailureTaxonomyAndRetries:
    async def test_connect_error_is_clean_and_does_not_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise httpx.ConnectError("Connection refused")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 1
        assert outcome.applied is False
        assert outcome.caller_error == "proposal apply service unreachable"
        assert outcome.indeterminate is False

    async def test_definite_terminal_statuses_do_not_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        for code, expected_err in [
            (401, "server configuration error"),
            (403, "server configuration error"),
            (422, "proposal apply request was rejected as malformed"),
            (404, "proposal apply service returned unexpected status"),
        ]:
            calls = 0

            def handler(request: httpx.Request, status=code) -> httpx.Response:
                nonlocal calls
                calls += 1
                return httpx.Response(status, json={"detail": "error"})

            _patch_transport(monkeypatch, handler)
            outcome = await apply_proposal(_ctx())
            assert calls == 1
            assert outcome.applied is False
            assert outcome.caller_error == expected_err
            assert outcome.indeterminate is False

    async def test_retry_recovers_from_409_conflict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    409, json={"detail": "an apply for this proposal is already in progress"}
                )
            return httpx.Response(200, json={"applied": True, "result": {"recovered": True}})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 2
        assert outcome.applied is True
        assert outcome.result == {"recovered": True}
        assert outcome.indeterminate is False

    async def test_retry_recovers_from_5xx_server_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(500, text="internal server error")
            return httpx.Response(200, json={"applied": True, "result": {"ok": True}})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 2
        assert outcome.applied is True
        assert outcome.indeterminate is False

    async def test_retry_recovers_from_read_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.ReadTimeout("Read timed out")
            return httpx.Response(200, json={"applied": True, "result": {"ok": True}})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 2
        assert outcome.applied is True
        assert outcome.indeterminate is False

    async def test_saw_ambiguous_stickiness_invariant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Critical invariant: once ambiguous, always ambiguous.

        If attempt 1 fails ambiguously (ReadTimeout) and attempt 2 fails with a
        definite-clean error (ConnectError), the final outcome MUST remain
        indeterminate=True because attempt 1 may have succeeded server-side.
        """
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "2")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.ReadTimeout("Timeout waiting for response")
            raise httpx.ConnectError("Network dropped completely")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 2
        assert outcome.applied is False
        assert outcome.indeterminate is True
        assert "awaiting manual reconciliation" in (outcome.caller_error or "")

    async def test_retry_exhaustion_on_ambiguous_returns_indeterminate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "3")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                409, json={"detail": "an apply for this proposal is already in progress"}
            )

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 3
        assert outcome.applied is False
        assert outcome.indeterminate is True
        assert "awaiting manual reconciliation" in (outcome.caller_error or "")

    async def test_retry_budget_exhaustion_returns_indeterminate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "5")
        # Budget of 0.2s will exhaust after 1 ambiguous attempt
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR, "0.2")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "1.0")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(500, text="server error")

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert calls == 1
        assert outcome.applied is False
        assert outcome.indeterminate is True

    async def test_payload_identity_preserved_across_retries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verifies that the same payload dict and request body bytes are sent
        on every retry, guaranteeing request-digest determinism.
        """
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "2")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01")
        payloads: list[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            payloads.append(request.content)
            if len(payloads) == 1:
                return httpx.Response(503, text="temporarily unavailable")
            return httpx.Response(200, json={"applied": True})

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is True
        assert len(payloads) == 2
        assert payloads[0] == payloads[1]

    async def test_cancellation_during_backoff_sleep_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "3")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "5.0")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Timeout")

        _patch_transport(monkeypatch, handler)

        async def _run_and_cancel():
            task = asyncio.create_task(apply_proposal(_ctx()))
            await asyncio.sleep(0.05)  # Let it hit the sleep
            task.cancel()
            await task

        with pytest.raises(asyncio.CancelledError):
            await _run_and_cancel()


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
            applied=True,
            result={"applied_via": "http"},
            caller_error=None,
            log_detail=None,
            indeterminate=False,
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
        assert delegate.apply_called is False


class TestConfigValidationHardFails:
    """FIX 2: validate_configuration() must hard-fail (raise RuntimeError)
    when HttpApplyProposalJudge has missing or invalid configuration.
    """

    def test_fails_when_proposal_apply_url_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.delenv(PROPOSAL_APPLY_URL_ENV_VAR)
        with pytest.raises(RuntimeError, match="PROPOSAL_APPLY_URL is required"):
            validate_proposal_apply_configuration()

    def test_fails_when_proposal_apply_url_not_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, "http://insecure.example.com")
        with pytest.raises(RuntimeError, match="must be an https:// URL"):
            validate_proposal_apply_configuration()

    def test_fails_when_proposal_apply_token_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.delenv(PROPOSAL_APPLY_TOKEN_ENV_VAR)
        with pytest.raises(RuntimeError, match="PROPOSAL_APPLY_TOKEN is required"):
            validate_proposal_apply_configuration()

    def test_validate_configuration_hard_fails_when_http_apply_judge_unconfigured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        delegate = _MockJudgeDelegate()
        monkeypatch.setitem(
            plugins.PROPOSAL_JUDGES, "custom_http", lambda: HttpApplyProposalJudge(delegate)
        )
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "custom_http")
        monkeypatch.delenv(PROPOSAL_APPLY_URL_ENV_VAR, raising=False)
        monkeypatch.delenv("PROPOSAL_ACTION_URL", raising=False)
        plugins._proposal_judge = None

        with pytest.raises(RuntimeError, match="PROPOSAL_APPLY_URL is required"):
            plugins.validate_configuration()

    def test_build_rh_proposal_judge_factory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeRH:
            pass

        monkeypatch.setattr(proposal_apply_http_client, "_load_rh_proposal_judge", lambda: FakeRH())
        judge = build_rh_proposal_judge()
        assert isinstance(judge, HttpApplyProposalJudge)
        assert isinstance(judge.delegate, FakeRH)

    def test_validate_configuration_passes_for_escalate_all_without_apply_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(plugins.PROPOSAL_JUDGE_ENV_VAR, raising=False)
        monkeypatch.delenv(PROPOSAL_APPLY_URL_ENV_VAR, raising=False)
        monkeypatch.delenv("PROPOSAL_ACTION_URL", raising=False)
        plugins._proposal_judge = None

        # Must not raise
        plugins.validate_configuration()


class TestSubclassBypassAndRealPackageReachability:
    """FIX 1 & FIX 3:
    - Subclass bypass prevention: a subclass of RHProposalJudge must STILL be
      wrapped with HttpApplyProposalJudge.
    - Integration test with real RHProposalJudge: verify that resolving via
      plugins.get_proposal_judge() and calling apply() never imports Linear modules.
    """

    def test_subclass_of_rh_proposal_judge_is_wrapped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeBaseRHProposalJudge:
            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                return ProposalClassification(priority="low")

            async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
                return ProposalFingerprint(status="no_target")

            async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
                return ProposalVerdict(approved=False, decision_note=None)

            async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
                raise AssertionError("shim must not be called")

        # Give it the name RHProposalJudge
        FakeBaseRHProposalJudge.__name__ = "RHProposalJudge"

        class CustomRHProposalJudge(FakeBaseRHProposalJudge):
            pass

        plugins._proposal_judge = None
        monkeypatch.setitem(plugins.PROPOSAL_JUDGES, "custom_rh", lambda: CustomRHProposalJudge())
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "custom_rh")

        resolved = plugins.get_proposal_judge()
        assert isinstance(resolved, HttpApplyProposalJudge)
        assert isinstance(resolved.delegate, CustomRHProposalJudge)

    async def test_real_package_loading_and_zero_linear_reachability(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FIX 3: integration test using the REAL agent-comms-approvals RHProposalJudge.
        Confirms sys.modules never contains rh_comms_plugins.linear_client or
        rh_comms_plugins.proposal_apply_service after a full get_proposal_judge() + apply() call.
        """
        # Ensure sibling approvals repo is importable if on disk
        candidates = [
            Path(__file__).resolve().parents[2] / "agent-comms-approvals-tech-5755",
            Path(__file__).resolve().parents[2] / "agent-comms-approvals",
            Path(__file__).resolve().parents[2] / "agent-comms-approvals-proposal-judge-plan",
        ]
        for candidate in candidates:
            if (candidate / "rh_comms_plugins" / "proposal_judge.py").is_file():
                if str(candidate) not in sys.path:
                    sys.path.insert(0, str(candidate))
                break

        try:
            from rh_comms_plugins.proposal_judge import RHProposalJudge
        except ImportError:
            pytest.skip("rh_comms_plugins is not installed in this environment")

        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": True, "result": {"real_ok": True}})

        _patch_transport(monkeypatch, handler)

        # Test both base RHProposalJudge and a custom subclass
        class CustomRealRHProposalJudge(RHProposalJudge):
            pass

        for judge_factory in (RHProposalJudge, CustomRealRHProposalJudge):
            plugins._proposal_judge = None
            monkeypatch.setitem(
                plugins.PROPOSAL_JUDGES, "test_real_rh", lambda f=judge_factory: f()
            )
            monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "test_real_rh")

            judge = plugins.get_proposal_judge()
            assert isinstance(judge, HttpApplyProposalJudge)
            assert isinstance(judge.delegate, judge_factory)

            ctx = _ctx()
            outcome = await judge.apply(ctx)
            assert outcome.applied is True

            forbidden = {
                "rh_comms_plugins.linear_client",
                "rh_comms_plugins.proposal_apply_service",
            }
            loaded = forbidden & set(sys.modules.keys())
            assert not loaded, f"Linear modules leaked into sys.modules: {loaded}"
