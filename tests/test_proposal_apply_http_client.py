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
import time
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
    TAILNET_HTTP_PROXY_ENV_VAR,
    HttpApplyProposalJudge,
    apply_proposal,
    build_rh_proposal_judge,
    tailnet_proxy_mounts,
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
    monkeypatch.delenv(TAILNET_HTTP_PROXY_ENV_VAR, raising=False)


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

    async def test_returns_applied_false_with_indeterminate_true_preserves_indeterminate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TECH-7170: When approvals returns 200 with applied=false and indeterminate=true
        (e.g. backend transport timeout), proposal_apply_http_client treats it as ambiguous,
        preserving indeterminate=True so the hold remains at status='applying'."""
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "1")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "applied": False,
                    "caller_error": "Arcana API timeout",
                    "indeterminate": True,
                },
            )

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is True
        assert "awaiting manual reconciliation" in (outcome.caller_error or "")
        assert "Arcana API timeout" in str(outcome.log_detail)

    async def test_indeterminate_false_or_missing_returns_decided_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backward compatibility: when indeterminate is explicitly false or missing,
        applied=false is a decided terminal failure (indeterminate=False)."""
        _set_required_env(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "applied": False,
                    "caller_error": "stale head revision",
                    "indeterminate": False,
                },
            )

        _patch_transport(monkeypatch, handler)
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "stale head revision"

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

    async def test_cross_brain_target_is_sent_only_when_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        bodies: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"applied": True, "result": None})

        _patch_transport(monkeypatch, handler)
        await apply_proposal(_ctx())
        await apply_proposal(_ctx()._replace(cross_brain_target_sub="target-sub"))
        assert "cross_brain_target_sub" not in bodies[0]
        assert bodies[1]["cross_brain_target_sub"] == "target-sub"


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
        assert "must be an https:// URL, got scheme='http'" in (outcome.log_detail or "")

    async def test_missing_proposal_apply_token_fails_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.delenv(PROPOSAL_APPLY_TOKEN_ENV_VAR)

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
        # Budget of 2.1s: attempt 1 runs (delay 0.2s), before attempt 2 remaining budget < 2.0s
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR, "2.1")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "1.0")
        calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.2)
            return httpx.Response(500, text="server error")

        def fake_build_apply_client(
            timeout_seconds: float, tls_sni_host: str | None
        ) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                timeout=httpx.Timeout(timeout_seconds),
                transport=httpx.MockTransport(handler),
            )

        monkeypatch.setattr(
            proposal_apply_http_client, "_build_apply_client", fake_build_apply_client
        )

        outcome = await apply_proposal(_ctx())
        assert calls == 1
        assert outcome.applied is False
        assert outcome.indeterminate is True

    async def test_wall_clock_timeout_enforced_via_asyncio_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "1")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR, "2.05")

        async def slow_handler(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(2.5)
            return httpx.Response(200, json={"applied": True})

        def fake_build_apply_client(
            timeout_seconds: float, tls_sni_host: str | None
        ) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                timeout=httpx.Timeout(timeout_seconds),
                transport=httpx.MockTransport(slow_handler),
            )

        monkeypatch.setattr(
            proposal_apply_http_client, "_build_apply_client", fake_build_apply_client
        )

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is True
        assert "wall-clock retry budget expired" in (outcome.log_detail or "")

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
        """Verifies that asyncio.CancelledError during retry backoff sleep
        propagates immediately.
        """
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "3")
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "5.0")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Timeout")

        _patch_transport(monkeypatch, handler)

        async def _run_and_cancel() -> None:
            task = asyncio.create_task(apply_proposal(_ctx()))
            await asyncio.sleep(0.05)
            task.cancel()
            await task

        with pytest.raises(asyncio.CancelledError):
            await _run_and_cancel()

    async def test_attempt_not_started_when_budget_already_expired(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verifies that zero HTTP requests are started when the budget is already expired,
        and a definite (non-indeterminate) outcome is returned because no request was sent.
        """
        _set_required_env(monkeypatch)
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, json={"applied": True})

        _patch_transport(monkeypatch, handler)
        t0 = time.monotonic()
        times = [t0, t0 + 50.0, t0 + 50.0]
        monkeypatch.setattr(time, "monotonic", lambda: times.pop(0) if times else t0 + 50.0)

        outcome = await apply_proposal(_ctx())
        assert calls == 0
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert "retry budget expired before any request was sent" in (outcome.caller_error or "")


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


class TestTailnetProxyRouting:
    """TECH-8246: Route *.ts.net apply requests through TAILNET_HTTP_PROXY."""

    def test_unset_proxy_env_returns_empty_mounts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(TAILNET_HTTP_PROXY_ENV_VAR, raising=False)
        assert tailnet_proxy_mounts() == {}

    def test_empty_proxy_env_returns_empty_mounts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, "")
        assert tailnet_proxy_mounts() == {}
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, "   ")
        assert tailnet_proxy_mounts() == {}

    @pytest.mark.parametrize(
        "loopback_url",
        [
            "http://127.0.0.1:1055",
            "http://localhost:1055",
            "http://[::1]:1055",
        ],
    )
    def test_valid_loopback_proxy_mounts_ts_net(
        self, monkeypatch: pytest.MonkeyPatch, loopback_url: str
    ) -> None:
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, loopback_url)
        mounts = tailnet_proxy_mounts()
        assert list(mounts.keys()) == ["all://*.ts.net"]
        assert isinstance(mounts["all://*.ts.net"], httpx.AsyncHTTPTransport)

    @pytest.mark.parametrize(
        "invalid_proxy",
        [
            "https://127.0.0.1:1055",
            "http://example.com:1055",
            "http://10.0.0.1:1055",
            "http://192.168.1.1:1055",
            "http://127.0.0.1",
            "127.0.0.1:1055",
            "ftp://127.0.0.1:1055",
            "socks5://127.0.0.1:1055",
        ],
    )
    async def test_malformed_or_non_loopback_proxy_rejected(
        self, monkeypatch: pytest.MonkeyPatch, invalid_proxy: str
    ) -> None:
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, invalid_proxy)
        with pytest.raises(ValueError, match="TAILNET_HTTP_PROXY"):
            tailnet_proxy_mounts()

        with pytest.raises(ValueError, match="TAILNET_HTTP_PROXY"):
            proposal_apply_http_client._build_apply_client(10.0, None)

        _set_required_env(monkeypatch)
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, invalid_proxy)
        with pytest.raises(RuntimeError, match="TAILNET_HTTP_PROXY"):
            validate_proposal_apply_configuration()

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "server configuration error"
        assert "TAILNET_HTTP_PROXY" in (outcome.log_detail or "")

    def test_tailnet_url_uses_proxy_and_non_tailnet_direct(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, "http://127.0.0.1:1055")
        client = proposal_apply_http_client._build_apply_client(10.0, None)

        tsnet_req = client.build_request(
            "POST",
            "https://comms-approvals.drum-mackarel.ts.net/actions/proposals/apply",
        )
        tsnet_transport = client._transport_for_url(tsnet_req.url)
        # Transport for *.ts.net must be the proxy transport, not client._transport
        assert tsnet_transport is not client._transport
        assert isinstance(tsnet_transport, httpx.AsyncHTTPTransport)

        direct_req1 = client.build_request("POST", "https://api.linear.app/graphql")
        direct_req2 = client.build_request("POST", "https://127.0.0.1:8000/actions")
        assert client._transport_for_url(direct_req1.url) is client._transport
        assert client._transport_for_url(direct_req2.url) is client._transport

    async def test_connect_proxy_routing_and_sni_host_preserved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        connects: list[str] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            head = await reader.readuntil(b"\r\n\r\n")
            connects.append(head.split(b"\r\n")[0].decode())
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, f"http://127.0.0.1:{port}")
        sni_host = "approvals-peer.drum-mackarel.ts.net"
        client = proposal_apply_http_client._build_apply_client(5.0, sni_host)
        assert client.follow_redirects is False

        seen: list[tuple[str, str]] = []

        async def record_hook(r: httpx.Request) -> None:
            seen.append((r.headers["host"], str(r.extensions.get("sni_hostname"))))

        client.event_hooks.setdefault("request", []).append(record_hook)

        async with server, client:
            # Non-ts.net dials direct (bypasses proxy)
            with pytest.raises(httpx.ConnectError):
                await client.get("https://127.0.0.1:1/actions")
            assert connects == []

            # *.ts.net routes through CONNECT proxy
            with pytest.raises(httpx.ProxyError):
                await client.post(
                    "https://comms-approvals.drum-mackarel.ts.net/actions/proposals/apply"
                )

        assert connects == ["CONNECT comms-approvals.drum-mackarel.ts.net:443 HTTP/1.1"]
        assert (sni_host, sni_host) in seen

    async def test_apply_proposal_with_proxy_failure_disposition(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        _set_required_env(monkeypatch)
        monkeypatch.setenv(
            proposal_apply_http_client.PROPOSAL_APPLY_URL_ENV_VAR,
            "https://comms-approvals.drum-mackarel.ts.net/actions",
        )
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, f"http://127.0.0.1:{port}")

        async with server:
            outcome = await apply_proposal(_ctx())

        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "proposal apply service unreachable"
        assert "connection failed" in (outcome.log_detail or "")

    async def test_apply_proposal_dials_connect_proxy_for_ts_net_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end socket-level proof that apply_proposal's *.ts.net POST
        actually dials the CONNECT proxy: the proxy server records the tunnel
        request line it received.

        The 502 disposition test above cannot distinguish proxy-routed from
        direct-dialed traffic -- httpx.ConnectError (direct dial, DNS failure)
        and httpx.ProxyError map to IDENTICAL outcome strings -- so only the
        recorded CONNECT line proves routing. A regression that drops
        ``mounts=`` from the client construction would dial direct and never
        reach this server. Exactly one CONNECT also pins the no-retry
        semantics for a definite-clean proxy failure.
        """
        connects: list[str] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            head = await reader.readuntil(b"\r\n\r\n")
            connects.append(head.split(b"\r\n")[0].decode())
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        _set_required_env(monkeypatch)
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, f"http://127.0.0.1:{port}")

        async with server:
            # Real _build_apply_client (no MockTransport patch): mounts must
            # carry the POST through the proxy for the default ts.net base URL.
            outcome = await apply_proposal(_ctx())

        assert connects == ["CONNECT comms-approvals.example.ts.net:443 HTTP/1.1"]
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "proposal apply service unreachable"
        assert "connection failed" in (outcome.log_detail or "")

    @pytest.mark.parametrize(
        "bad_port_proxy",
        [
            "http://127.0.0.1:abc",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:-1",
        ],
    )
    async def test_unparseable_proxy_port_rejected_safely(
        self, monkeypatch: pytest.MonkeyPatch, bad_port_proxy: str
    ) -> None:
        """Ports urlsplit cannot parse (non-numeric / out of 0-65535 range)
        raise ValueError with messages that do NOT name TAILNET_HTTP_PROXY, so
        the match="TAILNET_HTTP_PROXY" parametrize above cannot cover them.
        Every seam must still reject them safely: ValueError from the mounts
        builder and the client builder, RuntimeError from boot validation, and
        a safe non-indeterminate outcome from apply_proposal (no raise, no
        network attempt -- the failure is caught at config pre-flight).
        """
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, bad_port_proxy)
        with pytest.raises(ValueError):
            tailnet_proxy_mounts()
        with pytest.raises(ValueError):
            proposal_apply_http_client._build_apply_client(10.0, None)

        _set_required_env(monkeypatch)
        monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, bad_port_proxy)
        with pytest.raises(RuntimeError):
            validate_proposal_apply_configuration()

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "server configuration error"
        assert outcome.log_detail  # sanitized parse failure surfaced for operators


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


# TECH-7711: a duck-typed stand-in for agent-comms-approvals'
# rh_comms_plugins.proposal_judge.InvalidProposalAction, plus the sentinel its
# message carries (preserved on __cause__ for logging, never echoed to a
# caller).
_FORWARDED_PLUGIN_SENTINEL = "SECRET-DELEGATE-INTERNALS-7711"


class _DuckTypedInvalidActionError(ValueError):
    def __init__(self, errors: Any) -> None:
        self.proposal_action_errors = errors
        super().__init__(f"delegate internals: {_FORWARDED_PLUGIN_SENTINEL}")


class _CapabilityDelegate(_MockJudgeDelegate):
    """A delegate exposing the optional ``supported_proposal_kinds``
    capability (an instance attribute, set by each test)."""

    supported_proposal_kinds: Any = None


class TestHttpApplyProposalJudgeWrapper:
    def test_classify_delegates_to_underlying_judge(self) -> None:
        delegate = _MockJudgeDelegate()
        judge = HttpApplyProposalJudge(delegate)
        res = judge.classify("kind", {"foo": "bar"})
        assert delegate.classify_called is True
        assert res.priority == "medium"

    def test_supported_proposal_kinds_forwards_the_delegate_capability(self) -> None:
        """TECH-7711: the wrapper forwards the delegate's optional
        ``supported_proposal_kinds`` capability verbatim -- same object, so
        the board's defensive read sees exactly what the delegate declares."""
        kinds = frozenset({"arcana_source_add", "arcana_source_revise", "linear_progress_update"})
        delegate = _CapabilityDelegate()
        delegate.supported_proposal_kinds = kinds
        judge = HttpApplyProposalJudge(delegate)
        assert judge.supported_proposal_kinds is kinds

    def test_supported_proposal_kinds_is_none_when_delegate_lacks_it(self) -> None:
        """A delegate without the capability forwards ``None`` -- "unknown",
        the same value the board's defensive read treats exactly like an
        absent attribute."""
        judge = HttpApplyProposalJudge(_MockJudgeDelegate())
        assert judge.supported_proposal_kinds is None

    def test_raising_delegate_capability_is_absorbed_by_the_boards_defensive_read(self) -> None:
        """A delegate whose ``supported_proposal_kinds`` property raises
        makes the WRAPPER's own property raise too -- but the board never
        reads it outside ``service._read_supported_proposal_kinds``'s
        try/except, so the capability still reads as "unknown" (``None``),
        never an escaping exception."""
        from service import _read_supported_proposal_kinds

        class _RaisingCapabilityDelegate(_MockJudgeDelegate):
            @property
            def supported_proposal_kinds(self) -> Any:
                raise RuntimeError("exploding capability")

        judge = HttpApplyProposalJudge(_RaisingCapabilityDelegate())
        with pytest.raises(RuntimeError, match="exploding capability"):
            _ = judge.supported_proposal_kinds
        assert _read_supported_proposal_kinds(judge) is None

    def test_classify_signal_flows_through_the_wrapper_into_the_board_error(self) -> None:
        """End-to-end through the wrapper: the delegate's duck-typed
        ``proposal_action_errors`` signal (the shape agent-comms-approvals'
        real ``InvalidProposalAction`` emits) surfaces through
        ``service._classify_proposal`` as ``InvalidProposalActionError`` with
        the sanitized, board-owned message -- the deployment-realistic path
        (board configured with ``PROPOSAL_JUDGE=custom_http`` wrapping the
        real approvals judge)."""

        class _InvalidActionDelegate(_MockJudgeDelegate):
            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                self.classify_called = True
                raise _DuckTypedInvalidActionError([("content", "missing")])

        from exceptions import InvalidProposalActionError
        from service import _classify_proposal

        judge = HttpApplyProposalJudge(_InvalidActionDelegate())
        with pytest.raises(InvalidProposalActionError) as exc_info:
            _classify_proposal(judge, "arcana_source_add", {})
        assert exc_info.value.detail == "invalid arcana_source_add action: content: missing"
        assert exc_info.value.field_errors == (("content", "missing"),)
        assert _FORWARDED_PLUGIN_SENTINEL not in exc_info.value.detail

    def test_unsupported_kind_through_the_wrapper_lists_forwarded_kinds(self) -> None:

        class _UnsupportedKindDelegate(_MockJudgeDelegate):
            supported_proposal_kinds = frozenset(
                {"arcana_source_add", "arcana_source_revise", "linear_progress_update"}
            )

            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                self.classify_called = True
                raise ValueError("unsupported kind: 'arcana_source_upsert'")

        from service import _classify_proposal

        judge = HttpApplyProposalJudge(_UnsupportedKindDelegate())
        with pytest.raises(ValueError) as exc_info:
            _classify_proposal(judge, "arcana_source_upsert", {})
        assert exc_info.value.args[0] == (
            "unsupported proposal kind: 'arcana_source_upsert'; "
            "supported kinds: arcana_source_add, arcana_source_revise, linear_progress_update"
        )

    def test_bare_value_error_for_a_forwarded_supported_kind_is_invalid_action(self) -> None:

        class _BareErrorDelegate(_MockJudgeDelegate):
            supported_proposal_kinds = frozenset({"arcana_source_add"})

            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                self.classify_called = True
                raise ValueError("plugin internals only")

        from exceptions import InvalidProposalActionError
        from service import _classify_proposal

        judge = HttpApplyProposalJudge(_BareErrorDelegate())
        with pytest.raises(InvalidProposalActionError) as exc_info:
            _classify_proposal(judge, "arcana_source_add", {})
        assert exc_info.value.detail == "invalid arcana_source_add action"
        assert exc_info.value.field_errors == ()

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

    def test_fails_when_proposal_apply_budget_below_minimum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)
        monkeypatch.setenv(PROPOSAL_APPLY_RETRY_BUDGET_SECONDS_ENV_VAR, "1.5")
        with pytest.raises(RuntimeError, match=r"must be a finite number >= 2\.0"):
            validate_proposal_apply_configuration()

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

    def test_direct_rh_proposal_judge_instance_triggers_mro_wrapping(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Material suggestion 2: passing an RHProposalJudge-shaped instance directly
        to get_proposal_judge() exercises the MRO wrapping path.
        """

        class FakeDirectRHProposalJudge:
            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                return ProposalClassification(priority="low")

            async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
                return ProposalFingerprint(status="no_target")

            async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
                return ProposalVerdict(approved=False, decision_note=None)

            async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
                raise AssertionError("shim must not be called")

        FakeDirectRHProposalJudge.__name__ = "RHProposalJudge"

        direct_instance = FakeDirectRHProposalJudge()
        plugins._proposal_judge = None
        monkeypatch.setitem(plugins.PROPOSAL_JUDGES, "direct_rh", lambda: direct_instance)
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "direct_rh")

        resolved = plugins.get_proposal_judge()
        assert isinstance(resolved, HttpApplyProposalJudge)
        assert resolved.delegate is direct_instance

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

    def test_mro_fallback_when_package_genuinely_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BLOCKING #2: MRO fallback still wraps when rh_comms_plugins is genuinely unavailable."""

        class FakeBaseRHProposalJudge:
            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                return ProposalClassification(priority="low")

            async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
                return ProposalFingerprint(status="no_target")

            async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
                return ProposalVerdict(approved=False, decision_note=None)

            async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
                raise AssertionError("shim must not be called")

        FakeBaseRHProposalJudge.__name__ = "RHProposalJudge"

        class SubclassWhenPackageUnavailable(FakeBaseRHProposalJudge):
            pass

        # Force ImportError on import of rh_comms_plugins.proposal_judge
        monkeypatch.setitem(sys.modules, "rh_comms_plugins", None)
        monkeypatch.setitem(sys.modules, "rh_comms_plugins.proposal_judge", None)

        plugins._proposal_judge = None
        monkeypatch.setitem(
            plugins.PROPOSAL_JUDGES,
            "unavailable_rh",
            lambda: SubclassWhenPackageUnavailable(),
        )
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "unavailable_rh")

        resolved = plugins.get_proposal_judge()
        assert isinstance(resolved, HttpApplyProposalJudge)
        assert isinstance(resolved.delegate, SubclassWhenPackageUnavailable)

    def test_get_proposal_judge_with_rh_registry_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """BLOCKING #2: PROPOSAL_JUDGE='rh_proposal_judge' resolves via registry
        to HttpApplyProposalJudge.
        """

        class FakeRH:
            def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
                return ProposalClassification(priority="low")

            async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
                return ProposalFingerprint(status="no_target")

            async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
                return ProposalVerdict(approved=False, decision_note=None)

            async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
                raise AssertionError("shim must not be called")

        monkeypatch.setattr(proposal_apply_http_client, "_load_rh_proposal_judge", lambda: FakeRH())
        plugins._proposal_judge = None
        monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, "rh_proposal_judge")

        resolved = plugins.get_proposal_judge()
        assert isinstance(resolved, HttpApplyProposalJudge)
        assert isinstance(resolved.delegate, FakeRH)

    async def test_real_package_loading_and_zero_linear_reachability(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Integration test using the REAL agent-comms-approvals RHProposalJudge.

        Confirms sys.modules never contains rh_comms_plugins.linear_client or
        rh_comms_plugins.proposal_apply_service after a full get_proposal_judge() + apply() call.

        Note: When run in public CI (GitHub Actions), this test will skip because
        agent-comms-approvals is a private downstream package not published to public PyPI.
        Synthetic coverage for MRO wrapping and subclass handling is provided by
        test_subclass_of_rh_proposal_judge_is_wrapped and
        test_mro_fallback_when_package_genuinely_unavailable. Real structural enforcement
        runs at image build time via Dockerfile.board-derived (TECH-6247).
        """
        orig_sys_path = list(sys.path)
        try:
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
                from rh_comms_plugins.proposal_judge import (  # type: ignore[import-not-found]
                    RHProposalJudge,
                )
            except ImportError:
                pytest.skip(
                    "Skipping real-package zero-Linear-reachability check: `rh_comms_plugins` "
                    "(agent-comms-approvals) is not installed in this environment. This is "
                    "EXPECTED and PERMANENT in this repo's public CI (agent-comms-approvals is "
                    "a private package with no path to public GitHub Actions). This test only "
                    "provides real coverage when run LOCALLY with a sibling agent-comms-approvals "
                    "checkout present. The actual CI-enforced regression protection for the "
                    "subclass-bypass bug this test also covers comes from the separate MRO-based "
                    "synthetic tests (which don't require the real package) -- see "
                    "test_subclass_of_rh_proposal_judge_is_wrapped and "
                    "test_mro_fallback_when_package_genuinely_unavailable in this same file. "
                    "See TECH-6247 (agent-comms-approvals) for the real structural enforcement "
                    "mechanism (a build-time Dockerfile assertion in the actual derived image, "
                    "which DOES have the real package installed)."
                )

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
        finally:
            sys.path[:] = orig_sys_path
