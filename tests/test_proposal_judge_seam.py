"""Tests for the ``PROPOSAL_JUDGE`` seam's own contract (proposal-judge-arch
migration): the default ``plugins.EscalateAllProposalJudge``, the
board's defensive wrappers around every plugin call (
``service._classify_proposal``/``service._safe_fingerprint``/
``service._safe_apply``), and the integration-level fail-closed handling in
``create_proposal`` and ``_apply_or_finalize_proposal_hold``.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any, NamedTuple

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from exceptions import InvalidProposalActionError
from models import ProposalHold
from plugins import (
    FINGERPRINT_DIGEST,
    FINGERPRINT_NO_TARGET,
    FINGERPRINT_UNAVAILABLE,
    PROPOSAL_ACTION_ERROR_CODES,
    PROPOSAL_ACTION_ERRORS_ATTR,
    PROPOSAL_SUPPORTED_KINDS_ATTR,
    EscalateAllProposalJudge,
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalContext,
    ProposalFingerprint,
    ProposalTargetError,
    ProposalVerdict,
)
from service import (
    MAX_DECISION_REASON_LENGTH,
    PROPOSAL_HOLD_LEVELS,
    _bound_proposal_error_message,
    _classify_proposal,
    _classify_value_error_to_proposal_error,
    _is_well_formed_target_error,
    _read_supported_proposal_kinds,
    _safe_apply,
    _safe_fingerprint,
    _safe_proposal_kind_label,
    _sanitize_plugin_action_errors,
    _scrub_proposal_error_string,
    create_proposal,
)
from tests.proposal_judge_fakes import FakeProposalJudge


def _ctx(**overrides: Any) -> ProposalContext:
    defaults: dict[str, Any] = {
        "kind": "linear_progress_update",
        "action": {"target_id": "TECH-1", "action_type": "close_ticket"},
        "target_id": "TECH-1",
        "action_type": "close_ticket",
        "rationale": "because reasons",
        "proposed_by_bot_id": "bot-1",
        "owner_sub": "owner-a@example.com",
        "hold_id": uuid.uuid4(),
    }
    defaults.update(overrides)
    return ProposalContext(**defaults)


class TestEscalateAllProposalJudge:
    """The v1 default: accepts any kind at low priority, never
    fingerprints a real target, never auto-approves, and never writes
    anywhere. Fuller registry-level coverage (default-registry membership,
    ``get_proposal_judge()`` resolution) lives in ``tests/test_plugins.py``;
    this class exercises the four methods' own return values directly."""

    def test_classify_accepts_any_kind_at_low_priority(self) -> None:
        judge = EscalateAllProposalJudge()
        assert judge.classify("literally-anything", {}) == ProposalClassification(priority="low")

    async def test_fingerprint_reports_no_target(self) -> None:
        judge = EscalateAllProposalJudge()
        result = await judge.fingerprint(_ctx())
        assert result.status == FINGERPRINT_NO_TARGET

    async def test_judge_never_approves(self) -> None:
        judge = EscalateAllProposalJudge()
        verdict = await judge.judge(_ctx())
        assert verdict.approved is False

    async def test_apply_never_writes_and_explains_why(self) -> None:
        judge = EscalateAllProposalJudge()
        ctx = _ctx(kind="linear_progress_update", action_type="close_ticket")
        outcome = await judge.apply(ctx)
        assert outcome.applied is False
        assert outcome.result is None
        assert outcome.caller_error == "no proposal judge is configured for this deployment"
        assert "PROPOSAL_JUDGE is unset" in (outcome.log_detail or "")


class TestClassifyProposalSeam:
    """``service._classify_proposal`` -- the defensive wrapper around
    ``judge.classify()``."""

    def test_returns_the_judges_priority(self) -> None:
        judge = FakeProposalJudge(classify_result=ProposalClassification(priority="high"))
        assert _classify_proposal(judge, "linear_progress_update", {}) == "high"

    def test_value_error_wrapped_into_board_controlled_message(self) -> None:
        judge = FakeProposalJudge(classify_raises=ValueError("secret internal config key: 12345"))
        with pytest.raises(ValueError, match="unsupported proposal kind: 'nonsense'") as exc_info:
            _classify_proposal(judge, "nonsense", {})
        assert "secret internal config key: 12345" not in str(exc_info.value)
        assert "secret internal config key: 12345" in str(exc_info.value.__cause__)

    def test_non_value_error_is_converted_to_value_error(self) -> None:
        """Fail closed: classify() runs before any hold exists, so there is
        nothing to resolve to `pending` -- an unexpected exception is
        converted into the same ValueError -> 422 path as a genuinely
        unsupported kind, never left to crash the request with a 500."""
        judge = FakeProposalJudge(classify_raises=RuntimeError("boom"))
        with pytest.raises(ValueError):
            _classify_proposal(judge, "linear_progress_update", {})

    @pytest.mark.parametrize("bad_priority", ["urgent", "", "HIGH", None, "invalid", 123])
    def test_priority_outside_hold_levels_raises_value_error(self, bad_priority: Any) -> None:
        judge = FakeProposalJudge(classify_result=ProposalClassification(priority=bad_priority))
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_classify_returning_none_raises_value_error(self) -> None:
        judge = FakeProposalJudge(classify_result=None)
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_classify_returning_non_classification_object_raises_value_error(self) -> None:
        judge = FakeProposalJudge(classify_result={"priority": "low"})
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_valid_priority_passes_through_unchanged(self) -> None:
        for level in PROPOSAL_HOLD_LEVELS:
            judge = FakeProposalJudge(classify_result=ProposalClassification(priority=level))
            assert _classify_proposal(judge, "linear_progress_update", {}) == level


class TestSafeFingerprintSeam:
    """``service._safe_fingerprint`` -- the defensive wrapper around
    ``judge.fingerprint()``."""

    async def test_digest_result_passes_through(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest="abc123")
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_DIGEST
        assert result.digest == "abc123"

    async def test_no_target_result_passes_through(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_NO_TARGET)
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_NO_TARGET

    async def test_unavailable_result_with_error_passes_through(self) -> None:
        error = ProposalTargetError(
            status_code=503, error_code="service_unavailable", detail="unavailable", log_detail="x"
        )
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_UNAVAILABLE, error=error)
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error == error

    async def test_raising_is_normalized_to_unavailable(self) -> None:
        """Fail closed: fingerprint() is contractually never supposed to
        raise, but this board cannot trust a duck-typed plugin to honor
        that -- a raise is caught and normalized to a generic
        FINGERPRINT_UNAVAILABLE outcome, never propagated as an unhandled
        500."""
        judge = FakeProposalJudge(fingerprint_raises=RuntimeError("boom"))
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.status_code == 500
        assert "boom" not in result.error.detail

    async def test_cancelled_error_propagates_uncaught(self) -> None:
        judge = FakeProposalJudge(fingerprint_raises=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            await _safe_fingerprint(judge, _ctx())

    async def test_digest_status_with_non_string_digest_is_a_contract_violation(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_DIGEST, digest=None)
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE

    async def test_fingerprint_returning_none_is_a_contract_violation(self) -> None:
        judge = FakeProposalJudge(fingerprint_result=None)
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"

    async def test_unavailable_status_with_no_error_is_a_contract_violation(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_UNAVAILABLE, error=None)
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"

    @pytest.mark.parametrize(
        "bad_error",
        [
            "not a ProposalTargetError",
            123,
            {"status_code": 500, "error_code": "err", "detail": "msg"},
            ProposalTargetError(status_code="500", error_code="err", detail="msg", log_detail=None),  # type: ignore[arg-type]
            ProposalTargetError(status_code=True, error_code="err", detail="msg", log_detail=None),  # type: ignore[arg-type]
            ProposalTargetError(status_code=500, error_code="", detail="msg", log_detail=None),
            ProposalTargetError(status_code=500, error_code="err", detail="", log_detail=None),
            ProposalTargetError(status_code=500, error_code="err", detail="msg", log_detail=123),  # type: ignore[arg-type]
            ProposalTargetError(status_code=0, error_code="err", detail="msg", log_detail=None),
            ProposalTargetError(status_code=200, error_code="err", detail="msg", log_detail=None),
            ProposalTargetError(status_code=400, error_code="err", detail="msg", log_detail=None),
            ProposalTargetError(status_code=600, error_code="err", detail="msg", log_detail=None),
            ProposalTargetError(
                status_code=500, error_code="x" * 65, detail="msg", log_detail=None
            ),
        ],
    )
    async def test_unavailable_status_with_malformed_error_synthesizes_generic_error(
        self, bad_error: Any
    ) -> None:
        """A plugin returning FINGERPRINT_UNAVAILABLE with an invalid error shape
        must have a well-formed generic ProposalTargetError synthesized by the wrapper,
        so downstream call sites that access error.status_code/error_code/detail never crash.
        """
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status=FINGERPRINT_UNAVAILABLE, error=bad_error)
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"

    async def test_target_error_detail_scrubs_credentials_and_query_strings(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_UNAVAILABLE,
                error=ProposalTargetError(
                    status_code=503,
                    error_code="service_unavailable",
                    detail=(
                        "upstream error: api_key=secret12345 in call to "
                        "https://api.linear.app/graphql?token=abc456"
                    ),
                    log_detail="raw log detail with api_key=secret12345",
                ),
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.detail == "upstream error: in call to https://api.linear.app/graphql"
        assert "secret12345" not in result.error.detail
        assert "abc456" not in result.error.detail
        assert "token=" not in result.error.detail
        # log_detail is untouched
        assert result.error.log_detail == "raw log detail with api_key=secret12345"

    async def test_target_error_detail_only_credential_falls_back_to_generic_detail(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_UNAVAILABLE,
                error=ProposalTargetError(
                    status_code=503,
                    error_code="service_unavailable",
                    detail="token=secret12345",
                    log_detail="raw log",
                ),
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.detail == "unable to verify target status"
        assert result.error.log_detail == "raw log"

    async def test_target_error_detail_overlong_is_truncated(self) -> None:
        overlong_detail = "x" * 600
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(
                status=FINGERPRINT_UNAVAILABLE,
                error=ProposalTargetError(
                    status_code=503,
                    error_code="service_unavailable",
                    detail=overlong_detail,
                    log_detail="raw error detail",
                ),
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert len(result.error.detail) == 500
        assert result.error.detail.endswith("... [truncated]")
        assert result.error.detail.startswith("x" * 100)
        assert result.error.status_code == 503
        assert result.error.error_code == "service_unavailable"
        assert result.error.log_detail == "raw error detail"

    async def test_unrecognized_status_is_a_contract_violation(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=ProposalFingerprint(status="not_a_real_status")
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert result.error is not None
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"


class TestSafeApplySeam:
    """``service._safe_apply`` -- the defensive wrapper around
    ``judge.apply()``."""

    async def test_applied_true_with_dict_result_passes_through(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=True, result={"id": "abc"}, caller_error=None, log_detail=None
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is True
        assert result.result == {"id": "abc"}

    async def test_applied_true_with_none_result_passes_through(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is True
        assert result.result is None

    async def test_applied_false_with_caller_error_passes_through(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False, result=None, caller_error="target unavailable", log_detail="raw"
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.caller_error == "target unavailable"
        assert result.log_detail == "raw"

    async def test_raising_is_normalized_to_apply_failed_with_generic_message(self) -> None:
        """Fail closed: a plugin raising from apply() must resolve to
        ``applied=False`` with a generic, caller-safe message -- never a
        500. The raw exception text is captured in ``log_detail`` only."""
        judge = FakeProposalJudge(apply_raises=RuntimeError("credentials: sk-abc123"))
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.result is None
        assert result.caller_error == "unable to apply this proposal"
        assert "sk-abc123" not in result.caller_error
        assert "sk-abc123" in (result.log_detail or "")

    async def test_cancelled_error_propagates_uncaught(self) -> None:
        judge = FakeProposalJudge(apply_raises=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            await _safe_apply(judge, _ctx())

    async def test_applied_true_with_non_dict_result_is_a_contract_violation(self) -> None:
        """A plugin returning ``applied=True`` with a non-dict, non-None
        ``result`` cannot be trusted to write into the JSONB
        ``apply_result`` column -- treated as apply_failed instead of
        persisting a malformed value."""
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=True,
                result="not-a-dict",
                caller_error=None,
                log_detail=None,  # type: ignore[arg-type]
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.caller_error == "unable to apply this proposal"

    async def test_applied_false_with_no_caller_error_is_a_contract_violation(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False, result=None, caller_error=None, log_detail="something failed"
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.caller_error == "unable to apply this proposal"

    async def test_apply_returning_none_is_a_contract_violation(self) -> None:
        """A plugin returning None from apply() must resolve to applied=False with
        a generic caller error, never raising AttributeError outside the wrapper.
        """
        judge = FakeProposalJudge(apply_result=None)
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.result is None
        assert result.caller_error == "unable to apply this proposal"
        assert "malformed result: None" in (result.log_detail or "")

    async def test_apply_returning_non_outcome_is_a_contract_violation(self) -> None:
        judge = FakeProposalJudge(apply_result={"applied": True})
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.result is None
        assert result.caller_error == "unable to apply this proposal"

    @pytest.mark.parametrize("bad_applied", ["true", "false", 1, 0, None, []])
    async def test_applied_not_bool_is_a_contract_violation(self, bad_applied: Any) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=bad_applied,  # type: ignore[arg-type]
                result=None,
                caller_error=None,
                log_detail=None,
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.result is None
        assert result.caller_error == "unable to apply this proposal"
        assert "non-bool applied" in (result.log_detail or "")

    async def test_apply_returning_non_json_serializable_result_treated_as_apply_failed(
        self,
    ) -> None:
        """A plugin returning applied=True with a dict containing non-JSON-serializable
        values (e.g. set, datetime) must be caught by _safe_apply and normalized to
        applied=False, rather than failing at commit time and stranding the row.
        """
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=True,
                result={"invalid_set": {1, 2, 3}},
                caller_error=None,
                log_detail=None,
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.result is None
        assert result.caller_error == "unable to apply this proposal"
        assert "non-JSON-serializable" in (result.log_detail or "")

    async def test_apply_caller_error_overlong_is_truncated(self) -> None:
        overlong_error = "e" * 600
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error=overlong_error,
                log_detail="raw detail",
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.result is None
        assert len(result.caller_error or "") == 500
        assert (result.caller_error or "").endswith("... [truncated]")
        assert (result.caller_error or "").startswith("e" * 100)
        assert result.log_detail == "raw detail"

    async def test_apply_caller_error_scrubs_credentials_and_query_strings(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error=(
                    "upstream error: token=secret12345 in call to "
                    "https://api.linear.app/graphql?api_key=abc456"
                ),
                log_detail="raw log detail with token=secret12345",
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.caller_error == "upstream error: in call to https://api.linear.app/graphql"
        assert "secret12345" not in (result.caller_error or "")
        assert "abc456" not in (result.caller_error or "")
        assert "api_key=" not in (result.caller_error or "")
        # log_detail is untouched
        assert result.log_detail == "raw log detail with token=secret12345"

    async def test_apply_caller_error_only_credential_falls_back_to_generic_error(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="token=secret12345",
                log_detail="raw log",
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.caller_error == "unable to apply this proposal"
        assert result.log_detail == "raw log"

    async def test_apply_caller_error_preserves_legitimate_prose_with_equals(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error=(
                    "cannot transition ticket when status=closed and priority=high (count = 0)"
                ),
                log_detail=None,
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert (
            result.caller_error
            == "cannot transition ticket when status=closed and priority=high (count = 0)"
        )

    async def test_apply_illegal_applied_true_with_indeterminate_true_is_normalized(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=True,
                result={"issue_id": "LIN-1"},
                caller_error=None,
                log_detail=None,
                indeterminate=True,
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.indeterminate is True
        assert result.caller_error == "unable to apply this proposal"

    async def test_apply_indeterminate_flag_preserved_on_failure(self) -> None:
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="timeout after 3 attempts",
                log_detail="raw timeout",
                indeterminate=True,
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.indeterminate is True
        assert result.caller_error == "timeout after 3 attempts"

    async def test_apply_http_judge_indeterminate_200_response_propagates_indeterminate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TECH-7170: HttpApplyProposalJudge receiving approvals HTTP 200 with
        applied=false, indeterminate=true yields indeterminate=True through _safe_apply."""
        import httpx

        from proposal_apply_http_client import (
            PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR,
            PROPOSAL_APPLY_TOKEN_ENV_VAR,
            PROPOSAL_APPLY_URL_ENV_VAR,
            HttpApplyProposalJudge,
        )
        from tests.test_proposal_apply_http_client import _patch_transport

        monkeypatch.setenv(PROPOSAL_APPLY_URL_ENV_VAR, "https://approvals.example.ts.net/actions")
        monkeypatch.setenv(PROPOSAL_APPLY_TOKEN_ENV_VAR, "mock-token")
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
        http_judge = HttpApplyProposalJudge(FakeProposalJudge())
        result = await _safe_apply(http_judge, _ctx())
        assert result.applied is False
        assert result.indeterminate is True
        assert result.caller_error is not None
        assert "awaiting manual reconciliation" in result.caller_error

    async def test_apply_indeterminate_flag_preserved_when_caller_error_missing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """BLOCKING #1: missing/empty caller_error must still propagate indeterminate=True."""
        ctx = _ctx()
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error=None,
                log_detail="retry budget exhausted",
                indeterminate=True,
            )
        )
        with caplog.at_level(logging.WARNING, logger="service"):
            result = await _safe_apply(judge, ctx)
        assert result.applied is False
        assert result.indeterminate is True
        assert result.caller_error == "unable to apply this proposal"
        assert f"applied=False with no caller_error for hold {ctx.hold_id}" in caplog.text

    async def test_apply_empty_caller_error_logs_warning_and_uses_generic_message(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Item 7: applied=False with empty caller_error logs warning and assigns
        generic message.
        """
        ctx = _ctx()
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="   ",
                log_detail=None,
                indeterminate=False,
            )
        )
        with caplog.at_level(logging.WARNING, logger="service"):
            result = await _safe_apply(judge, ctx)
        assert result.applied is False
        assert result.indeterminate is False
        assert result.caller_error == "unable to apply this proposal"
        assert f"applied=False with no caller_error for hold {ctx.hold_id}" in caplog.text

    async def test_apply_indeterminate_flag_preserved_when_caller_error_truncated(self) -> None:
        """BLOCKING #1: truncated caller_error must still propagate indeterminate=True."""
        judge = FakeProposalJudge(
            apply_result=ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="A" * 600,
                log_detail="log",
                indeterminate=True,
            )
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.indeterminate is True
        assert result.caller_error is not None
        assert len(result.caller_error) <= 500

    async def test_apply_exception_catch_all_defaults_to_indeterminate_true(self) -> None:
        """BLOCKING #1: unhandled exception escaping apply() defaults to indeterminate=True."""
        judge = FakeProposalJudge(
            apply_raises=RuntimeError("unexpected crash inside apply"),
        )
        result = await _safe_apply(judge, _ctx())
        assert result.applied is False
        assert result.indeterminate is True
        assert result.caller_error == "unable to apply this proposal"


class TestScrubProposalErrorString:
    def test_preserves_clean_prose(self) -> None:
        text = "ticket TECH-1234 was not found in team TECH"
        assert _scrub_proposal_error_string(text) == text

    def test_preserves_prose_with_equals(self) -> None:
        text = "filter status=closed returned count = 0 results (target_id=TECH-1)"
        assert _scrub_proposal_error_string(text) == text

    def test_preserves_prose_with_question_mark(self) -> None:
        text = "Did the target ticket exist? Please verify."
        assert _scrub_proposal_error_string(text) == text

    def test_strips_url_query_strings(self) -> None:
        text = (
            "failed: https://api.linear.app/graphql?token=secret123&foo=bar and /v1/issue?auth=xyz"
        )
        expected = "failed: https://api.linear.app/graphql and /v1/issue"
        assert _scrub_proposal_error_string(text) == expected

    def test_strips_credential_key_value_tokens(self) -> None:
        text = "auth error: api_key=secret_123, token='abc', password=\"pwd\", client_secret=cs"
        expected = "auth error:"
        assert _scrub_proposal_error_string(text) == expected


@pytest.mark.usefixtures("_migrated_schema")
class TestJudgeApplyIntegrationSeam:
    """Integration-level contract tests requiring real Postgres to prove
    that contract-violating plugin return values fail closed in the database
    (e.g. holds are not stranded at status='applying', malformed judge verdicts
    never auto-approve).
    """

    @pytest_asyncio.fixture(autouse=True)
    async def _clean_tables(self, engine: AsyncEngine) -> AsyncIterator[None]:
        async with engine.begin() as conn:
            await conn.execute(
                text("TRUNCATE TABLE proposal_holds, audit_log RESTART IDENTITY CASCADE")
            )
        yield

    async def test_judge_returning_truthy_string_approved_does_not_auto_approve(
        self, session: AsyncSession
    ) -> None:
        """Fix 2: approved="false" (a truthy non-bool string) must NOT auto-approve
        or call apply(); it must resolve to status='pending' with a judge error note.
        """
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved="false", decision_note=None),  # type: ignore[arg-type]
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: ProposalVerdict.approved must be a bool, got str"
        )
        assert judge.apply_calls == []

    async def test_judge_returning_truthy_int_approved_does_not_auto_approve(
        self, session: AsyncSession
    ) -> None:
        """Fix 2: approved=1 (truthy int) must NOT auto-approve or call apply();
        it must resolve to status='pending' with a judge error note.
        """
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=1, decision_note=None),  # type: ignore[arg-type]
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: ProposalVerdict.approved must be a bool, got int"
        )
        assert judge.apply_calls == []

    async def test_judge_returning_non_str_decision_note_is_treated_as_judge_error(
        self, session: AsyncSession
    ) -> None:
        """Fix 2: non-str and non-None decision_note is a contract violation;
        must resolve to status='pending' with a judge error note.
        """
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=False, decision_note=123),  # type: ignore[arg-type]
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: ProposalVerdict.decision_note must be None or str, got int"
        )
        assert judge.apply_calls == []

    async def test_judge_returning_none_is_treated_as_judge_error(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=None,
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: verdict missing approved/decision_note, got NoneType"
        )
        assert judge.apply_calls == []

    async def test_apply_returning_none_does_not_strand_row_at_applying(
        self, session: AsyncSession
    ) -> None:
        """Fix 3: apply() returning None must resolve to apply_failed and not strand
        the row at status='applying'.
        """
        judge = FakeProposalJudge(
            judge_result=ProposalVerdict(approved=True, decision_note="auto-approve"),
            apply_result=None,
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "apply_failed"
        assert result["apply_error"] == "unable to apply this proposal"

        # Explicitly check the hold's final DB status after the call
        hold_id = uuid.UUID(result["proposal_id"])
        hold = await session.get(ProposalHold, hold_id)
        assert hold is not None
        assert hold.status == "apply_failed"
        assert hold.status != "applying"
        assert hold.apply_error == "unable to apply this proposal"


# ---------------------------------------------------------------------------
# Foreign structural stand-ins regression tests (cross-repo duck-typing)
# ---------------------------------------------------------------------------
#
# The _Foreign*/_VerdictOnly* classes below are hand-maintained approximations
# of the real structural types returned by external plugin packages (e.g.
# agent-comms-approvals' rh_comms_plugins.proposal_judge) -- they are NOT
# imported from that package, so they can silently drift from its actual
# shape over time. See TECH-6271, which tracks this specific gap.


class _ForeignClassification(NamedTuple):
    priority: Any


class _ForeignTargetError(NamedTuple):
    status_code: Any
    error_code: Any
    detail: Any
    log_detail: Any = None


class _ForeignFingerprint(NamedTuple):
    status: Any
    digest: Any = None
    error: Any = None


class _ForeignVerdict(NamedTuple):
    approved: Any
    decision_note: Any


class _VerdictOnlyApproved(NamedTuple):
    approved: Any


class _VerdictOnlyDecisionNote(NamedTuple):
    decision_note: Any


class TestForeignStructuralStandinsClassify:
    """Site 1: _classify_proposal accepts foreign ProposalClassification stand-ins
    and validates priority by value, rejecting invalid values and non-objects."""

    def test_accepts_foreign_classification_for_all_hold_levels(self) -> None:
        for level in PROPOSAL_HOLD_LEVELS:
            judge = FakeProposalJudge(classify_result=_ForeignClassification(priority=level))
            assert _classify_proposal(judge, "linear_progress_update", {}) == level

    @pytest.mark.parametrize("bad_priority", ["urgent", "", "HIGH", None, "invalid", 123])
    def test_rejects_foreign_classification_with_invalid_priority(self, bad_priority: Any) -> None:
        judge = FakeProposalJudge(classify_result=_ForeignClassification(priority=bad_priority))
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    @pytest.mark.parametrize("bad_result", [None, {"priority": "low"}, "low", 42])
    def test_rejects_none_bare_dict_and_plain_primitives(self, bad_result: Any) -> None:
        judge = FakeProposalJudge(classify_result=bad_result)
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_rejects_pathological_raising_priority_property(self) -> None:
        class _ExplodingPriority:
            @property
            def priority(self) -> Any:
                raise RuntimeError("property explosion")

        judge = FakeProposalJudge(classify_result=_ExplodingPriority())
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_rejects_pathological_value_error_raising_priority_property(self) -> None:
        class _ValueErrorPriority:
            @property
            def priority(self) -> Any:
                raise ValueError("property ValueError")

        judge = FakeProposalJudge(classify_result=_ValueErrorPriority())
        with pytest.raises(ValueError, match="invalid priority") as exc_info:
            _classify_proposal(judge, "linear_progress_update", {})
        assert "unsupported proposal kind" not in str(exc_info.value)

    def test_rejects_priority_whose_membership_test_raises(self) -> None:
        """A priority value that passes the isinstance(str) check but whose
        __eq__/__hash__ raises during the `priority not in
        PROPOSAL_HOLD_LEVELS` membership test must be caught and mapped to
        the same "invalid priority" ValueError -> 422 path, not escape as an
        uncaught exception (BLOCKING: the membership test must live inside
        the same try/except as the getattr call). Must subclass `str` so the
        isinstance guard doesn't short-circuit before the membership test
        ever runs."""

        class _ExplodingEqPriority(str):
            def __eq__(self, other: object) -> bool:
                raise RuntimeError("__eq__ explosion")

            def __hash__(self) -> int:
                raise RuntimeError("__hash__ explosion")

        judge = FakeProposalJudge(
            classify_result=_ForeignClassification(priority=_ExplodingEqPriority("junk"))
        )
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_rejects_non_str_priority_spoofing_equality_with_valid_level(self) -> None:
        """A non-str priority whose __eq__ returns True when compared to a
        valid PROPOSAL_HOLD_LEVELS string must be rejected by the
        isinstance(priority, str) check -- it must never be accepted as if it
        were that string, since cast() alone has no runtime effect."""

        class _SpoofedHighPriority:
            def __eq__(self, other: object) -> bool:
                return other == "high"

            def __hash__(self) -> int:
                return hash("high")

        judge = FakeProposalJudge(
            classify_result=_ForeignClassification(priority=_SpoofedHighPriority())
        )
        with pytest.raises(ValueError, match="invalid priority"):
            _classify_proposal(judge, "linear_progress_update", {})


class TestForeignStructuralStandinsTargetError:
    """Site 2: _is_well_formed_target_error accepts foreign ProposalTargetError stand-ins
    and rejects malformed shapes, non-objects, and invalid field values."""

    def test_accepts_foreign_target_error_with_log_detail(self) -> None:
        err = _ForeignTargetError(
            status_code=503,
            error_code="service_unavailable",
            detail="service is down",
            log_detail="upstream timeout",
        )
        validated = _is_well_formed_target_error(err)
        assert validated is not None
        assert validated.status_code == 503
        assert validated.error_code == "service_unavailable"
        assert validated.detail == "service is down"
        assert validated.log_detail == "upstream timeout"

    def test_accepts_foreign_target_error_without_log_detail(self) -> None:
        err = _ForeignTargetError(
            status_code=422,
            error_code="invalid_action",
            detail="action payload unprocessable",
        )
        validated = _is_well_formed_target_error(err)
        assert validated is not None
        assert validated.status_code == 422
        assert validated.error_code == "invalid_action"
        assert validated.detail == "action payload unprocessable"
        assert validated.log_detail is None

    def test_accepts_foreign_target_error_403(self) -> None:
        err = _ForeignTargetError(
            status_code=403,
            error_code="forbidden",
            detail="bot principal is not authorized to propose",
            log_detail="arcana admission denied",
        )
        validated = _is_well_formed_target_error(err)
        assert validated is not None
        assert validated.status_code == 403
        assert validated.error_code == "forbidden"
        assert validated.detail == "bot principal is not authorized to propose"
        assert validated.log_detail == "arcana admission denied"

    def test_accepts_foreign_target_error_404(self) -> None:
        err = _ForeignTargetError(
            status_code=404,
            error_code="not_found",
            detail="Arcana resource not found",
            log_detail="source not found",
        )
        validated = _is_well_formed_target_error(err)
        assert validated is not None
        assert validated.status_code == 404
        assert validated.error_code == "not_found"
        assert validated.detail == "Arcana resource not found"
        assert validated.log_detail == "source not found"

    @pytest.mark.parametrize(
        "bad_err",
        [
            None,
            "status_code=500",
            {"status_code": 500, "error_code": "err", "detail": "msg"},
            _ForeignTargetError(status_code=200, error_code="ok", detail="msg"),
            _ForeignTargetError(status_code=True, error_code="err", detail="msg"),
            _ForeignTargetError(status_code="500", error_code="err", detail="msg"),
            _ForeignTargetError(status_code=500, error_code="", detail="msg"),
            _ForeignTargetError(status_code=500, error_code="x" * 65, detail="msg"),
            _ForeignTargetError(status_code=500, error_code="err", detail=""),
            _ForeignTargetError(status_code=500, error_code="err", detail="msg", log_detail=123),
        ],
    )
    def test_rejects_invalid_foreign_target_errors_and_non_objects(self, bad_err: Any) -> None:
        assert _is_well_formed_target_error(bad_err) is None


class TestForeignStructuralStandinsFingerprint:
    """Site 3: _safe_fingerprint accepts foreign ProposalFingerprint and ProposalTargetError
    stand-ins, reconstructing the board's own types on return, and fails closed on invalid shapes.
    """

    async def test_accepts_foreign_fingerprint_digest(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(status=FINGERPRINT_DIGEST, digest="sha256:abc")
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_DIGEST
        assert result.digest == "sha256:abc"

    async def test_accepts_foreign_fingerprint_no_target(self) -> None:
        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(status=FINGERPRINT_NO_TARGET)
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_NO_TARGET

    async def test_accepts_foreign_fingerprint_unavailable_with_foreign_target_error(self) -> None:
        foreign_err = _ForeignTargetError(
            status_code=503,
            error_code="service_unavailable",
            detail="linear API unavailable",
            log_detail="HTTP 503 from linear backend",
        )
        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(
                status=FINGERPRINT_UNAVAILABLE, error=foreign_err
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert type(result.error) is ProposalTargetError
        assert result.error.status_code == 503
        assert result.error.error_code == "service_unavailable"
        assert result.error.detail == "linear API unavailable"
        assert result.error.log_detail == "HTTP 503 from linear backend"

    async def test_foreign_target_error_raising_property_fails_closed(self) -> None:
        """A foreign target error whose property raises a non-AttributeError exception
        fails closed to FINGERPRINT_UNAVAILABLE (500) via _safe_fingerprint's outer catch."""

        class _ExplodingTargetError:
            @property
            def status_code(self) -> Any:
                raise RuntimeError("exploding status_code")

            error_code = "service_unavailable"
            detail = "exploded"
            log_detail = None

        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(
                status=FINGERPRINT_UNAVAILABLE, error=_ExplodingTargetError()
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert type(result.error) is ProposalTargetError
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"

    async def test_foreign_target_error_detail_overlong_is_truncated(self) -> None:
        overlong_detail = "x" * 600
        foreign_err = _ForeignTargetError(
            status_code=503,
            error_code="service_unavailable",
            detail=overlong_detail,
            log_detail="raw error detail",
        )
        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(
                status=FINGERPRINT_UNAVAILABLE, error=foreign_err
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert type(result) is ProposalFingerprint
        assert type(result.error) is ProposalTargetError
        assert result.error is not None
        assert len(result.error.detail) == 500
        assert result.error.detail.endswith("... [truncated]")
        assert result.error.detail.startswith("x" * 100)
        assert result.error.status_code == 503
        assert result.error.error_code == "service_unavailable"
        assert result.error.log_detail == "raw error detail"

    async def test_foreign_target_error_toctou_resilient(self) -> None:
        """A pathological error whose property returns valid on first read
        and invalid on second read is safely handled by snapshotting."""

        class _FlakyTargetError:
            def __init__(self) -> None:
                self._reads = 0

            @property
            def status_code(self) -> int:
                self._reads += 1
                return 503 if self._reads == 1 else 200  # 200 is disallowed

            error_code = "service_unavailable"
            detail = "service down"
            log_detail = None

        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(
                status=FINGERPRINT_UNAVAILABLE, error=_FlakyTargetError()
            )
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert type(result.error) is ProposalTargetError
        assert result.error.status_code == 503

    @pytest.mark.parametrize(
        "bad_result",
        [
            None,
            "no_target",
            {"status": FINGERPRINT_NO_TARGET},
            _ForeignFingerprint(status=FINGERPRINT_DIGEST, digest=123),
            _ForeignFingerprint(status=FINGERPRINT_DIGEST, digest=None),
            _ForeignFingerprint(status="unknown_status"),
            _ForeignFingerprint(
                status=FINGERPRINT_UNAVAILABLE,
                error=_ForeignTargetError(status_code=200, error_code="ok", detail="msg"),
            ),
            _ForeignFingerprint(status=FINGERPRINT_UNAVAILABLE, error=None),
        ],
    )
    async def test_rejects_invalid_foreign_fingerprint_shapes(self, bad_result: Any) -> None:
        judge = FakeProposalJudge(fingerprint_result=bad_result)
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert type(result.error) is ProposalTargetError
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"

    async def test_rejects_non_str_status_spoofing_equality_with_valid_status(self) -> None:
        """A non-str status whose __eq__ returns True when compared to a
        valid FINGERPRINT_* constant must be rejected by the
        isinstance(status, str) check -- it must fall through to the
        generic FINGERPRINT_UNAVAILABLE fail-closed path, not be accepted as
        FINGERPRINT_NO_TARGET."""

        class _SpoofedNoTargetStatus:
            def __eq__(self, other: object) -> bool:
                return other == FINGERPRINT_NO_TARGET

            def __hash__(self) -> int:
                return hash(FINGERPRINT_NO_TARGET)

        judge = FakeProposalJudge(
            fingerprint_result=_ForeignFingerprint(status=_SpoofedNoTargetStatus())
        )
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_UNAVAILABLE
        assert type(result.error) is ProposalTargetError
        assert result.error.status_code == 500
        assert result.error.error_code == "server_configuration_error"
        assert result.error.detail == "unable to verify target status"

    async def test_foreign_fingerprint_digest_with_exploding_error_property_succeeds(self) -> None:
        """A foreign fingerprint with status=FINGERPRINT_DIGEST and a valid digest
        whose .error property raises must succeed, because .error is only read when
        status == FINGERPRINT_UNAVAILABLE."""

        class _ExplodingErrorFingerprint:
            status = FINGERPRINT_DIGEST
            digest = "sha256:123"

            @property
            def error(self) -> Any:
                raise RuntimeError("exploding error property")

        judge = FakeProposalJudge(fingerprint_result=_ExplodingErrorFingerprint())
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_DIGEST
        assert result.digest == "sha256:123"

    async def test_foreign_fingerprint_no_target_exploding_error_succeeds(self) -> None:
        """A foreign fingerprint with status=FINGERPRINT_NO_TARGET whose .error
        property raises must succeed, because .error is only read when
        status == FINGERPRINT_UNAVAILABLE."""

        class _ExplodingErrorNoTargetFingerprint:
            status = FINGERPRINT_NO_TARGET

            @property
            def error(self) -> Any:
                raise RuntimeError("exploding error property")

        judge = FakeProposalJudge(fingerprint_result=_ExplodingErrorNoTargetFingerprint())
        result = await _safe_fingerprint(judge, _ctx())
        assert type(result) is ProposalFingerprint
        assert result.status == FINGERPRINT_NO_TARGET


@pytest.mark.usefixtures("_migrated_schema")
class TestForeignStructuralStandinsVerdict:
    """Site 4: create_proposal accepts foreign ProposalVerdict stand-ins,
    validates fields by value, and rejects non-bool approved or malformed verdicts."""

    @pytest_asyncio.fixture(autouse=True)
    async def _clean_tables(self, engine: AsyncEngine) -> AsyncIterator[None]:
        async with engine.begin() as conn:
            await conn.execute(
                text("TRUNCATE TABLE proposal_holds, audit_log RESTART IDENTITY CASCADE")
            )
        yield

    async def test_accepts_foreign_verdict_approved(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(
            judge_result=_ForeignVerdict(
                approved=True, decision_note="auto-approved by foreign judge"
            ),
            apply_result=ProposalApplyOutcome(
                applied=True, result=None, caller_error=None, log_detail=None
            ),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "applied"
        assert result["decision_note"] == "auto-approved by foreign judge"

    async def test_accepts_foreign_verdict_pending_with_none_note(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=_ForeignVerdict(approved=False, decision_note=None),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert result.get("decision_note") is None
        assert judge.apply_calls == []

    async def test_pending_verdict_note_is_dropped(self, session: AsyncSession) -> None:
        # A legitimately pending judge verdict has decision_note=None by convention
        # (see service.py ~line 7015); unlike judge error notes, any plugin-supplied
        # note on a pending verdict is intentionally dropped and not persisted.
        judge = FakeProposalJudge(
            judge_result=_ForeignVerdict(
                approved=False, decision_note="escalated to human reviewer"
            ),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert result.get("decision_note") is None
        assert judge.apply_calls == []

    @pytest.mark.parametrize(
        ("bad_approved", "expected_type"),
        [
            ("true", "str"),
            ("false", "str"),
            (1, "int"),
            (0, "int"),
            ([], "list"),
        ],
    )
    async def test_rejects_foreign_verdict_with_non_bool_approved(
        self, session: AsyncSession, bad_approved: Any, expected_type: str
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=_ForeignVerdict(approved=bad_approved, decision_note=None),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == f"judge error: ProposalVerdict.approved must be a bool, got {expected_type}"
        )

    async def test_rejects_foreign_verdict_with_non_str_decision_note(
        self, session: AsyncSession
    ) -> None:
        judge = FakeProposalJudge(
            judge_result=_ForeignVerdict(approved=False, decision_note=12345),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: ProposalVerdict.decision_note must be None or str, got int"
        )

    @pytest.mark.parametrize(
        ("bad_verdict", "expected_type"),
        [
            (None, "NoneType"),
            ({"approved": True, "decision_note": "ok"}, "dict"),
            ("approved", "str"),
            (123, "int"),
        ],
    )
    async def test_rejects_none_bare_dict_and_plain_primitives_for_verdict(
        self, session: AsyncSession, bad_verdict: Any, expected_type: str
    ) -> None:
        judge = FakeProposalJudge(judge_result=bad_verdict)
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == f"judge error: verdict missing approved/decision_note, got {expected_type}"
        )

    async def test_rejects_verdict_missing_decision_note(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(judge_result=_VerdictOnlyApproved(approved=True))
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: verdict missing approved/decision_note, got _VerdictOnlyApproved"
        )
        assert judge.apply_calls == []

    async def test_rejects_verdict_missing_approved(self, session: AsyncSession) -> None:
        judge = FakeProposalJudge(judge_result=_VerdictOnlyDecisionNote(decision_note="looks good"))
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert (
            result["decision_note"]
            == "judge error: verdict missing approved/decision_note, got _VerdictOnlyDecisionNote"
        )
        assert judge.apply_calls == []

    async def test_foreign_verdict_raising_approved_property_fails_closed(
        self, session: AsyncSession
    ) -> None:
        """A foreign verdict whose `approved` property raises a non-AttributeError
        exception fails closed to the same pending/judge-error path as any other
        judge.judge() exception (see the outer `except Exception` in
        service.create_proposal)."""

        class _ExplodingApproved:
            @property
            def approved(self) -> Any:
                raise RuntimeError("exploding approved")

            decision_note = None

        judge = FakeProposalJudge(judge_result=_ExplodingApproved())
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "pending"
        assert result["decision_note"] == "judge error: RuntimeError"
        assert judge.apply_calls == []

    async def test_foreign_verdict_with_overlong_decision_note_is_truncated(
        self, session: AsyncSession
    ) -> None:
        """Truncation applies identically to a foreign verdict's decision_note
        as it does to the native ProposalVerdict path (see
        test_proposal_service.test_overlong_decision_note_is_truncated)."""
        overlong_note = "n" * 2500
        judge = FakeProposalJudge(
            judge_result=_ForeignVerdict(approved=True, decision_note=overlong_note),
            apply_result=ProposalApplyOutcome(
                applied=True, result={"ok": True}, caller_error=None, log_detail=None
            ),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert result["status"] == "applied"
        assert len(result["decision_note"]) == MAX_DECISION_REASON_LENGTH
        assert result["decision_note"].endswith("... [truncated]")
        assert result["decision_note"].startswith("n" * 100)

    async def test_foreign_verdict_approved_and_decision_note_read_exactly_once(
        self, session: AsyncSession
    ) -> None:
        """TOCTOU guard: `approved`/`decision_note` must each be read from the
        foreign verdict object exactly once -- the same value used for
        validation must be the value that ends up persisted/returned, not a
        second, possibly-different read."""

        class _FlakyVerdict:
            def __init__(self) -> None:
                self.approved_reads = 0
                self.decision_note_reads = 0

            @property
            def approved(self) -> Any:
                self.approved_reads += 1
                return True

            @property
            def decision_note(self) -> Any:
                self.decision_note_reads += 1
                return "first read" if self.decision_note_reads == 1 else "second read"

        verdict = _FlakyVerdict()
        judge = FakeProposalJudge(
            judge_result=verdict,
            apply_result=ProposalApplyOutcome(
                applied=True, result={"ok": True}, caller_error=None, log_detail=None
            ),
        )
        result = await create_proposal(
            session,
            kind="linear_progress_update",
            proposed_by_bot_id="bot-1",
            owner_sub="owner-a@example.com",
            action={"target_id": "TECH-1", "action_type": "close_ticket"},
            rationale="test",
            confidence="medium",
            importance="medium",
            impact="medium",
            judge=judge,
            target_fingerprint="deadbeef",
        )
        assert verdict.approved_reads == 1
        assert verdict.decision_note_reads == 1
        assert result["status"] == "applied"
        assert result["decision_note"] == "first read"


# ---------------------------------------------------------------------------
# TECH-7711: structured "malformed action for a supported kind" signal
# ---------------------------------------------------------------------------
#
# A judge's ``classify()`` reports a malformed ``action`` on an otherwise
# supported ``kind`` by raising a ``ValueError`` subclass carrying a
# duck-typed ``proposal_action_errors`` tuple of ``(path, code)`` pairs --
# never by its class name, never by its message text. The tests below cover
# ``service._sanitize_plugin_action_errors`` (the adversarial re-validation
# of a plugin-supplied signal), ``service._read_supported_proposal_kinds``
# (the optional capability), and ``service._classify_value_error_to_proposal_
# error`` / ``_classify_proposal`` (the rebuilt, board-owned 422 error).

# Distinctive sentinel carried ONLY on the plugin exception's own message and
# ``__cause__`` (which the board deliberately preserves for logging) -- it
# must never reach any caller-facing string below.
_PLUGIN_SENTINEL = "SECRET-PLUGIN-INTERNALS-7711"
_PLUGIN_SENTINEL_MESSAGE = (
    f"pydantic internals: content={_PLUGIN_SENTINEL} api_key=sk-{_PLUGIN_SENTINEL}"
)


class _ForeignInvalidActionError(ValueError):
    """Duck-typed stand-in for agent-comms-approvals'
    ``rh_comms_plugins.proposal_judge.InvalidProposalAction`` (TECH-7711) --
    hand-maintained in the same spirit as the ``_Foreign*`` stand-ins above:
    NOT imported from that package, so it can drift, which is exactly what
    the board's own re-validation defends against (every test below feeds
    it adversarial shapes a real plugin would never emit).

    The attribute name must match ``plugins.PROPOSAL_ACTION_ERRORS_ATTR``
    literally -- pinned by the test directly below.
    """

    def __init__(self, errors: Any, message: str = _PLUGIN_SENTINEL_MESSAGE) -> None:
        self.proposal_action_errors = errors
        super().__init__(message)


class TestProposalActionSignalContractConstants:
    """Pin the duck-typed contract constants the plugins module exports."""

    def test_attribute_names_are_the_duck_typed_literals(self) -> None:
        assert PROPOSAL_ACTION_ERRORS_ATTR == "proposal_action_errors"
        assert PROPOSAL_SUPPORTED_KINDS_ATTR == "supported_proposal_kinds"

    def test_error_codes_is_the_closed_ten_code_set(self) -> None:
        expected = {
            "missing",
            "extra_field",
            "invalid_type",
            "too_short",
            "too_long",
            "out_of_range",
            "invalid_format",
            "invalid_value",
            "not_canonical",
            "digest_mismatch",
        }
        assert frozenset(expected) == PROPOSAL_ACTION_ERROR_CODES

    def test_foreign_invalid_action_error_is_a_value_error_carrying_the_attr(self) -> None:
        exc = _ForeignInvalidActionError([("content", "missing")])
        assert isinstance(exc, ValueError)
        assert getattr(exc, PROPOSAL_ACTION_ERRORS_ATTR) == [("content", "missing")]


class TestSanitizePluginActionErrors:
    """``service._sanitize_plugin_action_errors`` -- adversarial re-validation
    of the plugin-supplied ``proposal_action_errors`` signal. Only exact
    ``tuple``/``list`` containers, exact ``str`` members and at most 200 raw
    entries are inspected; every path is re-validated against the strict path
    grammar (else ``"action"``), every code against the closed set (else
    ``"invalid_value"``); the result is deduplicated, sorted and capped at 20
    with ``omitted`` counting everything cut."""

    def test_absent_attribute_is_not_signalled(self) -> None:
        signalled, field_errors, omitted = _sanitize_plugin_action_errors(ValueError("x"))
        assert (signalled, field_errors, omitted) == (False, (), 0)

    def test_well_formed_pairs_pass_through_sorted_and_deduplicated(self) -> None:
        exc = _ForeignInvalidActionError(
            [("content", "missing"), ("citations.0.quote", "too_long"), ("content", "missing")]
        )
        signalled, field_errors, omitted = _sanitize_plugin_action_errors(exc)
        assert signalled is True
        assert field_errors == (("citations.0.quote", "too_long"), ("content", "missing"))
        assert omitted == 0

    @pytest.mark.parametrize(
        ("raw_path", "expected_path"),
        [
            # Attacker-chosen keys / values can never reach the output: only
            # the strict lowercase-snake grammar (with bounded numeric list
            # indexes) survives, everything else collapses to "action".
            ("Evil-Key!", "action"),
            ("target_id; DROP TABLE", "action"),
            ("content\ninjection", "action"),
            ("content extra", "action"),
            ("9content", "action"),
            ("-content", "action"),
            ("content ", "action"),
            ("a" * 129, "action"),
            ("a.b.c.d.e.f.g.h.i", "action"),  # 9 segments (max is 8)
            ("citations.99999.quote", "action"),  # 5-digit index (max is 4)
            ("citations.-1.quote", "action"),
            ("Citations.0.quote", "action"),
            # Grammar-valid shapes survive (schema-awareness is NOT claimed --
            # a grammar-valid but schema-unknown key is still safe to echo).
            ("content", "content"),
            ("citations.0.quote", "citations.0.quote"),
            ("a.b.c.d.e.f.g.h", "a.b.c.d.e.f.g.h"),  # 8 segments
            ("citations.9999.quote", "citations.9999.quote"),
        ],
    )
    def test_paths_are_revalidated_against_the_grammar(
        self, raw_path: str, expected_path: str
    ) -> None:
        exc = _ForeignInvalidActionError([(raw_path, "missing")])
        _, field_errors, _ = _sanitize_plugin_action_errors(exc)
        assert field_errors == ((expected_path, "missing"),)

    @pytest.mark.parametrize("bad_code", ["nope", "MISSING", "missing ", "", "not_canonical!"])
    def test_unknown_codes_downgrade_to_invalid_value(self, bad_code: str) -> None:
        exc = _ForeignInvalidActionError([("content", bad_code)])
        _, field_errors, _ = _sanitize_plugin_action_errors(exc)
        assert field_errors == (("content", "invalid_value"),)

    @pytest.mark.parametrize(
        "bad_item",
        [
            "not-a-pair",
            42,
            None,
            ("one",),
            ("a", "b", "c"),
            (1, "missing"),
            ("content", 7),
            (None, "missing"),
            (["content"], "missing"),
        ],
    )
    def test_malformed_items_collapse_to_the_generic_pair(self, bad_item: Any) -> None:
        exc = _ForeignInvalidActionError([("content", "missing"), bad_item])
        _, field_errors, _ = _sanitize_plugin_action_errors(exc)
        assert field_errors == (
            ("action", "invalid_value"),
            ("content", "missing"),
        )

    @pytest.mark.parametrize(
        "bad_raw",
        [
            "content:missing",  # a plain str
            {"content": "missing"},  # mapping
            None,
            42,
            iter([("content", "missing")]),  # generator: not a tuple/list
            frozenset({("content", "missing")}),
        ],
    )
    def test_non_container_raw_values_signal_with_no_field_errors(self, bad_raw: Any) -> None:
        """A present-but-untrustworthy attribute still means "invalid action"
        -- it just yields no (or fallback) reasons rather than ever surfacing
        plugin text."""
        exc = _ForeignInvalidActionError(bad_raw)
        signalled, field_errors, omitted = _sanitize_plugin_action_errors(exc)
        assert signalled is True
        assert field_errors == ()
        assert omitted == 0

    def test_flat_two_tuple_is_a_container_of_two_malformed_items(self) -> None:
        """A flat ``("content", "missing")`` 2-tuple is accepted as a
        container (the container check is type-based, not shape-based) and
        its two plain-``str`` members each collapse to the generic pair -- a
        safe fallback, never an echo of either member."""
        exc = _ForeignInvalidActionError(("content", "missing"))
        signalled, field_errors, omitted = _sanitize_plugin_action_errors(exc)
        assert signalled is True
        assert field_errors == (("action", "invalid_value"),)
        assert omitted == 0

    def test_raising_attribute_signals_with_no_field_errors(self) -> None:
        class _ExplodingSignalError(ValueError):
            @property
            def proposal_action_errors(self) -> Any:
                raise RuntimeError(f"exploding attr {_PLUGIN_SENTINEL}")

        signalled, field_errors, omitted = _sanitize_plugin_action_errors(
            _ExplodingSignalError("x")
        )
        assert signalled is True
        assert field_errors == ()
        assert omitted == 0

    def test_more_than_200_raw_entries_are_counted_as_omitted(self) -> None:
        raw = [(f"field{i:04d}", "missing") for i in range(250)]
        exc = _ForeignInvalidActionError(raw)
        signalled, field_errors, omitted = _sanitize_plugin_action_errors(exc)
        assert signalled is True
        assert len(field_errors) == 20  # the reported cap
        # 250 raw entries: 200 inspected -> 200 unique -> 20 reported
        # (180 omitted) + 50 never inspected. Entries past the 200-entry
        # inspection cap contribute ONLY to this count -- they are never
        # read as pairs (all 250 are distinct, so only prefixes from the
        # first 200, "field0000".."field0199", can appear in the output).
        assert omitted == 230
        assert all(path < "field0200" for path, _code in field_errors)

    def test_more_than_20_unique_pairs_are_capped_with_omitted_count(self) -> None:
        raw = [(f"field{i:02d}", "missing") for i in range(25)]
        exc = _ForeignInvalidActionError(raw)
        _, field_errors, omitted = _sanitize_plugin_action_errors(exc)
        assert len(field_errors) == 20
        assert field_errors == tuple(sorted(raw)[:20])
        assert omitted == 5

    def test_list_raw_container_is_accepted(self) -> None:
        exc = _ForeignInvalidActionError([("content", "missing")])
        _, field_errors, _ = _sanitize_plugin_action_errors(exc)
        assert field_errors == (("content", "missing"),)

    def test_tuple_raw_container_is_accepted(self) -> None:
        exc = _ForeignInvalidActionError((("content", "missing"),))
        _, field_errors, _ = _sanitize_plugin_action_errors(exc)
        assert field_errors == (("content", "missing"),)


class TestReadSupportedProposalKinds:
    """``service._read_supported_proposal_kinds`` -- the optional
    ``supported_proposal_kinds`` capability, read defensively. Absent, ``None``,
    empty, a ``str``/``bytes``/mapping, a non-iterable, an iteration error,
    more than 32 entries, or any entry that is not a safe kind label all mean
    "unknown" (``None``); at most 33 entries are ever pulled from a runaway
    iterable."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (
                frozenset({"arcana_source_add", "linear_progress_update"}),
                frozenset({"arcana_source_add", "linear_progress_update"}),
            ),
            (
                ["arcana_source_add", "linear_progress_update"],
                frozenset({"arcana_source_add", "linear_progress_update"}),
            ),
            (("arcana_source_add",), frozenset({"arcana_source_add"})),
            ({"arcana_source_add"}, frozenset({"arcana_source_add"})),  # a set, not a mapping
        ],
    )
    def test_valid_iterables_round_trip(self, raw: Any, expected: frozenset[str]) -> None:
        judge = type("J", (), {PROPOSAL_SUPPORTED_KINDS_ATTR: raw})()
        assert _read_supported_proposal_kinds(judge) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            None,  # explicit None value
            "arcana_source_add",  # a plain str
            b"arcana_source_add",
            bytearray(b"x"),
            {"arcana_source_add": True},  # mapping
            [],  # empty iterable
            (),  # empty tuple
            set(),  # empty set
            42,  # non-iterable
        ],
    )
    def test_untrustworthy_values_read_as_unknown(self, raw: Any) -> None:
        judge = type("J", (), {PROPOSAL_SUPPORTED_KINDS_ATTR: raw})()
        assert _read_supported_proposal_kinds(judge) is None

    def test_absent_attribute_reads_as_unknown(self) -> None:
        assert _read_supported_proposal_kinds(object()) is None

    def test_at_most_32_entries_are_accepted(self) -> None:
        judge = type("J", (), {PROPOSAL_SUPPORTED_KINDS_ATTR: [f"kind{i}" for i in range(32)]})()
        assert len(_read_supported_proposal_kinds(judge) or ()) == 32

    def test_more_than_32_entries_read_as_unknown(self) -> None:
        judge = type("J", (), {PROPOSAL_SUPPORTED_KINDS_ATTR: [f"kind{i}" for i in range(33)]})()
        assert _read_supported_proposal_kinds(judge) is None

    @pytest.mark.parametrize(
        "entry",
        ["Not-Lowercase", "x" * 65, "", "has-dash", "9starts-digit", "kind with space", 42, None],
    )
    def test_any_unsafe_entry_kills_the_whole_capability(self, entry: Any) -> None:
        judge = type("J", (), {PROPOSAL_SUPPORTED_KINDS_ATTR: ["arcana_source_add", entry]})()
        assert _read_supported_proposal_kinds(judge) is None

    def test_raising_property_reads_as_unknown(self) -> None:
        class _Raising:
            @property
            def supported_proposal_kinds(self) -> Any:
                raise RuntimeError(f"boom {_PLUGIN_SENTINEL}")

        assert _read_supported_proposal_kinds(_Raising()) is None

    def test_runaway_iterable_is_never_drained_past_33(self) -> None:
        pulled = {"n": 0}

        def infinite() -> Any:
            i = 0
            while True:
                pulled["n"] += 1
                if pulled["n"] > 100:
                    raise AssertionError("a runaway iterable must never be drained past 33")
                yield f"kind{i}"
                i += 1

        judge = type("J", (), {PROPOSAL_SUPPORTED_KINDS_ATTR: infinite()})()
        assert _read_supported_proposal_kinds(judge) is None
        assert pulled["n"] == 33


class TestSafeProposalKindLabel:
    """``service._safe_proposal_kind_label`` -- a ``kind`` is echoed back to
    the caller only when it is a plain ``str`` matching
    ``[a-z][a-z0-9_]{0,63}``."""

    @pytest.mark.parametrize(
        "label",
        ["arcana_source_add", "linear_progress_update", "a", "x" * 64, "kind9with_digits_2"],
    )
    def test_safe_labels_pass_through(self, label: str) -> None:
        assert _safe_proposal_kind_label(label) == label

    @pytest.mark.parametrize(
        "label",
        [
            "UPPER",
            "Arcana_Source_Add",
            "x" * 65,
            "",
            "kind-dash",
            "9kind",
            "kind space",
            "kind\nnewline",
            "kind; DROP TABLE",
            "arcana-source:add",
        ],
    )
    def test_unsafe_labels_read_as_none(self, label: str) -> None:
        assert _safe_proposal_kind_label(label) is None

    def test_non_str_kinds_read_as_none(self) -> None:
        for bad in (42, None, b"bytes", ["kind"], {"kind": 1}, "KIND"):
            assert _safe_proposal_kind_label(bad) is None


class TestBoundProposalErrorMessage:
    """``service._bound_proposal_error_message`` -- final scrub + 500-char
    truncation of a caller-facing proposal error string."""

    def test_scrubs_credential_kv_tokens_and_url_query_strings(self) -> None:
        message = (
            "upstream failed: token=secret12345 at "
            "https://api.linear.app/graphql?api_key=abc456 end"
        )
        bound = _bound_proposal_error_message(message)
        assert "secret12345" not in bound
        assert "abc456" not in bound
        assert "api_key=" not in bound
        assert bound == "upstream failed: at https://api.linear.app/graphql end"

    def test_truncates_to_500_chars_with_suffix(self) -> None:
        bound = _bound_proposal_error_message("y" * 600)
        assert len(bound) == 500
        assert bound.endswith("... [truncated]")
        assert bound.startswith("y" * 100)

    def test_short_clean_messages_pass_through_unchanged(self) -> None:
        assert _bound_proposal_error_message("invalid x action: a: missing") == (
            "invalid x action: a: missing"
        )


class TestClassifyValueErrorToProposalError:
    """``service._classify_value_error_to_proposal_error`` -- the board-owned
    mapping of a judge ``ValueError`` to the caller-facing 422 error. Never
    uses ``str(exc)`` or the exception class."""

    def test_signalled_error_maps_to_invalid_proposal_action_error(self) -> None:
        judge = FakeProposalJudge()
        exc = _ForeignInvalidActionError([("content", "missing")])
        mapped = _classify_value_error_to_proposal_error(judge, "arcana_source_add", exc)
        assert isinstance(mapped, InvalidProposalActionError)
        assert isinstance(mapped, ValueError)
        assert mapped.detail == "invalid arcana_source_add action: content: missing"
        assert mapped.field_errors == (("content", "missing"),)
        assert mapped.omitted == 0
        assert _PLUGIN_SENTINEL not in mapped.detail

    def test_signalled_error_message_lists_pairs_sorted_with_omitted_suffix(self) -> None:
        exc = _ForeignInvalidActionError(
            [("z_field", "missing"), ("a_field", "too_long"), ("m_field", "missing")]
        )
        mapped = _classify_value_error_to_proposal_error(
            FakeProposalJudge(), "arcana_source_add", exc
        )
        assert isinstance(mapped, InvalidProposalActionError)
        assert mapped.detail == (
            "invalid arcana_source_add action: a_field: too_long; "
            "m_field: missing; z_field: missing"
        )

    def test_omitted_reasons_appear_as_a_bounded_suffix(self) -> None:
        raw = [(f"field{i:02d}", "missing") for i in range(25)]
        exc = _ForeignInvalidActionError(raw)
        mapped = _classify_value_error_to_proposal_error(
            FakeProposalJudge(), "arcana_source_add", exc
        )
        assert isinstance(mapped, InvalidProposalActionError)
        assert mapped.detail.endswith("(+5 more)")
        assert mapped.omitted == 5
        assert len(mapped.field_errors) == 20

    def test_message_is_capped_at_500_chars_even_with_maximal_pairs(self) -> None:
        # 20 DISTINCT grammar-valid 127-char paths (identical pairs would
        # dedup to one; a dotless path can be at most 64 chars, so use the
        # full 8-segment dotted shape).
        raw = [(".".join([f"p{i:02d}" + "s" * 12] + ["s" * 15] * 7), "missing") for i in range(20)]
        assert all(len(path) == 127 for path, _code in raw)
        exc = _ForeignInvalidActionError(raw)
        mapped = _classify_value_error_to_proposal_error(
            FakeProposalJudge(), "arcana_source_add", exc
        )
        assert isinstance(mapped, InvalidProposalActionError)
        assert len(mapped.detail) == 500
        assert mapped.detail.endswith("... [truncated]")

    def test_unsafe_kind_label_yields_a_generic_invalid_action_message(self) -> None:
        for kind in ("UPPER", "x" * 65, "kind; DROP TABLE", "kind\ninjection"):
            exc = _ForeignInvalidActionError([("content", "missing")])
            mapped = _classify_value_error_to_proposal_error(FakeProposalJudge(), kind, exc)
            assert isinstance(mapped, InvalidProposalActionError)
            assert mapped.detail == "invalid proposal action: content: missing"
            assert kind not in mapped.detail

    def test_malformed_signal_yields_generic_invalid_action_without_plugin_text(self) -> None:
        exc = _ForeignInvalidActionError("content:missing")
        mapped = _classify_value_error_to_proposal_error(
            FakeProposalJudge(), "arcana_source_add", exc
        )
        assert isinstance(mapped, InvalidProposalActionError)
        assert mapped.detail == "invalid arcana_source_add action"
        assert mapped.field_errors == ()
        assert _PLUGIN_SENTINEL not in mapped.detail

    def test_bare_value_error_for_a_declared_supported_kind_is_invalid_action(self) -> None:
        judge = FakeProposalJudge(supported_proposal_kinds=frozenset({"arcana_source_add"}))
        mapped = _classify_value_error_to_proposal_error(
            judge, "arcana_source_add", ValueError(f"plugin detail {_PLUGIN_SENTINEL}")
        )
        assert isinstance(mapped, InvalidProposalActionError)
        assert mapped.detail == "invalid arcana_source_add action"
        assert mapped.field_errors == ()
        assert _PLUGIN_SENTINEL not in mapped.detail

    def test_bare_value_error_for_an_undeclared_kind_lists_supported_kinds(self) -> None:
        judge = FakeProposalJudge(
            supported_proposal_kinds=["arcana_source_add", "arcana_source_revise"]
        )
        mapped = _classify_value_error_to_proposal_error(
            judge, "arcana_source_upsert", ValueError(f"plugin detail {_PLUGIN_SENTINEL}")
        )
        assert type(mapped) is ValueError
        assert mapped.args[0] == (
            "unsupported proposal kind: 'arcana_source_upsert'; "
            "supported kinds: arcana_source_add, arcana_source_revise"
        )
        assert _PLUGIN_SENTINEL not in mapped.args[0]

    def test_bare_value_error_without_the_capability_keeps_the_plain_message(self) -> None:
        judge = FakeProposalJudge()  # supported_proposal_kinds defaults to None (unknown)
        mapped = _classify_value_error_to_proposal_error(
            judge, "arcana_source_upsert", ValueError("plugin detail")
        )
        assert type(mapped) is ValueError
        assert mapped.args[0] == "unsupported proposal kind: 'arcana_source_upsert'"

    def test_capability_with_an_unsafe_kind_still_names_supported_kinds(self) -> None:
        judge = FakeProposalJudge(supported_proposal_kinds=frozenset({"arcana_source_add"}))
        mapped = _classify_value_error_to_proposal_error(
            judge, "UPPER-CASE-KIND", ValueError("plugin detail")
        )
        assert type(mapped) is ValueError
        assert mapped.args[0] == "unsupported proposal kind; supported kinds: arcana_source_add"
        assert "UPPER-CASE-KIND" not in mapped.args[0]

    def test_message_is_scrubbed_when_rebuilt_from_pairs(self) -> None:
        """The rebuilt message goes through the credential/URL scrub before
        reaching the caller -- a path/code pair can never smuggle
        credential-shaped text through because paths are grammar-validated,
        but the kind label and the assembled message are still scrubbed
        end-to-end."""
        exc = _ForeignInvalidActionError([("content", "missing")])
        mapped = _classify_value_error_to_proposal_error(
            FakeProposalJudge(), "arcana_source_add", exc
        )
        assert isinstance(mapped, InvalidProposalActionError)
        assert "api_key" not in mapped.detail
        assert "sk-" not in mapped.detail


class TestClassifyProposalInvalidActionSeam:
    """``service._classify_proposal`` end-to-end with the TECH-7711 signal:
    the duck-typed error maps to ``InvalidProposalActionError`` with the
    sanitized, board-owned message, preserving the plugin exception as
    ``__cause__`` (where the sentinel lives, and only there)."""

    def test_signalled_error_through_classify_proposal(self) -> None:
        judge = FakeProposalJudge(
            classify_raises=_ForeignInvalidActionError([("content", "missing")])
        )
        with pytest.raises(InvalidProposalActionError) as exc_info:
            _classify_proposal(judge, "arcana_source_add", {})
        assert exc_info.value.detail == "invalid arcana_source_add action: content: missing"
        assert exc_info.value.field_errors == (("content", "missing"),)
        assert exc_info.value.omitted == 0
        # The plugin's own exception (with its sentinel text) is preserved as
        # __cause__ for logging -- but never reaches the caller-facing detail.
        assert isinstance(exc_info.value.__cause__, _ForeignInvalidActionError)
        assert _PLUGIN_SENTINEL in str(exc_info.value.__cause__)
        assert _PLUGIN_SENTINEL not in exc_info.value.detail

    def test_bare_value_error_with_capability_through_classify_proposal(self) -> None:
        judge = FakeProposalJudge(
            classify_raises=ValueError(f"plugin detail {_PLUGIN_SENTINEL}"),
            supported_proposal_kinds=frozenset({"arcana_source_add", "arcana_source_revise"}),
        )
        with pytest.raises(InvalidProposalActionError) as exc_info:
            _classify_proposal(judge, "arcana_source_add", {})
        assert exc_info.value.detail == "invalid arcana_source_add action"
        assert exc_info.value.field_errors == ()
        assert _PLUGIN_SENTINEL not in exc_info.value.detail

    def test_unknown_kind_with_capability_through_classify_proposal(self) -> None:
        judge = FakeProposalJudge(
            classify_raises=ValueError("unsupported kind: 'arcana_source_upsert'"),
            supported_proposal_kinds=frozenset(
                {"arcana_source_add", "arcana_source_revise", "linear_progress_update"}
            ),
        )
        with pytest.raises(ValueError) as exc_info:
            _classify_proposal(judge, "arcana_source_upsert", {})
        assert not isinstance(exc_info.value, InvalidProposalActionError)
        assert exc_info.value.args[0] == (
            "unsupported proposal kind: 'arcana_source_upsert'; "
            "supported kinds: arcana_source_add, arcana_source_revise, linear_progress_update"
        )
        assert _PLUGIN_SENTINEL not in exc_info.value.args[0]
        assert "unsupported kind: 'arcana_source_upsert'" in str(exc_info.value.__cause__)

    def test_plugin_sentinel_never_reaches_the_caller_facing_message(self) -> None:
        judge = FakeProposalJudge(
            classify_raises=_ForeignInvalidActionError(
                [("Evil-Key; secret=" + _PLUGIN_SENTINEL, "nope")],
                message=f"echoes content={_PLUGIN_SENTINEL}",
            )
        )
        with pytest.raises(InvalidProposalActionError) as exc_info:
            _classify_proposal(judge, "arcana_source_add", {})
        assert exc_info.value.detail == "invalid arcana_source_add action: action: invalid_value"
        assert _PLUGIN_SENTINEL not in exc_info.value.detail
        assert _PLUGIN_SENTINEL not in repr(exc_info.value.field_errors)

    def test_generic_exception_path_message_is_unchanged(self) -> None:
        """Pre-TECH-7711 behavior pinned deliberately (scope note for review):
        a non-ValueError plugin bug still echoes the caller-supplied ``kind``
        in ``proposal classification failed for kind {kind!r}``."""
        judge = FakeProposalJudge(classify_raises=RuntimeError("boom"))
        with pytest.raises(ValueError, match="proposal classification failed for kind") as exc_info:
            _classify_proposal(judge, "linear_progress_update", {})
        assert "'linear_progress_update'" in str(exc_info.value)

    def test_priority_validation_path_message_is_unchanged(self) -> None:
        """Pre-TECH-7711 behavior pinned deliberately (scope note for review):
        an unusable priority still echoes the caller-supplied ``kind``."""
        judge = FakeProposalJudge(classify_result=ProposalClassification(priority="urgent!!"))
        with pytest.raises(
            ValueError,
            match="proposal judge returned invalid priority for kind 'linear_progress_update'",
        ) as exc_info:
            _classify_proposal(judge, "linear_progress_update", {})
        assert "must be one of" in str(exc_info.value)
