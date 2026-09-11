"""Tests for the ``PROPOSAL_JUDGE`` seam's own contract (proposal-judge-arch
migration): the default ``plugins.EscalateAllProposalJudge``, the
board's defensive wrappers around every plugin call (
``service._classify_proposal``/``service._safe_fingerprint``/
``service._safe_apply``), and the integration-level fail-closed handling in
``create_proposal`` and ``_apply_or_finalize_proposal_hold``.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from models import ProposalHold
from plugins import (
    FINGERPRINT_DIGEST,
    FINGERPRINT_NO_TARGET,
    FINGERPRINT_UNAVAILABLE,
    EscalateAllProposalJudge,
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalContext,
    ProposalFingerprint,
    ProposalTargetError,
    ProposalVerdict,
)
from service import (
    PROPOSAL_HOLD_LEVELS,
    _classify_proposal,
    _safe_apply,
    _safe_fingerprint,
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
        with pytest.raises(ValueError, match="expected ProposalClassification"):
            _classify_proposal(judge, "linear_progress_update", {})

    def test_classify_returning_non_classification_object_raises_value_error(self) -> None:
        judge = FakeProposalJudge(classify_result={"priority": "low"})
        with pytest.raises(ValueError, match="expected ProposalClassification"):
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
        assert result["decision_note"] == "judge error: expected ProposalVerdict, got NoneType"
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
