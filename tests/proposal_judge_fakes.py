"""Shared ``plugins.ProposalJudge`` test double (proposal-judge-arch
migration) -- used by ``tests/test_proposal_service.py`` (board-mechanics
integration, real Postgres) and ``tests/test_proposal_judge_seam.py``
(the seam's own fail-closed/contract-violation coverage, no DB needed).

Not a ``test_*.py`` module on purpose -- pytest would otherwise try to
collect it (and warn about ``FakeProposalJudge`` not being a `Test*`-shaped
class, harmlessly, but noisily).
"""

from __future__ import annotations

from typing import Any

from plugins import (
    FINGERPRINT_NO_TARGET,
    ProposalApplyOutcome,
    ProposalClassification,
    ProposalContext,
    ProposalFingerprint,
    ProposalVerdict,
)

_UNSET: Any = object()


class FakeProposalJudge:
    """Scriptable fake for ``plugins.ProposalJudge`` -- exercises the
    board's own dispatch/state-machine behavior around whatever verdict
    this fake hands it, without any real Linear/GitHub-style artifact
    checking.

    Each of the four methods returns whichever ``*_result`` is currently
    set, or raises ``*_raises`` instead when that's set (checked first) --
    read at CALL time, not construction time, so a single instance can be
    reused across a resubmission with a different verdict by mutating the
    relevant attribute between calls. ``classify_calls``/
    ``fingerprint_calls``/``judge_calls``/``apply_calls`` record every call's
    arguments, for assertions like "the applier was never called."
    """

    def __init__(
        self,
        *,
        classify_result: Any = _UNSET,
        classify_raises: Exception | None = None,
        fingerprint_result: Any = _UNSET,
        fingerprint_raises: Exception | None = None,
        judge_result: Any = _UNSET,
        judge_raises: Exception | None = None,
        apply_result: Any = _UNSET,
        apply_raises: Exception | None = None,
    ) -> None:
        self.classify_result: Any = (
            ProposalClassification(priority="low") if classify_result is _UNSET else classify_result
        )
        self.classify_raises = classify_raises
        self.fingerprint_result: Any = (
            ProposalFingerprint(status=FINGERPRINT_NO_TARGET)
            if fingerprint_result is _UNSET
            else fingerprint_result
        )
        self.fingerprint_raises = fingerprint_raises
        self.judge_result: Any = (
            ProposalVerdict(approved=False, decision_note=None)
            if judge_result is _UNSET
            else judge_result
        )
        self.judge_raises = judge_raises
        self.apply_result: Any = (
            ProposalApplyOutcome(
                applied=False,
                result=None,
                caller_error="FakeProposalJudge: no apply_result configured",
                log_detail=None,
            )
            if apply_result is _UNSET
            else apply_result
        )
        self.apply_raises = apply_raises
        self.classify_calls: list[tuple[str, dict[str, Any]]] = []
        self.fingerprint_calls: list[ProposalContext] = []
        self.judge_calls: list[ProposalContext] = []
        self.apply_calls: list[ProposalContext] = []

    def classify(self, kind: str, action: dict[str, Any]) -> ProposalClassification:
        self.classify_calls.append((kind, action))
        if self.classify_raises is not None:
            raise self.classify_raises
        return self.classify_result  # type: ignore[no-any-return]

    async def fingerprint(self, ctx: ProposalContext) -> ProposalFingerprint:
        self.fingerprint_calls.append(ctx)
        if self.fingerprint_raises is not None:
            raise self.fingerprint_raises
        return self.fingerprint_result  # type: ignore[no-any-return]

    async def judge(self, ctx: ProposalContext) -> ProposalVerdict:
        self.judge_calls.append(ctx)
        if self.judge_raises is not None:
            raise self.judge_raises
        return self.judge_result  # type: ignore[no-any-return]

    async def apply(self, ctx: ProposalContext) -> ProposalApplyOutcome:
        self.apply_calls.append(ctx)
        if self.apply_raises is not None:
            raise self.apply_raises
        return self.apply_result  # type: ignore[no-any-return]
