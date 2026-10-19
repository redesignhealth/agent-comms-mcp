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
        supported_proposal_kinds: Any = None,
    ) -> None:
        # The optional TECH-7711 capability, defaulting to ``None`` -- the
        # same "unknown" value ``service._read_supported_proposal_kinds``
        # treats exactly like an absent attribute, so every pre-existing
        # construction site is unaffected. A test that wants the board to
        # know this fake's supported kinds passes e.g.
        # ``frozenset({"arcana_source_add", "arcana_source_revise",
        # "linear_progress_update"})``.
        self.supported_proposal_kinds: Any = supported_proposal_kinds
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


# --- TECH-7711: shared "malformed action for a supported kind" driver ---------
#
# The six-case driver shared by ``tests/test_proposal_service.py`` (real
# Postgres, create_proposal level), ``tests/test_proposal_endpoint.py`` (REST
# parity) and ``tests/test_proposal_tools.py`` (MCP parity): one source of
# truth for the duck-typed signal a real judge (agent-comms-approvals'
# ``InvalidProposalAction``) emits, the judge that emits it, and the exact
# board-owned message each case must surface. ``tests/test_proposal_judge_
# seam.py`` keeps its own stand-in (it feeds varied plugin messages through
# the sanitizer); this one drives the fixed six-case matrix.


# Distinctive sentinel carried ONLY on the plugin exception's own message and
# ``__cause__`` (which the board deliberately preserves for logging) -- it
# must never reach any caller-facing string.
PLUGIN_SENTINEL = "SECRET-PLUGIN-INTERNALS-7711"

# The RH judge's kind set (agent-comms-approvals' registered kinds) as the
# fakes declare it for the six-case matrix.
SUPPORTED_PROPOSAL_KINDS = frozenset(
    {"arcana_source_add", "arcana_source_revise", "linear_progress_update"}
)


class ForeignInvalidActionError(ValueError):
    """Duck-typed stand-in for agent-comms-approvals'
    ``rh_comms_plugins.proposal_judge.InvalidProposalAction`` (TECH-7711) --
    a ``ValueError`` subclass carrying a ``proposal_action_errors`` tuple of
    ``(path, code)`` pairs, with a sentinel-laden message the board must
    never echo."""

    def __init__(self, errors: Any, message: str | None = None) -> None:
        self.proposal_action_errors = errors
        super().__init__(
            message
            if message is not None
            else f"pydantic internals: content={PLUGIN_SENTINEL} api_key=sk-{PLUGIN_SENTINEL}"
        )


# The six TECH-7711 cases -> the plugin-reported (path, code) pairs, or None
# for the bare-ValueError "unsupported kind" signal.
INVALID_ACTION_CASES: dict[str, tuple[tuple[str, str], ...] | None] = {
    "unknown_kind": None,
    "wrong_action_type": (("action_type", "invalid_value"),),
    "missing_field": (("content", "missing"),),
    "extra_field": (("action", "extra_field"),),
    "bad_canonical_target": (("target_id", "not_canonical"),),
    "sha_mismatch": (("sha256", "digest_mismatch"),),
}


def invalid_action_classify_raises(case: str) -> Exception:
    """The exception ``judge.classify()`` raises for ``case``: the
    duck-typed ``ForeignInvalidActionError`` carrying the case's
    ``(path, code)`` pairs, or a bare ``ValueError`` for ``unknown_kind``
    (with a sentinel-laden message the board must never echo)."""
    pairs = INVALID_ACTION_CASES[case]
    if pairs is None:
        # A real plugin's unsupported-kind message may carry plugin
        # internals; the board must never echo it (proven by the sentinel).
        return ValueError(f"unsupported kind: 'arcana_source_upsert' ({PLUGIN_SENTINEL})")
    return ForeignInvalidActionError(list(pairs))


def invalid_action_judge(case: str) -> FakeProposalJudge:
    """A ``FakeProposalJudge`` whose ``classify()`` raises ``case``'s signal
    (the duck-typed error, or a bare ``ValueError`` for ``unknown_kind``),
    declaring the RH kind set via the optional ``supported_proposal_kinds``
    capability."""
    return FakeProposalJudge(
        classify_raises=invalid_action_classify_raises(case),
        supported_proposal_kinds=SUPPORTED_PROPOSAL_KINDS,
    )


def invalid_action_kind(case: str) -> str:
    """The request ``kind`` for ``case``: the unsupported
    ``arcana_source_upsert`` for the unknown-kind case (so the bare
    ``ValueError`` maps to the unsupported-kind message listing the declared
    kinds), ``arcana_source_add`` for every malformed-action case."""
    return "arcana_source_upsert" if INVALID_ACTION_CASES[case] is None else "arcana_source_add"


def expected_invalid_action_detail(case: str) -> str:
    """The exact board-owned caller-facing message ``case`` must surface
    (identical across the service error, the REST ``detail`` and the MCP
    ``ToolError``)."""
    pairs = INVALID_ACTION_CASES[case]
    if pairs is None:
        return (
            "unsupported proposal kind: 'arcana_source_upsert'; "
            "supported kinds: arcana_source_add, arcana_source_revise, "
            "linear_progress_update"
        )
    return "invalid arcana_source_add action: " + "; ".join(
        f"{path}: {code}" for path, code in pairs
    )


def arcana_style_action() -> dict[str, Any]:
    """A minimal but realistic ``arcana_source_add`` action body for the
    six-case matrix: carries the required ``action_type``/``target_id`` (the
    create-time dedup key, extracted BEFORE the classify call) plus the
    arcana-style fields a real judge would have validated."""
    return {
        "action_type": "source_add",
        "target_id": "arcana-source:doc-1",
        "logical_id": "doc-1",
        "filename": "doc.md",
        "content": "Fact: the sky is blue.",
        "sha256": "0" * 64,
        "audience": "private",
    }
