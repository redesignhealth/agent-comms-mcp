"""Pluggable risk-scoring seam (TECH-5389).

Follows this codebase's existing ``OwnershipClient`` seam (see
``service.py``): a ``Protocol`` interface, a verdict type callers pattern-
match on, and a same-transaction-safe implementation resolved by the caller
and passed in as a parameter — never looked up ad hoc inside ``service.py``.

Resolution mechanism (env-var config, fail-fast at startup, no plugin
framework): ``resolve_plugin`` looks up an env var's value in a registry by
name; if the value contains a ``:`` it is instead treated as an import path
(``"pkg.module:factory"``) and resolved via ``importlib``, so a company can
plug in a private implementation from its own package on ``PYTHONPATH``
without forking this repo. Either path raises ``RuntimeError`` on an unknown
name / bad import / wrong shape — callers MUST call ``validate_configuration``
at process start (see ``main._cli``) so a misconfigured ``RISK_SCORER`` is
loud at boot, not on the first high-risk message.

PR1 (TECH-5389) scope note: this module currently holds only the risk-scorer
seam. The auto-approver and notifier seams described in the TECH-5389 plan
(``docs/TECH-5389-APPROVAL-PIPELINE.md``) land in a later PR alongside the
approval-holds pipeline that actually exercises them.
"""

from __future__ import annotations

import importlib
import os
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol

from schemas import CONVERSATION_TYPES

if TYPE_CHECKING:
    # Avoids a runtime circular import: service.py imports this module to
    # get RiskScorer/MessageRiskContext, so this module must not import
    # service.py back at runtime — only its OwnershipClient TYPE for
    # annotations, which both modules already do via
    # ``from __future__ import annotations`` (deferred evaluation).
    from service import OwnershipClient

RISK_SCORER_ENV_VAR = "RISK_SCORER"
DEFAULT_RISK_SCORER = "boundary_v1"

# The former ``schemas.MessageSchema.boundary_safe=False`` set — now
# scorer-private policy data instead of a schema field. Any message type
# NOT in this set is exempt from ownership-boundary scoring entirely (no
# lookup, always low risk) -- the cheap common path.
BARRIER_SENSITIVE_TYPES: frozenset[str] = frozenset({"note"})


class RiskVerdict(NamedTuple):
    """A risk scorer's decision for one message.

    ``reason`` is enum-coded (e.g. ``"boundary_crossing"``) and ``None``
    when not high risk. ``detail`` carries audit-only extras (e.g.
    ``{"bypass": "shared_sender"}``) and is never shown to the caller.
    """

    high_risk: bool
    reason: str | None
    detail: dict[str, Any] | None


class RiskScoringInfraError(Exception):
    """Raised by a ``RiskScorer.score()`` on any infrastructure failure —
    an ownership lookup error, an empty owner set, or an unrecognized
    ``conversation_type`` row. The caller (``service._score_message_risk``)
    must map every instance to a hard denial, never a silent post — a
    scorer implementation returns a ``RiskVerdict`` only when scoring
    itself succeeded.

    ``cause`` is an enum-coded string (e.g. ``"ownership_unverified"``,
    ``"unknown_conversation_type"``) for the caller's audit detail.
    """

    def __init__(self, cause: str) -> None:
        self.cause = cause
        super().__init__(cause)


class MessageRiskContext(NamedTuple):
    """Everything a ``RiskScorer`` needs to score one message.

    Primitives plus the injected ``OwnershipClient`` — no payload in v1
    (the v1 rule is type/topology-based, not content-based); adding
    ``payload`` later is additive.
    """

    conversation_type: str
    conversation_id: uuid.UUID | None
    sender_agent_id: uuid.UUID
    other_agent_ids: list[uuid.UUID]
    message_type: str
    schema_version: int
    ownership_client: OwnershipClient


class RiskScorer(Protocol):
    async def score(self, ctx: MessageRiskContext) -> RiskVerdict:
        """Return a verdict, or raise ``RiskScoringInfraError`` on any
        infrastructure failure. Never raise for a genuine high-risk
        finding — that is a normal ``RiskVerdict(high_risk=True, ...)``."""
        ...


class BoundaryCrossingScorer:
    """``boundary_v1`` — DESIGN.md §9 Axis 2's ownership-boundary rule,
    relocated here from ``state_machine.is_boundary_crossing_safe`` +
    ``service._enforce_boundary_crossing`` (TECH-5389 PR1).

    - A message type not in ``BARRIER_SENSITIVE_TYPES`` is never high risk
      and never triggers an ownership lookup.
    - An unrecognized ``conversation_type`` (e.g. a legacy pre-rename row)
      is checked FIRST, for every message type, and raises
      ``RiskScoringInfraError("unknown_conversation_type")`` — matching the
      pre-existing default-deny posture this scorer replaces (a
      boundary-safe message posted into an unrecognized conversation type
      was denied too, not just a sensitive one).
    - ``internal``: never high risk (every participant shares one owner
      set by construction).
    - ``open``: high risk iff the message type is sensitive.
    - ``asymmetric`` + sensitive type: an ownership lookup decides. A
      shared sender (``is_shared``) bypasses the check
      (``detail={"bypass": "shared_sender"}``); otherwise high risk iff any
      other participant's owner falls outside the sender's own owner set.
      A lookup failure, or an empty owner set for the sender or any other
      participant, raises ``RiskScoringInfraError`` rather than resolving
      the crossing question at all — an ownership-service outage must fail
      closed, not be silently treated as safe OR flood the approval queue
      (deferred to PR2) with unscorable holds.
    """

    async def score(self, ctx: MessageRiskContext) -> RiskVerdict:
        if ctx.conversation_type not in CONVERSATION_TYPES:
            raise RiskScoringInfraError("unknown_conversation_type")
        if ctx.message_type not in BARRIER_SENSITIVE_TYPES:
            return RiskVerdict(high_risk=False, reason=None, detail=None)
        if ctx.conversation_type == "internal":
            return RiskVerdict(high_risk=False, reason=None, detail=None)
        if ctx.conversation_type == "open":
            return RiskVerdict(high_risk=True, reason="boundary_crossing", detail=None)

        # asymmetric: sequential, not asyncio.gather -- the injected
        # OwnershipClient shares this call's AsyncSession, which
        # SQLAlchemy's AsyncSession does not support across concurrent
        # coroutines (see service._owner_sets_for's own docstring).
        try:
            sender_info = await ctx.ownership_client.get_agent_owners(ctx.sender_agent_id)
        except Exception as exc:
            raise RiskScoringInfraError("ownership_unverified") from exc
        if sender_info.get("is_shared"):
            return RiskVerdict(high_risk=False, reason=None, detail={"bypass": "shared_sender"})
        sender_owners = frozenset(sender_info.get("owners") or [])
        if not sender_owners:
            raise RiskScoringInfraError("empty_owner_set")

        other_owner_sets: list[frozenset[str]] = []
        try:
            for agent_id in ctx.other_agent_ids:
                info = await ctx.ownership_client.get_agent_owners(agent_id)
                other_owner_sets.append(frozenset(info.get("owners") or []))
        except Exception as exc:
            raise RiskScoringInfraError("ownership_unverified") from exc
        if any(not owners for owners in other_owner_sets):
            raise RiskScoringInfraError("empty_owner_set")

        other_owners = frozenset().union(*other_owner_sets) if other_owner_sets else frozenset()
        if other_owners <= sender_owners:
            return RiskVerdict(high_risk=False, reason=None, detail=None)
        return RiskVerdict(high_risk=True, reason="boundary_crossing", detail=None)


RISK_SCORERS: dict[str, Callable[[], RiskScorer]] = {
    DEFAULT_RISK_SCORER: BoundaryCrossingScorer,
}


def resolve_plugin(env_var: str, registry: dict[str, Callable[[], Any]], default: str) -> Any:
    """Resolve ``env_var`` (defaulting to ``default``) to a constructed
    plugin instance.

    The value is looked up in ``registry`` by name; if it contains a
    ``:`` it is instead treated as an import path
    (``"pkg.module:factory"``), resolved via ``importlib`` and called with
    no arguments. Raises ``RuntimeError`` for an unknown name or a failed
    import — never returns a partially-broken plugin.
    """
    name = os.environ.get(env_var, default)
    if ":" in name:
        module_path, _, attr = name.partition(":")
        try:
            module = importlib.import_module(module_path)
            factory = getattr(module, attr)
        except Exception as exc:
            raise RuntimeError(f"{env_var}: failed to import plugin {name!r}: {exc}") from exc
    else:
        factory = registry.get(name)
        if factory is None:
            raise RuntimeError(f"{env_var}: unknown plugin {name!r} (known: {sorted(registry)})")
    return factory()


_risk_scorer: RiskScorer | None = None


def get_risk_scorer() -> RiskScorer:
    """Return the process-wide configured ``RiskScorer``, resolving it on
    first use (mirrors ``db.get_engine``'s lazy-singleton pattern). A
    resolution failure is not cached — the next call retries against the
    same (still-broken) configuration, exactly as ``get_engine`` does for a
    bad ``DATABASE_URL``."""
    global _risk_scorer
    if _risk_scorer is None:
        _risk_scorer = resolve_plugin(RISK_SCORER_ENV_VAR, RISK_SCORERS, DEFAULT_RISK_SCORER)
    return _risk_scorer


def validate_configuration() -> None:
    """Fail fast at process start if ``RISK_SCORER`` doesn't resolve.

    Called from ``main._cli()`` beside the existing ``db.database_url()``
    fail-fast call — an unknown registry name or a bad import path must
    crash at boot, not lazily on the first high-risk message.
    """
    get_risk_scorer()


__all__ = [
    "BARRIER_SENSITIVE_TYPES",
    "DEFAULT_RISK_SCORER",
    "RISK_SCORERS",
    "RISK_SCORER_ENV_VAR",
    "BoundaryCrossingScorer",
    "MessageRiskContext",
    "RiskScorer",
    "RiskScoringInfraError",
    "RiskVerdict",
    "get_risk_scorer",
    "resolve_plugin",
    "validate_configuration",
]
