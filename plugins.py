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

PR2 (TECH-5389) adds two more seams, same mechanism: the auto-approver
(``AutoApprover``/``AUTO_APPROVERS``/``AUTO_APPROVER_ENV_VAR``) and the
approval-request notifier (``ApprovalNotifier``/``APPROVAL_NOTIFIERS``/
``APPROVAL_NOTIFIER_ENV_VAR``), both resolved via the same
``resolve_plugin`` helper the risk scorer already uses.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol

import httpx
import structlog

from schemas import CONVERSATION_TYPES

if TYPE_CHECKING:
    # Avoids a runtime circular import: service.py imports this module to
    # get RiskScorer/MessageRiskContext, so this module must not import
    # service.py back at runtime — only its OwnershipClient TYPE for
    # annotations, which both modules already do via
    # ``from __future__ import annotations`` (deferred evaluation).
    from service import OwnershipClient

logger = logging.getLogger(__name__)
# Structured event logging for the notifier seam only (LogOnlyNotifier's
# "safe in a bare deployment" default and WebhookNotifier's failure path)
# — unlike service.py, which never imports structlog (see its own
# docstring: that module's logger exists solely for CloudWatch-visible
# diagnostics), this module's notifier seam is asked by the plan doc for a
# real structured ``approval_escalated`` event, and structlog is already a
# pinned dependency (observability.py).
_notify_log = structlog.get_logger(module=__name__)

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


def _plugin_display_name(instance: Any, registry: dict[str, Callable[[], Any]]) -> str:
    """Recover a human/audit-readable name for a resolved plugin instance.

    Reverse-looks-up ``instance``'s class against ``registry`` (the common
    case: resolved by registry name) so ``approval_holds.risk_scorer`` /
    ``.auto_approver`` record the SAME string the ``RISK_SCORER``/
    ``AUTO_APPROVER`` env var was set to, per the plan doc's data-model
    section. Falls back to a synthesized ``module:qualname`` import-path-
    shaped string for anything not found in the registry (an
    import-path-configured plugin, or a test-injected fake) — not
    necessarily byte-identical to a caller's configured import path, but
    equally recoverable/auditable.
    """
    cls = type(instance)
    for name, factory in registry.items():
        if factory is cls:
            return name
    return f"{cls.__module__}:{cls.__qualname__}"


def risk_scorer_name(scorer: RiskScorer) -> str:
    """Audit-readable name for a resolved ``RiskScorer`` instance."""
    return _plugin_display_name(scorer, RISK_SCORERS)


def auto_approver_name(approver: AutoApprover) -> str:
    """Audit-readable name for a resolved ``AutoApprover`` instance."""
    return _plugin_display_name(approver, AUTO_APPROVERS)


def notifier_name(notifier: ApprovalNotifier) -> str:
    """Audit-readable name for a resolved ``ApprovalNotifier`` instance."""
    return _plugin_display_name(notifier, APPROVAL_NOTIFIERS)


def validate_configuration() -> None:
    """Fail fast at process start if any of the three seams don't resolve.

    Called from ``main._cli()`` beside the existing ``db.database_url()``
    fail-fast call — an unknown registry name, a bad import path, or (for
    ``APPROVAL_NOTIFIER=webhook``) a missing webhook env var must crash at
    boot, not lazily on the first high-risk message.
    """
    get_risk_scorer()
    get_auto_approver()
    get_approval_notifier()


# --- Seam 2: the auto-approver (TECH-5389 PR2) -------------------------------

AUTO_APPROVER_ENV_VAR = "AUTO_APPROVER"
DEFAULT_AUTO_APPROVER = "escalate_all"


class AutoDecision(NamedTuple):
    """An auto-approver's decision for one hold.

    ``cleared=True`` means "post now, no human needed"; ``detail`` carries
    audit-only extras (mirrors ``RiskVerdict.detail``).
    """

    cleared: bool
    detail: dict[str, Any] | None


class HoldContext(NamedTuple):
    """Everything an ``AutoApprover`` needs to review one hold.

    Unlike ``MessageRiskContext``, this DOES carry the payload — per the
    plan doc, the risk flag stays light and the expensive judgment belongs
    here.
    """

    hold_id: uuid.UUID
    conversation_id: uuid.UUID
    conversation_type: str
    sender_agent_id: uuid.UUID
    owner_sub: str
    message_type: str
    schema_version: int
    payload: dict[str, Any]
    risk_reason: str


class AutoApprover(Protocol):
    async def review(self, ctx: HoldContext) -> AutoDecision:
        """Return a decision for this hold. Never raise for an ordinary
        "not clearing this" outcome — that is ``AutoDecision(cleared=False, ...)``."""
        ...


class EscalateAllAutoApprover:
    """``escalate_all`` — v1 auto-approver: always escalates to a human.

    Returns ``cleared=False`` unconditionally, but is invoked inline, for
    real, on every high-risk post (``service.post_message`` /
    ``service.start_conversation``) — not dead code. See the plan doc's
    "sync-now/async-later accommodation" (§3) for why the hold-status
    vocabulary already contains ``pending_auto`` even though v1 never
    observes a committed row in that state.
    """

    async def review(self, ctx: HoldContext) -> AutoDecision:
        return AutoDecision(cleared=False, detail=None)


AUTO_APPROVERS: dict[str, Callable[[], AutoApprover]] = {
    DEFAULT_AUTO_APPROVER: EscalateAllAutoApprover,
}

_auto_approver: AutoApprover | None = None


def get_auto_approver() -> AutoApprover:
    """Return the process-wide configured ``AutoApprover`` (lazy singleton,
    mirrors ``get_risk_scorer``)."""
    global _auto_approver
    if _auto_approver is None:
        _auto_approver = resolve_plugin(
            AUTO_APPROVER_ENV_VAR, AUTO_APPROVERS, DEFAULT_AUTO_APPROVER
        )
    return _auto_approver


# --- Seam 3: the approval-request notifier (TECH-5389 PR2) ------------------

APPROVAL_NOTIFIER_ENV_VAR = "APPROVAL_NOTIFIER"
DEFAULT_APPROVAL_NOTIFIER = "log_only"
APPROVAL_WEBHOOK_URL_ENV_VAR = "APPROVAL_WEBHOOK_URL"
APPROVAL_WEBHOOK_SECRET_ENV_VAR = "APPROVAL_WEBHOOK_SECRET"
APPROVAL_WEBHOOK_SIGNATURE_HEADER = "X-Approval-Signature"
_WEBHOOK_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class ApprovalNotification:
    """Pointer-not-content payload handed to ``ApprovalNotifier.notify_escalated``.

    Deliberately excludes the held message's payload/text — this is the
    one place approval data leaves the service's trust boundary (per the
    plan doc §4). Everything a human needs to ROUTE and RENDER a link to
    the real approval surface (``GET /approvals/pending`` /
    ``comms_get_hold_status``) is here; the actual content is fetched
    through that authenticated, owner-matched surface instead.
    """

    hold_id: str
    conversation_id: str
    conversation_type: str
    sender_agent_id: str
    sender_display_name: str
    owner_sub: str
    owner_email: str
    message_type: str
    risk_reason: str
    expires_at: str
    created_at: str


class ApprovalNotifier(Protocol):
    async def notify_escalated(self, notification: ApprovalNotification) -> None:
        """Best-effort notification that a hold entered ``pending_human``.

        Callers (``service._fire_notifier``) invoke this post-commit and
        treat any exception as non-fatal — see that function's docstring
        for the exact failure semantics (log + ``approval.notify_failed``
        audit row, never a rollback, never a failed tool response)."""
        ...


class LogOnlyNotifier:
    """``log_only`` — the default. Zero required config, no accidental
    egress to a half-configured URL: safe in a bare deployment."""

    async def notify_escalated(self, notification: ApprovalNotification) -> None:
        _notify_log.info("approval_escalated", **asdict(notification))


class WebhookNotifier:
    """``webhook`` — ``POST``s the notification JSON to
    ``APPROVAL_WEBHOOK_URL``, HMAC-SHA256-signed (keyed by
    ``APPROVAL_WEBHOOK_SECRET``) via the ``X-Approval-Signature`` header.

    Both env vars are required when this notifier is selected, validated
    at construction time (i.e. by ``validate_configuration`` at startup,
    the same fail-fast pass every other plugin misconfiguration goes
    through) rather than lazily on the first escalation. No retries in v1
    (ratified — see the plan doc §17).
    """

    def __init__(self) -> None:
        url = os.environ.get(APPROVAL_WEBHOOK_URL_ENV_VAR)
        secret = os.environ.get(APPROVAL_WEBHOOK_SECRET_ENV_VAR)
        if not url or not secret:
            raise RuntimeError(
                f"{APPROVAL_NOTIFIER_ENV_VAR}=webhook requires both "
                f"{APPROVAL_WEBHOOK_URL_ENV_VAR} and {APPROVAL_WEBHOOK_SECRET_ENV_VAR} "
                "to be set"
            )
        self._url = url
        self._secret = secret.encode("utf-8")

    async def notify_escalated(self, notification: ApprovalNotification) -> None:
        body = json.dumps(asdict(notification)).encode("utf-8")
        signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT_SECONDS) as client:
            response = await client.post(
                self._url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    APPROVAL_WEBHOOK_SIGNATURE_HEADER: signature,
                },
            )
            response.raise_for_status()


APPROVAL_NOTIFIERS: dict[str, Callable[[], ApprovalNotifier]] = {
    DEFAULT_APPROVAL_NOTIFIER: LogOnlyNotifier,
    "webhook": WebhookNotifier,
}

_approval_notifier: ApprovalNotifier | None = None


def get_approval_notifier() -> ApprovalNotifier:
    """Return the process-wide configured ``ApprovalNotifier`` (lazy
    singleton, mirrors ``get_risk_scorer``)."""
    global _approval_notifier
    if _approval_notifier is None:
        _approval_notifier = resolve_plugin(
            APPROVAL_NOTIFIER_ENV_VAR, APPROVAL_NOTIFIERS, DEFAULT_APPROVAL_NOTIFIER
        )
    return _approval_notifier


__all__ = [
    "APPROVAL_NOTIFIERS",
    "APPROVAL_NOTIFIER_ENV_VAR",
    "APPROVAL_WEBHOOK_SECRET_ENV_VAR",
    "APPROVAL_WEBHOOK_URL_ENV_VAR",
    "AUTO_APPROVERS",
    "AUTO_APPROVER_ENV_VAR",
    "BARRIER_SENSITIVE_TYPES",
    "DEFAULT_APPROVAL_NOTIFIER",
    "DEFAULT_AUTO_APPROVER",
    "DEFAULT_RISK_SCORER",
    "RISK_SCORERS",
    "RISK_SCORER_ENV_VAR",
    "ApprovalNotification",
    "ApprovalNotifier",
    "AutoApprover",
    "AutoDecision",
    "BoundaryCrossingScorer",
    "EscalateAllAutoApprover",
    "HoldContext",
    "LogOnlyNotifier",
    "MessageRiskContext",
    "RiskScorer",
    "RiskScoringInfraError",
    "RiskVerdict",
    "WebhookNotifier",
    "auto_approver_name",
    "get_approval_notifier",
    "get_auto_approver",
    "get_risk_scorer",
    "notifier_name",
    "resolve_plugin",
    "risk_scorer_name",
    "validate_configuration",
]
