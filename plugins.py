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

``resolve_plugin``'s single-name resolution rule (registry lookup or
``pkg.module:factory`` import path) is factored out into
``resolve_plugin_name`` so a call site that needs to resolve MULTIPLE names
(TECH-5396's ``AGENT_TOKEN_VERIFIERS``, a comma-separated list) can reuse it
without duplicating the lookup/import logic. That seam's registry lives in
``auth.py``, not here — ``service.py`` imports this module, and this module
must stay fastmcp-free, so a ``TokenVerifier`` registry cannot live here.
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
      on its own — but for ``asymmetric`` this is no longer checked first
      (Argus round 1 fix, TECH-5786 PR follow-up): the shared-recipient
      check below runs regardless of message type, since it must catch
      every send to a shared recipient, not just sensitive-type ones. Only
      ``internal``/``open`` skip the ownership lookup entirely for a
      non-sensitive type.
    - An unrecognized ``conversation_type`` (e.g. a legacy pre-rename row)
      is checked FIRST, for every message type, and raises
      ``RiskScoringInfraError("unknown_conversation_type")`` — matching the
      pre-existing default-deny posture this scorer replaces (a
      boundary-safe message posted into an unrecognized conversation type
      was denied too, not just a sensitive one).
    - ``internal``: never high risk. This is safe BY CONSTRUCTION, not by
      runtime recheck (TECH-5735): admission (``_authorize_conversation_open``)
      and the invite gate (``_authorize_invite_owner_freeze``) both refuse
      to ever admit an ``is_shared`` agent into an `internal` conversation
      — the one thing that could make an already-equal owner set drift
      after open for that dimension, so there is nothing here to recheck
      for it. (A per-message runtime check would not have helped anyway:
      the exposure this ticket closes is at INVITE time — ``comms_accept``
      grants full conversation history the moment a participant is
      admitted — not at each subsequent message send.) This does NOT mean
      equality is unconditionally frozen forever: two accepted residual
      gaps remain outside this scorer's reach — (1) two already-admitted,
      already-non-shared participants' ``owner_sub``s can independently
      drift apart via ``write_through_ownership``/``reconcile_agent_ownership``,
      and (2) ``set_agent_shared`` can flip an already-admitted
      participant's ``is_shared`` to ``True`` after the conversation
      opened. Neither is checked here or anywhere else at send time — see
      ``docs/DESIGN.md`` §9's "Accepted residual gap (TECH-5735)" notes.
    - ``open``: high risk iff the message type is sensitive.
    - ``asymmetric``: every message (ANY type, not just a sensitive one)
      resolves every other participant's ownership info first, to run the
      shared-recipient check below before any type-based short-circuit.
      Two ``is_shared`` special cases are checked BEFORE the ordinary
      owner-set comparison is consulted at all, and BEFORE the
      ``BARRIER_SENSITIVE_TYPES`` filter for the shared-recipient case
      specifically:

      - A shared RECIPIENT (any participant in ``other_agent_ids`` with
        ``is_shared=True``) always forces ``high_risk=True``
        (``reason="boundary_crossing"``, ``detail={"reason":
        "shared_recipient"}``) — symmetric to, but the opposite effect of,
        the shared-sender bypass below. This is checked FIRST, for EVERY
        message type, and wins even when the sender is ALSO shared: sending
        TO a shared agent must always get flagged for review (the whole
        point of the DESIGN.md §5 `is_shared` semantics — a shared agent
        spans ownership boundaries, so traffic reaching it is exactly the
        boundary-crossing traffic this scorer exists to catch), and a
        message must never be able to launder its way past that by routing
        through a sender who also happens to be shared, or by using a
        non-sensitive message type. There is no such thing as a
        "shared-to-shared bypass" here.
      - Once no OTHER participant is shared, the ``BARRIER_SENSITIVE_TYPES``
        filter applies as usual (non-sensitive → low risk, no further
        lookup), and for a sensitive type a shared SENDER (``is_shared``)
        bypasses the check (``detail={"bypass": "shared_sender"}``) —
        `asymmetric`-only, since `internal` admission never lets a shared
        initiator bypass its own pairwise check either.

      Because the shared-recipient check must inspect every other
      participant's ``is_shared`` flag regardless of the sender's own status
      OR the message type, this scorer now always resolves every other
      participant's ownership info for every `asymmetric` message — not just
      sensitive-type ones, and the shared-sender bypass no longer
      short-circuits before those lookups the way it used to (it only skips
      resolving their OWNER SETS into the superset comparison, once it's
      confirmed none of them are shared). A lookup failure, or an
      empty owner set for the sender or any other non-shared participant,
      raises ``RiskScoringInfraError`` rather than resolving the crossing
      question at all — an ownership-service outage must fail closed, not be
      silently treated as safe OR flood the approval queue (deferred to
      PR2) with unscorable holds.
    """

    async def score(self, ctx: MessageRiskContext) -> RiskVerdict:
        if ctx.conversation_type not in CONVERSATION_TYPES:
            raise RiskScoringInfraError("unknown_conversation_type")
        if ctx.conversation_type == "internal":
            return RiskVerdict(high_risk=False, reason=None, detail=None)
        if ctx.conversation_type == "open":
            if ctx.message_type not in BARRIER_SENSITIVE_TYPES:
                return RiskVerdict(high_risk=False, reason=None, detail=None)
            return RiskVerdict(high_risk=True, reason="boundary_crossing", detail=None)

        # asymmetric from here on: sequential, not asyncio.gather -- the
        # injected OwnershipClient shares this call's AsyncSession, which
        # SQLAlchemy's AsyncSession does not support across concurrent
        # coroutines (see service._owner_sets_for's own docstring).
        other_infos: list[dict[str, Any]] = []
        try:
            for agent_id in ctx.other_agent_ids:
                other_infos.append(await ctx.ownership_client.get_agent_owners(agent_id))
        except Exception as exc:
            raise RiskScoringInfraError("ownership_unverified") from exc

        # Shared-RECIPIENT check runs BEFORE the BARRIER_SENSITIVE_TYPES
        # filter below and regardless of message type (Argus round 1 fix,
        # TECH-5786 PR follow-up): the filter used to run first and return
        # low-risk for any non-`note` type with no ownership lookup at all,
        # so `availability_request`/`task_assign`/etc. crossed an ownership
        # boundary to a shared recipient with ZERO review -- directly
        # contradicting this PR's own stated intent ("shared-recipient
        # traffic ALWAYS forces boundary-crossing review") and DESIGN.md
        # §6's framing of exactly those types as where "judgment crosses
        # the boundary." Takes priority over the shared-sender bypass
        # below too, and over the ordinary owner-set comparison -- see the
        # class docstring. Deliberately does not touch `other_infos`'
        # "owners" sets at all: a shared agent's set is a roster, not the
        # point here.
        # Explicit `is True` (Argus round 2, TECH-5786 PR follow-up), not
        # bare truthiness: the current DB-backed OwnershipClient always
        # returns a real bool, but a future malformed or HTTP-backed
        # response with `None`/`0`/a missing key must not silently be
        # treated as "not shared" for a check this security-relevant.
        if any(info.get("is_shared") is True for info in other_infos):
            return RiskVerdict(
                high_risk=True,
                reason="boundary_crossing",
                detail={"reason": "shared_recipient"},
            )

        if ctx.message_type not in BARRIER_SENSITIVE_TYPES:
            return RiskVerdict(high_risk=False, reason=None, detail=None)

        try:
            sender_info = await ctx.ownership_client.get_agent_owners(ctx.sender_agent_id)
        except Exception as exc:
            raise RiskScoringInfraError("ownership_unverified") from exc

        if sender_info.get("is_shared") is True:
            return RiskVerdict(high_risk=False, reason=None, detail={"bypass": "shared_sender"})
        sender_owners = frozenset(sender_info.get("owners") or [])
        if not sender_owners:
            raise RiskScoringInfraError("empty_owner_set")

        other_owner_sets = [frozenset(info.get("owners") or []) for info in other_infos]
        if any(not owners for owners in other_owner_sets):
            raise RiskScoringInfraError("empty_owner_set")

        other_owners = frozenset().union(*other_owner_sets) if other_owner_sets else frozenset()
        if other_owners <= sender_owners:
            return RiskVerdict(high_risk=False, reason=None, detail=None)
        return RiskVerdict(high_risk=True, reason="boundary_crossing", detail=None)


RISK_SCORERS: dict[str, Callable[[], RiskScorer]] = {
    DEFAULT_RISK_SCORER: BoundaryCrossingScorer,
}


def resolve_plugin_name(env_var: str, registry: dict[str, Callable[[], Any]], name: str) -> Any:
    """Resolve a single plugin ``name`` to a constructed instance.

    ``name`` is looked up in ``registry`` by name; if it contains a ``:`` it
    is instead treated as an import path (``"pkg.module:factory"``),
    resolved via ``importlib`` and called with no arguments. Raises
    ``RuntimeError`` for an unknown name or a failed import — never returns
    a partially-broken plugin. ``env_var`` is only used to make the error
    message identify which knob was misconfigured.

    Factored out of ``resolve_plugin`` so other call sites needing the same
    registry-name-or-import-path resolution (e.g. ``auth.py``'s
    ``AGENT_TOKEN_VERIFIERS``, which resolves a comma-separated LIST of
    names rather than a single env-var value) share this implementation
    instead of duplicating it.

    ``name`` is expected to be operator-controlled deployment configuration
    (an environment variable's value) at every current call site, never
    request input or a database row -- this function itself does not
    enforce that, it trusts its callers, so a hypothetical future caller
    passing anything else would need its own justification for why that's
    still safe (see DESIGN.md's "Trust model for `pkg.module:factory` import
    paths").
    """
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


def resolve_plugin(env_var: str, registry: dict[str, Callable[[], Any]], default: str) -> Any:
    """Resolve ``env_var`` (defaulting to ``default``) to a constructed
    plugin instance.

    See ``resolve_plugin_name`` for the actual name-to-instance resolution
    rule (registry lookup or ``pkg.module:factory`` import path).
    """
    name = os.environ.get(env_var, default)
    return resolve_plugin_name(env_var, registry, name)


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
    """Fail fast at process start if any of the four seams in THIS MODULE
    don't resolve. ``OWNERSHIP_CLIENT`` is a fifth, board-wide seam that
    lives in ``service.py`` and is validated separately, by
    ``service.validate_ownership_client_configuration()``.

    Called from ``main._cli()`` beside the existing ``db.database_url()``
    fail-fast call — an unknown registry name, a bad import path, or (for
    ``APPROVAL_NOTIFIER=webhook``) a missing webhook env var must crash at
    boot, not lazily on the first high-risk message.
    """
    get_risk_scorer()
    get_auto_approver()
    get_approval_notifier()
    get_active_checker()


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


class ParticipantInfo(NamedTuple):
    """One other conversation participant, as seen by a ``HoldContext``.

    Same FIELD NAMES as ``service.get_hold_conversation_participants``'s
    HTTP response entries (``agent_id``/``display_name``/``role``/
    ``status``), kept here as a typed value rather than a dict since this
    travels in-process through the ``AutoApprover`` seam, not over HTTP --
    but NOT the same membership: that HTTP endpoint returns every
    active/invited participant including the sender/inviter, while this
    always EXCLUDES the sender/inviter (see ``HoldContext.participants``'s
    own docstring). Also note ``agent_id`` is a ``uuid.UUID`` here vs a
    ``str`` in the HTTP response, and that response has no ``sub`` field
    at all (``sub`` added here, TECH-5755, same reasoning as
    ``HoldContext.sender_sub``: an ``AutoApprover`` that needs to map a
    participant to an external system's own identity for that agent --
    e.g. confirming a message recipient is a specific Arc site's
    orchestrator bot -- has no DB session of its own to resolve
    ``agent_id`` -> ``sub`` another way).
    """

    agent_id: uuid.UUID
    display_name: str
    role: str
    status: str
    sub: str


class HoldContext(NamedTuple):
    """Everything an ``AutoApprover`` needs to review one hold.

    Unlike ``MessageRiskContext``, this DOES carry the payload — per the
    plan doc, the risk flag stays light and the expensive judgment belongs
    here.

    ``participants`` (TECH-5754) is the OTHER active/invited conversation
    participants (never includes ``sender_agent_id``/the inviter) — who
    this hold's message is actually addressed to, or who is already in the
    conversation being invited into. Additive: existing ``AutoApprover``
    implementations (``EscalateAllAutoApprover``) ignore it. Sorted by
    ``Agent.sub`` in codepoint order, consistently across every producer
    path (``service.py``'s SQL sites pin ``COLLATE "C"`` specifically so
    they can't drift from the ``start_conversation`` path's plain Python
    sort under a non-C Postgres locale) — an ``AutoApprover`` that builds a
    prompt from this list should preserve that order rather than
    re-sorting, for stable/cacheable prompts across repeated holds.

    ``sender_sub`` (TECH-5755) is the sender's own ``Agent.sub`` — the
    agent-jwt subject this agent registered with, board-wide-unique. For a
    real RH-internal bot this is the same string as its Arc ``bot_id``
    (``RHAgentVerifier`` normalizes an rh-auth service token's ``sub``
    straight through as the board identity at registration — see
    ``rh_comms_plugins.auth``, ``agent-comms-approvals``), which is what
    lets an ``AutoApprover`` map a hold back to an Arc site without a DB
    session of its own (this Protocol's only input is this NamedTuple).
    Additive, same as ``participants``: existing implementations ignore
    it. Threaded straight through from the already-loaded sender ``Agent``
    row at all three producer paths (``initiator``/``sender``/``inviter``
    in ``service.py`` — no extra query needed, same reasoning as
    ``participants``'s own docstring above).
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
    participants: list[ParticipantInfo]
    sender_sub: str


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
        # Omit owner_email (PII) from the log record -- the log-only path has
        # no authenticated audience the way the webhook path's HTTPS
        # destination does, so it shouldn't carry the same PII by default.
        fields = asdict(notification)
        del fields["owner_email"]
        _notify_log.info("approval_escalated", **fields)


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
        if not url.startswith("https://"):
            # Argus round-1 BLOCKING catch: the notification payload
            # carries owner_email/owner_sub (PII). Plain http:// leaks it
            # in cleartext; an unscheme-restricted URL is also an SSRF
            # vector (e.g. a cloud metadata address). Fail fast at
            # construction, same fail-closed posture as the missing-env
            # check above.
            raise RuntimeError(
                f"{APPROVAL_WEBHOOK_URL_ENV_VAR} must be an https:// URL, got {url!r}"
            )
        self._url = url
        self._secret = secret.encode("utf-8")

    async def notify_escalated(self, notification: ApprovalNotification) -> None:
        body = json.dumps(asdict(notification)).encode("utf-8")
        signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        # Pinned explicitly even though it matches httpx's own current
        # default (False) -- an SSRF-via-redirect vector if a future httpx
        # release ever flips that default. Do not change without
        # re-reading the class docstring's SSRF note above.
        async with httpx.AsyncClient(
            timeout=_WEBHOOK_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
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


# --- Seam 4 of this module (fifth board-wide seam; OWNERSHIP_CLIENT lives in
# service.py) -- the active checker (TECH-5703) ------------------------------
#
# Answers "is this board agent's owning registry still active?" for
# comms_list_agents/comms_lookup_agent_by_email filtering and for refusing
# new start_conversation/invite targets. Stateless, same shape as
# RiskScorer/AutoApprover/ApprovalNotifier above (not session-scoped like
# OwnershipClient) -- a real implementation talks to an external registry
# over HTTP and caches results in-process across requests, so it must
# outlive any single request's AsyncSession, exactly like WebhookNotifier
# above does for its own HTTP calls.
#
# The default, `always_active`, exactly preserves this board's behavior
# before this seam existed: no filtering, no invite refusal, until a
# deployment configures a real one via ACTIVE_CHECKER. This board has no
# registry of its own to consult by default -- a real, registry-backed
# implementation is expected to be supplied by whichever consumer deploys
# this board alongside an actual agent-ownership registry, via the same
# `pkg.module:factory` import-path mechanism AGENT_TOKEN_VERIFIERS/
# OWNERSHIP_CLIENT already use. Design note (TECH-5703 ticket): such an
# implementation should reuse whatever TTL/stale-serve cache its registry
# lookup already needs for auth-time resolution, not stand up a second,
# differently-tuned cache for this seam's slightly different question
# ("active or not" vs. "who owns this").

ACTIVE_CHECKER_ENV_VAR = "ACTIVE_CHECKER"
DEFAULT_ACTIVE_CHECKER = "always_active"


class ActiveChecker(Protocol):
    async def is_active(self, sub: str) -> bool:
        """True if ``sub`` is active, or unknown to whatever this checker
        consults (fail-open -- matches this board's own behavior before
        this seam existed, and matches an OAuth-registered/registry-less
        sub having no registry entry at all to report inactive). False
        ONLY for a sub this checker's backing registry has affirmatively
        reported inactive/retired. Must never raise for "don't know" --
        that case returns True, same as "no checker configured" does; a
        registry-availability failure should fail OPEN here (worst case: a
        retired agent stays briefly visible/reachable), not closed (which
        would make a registry outage silently hide or block healthy
        agents board-wide). ``service._is_active_safe`` enforces the
        fail-open contract at the call site too (catches, logs, returns
        True) as a backstop for an implementation that raises anyway --
        implementors should still treat "never raise" as the real contract,
        not rely on that backstop. ``comms_list_agents`` calls this
        concurrently across an entire page via ``asyncio.gather`` (up to
        ``limit``, capped at 200, calls in flight at once) -- a
        registry-backed implementation must be safe under that burst width
        (e.g. connection-pool-bounded), not written assuming one call at a
        time."""
        ...


class AlwaysActiveChecker:
    """``always_active`` -- the default. Every sub is active."""

    async def is_active(self, sub: str) -> bool:
        return True


ACTIVE_CHECKERS: dict[str, Callable[[], ActiveChecker]] = {
    DEFAULT_ACTIVE_CHECKER: AlwaysActiveChecker,
}

_active_checker: ActiveChecker | None = None


def get_active_checker() -> ActiveChecker:
    """Return the process-wide configured ``ActiveChecker`` (lazy
    singleton, mirrors ``get_risk_scorer``)."""
    global _active_checker
    if _active_checker is None:
        _active_checker = resolve_plugin(
            ACTIVE_CHECKER_ENV_VAR, ACTIVE_CHECKERS, DEFAULT_ACTIVE_CHECKER
        )
    return _active_checker


__all__ = [
    "ACTIVE_CHECKERS",
    "ACTIVE_CHECKER_ENV_VAR",
    "APPROVAL_NOTIFIERS",
    "APPROVAL_NOTIFIER_ENV_VAR",
    "APPROVAL_WEBHOOK_SECRET_ENV_VAR",
    "APPROVAL_WEBHOOK_URL_ENV_VAR",
    "AUTO_APPROVERS",
    "AUTO_APPROVER_ENV_VAR",
    "BARRIER_SENSITIVE_TYPES",
    "DEFAULT_ACTIVE_CHECKER",
    "DEFAULT_APPROVAL_NOTIFIER",
    "DEFAULT_AUTO_APPROVER",
    "DEFAULT_RISK_SCORER",
    "RISK_SCORERS",
    "RISK_SCORER_ENV_VAR",
    "ActiveChecker",
    "AlwaysActiveChecker",
    "ApprovalNotification",
    "ApprovalNotifier",
    "AutoApprover",
    "AutoDecision",
    "BoundaryCrossingScorer",
    "EscalateAllAutoApprover",
    "HoldContext",
    "LogOnlyNotifier",
    "MessageRiskContext",
    "ParticipantInfo",
    "RiskScorer",
    "RiskScoringInfraError",
    "RiskVerdict",
    "WebhookNotifier",
    "auto_approver_name",
    "get_active_checker",
    "get_approval_notifier",
    "get_auto_approver",
    "get_risk_scorer",
    "notifier_name",
    "resolve_plugin",
    "resolve_plugin_name",
    "risk_scorer_name",
    "validate_configuration",
]
