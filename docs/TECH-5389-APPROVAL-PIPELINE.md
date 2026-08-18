# TECH-5389 — Final Plan: Pluggable Risk Scoring + Approval Pipeline

Status: **final implementation plan** (2026-08-17). All owner decisions ratified; only the
items in §17 remain genuinely open. This document is the planning deliverable — no code
or existing files have been modified. DESIGN.md changes are *listed* in §13 as planned
edits, not applied.

Verified against the current worktree:

- Migration head: `136265b3f22d` (`drop_redundant_participants_index`).
- `boundary_safe` blast radius (grep-verified): `schemas.py`, `state_machine.py`,
  `service.py`, `providers/comms.py`, `main.py`, plus `tests/test_schemas.py` (20
  mentions), `tests/test_state_machine.py` (27), `tests/test_service.py` (44),
  `tests/test_comms_tools.py` (15).
- `mcp.custom_route` registers plain Starlette routes **outside** MultiAuth (per
  `/health`'s own docstring in `main.py`) — the new HTTP endpoints self-verify tokens.

## 0. Architecture in one paragraph

`post_message` runs every existing gate unchanged (membership, state, sender role,
payload schema, rate limits, the `accepted_types` capability gate — which stays a hard
denial: it is a capability question, not a risk question). Then the configured **risk
scorer** (seam 1) runs. Not high risk → the message posts exactly as today. High risk →
the message is written to an `approval_holds` row instead of `messages`, the
**auto-approver** (seam 2) runs (v1: escalates everything), the hold lands in
`pending_human`, and post-commit the **notifier** (seam 3) fires best-effort. The agent
gets a distinct "held for approval" response — not an error. The submitting agent's
human owner decides via a non-MCP HTTP endpoint (interactive-token-only + `owner_sub`
match); approval atomically posts the message **under its original type**; rejection
records the human's free-text *why*, which the agent retrieves via the new
`comms_get_hold_status` tool. A high-risk `start_conversation` opener no longer denies:
the conversation opens with a service-synthesized safe seq-1 marker and the real content
is held like any other post. There is no `approved_note` type, no `boundary_safe` flag,
and no `comms_submit_for_approval` tool.

## 1. One pluggability mechanism for all three seams

Fits this codebase's conventions (env-var config, fail-fast at startup, `Protocol`
seams like `OwnershipClient`, no plugin frameworks):

- **New module `plugins.py`** holding: the three `Protocol` interfaces, their
  verdict/context types, the in-tree default implementations, per-seam registries
  (`RISK_SCORERS: dict[str, Callable[[], RiskScorer]]`, likewise `AUTO_APPROVERS`,
  `APPROVAL_NOTIFIERS`), and one shared resolver.
- **Resolution rule** (shared `resolve_plugin(env_var, registry, default)`): the env
  var's value is looked up in the registry by name; if it contains a `:` it is treated
  as an import path (`"rh_comms_plugins.notify:SlackNotifier"`) resolved via
  `importlib`. Unknown name / failed import / wrong interface → `RuntimeError` **at
  startup** (`_cli()` calls `plugins.validate_configuration()` beside the existing
  fail-fast `database_url()` call), never lazily on the first post.
- Env vars + defaults (**confirmed**): `RISK_SCORER=boundary_v1`,
  `AUTO_APPROVER=escalate_all`, `APPROVAL_NOTIFIER=log_only`.
- **Injection follows the `ownership_client` precedent**: `providers/comms.py` resolves
  the configured singletons and passes them as parameters into
  `service.post_message(...)` / `service.start_conversation(...)` (service stays
  fastmcp-free); tests inject fakes directly, exactly as they fake `OwnershipClient`.
- Import hygiene, verified: `plugins.py` needs the `OwnershipClient` type from
  `service.py`, and `service.py` imports `plugins` — resolved with a
  `TYPE_CHECKING`-only import in `plugins.py` (both files already use
  `from __future__ import annotations`). No module moves. (Code-comment note:
  `OwnershipClient` is effectively a pre-existing fourth seam of the same shape.)

Tradeoff, stated: registry names give typo-safety for in-tree implementations; the
import-path fallback lets company code plug in from a private package on `PYTHONPATH`
without forking. Startup validation makes a bad import path loud instead of a 500 on
the first high-risk post.

## 2. Seam 1 — the risk scorer (replaces `boundary_safe`)

Interface (in `plugins.py`):

```python
class RiskVerdict(NamedTuple):
    high_risk: bool
    reason: str | None      # enum-coded, e.g. "boundary_crossing"; None if not high risk
    detail: dict | None     # audit-only extras (e.g. {"bypass": "shared_sender"})

class RiskScorer(Protocol):
    async def score(self, ctx: MessageRiskContext) -> RiskVerdict:
        """Raise on any infrastructure failure (ownership lookup error, empty
        owner set, unrecognized conversation type) — the service maps every
        exception to a HARD DENIAL (denied.risk_unscored), never a hold and
        never a silent post. Return a verdict only when scoring succeeded."""
```

`MessageRiskContext` (frozen dataclass, primitives + the injected `OwnershipClient`):
`conversation_type`, `conversation_id | None`, `sender_agent_id`, `other_agent_ids`,
`message_type`, `schema_version`, `ownership_client`. No payload in v1's context (the
v1 rule is type/topology-based); adding `payload` later is additive.

**v1 implementation `BoundaryCrossingScorer` ("boundary_v1")** — the existing
info-barrier logic, relocated verbatim in substance:

- Module-level `BARRIER_SENSITIVE_TYPES: frozenset[str] = frozenset({"note"})` — the
  former `boundary_safe=False` set, now scorer-private policy data.
- Non-sensitive type → `high_risk=False` immediately (no ownership lookup — preserves
  today's cheap common path). `conversation_opened` (§6) is never sensitive.
- Sensitive type: `internal` → not high risk; `open` → high risk
  (`boundary_crossing`); `asymmetric` → ownership lookups (sequential — same
  shared-`AsyncSession` constraint documented in `service._owner_sets_for`),
  shared-sender bypass preserved (`high_risk=False`,
  `detail={"bypass": "shared_sender"}` so the service emits a bypass-observability
  audit event — renamed to the scorer-neutral `risk.shared_sender_bypass`, replacing
  `agent.boundary_check_bypassed_shared`; backwards compatibility deliberately not
  kept, ratified), otherwise high risk iff any other active-or-invited participant's owner
  falls outside the sender's owner set (the current `other_owners <= sender_owners`
  rule, moved out of `state_machine.py`).
- **Infrastructure failure = hard deny (ratified, decision 3)**: ownership-lookup
  exceptions, empty owner sets, and unrecognized `conversation_type` rows all
  **raise**; the service wrapper catches and denies via the uniform
  `AccessDeniedError`, audited `denied.risk_unscored` (detail carries the cause:
  `ownership_unverified` / `empty_owner_set` / `unknown_conversation_type`). Rationale
  (owner): an ownership-service outage must not flood the human approval queue with
  unscorable holds. Genuine "crossing detected" verdicts divert as designed. This
  preserves the pre-existing fail-closed *denial* posture for infrastructure failures;
  only real verdicts changed from deny to divert.

**`boundary_safe` removal plan** (all sites verified):

- `schemas.py`: drop the `boundary_safe` field — and since the `MessageSchema`
  NamedTuple then wraps a single field, flatten `MESSAGE_SCHEMAS` to
  `dict[tuple[str, int], type[BaseModel]]` and delete `MessageSchema` +
  `is_boundary_safe()` (single-use abstraction). `get_schema`/`validate_payload` call
  sites adjust trivially. `NoteV1`'s docstring rewritten (no longer "pre-quarantine
  provisional").
- `state_machine.py`: delete `is_boundary_crossing_safe` (+ `__all__` entry); its
  predicate logic lives inside `BoundaryCrossingScorer`. The other two functions are
  untouched.
- `service.py`: `_enforce_boundary_crossing` and the boundary half of
  `_check_boundary_crossing` are deleted; replaced by one `_score_message_risk(...)`
  helper that builds the context (reusing the existing participants-join for
  `other_agent_ids` — that query survives because the capability gate still needs it),
  invokes the injected scorer, emits the shared-bypass audit when the verdict says so,
  and maps scorer exceptions to `denied.risk_unscored`. The per-message
  `denied.boundary_crossing` denial path is retired. Module docstring / audit-contract
  text updated. The Axis 1 admission checks (`_authorize_conversation_open`, invite
  owner-freeze) are **untouched** and keep their hard `denied.ownership_unverified`
  denials — only the per-message Axis 2 check is subsumed.
- `providers/comms.py` `post_message` docstring (the `note` bullet) and `main.py`
  `instructions` string rewritten: `note` is no longer "never allowed under open" —
  it is *held for human approval* when it would cross a boundary.

## 3. Seam 2 — the auto-approver

Interface:

```python
class AutoDecision(NamedTuple):
    cleared: bool           # True → post now, no human needed
    detail: dict | None

class AutoApprover(Protocol):
    async def review(self, ctx: HoldContext) -> AutoDecision: ...
```

`HoldContext`: hold id, conversation id/type, sender agent id + owner_sub,
message_type, schema_version, payload, risk reason. (Unlike the scorer, the
auto-approver *does* get the payload — per the owner, the risk flag stays light and
the expensive judgment belongs here.)

**v1 implementation `EscalateAllAutoApprover` ("escalate_all")**: returns
`cleared=False` unconditionally. Invoked inline, for real, in the `post_message`
transaction — the seam is exercised on every high-risk post, not dead code.

**Sync-now / async-later accommodation** (no async infra built now):

- The hold status vocabulary contains the pre-human stage from day one:
  `pending_auto` → `pending_human`. In v1 the inline no-op means no committed row is
  ever *observed* as `pending_auto` (created and transitioned within one transaction),
  but the state exists in the CHECK constraint and lifecycle now.
- "Approve and post atomically" is one reusable service function
  (`_approve_hold_and_post`, shared by the human decide path and the auto-cleared
  path), parameterized by actor attribution (`decided_by_sub` = human sub, or
  `system:auto_approver/<name>`).
- A future async auto-approver therefore needs only: commit the hold at
  `pending_auto`, return the held response, and have a worker call `review()` then
  either `_approve_hold_and_post` or flip to `pending_human` + fire the notifier. No
  schema change, no response-shape change, no new endpoint. The decide endpoint treats
  `pending_auto` as not-yet-actionable (409 `{"error": "awaiting_auto_review"}`) —
  unreachable in v1 but specified now.
- If a (test-injected or future) auto-approver clears inline: the message inserts in
  the same transaction under the already-held conversation lock; the agent gets the
  normal posted response plus `{"auto_approved": true, "hold_id": ...}`.

## 4. Seam 3 — the approval-request notifier

Same Protocol + registry + env-var mechanism as §1.

```python
@dataclass(frozen=True)
class ApprovalNotification:
    hold_id: str
    conversation_id: str
    conversation_type: str
    sender_agent_id: str
    sender_display_name: str
    owner_sub: str            # routing key: whose approval is needed
    owner_email: str          # human-friendly routing (Slack lookup, email)
    message_type: str
    risk_reason: str
    expires_at: str           # ISO 8601
    created_at: str

class ApprovalNotifier(Protocol):
    async def notify_escalated(self, notification: ApprovalNotification) -> None: ...
```

**Payload excludes the held text — pointer, not content.** The notifier is the one
place approval data leaves this service's trust boundary (webhook endpoints, Slack),
with no membership check and no audit of the receiving side. Everything needed to
*route and render* an approval request is in the metadata above; the human fetches the
actual text through the authenticated, owner-matched `GET /approvals/pending` / decide
surface — the same posture DESIGN.md already takes for raw text. A company notifier
that truly wants inline text can fetch it itself with an interactive credential;
that's its risk decision, made outside the OSS trust boundary.

**Shipped implementations (confirmed):**

- `LogOnlyNotifier` ("log_only") — **the default**: structured log line (structlog
  event `approval_escalated`, no payload text). Default because it is safe in a bare
  deployment: zero required config, no accidental egress to a half-configured URL.
- `WebhookNotifier` ("webhook") — in-tree, selectable: `POST` of the
  `ApprovalNotification` JSON to `APPROVAL_WEBHOOK_URL`, HMAC-SHA256 signature header
  (`X-Approval-Signature`) keyed by `APPROVAL_WEBHOOK_SECRET` (both required when this
  notifier is selected — validated by the same startup fail-fast pass), ~5s timeout,
  no retries in v1.
- Company-specific (e.g. RH: Slack DM to the owner + an aggregation UI) lives
  **outside this repo**: `APPROVAL_NOTIFIER=rh_comms_plugins.notify:SlackNotifier` on
  a private package in `PYTHONPATH`. This absorbs the earlier "webhook on hold
  creation" contract ask as a first-class seam.

**When it fires:** on the transition into `pending_human` only. Expiry/reminder hooks
are deliberately out of v1: hold expiry is lazy (no scheduler/sweep exists in this
codebase — the TECH-5378 gap), so there is no process moment to fire a reminder from.
Adding `notify_expired` later is additive.

**Failure semantics:** invoked **post-commit**, best-effort, wrapped in
`try/except Exception`; on failure: `logger.warning(..., exc_info=True)` + an
`approval.notify_failed` audit row (fresh short transaction — the main commit already
succeeded) with detail `{hold_id, notifier, error_type}`. Success is a structlog
event, not an audit row (neither mutation, denial, nor bypass). A notifier failure
never fails, rolls back, or delays the agent's held response; **`GET
/approvals/pending` is the source of truth**, notification is an accelerant.

## 5. Data model

### `approval_holds` (new table)

Follows `models.py` conventions (UUID PK via `gen_random_uuid()`, TEXT over VARCHAR,
TIMESTAMPTZ, CHECK constraints for closed vocabularies, `idx_{table}_{columns}` names,
index parity between model declaration and migration):

```
approval_holds
  id                  UUID PK
  conversation_id     UUID NOT NULL FK conversations.id
  sender_agent_id     UUID NOT NULL FK agents.id
  message_type        TEXT NOT NULL      -- the ORIGINAL type (e.g. 'note'); posts as itself on approval
  schema_version      INTEGER NOT NULL   -- the conversation's pinned version at hold time
  payload             JSONB NOT NULL     -- validated, normalized dump (insert-ready)
  risk_reason         TEXT NOT NULL      -- scorer verdict reason ('boundary_crossing', ...)
  risk_scorer         TEXT NOT NULL      -- which scorer produced the verdict (registry name / import path)
  status              TEXT NOT NULL CHECK IN
                        ('pending_auto','pending_human','auto_approved','approved','rejected','expired')
  auto_approver       TEXT NULL          -- which implementation reviewed it
  auto_decision       TEXT NULL CHECK IN ('cleared','escalated')
  auto_decided_at     TIMESTAMPTZ NULL
  decided_by_sub      TEXT NULL          -- human approver's verified sub
  decided_at          TIMESTAMPTZ NULL
  decision_reason     TEXT NULL          -- optional free-text why from the human (both directions; see §8)
  message_id          UUID NULL FK messages.id, UNIQUE  -- the resulting post (either approval kind)
  expires_at          TIMESTAMPTZ NOT NULL              -- created + APPROVAL_HOLD_TTL, lazy expiry
  created_at / updated_at

  idx_approval_holds_sender_agent_id_status_created_at   -- hold rate limit + list-pending + get_hold_status
  idx_approval_holds_conversation_id
```

- **No `high_risk` boolean**: a hold exists *only because* the verdict was high-risk;
  `risk_reason`/`risk_scorer` carry the verdict.
- No `owner_sub` snapshot: `agents.owner_sub` is frozen at first registration
  (verified in `service.register_agent`), so the decide-time join reads the identical
  value a snapshot would have captured.
- `decision_reason` free text is acceptable here — see the trust argument in §8.
- Mutable table (status flips), hence `updated_at` — the append-only invariant on
  `messages`/`audit_log` is untouched.

### `messages` — no new column (recommended, unchanged)

Provenance is fully recoverable: `approval_holds.message_id` is a UNIQUE FK (both
directions queryable) and the approval-time `message.post` audit row carries `hold_id`
in detail. Under the new rules a `note` in an `open` conversation *implies* approval —
there is no other way for one to exist there. Reader-visible provenance
(`messages.approval_hold_id`) remains an open question (§17), trivially additive later.

### Constants (confirmed)

`APPROVAL_HOLD_TTL = timedelta(days=7)`; `MAX_APPROVAL_HOLDS_PER_HOUR = 10` (counted
from `approval_holds.created_at` per sender — table-count pattern, no Redis).

## 6. Seq-1 high-risk opener: auto-post a safe system opener (ratified, decision 1)

When `start_conversation`'s opening message scores high-risk, the conversation is
**created anyway**, with a service-synthesized safe marker as its seq-1 message; the
caller's actual content is diverted into a hold exactly like any other post. No denial.

**Opener type — new minimal system type `conversation_opened`.** The existing
vocabulary was checked and nothing fits: `availability_request`/`task_assign` need
real scheduling parameters the service can't honestly synthesize;
`needs_clarification` requires `about_seq >= 1` referencing a *prior* message (invalid
at seq 1); `task_report` requires a status about work that doesn't exist; `note` is
free text — the sensitive class itself. So:

- `ConversationOpenedV1(_StrictModel)`:
  `type: Literal["conversation_opened"] = "conversation_opened"`,
  `reason: Literal["pending_approval"] = "pending_approval"`. Fully enum-coded, no
  free text, and deliberately **content-blind**: it reveals that the conversation was
  opened with something pending approval, and nothing about what. (Invited targets who
  accept will see this marker before any approval lands — they learn a hold exists,
  not its content. Judged acceptable and arguably useful; noted, not hidden.)
- Registered in `MESSAGE_SCHEMAS` + the `MessageType` Literal (the import-time drift
  guard enforces both move together). `resulting_conversation_state` → `None`;
  `is_message_legal` picks it up automatically (active-only). Not in
  `BARRIER_SENSITIVE_TYPES`, so it can never itself score high-risk.
- **`sender_id` = the initiating agent** (the board has no agent row of its own;
  it is the initiator's conversation and their pending content). The audit row and
  the message-post audit detail mark it `{"system_synthesized": true, "hold_id": ...}`
  so the trail distinguishes it from an agent-authored payload.
- **Sender-role map**: not in `_MESSAGE_TYPE_SENDER_ROLES` — but as the seq-1 message
  it is only ever synthesized for the initiator, who is `role=owner` by construction.
  No restriction needed.

**Capability-gate interaction (decided: system type is exempt).** Targets will not
have declared `conversation_opened` (the `e1db7c2e6b70` grandfather backfill is
explicitly one-time; new types are never retroactively included), so requiring
acceptance would break the flow for essentially every agent. Instead:

- A `_SYSTEM_MESSAGE_TYPES = frozenset({"conversation_opened"})` set in `service.py`
  is **exempt** from `_enforce_message_type_accepted`. Justification in the gate's own
  terms: the capability gate answers "does this agent's implementation know what to do
  with this type" — a board-synthesized marker requires no handling capability beyond
  ignoring it, and no agent authored it.
- Symmetrically, **agents may not post it directly**: a caller-supplied
  `message_type == "conversation_opened"` in `post_message`/`start_conversation` is
  denied (uniform `AccessDeniedError`, audited `denied.system_message_type`). Without
  this, an agent could forge the board's "opened pending approval" marker. (This is a
  deliberately tiny resurrection of the earlier plan's mint-gate mechanic, scoped to
  one system marker type rather than a content-carrying type.)
- The **held content's own type still passes the normal capability gate**: in the
  diverted-opener flow, `start_conversation` runs `_enforce_message_type_accepted`
  against the named targets for the ORIGINAL message type (hard denial, exactly
  today's semantics — a target that can't handle `note` still fails conversation
  creation) *before* the scorer runs. So by approval time every participant admitted
  at creation had declared the held type; the approve-time re-check (§9) covers
  later-added participants.

**Flow in `start_conversation`** (order preserved from today up through the capability
gate): admission, negotiation, rate limits, payload validation, sender-role check,
capability gate on the original type → scorer on the original type. Not high risk →
identical to today. High risk → hold rate limit check; create conversation +
participants; synthesize + insert the `conversation_opened` seq-1 message at the
negotiated schema version (**preserving the pinned-schema-version invariant** —
`_conversation_pinned_schema_version` and `invite`'s re-check keep working
unmodified); create the hold (referencing the real payload/type); run the
auto-approver inline (cleared → the real message posts as seq 2 in the same
transaction; v1: escalate); commit; notifier post-commit. The tool response is the
normal conversation-created shape **plus** the held-for-approval block (§7), so the
initiator knows the conversation exists but the content does not yet.

**Known wrinkles (resolved but worth eyes):**

1. A rejected/expired hold leaves a conversation whose only message is the marker.
   Acceptable: participants can post normally, leave, or let the TTL expire it; the
   sender learns the outcome via `comms_get_hold_status` and can decide what to do
   with the shell. No cleanup mechanism in v1.
2. The marker counts toward the initiator's global sender rate limit (it is a real
   seq-1 message on the existing enforcement path). Accepted — one message per
   diverted open, bounded further by `MAX_APPROVAL_HOLDS_PER_HOUR`.
3. `conversation_opened` appears in `MESSAGE_TYPES` (derived from the registry), so
   agents *can* list it in `accepted_types` at registration. Harmless — the gate
   exemption makes the declaration inert.

## 7. `post_message` flow and response shapes

Service-layer sequence in `post_message`, after every existing check up to and
including the capability gate (all unchanged):

1. `_score_message_risk(...)` — build context, run injected scorer. Scorer raised →
   hard deny `denied.risk_unscored` (§2).
2. `high_risk=False` → insert message exactly as today. Zero change to the happy path
   or its response shape.
3. `high_risk=True` →
   - Hold rate limit (`denied.rate_limited`, `limit="approval_holds_per_hour"` — rate
     limiting was never part of the divert-don't-deny reversal).
   - Insert hold (`pending_auto`), audit `approval.hold`.
   - Auto-approver inline. Cleared → `_approve_hold_and_post` in the same transaction
     (conversation lock already held via
     `_load_participant_for_transition(for_update=True)`, seq assigned race-safe),
     hold → `auto_approved` + `message_id`, audits `approval.auto_approve` +
     `message.post`; response = normal posted shape + `{"auto_approved": true,
     "hold_id": ...}`. Not cleared (v1 always) → hold → `pending_human`, audit
     `approval.escalate`, commit.
   - Post-commit: notifier fires (§4 semantics).
4. Service returns `Message | ApprovalHold`; the tools layer branches on the type.

Tool response for a held post — distinct shape, not an error (explicit owner decision
reversing the earlier denial posture):

```json
{
  "held_for_approval": true,
  "hold_id": "…",
  "conversation_id": "…",
  "status": "pending_human",
  "risk_reason": "boundary_crossing",
  "expires_at": "…",
  "created_at": "…"
}
```

The normal posted shape is unchanged (backward compatible); tool docstrings document
both shapes and instruct agents to check `held_for_approval`, keep the `hold_id`, and
poll `comms_get_hold_status`. Documented consequence: a held message has no `seq` and
is invisible to all participants (including the sender via `comms_get_conversation`)
unless and until approved.

## 8. Outcome feedback to the agent (ratified, decision 2)

**(a) `comms_get_hold_status` — CONFIRMED IN, PR 2.** New read-only MCP tool
(`providers/comms.py`), enrolled in `TOOL_SCOPES` as
`"comms_get_hold_status": "comms:read"` in the same PR (fail-closed registry;
`TestScopeRegistryParity` enforces enrollment mechanically).

- `comms_get_hold_status(hold_id: str, agent_key: str | None = None)`.
- **Sender-only**: the caller's resolved agent must equal the hold's
  `sender_agent_id`. Unknown `hold_id` and someone-else's hold raise the identical
  uniform `AccessDeniedError` (audit distinguishes `denied.unknown_hold` /
  `denied.hold_not_sender`).
- Applies lazy TTL expiry on touch (same `_maybe_expire` pattern; audited
  `approval.expire`).
- Returns: `{hold_id, conversation_id, status, risk_reason, created_at, expires_at,
  decided_at?, decision_reason?, message_seq?, message_id?}` — `decision_reason` on
  rejected (and approved, if the human left a note); `message_seq`/`message_id` on
  approved/auto_approved so the agent can correlate with `get_conversation`.

**(b) Human's free-text why.** The decide endpoint's body becomes
`{"decision": "approve" | "reject", "reason": "<optional free text, max 2000 chars>"}`.
Stored in `approval_holds.decision_reason`, surfaced only via `comms_get_hold_status`
(sender-only) and `GET /approvals/pending`-adjacent detail reads (owner-only).
**Approve also accepts the optional reason** — symmetric, near-zero cost, and "here's
why I approved this" is as useful a learning signal as a rejection why.

**Trust argument for free text here (explicit, per owner):** the board's no-free-text
posture exists to keep unstructured text from crossing trust boundaries into other
owners' agents. `decision_reason` flows in exactly one direction: from a human to the
submitting agent — an agent that human *owns*. Same trust domain, no barrier crossed,
so the enum-only stance that governs inter-agent payloads does not apply. It is
length-capped and never enters any other participant's read surface.

**Polling is sufficient for v1 (decided).** Hold decisions do not surface in
`comms_inbox` or other read surfaces: inbox is built on `max(seq) > last_read_seq`
over `messages`, and holds have no seq — surfacing them would mean either fake
message rows (violating the hold model) or a parallel unread-tracking mechanism for a
second table (real schema/query work). The agent already holds the `hold_id` from the
held response at the moment it cares most; polling `comms_get_hold_status` is the
minimal correct thing. An inbox integration can come later without breaking anything.

## 9. The decide endpoint (non-MCP HTTP) — carried over; deltas noted

Everything structural from the prior revision survives: `POST
/approvals/{hold_id}/decide` via `mcp.custom_route` (handler self-verifies the bearer
against the shared MultiAuth provider instance — exact verify-method name pinned down
against the installed FastMCP version at implementation time); **hard interactive-token
gate with NO agent-scope escape hatch** (`is_interactive_token(token)` required;
agent-jwt rejected outright regardless of any scope including `comms:admin` —
deliberately unlike the `is_interactive_token(token) or "comms:admin" in
scopes_for_token(token)` pattern in `providers/comms.py`; this structural gate is what
makes agent self-approval impossible); approver's verified sub
(`identity.try_resolve_email`) must equal the sender agent's `owner_sub`;
**uniform 404** for unknown-hold and not-your-hold (audit distinguishes
`denied.unknown_hold` / `denied.hold_not_owner`); 409 already-decided
(`denied.hold_wrong_state.<status>`); 410 lazily-expired (`approval.expire`); 422 bad
body; no endpoint rate limiting (interactive-human-only by construction).

Deltas for the ratified design:

- Body now carries the optional `reason` (§8b); stored on the hold in the same
  transaction as the decision.
- Human decide acts only on `pending_human` (`pending_auto` → 409
  `awaiting_auto_review`; unreachable in v1, specified for the async future).
- **Approve is one atomic transaction**: conversation `SELECT ... FOR UPDATE` +
  `_maybe_expire`; if the conversation is no longer `active` →
  `InvalidConversationStateError` (audited `denied.bad_state`), hold stays
  `pending_human` (the human can still reject with a reason) → 409 distinct body.
  Re-run the `accepted_types` capability gate against current active participants.
  Assign `next_seq` under the lock; insert `Message` with `sender_id` = the sender
  agent, **original type**, hold's pinned `schema_version`, hold's stored payload
  verbatim; flip hold (`approved`, `decided_by_sub`, `decided_at`,
  `decision_reason?`, `message_id`); audit `approval.approve` + `message.post`
  (detail gains `hold_id`); single commit. **The risk scorer is deliberately NOT
  re-run at approval — the human decision IS the override.**
- Reject: flip + reason + audit `approval.reject`; **no `messages` row is ever
  created**; commit.

## 10. `GET /approvals/pending` — in scope (confirmed)

Same non-MCP surface and identical auth gate as decide (interactive-only +
owner-match). Returns full hold detail **including the held text** for holds whose
sender agent's `owner_sub` == the caller's verified sub, `pending_human` only, ordered
`created_at` ASC, simple `limit` + `has_more`. Load-bearing twice: the notifier
deliberately carries a pointer (this is where the human reads the text), and it is the
aggregation read-path any company approval UI (e.g. RH's Slack + list view) consumes.

## 11. Audit actions

| Action | Actor (`actor_sub`) | When |
|---|---|---|
| `approval.hold` | sender agent's sub | hold created (detail: `hold_id`, `risk_reason`, `risk_scorer`, `message_type`) |
| `approval.escalate` | sender agent's sub | auto stage declined to clear → `pending_human` (detail: `auto_approver`) |
| `approval.auto_approve` | `system:auto_approver/<name>` | auto stage cleared (paired with `message.post`) |
| `approval.approve` / `approval.reject` | human approver's verified sub | human decision (detail: `hold_id`, `has_reason`; approve pairs with `message.post`) |
| `approval.expire` | whoever's touch triggered lazy expiry | pending hold past TTL (decide, get_hold_status, or list touch) |
| `approval.notify_failed` | sender agent's sub (the request whose post-commit hook failed) | notifier raised (detail: notifier name, error type) |
| `message.post` (existing) | approver / system actor / initiator | approval-time insert (detail gains `hold_id`); the synthesized opener's row carries `system_synthesized: true` |
| `denied.risk_unscored` | sender's sub | scorer infrastructure failure — hard deny (detail: cause) |
| `denied.rate_limited` (`approval_holds_per_hour`) | sender's sub | hold spam cap |
| `denied.system_message_type` | sender's sub | agent tried to post `conversation_opened` directly |
| `denied.approval_requires_interactive` | endpoint caller identity | agent-jwt token hit a decide/list endpoint |
| `denied.unknown_hold` / `denied.hold_not_owner` / `denied.hold_not_sender` | caller | uniform-denial pairs (endpoint 404s; tool uniform error) |
| `denied.hold_wrong_state.<status>` | approver | already-decided hold |
| `risk.shared_sender_bypass` (renames `agent.boundary_check_bypassed_shared`; no back-compat, ratified) | sender | shared-sender bypass verdict from the v1 scorer |

Retired: per-message `denied.boundary_crossing`, per-message
`denied.ownership_unverified` and `denied.unknown_conversation_type` (both folded into
`denied.risk_unscored`'s detail). Axis 1's `denied.ownership_unverified`
(conversation open / invite) is unchanged. `service.py`'s audit-contract docstring
updated accordingly.

## 12. Migration

Still **one additive Alembic revision**, `down_revision = "136265b3f22d"`: create
`approval_holds` with the §5 columns **including `decision_reason`**, both CHECKs,
both indexes, UNIQUE on `message_id`, `if_not_exists`/`if_exists` guards per repo
style (`a1b2c3d4e5f6` precedent). `boundary_safe` never existed in the DB — its
removal is code-only. Purely additive → normal rolling deploy is safe (deployment
docstring says so). Offline-SQL assertions added to `test_migrations_offline.py`.

## 13. DESIGN.md updates (planned edits — not applied by this deliverable)

- **§4**: note the approval pipeline as a per-message control plane and the three
  configured seams; permissions table gains a note that high-risk posting is gated by
  human/auto approval, not scopes.
- **§5**: six tables; `approval_holds` block (mutable, unlike `messages`/`audit_log`).
- **§6**: drop the `boundary_safe` column from the type table; add
  `conversation_opened` (system-synthesized, agent-post denied); `note`'s row
  rewritten (held-for-approval when crossing; can now legitimately appear in `open`
  conversations once human-approved).
- **§7**: `comms_post_message`/`comms_start_conversation` rows note the two response
  shapes; add `comms_get_hold_status | comms:read`; note the deliberate absence of
  approve/reject/list MCP tools (non-MCP surface).
- **§8 invariants**: rewrite invariants 2–3 — "high-risk content crosses an ownership
  boundary only via an explicitly-approved hold (human, or a configured
  auto-approver), atomically audited"; add the interactive-token + owner_sub decide
  invariant; state that scorer infrastructure failure hard-denies
  (`denied.risk_unscored`) — never fails open, never floods the approval queue.
- **§9 Axis 2**: retitled "Axis 2: per-message risk scoring (pluggable)"; Axis 1
  admission untouched; document the three seams, the lifecycle
  (`pending_auto → pending_human → approved|rejected|expired`,
  `pending_auto → auto_approved`), v1 implementations, pointer-not-text notifier
  posture, the seq-1 auto-opener design (§6 above), the capability-gate exemption for
  system types, "the scorer is not re-run at approval," and the `decision_reason`
  trust argument (§8).
- **§10**: free-text bullet updates from "deferred behind quarantine" to "shipped as
  human-approval diversion (TECH-5389); sandboxed tool-less extraction remains a
  possible future scorer/auto-approver"; note the explicit divergence: approved text
  *does* enter counterpart agents' contexts — human judgment is the injection control.
- New configuration subsection: `RISK_SCORER` / `AUTO_APPROVER` / `APPROVAL_NOTIFIER`,
  import-path plugins, startup fail-fast, webhook env vars, and the `owner_sub`
  accepted-risk statement (§15).
- `main.py` `instructions` string and affected tool docstrings updated in the same PR.

## 14. Test plan

| File | Coverage |
|---|---|
| **New `tests/test_plugins.py`** | Scorer verdict matrix (type × conversation-type × ownership topology — absorbing `is_boundary_crossing_safe`'s cases from `test_state_machine.py`); shared-sender bypass verdict; scorer RAISES on lookup error / empty owners / unknown conversation type; registry + import-path resolution; startup fail-fast (unknown name, bad path, missing webhook env); `EscalateAllAutoApprover`; notifier payload excludes text; `LogOnlyNotifier`; `WebhookNotifier` HMAC + timeout |
| `tests/test_state_machine.py` | Remove the 27 boundary mentions (moved); `conversation_opened` legal only in `active`, no state transition |
| `tests/test_schemas.py` | Remove `boundary_safe`/`MessageSchema`/`is_boundary_safe` tests (20 mentions); `ConversationOpenedV1` validation; drift guard covers the new Literal entry |
| `tests/test_service.py` | Diversion: high-risk post creates hold + **no** `messages` row + held return; non-high-risk path byte-for-byte unchanged; scorer exception → `denied.risk_unscored` hard denial (no hold row); inline auto-clear (fake approver) posts atomically; hold rate limit; notifier-failure isolation (`approval.notify_failed`, response still held); **seq-1 divert**: conversation created with `conversation_opened` seq 1 at the negotiated version, `invite`'s pin re-check still works, held content posts as seq 2 on approval, capability gate still hard-denies targets not accepting the ORIGINAL type, direct agent post of `conversation_opened` denied; decide flows (approve atomicity incl. forced-failure rollback, seq race vs. concurrent post, reject-no-message + `decision_reason` stored, owner mismatch ≡ unknown hold, already-decided, expired, conversation-went-terminal, capability re-check); `get_hold_status` service logic (sender-only uniform denial, lazy expiry, reason/seq surfacing); full audit-row assertions per §11; the 44 existing boundary-denial tests rewritten to expect holds (or `denied.risk_unscored` where the cause was infrastructure) |
| `tests/test_comms_tools.py` | End-to-end: `note` into an `open` conversation returns the held shape (rewrites the 15 boundary mentions); approved hold's message then visible via `comms_get_conversation` with original type; `comms_get_hold_status` happy path + rejected-with-reason + uniform denial; seq-1 divert response shape |
| `tests/test_db_models.py` | `approval_holds` round-trip, both CHECKs, FKs, `message_id` uniqueness, `decision_reason` nullable |
| `tests/test_migrations_offline.py` | New revision DDL assertions |
| **New `tests/test_approval_endpoint.py`** | 401/403 (incl. **agent-jwt + `comms:admin` → 403** — the load-bearing structural test), uniform 404 pair, decide flows over HTTP incl. `reason` persistence, `pending_human`-only, list-pending owner filtering + includes text, audit attribution to the approver's sub. Own file: needs the Postgres fixture block (mirrored from `test_comms_tools.py`), which `test_main.py` deliberately lacks |
| `tests/test_main.py` | `TestScopeRegistryParity` covers `comms_get_hold_status` enrollment mechanically |
| `tests/test_scopes.py` | `comms_get_hold_status` → `comms:read` mapping |

## 15. `owner_sub` provenance — accepted risk (carried verbatim)

- Okta-registered agents: `owner_sub` = verified email-resolved identity. Sound.
- agent-jwt-registered agents: `owner_sub` = the **caller-supplied, unverified**
  `owner_sub` extra claim (protected only by possession of `AGENT_JWT_SECRET` at mint
  time), frozen at first registration so it cannot be re-registered onto a victim
  later. **Accepted risk per ticket owner — documented, not open.**
- Finding 1 (now more important, since *every* high-risk post depends on the match):
  the no-claim fallback sets `owner_sub` to the agent-jwt `sub`, which
  `identity.validate_sub_shape` forbids from containing `@` — such agents are
  **permanently un-approvable** by any email-identified Okta human; their high-risk
  posts will hold and then expire. The platform must mint `owner_sub` = the owner's
  Okta-resolved email.
- Finding 2: the decide/list/status match is exact-string. Exact match in v1 — a case
  mismatch yields an un-approvable hold, not a security hole.

## 16. PR sequencing

**PR 1 — behavior-preserving seam refactor.** `plugins.py` (scorer
Protocol/registry/resolver + `BoundaryCrossingScorer`), remove
`boundary_safe`/`is_boundary_safe`/`is_boundary_crossing_safe`, rewire `service.py` to
the scorer — but map `high_risk=True` to the **existing denial** for now, and scorer
exceptions to the existing `denied.ownership_unverified`-equivalent denial. Tests:
`test_plugins.py` scorer matrix; every existing test stays green with zero behavior
change. Verify: full suite.

**PR 2 — the pipeline.** `approval_holds` model + migration (incl.
`decision_reason`); auto-approver + notifier seams (defaults + webhook impl);
diversion flow + held response shape + hold rate limit; `denied.risk_unscored`
finalized; seq-1 auto-opener (`conversation_opened` type + system-type gate/exemption);
`comms_get_hold_status` + `TOOL_SCOPES` entry; decide + list-pending endpoints;
audit actions; DESIGN.md edits; all remaining tests. Verify: suite +
`alembic upgrade head --sql` review.

The split is deliberate: PR 1 is a pure refactor reviewable for equivalence; PR 2 is
where behavior changes, so the reversal-of-denial-posture diff is isolated and
auditable.

## 17. Final ratified decisions (formerly open questions)

All three closed by the ticket owner (2026-08-17):

1. **Webhook notifier retry policy** — none in v1; revisit with a real consumer.
2. **Audit-name continuity** — not needed; `agent.boundary_check_bypassed_shared` is
   renamed to the scorer-neutral `risk.shared_sender_bypass` (see §2/§11).
3. **Reader-visible provenance** — not built in v1 (no `messages.approval_hold_id`
   column, no `via_approval` flag); provenance stays recoverable via
   `approval_holds.message_id` and audit detail. Trivially additive later if wanted.
