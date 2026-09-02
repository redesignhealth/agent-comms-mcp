# TECH-5389 — Final Plan: Pluggable Risk Scoring + Approval Pipeline

Status: **implemented** (2026-08-17). All owner decisions ratified; PR 1 (risk-scorer seam),
PR 2 (approval pipeline, including the `owner_sub` hold-time snapshot and the structurally
interactive-only decide gate), and the companion agent-token-verification seam
(TECH-5396) have all landed on this branch (PR #14). Only the items in §17 remain
genuinely open. DESIGN.md's §13-listed changes have been applied.

Revision history (each entry describes the state AT THE TIME it was written — the
Status line above is the current, final state; an entry below that describes something
as "not yet landed" is a superseded historical snapshot, not a live status claim):

- 2026-08-17, pluggable auth verification: at this point only PR 1 (the risk-scorer seam
  in `plugins.py`) and the `mint_token.py` CLI had landed. §15 was rewritten from an
  accepted risk into a resolved design: agent-token *verification* becomes a pluggable
  auth-layer seam (same mechanism as §1, tracked as a **companion ticket**, not
  TECH-5389), and the decide surface was designed to gain two verifier-agnostic
  hardenings in TECH-5389 PR 2 — an `owner_sub` hold-time snapshot and a structurally
  interactive-only decide gate. Sections touched by this revision: §1, §4, §5, §7,
  §9–§14, §15 (rewritten), §16.
- 2026-08-17, later: PR 2 and the companion ticket (TECH-5396) both landed too — see the
  Status line above, which supersedes this entry's "tracked as a companion ticket, not
  TECH-5389" framing insofar as that companion ticket is now ALSO done, just not as part
  of TECH-5389's own PR sequence.

Verified against the current worktree:

- Migration head: `f4a9c1d2b3e7` (post-implementation; was `136265b3f22d` at planning time).
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
- **A further pluggable seam of the same mechanism — the agent-token verifier — lives
  at the auth layer, deliberately NOT in this list**: it is resolved in
  `auth.build_auth_provider()` (not `providers/comms.py`), consumed by FastMCP's
  `MultiAuth` (not `service.py`), and its registry lives in `auth.py` (`plugins.py`
  must stay importable by the fastmcp-free `service.py`, so it cannot grow a fastmcp
  dependency). Design, trust argument, and ticket split in §15.

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
- Sensitive type: `internal` → not high risk, no ownership lookup at all — TECH-5735
  made this an actual structural guarantee rather than an open-time assumption:
  admission (`_authorize_conversation_open`) and the invite gate
  (`_authorize_invite_owner_freeze`) both refuse to ever admit an `is_shared`
  participant into `internal`, so the "one owner, forever" invariant this fast
  path relies on can't become false after open — there is nothing left to
  recheck. (Re-checking live on every `internal` send was considered and
  rejected: the actual exposure TECH-5735 closes is at INVITE time —
  `comms_accept` grants full retroactive history read the moment a participant
  is admitted — not at each subsequent send; see `_divert_invite_for_approval`.)
  `open` → high risk (`boundary_crossing`, no lookup — `open` has no ownership
  concept); `asymmetric` → ownership lookups (sequential — same
  shared-`AsyncSession` constraint documented in `service._owner_sets_for`).
  `asymmetric`'s shared-sender bypass is preserved (`high_risk=False`,
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
  owner-freeze) were untouched BY THIS (TECH-5389 PR2) change and kept their hard
  `denied.ownership_unverified` denials — only the per-message Axis 2 check is
  subsumed. (A later ticket, TECH-5735, does split invite owner-freeze's denial
  into two reason strings for its own re-validation needs — see DESIGN.md's
  ownership-admission section for the current state.)
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
message_type, schema_version, payload, risk reason, participants, sender_sub.
(Unlike the scorer, the auto-approver *does* get the payload — per the owner,
the risk flag stays light and the expensive judgment belongs here.)

`participants` (added TECH-5754): the OTHER active/invited conversation
participants — who this hold's message is actually addressed to, or who is
already in the conversation being invited into. Always excludes the
sender/inviter itself. Additive: existing `AutoApprover` implementations
ignore it. Sorted by `Agent.sub` in codepoint order on every path (the two
SQL-backed paths pin `.order_by(Agent.sub.collate("C"))` specifically so
they can't drift from `start_conversation`'s plain Python `sorted(...,
key=lambda t: t.sub)` under a non-C Postgres locale) — important for an
ordering-sensitive downstream consumer (e.g. an LLM-judge AutoApprover) to
get a stable, cacheable prompt across repeated holds. This is NOT
necessarily the same order `get_hold_conversation_participants`/
`get_conversation`'s HTTP surfaces use (those query without a `COLLATE`
pin), so don't assume byte-for-byte parity with those endpoints' ordering,
only that every `HoldContext.participants` producer path agrees with each
other. Also note `ParticipantInfo` is field-name-compatible with, but not
identical to, `get_hold_conversation_participants`'s HTTP response entries:
that endpoint includes the sender/inviter (this never does), its
`agent_id` is a `str` (here it's a `uuid.UUID`), and it has no `sub` field
at all (`ParticipantInfo.sub`, added TECH-5755 for the same reason as
`HoldContext.sender_sub` below) — see `plugins.py`'s `ParticipantInfo`
docstring.

`sender_sub` (added TECH-5755): the sender/inviter's own `Agent.sub` —
board-wide-unique, and for a real RH-internal bot the same string as its
Arc `bot_id` (an rh-auth service token's `sub` is normalized straight
through as the board identity at registration — see
`agent-comms-approvals`' `RHAgentVerifier`). Exists so an `AutoApprover`
can map a hold back to an external system's own identity for that agent
without a DB session of its own — `review()`'s only input is this
NamedTuple. Threaded straight through from the already-loaded sender
`Agent` row at every producer path, same as `participants` above — no
extra query. `ParticipantInfo.sub` (above) is the same idea applied to
recipients rather than the sender: an `AutoApprover` that needs to confirm
a specific *participant* is, say, a particular external system's own
service identity (not just the sender) needs this too.

**NamedTuple field-addition deployment ordering**: neither `participants`
(TECH-5754) nor `sender_sub`/`ParticipantInfo.sub` (TECH-5755) have
default values, so any external consumer that constructs `HoldContext`/
`ParticipantInfo` directly (most plausibly `agent-comms-approvals`' own
`AutoApprover` unit-test fixtures) gets a loud `TypeError` the moment it
picks up a version of this repo with a field it doesn't yet pass — this
repo must deploy (or at least merge, for a same-day pairing) before a
consumer updates its own fixtures to match. A sentinel default is
deliberately not used instead: a defaulted `sender_sub=""` would silently
break the Arc `bot_id` mapping rather than fail loudly.

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
    owner_sub: str            # routing key: whose approval is needed (the hold's §15.4 snapshot)
    owner_email: str          # human-friendly routing (Slack lookup, email; still from the agents row)
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
  owner_sub           TEXT NOT NULL      -- approver routing key: the sender's verified owner identity,
                                         -- snapshotted at hold-creation time (§15.4)
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

  idx_approval_holds_sender_agent_id_status_created_at   -- hold rate limit + get_hold_status
  idx_approval_holds_owner_sub_status_created_at         -- list-pending owner filter (§10)
  idx_approval_holds_conversation_id
```

- **No `high_risk` boolean**: a hold exists *only because* the verdict was high-risk;
  `risk_reason`/`risk_scorer` carry the verdict.
- **`owner_sub` IS snapshotted** (reverses this section's earlier "no snapshot"
  position — the old rationale assumed the frozen `agents.owner_sub` and a hold-time
  snapshot were always identical, which stops being true once verification is
  pluggable, §15). Sourced from the sender's *verified* `owner_sub` claim on the
  request that created the hold, falling back to `agents.owner_sub` when the claim is
  absent; under the OSS default verifier the two normally coincide. Decide, list, and
  the notifier read the hold's snapshot, never the agents row (§15.4).
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

`APPROVAL_HOLD_TTL = timedelta(days=7)`; `MAX_APPROVAL_HOLDS_PER_MINUTE = 2` (counted
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
   diverted open, bounded further by `MAX_APPROVAL_HOLDS_PER_MINUTE`.
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
   - Hold rate limit (`denied.rate_limited`, `limit="approval_holds_per_minute"` — rate
     limiting was never part of the divert-don't-deny reversal).
   - Insert hold (`pending_auto`; `owner_sub` snapshotted from the sender's verified
     claim per §15.4, passed down from the tools layer as a parameter — the existing
     "identity derives from verified claims, never arguments" rule), audit
     `approval.hold`.
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
  "created_at": "…",
  "decision_url": "…"
}
```

`decision_url` (added post-PR-2) is present only when the board has
`DECISION_PAGE_BASE_URL` configured — a human-clickable link straight to the hold on
the separate `agent-comms-approvals-decision-page` service, built as
`f"{DECISION_PAGE_BASE_URL}/holds/{hold_id}"`. Omitted (not null) when unset, so
callers should treat it as optional rather than always present.

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
  rejected (and approved, if the human left a note); `message_seq`/`message_id`
  present whenever `message_id` is set on the hold row (only ever set at
  message-creation time, on the approve/auto_approve path — TECH-5735 tightened
  this doc's earlier "on approved/auto_approved" phrasing to describe the actual
  implementation gate, see DESIGN.md's `comms_get_hold_status` row) so the agent
  can correlate with `get_conversation`.

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

Everything structural from the prior revision survives, with the interactive gate
*strengthened* now that verification is pluggable (§15): `POST
/approvals/{hold_id}/decide` via `mcp.custom_route` (handler self-verifies the bearer
— exact verify-method name pinned down against the installed FastMCP version at
implementation time); **hard interactive-token gate with NO agent-scope escape hatch,
enforced by verification path, not claim inspection**: the handler verifies the bearer
against the interactive (Okta OIDC) provider ONLY — the agent-verifier chain (§15) is
never consulted for authorization here, so no agent credential of ANY format (OSS
agent-jwt or a consumer plugin's tokens) can pass, regardless of any scope including
`comms:admin` — deliberately unlike the `is_interactive_token(token) or "comms:admin"
in scopes_for_token(token)` pattern in `providers/comms.py`. `is_interactive_token`
is still asserted on the verified result as a belt-and-braces check, but the load-
bearing gate is *which provider verified the token*: even a buggy or hostile plugin
verifier (§15.3) cannot make an agent token decide a hold. A bearer that fails
interactive verification is run through the agent chain solely to attribute the
`denied.approval_requires_interactive` audit row, then rejected. Approver's verified
sub (`identity.try_resolve_email`) must equal the hold's `owner_sub` snapshot
(§15.4 — no longer the frozen `agents.owner_sub`);
**uniform 404** for unknown-hold and not-your-hold (audit distinguishes
`denied.unknown_hold` / `denied.hold_not_owner`); 409 already-decided
(`denied.hold_wrong_state.<status>`); 410 lazily-expired (`approval.expire`); 422 bad
body; no endpoint rate limiting (interactive-human-only by construction).

Deltas for the ratified design:

- **Owner-match source changed (pluggable-verifier revision)**: decide reads
  `approval_holds.owner_sub` — the hold-time snapshot — not the frozen
  `agents.owner_sub` (§15.4 for the full rationale). Verifier-agnostic; lands in PR 2
  regardless of whether the companion verifier-seam ticket has shipped.
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

Same non-MCP surface and identical auth gate as decide (interactive-provider-only
verification + owner-match, §9). Returns full hold detail **including the held text**
for holds whose `owner_sub` snapshot (§15.4) == the caller's verified sub, `pending_human` only, ordered
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
| `denied.rate_limited` (`approval_holds_per_minute`) | sender's sub | hold burst cap (2/min; sustained rate equals `MAX_MESSAGES_PER_SENDER_PER_HOUR`, so this is burst-shaping only, not an independent sustained-flood ceiling — Argus round-2) |
| `denied.system_message_type` | sender's sub | agent tried to post `conversation_opened` directly |
| `denied.approval_requires_interactive` | endpoint caller identity | non-interactive (agent) token hit a decide/list endpoint — bearer failed interactive-provider verification; the agent chain is consulted for attribution only (§9) |
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
`approval_holds` with the §5 columns **including `decision_reason` and the
`owner_sub` snapshot**, both CHECKs, all three indexes, UNIQUE on `message_id`,
`if_not_exists`/`if_exists` guards per repo
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
  provenance statement (§15 — resolved-by-design under a live-resolving verifier;
  static-claim `mint_token.py` path as the OSS default). The `AGENT_TOKEN_VERIFIERS`
  seam itself is documented in DESIGN.md by its companion ticket (TECH-5396), not TECH-5389's pass.
- `main.py` `instructions` string and affected tool docstrings updated in the same PR.

## 14. Test plan

| File | Coverage |
|---|---|
| **New `tests/test_plugins.py`** | Scorer verdict matrix (type × conversation-type × ownership topology — absorbing `is_boundary_crossing_safe`'s cases from `test_state_machine.py`); shared-sender bypass verdict; scorer RAISES on lookup error / empty owners / unknown conversation type; registry + import-path resolution; startup fail-fast (unknown name, bad path, missing webhook env); `EscalateAllAutoApprover`; notifier payload excludes text; `LogOnlyNotifier`; `WebhookNotifier` HMAC + timeout |
| `tests/test_state_machine.py` | Remove the 27 boundary mentions (moved); `conversation_opened` legal only in `active`, no state transition |
| `tests/test_schemas.py` | Remove `boundary_safe`/`MessageSchema`/`is_boundary_safe` tests (20 mentions); `ConversationOpenedV1` validation; drift guard covers the new Literal entry |
| `tests/test_service.py` | Diversion: high-risk post creates hold + **no** `messages` row + held return; non-high-risk path byte-for-byte unchanged; scorer exception → `denied.risk_unscored` hard denial (no hold row); inline auto-clear (fake approver) posts atomically; hold rate limit; notifier-failure isolation (`approval.notify_failed`, response still held); **seq-1 divert**: conversation created with `conversation_opened` seq 1 at the negotiated version, `invite`'s pin re-check still works, held content posts as seq 2 on approval, capability gate still hard-denies targets not accepting the ORIGINAL type, direct agent post of `conversation_opened` denied; decide flows (approve atomicity incl. forced-failure rollback, seq race vs. concurrent post, reject-no-message + `decision_reason` stored, owner mismatch ≡ unknown hold, already-decided, expired, conversation-went-terminal, capability re-check); **`owner_sub` snapshot**: hold captures the verified claim (falls back to `agents.owner_sub` when absent), decide/list match the snapshot not the agents row — a re-minted corrected owner routes *future* holds (§15.4); `get_hold_status` service logic (sender-only uniform denial, lazy expiry, reason/seq surfacing); full audit-row assertions per §11; the 44 existing boundary-denial tests rewritten to expect holds (or `denied.risk_unscored` where the cause was infrastructure) |
| `tests/test_comms_tools.py` | End-to-end: `note` into an `open` conversation returns the held shape (rewrites the 15 boundary mentions); approved hold's message then visible via `comms_get_conversation` with original type; `comms_get_hold_status` happy path + rejected-with-reason + uniform denial; seq-1 divert response shape |
| `tests/test_db_models.py` | `approval_holds` round-trip, both CHECKs, FKs, `message_id` uniqueness, `decision_reason` nullable, `owner_sub` NOT NULL |
| `tests/test_migrations_offline.py` | New revision DDL assertions |
| **New `tests/test_approval_endpoint.py`** | 401/403 (incl. **agent-jwt + `comms:admin` → 403** — the load-bearing structural test, now asserting the bearer is verified against the interactive provider ONLY, with the agent chain consulted solely for denial attribution — §9/§15), uniform 404 pair, decide flows over HTTP incl. `reason` persistence, `pending_human`-only, list-pending owner filtering + includes text, audit attribution to the approver's sub. Own file: needs the Postgres fixture block (mirrored from `test_comms_tools.py`), which `test_main.py` deliberately lacks |
| `tests/test_main.py` | `TestScopeRegistryParity` covers `comms_get_hold_status` enrollment mechanically |
| `tests/test_scopes.py` | `comms_get_hold_status` → `comms:read` mapping |

## 15. Pluggable agent-token verification; `owner_sub` provenance resolved

*(Rewrites the former "`owner_sub` provenance — accepted risk". The risk is now
resolvable by construction rather than merely accepted; the OSS static-claim path
remains a complete, correct, standalone default. The seam itself is a **companion
ticket**, not TECH-5389 scope — see §15.5 for the exact split.)*

### 15.1 The correction

The plan so far treated agent-token verification as fixed: `auth.build_auth_provider()`
hardcodes one `JWTVerifier(public_key=require_env("AGENT_JWT_SECRET"),
algorithm="HS256", issuer=AGENT_JWT_ISSUER)` into FastMCP's `MultiAuth` alongside the
Okta `OIDCProxy` (auth.py:312–342). Under that assumption, an agent's human owner can
only ever be a static `owner_sub` claim baked in at mint time (`mint_token.py`'s
mandatory `--owner-email`/`--self-owned` choice), read once at first registration
(providers/comms.py:431) and frozen into `agents.owner_sub` — hence this section's
former accepted-risk framing. A consumer with its own credential system (e.g. an
opaque-key-exchange service that hashes keys at rest and resolves ownership live from
its own DB) had no way in short of forking, and importing any consumer-private auth
package into this repo would break the open-source deployability story. The fix:
the *verification* side becomes pluggable via the exact §1 mechanism; consumer-side
verifiers live entirely in private packages that this repo is merely configured to
trust.

### 15.2 The seam (env var, registry, composition)

**Placement call — deliberately NOT a fourth entry in §1's seam list.** The §1 seams
are approval-pipeline policy: resolved in `providers/comms.py`, injected as parameters
into `service.py`, exercised per message. This seam is auth-layer plumbing: resolved
once inside `auth.build_auth_provider()` at process build, consumed by `MultiAuth`,
never seen by `service.py`. Same *mechanism* (Protocol + registry + env-var/import-path
+ fail-fast), different layer, different trust argument — so it gets its own section
here and its own ticket. Concretely, the registry cannot live in `plugins.py` anyway:
`service.py` imports `plugins`, and the plan pins service as fastmcp-free, so
`plugins.py` must not grow a fastmcp import; only `resolve_plugin`'s generic per-name
resolution logic is shared (factored so both call sites use one implementation).

- **Env var `AGENT_TOKEN_VERIFIERS`** (plural: comma-separated, ordered), default
  `agent_jwt_hs256`. Each element is a registry name or a `pkg.module:factory` import
  path — §1's resolution rule verbatim. `MultiAuth(verifiers=[...])` already takes a
  list (auth.py's own docstring documents trial order: OIDCProxy first, then each
  verifier), so **coexistence and replacement both fall out of the same knob**:
  `AGENT_TOKEN_VERIFIERS=agent_jwt_hs256,rh_comms_plugins.auth:build_rh_agent_verifier` runs the
  OSS default and a consumer verifier side by side (tried in that order); a lone import
  path fully replaces the default. An empty value is a startup `RuntimeError`
  (fail-fast; an interactive-only deployment is out of scope until someone needs it).
- **Registry in `auth.py`**: `TOKEN_VERIFIERS: dict[str, Callable[[], TokenVerifier]]`
  with one in-tree entry — `"agent_jwt_hs256"` → exactly today's `JWTVerifier(...)`
  construction, moved verbatim into the factory. Consequence: `AGENT_JWT_SECRET`
  becomes required *iff* `agent_jwt_hs256` is configured (the `require_env` call moves
  inside the factory); a consumer that fully replaces the default no longer sets it.
- **Protocol = FastMCP's own `TokenVerifier`** (`async verify_token(token: str) ->
  AccessToken | None`) — no parallel Protocol invented; a plugin is anything MultiAuth
  can already compose. (Exact class surface pinned against the installed FastMCP
  version at implementation time, same caveat §9 already carries for the verify
  method.)
- **Fail-fast for free**: `build_auth_provider()` runs at process start, so an unknown
  registry name or bad import path crashes at boot with no extra
  `validate_configuration()` pass needed.

### 15.3 The normalized-claims contract (what a verifier must expose)

Everything downstream of verification keys on **one claim shape**, not on wire format:
`scopes.is_interactive_token` / `scopes.scopes_for_token` / `scopes.safe_client_id`
branch on `iss`; `identity.try_resolve_email` resolves agent identity from `sub`;
registration reads `owner_sub`. So the contract is: **a plugin verifier may verify any
wire format it likes (opaque key exchanged live against a private service, RS256 JWT
from a private issuer, …), but the `AccessToken` it returns must carry normalized
claims:**

| claim | requirement |
|---|---|
| `iss` | MUST equal `"agent-jwt"` (`identity.AGENT_JWT_ISSUER`) — the normalized agent marker, regardless of what the wire token's own issuer was |
| `sub` | the agent's identity string; a `str` instance, non-empty, passes `identity.validate_sub_shape` (never email-shaped — the anti-impersonation rule) |
| `scopes` | `list[str]` in `scopes.py`'s `TOOL_SCOPES` vocabulary |
| `owner_sub` | OPTIONAL: the owning human's identity (their Okta-resolved email). **This is the live-resolution hook**: a consumer verifier may resolve it freshly from its own systems on every verification, instead of it being baked in at mint time |
| `exp` / `nbf` / `AccessToken.expires_at` | OPTIONAL, but when present MUST NOT be expired (`exp`/`expires_at`) or not-yet-valid (`nbf`) — checked independently by the OSS-owned adapter (60s clock-skew leeway), not trusted from the inner verifier. A verifier with no expiry mechanism at all (relying instead on live revocation) is not required to set any of these |

Why force `iss="agent-jwt"` rather than letting each verifier keep its own issuer:
`scopes.is_interactive_token` (scopes.py:75–96) is a **denylist** — `iss !=
"agent-jwt"` ⇒ interactive ⇒ full scope-check bypass. A plugin verifier surfacing
`iss="acme"` would make its *agent* tokens look *interactive*: scope bypass everywhere
and, absent §9's structural gate, admission to the decide surface — agent
self-approval. Normalization makes the existing denylist safe by construction, and the
whole identity stack (`try_resolve_email`'s sub-only path, `scopes_for_token`'s
iss gate, `validate_sub_shape`) works on plugin-verified tokens unchanged.

**Trust bound, stated.** A configured verifier is operator-trust-level by
construction: whoever can set `AGENT_TOKEN_VERIFIERS` can set `AGENT_JWT_SECRET` and
mint arbitrary tokens today, so a *malicious* plugin is a malicious operator — outside
the threat model, exactly like a malicious `RISK_SCORER`. What does need bounding is
the *honest-but-buggy* plugin (forgot to normalize, leaked a raw upstream claim set):

1. **OSS-owned adapter**: `auth.py` wraps every configured verifier in a thin
   normalization-enforcing adapter that post-checks the contract on each successful
   verification and treats any violation as verification *failure* (return `None` +
   structured log) — fail closed into 401, never fail open into "interactive."
2. **The decide surface doesn't depend on any of it**: §9's gate verifies against the
   interactive provider only; agent verifiers — default or plugin, correct or buggy —
   are structurally incapable of admitting a token there.

### 15.4 Where owner identity is read — the snapshot design

Owner identity now has three read points, with a deliberate hold-time snapshot in the
middle:

1. **Registration (unchanged):** `register` reads the verified `owner_sub` claim,
   frozen into `agents.owner_sub` at first registration — still the anti-forgery
   freeze, still what `AgentTableOwnershipClient` feeds the risk scorer's owner sets.
2. **Hold creation (new):** `post_message` / `start_conversation` snapshot the
   sender's verified `owner_sub` claim *from the current request's token* into
   `approval_holds.owner_sub`, falling back to `agents.owner_sub` when the claim is
   absent (the column is NOT NULL either way). The tools layer passes the claim down
   as a parameter — the existing "identity derives from verified claims, never
   arguments" rule; `service.py` still never touches fastmcp.
3. **Decide / list / notify (changed source):** the approver match (§9), the
   `GET /approvals/pending` owner filter (§10), and `ApprovalNotification.owner_sub`
   (§4) all read the hold's snapshot — stable for the life of the hold, and requiring
   **no decide-time call into any consumer system**.

Why a snapshot, rather than (a) keeping the frozen `agents.owner_sub` or (b) asking
the plugin to resolve ownership live at decide time: (a) is precisely the old accepted
risk — a mint-time or registration-time mistake is permanent, and it discards the
live-verifier's freshness entirely; (b) would couple the human approval surface to a
consumer service's availability, and there is nothing for a *token verifier* to verify
at decide time anyway — the agent's credential is presented at *post* time, the
human's at decide time. The snapshot captures the live-resolution benefit (owner as of
the moment of the held post) at zero decide-time coupling, through a single
verifier-agnostic mechanism the decide endpoint reads identically no matter which
verifier produced the claim.

What this resolves, per deployment class:

- **Consumer with a live-resolving verifier (e.g. RH reusing its own bot-credential
  service):** `owner_sub` is never baked at mint time at all — the wire credential can
  be an opaque key with no claims; the verifier stamps the current owner from the
  consumer's system of record on every verification, and every hold routes to the
  owner as of post time. The former accepted-risk section is **moot** for this class.
- **OSS default (static claim, `mint_token.py` as-is):** a complete, correct,
  standalone path — nothing about it changes, and it stays the out-of-the-box default.
  One strict improvement falls out: an agent minted with a wrong `--owner-email` (or
  the pre-CLI no-claim fallback) is no longer *permanently* un-approvable — re-minting
  with the correct `--owner-email` fixes routing for all **future** holds, because the
  hold reads the claim, not the frozen row. (Former Finding 1, downgraded from
  permanent to mint-fixable.)
- **`--self-owned` / no-claim agents:** the fallback is the agent's own `sub`, which
  `validate_sub_shape` guarantees is never email-shaped, so no email-identified Okta
  human can match — un-approvable **by design**, unchanged, and since `mint_token.py`
  landed it is an explicit mint-time choice rather than a silent default.

Residuals, stated:

- Trust root unchanged: the snapshot is exactly as trustworthy as the verifier that
  attested the claim (OSS default: possession of `AGENT_JWT_SECRET` at mint time;
  plugin: the consumer's credential system). Verifier-attested ≠ caller-suppliable —
  the claim never arrives as a tool argument.
- A hold's approver is fixed at hold time: an ownership change during the ≤7-day TTL
  does not re-route in-flight holds. Accepted; they expire or the recorded owner acts.
- The risk *scorer* still consumes the frozen `agents.owner_sub` via
  `AgentTableOwnershipClient`, so a re-minted owner changes approval **routing** but
  not boundary **scoring**. Making `OwnershipClient` env-pluggable (it is already the
  same Protocol shape — §1's code-comment note) so live-ownership consumers get
  consistent scoring + routing is an explicit open question on the companion ticket
  (TECH-5396), not built here.
- Exact-string match retained (former Finding 2): a case mismatch yields an
  un-approvable hold, not a security hole.
- **`is_shared` does NOT exempt an agent from needing an `owner_sub` (ratified).**
  `is_shared` (frozen at registration, `models.py:166`) and `owner_sub` are independent
  axes: `is_shared` tells the risk scorer this agent legitimately spans multiple
  owners (the shared-sender bypass), `owner_sub` says whose approval a hold needs. The
  bypass only fires in `asymmetric` conversations — in `open`, any `note` is high-risk
  unconditionally regardless of `is_shared`, so a shared agent posting free text into an
  `open` conversation hits the hold pipeline exactly as often as any other agent; the
  bypass reduces hold frequency only for the `asymmetric` case it actually covers. Either
  way, a shared agent still records exactly one accountable human `owner_sub` — no
  exemption, no multi-owner concept. This is also the zero-added-complexity path: exempting
  shared agents would require new branching in the hold/snapshot/decide logic; requiring
  `owner_sub` uniformly needs none.

### 15.5 Ticket split

Verifier-**agnostic** pieces land in **TECH-5389 PR 2** — they harden the decide
surface even with only the default verifier configured: the `approval_holds.owner_sub`
snapshot column + fallback + changed read points (§4/§5/§9/§10), and §9's
interactive-provider-only structural gate. The **seam itself** —
`AGENT_TOKEN_VERIFIERS`, the `auth.py` registry, the normalization-enforcing adapter,
conditional `AGENT_JWT_SECRET` — is a separate companion ticket (TECH-5396): additive at
the auth layer, no approval-pipeline coupling, independently shippable before or after PR 2.

## 16. PR sequencing

**PR 1 — behavior-preserving seam refactor.** `plugins.py` (scorer
Protocol/registry/resolver + `BoundaryCrossingScorer`), remove
`boundary_safe`/`is_boundary_safe`/`is_boundary_crossing_safe`, rewire `service.py` to
the scorer — but map `high_risk=True` to the **existing denial** for now, and scorer
exceptions to the existing `denied.ownership_unverified`-equivalent denial. Tests:
`test_plugins.py` scorer matrix; every existing test stays green with zero behavior
change. Verify: full suite.

**PR 2 — the pipeline.** `approval_holds` model + migration (incl.
`decision_reason` and the `owner_sub` snapshot column, §15.4); auto-approver +
notifier seams (defaults + webhook impl);
diversion flow + held response shape + hold rate limit; `denied.risk_unscored`
finalized; seq-1 auto-opener (`conversation_opened` type + system-type gate/exemption);
`comms_get_hold_status` + `TOOL_SCOPES` entry; decide + list-pending endpoints
(interactive-provider-only gate + snapshot-based owner match, §9);
audit actions; DESIGN.md edits; all remaining tests. Verify: suite +
`alembic upgrade head --sql` review.

**Not in either PR:** the pluggable agent-token-verifier seam itself (§15.2–§15.3) is
a companion ticket (TECH-5396) at the auth layer — PR 2 is designed so that ticket is purely
additive (the snapshot and the structural decide gate are verifier-agnostic and land
here regardless).

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

## 18. Argus review dispositions (deferred)

- **Unbounded 403-audit writes** (Argus round 1, S9): a caller that repeatedly hits a
  denial path can generate unbounded `_deny`-audited rows since there's no rate limit
  on denials themselves (unlike the approval-hold creation rate limit, §5). Deferred,
  not fixed in this pass: this is a pre-existing posture shared by every other denial
  path in the service (predates TECH-5389), not something this pipeline introduced, and
  addressing it (e.g. a per-agent denial rate limit) is a broader hardening question than
  this ticket's scope.
