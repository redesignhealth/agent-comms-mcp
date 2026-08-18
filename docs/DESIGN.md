# agent-comms-mcp: Design

Status: **agreed v1 plan** (2026-08-11), the spec of record for the comms layer.

## 1. What this is

A structured message board, exposed as an MCP server, for permissioned agent-to-agent
communication. First use case: a user's main agent delegates to a dedicated EA agent,
which negotiates meeting availability with other people's EA agents by exchanging
*judgments* (scored candidate slots). Raw calendar data never crosses that boundary.

This repo is only the comms layer. Out of scope, by explicit decision:

- **EA agent logic**: lives elsewhere.
- **Email/Slack transports**: external channels are handled by each user's main
 agent, which listens there and posts typed messages to this board as it deems fit.
 The board neither knows nor cares that a counterparty is being represented over
 email. It only ever sees typed messages from a registered agent.

## 2. Why this shape (research summary)

Reviewed Aug 2026: shipping EA products (Lindy, Skej, Clara, historically
Amy/x.ai), Google A2A (Linux Foundation, spec v1.0), MCP auth spec (2025-06-18 /
2025-11-25), IBM ACP (merged into A2A), Cisco AGNTCY, ANP, Microsoft Entra Agent ID,
and the inter-agent security literature (Invariant Labs tool poisoning, Zenity
AgentFlayer, Simon Willison's "lethal trifecta", cross-agent injection propagation
studies).

Key findings that drove the design:

1. **No shipping product does open, structured, cross-owner agent negotiation.**
 Live patterns are (a) same-vendor calendar intersection server-side, or (b)
 natural-language email negotiation. The structured-with-consent lane is open.
2. **A2A has the right shapes but no consent model.** We borrow its task lifecycle
 (including protocol-native decline), its opaque-agent principle, and its
 don't-reveal-unauthorized-resources rule, without adopting the protocol.
3. **MCP's auth spec is the best normative security reference** (OAuth 2.1 resource
 server, audience-bound tokens, no token passthrough).
4. **Inter-agent messages are the top injection channel.** The consistent mitigation
 across all documented attacks: strictly typed, schema-validated messages, never
 free text into a privileged agent's context. Hence: **no free-text fields in v1.**
5. "Paperclip" (paperclip.ing) is an intra-company agent-orchestration platform
 (tickets, org charts, budgets), distinct in purpose from an EA or cross-user comms product. Its human
 approval gates and budget auto-pause are good prior art for the EA side, out of
 scope here.

## 3. Architecture decision: hub over peer-to-peer

One central board (this MCP server) that all EA agents connect to as clients, vs. per-agent
servers with discovery and signed cards. Rationale: one audit trail, no
discovery problem, and the borrowed A2A shapes keep a later migration to true
federation open.

## 4. Identity and permissions

**Everything roots in OAuth**: FastMCP `MultiAuth` = Okta `OIDCProxy`
for interactive humans + one or more pluggable agent-token verifiers for
headless agent tokens (`AGENT_TOKEN_VERIFIERS`, default: the built-in HS256
`JWTVerifier`, `iss="agent-jwt"` — see "Configuration: pluggable agent-token
verification" below).
Owner identity (`owner_sub`, `owner_email`) is always derived from verified token claims:
never accepted as a parameter.

**There is no board-level permission layer.** Holding a valid scoped token is
admission: token issuance is the permissioned ceremony, and it happens upstream of this
service. Agent rows are self-provisioned on first authenticated call via an idempotent
`register` tool (sets `display_name`, `accepted_types`). The `status` column
(`active`/`suspended`) is an ops kill-switch. It carries no permission
semantics: no authorization decision reads it.

**`agent_key`: stopgap for one-token-per-many-agents.** The board's
`sub` is keyed on the caller's verified token identity, which today is one Okta sub
per *human*, shared across every agent that human runs: the platform mints every
EA-managed agent acting for a given human the same agent-jwt token `sub`, because it
has no way yet to carry a distinct, verified per-agent identity in the token or in
message metadata. Without a fix, `register`'s idempotent upsert on `agents.sub`
collapses all of a human's agents into one row: the second `register` call silently
overwrites the first's `display_name`/`accepted_types` (observed: an agent named
"Pepper Pots" overwrote one named "Bond 007"). `register` accepts an optional
`agent_key`, appended to the verified base identity to form `sub`
(`f"{base_sub}::{agent_key}"`): a self-chosen partition *within* an already-verified
identity. It never substitutes for verified identity itself. `owner_sub`/`owner_email`
are still derived solely from the base identity, computed before this composition, so
they are unaffected by `agent_key`, and admission decisions (`may_assign`) stay keyed
on verified ownership. Two different owners can pass an identical `agent_key` string
without colliding, since the prefix differs. This is explicitly a stopgap: the durable
fix is for the platform to mint each agent its own distinct verified identity, at which
point `agent_key` should be removed.

**Permissions live in three places:**

| Layer | Mechanism | Question it answers |
|---|---|---|
| Token scopes | fail-closed `TOOL_SCOPES` middleware (`comms:read`, `comms:write`) | may this token call this tool at all? |
| Parameter-level scope gate | in-handler check (e.g. `comms:admin`, see §5/§7) | may this token set THIS privileged input on an otherwise-reachable tool? |
| Conversation membership | `participants` rows, checked on every read and write | may this agent see/do anything in this conversation? |

The parameter-level gate is narrower than `TOOL_SCOPES`: it doesn't decide whether the
tool is reachable (that's still `TOOL_SCOPES`, fail-closed), only whether one specific
input to an already-reachable tool is accepted. See `scopes.py`'s `:admin` verb comment.

**A fourth, orthogonal control plane (TECH-5389): the approval pipeline.**
Whether a given SEND is admitted (the table above) is a separate question from
whether its CONTENT is high-risk enough to need a human in the loop before it
crosses an ownership boundary. That question is answered per-message by three
pluggable seams (a risk scorer, an auto-approver, and a notifier — see §9's
retitled Axis 2), never by scopes or membership: a fully-admitted, fully-scoped
sender can still have a specific send diverted into an `approval_holds` row
instead of posted immediately. This plane sits downstream of every check in the
table above, not in place of any of them.

**Scope enforcement applies only to agent-jwt (headless agent) tokens.** Interactive
callers authenticated via Okta bypass scope checks entirely. Scope enforcement is the
agent-token access gate. It never gates human users.

**Membership rules (v1):**

- Any registered agent may start a conversation with N other agents. All named
 targets must exist and be active. (`accepted_types` is not checked at
 invitation/join time: conversation-type admission is Axis 1's ownership
 rule below, unrelated to which message types a target has declared. It is
 enforced on each message send instead: see the capability gate below.
 Because starting a conversation requires an initial message, a target
 that hasn't declared that message's type still causes conversation
 creation to fail. That failure is an admission-shaped effect of the
 mandatory first message; it is never a separate admission check in its
 own right.)
 The creator becomes an `active` participant with `role=owner`. **Named targets are
 added as `invited`, never `active` on creation** (see acceptance flow below).
- **Any active member may invite others** (creator is `owner` so this can tighten to
 owner-only as a policy change, without a migration). New invitees also start as
 `invited`: no unilateral disclosure. This applies uniformly regardless of who does
 the inviting.
- **Acceptance gates visibility as well as participation.** An `invited` participant
 can see minimal metadata (conversation type, who invited them, current member
 list) but **not** message history or content. Calling `comms_accept` flips
 `invited → active`, which grants full history read and posting rights from that
 point. Calling decline sets `declined` directly: no access is ever granted.
 This mirrors A2A's task lifecycle (§3): `invited` ≈ a pending task awaiting
 `input_required`/acceptance, `declined` ≈ the protocol-native `rejected` state.
- Membership = visibility (for `active` participants only): members read all rows of
 their conversations, including full history from the moment they accept. Non-members
 (and not-yet-accepted invitees, for content) get a **uniform denial**: identical
 whether the conversation exists or not (anti-enumeration).
- Decline/leave is the consent mechanism. `comms_decline_invite` is for `invited`
 participants (terminal, no access ever granted). `comms_leave` covers already-`active`
 members. Leaving revokes access immediately.
- No pairwise grants in v1 (within the deployment's trust domain: colleagues don't need a consent
 handshake to ask availability). Conversation-open authorization is routed through a
 single policy function (`_authorize_conversation_open` in `service.py`: a
 module-private implementation hook, never exposed as a public API), which is the seam where a
 grants/consent layer lands when external counterparties arrive.

## 5. Data model (Postgres)

Six tables. `messages` and `audit_log` are append-only: no UPDATE/DELETE paths in code.
`approval_holds` (TECH-5389) is the one MUTABLE table besides `conversations`/
`participants`/`agents`: a hold's `status` flips as it moves through its lifecycle.

```
agents id, sub UNIQUE, owner_sub, owner_email, display_name,
 accepted_types text[] (max 20 types, 100 chars each),
 status(active|suspended), min/max_schema_version,
 is_shared boolean (default false, frozen against self-re-registration,
 admin-mutable via comms_set_agent_shared),
 bound_at, timestamps
conversations id, type, state(active|completed|canceled|expired),
 created_by, expires_at, owner_snapshot jsonb (nullable),
 timestamps
participants (conversation_id, agent_id) UNIQUE, role(owner|member),
 status(invited|active|left|declined), invited_by, invited_at,
 joined_at (set on accept), last_read_seq
messages id, conversation_id, seq (UNIQUE per conversation, server-assigned,
 race-safe), sender_id, type, schema_version, payload jsonb, created_at
audit_log id (bigint), at, actor_sub, action,
 agent_id/conversation_id/message_id, detail jsonb
 -- every mutation AND every denial
approval_holds id, conversation_id, sender_agent_id, owner_sub, message_type,
 schema_version, payload jsonb (the held content -- validated, insert-ready),
 risk_reason, risk_scorer, status(pending_auto|pending_human|auto_approved|
 approved|rejected|expired), auto_approver, auto_decision(cleared|escalated),
 auto_decided_at, decided_by_sub, decided_at, decision_reason (free text --
 see §9's trust argument), message_id UNIQUE (nullable FK to the resulting
 messages row, either approval kind), expires_at, timestamps
 -- MUTABLE (status flips); a hold exists ONLY because the risk verdict was
 high-risk, so there is no separate `high_risk` boolean. `owner_sub` IS a
 snapshot -- taken from the sender's verified `owner_sub` claim at hold-
 creation time (falling back to `agents.owner_sub` when the claim is
 absent), NOT a live join to the `agents` row: once agent-token
 verification becomes pluggable, a live-resolving verifier can change what
 `agents.owner_sub` means between hold-creation and decide-time, so the
 decide/list paths match against the hold's own snapshot (see §9)
```

Design notes:

- `last_read_seq` per participant makes "what needs my attention" trivial and keeps
 per-message-type logic out of the board: inbox = active conversations with
 `max(seq) > last_read_seq`.
- `schema_version` on messages lets payload formats evolve without breaking history.
- Conversations expire (`expires_at`, checked lazily on direct access via
 `comms_get_conversation`). `comms_inbox` does not trigger expiry; the next
 direct touch on a conversation does.
- Rate limits (per-sender posts per conversation per hour: 30; conversation-starts per
 hour: 10) are computed from the tables. No Redis until it matters. Conversation TTL
 is 7 days.
- `bound_at` on agents tracks when each agent last registered (updated on every
 `comms_register` call, including re-registration).
- `is_shared` marks an agent that spans ownership boundaries (e.g. a bot serving
 multiple users). It is an admission-decision input (see §9), so it is frozen
 at first registration (re-registering with a different value has no effect),
 and self-declaring `True` at first registration requires the caller's token
 to carry an elevated `comms:admin` scope (or be an interactive/Okta caller).
 Without it, `comms_register` denies with `denied.is_shared_requires_elevated_scope`
 (this is the audit-log reason key only: the caller receives the generic
 `access_denied` message).
 `comms_register` itself never overwrites an existing agent's `is_shared` on
 re-registration (a re-registration presenting a different value is a no-op,
 audited as `agent.reregister_is_shared_ignored`) -- the freeze holds against
 the agent's own self-reported claims. The only supported way to correct an
 existing agent's `is_shared` is the separate `comms_set_agent_shared` admin
 tool, gated on the same elevated `comms:admin` scope (or interactive/Okta
 caller); a caller without it gets `denied.set_shared_requires_elevated_scope`
 (audit-log reason key only). This keeps the guarantee `is_shared` is meant to
 provide -- it cannot change as a side effect of the agent's own traffic --
 while giving an operator a deliberate, separately-audited (`agent.set_shared`)
 lever to fix a value an agent got wrong at registration. The per-message
 `_enforce_boundary_crossing` check (§9 Axis 2) queries the current row on
 every post, not a value cached at conversation-open time, so flipping
 `is_shared` takes effect retroactively on already-open `asymmetric`
 conversations for THAT check: correcting a wrongly-`False` agent to `True`
 immediately grants the boundary bypass on its existing conversations, and
 correcting a wrongly-`True` agent back to `False` immediately withdraws it,
 mid-conversation. This retroactive effect is narrower than it may sound,
 though: `_authorize_conversation_open`'s pairwise-ownership admission (§9
 Axis 1) runs exactly once, at conversation creation, so flipping the flag
 changes admission only for conversations opened AFTER the flip, never for
 ones already open. The invite gate (`_enforce_invite_owner_boundary`) is
 governed entirely by `Conversation.owner_snapshot`, frozen at open time with
 no `is_shared` bypass of its own, so it is unaffected by the flag either
 way, at any time.

## 6. Message schemas (two-axis model)

Strict Pydantic (`extra='forbid'`), timezone-aware datetimes only, enum-coded reasons,
**no free-text fields anywhere except `note`**. All types legal only in `state=active`.

The `boundary_safe` column (below) no longer exists as a schema field (TECH-5389):
which types can cross an ownership boundary is now scorer-private policy
(`plugins.BoundaryCrossingScorer.BARRIER_SENSITIVE_TYPES`), and a "sensitive" type
crossing a boundary no longer denies the send — it diverts to a human-approval hold
(§9's retitled Axis 2). The table's "sensitive?" column names what used to be
`boundary_safe=False`.

| Type | sensitive? | Payload | Semantics |
|---|---|---|---|
| `availability_request` | no | window {start,end}, duration_min, modality(video\|phone\|in_person), priority, constraints[] (enum-coded) | opens scheduling negotiation |
| `availability_response` | no | slots[{start,end,preference 0..1}] max 10, or none_available+reason | **`preference` is the product**: judgment crosses the boundary, never calendar data |
| `counter_proposal` | no | same slots shape | iterate on slots |
| `confirm` | no | slot {start,end} | transitions conversation → `completed`. Booking itself is EA-side |
| `decline` | no | reason (enum) | sets sender's participant status to `declined`. All non-owners declined → conversation `canceled` |
| `needs_clarification` | no | about_seq | pause signal. A human/EA needs to weigh in |
| `task_assign` | no | action (enum), scheduling params | opens task-coordination; structured spec, no free text |
| `task_report` | no | progress (enum), optional note_ref | non-terminal status update from assignee |
| `task_complete` | no | _(minimal)_ | transitions conversation → `completed` |
| `task_decline` | no | reason (enum) | member-only; transitions conversation → `canceled` |
| `task_cancel` | no | reason (enum) | owner-only; transitions conversation → `canceled` |
| `note` | **yes** | text (string) | free-text note; posts immediately unless it would cross a boundary, in which case it is held for human approval (never denied for that reason alone — see §9) |
| `conversation_opened` | no (exempt) | reason (enum, fixed `"pending_approval"`) | service-synthesized-only marker; never legal as a caller-supplied `message_type` (`denied.system_message_type`); the seq-1 message of a conversation whose real opener was diverted to a hold (§9) |

## 7. MCP tool surface

All tools enrolled in the fail-closed `TOOL_SCOPES` catalog (registry-parity enforced
by test). AXI conventions: compact structured returns, `total_count`/`has_more`,
explicit empty states. `comms_list_conversations` deliberately omits
`total_count`: it would need a second `SELECT COUNT(*)` replaying the same
filter predicates, and `has_more`/`next_cursor` are sufficient for its
scroll-to-load-more use case.

| Tool | Scope | Notes |
|---|---|---|
| `comms_whoami` | comms:read | caller identity/scopes; also returns this identity's registered min/max_schema_version via a best-effort DB lookup if already `comms_register`'d -- omitted if not yet registered or the DB is unreachable (this tool remains usable as an auth-only diagnostic either way) |
| `comms_register` | comms:write | idempotent self-provisioning: display_name, accepted_types (max 20, 100 chars each), min/max_schema_version (default 1/1, for schema-version capability negotiation); `is_shared=True` on first registration additionally requires comms:admin (see §5) |
| `comms_set_agent_shared` | comms:write | admin override of an existing agent's `is_shared`, since `comms_register` freezes it against the agent's own re-registration; additionally requires comms:admin (see §5) |
| `comms_list_agents` | comms:read | directory (internal domain, enumeration acceptable). Returns agent UUIDs used as target identifiers in other tools |
| `comms_lookup_agent_by_email` | comms:read | directory lookup by owner email; `{"agent": ..., "found": bool}`. O(1) targeted equivalent of paginating `comms_list_agents` -- see §10's enumeration-posture note |
| `comms_start_conversation` | comms:write | type + up to 50 target agent UUIDs (from `comms_list_agents`) + initial request payload. **Two response shapes** (TECH-5389): the normal conversation-created shape, or (if the opener was high-risk) that same shape plus a `held_for_approval`/`hold_id`/`hold_status`/`risk_reason` block — the conversation is created anyway, opened with a service-synthesized `conversation_opened` marker at seq 1, and the real content is held (§9) |
| `comms_post_message` | comms:write | typed, schema-validated, state-machine-checked. **Two response shapes**: the normal posted-message shape (unchanged; gains `auto_approved`/`hold_id` if a configured auto-approver cleared a high-risk send inline), or `{"held_for_approval": true, "hold_id", "conversation_id", "status", "risk_reason", "expires_at", "created_at"}` — not an error — when the send is diverted to a hold (§9) |
| `comms_get_hold_status` | comms:read | poll a held message's approval status; sender-only (uniform `access_denied` otherwise). Returns status, risk_reason, timestamps, and (once decided) `decision_reason`/`message_id`/`message_seq`. **Deliberately the only MCP-side surface for this pipeline** — approve/reject/list-pending are non-MCP HTTP endpoints (§9), by design: an agent must never be able to approve its own high-risk content, so there is no MCP tool that could even attempt it |
| `comms_get_conversation` | comms:read | combined read: conversation + participants + messages since seq, capped at `MAX_MESSAGES_PER_GET_CONVERSATION` (500) per call. Advances caller's `last_read_seq` when messages are returned and the page's own max seq exceeds the current cursor. When `has_more` is `true`, continue with `since_seq=page_max_seq` (the returned page's own max seq) -- NOT `since_seq=last_read_seq`, which is the caller's persisted cursor and can already be ahead of a page being re-read at a lower `since_seq` (TECH-5377). For an `invited` (not yet accepted) caller, returns metadata only: no messages, `has_more` always `false`, plus `invited_by` (the agent ID that invited the caller, whether named at `comms_start_conversation` time or added later via `comms_invite`). `participants.invited_by` is nullable at the schema level with no `CHECK` constraint tying it to `status`; both current code paths that create an `invited`-status row always set it, a code-level convention only, not a schema-enforced guarantee -- the service layer's own defensive `if participant.invited_by else None` reflects that (Argus round-5 SUGGESTION: an earlier version of this row overstated it as unreachable) |
| `comms_inbox` | comms:read | active conversations with unread messages, **plus pending invites awaiting accept/decline**. Each list capped (`MAX_UNREAD_CONVERSATIONS_PER_INBOX`/`MAX_PENDING_INVITES_PER_INBOX`, both 100) with a `*_has_more` flag; `total_count` is always a true count, unaffected by either cap -- computed via a real `COUNT(*)` only when that half's own list was actually truncated, otherwise the (untruncated) list's own length already IS the true count. **Known gap**: no cursor -- if either cap is hit, there is currently no tool-level way to page through the remainder (`comms_list_conversations` filters by the CONVERSATION's state, not participant status, so it can't isolate just the overflowed set either) |
| `comms_list_conversations` | comms:read | paginated conversation list, filterable by `role`, `type`, and `state`; both `invited` and `active` participant statuses included |
| `comms_accept` | comms:write | flips caller's participant status `invited → active`. Grants history read and posting rights from this point |
| `comms_decline_invite` | comms:write | declines a pending invite: terminal, no access is ever granted. Requires caller to currently be `invited`. Distinct from `comms_leave` (which covers already-`active` members), keeping the audit trail clean |
| `comms_invite` / `comms_leave` | comms:write | membership changes. `invite` adds a target as `invited` (not `active`). `leave` covers already-active members |

## 8. Security invariants

1. Owner identity derives from verified OAuth token claims, never parameters.
2. High-risk content crosses an ownership boundary only via an explicitly-approved
 hold (human decision, or a configured auto-approver), atomically audited
 (TECH-5389). It is never silently posted and never silently dropped: a
 diversion always produces exactly one of `approved`/`auto_approved`
 (content posts under its original type), `rejected`/`expired` (content
 never posts), or `pending_human` (awaiting a decision).
3. Typed, schema-validated payloads only. No free text except `note`,
 which now posts immediately when it doesn't cross a boundary and is held
 for human approval (never silently dropped, never denied for that reason
 alone) when it would (§9). Scorer INFRASTRUCTURE failure (an unscorable
 message) still hard-denies via `denied.risk_unscored` — it never floods
 the human approval queue with unscorable holds, and it never fails open.
4. Uniform denial messages. Existence of unauthorized resources is never revealed.
 The decide/list-pending HTTP endpoints (§9) extend this with a hard,
 structural interactive-token-only gate (no agent-jwt scope escape hatch —
 an agent can never approve its own content) plus an exact match against
 the hold's own `owner_sub` snapshot (§5); unknown-hold and not-your-hold
 are a uniform 404, matching this invariant's posture at the HTTP layer.
5. Append-only messages and audit. Every mutation and every denial is audited.
 A third category, bypass/best-effort-observability, also audits privileged
 or fire-and-forget paths that are neither mutations nor denials:
 `risk.shared_sender_bypass`/`agent.conversation_open_bypassed_shared`
 (a `comms:admin`-authorized shared sender/initiator skipped the ownership-boundary
 check, §9), `agent.reregister_is_shared_ignored` (a re-registration's requested
 `is_shared` diverged from the frozen row value and was ignored, §5), and
 `approval.notify_failed` (the post-commit approval notifier raised — logged,
 never fails the triggering call, §9). Unlike denial
 events (committed immediately by the denial helper), bypass events
 are staged within the request's own transaction and are only persisted if that
 transaction ultimately commits; `approval.notify_failed` is the one exception,
 written in its own fresh transaction after the main commit already succeeded.
6. Fail-closed tool scoping: unenrolled tool is unreachable by agent tokens.
7. Rate limits per sender (30 messages/hour/conversation, 10 conversation-starts/hour,
 10 approval holds/hour), message size caps, participant cap (50 per conversation),
 and conversation expiry (7 days).

## 9. Two-axis model: conversation type (admission) × message type (boundary)

The design replaced the earlier dedicated `tasks` table with a
general two-axis model that handles both scheduling negotiation and task
coordination through the same conversations/messages layer.

**Why tasks-as-conversations works (addressing the earlier objection)**

The original §9 rejected this shape because "messages is append-only while a
task's status mutates in place." That objection doesn't apply: task state lives
on `conversations.state` (already mutable via `completed`/`canceled`) without
needing to be folded out of the message stream. A `task_complete` message
triggers the same state-machine transition that `confirm` already triggers for
scheduling: no new mechanism is needed. The append-only invariant on `messages`
is untouched.

### Axis 1: conversation type → admission policy

| Type | Admission rule | Use case |
|---|---|---|
| `open` | any active agent (no ownership check) | scheduling negotiation across ownership boundaries |
| `internal` | all participants share identical verified owner sets (no exception — a shared initiator does not bypass this) | same-owner multi-agent coordination (e.g. CoS ↔ EA) |
| `asymmetric` | all pairwise owner-set intersections are non-empty, **except**: a shared initiator (`agents.is_shared=True`) is admitted without the pairwise check | cross-owner task delegation where a shared agent bridges two users |

Ownership is resolved via an injected `OwnershipClient` seam. It is never read
from `agents.owner_sub` directly, since a shared agent's row can't represent
multiple owners. Fails closed (`denied.ownership_unverified`) on any lookup
error. The interim `AgentTableOwnershipClient` wraps `agents.owner_sub` as a
single-element set: correct for every agent registered today. Swap it for the
real platform endpoint once shared agents exist.

For `internal`/`asymmetric` conversations, the verified owner-set union is frozen
at creation time in `conversations.owner_snapshot` (JSONB, nullable: `open` does
not use it). Subsequent invites are checked against this snapshot: an invite that
would expand the owner set is denied, preventing unilateral de-isolation of an
`internal` conversation.

### Axis 2: per-message risk scoring (pluggable) [TECH-5389]

Axis 1 (admission — the whole participant set at conversation-open time,
above) is untouched by this section. Axis 2 used to be a single hard
`boundary_safe` schema flag; it is now three pluggable seams evaluated on
every send, sharing one resolution mechanism (env-var-configured, fail-fast
at startup — see the Configuration subsection below): a **risk scorer**, an
**auto-approver**, and an **approval notifier**. `plugins.py` holds all
three `Protocol` interfaces, their registries, and the shared resolver
(`resolve_plugin`), mirroring this codebase's existing `OwnershipClient` seam
convention: injected by the caller, never looked up ad hoc inside
`service.py`.

**Seam 1 — the risk scorer** decides, per send, whether the message is
high-risk (`RiskVerdict(high_risk, reason, detail)`). The v1 implementation,
`boundary_v1` (`BoundaryCrossingScorer`), is the relocated former
`boundary_safe` rule, now scorer-private policy data
(`BARRIER_SENSITIVE_TYPES = {"note"}`) rather than a schema field:

- A non-sensitive type is never high risk (no ownership lookup at all — the
 cheap common path).
- `internal`: never high risk (every participant shares one owner set by
 construction).
- `open`: a sensitive type is always high risk.
- `asymmetric` + sensitive type: an ownership lookup decides (sender's owner
 set must be a superset of every other active-or-invited participant's), with
 the same shared-sender bypass as before (`agents.is_shared=True` skips the
 lookup unconditionally, audited `risk.shared_sender_bypass`).
- **Scorer infrastructure failure still hard-denies** (`denied.risk_unscored`,
 detail carries the cause: `ownership_unverified`/`empty_owner_set`/
 `unknown_conversation_type`) — an ownership-service outage must not flood
 the human approval queue with unscorable holds. Only a GENUINE high-risk
 VERDICT diverts; an unscorable message still denies, exactly as before.

**High risk no longer denies — it diverts.** A `high_risk=True` verdict
creates an `approval_holds` row (§5) instead of a `messages` row, runs the
**auto-approver** (seam 2) inline, and returns a distinct "held for approval"
response (not an error) to the caller. `comms_post_message`/
`comms_start_conversation` document both response shapes (§7).

**Seam 2 — the auto-approver** (`AutoApprover.review(HoldContext) ->
AutoDecision`) gets the full payload, unlike the risk scorer (which is
type/topology-based only) — the expensive judgment belongs here, where a
future implementation can afford to make it. The v1 implementation,
`escalate_all` (`EscalateAllAutoApprover`), always returns `cleared=False`:
every high-risk send escalates to a human today, but the seam is exercised
inline on every one, not dead code. The lifecycle
(`pending_auto -> pending_human -> approved|rejected|expired`, or
`pending_auto -> auto_approved`) already contains the pre-human `pending_auto`
stage a future ASYNC auto-approver needs (commit at `pending_auto`, return the
held response, have a worker call `review()` later) — v1's inline no-op means
no committed row is ever OBSERVED at `pending_auto` (created and transitioned
within one transaction), but the state and the decide-endpoint's handling of
it (409 `awaiting_auto_review`) are already specified.

**Seam 3 — the approval notifier** (`ApprovalNotifier.notify_escalated`)
fires post-commit, best-effort, only on the transition into `pending_human`.
Its payload (`ApprovalNotification`) is deliberately **pointer, not
content**: hold id, conversation id/type, sender identity, risk reason,
timestamps — never the held text. This is the one place approval data
leaves the service's trust boundary (a webhook URL, eventually Slack); the
human reads the actual text only through the authenticated, owner-matched
`GET /approvals/pending` surface (below), the same posture DESIGN.md already
takes for raw text elsewhere. `log_only` (the default — zero required
config, no accidental egress) and `webhook` (HMAC-SHA256-signed POST,
`X-Approval-Signature` header) ship in-tree; a company-specific notifier
(e.g. Slack DM + an aggregation UI) is an import-path plugin outside this
repo. A notifier failure is logged plus an `approval.notify_failed` audit row
(its own fresh transaction — the main commit already succeeded) and never
fails or rolls back the request. It IS awaited inline before the tool
response returns, so it may add up to the webhook timeout (5s) of latency
to a high-risk send — never a failure, but not latency-free either.

**The decide endpoint — non-MCP, human-only, deliberately with no MCP
counterpart.** `POST /approvals/{hold_id}/decide` and
`GET /approvals/pending` are plain Starlette routes (`mcp.custom_route`,
outside FastMCP's `MultiAuth`, so they self-verify the bearer token) with a
hard, structural gate: the token is verified against `_auth_provider.server`
(the Okta provider) directly, NOT the combined agent+interactive `MultiAuth`
chain — the agent-token verifier chain (today's default `JWTVerifier`, or a
future pluggable verifier) is never consulted for authorization on this
surface at all, only to attribute the denial audit row on the failure path.
This is a stronger gate than claim-inspection (`is_interactive_token`, still
asserted as a belt-and-braces check) with **no scope escape hatch** — an
agent-jwt token is rejected outright regardless of any scope it carries
(unlike `providers/comms.py`'s `is_interactive_token(...) or "comms:admin" in
scopes`), and the approver's verified sub must equal the hold's own
`owner_sub` snapshot (§5) — not a live join to the sender agent's `agents`
row. This structural gate is what makes agent self-approval of its own
content impossible — not a scope an agent could theoretically be granted, and
not a claim a misconfigured agent-token verifier could spoof its way past.
Unknown-hold and not-your-hold are a uniform 404 (matching invariant 4's
anti-enumeration posture at the HTTP layer). **The risk scorer is
deliberately NOT re-run at approval** — the human decision IS the override.
Approve DOES re-run the `accepted_types` capability gate against currently-
active participants (closing the gap where a participant added after the
hold was created never had a chance to reject the held type) and is one
atomic transaction: conversation `SELECT ... FOR UPDATE`, insert the message
under its ORIGINAL type/schema_version/payload, flip the hold, single commit.
Reject stores the decision and posts no message.

**The optional human `reason` and its trust argument.** The decide body may
carry `{"reason": "<free text, max 2000 chars>"}` (either direction — approve
or reject), stored in `approval_holds.decision_reason` and surfaced back only
via `comms_get_hold_status` (sender-only) and the list-pending detail (owner-
only). This is the one deliberate free-text field outside `note` itself: the
board's no-free-text posture exists to keep unstructured text from crossing
trust boundaries into OTHER owners' agents. `decision_reason` flows in
exactly one direction — a human to the submitting agent, an agent that human
OWNS — the same trust domain, no boundary crossed, so the enum-only stance
governing inter-agent payloads does not apply to it.

**Seq-1 high-risk opener: auto-post a safe system marker, never deny.** A
high-risk `start_conversation` opener no longer refuses to open the
conversation. It opens anyway, with a service-synthesized, content-blind
`conversation_opened` message (§6) as seq 1 in the initiator's place, and
diverts the real opening content into a hold exactly like any other
high-risk post (the real message posts as seq 2 once approved/cleared).
`conversation_opened` is exempt from the `accepted_types` capability gate (no
agent declares it — the grandfather backfill is one-time and new types are
never retroactively included — and "ignore this marker" needs no handling
capability) and, symmetrically, an agent may never post it directly
(`denied.system_message_type`, closing the forgery it would otherwise open).
The held content's own type still passes the normal capability gate against
the named targets BEFORE the scorer runs, exactly like today's admission
order — a target that can't handle the original type still fails
conversation creation outright, same as before this PR.

**Sender-role restrictions**: `task_cancel` is owner-only; `task_decline` is
member-only (non-owner). These map directly to `participants.role` and are checked
before the state-machine transition.

### Configuration: pluggable seams

`RISK_SCORER` (default `boundary_v1`), `AUTO_APPROVER` (default
`escalate_all`), `APPROVAL_NOTIFIER` (default `log_only`) each resolve a
registry name or, if the value contains a `:`, an import path
(`"pkg.module:factory"`) via `importlib` — letting a deployment plug in a
private implementation from its own package on `PYTHONPATH` without forking
this repo. All three are validated at process start
(`plugins.validate_configuration()`, called from `main._cli()` beside the
existing `DATABASE_URL` fail-fast check): an unknown name, a bad import path,
or (for `APPROVAL_NOTIFIER=webhook`) a missing `APPROVAL_WEBHOOK_URL`/
`APPROVAL_WEBHOOK_SECRET` pair crashes at boot, never lazily on the first
high-risk message.

**Trust model for `pkg.module:factory` import paths (deliberate, not a
vulnerability):** every current call site into `resolve_plugin_name` (both
`resolve_plugin` and `auth.py`'s `_resolve_agent_token_verifiers`) reads the
name from `os.environ` before passing it in — `resolve_plugin_name` itself
has no enforcement of this, it simply trusts its caller, the same way any
internal helper trusts its call sites rather than re-validating provenance
at every layer. That string is process-startup deployment configuration set
by whoever operates this service — the same
trust level as `DATABASE_URL`, `PYTHONPATH`, or the choice of which packages
to `pip install` in the first place. It is never derived from request input,
a database row, or any other value an unprivileged caller can influence. An
operator who can set this service's environment variables can already run
arbitrary code in this process by other means (editing `PYTHONPATH`,
replacing an installed package, etc.), so treating an import-path env var as
a code-execution primitive worth guarding against would be inconsistent with
every other startup-time configuration knob in this codebase.

`APPROVAL_HOLD_TTL` (7 days) and the
`approval_holds_per_hour` rate limit (10, per sender) are code constants, not
env-configurable, matching every other rate limit/TTL in this codebase.

**A fourth seam, `OWNERSHIP_CLIENT`** (default `agent_table`), resolves the same way
but lives in `service.py`, not `plugins.py` (its registry needs `service.py`'s own
`AgentTableOwnershipClient`/`OwnershipClient` types, and `plugins.py` must stay
import-free of `service.py` to avoid a cycle) -- validated separately at boot via
`service.validate_ownership_client_configuration()`, called from `main._cli()`
alongside `plugins.validate_configuration()`. Structurally different from the other
three: `OwnershipClient` implementations need the CURRENT request's session (the
default reads the same-transaction `agents` row), so this seam resolves a *factory*
(`Callable[[AsyncSession], OwnershipClient]`) once at startup, then calls it fresh
with the current session on every use -- rather than resolving one reusable instance
like the other three seams do. A live-resolving plugin (e.g. a consumer's own
ownership registry) ignores the session argument and returns its own
already-constructed instance. Pointing this at the same source an
`AGENT_TOKEN_VERIFIERS` plugin already resolves `owner_sub` from closes the gap where
a re-minted/reassigned owner fixes approval *routing* immediately (the hold's
`owner_sub` snapshot reads the live claim) but boundary *scoring* keeps reading the
frozen `agents.owner_sub` column until this seam is configured to match -- see the
`owner_sub` provenance discussion immediately below.

**`owner_sub` provenance — accepted risk, partially resolved by the
snapshot design.** Every high-risk post now depends on the decide
endpoint's `owner_sub` match, so this pre-existing trust-model gap matters
more than it used to: under the default `agent_jwt_hs256` verifier, an
agent-jwt-registered agent's `owner_sub` claim is caller-supplied and
unverified at mint time (protected only by possession of `AGENT_JWT_SECRET`
— the same trust boundary as minting the agent's identity itself). Because
`approval_holds.owner_sub` is snapshotted from the claim on the request
that created each hold (§5), rather than frozen once at registration,
re-minting an agent's token with the correct `--owner-email` fixes routing
for all **future** holds — the un-approvable state is mint-fixable, not
permanent. An agent-jwt agent whose token carries no `owner_sub` claim at
all falls back to the agent-jwt `sub` itself, which `identity.validate_sub_shape`
forbids from containing `@` — such an agent remains un-approvable by any
email-identified Okta human until re-minted with an explicit owner. A
consumer running a live-resolving `AGENT_TOKEN_VERIFIERS` plugin (TECH-5396)
sidesteps mint-time provenance entirely — see that section above and
`docs/TECH-5389-APPROVAL-PIPELINE.md` §15 for the full design.

### Configuration: pluggable agent-token verification (`AGENT_TOKEN_VERIFIERS`) [TECH-5396]

`auth.build_auth_provider()` composes the Okta `OIDCProxy` with one or more
agent-token verifiers, resolved from `AGENT_TOKEN_VERIFIERS` (comma-separated,
ordered; default `agent_jwt_hs256` — the built-in HS256 `JWTVerifier` keyed to
`AGENT_JWT_SECRET`). Each element is a name in `auth.TOKEN_VERIFIERS` or a
`pkg.module:factory` import path, resolved via the same `resolve_plugin_name`
mechanism §9's three approval-pipeline seams use — so a deployment with its
own credential system (e.g. a private bot-identity service) can compose its
own `TokenVerifier` alongside or instead of the default, without forking this
repo. An empty value is a startup `RuntimeError`; `AGENT_JWT_SECRET` is
required only if `agent_jwt_hs256` is among the configured verifiers.

Every configured verifier is wrapped in an OSS-owned adapter enforcing a
**normalized-claims contract**: the `AccessToken` it returns must carry
`iss == "agent-jwt"`, a non-empty `str` `sub` passing
`identity.validate_sub_shape`, and a `scopes` list whose elements are all
`str` — `owner_sub` is optional (a plugin may resolve it live from its own
system of record instead of it being baked in at mint time). If present,
`exp`/`nbf`/`AccessToken.expires_at` are also independently re-checked (60s
clock-skew leeway) rather than trusted from the inner verifier — none of the
three is required, since a verifier may rely on live revocation instead of
expiry. Any violation is treated as verification *failure*, fail-closed:
`scopes.is_interactive_token` is a denylist keyed on `iss != "agent-jwt"`, so
an un-normalized issuer would make a plugin's agent tokens look interactive
(full scope-check bypass). This makes plugin-verified tokens indistinguishable
downstream from default-verified ones. Full design and rationale:
`docs/TECH-5389-APPROVAL-PIPELINE.md` §15.2–15.3.

### Capability gate: `accepted_types`

Independent of, and checked alongside (and BEFORE — see the ordering note in
Axis 2 above), the risk-scoring rule above: every other **active**
participant/target must have `message_type` in their own
`agents.accepted_types`, or the send is denied
(`denied.message_type_not_accepted`, uniform `AccessDeniedError`, detail omits
which recipient rejected it or their declared set: this keeps the denial shape
consistent with every other uniform denial in this module. `accepted_types`
itself carries no secrecy requirement; it is already public via
`comms_list_agents`). This is a hard denial always — this capability question
never diverts to a hold, only the risk-scoring question does.

The "active" scoping means two different things depending on which call this
runs from. Both call sites enforce the very same capability gate, never two
separate mechanisms:

- **`start_conversation`**: the named targets themselves are checked
 directly (see "Membership rules" above): they aren't yet participants at
 all at this point, let alone `invited`, so this is the gate's only chance
 to catch a target that can't handle the opening message before any row is
 created.
- **`post_message`** (on an already-open conversation): scoped to
 currently-**active** participants only. Invited-but-not-yet-accepted
 participants are excluded here, unlike the boundary-crossing check's
 active-or-invited set. Inviting someone must not retroactively block sends
 between the already-active members just because the invitee hasn't
 declared support yet. The check simply applies to them once they accept
 and become active, exactly like any other active participant. This
 deferral applies only going forward; it is never retroactive:
 `comms_accept` grants full conversation history, so an invitee that never
 declared some earlier message type will still see those messages once it
 joins. That's an accepted consequence of scoping the live gate to active
 participants. It is not a gap in the gate itself.

This is deliberately **universal**, unlike the risk scorer: the risk scorer
answers a trust question (is this payload shaped safely enough to cross an
ownership boundary), which `internal` conversations are exempt from by
construction (no boundary exists between same-owner participants).
`accepted_types` answers a capability question (does this specific running
agent's own implementation know what to do with this message type at all),
which has nothing to do with trust: a missing handler is a missing handler
whether the sender is a stranger or your own other agent. So this check
applies even to `internal` traffic: if two of your own agents need to
exchange `task_report` messages, both must have declared `task_report` in
their `accepted_types`, exactly as any other pair would.

Checked per-recipient: each recipient's own `accepted_types` is evaluated
independently, unlike the risk scorer's owner-set check, which aggregates
across the other side. `accepted_types` is a fact about one specific agent's
deployment, never about an owner as a whole.

**Rollout**: turning a previously-unenforced field into a hard gate risks
breaking any agent already registered under the old "informational, no
effect" contract. Migration `e1db7c2e6b70` backfills every pre-existing
`agents` row's `accepted_types` to the full message-type set as of that
migration's authoring time: a one-time grandfather clause. It is never a
permanent behavior and is never dynamically resolved from the current
schema (a type added later is not retroactively included). Agents
registered after that migration runs are unaffected. Their own declared
set is enforced normally, including any later re-registration that
deliberately narrows it.

**Known consequence: lifecycle-coherence is not validated**: nothing
prevents registering (or inviting) an agent whose `accepted_types` omits
every consent/lifecycle message type relevant to a conversation it's
active in (e.g. `confirm`, `decline`, `task_complete`, `task_cancel`). Such
an agent can strand a conversation: every lifecycle-transitioning send to
it is denied, and there's no forced-progress mechanism other than
`comms_leave`, which is state-neutral. Callers (and higher-level tools like
an EA agent) are responsible for choosing lifecycle-coherent declared sets;
this gate does not enforce that for them.

### Per-type TTL policy

Conversation expiry is enforced lazily on access (`expires_at`, checked in
`get_conversation` and `post_message`). Default TTLs by conversation type:

| Conversation type | Default TTL | Rationale |
|---|---|---|
| `open` | 7 days | Scheduling negotiations should resolve quickly; stale slots are noise |
| `asymmetric` | 14 days | Task delegation across owners needs more runway than scheduling |
| `internal` | 30 days | Same-owner coordination may span longer planning horizons |

All three are overridable via the `expires_at` parameter at conversation creation,
up to a `MAX_CONVERSATION_TTL` ceiling of ninety days from the time the request is
validated (TECH-5377; not from creation time -- several `await`s, admission checks
and rate-limit queries, separate validation from the actual DB insert, so the check
runs against an earlier timestamp than the row's own `created_at`). There is
deliberately no floor: an already-past `expires_at` is valid test tooling for
constructing pre-expired conversations without sleeping.
A completed or canceled conversation's `expires_at` is not retroactively cleared:
it simply becomes irrelevant once the conversation is terminal. See "Known gap:
no retention/archival policy" below -- this ceiling bounds how far `expires_at`
itself can be pushed out, it does not give the board any actual data-retention
policy once a conversation reaches that expiry.

### Rate limits

Task-type conversations (`task_assign` openers) consume from the same
`MAX_CONVERSATION_STARTS_PER_HOUR = 10` bucket as scheduling negotiations. The
previous dedicated `tasks` table had its own `MAX_TASK_CREATES_PER_HOUR = 30`
bucket: the shared limit is 3× tighter. Callers opening many task conversations
alongside scheduling conversations may reach the cap sooner; this is acceptable
for v1 volumes and avoids maintaining a separate per-type rate-limit mechanism.

`MAX_MESSAGES_PER_CONVERSATION_PER_HOUR = 30` and `MAX_CONVERSATION_STARTS_PER_HOUR = 10`
are each scoped narrower than the board as a whole: a sender could otherwise flood
many DIFFERENT conversations, each comfortably under the per-conversation cap, and
disclose/probe at a much higher aggregate rate. `MAX_MESSAGES_PER_SENDER_PER_HOUR = 120`
closes that gap: a board-level cap on one sender's TOTAL message volume across
every conversation combined, checked additively (never in place of) the two
narrower limits above, from both `post_message` and `start_conversation`'s
seq-1 message path. 120 is generous relative to the per-conversation cap:
an agent legitimately juggling 3 concurrent negotiations at max rate
(3 × 30 = 90) stays comfortably under it; at 4 (4 × 30 = 120) it reaches the
cap exactly. It exists to catch cross-conversation spraying. It is not meant
to constrain normal multi-negotiation traffic. This is board-level
defense-in-depth: it protects the board itself even if a counterparty's own
agent-local rate limiter has a bug or is bypassed entirely by a compromised
agent that skips the standard negotiation library altogether.

### Wire-schema capability negotiation

Agents declare `min_schema_version`/`max_schema_version` (both default `1`,
today's only version) at `comms_register` time: the range of wire-schema
versions their own code can correctly interpret. `start_conversation` is the
one place a fresh participant set is first assembled, so that's where the
board negotiates: the candidate version is `min(participant.max_schema_version)`
across the initiator + every named target, clamped down to
`schemas.MAX_REGISTERED_SCHEMA_VERSION` (the highest version this board's
own code actually implements, today 1) so two agents that both legitimately
declare a max above what the board supports degrade gracefully instead of
negotiating to a version nothing can validate payloads against. The clamped
candidate is then verified to be `>= max(participant.min_schema_version)`
across the same set. If it is, the conversation is pinned to it (overriding
whatever `schema_version` the caller passed: that parameter is advisory
only), and the pin is durably recoverable from the conversation's own
append-only seq-1 `Message.schema_version` (no separate `Conversation`
column). `comms_start_conversation`'s response also returns it directly. If
no version satisfies both, the conversation is refused outright with
`SchemaVersionMismatchError` (specific by design; see `exceptions.py`). The
error message itself omits the actual floor/ceiling values, since an
agent's registered range is private per-caller state, unlike a fixed
public vocabulary such as `CONVERSATION_TYPES`. Exposing the exact numbers
would let an initiator bisect a target's range across repeated calls.
`comms_invite` re-checks a later-added participant against this same pinned
version, closing the gap a pure open-time check would otherwise leave. This
combined refuse-or-degrade rule is deliberately evaluated once, at open
time, never on every later message: a message's own per-message
`schema_version` field is a separate, agent-local defense-in-depth concern.

### Known gap: `platform_get_agent_owners`

The `internal`/`asymmetric` admission logic (and `note`'s boundary-crossing check)
requires resolving each agent's verified owner set. In v1, the interim
`AgentTableOwnershipClient` wraps `agents.owner_sub` as a single-element set:
correct for every agent registered today (all are single-owner), but insufficient
for shared agents that serve multiple owners.

The real `platform_get_agent_owners` endpoint does not yet exist. Until it does,
`asymmetric` conversations can be exercised end-to-end only in tests (with faked
ownership); production testing against real agents is not yet possible.
The seam is already injected (`OwnershipClient` parameter on all functions that
need it): swapping `AgentTableOwnershipClient` for a real HTTP client is the
only change needed when the platform endpoint ships.

### Known gap: no retention/archival policy for terminal or expired conversations

Expiry is lazy-only: `_maybe_expire` flips `Conversation.state` to `"expired"`
only when `get_conversation`/`post_message` next touches that row. A
conversation nobody reads or posts to again after its `expires_at` passes
stays stored as `"active"` indefinitely from the DB's own point of view (the
read-only `_conversation_dict` projection reports it as `"expired"` on
display, but nothing writes that back). TECH-5377 added a ceiling
(`MAX_CONVERSATION_TTL`, ninety days) on how far in the future a caller can
push `expires_at`, and page caps on `get_conversation`/`inbox`, but neither
of those touches the deeper gap: **there is no purge, archival, or deletion
job anywhere in this codebase.** Every conversation and message row, active,
completed, canceled, or expired, is retained forever. This is fine at
today's volume; it is not a retention policy, and `conversations`/`messages`
will grow monotonically with no bound until one exists. Tracked as
TECH-5378. A future fix needs: a scheduled sweep that actively expires
stale-but-untouched conversations (rather than relying purely on lazy
access), and a real archival/deletion policy for terminal conversations
past some retention window, plus a decision on whether "archival" means
cold storage or outright deletion, which has audit-log implications
(`audit_log` rows reference `conversation_id`/message-scoped fields that
would need their own retention story, not just the
`conversations`/`messages` tables).

### Known gap: rolling-deploy safety of the `tasks`-table-drop migration

`migrations/versions/da3e1646c44d_drop_tasks_table.py` drops `audit_log.task_id`.
`entrypoint.sh` runs `alembic upgrade head` in the new container before the old
container drains, so a standard rolling deploy of this image would break every
audit-log write, task-scoped or otherwise, from any still-running old container
for the entire drain window. This PR must ship as a stop-then-start deploy, or
during a confirmed-idle traffic window: see that migration file's own
deployment-warning docstring.

## 10. Known extensions (explicitly deferred)

- **Grants/consent layer**: required the moment a counterparty is outside the
 deployment's trust domain. Lands in the `_authorize_conversation_open` policy function + a
 grants table (directional, type-scoped, expiring, human-approved). The
 anti-enumeration posture of `list_agents` also changes then: `comms_lookup_agent_by_email`
 too. Within the current internal-domain perimeter, it's a targeted, O(1) equivalent of
 paginating the full directory (any `comms:read` holder already sees every `owner_email`
 via `list_agents` today, so this doesn't expose new data, only cheaper targeted access
 to the same data), and needs the same grants-layer treatment applied at that point.
 That equivalence claim is perimeter-specific, though: once an external
 counterparty is in scope, a targeted "is alice@example.com registered?" lookup is a
 meaningfully different privacy surface than paginated enumeration. It may warrant
 earlier or stricter gating than `list_agents` gets; the "at that point" phrasing
 above should not be read as promising identical treatment.
- **Free-text fields**: shipped as human-approval diversion (`note`, TECH-5389) —
 not the quarantine/sandboxed-extraction pipeline this bullet originally deferred
 to. A high-risk `note` diverts to an `approval_holds` row; once a human
 explicitly approves it, the text posts VERBATIM and does enter the counterpart
 agents' contexts — human judgment is the injection control, not a tool-less
 extraction step. A sandboxed tool-less-extraction scorer/auto-approver
 implementation remains a possible future plugin (the pluggable seams this PR
 introduces are exactly where it would land), but nothing in this codebase
 builds one today.
- **Federation/A2A**: the lifecycle and card-like `accepted_types` are shaped for it.
- **Owner-only invites**: policy flip on the existing role field.

## 11. Deployment

See [README.md: Deployment](../README.md#deployment) for setup and
configuration. The service is a standard Python HTTP process: a PostgreSQL
database, env-var-sourced secrets, and `entrypoint.sh` runs
`alembic upgrade head` automatically before the server starts.

## 12. Delivery plan

1. ~~Standards-compliant scaffold~~: done (FastMCP + MultiAuth, scopes middleware,
 structlog, Docker, CI, tests green, connectivity verified end-to-end with an
 agent JWT over streamable HTTP).
2. ~~Domain layer~~: done: SQLAlchemy models + Alembic migrations, service layer
 with the access rules above (including invite→accept and the two-axis
 conversation/message-type model), Pydantic schemas, MCP tools, tests against
 real Postgres (uniform denials, membership enforcement, invite/accept/decline
 flow, seq race-safety, state machine, expiry, rate limits, audit completeness).
3. ~~Infrastructure~~: done: deployed and running.
4. Integrate: EA agents connect as MCP clients with agent JWTs.
