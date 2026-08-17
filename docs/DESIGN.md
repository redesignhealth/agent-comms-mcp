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
for interactive humans + `JWTVerifier` for headless agent tokens (HS256, `iss="agent-jwt"`).
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

Five tables. `messages` and `audit_log` are append-only: no UPDATE/DELETE paths in code.

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
**no free-text fields anywhere (except `note`, which is provisional/pre-quarantine pipeline)**. All types legal only in `state=active`.

| Type | `boundary_safe` | Payload | Semantics |
|---|---|---|---|
| `availability_request` | True | window {start,end}, duration_min, modality(video\|phone\|in_person), priority, constraints[] (enum-coded) | opens scheduling negotiation |
| `availability_response` | True | slots[{start,end,preference 0..1}] max 10, or none_available+reason | **`preference` is the product**: judgment crosses the boundary, never calendar data |
| `counter_proposal` | True | same slots shape | iterate on slots |
| `confirm` | True | slot {start,end} | transitions conversation → `completed`. Booking itself is EA-side |
| `decline` | True | reason (enum) | sets sender's participant status to `declined`. All non-owners declined → conversation `canceled` |
| `needs_clarification` | True | about_seq | pause signal. A human/EA needs to weigh in |
| `task_assign` | True | action (enum), scheduling params | opens task-coordination; structured spec, no free text |
| `task_report` | True | progress (enum), optional note_ref | non-terminal status update from assignee |
| `task_complete` | True | _(minimal)_ | transitions conversation → `completed` |
| `task_decline` | True | reason (enum) | member-only; transitions conversation → `canceled` |
| `task_cancel` | True | reason (enum) | owner-only; transitions conversation → `canceled` |
| `note` | **False** | text (string) | free-text note; pre-quarantine — provisional |

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
| `comms_start_conversation` | comms:write | type + up to 50 target agent UUIDs (from `comms_list_agents`) + initial request payload |
| `comms_post_message` | comms:write | typed, schema-validated, state-machine-checked |
| `comms_get_conversation` | comms:read | combined read: conversation + participants + messages since seq. Advances caller's `last_read_seq` when messages are returned and `max_seq` exceeds the current cursor. For an `invited` (not yet accepted) caller, returns metadata only: no messages |
| `comms_inbox` | comms:read | active conversations with unread messages, **plus pending invites awaiting accept/decline** |
| `comms_list_conversations` | comms:read | paginated conversation list, filterable by `role`, `type`, and `state`; both `invited` and `active` participant statuses included |
| `comms_accept` | comms:write | flips caller's participant status `invited → active`. Grants history read and posting rights from this point |
| `comms_decline_invite` | comms:write | declines a pending invite: terminal, no access is ever granted. Requires caller to currently be `invited`. Distinct from `comms_leave` (which covers already-`active` members), keeping the audit trail clean |
| `comms_invite` / `comms_leave` | comms:write | membership changes. `invite` adds a target as `invited` (not `active`). `leave` covers already-active members |

## 8. Security invariants

1. Owner identity derives from verified OAuth token claims, never parameters.
2. Judgments cross the boundary, never raw data (schemas have no field for it).
3. Typed, schema-validated payloads only. No free text except the
 provisional `note` type (`boundary_safe=False`, blocked in `open`
 conversations; pre-quarantine pipeline per §10).
4. Uniform denial messages. Existence of unauthorized resources is never revealed.
5. Append-only messages and audit. Every mutation and every denial is audited.
 A third category, bypass-observability, also audits privileged paths that are
 neither mutations nor denials: `agent.boundary_check_bypassed_shared`/`agent.conversation_open_bypassed_shared`
 (a `comms:admin`-authorized shared sender/initiator skipped the ownership-boundary
 check, §9) and `agent.reregister_is_shared_ignored` (a re-registration's requested
 `is_shared` diverged from the frozen row value and was ignored, §5). Unlike denial
 events (committed immediately by the denial helper), bypass-observability events
 are staged within the request's own transaction and are only persisted if that
 transaction ultimately commits. This is a deliberate consistency tradeoff shared
 by both bypass events: it makes no separate durability guarantee.
6. Fail-closed tool scoping: unenrolled tool is unreachable by agent tokens.
7. Rate limits per sender (30 messages/hour/conversation, 10 conversation-starts/hour),
 message size caps, participant cap (50 per conversation), and conversation expiry (7 days).

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

### Axis 2: message type → schema + `boundary_safe`

Each message type declares `boundary_safe: bool` independent of conversation type.
The flag gates legality within a conversation:

- `open` conversations require `boundary_safe=True` (raw scheduling data must
 never cross an owner boundary: only judgments do).
- `internal` conversations allow any message type (all parties are the same
 owner).
- `asymmetric` conversations allow `boundary_safe=True` always. `boundary_safe=False`
 is allowed only when the message does not cross an ownership boundary (sender's
 owner set must be a superset of all other active-or-invited participants' owner
 sets: an invited-but-not-yet-accepted participant's owner set was already
 validated against the owner snapshot at invite time, so including them here
 keeps the boundary check consistent with that snapshot invariant and closes a
 one-post gap that would otherwise persist until they accept), **except**: a shared sender (`agents.is_shared=True`) may post
 `boundary_safe=False` messages in `asymmetric` conversations unconditionally,
 without the ownership-boundary check.

Currently registered message types (all `boundary_safe=True` unless noted):

| Type | `boundary_safe` | Semantics |
|---|---|---|
| `availability_request` | True | opens scheduling negotiation |
| `availability_response` | True | scored candidate slots (judgment, not calendar data) |
| `counter_proposal` | True | iterate on slots |
| `confirm` | True | transitions conversation → `completed` |
| `decline` | True | sender's participant → `declined`; all non-owners declined → `canceled` |
| `needs_clarification` | True | pause signal |
| `task_assign` | True | opens a task-coordination conversation; structured spec (action enum + scheduling params) |
| `task_report` | True | non-terminal status update from assignee |
| `task_complete` | True | transitions conversation → `completed` |
| `task_decline` | True | assignee-only; transitions conversation → `canceled` |
| `task_cancel` | True | owner-only; transitions conversation → `canceled` |
| `note` | **False** | free-text note (pre-quarantine pipeline; `internal` always; `asymmetric` only when no boundary crossed; blocked in `open`) |

**Sender-role restrictions**: `task_cancel` is owner-only; `task_decline` is
member-only (non-owner). These map directly to `participants.role` and are checked
before the state-machine transition.

### Capability gate: `accepted_types`

Independent of, and checked alongside, the `boundary_safe` crossing rule above:
every other **active** participant/target must have `message_type` in their
own `agents.accepted_types`, or the send is denied
(`denied.message_type_not_accepted`, uniform `AccessDeniedError`, detail omits
which recipient rejected it or their declared set: this keeps the denial shape
consistent with `denied.boundary_crossing`. `accepted_types` itself carries no
secrecy requirement; it is already public via `comms_list_agents`).

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

This is deliberately **universal**, unlike `boundary_safe`: `boundary_safe`
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
independently, unlike `boundary_safe`'s owner-set check, which aggregates
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

All three are overridable via the `expires_at` parameter at conversation creation.
A completed or canceled conversation's `expires_at` is not retroactively cleared:
it simply becomes irrelevant once the conversation is terminal.

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
- **Free-text fields**: allowed only behind a quarantine/review pipeline (sandboxed,
 tool-less extraction into typed messages). Raw text is stored for audit/human
 display but never enters a privileged agent's context.
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
