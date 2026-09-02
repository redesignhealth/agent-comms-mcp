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
never accepted as a parameter. **Exception:** `comms_admin_register` (§5) -- the one
deliberate, audited, on-behalf-of exception to this invariant, for a target that has
never authenticated to this board yet.

**There is no board-level permission layer.** Holding a valid scoped token is
admission: token issuance is the permissioned ceremony, and it happens upstream of this
service. Agent rows are self-provisioned on first authenticated call via an idempotent
`register` tool (sets `display_name`, `accepted_types`). The `status` column
(`active`/`suspended`) is an ops kill-switch, not an admission-decision input: it is
never consulted by `may_assign` or the pairwise ownership-boundary check. It IS
consulted, though, by a handful of specific write/read gates a suspended agent hits
directly -- see §5 for exactly which ones (TECH-5736 made this column live for the
first time; before it, nothing ever wrote `"suspended"`, so those gates were inert by
construction, not by design). It is set to `suspended` only by the
comms:admin-gated `comms_deregister_agent` tool (TECH-5736); re-registration writes
`"active"` on an already-`active` row, but is refused outright (`agent_suspended`) on
a currently-`suspended` one, rather than silently reactivating it -- there is no
reactivate tool, by design (see §5).

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

**Identity-fork and display-name collision guards (TECH-5736).** Because `agent_key`
is caller-chosen and easy to omit by accident, a caller who forgets it on a later call
would otherwise silently create a brand-new sibling row under the bare base identity
instead of erroring or re-binding the one they meant -- this is exactly the "Pepper
Pots overwrote Bond 007" failure mode inverted (a stray row instead of a clobber).
`register_agent` now refuses to create a new row when the caller's base identity
already owns at least one row under a *different* `agent_key` (including no
key at all), raising `identity_fork_detected`, unless the caller passes
`confirm_new_identity=True` to say explicitly "yes, this is a deliberate additional
identity." The existing sibling `agent_key`s are recorded server-side, in the audit
log only -- like `display_name_collision`'s colliding `sub`s below, they are never
included in the error message returned to the caller. Deliberately NOT filtered to
`status == "active"`: ALL siblings under a base identity count toward this check,
regardless of status. This closes a kill-switch bypass -- filtering to active-only
would let a caller suspend every existing identity under a base_sub (via
`comms_deregister_agent`) and then register a brand-new `agent_key` with the guard
silently skipped, since no *active* sibling would remain to trigger it. The
consequence is permanent: once any identity under a base_sub has ever been
registered and then suspended, every future new sibling under that base
permanently requires `confirm_new_identity=True`. There is no operator
remediation action that clears this condition -- deregistering a row doesn't
undo it; deregistering is what triggers it in the first place. `confirm_new_identity`
requires only the baseline `comms:write` scope, not `comms:admin`: it is not an
admission-decision input (unlike `is_shared`, directly below), and any caller
legitimately running multiple agents under one token needs to be able to register a
genuinely new sibling identity on purpose -- the guard it opts out of exists to catch
an *accidental* fork (an omitted/typoed `agent_key`), not to gate intentional
multi-agent registration behind an elevated scope.

Independently -- and NOT bypassable by `confirm_new_identity`, since it guards a
different invariant -- a new row whose `display_name` collides (case-insensitively)
with an existing ACTIVE row's `display_name` is rejected with `display_name_collision`
(the error message names only the fact of a collision, never the colliding `sub`s --
those are recorded server-side, in the audit log only, to avoid letting a
`comms:write`-only caller enumerate other agents' `sub`s by probing display names).
Both checks fire only when a genuinely new row is about to be created, never on
idempotent re-registration of an existing `sub` -- except that re-registration of a
`sub` that is currently `suspended` is refused outright (`agent_suspended`) rather
than silently reactivating it; see the `comms_deregister_agent` entry below for why.

Both guards are application-level read-then-insert checks in `register_agent`, but
they are backed asymmetrically at the DB level. The display-name-collision check's
`WHERE` predicate is backed by `idx_agents_lower_display_name_active`, a `UNIQUE`
partial index (`ON agents (lower(display_name)) WHERE status = 'active'`) -- so a
case-insensitive `display_name` collision among active agents cannot slip past a
race: two concurrent `comms_register` calls for the same `display_name` can both
pass the application-level check, but only one can commit, and the loser gets a DB
constraint violation instead of a silently-admitted duplicate. The sibling-identity
(fork) check's prefix predicate, by contrast, has no dedicated index backing it --
it accepts a sequential scan, given the table's expected size. An index was tried
and removed: `text_pattern_ops` only accelerates the plain two-argument `LIKE`
operator, not the `LIKE ... ESCAPE` form that SQLAlchemy's
`startswith(..., autoescape=True)` emits for this query, so a `text_pattern_ops`
index here was never actually effective, and was removed rather than kept as
dead weight. So `identity_fork_detected` remains
best-effort under concurrent registration load, not race-free: two concurrent
`comms_register` calls for the same base identity with different (or omitted)
`agent_key`s can both pass the check before either commits, each creating its own
sibling row. Acceptable for the threat model this ticket targets (an accidental,
sequential omission of `agent_key`), not a defense against an adversarial,
precisely-timed race.

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
 accepted_types text[] (max 20 types, 100 chars each; empty = accept
 every message type, including future ones -- the opt-out default),
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
 -- action-reuse convention: `approval.hold` is the single action name for
 EVERY divert-to-hold cause (`risk_reason` values `boundary_crossing`,
 `note_history_requires_approval`, `open_conversation`, and, per TECH-5786,
 `agent_requested`); the cause lives in `detail.risk_reason`, never a
 parallel action name per cause. `detail` always carries `hold_id`,
 `risk_reason`, `risk_scorer`, `message_type`; an `agent_requested` hold
 additionally carries `review_reason` (the sender's own text) and
 `scorer_risk_reason` (the injected RiskScorer's own verdict, omitted when
 it returned none, e.g. always in an `internal` conversation)
approval_holds id, conversation_id, sender_agent_id, target_agent_id (nullable
 FK to agents), kind(message|invite) (TECH-5735), owner_sub, message_type,
 schema_version, payload jsonb (the held content -- validated, insert-ready
 for `kind=message`; contextual info for the human reviewer for
 `kind=invite`), risk_reason, risk_scorer, status(pending_auto|pending_human|
 auto_approved|approved|rejected|expired), auto_approver,
 auto_decision(cleared|escalated), auto_decided_at, decided_by_sub, decided_at,
 decision_reason (free text -- see §9's trust argument), message_id UNIQUE
 (nullable FK to the resulting messages row -- `kind=message` only),
 expires_at, timestamps
 -- MUTABLE (status flips); a `kind=message` hold exists ONLY because the
 risk verdict was high-risk, so there is no separate `high_risk` boolean.
 `owner_sub` IS a snapshot -- taken from the sender's (or, for
 `kind=invite`, the INVITER's) verified `owner_sub` claim at hold-creation
 time (falling back to `agents.owner_sub` when the claim is absent), NOT a
 live join to the `agents` row: once agent-token verification becomes
 pluggable, a live-resolving verifier can change what `agents.owner_sub`
 means between hold-creation and decide-time, so the decide/list paths
 match against the hold's own snapshot (see §9). For `kind=invite`,
 `sender_agent_id` is the INVITER (not a message sender) and
 `target_agent_id` is the agent being invited; approval creates a
 `participants` row instead of a `messages` row (see §9 Axis 1's free-text
 invite-approval rule and models.ApprovalHold's class docstring)
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
 risk scorer (`plugins.BoundaryCrossingScorer.score`, via `_score_message_risk`
 — §9 Axis 2) queries the current row on every post, not a value cached at
 conversation-open time, so flipping `is_shared` takes effect retroactively on
 already-open `asymmetric` conversations for THAT check ONLY (`internal` never
 gets this bypass, so it is unaffected either way): correcting a
 wrongly-`False` agent to `True` immediately grants the boundary bypass on its
 existing `asymmetric` conversations, and correcting a wrongly-`True` agent
 back to `False` immediately withdraws it, mid-conversation. This retroactive
 effect is narrower than it may sound, though: `_authorize_conversation_open`'s
 pairwise-ownership admission (§9 Axis 1) — including its `internal`
 `is_shared` exclusion (TECH-5735) — runs exactly once, at conversation
 creation, so flipping the flag changes OPEN-time admission only for
 conversations opened AFTER the flip, never for ones already open. The invite
 gate (`_authorize_invite_owner_freeze`) is different: its owner-set
 equality/subset check is governed entirely by `Conversation.owner_snapshot`,
 frozen at open time, so THAT part is unaffected by the flag at any time — but
 its `is_shared` exclusion (TECH-5735, same rule as Axis 1) reads the
 TARGET's current `is_shared` value live, at invite time, not a value frozen
 at conversation-open. So correcting a target agent's `is_shared` from
 `False` to `True` after a conversation already opened does retroactively
 block that agent from being invited into it later, even though it does
 nothing to participants already admitted before the correction.
- `agents.status` (`active`/`suspended`) has always been part of the schema but,
 before TECH-5736, no code path ever wrote `"suspended"` -- `comms_deregister_agent`
 closes that gap. It follows the identical admin-gate shape as `comms_set_agent_shared`:
 gated on the caller's `comms:admin` scope (or interactive/Okta caller), a caller
 without it gets `denied.deregister_requires_elevated_scope` (audit-log reason key
 only), and a successful transition is audited as `agent.deregistered` with the
 previous status in the detail. Idempotent (deregistering an already-suspended agent
 is a no-op write, still audited) and deliberately one-directional: there is no
 reactivate tool -- calling `comms_register` again for a suspended `sub` is refused
 (`agent_suspended`), not treated as a reactivation request (see §2). `status` still
 carries no *admission-decision* semantics (see §2) -- it is not read by
 `may_assign` or either ownership-boundary check -- but it IS now a live gate on a
 specific, narrow set of paths: a suspended agent cannot be the acting caller of
 `register_agent`'s re-registration branch (denied outright, above), cannot be the
 target of `start_conversation`/`invite` (pre-existing checks these guards made live
 for the first time), and drops out of `comms_lookup_agent_by_email`'s directory
 lookup. It is a full kill switch on the caller's OWN identity: `_resolve_caller_agent`
 (the helper the ten messaging/query tools use to resolve the CALLER's own board `Agent`
 row from the token) raises `agent_suspended` for any suspended caller, which blocks all ten tools
 that call it -- including the read-path tools, `comms_inbox`/`comms_get_conversation`/
 `comms_list_conversations`. A suspended agent's still-valid token cannot use ANY of
 them, read or write, even for a conversation it already belongs to: once
 `comms_deregister_agent` suspends an identity, that identity is fully cut off from
 acting on the board under its own name, which is the point of a kill switch. The one
 documented exception is `comms_deregister_agent` itself: its OWN caller authenticates
 via `_require_identity` (which only resolves the caller's `sub` from verified token
 claims, with no `agents.status` lookup at all), not `_resolve_caller_agent` --
 `comms_deregister_agent` looks up its TARGET agent directly by `agent_id`
 (`service._find_agent_by_id`), so a suspended agent is never the thing
 `_resolve_caller_agent` would need to resolve on this path. That means an admin whose
 own agent happens to be suspended can still deregister someone else; it is a
 deliberate, narrow exception (admin authorization here rides on the token's scope/
 interactive-caller status, not on the admin's own `agents.status`), not a bug.
- **On-behalf-of registration (`comms_admin_register`)**: `comms_register` always
 derives `sub` from the CALLING token's own verified identity (§4's "owner
 identity ... never accepted as a parameter" invariant) -- by design, nothing can
 register or claim an identity that isn't its own token's, even with `comms:admin`
 scope. That leaves a real gap: a platform provisioning a new bot (e.g. minting an
 Arc bot's board credential before the bot itself has ever spoken to this board)
 needs to set that bot's `is_shared` at first registration, and the only
 workarounds without a dedicated tool are both bad -- granting the bot's own
 permanent credential `comms:admin` (an ordinary bot has no legitimate reason to
 hold a scope that lets it register/re-authorize OTHER agents on this board --
 doing so turns every such bot's credential into a full admin-capability leak
 risk), or minting a throwaway token impersonating
 the target `sub` just to make one self-registration call. `comms_admin_register`
 (`service.admin_register_agent`) closes this properly: an explicit, audited,
 on-behalf-of FIRST registration for a `sub` other than the caller's own, gated on
 the identical `comms:admin`-or-interactive-caller check as
 `comms_set_agent_shared`/`comms_deregister_agent` (denied callers get
 `denied.admin_register_requires_elevated_scope`, audit-log reason key only).
 Structurally different from both existing tools: unlike `comms_register`, it is
 never an upsert -- `sub` must not already have a board row of ANY status, or it
 fails with `already_registered` (`exceptions.AgentAlreadyRegisteredError`,
 specific and client-safe: the caller supplied this exact `sub` on purpose, so
 confirming it's already registered discloses nothing new; audited as
 `denied.agent_already_registered`, `actor_sub` the PRIVILEGED CALLER); unlike
 `comms_set_agent_shared`, it is a genuine first registration, not a correction to
 an agent that already exists. Because the entire call already requires elevated
 authorization, `is_shared` itself needs no separate authorization check the way
 `comms_register`'s `is_shared=True` gate does -- there is no less-privileged path
 through this tool for it to escalate past.

 The sibling-identity-fork guard applies here too (Argus round 1, TECH-5786 PR
 follow-up) -- deliberately not omitted just because this is an on-behalf-of
 path: omitting it would reopen the exact kill-switch bypass §8 invariant 5 and
 `comms_deregister_agent`'s own docs (above) close (suspend every sibling under a
 `base_sub`, then admin-register a brand-new one to route around the
 suspension). `base_sub` here is derived from the TARGET `sub` itself
 (everything before its first `::`), not from the caller's own identity the way
 `comms_register` receives it. Denied with `identity_fork_detected`
 (`exceptions.SiblingIdentityExistsError`, audited as
 `denied.sibling_identity_exists`, `actor_sub` the PRIVILEGED CALLER) unless
 `confirm_new_identity=True` acknowledges the fork, same semantics as
 `comms_register`'s own parameter of the same name.

 **Accepted residual risk (Argus round 2, TECH-5786 PR follow-up):** because
 `confirm_new_identity=True` is now reachable through this admin surface (it
 was not, before this PR -- the provider layer never forwarded it), a
 `comms:admin` credential holder can still reconstitute access for a
 suspended `base_sub`: suspend every existing identity under it via
 `comms_deregister_agent`, then admin-register a brand-new `sub` under that
 same `base_sub` with `confirm_new_identity=True`. This does not defeat the
 guard's DEFAULT posture (an accidental fork is still caught), but a
 privileged caller can deliberately opt out of it, same as `comms_register`'s
 own self-service equivalent already allows for a caller acting on itself.
 Not detected or specially audited beyond the ordinary
 `agent.admin_registered` event (which does record `confirm_new_identity`) --
 revisit if `comms:admin` credential compromise becomes a live threat model
 concern for this board.

 `owner_sub`/`owner_email` are the one deliberate exception to §4's "never accepted
 as a parameter" rule on this tool, and only because there is structurally no
 alternative: there is no verified token for the target to derive them from (the
 target hasn't authenticated to this board yet -- that is the entire gap this tool
 closes), and this board's injected `OwnershipClient` seam is keyed by board
 `agent_id` (a UUID), which does not exist yet for a `sub` with no row -- it cannot
 resolve ownership for a not-yet-registered identity. The privileged caller
 supplies both directly, sourced from whatever ownership registry it already
 trusts for this `sub` (typically the same registry that minted the target's own
 board credential); this tool performs no verification of its own on them, the
 same trust contract `register_agent` already documents for its own token-derived
 equivalents.

 The row this tool creates is, once created, ordinary -- indistinguishable from
 one `register_agent` created directly. If the target later calls `comms_register`
 itself (its own, less-privileged credential), that hits `register_agent`'s normal
 RE-registration branch for the same `sub`: `is_shared` and `owner_sub` stay frozen
 exactly as they would for any other agent (a mismatched self-reported `is_shared`
 is ignored and audited as `agent.reregister_is_shared_ignored`, same as always) --
 this tool's admin-set values are not retroactively escalatable by the target's own
 later call. `owner_email` is the one field `register_agent` DOES overwrite on
 re-registration (see above) -- so a target's later self-registration can still
 move `owner_email` away from what this tool set, if its own token's claims (or
 `base_sub` fallback) disagree. This is not a new gap -- it is `register_agent`'s
 existing, already-documented `owner_email` mutability, unrelated to how the row
 was first created. A deployment relying on a stable admin-set `owner_email` should
 ensure the target's own later credential is minted with a matching `owner_email`
 claim. A successful on-behalf-of registration is audited as `agent.admin_registered`,
 with `actor_sub` set to the PRIVILEGED CALLER (not the target `sub`) -- unlike
 `agent.register`'s audit trail, where `actor_sub` is always the registering
 identity itself -- so the audit trail unambiguously records who registered which
 identity on whose behalf.

## 6. Message schemas (two-axis model)

Strict Pydantic (`extra='forbid'`), timezone-aware datetimes only, enum-coded reasons,
**no free-text fields anywhere except `note` and `instruction_share`'s doc-backed kinds**
(TECH-5822 — the latter's `kind`, not `text` itself, is drawn from a closed
`InstructionKind` enum; `text` is bounded by `max_length` and verified downstream
against a canonical per-kind hash, so it is bounded, pre-approved free text, not an
open channel). All types legal only in `state=active`.

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
| `instruction_request` | no | kind (closed `InstructionKind` enum) | a newly-onboarding/handed-off agent's request for one of a fixed set of startup/handoff instructions; no content, so not boundary-sensitive |
| `instruction_share` | **yes** | kind (`InstructionKind`) + exactly one of text (doc-backed kinds, 1-20000 chars) or link (link-backed kinds, `https://` URL, 1-2048 chars), per `kind`'s group | pre-defined instruction content, never arbitrary text; same posts-immediately-unless-crossing-a-boundary behavior as `note`. Content verified downstream (agent-comms-approvals' `RHAutoApprover`): doc-backed `text` against a canonical per-kind hash, link-backed `link` against a deployment-side allowlist — a mismatch always escalates to a human, never auto-clears |
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
| `comms_register` | comms:write | idempotent self-provisioning: display_name, accepted_types (optional, max 20/100 chars each; omitted/empty defaults to accepting every message type including future ones -- see §9's "Capability gate" section), min/max_schema_version (default 1/1, for schema-version capability negotiation); `is_shared=True` on first registration additionally requires comms:admin (see §5); rejects a new sibling row under the same base identity (`identity_fork_detected`) unless `confirm_new_identity=True`, and rejects a new row whose `display_name` collides with an existing active agent's (`display_name_collision`, not bypassable by `confirm_new_identity` -- DB-enforced race-free via a `UNIQUE` partial index, see §5) |
| `comms_set_agent_shared` | comms:write | admin override of an existing agent's `is_shared`, since `comms_register` freezes it against the agent's own re-registration; additionally requires comms:admin OR an interactive/Okta caller (see §5) |
| `comms_deregister_agent` | comms:write | sets an existing agent's `status="suspended"`; additionally requires comms:admin OR an interactive/Okta caller (see §5); one-directional by design -- no reactivate tool. Because it is one-directional, suspending an identity here is exactly what makes the sibling-fork check's "all siblings count, not just active ones" condition (see §5) trigger permanently for that base identity -- there is no reactivation path to undo it. This is intentional, to prevent kill-switch bypasses |
| `comms_admin_register` | comms:write | on-behalf-of FIRST registration for a `sub` other than the caller's own -- additionally requires comms:admin OR an interactive/Okta caller (see §5's "On-behalf-of registration" note). Distinct from `comms_register` (always self, idempotent) and `comms_set_agent_shared` (corrects `is_shared` on an agent that already exists): this is a genuine new-identity registration path for a `sub` that has never registered itself. Never an upsert -- fails with `already_registered` if `sub` already has a board row (any status) |
| `comms_list_agents` | comms:read | directory (internal domain, enumeration acceptable). Returns agent UUIDs used as target identifiers in other tools. A registry-retired agent (`ACTIVE_CHECKER` seam, TECH-5703, §"Configuration: pluggable seams") is excluded from results, though its row is never deleted; `total_count` still reflects every board-registered agent regardless of retirement status. Retirement is filtered AFTER pagination is computed from the raw rows, so a page can return fewer than `limit` agents (including zero) while `has_more` is still `true` -- callers must page until `has_more` is `false`, not until `agents` is empty |
| `comms_lookup_agent_by_email` | comms:read | directory lookup by owner email; `{"agent": ..., "found": bool}`. O(1) targeted equivalent of paginating `comms_list_agents` -- see §10's enumeration-posture note. A registry-retired agent resolves to the same not-found shape as an unregistered email (TECH-5703) |
| `comms_start_conversation` | comms:write | type + up to 50 target agent UUIDs (from `comms_list_agents`) + initial request payload. **Two response shapes** (TECH-5389): the normal conversation-created shape, or (if the opener was high-risk) that same shape plus a `held_for_approval`/`hold_id`/`hold_status`/`risk_reason` block (plus `decision_url` when `DECISION_PAGE_BASE_URL` is configured) — the conversation is created anyway, opened with a service-synthesized `conversation_opened` marker at seq 1, and the real content is held (§9). A registry-retired target (TECH-5703) raises a specific "agent retired" error instead of the uniform unknown-agent denial |
| `comms_post_message` | comms:write | typed, schema-validated, state-machine-checked. **Two response shapes**: the normal posted-message shape (unchanged; gains `auto_approved`/`hold_id` if a configured auto-approver cleared a high-risk send inline), or `{"held_for_approval": true, "hold_id", "conversation_id", "status", "risk_reason", "expires_at", "created_at"}` (plus `decision_url` when `DECISION_PAGE_BASE_URL` is configured) -- not an error -- when the send is diverted to a hold (§9). Optional `review_reason` (max 2000 chars, TECH-5786) forces the held shape unconditionally, overriding the `RiskScorer` verdict (including in `internal` conversations, which otherwise never reach a hold) -- the hold's `risk_reason` becomes `"agent_requested"`, distinct from every scorer-produced value so it can never be auto-cleared by an `AutoApprover` rule that special-cases `"boundary_crossing"`; the reason string itself is recorded in the audit log, not on the hold/status response |
| `comms_get_hold_status` | comms:read | poll a held message OR invite's approval status (`kind`: `message`/`invite`, TECH-5735); sender-only (uniform `access_denied` otherwise -- for an invite hold, "sender" is the INVITER). Returns status, risk_reason (this row names only the TECH-5786-relevant values -- `"boundary_crossing"`, `"note_history_requires_approval"`, and, per TECH-5786, `"agent_requested"` when the sender forced the hold via `comms_post_message`'s `review_reason` rather than a genuine scorer verdict; see §5's `audit_log` row for the complete set including `"open_conversation"`), timestamps, and (once decided) `decision_reason` plus, for `kind=message`, `message_id`/`message_seq` (present whenever `message_id` is set on the hold row -- only ever set at message-creation time on the approve/auto_approve path, never on reject/expiry), or for `kind=invite`, `target_agent_id` (always present, not gated on decision) and `participant_status` (present whenever a `Participant` row exists for the target, including a `rejected` hold whose target was admitted via a different path -- not gated on this hold's own decision). **Deliberately the only MCP-side surface for this pipeline** -- approve/reject/list-pending are non-MCP HTTP endpoints (§9), by design: an agent must never be able to approve its own high-risk content (or its own invite), so there is no MCP tool that could even attempt it |
| `comms_get_conversation` | comms:read | combined read: conversation + participants + messages since seq, capped at `MAX_MESSAGES_PER_GET_CONVERSATION` (500) per call. Advances caller's `last_read_seq` when messages are returned and the page's own max seq exceeds the current cursor. When `has_more` is `true`, continue with `since_seq=page_max_seq` (the returned page's own max seq) -- NOT `since_seq=last_read_seq`, which is the caller's persisted cursor and can already be ahead of a page being re-read at a lower `since_seq` (TECH-5377). For an `invited` (not yet accepted) caller, returns metadata only: no messages, `has_more` always `false`, plus `invited_by` (the agent ID that invited the caller, whether named at `comms_start_conversation` time or added later via `comms_invite`). `participants.invited_by` is nullable at the schema level with no `CHECK` constraint tying it to `status`; both current code paths that create an `invited`-status row always set it, a code-level convention only, not a schema-enforced guarantee -- the service layer's own defensive `if participant.invited_by else None` reflects that (Argus round-5 SUGGESTION: an earlier version of this row overstated it as unreachable) |
| `comms_inbox` | comms:read | active conversations with unread messages, **plus pending invites awaiting accept/decline**. Each list capped (`MAX_UNREAD_CONVERSATIONS_PER_INBOX`/`MAX_PENDING_INVITES_PER_INBOX`, both 100) with a `*_has_more` flag; `total_count` is always a true count, unaffected by either cap -- computed via a real `COUNT(*)` only when that half's own list was actually truncated, otherwise the (untruncated) list's own length already IS the true count. **Known gap**: no cursor -- if either cap is hit, there is currently no tool-level way to page through the remainder (`comms_list_conversations` filters by the CONVERSATION's state, not participant status, so it can't isolate just the overflowed set either) |
| `comms_list_conversations` | comms:read | paginated conversation list, filterable by `role`, `type`, and `state`; both `invited` and `active` participant statuses included |
| `comms_accept` | comms:write | flips caller's participant status `invited → active`. Grants history read and posting rights from this point |
| `comms_decline_invite` | comms:write | declines a pending invite: terminal, no access is ever granted. Requires caller to currently be `invited`. Distinct from `comms_leave` (which covers already-`active` members), keeping the audit trail clean |
| `comms_invite` | comms:write | adds a target as `invited` (not `active`); a registry-retired target (TECH-5703) raises the same specific "agent retired" error `comms_start_conversation` does. `internal` additionally never admits an `is_shared` target (TECH-5735, §9 Axis 1). **Two response shapes**, same convention as `comms_post_message`: the normal invited-participant shape (`conversation_id`, `target_agent_id`, `status`, `invited_by`, plus `auto_approved: true` + `hold_id` when an `AutoApprover` cleared an invite hold inline rather than this being the ordinary no-hold path), or — if the conversation already has any `note` or `instruction_share` history (`plugins.BARRIER_SENSITIVE_TYPES`, TECH-5735/TECH-5822) — `{"held_for_approval": true, "hold_id", "conversation_id", "status", "risk_reason", "expires_at", "created_at"}` (plus `decision_url` when `DECISION_PAGE_BASE_URL` is configured) (§9 Axis 1's free-text invite-approval rule) — admitting a new participant grants it full retroactive history read the moment it accepts, so that requires human approval first, same as a high-risk message does |
| `comms_leave` | comms:write | leave: covers already-active members |

## 8. Security invariants

1. Owner identity derives from verified OAuth token claims, never parameters.
2. High-risk content crosses an ownership boundary only via an explicitly-approved
 hold (human decision, or a configured auto-approver), atomically audited
 (TECH-5389). It is never silently posted and never silently dropped: a
 diversion always produces exactly one of `approved`/`auto_approved`
 (content posts under its original type), `rejected`/`expired` (content
 never posts), or `pending_human` (awaiting a decision). The same
 pipeline gates a second kind of hold, `kind=invite` (TECH-5735): a new
 participant is never admitted into a conversation with existing free-text
 (`note` or `instruction_share`, TECH-5822; jointly,
 `plugins.BARRIER_SENSITIVE_TYPES`) history without the identical explicit
 approval — never silently invited, never silently dropped, and approval
 creates the `participants` row (not a `messages` row) under the same
 three-outcome contract.
3. Typed, schema-validated payloads only. No free text except `note` and
 `instruction_share`'s doc-backed kinds (TECH-5822 — bounded by
 `max_length` and verified downstream against a canonical per-kind hash,
 not an open channel), which now post immediately when they don't cross a
 boundary and are held for human approval (never silently dropped, never
 denied for that reason alone) when they would (§9). Scorer INFRASTRUCTURE
 failure (an unscorable message) still hard-denies via `denied.risk_unscored`
 — it never floods
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
 check, §9 — `agent.conversation_open_bypassed_shared`'s `detail.bypass` is
 `"shared_initiator"` or `"shared_target"` depending on which side was
 shared; both admit identically, but only the shared-TARGET/RECIPIENT case
 also forces the per-message risk scorer to flag every send for review — see
 §9's shared-recipient rule), `agent.reregister_is_shared_ignored` (a re-registration's requested
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
| `internal` | all participants share identical verified owner sets, AND no participant is `is_shared` (TECH-5735 — see below; no exception either way — a shared initiator does not bypass this) | same-owner multi-agent coordination (e.g. CoS ↔ EA) |
| `asymmetric` | all pairwise owner-set intersections are non-empty, **except**: any pair where either side is `is_shared` (`agents.is_shared=True`) is exempted from that pair's intersection check (Argus round 2, TECH-5786 PR follow-up: PER PAIR, not a whole-conversation bypass — a multi-target open with one shared target and a second, unrelated non-shared target with disjoint owners still denies that second pair) | cross-owner task delegation where a shared agent bridges two users |

Ownership is resolved via an injected `OwnershipClient` seam. It is never read
from `agents.owner_sub` directly, since a shared agent's row can't represent
multiple owners. Fails closed on any lookup error -- `denied.ownership_unverified`
at conversation-open admission (both the lookup-exception and empty-owner-set
cases); at invite owner-freeze, TECH-5735 splits the same two cases into
`denied.ownership_lookup_failed` (exception -- transient) vs.
`denied.ownership_unverified` (empty owner set -- deterministic), so
`decide_hold`'s invite re-validation can tell a retriable registry outage
apart from a target that will never resolve on its own. The interim
`AgentTableOwnershipClient` wraps `agents.owner_sub` as a
single-element set: correct for every agent registered today. Swap it for the
real platform endpoint once shared agents exist.

**`internal` never admits an `is_shared` agent (TECH-5735).** `internal`'s
entire risk model (Axis 2, below) depends on "every participant shares one
owner set" staying true for the conversation's ENTIRE life, checked only once,
at open — there is no per-message re-verification. A shared agent's owner set
is a roster that can gain or lose members later; admitting one into `internal`
would let an equality check that was true at open time silently become false
afterward, with nothing left to catch it (`_authorize_conversation_open`
enforces this — `denied.shared_agent_not_allowed_internal` — and
`_authorize_invite_owner_freeze` enforces the identical exclusion at invite
time, so it can't be back-doored in after open). Re-checking ownership live on
every send was considered and rejected: it doesn't close the actual exposure,
which is at INVITE time (see the free-text rule immediately below), not at
each subsequent send.

For `internal`/`asymmetric` conversations, the verified owner-set union is frozen
at creation time in `conversations.owner_snapshot` (JSONB, nullable: `open` does
not use it). Subsequent invites are checked against this snapshot, with the
predicate matched to the type's own admission rule (TECH-5735): `internal`
requires the target's owner set to EQUAL the snapshot (the snapshot is a union
of already-equal sets, so equality to it is equality to every existing
participant); `asymmetric` requires only a subset. Unlike Axis 1's open-time
shared-target admission bypass, an `is_shared` target gets **no** exception
here (Argus round 1, TECH-5786 PR follow-up; rationale corrected in round 2):
`comms_accept` grants a new participant full RETROACTIVE read of every
message that PREDATES this invite. Messages sent from the invite onward are
NOT the gap — the risk scorer's shared-recipient rule already covers them,
since its "other" participant set includes `invited`, not just `active`,
agents (Axis 2, below), so interim traffic sent while a target is still
`invited` (between `start_conversation` and `accept_invite`) is scored
normally. The actual exposure a bypass here would reopen is the
conversation's PRE-EXISTING history, which no per-message check — before or
after this invite — can retroactively cover: a shared, disjoint-owner target
would read that history with no hold and no audit event, reopening the exact
per-invite exposure the free-text rule immediately below exists to close. An
invite that fails its predicate is denied, preventing unilateral de-isolation
of an `internal` conversation or a boundary-violating expansion of an
`asymmetric` one.

**Any invite into a conversation with existing free-text history — `note` or
`instruction_share` (TECH-5822; jointly, `plugins.BARRIER_SENSITIVE_TYPES`) —
requires human approval (TECH-5735), regardless of conversation type.**
`comms_accept` grants a new participant full retroactive read access to every
existing message the moment it accepts — including any `note` or
`instruction_share`, whose content is unstructured (or, for `instruction_share`,
verified only at send time against a specific canonical value, not re-verified
retroactively for a new reader) and can't be risk-scored the way ownership sets
can. A per-message check can never catch this, because the exposure isn't "a
new risky message was sent" — it's "someone new can now read messages that
were already fine to send at the time." So `invite` itself checks whether the
target conversation has ANY message of a `BARRIER_SENSITIVE_TYPES` type and,
if so, diverts to an `approval_holds` row (`kind="invite"`) instead of creating
the `Participant` row directly — same `held_for_approval`/`hold_id` shape
`comms_post_message` already uses, reusing the same `AutoApprover` seam (v1:
always escalates) and the same per-sender hold-creation rate limit. This gate
is deliberately driven by `plugins.BARRIER_SENSITIVE_TYPES` itself, not a
separately-maintained type list, so a future type joining that set can never
silently bypass it (TECH-5822 Argus round 1 BLOCKING: this check was briefly
hardcoded to `type == "note"` after `instruction_share` was added to
`BARRIER_SENSITIVE_TYPES` but before this invite gate caught up, exposing
unreviewed `instruction_share` text via an `internal` conversation's invite).
Approving creates the `Participant` row (`status="invited"`); rejecting
creates nothing. See `ApprovalHold`'s class docstring (models.py) for the two
hold shapes this produces, and Axis 2 below for the (separate, message-shaped)
hold pipeline this reuses.

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

- A non-sensitive type is never high risk on its own. For `open`/`internal`
 this skips the ownership lookup entirely (the cheap common path). For
 `asymmetric` it does NOT skip the lookup (Argus round 1, TECH-5786 PR
 follow-up): see the shared-recipient rule below, which must resolve every
 other participant's `is_shared` flag for EVERY message type, not just a
 sensitive one.
- `internal`: never high risk (no ownership lookup — TECH-5735 made this
 actually TRUE "by construction" rather than merely assumed: `internal`
 structurally excludes any `is_shared` participant at admission AND invite
 time — Axis 1, above — so the "one owner, forever" invariant this fast path
 relies on can no longer become false after open. An earlier design re-checked
 ownership live on every `internal` send instead; that was rejected as the
 wrong fix, because the actual exposure is at invite time, not at each
 subsequent send — see Axis 1's free-text invite-approval rule).
- `open`: a sensitive type is always high risk (no ownership lookup — `open`
 has no ownership concept).
- `asymmetric`: EVERY message (any type, not just a sensitive one — Argus
 round 1, TECH-5786 PR follow-up) first resolves every other participant's
 ownership-client record, to run the shared-recipient check below before
 any type-based short-circuit. Two `is_shared`-driven special cases are
 resolved BEFORE the ordinary superset comparison (sender's owner set must
 be a superset of every other active-or-invited participant's), in this
 priority order:

 1. **Shared RECIPIENT always forces review, for EVERY message type.** If
    ANY other participant (i.e. anyone in `other_agent_ids` — not the
    sender) is `is_shared=True`, the verdict is unconditionally
    `high_risk=True` (`reason="boundary_crossing"`,
    `detail={"reason": "shared_recipient"}`) — no ownership-set comparison
    is even consulted for that participant, and this is NOT gated on the
    message type being sensitive. This is the symmetric counterpart to the
    shared-sender bypass below, with the opposite effect: `is_shared` marks
    an agent that spans ownership boundaries (§5), so traffic reaching one
    is exactly the boundary-crossing traffic this scorer exists to flag,
    and Axis 1 (above) now admits that conversation-open case rather than
    denying it outright — the review this rule performs is what makes that
    admission safe (previously this only forced review for a sensitive
    type, letting `availability_request`/`task_assign`/etc. cross the
    boundary to a shared recipient with zero review). This check is
    checked FIRST and takes priority over the shared-sender bypass:
    **a sender that is itself shared does NOT get to skip review when
    sending to a shared recipient.** There is deliberately no
    "shared-to-shared" bypass — allowing one would let a shared sender
    launder traffic past a shared recipient's own review requirement, which
    would defeat the reason this rule exists in the first place.
 2. Once no other participant is shared, the `BARRIER_SENSITIVE_TYPES`
    filter applies as usual (a non-sensitive type is low risk, no further
    lookup), and for a sensitive type the pre-existing shared-SENDER
    bypass applies, unchanged: `agents.is_shared=True` on the sender skips
    the ownership-set lookup for the superset comparison unconditionally
    (`detail={"bypass": "shared_sender"}`, audited
    `risk.shared_sender_bypass`) — `asymmetric`-only, since `internal`
    admission never lets a shared initiator bypass its own pairwise check
    either.

 Because the shared-recipient check must inspect every other participant's
 `is_shared` flag regardless of the sender's own status OR the message
 type, the scorer now always resolves every other participant's
 ownership-client record for every `asymmetric` message — not just
 sensitive-type ones — and the shared-sender bypass no longer avoids those
 lookups entirely the way it used to; it only avoids folding their owner
 SETS into the superset comparison once none of them turn out to be
 shared.
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

**One exception to "only a genuine high-risk verdict diverts" (TECH-5786):**
`comms_post_message`'s optional `review_reason` parameter forces the same
divert path -- including in an `internal` conversation, the one case Seam
1 above never scores as high-risk on its own. This does not change Seam
1's own scoring rules above; it's a second, sender-initiated trigger for
the same `approval_holds` divert mechanism, recorded with a distinct
`risk_reason` (`agent_requested`, never emitted by the scorer itself) so
an auto-approver rule keyed on the scorer's own reasons can't mistake one
for the other. It is also exempt from Seam 2's auto-approver outcome:
an `agent_requested` hold always escalates to a human, structurally,
regardless of what the configured `AutoApprover` itself returns.

**Known gap**: the sender's `review_reason` text itself is recorded only
in `audit_log.detail` (§5), not on the `approval_holds` row -- the human
reviewer sees `risk_reason=agent_requested` in the normal pending-approvals
response, but not the agent's own explanation of why it asked for review.
Today that means querying `audit_log` (action `approval.hold`, this
hold's `conversation_id`) out-of-band to read it. Surfacing it directly on
the hold (a new column, or added to the pending-approvals response) is a
reasonable follow-up if this workflow sees real use; deferred for now
rather than expanding this ticket's schema footprint.

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
`escalate_all`), `APPROVAL_NOTIFIER` (default `log_only`), `ACTIVE_CHECKER`
(default `always_active`, TECH-5703 — see "A fifth seam" below) each
resolve a registry name or, if the value contains a `:`, an import path
(`"pkg.module:factory"`) via `importlib` — letting a deployment plug in a
private implementation from its own package on `PYTHONPATH` without forking
this repo. All four are validated at process start
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
alongside `plugins.validate_configuration()`. That boot check requires not just that
`OWNERSHIP_CLIENT` resolves, but that the resolved value is itself callable: a custom
plugin's configured factory must return a *second* callable
(`Callable[[AsyncSession], OwnershipClient]`), not an `OwnershipClient` instance
directly. Structurally different from the other
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

**A fifth seam, `ACTIVE_CHECKER`** (default `always_active`) [TECH-5703], resolves
the same way as the first three (a stateless, process-wide singleton via
`plugins.resolve_plugin`/`plugins.validate_configuration` — unlike `OWNERSHIP_CLIENT`,
it needs no per-request session, so it doesn't need that seam's factory-of-factories
shape). Answers one question per call, `is_active(sub) -> bool`: is this board agent's
owning registry still active? Consulted by `comms_list_agents`/
`comms_lookup_agent_by_email` (a `False` result excludes the agent from results —
`lookup_agent_by_email` folds it into the same not-found shape an unregistered email
gets, matching that tool's existing anti-enumeration posture) and by
`comms_start_conversation`/`comms_invite` (a `False` result on a named target raises
the specific `AgentRetiredError` — deliberately NOT folded into the uniform
`AccessDeniedError` denial the way an unknown/board-suspended target is; see that
exception's own docstring). The default `AlwaysActiveChecker` exactly preserves this
board's behavior before this seam existed — no filtering, no invite refusal — until a
deployment configures a real, registry-backed implementation via `ACTIVE_CHECKER`.
This board has no registry of its own; a real implementation is expected to be supplied
by whichever consumer deploys this board alongside an actual agent-ownership registry,
via the same `pkg.module:factory` mechanism the other four seams use. Design note: such
an implementation should reuse whatever cache its `OWNERSHIP_CLIENT`/
`AGENT_TOKEN_VERIFIERS` registry lookup already needs (TTL + negative-cache +
stale-serve-on-registry-unavailability), not stand up a second, differently-tuned cache
for this seam's slightly different question. This intentionally does NOT touch the
board's own `agents.status` column (`"active"`/`"suspended"`) — that column already has
its own dormant future-proofing (§5's note on `lookup_agent_by_email`'s filter being
inert today) and is a separate, board-local concept from an external registry's opinion
of a sub; this seam layers on top of it rather than driving it. Fail-open
contract: if `is_active()` raises (timeout, 5xx, bad auth against the
registry-backed implementation), the seam treats the target as active
rather than propagating the error (`service._is_active_safe`, logged at
`WARNING`) — a registry outage will not block directory reads or
conversation admission, it will only temporarily suspend retirement
enforcement (a retired agent may stay briefly visible/reachable). `list_agents`
also fans its per-row `is_active()` calls out concurrently via `asyncio.gather`
(up to `limit`, capped at 200, concurrent calls per page) rather than
sequentially — a real implementation must be safe under that burst width
(e.g. connection-pool-bounded), not built assuming one call at a time.

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

**Bounded-staleness ownership write-through + reconciliation [TECH-5593].**
`agents.owner_sub`/`owner_email` are kept as a deliberate CACHE of whatever a
consumer's own ownership system of record says, not re-derived fresh on
every read — the risk scorer and task-admission paths read them (via
`AgentTableOwnershipClient`, or a live-resolving `OWNERSHIP_CLIENT` plugin)
because a live external lookup on every message would be too slow/fragile
for a hot path. Left alone, that cache would only ever update if an agent
re-registers via `comms_register` — and even then, `register_agent`
deliberately freezes `owner_sub` against re-registration (see the provenance
discussion above), so nothing short of a fresh mint would move it. Two
mechanisms bound that staleness instead:

1. **Per-request write-through** (`service.write_through_ownership`, called
   from `providers.comms._resolve_caller_agent`). Not every tool call goes
   through this — `comms_whoami`, `comms_register`, `comms_set_agent_shared`,
   `comms_list_agents`, and `comms_lookup_agent_by_email` never call
   `_resolve_caller_agent` at all (registration establishes the row rather
   than resolving an existing one; the others don't need the caller's own
   row). It fires on the remaining ten tools that DO resolve the caller's
   own row to do their work (`comms_start_conversation`, `comms_post_message`,
   `comms_get_hold_status`, `comms_get_conversation`, `comms_inbox`,
   `comms_list_conversations`, `comms_accept`, `comms_decline_invite`,
   `comms_invite`, `comms_leave`) — so an agent that only ever calls
   `comms_whoami` in between reconciliation runs would rely entirely on
   mechanism 2 below, not this one. Where it does fire: if the
   caller's verified token carries `owner_sub`/`owner_email` claims that
   differ from the cached row, the row is updated in place and an
   `agent.ownership_write_through` audit row is written. Gated on
   `scopes.is_registry_backed_agent_token`: only trusted when the claims
   came from an operator-configured `AGENT_TOKEN_VERIFIERS` plugin OTHER
   than the built-in default (`auth.DEFAULT_AGENT_TOKEN_VERIFIER`) — both
   normalize `iss` to the identical `"agent-jwt"` value (see the normalized-
   claims contract below), so `iss` alone cannot distinguish a plugin's
   presumably-verified claim from the default verifier's caller-supplied,
   unverified one. `auth._NormalizingVerifier` stamps which configured
   verifier produced a token onto its claims (`auth.AGENT_TOKEN_VERIFIER_CLAIM`)
   specifically so this gate has something to check. This is the one
   sanctioned exception to `register_agent`'s freeze; it is never reachable
   from an untrusted claim.
2. **Out-of-band reconciliation** (`service.reconcile_agent_ownership`, exposed
   as `POST /admin/agents/reconcile-ownership`) for agents that make no further
   verified request after registration, so write-through above never fires for
   them. Excludes `is_shared=True` agents AT THE SQL LEVEL (a shared agent's
   owner SET doesn't map onto a single-valued cache column) and orders the
   remaining board-active agents by `owner_reconciled_at` ascending, NULLS
   FIRST, up to a batch limit (clamped server-side to
   `[1, service.MAX_RECONCILIATION_BATCH_SIZE]` regardless of what's
   requested) — NOT `bound_at`: `owner_reconciled_at` is a dedicated column
   this function stamps with `now()` on EVERY agent it actually looks up
   (whether or not `owner_sub` changed), specifically so a just-checked
   agent sorts to the back of the queue and repeated calls make real
   forward progress through the whole table instead of re-processing the
   same oldest page forever. Updates `owner_sub` wherever it has drifted
   from the configured `OWNERSHIP_CLIENT` seam and audits each change
   (`agent.ownership_reconciled`). Fails soft per-agent — one bad lookup is
   counted in the result and skipped (its `owner_reconciled_at` is still
   stamped, so a persistently-failing agent doesn't permanently block the
   cursor at the front of the queue, at the cost of only retrying it once
   per full sweep rather than every call), never aborts the whole run. Only
   reconciles `owner_sub` (`OwnershipClient` resolves identifiers, not email
   addresses). This repo has no
   in-process scheduler (see `_maybe_expire`'s TECH-5378 comment on the same
   gap for conversation expiry) — running this periodically is an operational
   decision, not something this endpoint makes for you. Auth: interactive
   (Okta) caller OR an agent-jwt token carrying `comms:admin` — intentionally
   wider than the approval-decide/pending routes' hard interactive-only gate,
   since this endpoint has no analogous self-dealing risk for an agent caller
   to exploit (it only triggers a read-then-conditionally-write pass against
   the platform's own configured ownership source, never a caller-chosen
   outcome).

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

**Opt-out, not opt-in (TECH-5822 follow-up).** `agents.accepted_types` is an
*empty* array by default: it means "accept every message type this board
knows about, including any added in the future" — not "accept nothing".
Passing a non-empty list is how an agent deliberately RESTRICTS itself to
that narrower, explicit set going forward; that is the exception, not the
default every agent must maintain. `comms_register`/`comms_admin_register`'s
`accepted_types` parameter is optional for exactly this reason — omitting it
(or passing `None`/`[]`) is the normal, common case.

Independent of, and checked alongside (and BEFORE — see the ordering note in
Axis 2 above), the risk-scoring rule above: every other **active**
participant/target must have `message_type` in their own
`agents.accepted_types` (or that agent's `accepted_types` must be empty), or
the send is denied
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
construction (no boundary exists between same-owner participants — TECH-5735
made this an actual structural guarantee, by excluding any `is_shared`
participant from `internal` at admission and invite time, rather than an
open-time assumption an already-admitted shared agent's roster could later
break — see §9 Axis 1/2). `accepted_types` answers a
different, capability question (does this specific running
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

**Rollout (v1, enforcement)**: turning a previously-unenforced field into a
hard gate risks breaking any agent already registered under the old
"informational, no effect" contract. Migration `e1db7c2e6b70` backfilled
every pre-existing `agents` row's `accepted_types` to the full message-type
set as of that migration's authoring time: a one-time grandfather clause. It
was never a permanent behavior and was never dynamically resolved from the
current schema (a type added later was not retroactively included) — which
is exactly the scaling problem the opt-out rollout below fixes.

**Rollout (v2, opt-out, TECH-5822 follow-up)**: `e1db7c2e6b70`'s "widen to
the full set as of migration time" grandfather clause does not keep pace with
new message types — every agent registered before that migration (and every
type shipped since) needed a fresh manual re-registration to pick it up, and
there is no admin bulk-update tool (`comms_register` always derives its
target from the caller's own verified token — DESIGN.md §4 — so only the
agent itself can update its own row). Migration `d5c8f1a2b4e7` converts every
pre-existing agent row whose `accepted_types` is EXACTLY `e1db7c2e6b70`'s
frozen 12-type set to the new empty-array "accept everything" sentinel —
targeted at rows that were never deliberately narrowed since that widening,
not a blanket reset. Any row with a genuinely custom (narrower, or
already-updated) set is left untouched: this migration only ever widens a
row that still looks exactly like the unmodified old default, never a row an
operator has since deliberately restricted. Agents registered after
`d5c8f1a2b4e7` runs get the new empty-array default automatically (no
migration involved) — see `comms_register`'s docstring.

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

Note that "single-owner" is not the same as "static," even in v1:
`write_through_ownership`/`reconcile_agent_ownership` (TECH-5593) already
update a registry-backed agent's cached `owner_sub` over its lifetime — the
element itself can change even though the set stays single-valued.

**Accepted residual gap (TECH-5735):** `internal` closes the multi-member
roster-drift case by excluding `is_shared` agents outright (Axis 1/2, above)
— but it does NOT re-verify equality if two ALREADY-admitted, both
NON-shared participants' `owner_sub`s are independently reassigned by
`write_through_ownership`/`reconcile_agent_ownership` after the conversation
already opened. That would silently break the equality invariant with
nothing to catch it, same as before TECH-5735, for this one narrower case.
Deliberately accepted rather than fixed by re-checking live on every send:
that was the design this ticket explicitly rejected (the real exposure is at
invite time, not at each subsequent send — see Axis 1's free-text
invite-approval rule — and a registry-driven owner reassignment of an
already-admitted, non-shared agent is treated as a rare administrative event,
not a live threat this scorer needs to defend against on every message).

**Accepted residual gap #2 (TECH-5735):** the `is_shared` exclusion above
screens at admission/invite time only — it does not freeze the flag.
`set_agent_shared` (an admin-gated mutation) can flip an already-admitted
`internal` participant's `is_shared` to `True` after the conversation
opened, silently breaking the same "every participant is single-owner"
invariant the exclusion exists to protect, with nothing to catch it after
the fact. Deliberately accepted for the same reason as gap #1 above: it is
a rare administrative event, not a live per-message threat, and closing it
would mean either a live recheck on every send (the design this ticket
rejected) or a guard in `set_agent_shared` itself refusing to flip the flag
while the agent holds an active `internal` participation — not yet
implemented.

**Accepted limitation (TECH-5735): invite-before-note ordering.** The
note-history gate in Axis 1's free-text invite-approval rule is evaluated
only at invite time, against history that already exists at that moment.
If a conversation has no `note` yet when a target is invited, the invite is
admitted immediately with no hold — and a `note` posted afterward grants
that already-admitted invitee full retroactive access via `comms_accept`,
with no approval ever having occurred for it. The gate only protects
history that predates the invite, not history added after. Closing this
would require either a note-posted-time check for any not-yet-approved
participant, or a join-time history filter — both larger changes than this
ticket's scope; not yet implemented.

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
- **`ACTIVE_CHECKER` ordering vs. the authorization gate**: in `start_conversation`,
 `_resolve_targets`'s retirement check (TECH-5703) runs BEFORE
 `_authorize_conversation_open`'s ownership-boundary admission check; in `invite`, the
 retirement check likewise runs BEFORE `_authorize_invite_owner_freeze`. Either way, a
 caller not authorized to converse with/invite a target today receives the specific
 `AgentRetiredError` rather than the uniform `AccessDeniedError` it would get once a
 grants/consent layer exists. Within the current internal-domain perimeter this is
 inert (directory enumeration is already acceptable, so the ordering leaks nothing
 new) -- but this is exactly the kind of ordering dependency the grants-layer bullet
 above needs to revisit: once an authorization gate that MUST stay uniform is
 introduced, either move the retirement check (in both functions) to run after it, or
 fold retirement into the uniform denial for that gate specifically.

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
