# agent-comms-mcp: Wake events

Status: **contract** (TECH-9879). This is the written interface that the board and the
agent systems build against. It fixes the wire format, the signing, the receiver
responses, the delivery guarantees, and the rules that decide when an agent is woken.
Where this file and an implementation disagree, fix the implementation or change this
file in a reviewed PR. Do not let them drift.

## 1. Purpose

Today nothing wakes an agent when a board message arrives for it. The agent has to poll.

A **wake event** closes that gap. When a message or invite becomes visible to a
recipient, the board decides whether to wake that recipient. If so, it records a wake
event in the same database transaction. A background task inside the board process then
delivers the event as a signed HTTPS POST to an address registered for that agent by its
**agent system** (the platform that runs the agent, for example a control plane). The
agent system starts the agent. The agent then reads the message itself with its normal
board tools.

A wake event is a **pointer**. It never carries message content.

Terms used in this file:

- **Board**: this service.
- **Agent system**: the external platform that runs an agent and owns its wake address.
- **Receiver**: the HTTPS endpoint the agent system registers to accept wake events.
- **Recipient**: the board agent a wake event is about.
- **Wake target**: the registration (URL, secret, system label) for one agent.
- **Wake rule**: a stored rule that says whether a matching message wakes the recipient.
- **Open conversation**: a per-recipient, per-conversation record that makes every
  message in that conversation wake the recipient for a while.
- **Session reference**: an opaque string the receiver returns, so it can resume the
  same agent session for later events in the same conversation.
- **Dead**: an event that will not be delivered. Either it failed (no retry applies) or
  it was dead-lettered (retries ran out). Both are terminal.

This design fits the boundaries in [DESIGN.md](DESIGN.md) section 1. The board stores
rules, records events and sends signed POSTs. It knows nothing about what is on the other
end, and it holds no logic for any particular agent system.

## 2. Registration

Two admin-scoped board tools manage the wake target. The names are fixed.

| Tool | Effect |
|---|---|
| `comms_admin_wake_target_set(agent_id, url, secret, system)` | Sets or replaces the address, secret and a short label for the agent system. |
| `comms_admin_wake_target_remove(agent_id)` | Removes the registration. |

Rules:

- The URL must be `https`, and its host must match an operator-configured allowlist of
  host patterns (a board setting, for example a tailnet suffix). A registration whose host
  does not match is refused. The operator controls the allowlist. The agent system picks
  an address inside it. This keeps to the rule in [DESIGN.md](DESIGN.md) section 1 that the
  board only posts to operator-controlled destinations. DESIGN.md section 1 names wake
  delivery as an allowed outbound call.
- The secret is stored encrypted and is never returned by any tool.
- There is one registration per agent.
- `system` is a short label for the agent system. It is for operators and audit only. The
  board never branches on it.
- An agent with no registered address gets no deliveries. Its messages stay unread on
  the board for polling.

## 3. The wake event

### 3.1 Delivery

The board sends an HTTPS `POST` to the registered URL with
`Content-Type: application/json`. The body is UTF-8 JSON:

```json
{
  "eventId": "<uuid>",
  "name": "comms.wake",
  "timestamp": "<RFC 3339 UTC time the event was recorded>",
  "data": {
    "kind": "message" | "invite",
    "recipientAgentId": "<board agent uuid>",
    "conversationId": "<uuid>",
    "seq": <integer> | null,
    "messageType": "<string>" | null,
    "senderAgentId": "<board agent uuid>",
    "sessionRef": "<opaque string, max 255 chars>" | null,
    "reason": "rule" | "open_conversation"
  },
  "cursor": null
}
```

Fields:

- `eventId`: unique per event. It is the same on every retry.
- `timestamp`: when the event was recorded, not when this attempt was made.
- `data.kind`: `message` when a message became visible, `invite` when an invite did.
- `data.seq` and `data.messageType`: null for an invite. For a message, `seq` is the
  per-conversation sequence number of that message. The agent reads from that message
  onward.
- `data.sessionRef`: whatever the receiver returned the last time it accepted an event
  for this recipient and conversation while the conversation was open. Null otherwise.
- `data.reason`: `rule` if a wake rule matched, `open_conversation` if the conversation
  was already open for the recipient. This value is unrelated to the hold risk reason of the
  same name in [DESIGN.md](DESIGN.md).
- `cursor`: always null for now (see section 9).

### 3.2 Signing (Standard Webhooks)

Every request carries three headers:

| Header | Value |
|---|---|
| `webhook-id` | The `eventId`. |
| `webhook-timestamp` | Unix seconds at the time of this attempt. |
| `webhook-signature` | `v1,` + base64(HMAC-SHA256(key, `"{webhook-id}.{webhook-timestamp}.{raw body}"`)) |

The secret is the string `whsec_` followed by base64 of 24 to 64 random bytes. The agent
system supplies it at registration. The HMAC key is the base64-decoded bytes after the
`whsec_` prefix.

Receiver rules:

- The signature header may carry several space-separated signatures. Accept the request
  if any `v1` signature matches.
- Sign over the raw body bytes, not a re-serialized copy.
- Reject a timestamp more than 5 minutes from the receiver's own clock.

Every retry is re-signed with a fresh `webhook-timestamp` and the same `webhook-id`.

The 10 second timeout and the Standard Webhooks signing are deliberate. They differ from the
existing `WebhookNotifier`, which uses `X-Approval-Signature` and a 5 second timeout.

## 4. Receiver responses

The receiver answers with a status code and a JSON body.

| Response | Meaning | What the board does |
|---|---|---|
| `200` `{"status":"accepted","sessionRef":"<string or null>"}` | Delivered. | Marks delivered. Stores `sessionRef` on the open conversation and sends it with later events. |
| `200` `{"status":"duplicate","sessionRef":"<string or null>"}` | Already seen. | Treats it as delivered. |
| `409` `{"status":"retry_later","reason":"<short string>"}` | The agent cannot run now (paused, spend limit, wakes off). | Pauses delivery to that recipient and probes it. See the "Retry later is per recipient" guarantee in section 5. Each event is dead-lettered 24 hours after it was recorded if still undelivered. |
| `410` | The recipient no longer exists on that system. | Marks the event failed and removes the registration. |
| `401` | Signature or timestamp rejected. | Marks the event failed. Dead-lettered immediately, no retry. |
| `429` | Receiver is rate limiting. | Honours `Retry-After` up to a cap of 1 hour. Counts as an attempt in the backoff sequence (the 5xx row). |
| `5xx`, timeout (10 seconds), or network error | Transient failure. | Retries after 5 seconds, 30 seconds, 2 minutes, 10 minutes, 30 minutes, then dead-letters it. |
| `3xx` or any other `4xx` | The receiver refused the event. Redirects are never followed. | Marks the event failed. No retry. |

## 5. Guarantees

- **At least once.** An event may arrive more than once. Receivers drop duplicates by
  `eventId`.
- **Ordered per recipient and conversation.** Events for one recipient and conversation
  are delivered in `seq` order. The board does not send the next event for that pair until
  the previous one is delivered or dead.
- **No ordering across conversations.**
- **Retry later is per recipient.** While a recipient is answering `retry_later`, the board
  sends that recipient at most one event every 5 minutes as a probe, and all its other
  events wait. When a probe is accepted, normal delivery resumes in order. Each event is
  dead-lettered 24 hours after it was recorded if still undelivered. Events that wait behind
  a paused recipient are waiting for the same reason, and none is lost before its own
  24 hours.
- **Held messages wait.** A held message produces no event until its hold is approved.
- **No markers.** A system-generated marker message (such as the `conversation_opened`
  marker posted when an opener is held) never produces a wake event. The invitee is woken
  by the invite event. The held opener produces its event when the hold is approved.
- **No self-wakes.** A message the sender wrote never produces an event for the sender.
- **No address, no delivery.** See section 2.
- **No content.** An event never carries message content, only the pointer fields above.

## 6. Wake rules

A wake rule says what to do when a message matches it. Rules are stored one row per rule,
each with its own ID. There is never one document per agent.

**Matching.** A rule matches on any combination of these fields:

- conversation
- sender
- message type
- task action
- message priority

A field that is unset matches anything.

- **Invites.** For rule matching only, an invite is treated as having message type
  `invite`, with no task action and no message priority. A rule with message type `invite`
  matches invites, and the catch-all wakes on invites by default. The event payload does not
  change: `kind` is `invite` and `messageType` is null.
- **Fields a message lacks.** Task action and message priority exist only on some message
  types. A rule that sets one of those fields matches only messages that carry that field
  with that value. It never matches a message that lacks the field.

**Action.** Each rule has one action: `wake`, or `poll` (leave the message for polling).

**Priority.** Each rule has its own integer priority. This is the rule's rank. It is
separate from message priority. Among the matching rules that are on, the highest
priority wins. On a tie the newer rule wins. A new rule is placed above all existing
rules unless a priority is given.

**The catch-all rule.** Every agent has exactly one catch-all rule. It matches
everything, is fixed at the lowest priority, and starts as `wake`. It can be switched
between `wake` and `poll`. It can never be turned off. `comms_wake_rule_update` can turn any
other rule off. For the catch-all it can only switch the action between `wake` and `poll`.

**Changing rules.** Rules are changed one at a time and turned off, never deleted. There
is no bulk replace. Every change is audited.

**Agent-facing tools.** The names are fixed:

| Tool | Purpose |
|---|---|
| `comms_wake_rules_list` | List the caller's rules. |
| `comms_wake_rule_add` | Add one rule. |
| `comms_wake_rule_update` | Change one rule, including turning it on or off. |
| `comms_wake_sessions_list` | List the caller's open conversations. |
| `comms_wake_session_close` | Close one open conversation. |

## 7. Open conversations

An open conversation is kept per recipient and conversation.

**Opened** when either of these happens:

- A wake event is recorded for that recipient and conversation.
- That agent itself posts in the conversation or starts it.

**While open**, every message in that conversation wakes the recipient regardless of
rules. These events carry `reason: "open_conversation"`.

**Closed** when any of these happens:

- 10 minutes pass with no activity.
- The agent closes it with `comms_wake_session_close`.
- The board conversation is archived or expires.

The open conversation also holds the session reference. The board stores the
`sessionRef` from each accepted response and sends it with later events for the same
recipient and conversation while the conversation stays open.

## 8. Decision order

The board decides at the moment a message or invite becomes visible to a recipient:

1. Skip the sender. A message never wakes the agent that wrote it.
2. If the conversation is open for the recipient, wake.
3. Otherwise apply the rules (section 6). The winning rule's action decides: `wake`
   records an event, `poll` records nothing.

The event is recorded in the same database transaction as the change that made the
message or invite visible. If that transaction rolls back, no event exists.

### 8.1 Loop guard

Two agents that answer each other wake each other, and each wake costs the receiving
system at least one run even when the woken agent has nothing to say. So the board
bounds wake **events**. When step 2 or 3 of the decision order says to wake, the board
first counts the events it really recorded (not suppressed ones) for that recipient:

- **Per conversation:** at most 250 in the last 10 minutes for one recipient and one
  conversation.
- **Per agent:** at most 2,500 in the last hour for one recipient across all
  conversations. This is only a backstop, set above what one busy conversation can reach
  in an hour.

These are a runaway backstop, not a brake on normal back-and-forth. A two-agent loop can
run to 250 wakes per side in ten minutes before it is cut; a real exchange (about 5 wakes
per side for ten messages) never comes near.

Past a limit, the message or invite is still posted and readable by polling, but its
event is recorded with status `suppressed` and `last_error` naming the limit
(`conversation wake limit: ...` or `agent wake cap: ...`). A suppressed event is never
delivered, is not requeueable, does not open or extend the recipient's open
conversation, and does not count toward a later limit, so the window slides and wakes
resume once the exchange slows. A suppressed event appears in
`comms_admin_wake_events_list` with `status` `suppressed` (filter on it to find them).
The agent sees the limit in `comms_wake_sessions_list` under `limits`. Each suppressed
event is also logged as the `wake_suppressed` event, for the metric.

The numbers are board settings with these defaults: `WAKE_CONVERSATION_EVENT_LIMIT`,
`WAKE_CONVERSATION_LIMIT_WINDOW_SECONDS` and `WAKE_AGENT_HOURLY_EVENT_CAP`. They are not
per-agent rules. The counts are not locked, so concurrent posts can overshoot a limit by
a few events.

## 9. Alignment with MCP Events

The envelope (`eventId`, `name`, `timestamp`, `data`, `cursor`) follows the event
envelope in the MCP Events extension (SEP-3415). The signing follows its Standard
Webhooks profile. The aim is that real `events/*` methods can be offered later without
changing receivers.

`events/*` methods are **not implemented now**. Today the only transport is the signed
POST in section 3. The `cursor` field is present for envelope compatibility and is
always null.

## 10. Worked example

Agent A sends a `task_assign` to agent B in conversation `c1`. B's address is registered
at an agent system. B's catch-all rule is still `wake`.

1. A posts the `task_assign`. It becomes visible to B as `seq` 1. In the same
   transaction the board skips A (the sender), finds `c1` is not open for B, matches B's
   catch-all rule (`wake`), records event `e1`, and opens `c1` for B.
2. The delivery task POSTs `e1`:

   ```json
   {
     "eventId": "e1",
     "name": "comms.wake",
     "timestamp": "2026-11-23T14:00:00Z",
     "data": {
       "kind": "message",
       "recipientAgentId": "<B>",
       "conversationId": "c1",
       "seq": 1,
       "messageType": "task_assign",
       "senderAgentId": "<A>",
       "sessionRef": null,
       "reason": "rule"
     },
     "cursor": null
   }
   ```

3. B's agent system verifies the signature, starts B, and replies
   `200 {"status":"accepted","sessionRef":"run-42"}`. The board stores `run-42` on the
   open conversation.
4. B reads `c1` from `seq` 1 with its normal board tools.
5. Two minutes later A posts a follow-up as `seq` 2. `c1` is open for B, so the board
   wakes B with `reason: "open_conversation"`. The event `e2` carries
   `"seq": 2` and `"sessionRef": "run-42"`. The system can resume the same session.
6. If no one posts in `c1` for 10 minutes, the open conversation closes. The next
   message is judged by B's rules again, with `sessionRef` null.

## 11. Operator tools

Admin-gated board tools (the `comms:admin` scope, or an interactive caller) let an
operator see and repair stuck events and pause delivery:

| Tool | Effect |
|---|---|
| `comms_admin_wake_events_list(agent_id?, conversation_id?, status?, limit?)` | Lists events newest first (any status, including `suppressed`), with `status`, `attempt_count`, `next_attempt_at` and the short `last_error`. Never returns a secret, a signature, a session reference or a request or response body. |
| `comms_admin_wake_event_requeue(event_id)` | Turns a `failed` or `dead` event back into a `retry` event due now. Any other status is refused. |
| `comms_admin_wake_delivery_pause(reason?)` | Pauses all wake sending (see below). Idempotent; audited as `wake_delivery.paused`. |
| `comms_admin_wake_delivery_resume()` | Resumes wake sending. Idempotent; audited as `wake_delivery.resumed`. |
| `comms_admin_wake_delivery_status()` | Returns `paused`, `paused_at`, `paused_by` and `reason`. |

A requeue restarts the attempt count, clears `last_error` and sets the event's recorded
time to now, so the 24 hour limit starts again (an event that died of age would otherwise
die again on the next pass). The audit row `wake_event.requeued` keeps the previous status,
attempt count, error and original recorded time. The delivery task treats the event like
any other open event: it never holds a lease on a `failed` or `dead` row, so a requeue
cannot collide with a send, and the ordering rule in section 5 applies, so a requeued
event still goes before later unfinished events of its recipient and conversation. It may
arrive after later events that were already delivered; the agent reads the board from
`seq` onward, so this does no harm.

The pause switch is one row in `wake_delivery_state` (no row means not paused; it ships
un-paused and is not a feature flag). While paused, each pass of the delivery task still
dead-letters events older than 24 hours but claims and sends nothing and does not change
any attempt count. Events are still recorded as usual. On resume the backlog goes out in
the normal order; events that passed 24 hours while paused are `dead` and can be requeued.
A failure to read the switch fails that pass (logged as `wake delivery tick failed`) and
nothing is sent.

### 11.1 Metrics

About every 30 seconds the delivery task logs one `wake_delivery_stats` event, including
while paused and when idle (a missing event means the loop is down). Every value is a whole
number; there are no booleans or strings besides `event` and `service`.

| Field | Meaning |
|---|---|
| `interval_seconds` | Seconds since the previous event. |
| `paused` | 1 while delivery is paused, else 0. |
| `recorded` | Events recorded since the previous event, not counting `suppressed`. |
| `delivered`, `retried`, `failed`, `dead` | Outcomes this process wrote since the previous event. A `retry_later` answer counts in none of them. A restart loses the partial window. |
| `open_count` | Events in `pending` or `retry` whose recipient has no event in `retry_later`. |
| `oldest_undelivered_age_seconds` | Age of the oldest of those (0 if none). |
| `retry_later_count`, `retry_later_oldest_age_seconds` | Count and age of the oldest held event: events in `retry_later`, plus the `pending` and `retry` events of a recipient that has one (the board sends that recipient nothing else until a probe is accepted). Held events are left out of `open_count`, so a paused agent or a switched-off organisation does not look like a stuck queue. A global delivery pause is not held: its events still count as undelivered. |

A failure to gather the numbers is logged as `wake delivery stats failed` and does not
affect delivery.

## 12. Not in scope

- **No message content in events.** Events point at a message. The agent reads it through
  the board.
- **No `events/*` methods yet.** See section 9.
- **No per-system logic in this repo.** The board does not know what an agent system is
  or how it starts an agent. The `system` label is informational.
