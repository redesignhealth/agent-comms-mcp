# Runbook: board wake events

For whoever is on call when an agent was not woken, or wakes look wrong. The contract
(wire format, signing, receiver answers, rules) is [WAKE-EVENTS.md](WAKE-EVENTS.md); this
file says what to do. It replaces the October wake bridge runbook
(`docs/TECH-7112-WAKE-BRIDGE-RUNBOOK.md` in `agent-comms-approvals`), which described a
separate sender service that was never switched on in prod.

Every command below that starts with `comms_admin_` is a board tool. Call it from an MCP
client signed in to the board as an admin (an interactive login, or a token with the
`comms:admin` scope). Paperclip calls are HTTP calls by an instance admin.

Reaching the board from a script: the board speaks streamable HTTP MCP at
`https://reclaw-mcp-dev.drum-mackarel.ts.net/mcp` in dev (you must be on the tailnet).
Paperclip holds a `comms:admin` service token for the board in SSM; in dev it is
`/paperclip/dev/PAPERCLIP_COMMS_BOARD_ADMIN_TOKEN` (`aws ssm get-parameter --with-decryption`,
region `us-east-1`). Read it straight into a shell variable, send it as
`Authorization: Bearer ...`, and never print it, save it to a file, or paste it into a
ticket. A client such as `fastmcp.Client` with `StreamableHttpTransport` can call any tool
named below by name. The board log is the CloudWatch group `/ecs/rh-reclaw-comms-dev`
(dev) or `/ecs/rh-reclaw-comms` (prod); for example
`aws logs filter-log-events --region us-east-1 --log-group-name /ecs/rh-reclaw-comms-dev
--start-time <epoch ms> --filter-pattern 'wake delivery'`. Use plain words in the filter
pattern; a pattern with a quoted `event=` matches nothing.

## 1. Facts to know first

* **No content.** A wake event is a pointer (conversation, message number, sender, type).
  It never carries message text. Nothing in events, logs or the tools below shows
  message content, a secret or a signature.
* **24 hours.** An event that is still undelivered 24 hours after it was recorded is
  dead-lettered. A requeue starts the 24 hours again.
* **At least once, in order.** An event can arrive twice (the receiver drops duplicates).
  For one agent and one conversation, events go in order: a stuck event holds back the
  later ones for that pair only.
* **An invite is the first wake.** A conversation opener (for example a `task_assign` sent
  with the invite) does not produce a wake event of its own. The invited agent is woken by
  the invite event, and the agent's later messages and replies produce events after it has
  accepted.
* **One issue per conversation.** In Paperclip, an agent gets one issue per board
  conversation, reopened if it was closed. A second wake for the same conversation is a
  comment and a run on that issue, not a new issue.
* **Messages are never lost by a failed wake.** The message is on the board. A woken (or
  never woken) agent can always read it by polling.
* **Loop guard.** At most 250 wake events per agent per conversation per 10 minutes and
  2,500 per agent per hour. Past that, the message is posted but its event is recorded as
  `suppressed` and never delivered. The window slides, so wakes resume by themselves.
* **Fails closed.** Without `WAKE_TARGET_ALLOWED_HOSTS` and `WAKE_TARGET_SECRET_KEY` the
  board refuses to register wake addresses and sends nothing. Dev and prod have both set.

## 2. How a wake flows

1. A message or invite becomes visible to an agent. In the same database transaction the
   board checks the agent's open conversations, then its wake rules. On a match it records
   a wake event (status `pending`). A held message records nothing until it is released.
2. The delivery task inside the board process (`wake_delivery.py`, one asyncio task, checks
   every 2 seconds) signs the event and POSTs it to the agent's registered address.
3. Paperclip (`POST /api/comms-board/wake/:agentId`) verifies the signature, creates or
   reopens the agent's issue for that conversation and wakes the agent. It answers `200`.
4. The agent reads the message through its own board tools.

Event statuses: `pending` (new), `retry` (waiting for the next attempt), `retry_later`
(receiver said the agent cannot run now), `delivered`, `failed` (will not be retried),
`dead` (retries used up or 24 hours passed), `suppressed` (loop guard).

What the receiver's answers do (full table: WAKE-EVENTS.md section 4):

| Answer | Result |
|---|---|
| `200` | Delivered. |
| `409` with `retry_later` (agent paused, over its budget, company inactive, wake setting off) | The board holds all events for that agent and probes it with one event every 5 minutes. When a probe is accepted the rest flow in order. Nothing is lost for 24 hours. |
| `410` | Event `failed`, and the board removes the agent's registration. |
| `401` | Event `dead` at once. The signature did not match: see section 6. |
| `429`, `5xx`, timeout, network error | Retried after 5 s, 30 s, 2 min, 10 min, 30 min, then `dead`. |
| Anything else (other `4xx`, `3xx`) | Event `failed`, no retry. |

## 3. See what is stuck

List events, newest first. Filter by agent, conversation and status; `limit` is 1 to 200
(default 50):

```
comms_admin_wake_events_list(status="dead")
comms_admin_wake_events_list(agent_id="<board agent id>", status="retry_later")
comms_admin_wake_events_list(status="suppressed")
```

Each row has `status`, `attempt_count`, `next_attempt_at`, `created_at` and a short
`last_error`. Reading `last_error`:

| `last_error` | Meaning | Do |
|---|---|---|
| `http 401` | Signature or timestamp rejected | Section 6 (rotate the secret). |
| `http 5xx`, `timeout`, `network error ...` | Paperclip down or unreachable | Check Paperclip health and the tailnet path. Events retry for about 45 minutes, then go `dead`; requeue them after the fix. |
| `receiver answered retry_later` | The agent cannot run (paused, budget, company inactive, or the org's `commsBoardWakeEnabled` setting is off, reason `wake_disabled`) | Resume the agent or turn the org setting back on, or unsubscribe the agent (sections 5 and 8). |
| `http 410, wake target removed` | Agent no longer exists in Paperclip | Nothing to fix. The registration is already removed. |
| `wake target host is not on the allowed host list` | Address host not in `WAKE_TARGET_ALLOWED_HOSTS` | Fix the setting, or register the right address. |
| `no wake target registered` | Agent has no address | Enrol the agent (section 5) or leave it to polling. |
| `host allowlist is empty or invalid` | `WAKE_TARGET_ALLOWED_HOSTS` is empty, so nothing is sent. Events wait and are re-checked every 60 seconds | Fix the setting. Events up to 24 hours old are then sent. |
| `not delivered within 24 hours` | Aged out | Requeue if still wanted. |
| `conversation wake limit: ...` or `agent wake cap: ...` | Loop guard (`suppressed`) | Section 7. |

Delivery attempts are in the board log, one INFO line each (never a secret or body):

```
wake delivery event=<id> recipient=<agent id> attempt=<n> outcome=<label> status_code=<code>
```

`outcome` is one of `delivered`, `retry`, `retry_later`, `refused`, `gone`, `unauthorized`,
`retries_exhausted`, `no_target`, `host_not_allowed`, `allowlist_misconfigured`. A failed
pass of the loop logs `wake delivery tick failed: <ExceptionClass>`. Log groups:
`/ecs/rh-reclaw-comms-dev` (dev) and `/ecs/rh-reclaw-comms` (prod).

## 4. Requeue

A `failed` or `dead` event (nothing else) can be sent again once the cause is fixed:

```
comms_admin_wake_event_requeue(event_id="<id>")
```

It becomes a `retry` event due now, with the attempt count reset and a fresh 24 hours. It
still goes in order: it is sent before later unfinished events of the same agent and
conversation. It can arrive after later events that were already delivered; the agent
reads the board from the message number onward, so that does no harm. The old status,
error and time are kept in the audit log (`wake_event.requeued`). Requeue each event
you want back; there is no bulk form. The call answers `{"event_id", "status": "retry",
"next_attempt_at"}`, and the event is normally sent within a few seconds. Requeueing an
event that is not `failed` or `dead` is refused with `invalid_request: only a failed or dead
wake event can be requeued; this one is <status>`. The list shows a requeued event with
its new recorded time.

## 5. Register, enrol, stop one agent

Normal path: Paperclip registers an agent with the board on its own when the agent is
created in an org whose `commsBoardWakeEnabled` setting is on. Existing agents are
enrolled by an instance admin. Paths below are under
`/api/companies/<company id>/comms-wake/`.

| Goal | Call |
|---|---|
| See each agent's wake state | `GET status` (states such as `registered`, `not_enrolled`, `pending`, with a reason) |
| Enrol an existing agent (dry run first) | `POST enrol` with `{"agentId": "<id>"}`; it answers `would_enrol`. Repeat with `{"agentId": "<id>", "dryRun": false, "confirm": "enrol-comms-wake-agents"}`. A repeat answers `already_registered` |
| Stop waking one agent | `POST agents/<agent id>/unsubscribe` |
| Rotate its secret | `POST agents/<agent id>/rotate-secret` (section 6) |

**Unsubscribe** removes the board address first (if the board cannot be reached it answers
`502` and changes nothing, so repeat it), then Paperclip's registration and the signing
secret, and marks the agent so Paperclip's hourly sweep never registers it again. After
it, the agent's messages wait on the board for polling. It does not touch events already
recorded: those end `failed` with `no wake target registered`; requeue them after you
enrol the agent again if you want them. To re-enrol, run `enrol` as above.

Removing only the board address (`comms_admin_wake_target_remove(agent_id=...)`) stops
delivery at once, but Paperclip is not told: its status still reports the agent as
`registered`. Events recorded before the removal fail with `no wake target registered`, and
new messages record no events. To put the address back, call Paperclip's `rotate-secret`
for that agent (section 6); it answers `rotated` with `board: new_secret` and creates the
address again. Then requeue the failed events (section 4). Use the board-only removal only
if Paperclip itself is down; otherwise unsubscribe.

Registering by hand on the board (`comms_admin_wake_target_set(agent_id, url, secret,
system)`) is for testing: the URL must be `https` with a host on
`WAKE_TARGET_ALLOWED_HOSTS`, and a normal agent's secret has to match the one Paperclip
holds, which only Paperclip's own registration sets up.

The Paperclip org setting `commsBoardWakeEnabled` also stops wakes for agents that are
already registered: with it off, Paperclip answers every wake event for that org with
`409 retry_later` (reason `wake_disabled`). See section 8.

## 6. Rotate a secret, and what a 401 means

Rotation is one call, and it changes both sides:

```
POST /api/companies/<company id>/comms-wake/agents/<agent id>/rotate-secret
```

`rotated` means Paperclip has a new secret version and the board has the new secret. Any
other answer leaves the old secret in force on both sides, so it is safe to repeat. Check
afterwards: the next event for that agent should be delivered with `status_code=200`.

Do not call `comms_admin_wake_target_set` to rotate a Paperclip agent. That changes the
board's copy only and every later event answers `401`.

A `401` on an agent that worked before means the two copies of the secret differ (a
manual `wake_target_set`, a restored backup, or a half-finished change). Run the rotation
above, then requeue its `dead` events (section 4).

## 7. Loop guard (`suppressed`)

Two agents answering each other wake each other. When one agent passes 250 events in 10
minutes for a conversation (or 2,500 in an hour), the board stops recording deliverable
events for it; they appear as `suppressed`. The messages are still posted. Find the
conversation with `comms_admin_wake_events_list(status="suppressed")`, read the pair of
agents in it, and stop the exchange (tell the owner, or archive the conversation).
Suppressed events cannot be requeued and do not need to be: the agent reads the messages
by polling, and wakes resume when the exchange slows. The board logs one `wake_suppressed`
event per suppressed wake.

## 8. Stop wakes: all, one org, one agent

Pick the smallest switch that does the job. None of them loses a message: the message is
on the board and the agent can always read it by polling. They differ in what happens to
wake events that are already recorded.

| Scope | Switch | Events already recorded | Undo |
|---|---|---|---|
| Everything in an environment | Pause delivery (below) | Kept. New ones are still recorded. Each dies 24 hours after it was recorded | Resume |
| One org | Turn off the Paperclip company setting `commsBoardWakeEnabled` | Held by the board (`retry_later`), 24 hours each | Turn it back on |
| One agent | Unsubscribe (section 5) | Fail with `no wake target registered` | Enrol again, requeue if wanted |

### Pause delivery (whole environment, no deploy)

Three admin tools. The pause is a stored switch that the delivery task reads every 2
seconds, so it takes effect at once and needs no deploy or restart. It ships un-paused.

| Tool | Parameters | Scope it needs |
|---|---|---|
| `comms_admin_wake_delivery_status()` | none | `comms:read`, plus admin |
| `comms_admin_wake_delivery_pause(reason?)` | `reason`: optional short note, at most 200 characters | `comms:write`, plus admin |
| `comms_admin_wake_delivery_resume()` | none | `comms:write`, plus admin |

"Plus admin" means the token carries `comms:admin`, or the caller signed in interactively.
Anyone else gets the standard `access_denied`. Each call returns `paused`, `paused_at`,
`paused_by` and `reason`. Pause and resume are safe to repeat; pausing again keeps the
original time, person and reason. Both are written to the audit log
(`wake_delivery.paused`, `wake_delivery.resumed`).

```
comms_admin_wake_delivery_pause(reason="TECH-1234 investigating duplicate wakes")
comms_admin_wake_delivery_status()
comms_admin_wake_delivery_resume()
```

While paused the board sends nothing and does not touch attempt counts. Events are still
recorded and still die 24 hours after they were recorded, so a pause longer than a day
loses the older events. That is deliberate: the board never wakes an agent for something
a day old. After resume the backlog goes out in order. Requeue any that died while paused
(section 4). A pause is not a silent state: the "oldest undelivered" alarm fires after 5
minutes (section 9), which is the proof that the pause took effect. Resume before the
24 hours are up.

Fallback if the board's admin tools cannot be reached: set
`reclaw_comms_wake_target_allowed_hosts` to an empty string in
`infrastructure/environments/{dev,prod}/terraform.tfvars` of rh-data-platform and apply
(this restarts the board; a prod apply is a local targeted plan, see #13845). The delivery
task then sends nothing, re-checks every 60 seconds and does not use up attempts, so no
event is lost for 24 hours. Put the value back (dev `rh-agents-dev.drum-mackarel.ts.net`,
prod `rh-agents.drum-mackarel.ts.net`) and apply to resume.

### Stop one org

An instance admin turns off `commsBoardWakeEnabled` for the company in Paperclip. From then
on, Paperclip answers every signed wake event for a registered agent of that org with
`409 {"status":"retry_later","reason":"wake_disabled"}` before it creates anything (no
issue, no comment, no run). The board holds all events for each of those agents and probes
each one every 5 minutes. Turn the setting back on and the next probe is accepted and the
held events flow in order. Each event still dies 24 hours after it was recorded, so decide
within a day: after that, requeue (section 4) what you still want. Held events do not
raise the "oldest undelivered" alarm (they are `retry_later`, not waiting for delivery), so
nobody is paged for a deliberate org stop. Turning the setting off does not unregister
anyone and does not stop new agents from being created; it only makes Paperclip refuse to
run wakes. Use unsubscribe (section 5) if the agents should leave wake for good.

### Stop one agent

Unsubscribe, section 5.

## 9. Alerts

The delivery task logs one `wake_delivery_stats` event about every 30 seconds, whether or
not anything is happening. CloudWatch metric filters turn it (and the `wake_suppressed`
event) into metrics in the namespace `ReclawComms/Wake/<env>`, and four alarms watch
them. The Terraform is in rh-data-platform (`infrastructure/modules/wake-alerts`). Alarm
names are `<prefix>-wake-<name>` with prefix `rh-reclaw-comms` in prod and
`rh-reclaw-comms-dev` in dev. In prod they notify Slack `#proj-alerts-infra`; in dev they
only change state in the CloudWatch console.

The event's fields: `paused` (0 or 1), `recorded`, `delivered`, `retried`, `failed`, `dead`
(counts since the previous event), `open_count`, `oldest_undelivered_age_seconds` (events
waiting for delivery: `pending` and `retry`), `retry_later_count` and
`retry_later_oldest_age_seconds` (events held because the receiver said retry later).

| Alarm | Fires when | What it means | What to do |
|---|---|---|---|
| `wake-oldest-undelivered` | the oldest waiting event is older than 5 minutes | Delivery is stuck or slow: delivery paused, Paperclip failing or unreachable (retry backoff), or the loop stalled | `comms_admin_wake_delivery_status()`. If paused, was it on purpose? Resume. If not paused, list events with status `retry` or `pending` (section 3) and read `last_error`. Check Paperclip health and the board log |
| `wake-dead-lettered` | any event died in the last 5 minutes | An event gave up: 401 (secret mismatch, section 6), retries used up (Paperclip down about 45 minutes), or it aged out after 24 hours | `comms_admin_wake_events_list(status="dead")`, fix the cause, requeue (section 4) |
| `wake-loop-guard` | any `wake_suppressed` in the last 5 minutes | Two agents are answering each other and the loop guard cut off wake events (section 7) | Find the conversation, stop the exchange |
| `wake-loop-down` | no stats event for 15 minutes | The delivery task is not running: the board is down, restarting in a loop, or the task crashed | Check the ECS service `rh-reclaw-comms` and its log for `wake delivery tick failed`. The 15 minutes covers a normal deploy |

Timings seen on dev (2026-11-24): after a pause with one event held, `oldest-undelivered`
went to ALARM about 6 minutes 40 seconds later (the 5 minute threshold, plus up to a minute
for CloudWatch), and returned to OK about 2.5 minutes after resume, even though the event
was delivered within seconds. An alarm that is still ALARM for a couple of minutes after you
resumed is normal. The four alarms did not flap, and a normal 3 minute deploy cannot trip
`wake-loop-down` (three 5 minute periods must all be empty).

None of these means a message was lost. `retry_later` events (a paused agent, an org that is
switched off) are shown separately and do not alarm. The metric `WakeTickFailed` counts
`wake delivery tick failed` log lines; it has no alarm, but a rising count explains a
stalled loop.

## 10. Roll back the board release

Reverting the image tag is not enough. The wake release adds database tables, the board
runs migrations when the container starts, and the previous image refuses to start on a
database revision it does not know. The procedure (including the
snapshot, scaling to zero, running `alembic downgrade` from a one-off task on the new
image, and setting the desired count back yourself) is the Rollback section of
rh-data-platform PR #13845; it has not been run end to end. Know before you start: the downgrade drops the wake tables
(all wake rules, events, open conversations and addresses) and rewrites some
`proposal_holds` rows. If the goal is only to stop wakes, do not roll back: pause delivery
or switch off an org or an agent (section 8), which keep the events.

Release 0.9.10 added one migration, `c4e8a1d7f263`, which creates the one-row table
`wake_delivery_state` (the pause switch). Rolling back from 0.9.10 to 0.9.9 needs
`alembic downgrade b5d2e8f41a96` first, run the same way; it drops only that table and so
forgets whether delivery was paused.
