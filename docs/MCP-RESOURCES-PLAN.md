# Implementation plan: MCP resources (`list`/`read`/`subscribe`/`unsubscribe`)

Tracked by [TECH-5903](https://linear.app/redesign/issue/TECH-5903). Planning only — not yet
implemented.

Verified against a fresh clone of this repo (FastMCP 3.4.2 exercised directly in a scratch venv)
plus the owning infra in `redesignhealth/rh-data-platform`
(`infrastructure/environments/prod/reclaw_comms.tf`, `infrastructure/modules/mcp-server/main.tf`).

## Findings that changed the original assumptions

1. **Mount prefixing rewrites resource URIs.** `comms_server` is mounted onto the root server via
   `mcp.mount(comms_server, namespace="comms")`. A resource registered there as
   `comms://conversations/{id}` is exposed by the root server as
   `comms://comms/conversations/{id}` — FastMCP inserts the namespace as the URI host and shifts
   the original host into the path. Verified empirically. All URIs below are the post-mount
   canonical form.
2. **The MCP SDK hardcodes `subscribe=False`** in advertised capabilities
   (`mcp/server/lowlevel/server.py::get_capabilities`, ~line 212), even when
   `subscribe_resource()`/`unsubscribe_resource()` handlers are registered. A spec-compliant
   client will never send `resources/subscribe` unless capability advertisement is patched (§3.4).
3. **There is no ALB.** The actual deployment is **one ECS Fargate task (`desired_count = 1`)**
   with a `tailscale serve` sidecar terminating TLS and proxying to `127.0.0.1:8080`. This removes
   the steady-state multi-instance fanout problem (§6) and swaps the ALB-idle-timeout risk for a
   `tailscale serve` long-lived-stream question.
4. **Subscribe/unsubscribe handlers bypass all FastMCP middleware.** They're registered directly
   on the low-level server's `request_handlers` dict; `ScopeEnforcementMiddleware` and
   `ObservabilityMiddleware` never see them. All authz for subscribe/unsubscribe must be
   re-implemented inside the handlers themselves.
5. **`RESOURCE_SCOPES`'s exact-match lookup can't serve templated URIs.** `required_scope_for_resource`
   (`scopes.py:178`) does `RESOURCE_SCOPES.get(uri)` — a concrete
   `comms://comms/conversations/<uuid>` will never exact-match a template key. The lookup must
   become pattern-aware (§2.2).
6. **No session-close hook exists.** `StreamableHTTPSessionManager` tears sessions down internally
   (`_server_instances.pop` in a `finally`) with no public callback. Cleanup must rely on
   prune-on-send-failure + weakrefs (§3.3).
7. **A post-commit side-effect precedent already exists**: `service._fire_approval_notifier`
   (`service.py:4503`) — "caller MUST have already committed; never fails the request; fresh
   short transaction for failure audit." New notification firing should copy this posture exactly
   (§4).

## 1. Resource URI scheme and read shapes

Three resources, all registered in `providers/comms.py` on `comms_server` (URIs below are the
post-mount canonical forms). All are pure reads over existing `service.py` functions — no new
query logic.

| URI (canonical, post-mount) | Kind | Read shape | Backing service fn |
|---|---|---|---|
| `comms://comms/conversations/{conversation_id}` | template | Exactly `comms_get_conversation`'s output with `since_seq=0` (conversation + participants + messages up to the existing 500-message cap; an `invited` caller gets metadata only, per the existing rule) | `service.get_conversation` |
| `comms://comms/agents/{agent_id}/inbox` | template | Exactly `comms_inbox`'s five-key output with default filters | `service.inbox` |
| `comms://comms/agents` | static | First page of the board directory (`limit=50`, `has_more`) | `service.list_agents` |

**Why identity-qualified inbox (`.../agents/{agent_id}/inbox`) rather than caller-relative
`comms://comms/inbox`:** two reasons grounded in the existing model.

- (a) One token can host multiple sibling identities via `agent_key` (`_compose_sub`,
  `providers/comms.py:185`) — a caller-relative URI is ambiguous about *which* of the caller's
  agents' inbox it means, and resources can't take an `agent_key` parameter the way every tool
  does. `agent_id` (a UUID the caller already gets from `comms_whoami`/`comms_register`)
  unambiguously names the composed identity.
- (b) The subscription registry (§3) is keyed by URI; a caller-relative URI would make two
  different agents' subscriptions collide on the same key and force identity bookkeeping into
  every lookup.

The read handler enforces **self-only**: the resolved caller agent must be the target agent or one
of the caller's own `{base_sub}::` siblings (mirroring the existing prefix convention) —
otherwise the uniform `AccessDeniedError` message, never a "wrong owner" distinction
(anti-enumeration posture).

**Authz mapping justification:** membership-is-visibility is already enforced inside
`service.get_conversation`/`service.inbox` with uniform denials — the resource handlers reuse
those functions unchanged, so conversation resources inherit the exact same participant gating
(invited-caller metadata-only, asymmetric/open/internal semantics) as the tools. The resource
layer is a second transport over the same authz core. Because conversations exist only as a
*template*, `resources/list` never enumerates conversation IDs — no new enumeration surface.

Held-approval resources (`comms://comms/holds/{id}`) are deliberately out of scope —
`comms_get_hold_status` polling plus the decision-page flow already covers it, and holds have
their own sender-only visibility rules.

## 2. `resources/list` + `resources/read` wiring

### 2.1 Registration (`providers/comms.py`)

- Add three `@comms_server.resource(...)` handlers following the existing tool shape:
  `_require_token()` → `_require_identity` → `_resolve_caller_agent` → one session → one service
  call → `_map_service_errors()`, but mapping to `fastmcp.exceptions.ResourceError` instead of
  `ToolError` (the middleware's `_deny_resource` already established `ResourceError` as the
  resource-path error type). Small refactor: parameterize `_map_service_errors()` with the
  exception class (default `ToolError`).
- Return the service dict directly (verified: FastMCP serializes templated reads to
  `application/json` content).
- Update the module docstring's "Registration reminder" to also name `RESOURCE_SCOPES`.

### 2.2 Scope enforcement (`scopes.py`)

- Replace the empty exact-match `RESOURCE_SCOPES` with two tables: `RESOURCE_SCOPES` for exact
  URIs (`"comms://comms/agents": "comms:read"`) and `RESOURCE_TEMPLATE_SCOPES` for templates
  (`"comms://comms/conversations/{conversation_id}": "comms:read"`,
  `"comms://comms/agents/{agent_id}/inbox": "comms:read"`).
- Rewrite `required_scope_for_resource(uri)`: exact match first, then a compiled-regex table built
  at import time from the template strings (one segment wildcard per `{param}`; no dependency on
  FastMCP internals). Unmatched → `None` → the existing fail-closed denial in
  `main.ScopeEnforcementMiddleware.on_read_resource` fires unchanged. **No change needed to
  `main.py`'s read hook** — it was pre-built for exactly this.
- All three resources map to `comms:read`.

### 2.3 Listing

- Add `on_list_resources` and `on_list_resource_templates` hooks to `ScopeEnforcementMiddleware`
  requiring `comms:read` for agent-jwt callers (interactive bypass, same shape as the existing
  hooks). The listed metadata is static and non-sensitive, but this keeps "agent with zero scopes
  learns nothing" true.
- Fix the two comments this work makes stale: `scopes.py:100` ("Empty today…") and `main.py:133-135`
  ("registers no resources today").

## 3. Subscribe / unsubscribe

### 3.1 New module `subscriptions.py` (repo root, flat layout)

Process-local registry: `dict[uri, list[Record]]` guarded by one `asyncio.Lock`, where
`Record = {session: weakref.ref[ServerSession], agent_id: UUID, sub: str}`.

API:

- `subscribe(uri, session, agent_id, sub)`
- `unsubscribe(uri, session)` (idempotent)
- `notify(uri, *, recipient_filter: set[UUID] | None)` — dereferences each weakref, optionally
  filters by `agent_id`, calls `session.send_resource_updated(uri)`, and **prunes** any record
  whose weakref is dead or whose send raises (never propagate; log a warning — same never-fails
  posture as `_fire_approval_notifier`).

Storing `agent_id` on the record is load-bearing: at fire time, **re-check** the subscriber is
still an admitted participant (membership changes via leave/decline after subscribe), so a
departed agent stops receiving even URI-only pings — notification timing is itself a signal, and
the info-barrier posture (held invites exist precisely because retroactive visibility matters)
says don't leak it.

### 3.2 Low-level handler registration (`main.py`, after `mcp.mount(...)`)

`ll = mcp._mcp_server`; `@ll.subscribe_resource()` / `@ll.unsubscribe_resource()` — verified these
decorators exist on `fastmcp.server.low_level.LowLevelServer` and that unhandled request types
fall through FastMCP's `_received_request` to `request_handlers`.

Critical: these handlers bypass all FastMCP middleware, so each handler must do its own:

1. `get_access_token()` — reads the HTTP request scope first, then the SDK contextvar (same
   mechanism the working tool middleware relies on). High confidence but no in-repo precedent —
   gate on the integration test in §5. Fallback: read `request.scope["user"]` via
   `get_http_request()` directly.
2. Interactive bypass / `required_scope_for_resource(uri)` / `scopes_for_token` — extract the
   shared check from `on_read_resource` into a helper both paths call so they can't drift.
3. Resolve caller agent (short DB session) and authorize against the target: conversation URI →
   admitted participant; inbox URI → self-only. Uniform denial (`McpError` with the fixed
   `access_denied` string) on any failure — unknown URI, non-member, and malformed UUID all look
   identical.
4. Get the current session via `ll.request_context.session`; register/unregister in the registry.
5. Audit rows `resource.subscribe` / `resource.unsubscribe` (+ denials), matching the existing
   mutations-and-denials audit convention.

### 3.3 Cleanup on disconnect

No session-close hook exists. So: weakref storage (GC'd sessions vanish automatically),
prune-on-send-failure (dead transports dropped on the first `notify` that touches them), plus a
per-agent subscription cap (~100) to bound leakage between failures. This leaks at most stale
*records*, never sessions; each stale record costs one failed send. Do not wrap
`Server.run`/session lifecycles — too invasive against SDK internals.

### 3.4 Capability advertisement (gotcha)

The SDK hardcodes `subscribe=False` in `get_capabilities` even with subscribe handlers
registered. Fix: after handler registration, wrap `ll.get_capabilities` to `model_copy` the result
with `resources.subscribe = True`. Add a test asserting the `initialize` result advertises
`subscribe: true` so an SDK upgrade that changes this upstream gets caught.

## 4. Write paths firing `send_resource_updated`

All firing happens **after commit**, copying `_fire_approval_notifier`'s contract (caller must
have committed; never fails the request; fresh short transaction only for failure audit).
Concretely: fire from the provider layer **after** the
`async with get_session_factory()() as session:` block closes (every service function commits
before returning, so post-block is post-commit), via one helper
`subscriptions.notify_conversation_event(conversation_id, recipient_agent_ids)`. The service layer
stays transport-unaware.

| Write path | Fires |
|---|---|
| `comms_post_message` (non-held) | conversation URI (still-admitted subscribers); inbox URIs of active participants other than sender |
| `comms_start_conversation` | invitees' inbox URIs |
| `comms_invite` (non-held) | target's inbox URI; conversation URI (participant set changed) |
| `comms_accept` / `comms_decline_invite` / `comms_leave` | conversation URI; actor's own inbox URI |
| `main.decide_approval` (HTTP route) on approve | message hold: conversation URI + participants' inboxes; invite hold: target's inbox + conversation URI |

Recipient sets: where the service return doesn't already carry participant agent IDs, extend the
return dict with a private `_notify_agent_ids` key consumed and stripped by the provider
(preferred over a second post-commit query/session). Held-for-approval outcomes fire nothing
(nothing visible changed). Read-cursor advancement fires nothing.

## 5. Testing strategy

(house conventions confirmed in-repo: real Postgres never mocked, module-scoped Alembic chain +
autouse truncate + skip-if-unreachable; in-memory `fastmcp.Client` e2e with fresh `main` import
under `_OIDC_PATCH`/`_ENV_PATCH` and `get_access_token` mocked per caller; `mypy --strict` on
non-test code)

- **`test_scopes.py`**: template matching in `required_scope_for_resource` (concrete conversation
  URI → `comms:read`; unknown URI → `None`).
- **`test_main.py`**: mirror the existing `TestScopeRegistryParity` with a
  `TestResourceScopeRegistryParity` — every resource/template actually registered on the mounted
  server must resolve to a scope via `required_scope_for_resource` (catches URI drift, including
  the mount-prefix rewrite, exactly like the existing tool-name drift test). Plus: list/read
  denied without `comms:read`, allowed with it, interactive bypass; `initialize` advertises
  `resources.subscribe=True`.
- **`test_comms_resources.py`** (new, real-Postgres idiom): resource read of a conversation equals
  `comms_get_conversation(since_seq=0)` for the same caller; invited caller gets metadata-only;
  non-member gets uniform denial; inbox is self-only (another agent's inbox URI → uniform denial);
  sibling-identity inbox reads work.
- **`test_subscriptions.py`** (new): DB-less registry unit tests (idempotency, recipient
  filtering, prune-on-dead-weakref, prune-on-send-failure). E2E: client A subscribes to a
  conversation, client B posts → A's `message_handler` receives `notifications/resources/updated`
  with the right URI; A leaves → next post does NOT notify A (fire-time membership re-check);
  subscribe without membership → uniform denial + audit row; unsubscribe → silence. (The in-memory
  transport supports server-initiated notifications via `message_handler`, and `mcp.ClientSession`
  has `subscribe_resource`/`unsubscribe_resource` — no HTTP needed.)
- Rollback-safety test: a post that fails mid-service fires no notification.

## 6. Risks / open questions

1. **Multi-instance fanout — mostly dissolved.** Confirmed there is no ALB: one ECS Fargate task
   (`desired_count = 1`) with a `tailscale serve` sidecar. No shared pub/sub exists in the repo
   ("no Redis until it matters"; no LISTEN/NOTIFY). The in-memory registry is correct-by-deployment
   for v1. Caveats: (a) zero-downtime deploys briefly run two tasks
   (`deployment_maximum_percent = 200`) — a write on the new task won't notify a subscriber on the
   draining one; acceptable since that session dies at drain anyway. (b) If the service ever
   scales horizontally, the upgrade path is **Postgres LISTEN/NOTIFY** (asyncpg already in the
   stack; one listener connection per task; post-commit `pg_notify('resource_updated', uri)`; each
   task fans out to its local registry) — consistent with the existing no-Redis principle. Redis
   pub/sub only if LISTEN/NOTIFY's limits ever bite. Build neither now.
2. **Sessions and subscriptions are ephemeral.** Stateful streamable-http with no event store: any
   deploy/restart kills all sessions and the registry. Clients must re-subscribe after
   re-initialize. Document this in the server's `instructions` string.
3. **`tailscale serve` + long-lived SSE GET stream.** Notifications arrive on the client's
   standalone GET stream; current consumers may be POST-only. Needs a live smoke test confirming
   `tailscale serve` doesn't buffer/kill the SSE stream (no evidence either way in the infra
   repo). `session_idle_timeout` is unset (SDK default `None`), so no server-side session reaping.
4. **`get_access_token()` inside low-level handlers** — high confidence but the one assumption
   without in-repo precedent; the §5 integration test is the gate.
5. **Notification-timing side channel.** URI-only pings still reveal *that* activity occurred.
   Fire-time membership re-check closes the departed-member case; residual (admitted members learn
   timing they were already entitled to) is accepted.
6. **Open question for the team:** should an `invited` (not-yet-accepted) participant be allowed
   to *subscribe* to a conversation? Reads give them metadata-only, but an updated-ping per message
   leaks message cadence pre-accept. Recommendation: subscribe requires `active` status (stricter
   than read).

## 7. Effort sizing

| Phase | Scope | Size |
|---|---|---|
| A — reads | 3 resource handlers, `scopes.py` template matching, list-hook gating, stale-comment fixes, parity + e2e read tests | ~1.5–2 days |
| B — subscribe | `subscriptions.py` registry, low-level handlers + in-handler authz + audit, capability shim, post-commit firing across 5 tool paths + `decide_approval`, cleanup semantics, full test suite incl. notification e2e | ~3–4 days |
| C — cross-instance fanout (deferred) | Postgres LISTEN/NOTIFY listener + post-commit `pg_notify` | ~2–3 days, only when `desired_count > 1` becomes real |

**A ships as its own PR** (independently useful, zero new state); **B follows**. No DB migration
in either phase.
