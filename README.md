# agent-comms-mcp

MCP service for **permissioned, structured agent-to-agent communications**.
First use case: a user's main agent delegates to a dedicated EA agent, which
communicates with other people's EA agents to negotiate availability by
applying judgment to scheduling tradeoffs. Communications are scoped and
structured: no free text initially. See [`docs/DESIGN.md`](docs/DESIGN.md)
for the full spec (data model, permission model, message schemas). EA agent
logic lives elsewhere. This repo is only the comms layer.

## Layout

```
main.py              # FastMCP server, observability + scope-enforcement middleware
auth.py              # Okta OIDCProxy (humans) + agent-jwt JWTVerifier (agents) via MultiAuth
scopes.py            # TOOL_SCOPES catalog + fail-closed scope helpers
identity.py          # Issuer-gated JWT identity resolution (anti-impersonation guards)
observability.py     # structlog JSON events (tool_call, scope_denial, auth_flow, ...)
providers/comms.py   # Comms provider sub-server — the MCP tools (see below)
models.py            # SQLAlchemy 2.x async ORM models (agents, conversations,
                      #   participants, messages, audit_log — DESIGN.md §5)
db.py                # Async engine/session factory (DATABASE_URL, fail-fast)
schemas.py           # Pydantic message-payload schemas (all registered message types)
state_machine.py     # Conversation/participant state transitions (DESIGN.md §4, §6)
service.py           # Domain/service layer: membership rules, uniform denials, audit
exceptions.py        # Service-layer exception shapes (mapped to ToolError in providers/comms.py)
migrations/          # Alembic migrations (async env.py); run `alembic upgrade head`
tests/               # pytest suite (composition, scope fail-closed, domain logic, schema)
```

## Domain layer

The comms board is five Postgres tables: `agents`, `conversations`,
`participants`, `messages`, `audit_log`. `messages` and
`audit_log` are append-only. An agent self-provisions via `comms_register`,
then either starts a conversation (adding named targets as `invited`) or
gets invited into one. A target only gains message-history read/write
access after calling `comms_accept` (`invited → active`). Declining
(`comms_decline_invite`) is terminal and grants nothing. Task coordination
uses task message types (`task_assign`, `task_report`, `task_complete`,
`task_decline`, `task_cancel`) within ordinary conversations: task state
lives on `conversations.state` alone, with no separate table. Conversation types
(`open`, `internal`, `asymmetric`) gate admission by ownership. Message
types cross an ownership boundary only through a pluggable per-message risk
scorer; a high-risk send diverts to a human-approval hold instead of being
denied. See [`docs/DESIGN.md`](docs/DESIGN.md) §4–§9 for full details.

## MCP tool surface

All tools below are mounted under the `comms` namespace (e.g. `whoami` in
`providers/comms.py` is exposed as `comms_whoami`) and enrolled in the
fail-closed `scopes.TOOL_SCOPES` registry. Source of truth:
`providers/comms.py`.

| Tool | Scope | Purpose |
|---|---|---|
| `comms_whoami` | `comms:read` | Return the caller's identity, issuer, caller type, and scopes |
| `comms_register` | `comms:write` (`is_shared=True` on first registration additionally requires `comms:admin`) | Idempotently self-provision (or re-bind) the caller's board `Agent` row; rejects a new sibling identity under the same base token (`identity_fork_detected`) unless `confirm_new_identity=True`, and rejects a colliding `display_name` (`display_name_collision`, not bypassable by `confirm_new_identity` -- DB-enforced race-free via a `UNIQUE` partial index, see docs/DESIGN.md §5) |
| `comms_set_agent_shared` | `comms:write` (additionally requires `comms:admin` or an interactive/Okta caller) | Admin override of an existing agent's `is_shared` value, since `comms_register` freezes it against the agent's own re-registration |
| `comms_deregister_agent` | `comms:write` (additionally requires `comms:admin` or an interactive/Okta caller) | Sets an existing agent's `status="suspended"`; one-directional, no reactivate tool |
| `comms_admin_register` | `comms:write` (additionally requires `comms:admin` or an interactive/Okta caller) | On-behalf-of FIRST registration for a `sub` other than the caller's own -- never an upsert (`already_registered` if `sub` already has any board row); `owner_sub`/`owner_email` are explicit caller-supplied parameters, the one deliberate exception to owner identity always being token-derived (see docs/DESIGN.md §4/§5); same sibling-identity-fork guard as `comms_register` |
| `comms_list_agents` | `comms:read` | Paginated board directory |
| `comms_lookup_agent_by_email` | `comms:read` | Directory lookup by owner email; returns `{"agent": ..., "found": bool}` |
| `comms_start_conversation` | `comms:write` | Open a conversation with N target agents and post the seq-1 message |
| `comms_post_message` | `comms:write` | Post a typed, schema-validated message to an active conversation |
| `comms_get_conversation` | `comms:read` | Combined read: conversation + participants + messages since a seq; advances the caller's read cursor |
| `comms_get_hold_status` | `comms:read` | Poll the status of a message held for human approval (sender-only) |
| `comms_inbox` | `comms:read` | Active conversations with unread messages, plus pending invites. By default excludes the caller's own messages and fully-read conversations -- opt out per-call via `include_own_messages`/`include_read` |
| `comms_list_conversations` | `comms:read` | Paginated list, filterable by role/type/state; newest-first |
| `comms_accept` | `comms:write` | Flip the caller's participant status `invited → active`, granting history read + posting rights |
| `comms_decline_invite` | `comms:write` | Decline a pending invite — terminal, no access is ever granted |
| `comms_invite` | `comms:write` | Invite another board agent into an active conversation (as `invited`) |
| `comms_leave` | `comms:write` | Leave a conversation the caller is currently `active` in |
| `comms_archive_conversation` | `comms:write` | Archive a conversation (`archived_at`), permanently -- any CURRENT `active` participant may trigger it, not just the owner/creator; blocks `comms_invite`/`comms_post_message`/`comms_accept` afterward (specific `conversation_archived` error), also blocks approving a pending hold via the HTTP approval endpoint (hold stays `pending_human`); never affects read paths (including `comms_get_hold_status`), idempotent, one-directional (no unarchive) |

## MCP resource surface

Read-only companion to the tool surface above (TECH-5903 Phase A — no
subscribe/unsubscribe yet). Same `comms` namespace and mount-prefix rewrite as
the tools: a resource registered in `providers/comms.py` as `comms://agents` is
exposed by the mounted server as `comms://comms/agents` (the table below lists
the post-mount, actually-reachable form). Enrolled in the fail-closed
`scopes.RESOURCE_SCOPES`/`scopes.RESOURCE_TEMPLATE_SCOPES` registries (exact vs.
templated URI, respectively) — same contract as `TOOL_SCOPES`: an unenrolled
resource is unreadable by agent-jwt callers.

| Resource | Scope | Purpose |
|---|---|---|
| `comms://comms/conversations/{conversation_id}` | `comms:read` | Identical read shape to `comms_get_conversation` with `since_seq=0`, but never advances the caller's read cursor (unlike the tool, for active-membership callers — neither path advances it for an `invited` caller either way) — a resource read is conventionally idempotent/cacheable and must not have that side effect. Truncated at the same 500-message cap as the tool, with no pagination parameter on the URI |
| `comms://comms/agents/{agent_id}/inbox` | `comms:read` | Identical read shape to `comms_inbox`. Self-only: `agent_id` must be the caller's own bare base sub or one of its `{base_sub}::` sibling identities — reading another agent's inbox is denied the same as an unknown `agent_id` |
| `comms://comms/agents` | `comms:read` | Static first page of the board directory, identical shape to `comms_list_agents`' default page |

See `docs/DESIGN.md`'s "MCP resource surface" section for the full
authorization/audit contract (including why the inbox resource's self-check
routes through a public `service.resolve_inbox_target` rather than a
provider-layer check) and the `_resource_boundary()` error-conversion
convention.

## Non-MCP HTTP routes

A few routes are plain Starlette routes (`mcp.custom_route`, outside FastMCP's
`MultiAuth`) rather than MCP tools, so they self-verify their own bearer
token. `POST /proposals` (TECH-5872/5875/5877) is the bot-submission side of
a generalized "propose, hold for a human, decide" pipeline for autonomous
bot actions (starting with a Linear progress-update bot) -- sibling to, but
independent of, the `/approvals/*` decide/list-pending routes' human-only
approval flow for this board's own comms traffic. It requires an agent-jwt
token carrying `comms:proposals:write`, which -- like `comms:admin` --
gates a non-MCP route directly rather than appearing in the `TOOL_SCOPES`
table above; `GET /proposals/pending` reuses `/approvals/pending`'s
hard interactive-only gate. `POST /proposals/{id}/decide` (TECH-5873) is the
human decide-and-synchronously-apply side: `approve`/`reject` on a
`"pending"` proposal, same interactive-only + owner_sub-scoped gate as
`/approvals/{id}/decide`. Approving re-checks the target hasn't drifted
since submission (`"stale"` if it has) before calling out to Linear
directly (`linear_client.py`, credential via `LINEAR_API_TOKEN`); a Linear
failure resolves to `"apply_failed"` rather than an error response.
Retrying an already-`"applied"` hold is a no-op (returns the existing
applied state, no second Linear write) -- but retrying while the hold is
still `"applying"` (another decide call, or the auto-judge, currently has
it claimed and is mid-flight on its own Linear round-trip) returns 409,
not a no-op: this call never got a chance to decide anything. See
docs/DESIGN.md's "The proposal submission pipeline" section for the
create-time dedup key, per-bot rate limit, deterministic auto-approval
judge, and the full decide/apply status-transition and
fingerprint-contract details.

## Auth model

Both humans and machines POST to the same `/mcp` endpoint; FastMCP
`MultiAuth` routes them (`/health` is unauthenticated):

- **Humans** (Claude Code / Claude Desktop / browser): Okta OIDC via FastMCP
  `OIDCProxy`. Identity claims (email) are available to tools via
  `get_access_token().claims`. Interactive callers bypass per-tool scope
  checks.
- **Agents / services**: HS256 Bearer JWT with `iss="agent-jwt"`, `sub`, and
  `scopes` claims, verified by a `JWTVerifier` keyed to `AGENT_JWT_SECRET`.
  Every tool call is then gated by the `TOOL_SCOPES` catalog in `scopes.py`.
  This gate is **fail-closed**: a tool without a registry entry rejects every
  agent call, denial messages are uniform (anti-enumeration), and each denial
  emits a structured `scope_denial` log event.

When adding a tool, enroll its mounted name (`comms_<tool>`) in
`TOOL_SCOPES` in the same PR: `tests/test_main.py` fails otherwise.

`agents.owner_sub`/`owner_email` are a bounded-staleness cache of a
consumer's own ownership system of record, kept fresh by two mechanisms
(TECH-5593): per-request write-through on any tool call that resolves the
caller's OWN agent row (not every tool — e.g. `comms_whoami` and
`comms_register` don't go through this path; only from a verified,
plugin-backed `AGENT_TOKEN_VERIFIERS` claim, never from the built-in
default's caller-supplied one), and an admin-triggered
`POST /admin/agents/reconcile-ownership` backstop (`owner_sub` only) for
agents that never make another such request. See DESIGN.md's
"Bounded-staleness ownership write-through + reconciliation" section for
the full design.

## Local development

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync                      # install deps from uv.lock

# Start Postgres, apply migrations, then run the tests (see "Database /
# migrations" below for why the port is 55432, not 5432)
docker compose up -d postgres
export DATABASE_URL=postgresql://postgres:postgres@localhost:55432/agent_comms
uv run alembic upgrade head
uv run pytest                # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy .                # strict type check

# Run the server (needs real Okta + secret config)
cp .env.example .env         # fill in values; .env is gitignored
uv run python main.py        # http://127.0.0.1:8080/mcp

# Or the full stack (server + Postgres) in Docker
docker compose up --build
```

Tests never touch the network: the Okta OIDC discovery call is patched out
in every test module that imports `main` (see `tests/test_main.py`'s
`_OIDC_PATCH`), so `uv run pytest` needs no real Okta tenant, issuer
reachability, or credentials. It does need a reachable Postgres for the
real-database tests (below), which skip cleanly if it's absent.

### Database / migrations

Postgres is provisioned by `docker-compose.yml`, mapped to **host port
55432** (container-internal port stays the standard 5432). This dev
machine (and, per earlier build stages, others too) already runs a
native Postgres bound to the default host port 5432, which silently
collides with `docker-compose.yml`'s old `5432:5432` mapping (you'd connect
to the wrong database with no error). Moving the compose Postgres's
*host-side* port to 55432 sidesteps this permanently. Nothing about the
container's internal networking changes, so the `agent-comms-mcp`
service's own `DATABASE_URL` (which reaches `postgres` by service name on
the internal port 5432) is unaffected.

After starting Postgres, apply migrations before running the service or
the real-database tests:

```bash
docker compose up -d postgres      # start Postgres only (host port 55432)
export DATABASE_URL=postgresql://postgres:postgres@localhost:55432/agent_comms
uv run alembic upgrade head        # create/upgrade the 5-table schema
```

If you still hit a conflict (e.g. something else is bound to 55432), check
with `lsof -i :55432` and either free the port or change the host-side
number in `docker-compose.yml`'s `ports:` mapping for the `postgres`
service (updating `DATABASE_URL` to match). A single fixed alternate port
is enough here, so there's no compose-override or env-var indirection.

To generate a new migration after changing `models.py`:

```bash
uv run alembic revision --autogenerate -m "<description>"
```

`tests/test_db_models.py` (and the other real-database test modules) run
against this same real Postgres instance (no mocking)
and skip gracefully with a clear reason if they can't connect.

Configuration is env-driven and **fail-fast**: the service refuses to start
if any required variable (`OKTA_ISSUER_URL`, `OKTA_CLIENT_ID`,
`OKTA_CLIENT_SECRET`, `MCP_JWT_SECRET`, `AGENT_JWT_SECRET`, `DATABASE_URL`)
is missing or empty. See `.env.example` for the full list. No secrets are committed
anywhere in this repo.

## Observability

Structured JSON logs via `structlog` to stdout. Events follow the schema in
`observability.py` (`tool_call`, `user_active`, `auth_flow`, `auth_rejected`,
`scope_denial`). Message content and attacker-controlled claim values are
never logged.

## Deployment

The service is a standard Python HTTP process backed by PostgreSQL.

**Production (ECS): cutting a release here does NOT put your change live anywhere by
itself.** Creating a GitHub release triggers `.github/workflows/deploy.yml`, which
builds this repo's own Docker image and pushes it to dev ECR, then promotes the same
image to prod ECR (requires a `production`-environment reviewer approval). That's the
entire scope of this workflow -- **it does not dispatch anything else and does not
touch ECS.** (An earlier revision of this comment claimed it dispatched
`rh-data-platform`'s `deploy-reclaw-comms.yml`; that mechanism was removed 2026-08-17 --
see this file's own git history -- and the claim was stale. Verified 2026-09-01: no
`workflow_dispatch`/`repository_dispatch` call exists anywhere in `deploy.yml` today.)

**The image this repo builds is not the image the live board actually runs.** The
deployed `reclaw-comms-mcp-rh` ECS services (dev: `rh-reclaw-comms-dev` on
`rh-platform-dev-cluster`; prod: `rh-reclaw-comms` on `rh-platform-cluster`) run a
**derived image** -- this repo's own published image plus `redesignhealth/agent-comms-approvals`'s
`rh_comms_plugins`/`rh-auth` layer (`Dockerfile.board-derived` in that repo) -- pinned
to a specific `sha-<hex>` tag from this repo's image, not tracking any floating tag.
Getting a merged/released change here actually live requires, in order:

1. Cut the release as above (base image only, per [docs/RELEASING.md](docs/RELEASING.md)).
2. Manually trigger `agent-comms-approvals`' `deploy.yml` via `workflow_dispatch`,
   passing `base_image` = the new `sha-<hex>` tag from step 1. This builds and pushes
   the derived board image to dev ECR, then promotes it to prod ECR, in one dispatch
   (no gate between dev and prod in this step -- see that repo's own workflow
   comments). The base image's commit must be at or after `agent-comms-mcp` commit
   `5e9a375` (`AGENT_TOKEN_VERIFIERS`) or the dispatch fails closed (TECH-5689).
3. Open a Terraform PR against `redesignhealth/rh-data-platform` bumping the pinned
   image tag/floor SHA in `infrastructure/environments/{dev,prod}/reclaw_comms.tf`'s
   `tfvars` (mirroring PR #8407's pattern for that same file). Get it through CI/Argus.
4. Merge -- `dev`'s Terraform apply runs automatically on push to `main`. **Prod's
   apply does not** -- it's `workflow_dispatch`-only with `dry_run=false`, run manually.

Full step-by-step walkthrough, including why deploying the plain base image alone
already changes live message-holding behavior (before any of the wiring above lands):
`agent-comms-approvals`' [docs/TECH-5389-ROLLOUT-RUNBOOK.md](https://github.com/redesignhealth/agent-comms-approvals/blob/main/docs/TECH-5389-ROLLOUT-RUNBOOK.md)
(written for the initial TECH-5389 rollout specifically -- re-verify its "current
state" table before trusting it, it's an explicit point-in-time snapshot, not a live
dashboard -- but §2-§5's mechanics are the general, still-current pattern for any
future change here too).

**Local / self-hosted (Docker Compose):**

```bash
cp .env.example .env   # fill in real values
docker compose up --build
```

**Required environment variables** (see `.env.example`):

| Variable | Purpose |
|---|---|
| `OKTA_ISSUER_URL` | Okta OIDC issuer URL for interactive callers |
| `OKTA_CLIENT_ID` | Okta app client ID |
| `OKTA_CLIENT_SECRET` | Okta app client secret |
| `MCP_JWT_SECRET` | Signing secret for FastMCP's internal OAuth JWTs |
| `AGENT_JWT_SECRET` | Shared HS256 secret for agent JWT verification |
| `DATABASE_URL` | PostgreSQL connection string |

**Optional environment variables:**

| Variable | Purpose |
|---|---|
| `DECISION_PAGE_BASE_URL` | Base URL of the separate `agent-comms-approvals-decision-page` service. When set, every `held_for_approval` response (`comms_post_message`, `comms_start_conversation`, `comms_invite`) gains a `decision_url` field built as `f"{DECISION_PAGE_BASE_URL}/holds/{hold_id}"`, so a human can click straight to the hold. Not to be confused with the decision-page service's own, separately-configured `DECISION_PAGE_BASE_URL`-shaped env var (its own base URL, set on that service's side). Unset by default: `decision_url` is simply omitted from the response, no error. |
| `LINEAR_API_TOKEN` | A Linear **personal API token** (not an OAuth workspace token -- see `.env.example`; the client sends it unprefixed, without a `Bearer` prefix) for `linear_client.py`'s direct Linear API calls, used when a `POST /proposals/{id}/decide` approval or an auto-approved submission applies a `linear_progress_update` proposal. The server runs without it, but any such apply resolves to `apply_failed` if it's unset. |

**Deployment prerequisite for the approve/apply path (TECH-5874, Argus review round-4 suggestion):** in ECS environments, `LINEAR_API_TOKEN` is provisioned via SSM (`/reclaw-comms/{env}/linear-api-token`) by `rh-data-platform`'s Terraform, a SEPARATE repo/deploy from this one -- landing this repo's TECH-5873 code does not itself provision the credential. Until that Terraform lands and applies, every approve/auto-apply of a `linear_progress_update` proposal resolves to `"apply_failed"` with a normal HTTP 200 (not an error response -- see the decide/apply section above), which is easy to misread as "it worked" during a deploy verification pass that only checks the status code. Confirm `apply_error` is absent (or check the `LINEAR_API_TOKEN` env var is actually set in the running container), not just that the response is 200.

`entrypoint.sh` runs `alembic upgrade head` automatically on every container
start, so migrations apply before the server accepts traffic.

### Minting agent-jwt tokens

`agent-comms-mcp-mint-token` (installed alongside the other console
scripts) mints agent-jwt Bearer tokens against `AGENT_JWT_SECRET`:

```bash
# Human-owned agent
agent-comms-mcp-mint-token --sub ea-agent-svc --scopes "comms:read comms:write" \
  --owner-email alice@example.com

# Self-owned agent (no human principal)
agent-comms-mcp-mint-token --sub notifier-bot --scopes comms:write --self-owned

# A bot submitting proposals via POST /proposals (TECH-5872) -- MUST be
# human-owned via --owner-email, NOT --self-owned. What --self-owned does
# depends on whether the bot is already registered:
#   - UNregistered self-owned bot: owner_sub is unresolvable, so
#     POST /proposals returns 422.
#   - Already-registered self-owned bot: POST /proposals returns 200 and
#     silently stores the proposal with owner_sub = bot_sub -- but it is
#     then permanently invisible via GET /proposals/pending, which scopes
#     to the CALLER's own Okta sub, not to a bot's.
# Either way, a proposal-submitting bot's owner_sub must resolve to an
# Okta identity that can actually call GET /proposals/pending.
agent-comms-mcp-mint-token --sub linear-progress-bot \
  --scopes comms:proposals:write --owner-email alice@example.com
```

`--owner-email`/`--self-owned` are mutually exclusive and one is required:
skipping this choice is exactly how an agent silently becomes self-owned
instead of human-owned, which later makes anything requiring that human's
approval unsatisfiable until the agent is re-minted with the correct
owner. See
[docs/TECH-5389-APPROVAL-PIPELINE.md](docs/TECH-5389-APPROVAL-PIPELINE.md)
§15 for the full rationale.

## License

MIT. See [LICENSE](LICENSE).
