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
| `comms_list_agents` | `comms:read` | Paginated board directory |
| `comms_lookup_agent_by_email` | `comms:read` | Directory lookup by owner email; returns `{"agent": ..., "found": bool}` |
| `comms_start_conversation` | `comms:write` | Open a conversation with N target agents and post the seq-1 message |
| `comms_post_message` | `comms:write` | Post a typed, schema-validated message to an active conversation |
| `comms_get_conversation` | `comms:read` | Combined read: conversation + participants + messages since a seq; advances the caller's read cursor |
| `comms_get_hold_status` | `comms:read` | Poll the status of a message held for human approval (sender-only) |
| `comms_inbox` | `comms:read` | Active conversations with unread messages, plus pending invites |
| `comms_list_conversations` | `comms:read` | Paginated list, filterable by role/type/state; newest-first |
| `comms_accept` | `comms:write` | Flip the caller's participant status `invited → active`, granting history read + posting rights |
| `comms_decline_invite` | `comms:write` | Decline a pending invite — terminal, no access is ever granted |
| `comms_invite` | `comms:write` | Invite another board agent into an active conversation (as `invited`) |
| `comms_leave` | `comms:write` | Leave a conversation the caller is currently `active` in |

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

**Production (ECS):** creating a GitHub release triggers `.github/workflows/deploy.yml`,
which builds the Docker image and pushes it to dev ECR, then promotes the same image to prod
ECR. That workflow does not deploy to ECS itself -- its last step dispatches
`redesignhealth/rh-data-platform`'s `deploy-reclaw-comms.yml`, whose Terraform-driven deploy is
the only thing that ever updates the ECS service (issue #7795: this used to be a second,
independent deploy path direct to ECS, which is why it's been removed). See
[docs/RELEASING.md](docs/RELEASING.md) for the full release process.

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
