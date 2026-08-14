"""partial index for case-insensitive active-agent email lookup

Revision ID: bb1ea7d2a0cf
Revises: e1db7c2e6b70
Create Date: 2026-08-13 16:50:57.343015

TECH-5159: backs ``service.lookup_agent_by_email``'s
``func.lower(Agent.owner_email) == normalized AND Agent.status == "active"``
query, added the same round as this migration. Without it, that query
sequential-scans ``agents`` on every call -- fine at today's table size, but
worth having the index in place before ``comms_lookup_agent_by_email`` sees
real traffic rather than adding it reactively later.

NOTE on in-place amendment (Argus round 4 correction: an earlier version of
this note claimed "this service has no deployed environment yet" -- false;
DESIGN.md §12 has said "Infrastructure: done -- deployed and running" since
before this PR opened, and `entrypoint.sh` runs `alembic upgrade head`
automatically on every deploy): like ``18f2d7735523`` before it, this
revision was authored and iterated on entirely within this single unmerged
PR (the column list changed from ``(lower(owner_email))`` alone to
``(lower(owner_email), bound_at DESC NULLS LAST)`` across Argus review
rounds). The reason in-place amendment is safe here is narrower than "no
deployment exists": deployments run whatever image was built from `main`
(or a release tag), never from an open feature branch, and this revision
has never existed on `main` -- so the deployed dev/prod database has never
run it, regardless of the service's own deployment status. CI runs against
a fresh, ephemeral Postgres container every run, and all local review
testing recreated the throwaway local Postgres container between rounds,
so neither of those ran a stale version of it either. In-place amendment
was therefore safe. Once this PR merges, treat this file as frozen: any
further schema change requires a NEW Alembic revision, never an edit to
this one.

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bb1ea7d2a0cf"
down_revision: str | None = "e1db7c2e6b70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Expression index on (lower(owner_email), bound_at DESC NULLS LAST),
    # partial on status = 'active': matches lookup_agent_by_email's WHERE
    # predicate and the bound_at half of its ORDER BY, so a multi-active-
    # agent owner_email (an expected, not exceptional, state -- see that
    # function's docstring) resolves the bound_at ordering via a single
    # index scan. This does NOT cover the query's secondary sort key
    # (created_at DESC, added to break a same-bound_at tie) -- that case
    # still falls back to an in-memory sort, but only for the rare
    # equal-bound_at rows, not every call. op.create_index doesn't support
    # Postgres expression indexes, partial WHERE clauses, or per-column
    # NULLS ordering directly, so this is raw DDL.
    #
    # Not CREATE INDEX CONCURRENTLY: that can't run inside a transaction,
    # and Alembic's env.py wraps every migration in one by default. The
    # ShareLock this acquires blocks writes to `agents` for the duration of
    # the build, which is a negligible window at today's table size --
    # revisit if `agents` grows large enough for that lock to matter.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_agents_lower_owner_email_active "
        "ON agents (lower(owner_email), bound_at DESC NULLS LAST) "
        "WHERE status = 'active'"
    )


def downgrade() -> None:
    # Schema-qualified to match da3e1646c44d's convention: unqualified DROP
    # INDEX under a wrong search_path would silently no-op (IF EXISTS makes
    # that failure invisible), leaving the index behind for a later
    # re-upgrade to collide with.
    op.execute("DROP INDEX IF EXISTS public.idx_agents_lower_owner_email_active")
