"""indexes for TECH-5736 collision guards

Revision ID: a45f344c9c00
Revises: b2bb6ccde02e
Create Date: 2026-08-29 00:00:00.000000

Backs two new query patterns added by TECH-5736's ``register_agent``
guards, added the same round as this migration (Argus round-1 suggestions
S2/S3): the display-name-collision check
(``func.lower(Agent.display_name) == ... AND Agent.status == "active"``)
and the sibling-identity check's prefix match
(``Agent.sub.startswith(f"{base_sub}::", autoescape=True)``, a
``LIKE 'base_sub::%'`` predicate). Same rationale as ``bb1ea7d2a0cf``:
fine at today's table size, worth having in place before real traffic
rather than adding reactively later.

NOTE on in-place amendment: the ``idx_agents_lower_display_name_active``
index below was originally created as a plain (non-unique) index --
see this file's prior revision for that rationale. Argus round-2 flagged
that the application-level display-name check ``register_agent`` added
(a racy read-then-check-then-insert, fixed separately in service.py this
same round) has no DB-level backing, so a concurrent request could still
slip a case-insensitive duplicate past it. Making this index UNIQUE
closes that gap at the database level instead of only adding a
performance index. Per bb1ea7d2a0cf's and this file's own established
convention, amending in place (rather than layering a second migration
that drops and recreates the same index) is safe: this revision was
authored entirely within this single unmerged PR, has never existed on
`main`, and has therefore never run against a deployed or otherwise
persistent database -- only ephemeral CI/local Postgres containers that
get torn down between rounds. Once this PR merges, treat this file as
frozen as usual.

Tightening to UNIQUE does carry a real, currently-unconfirmed risk that
hasn't changed: if any already-``active`` row in a real deployment
already has a case-insensitive display_name duplicate, this index build
will fail. This risk can NOT be waved away on "there is no deployed
environment for this service today" grounds -- that claim is false, for
the same reason bb1ea7d2a0cf's earlier docstring was corrected: DESIGN.md
§12 has said "Infrastructure: done -- deployed and running" since before
this PR opened, and `entrypoint.sh` runs `alembic upgrade head`
automatically on every deploy. (The separate "in-place amendment is
safe" reasoning above still holds -- that's about THIS revision never
having run anywhere, deployed or otherwise, not about whether a deployed
environment exists at all.) A deployed environment with real agent data
exists, and this migration WILL run against it once merged. Verify
before deploying that no already-``active`` row collides
case-insensitively on ``display_name`` with another; if one does,
resolve it (rename or deactivate the older row) before this migration
runs, or the ``CREATE UNIQUE INDEX`` below will fail in that environment.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a45f344c9c00"
down_revision: str | None = "b2bb6ccde02e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Matches register_agent's display-name-collision WHERE predicate, and
    # (as of this amendment -- see module docstring) enforces that same
    # invariant at the DB level: UNIQUE turns the app layer's racy
    # read-then-insert check into a real constraint, so a concurrent
    # register_agent call can no longer slip a case-insensitive duplicate
    # `display_name` past both checks. Raw DDL for the same reason as
    # bb1ea7d2a0cf: op.create_index doesn't support Postgres expression
    # indexes or partial WHERE clauses directly. Not CONCURRENTLY -- see
    # bb1ea7d2a0cf's comment on why (this migration runs inside Alembic's
    # default transaction wrapper).
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_lower_display_name_active "
        "ON agents (lower(display_name)) "
        "WHERE status = 'active'"
    )
    # Matches the sibling-identity query's `sub.startswith(f"{base_sub}::")`
    # prefix predicate, which compiles to `LIKE 'base_sub::%'`. The
    # existing unique index on `sub` (see ef8394b37c8d) was not created
    # with text_pattern_ops, so a LIKE prefix scan can't use it under a
    # non-C locale. text_pattern_ops also serves plain equality lookups,
    # so this doesn't duplicate the existing unique index's purpose.
    op.execute("CREATE INDEX IF NOT EXISTS idx_agents_sub_prefix ON agents (sub text_pattern_ops)")


def downgrade() -> None:
    # Schema-qualified per bb1ea7d2a0cf's convention.
    op.execute("DROP INDEX IF EXISTS public.idx_agents_sub_prefix")
    op.execute("DROP INDEX IF EXISTS public.idx_agents_lower_display_name_active")
