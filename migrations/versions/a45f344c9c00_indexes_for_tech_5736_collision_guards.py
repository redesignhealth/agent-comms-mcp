"""indexes for TECH-5736 collision guards

Revision ID: a45f344c9c00
Revises: 4f6eb79742ec
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

Deliberately NOT a UNIQUE index on ``lower(display_name)``: that would
enforce the collision guard's invariant at the DB level too, but this
service has no confirmed guarantee that every already-``active`` row in
an existing deployment is free of case-insensitive display_name
duplicates (the whole premise of this ticket is that duplicates have
happened in practice) -- a UNIQUE index could fail to build against real
data. A plain (non-unique) index is a safe, purely additive performance
change; tightening it to UNIQUE is a separate, deploy-verified change if
ever wanted.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a45f344c9c00"
down_revision: str | None = "4f6eb79742ec"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Matches register_agent's display-name-collision WHERE predicate.
    # Raw DDL for the same reason as bb1ea7d2a0cf: op.create_index doesn't
    # support Postgres expression indexes or partial WHERE clauses
    # directly. Not CONCURRENTLY -- see bb1ea7d2a0cf's comment on why (this
    # migration runs inside Alembic's default transaction wrapper).
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_agents_lower_display_name_active "
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
