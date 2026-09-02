"""accepted_types opt-out default

Revision ID: d5c8f1a2b4e7
Revises: c1a2b3d4e5f6
Create Date: 2026-09-02 00:00:00.000000

TECH-5822 follow-up: flips ``agents.accepted_types`` from an opt-IN
allowlist (every agent must declare every message type it wants to
receive, and re-declare on every new type the board ever adds) to an
opt-OUT model. An EMPTY array is now the "accept every message type,
including any added in the future" sentinel -- see
``service._validate_display_name_and_accepted_types`` /
``service._enforce_message_type_accepted`` for the corresponding
application-layer changes. A non-empty array is still an explicit,
narrower restriction, unchanged from before.

This revision does two things:

1. Adds ``server_default = '{}'`` to the column (DDL only -- the column
   was already ``NOT NULL`` with no default, so any raw-SQL insert that
   omits the column would previously have failed outright rather than
   silently narrowing; this is a pure safety net, not a behavior change
   for the ORM's own insert path, which always supplies a value).

2. Backfills EXISTING rows -- but narrowly, not a blanket "set everyone to
   accept-everything". Every agent registered before today declared its
   ``accepted_types`` under the OLD mandatory-allowlist contract, and
   migration ``e1db7c2e6b70`` (2026-08-13) already widened every row that
   existed at that time to the exact 12-type set that was "everything" as
   of that migration's authoring date (the literal list below is copied
   verbatim from that migration, not from the current
   ``schemas.MESSAGE_TYPES`` -- migrations are frozen historical
   artifacts, same rationale as that revision's own docstring). Two new
   types (``instruction_request``/``instruction_share``, TECH-5822)
   shipped after that widening, and -- as of this migration's authoring --
   every pre-existing agent except one is stuck on that now-stale 12-type
   set: proof that value was never a deliberately chosen restriction, just
   whatever the mandatory registration default happened to be, and that
   "declare everything you want" has never scaled past a single
   message-type addition.

   This migration therefore widens to the new empty-list sentinel ONLY the
   rows whose ``accepted_types`` (as a set) is EXACTLY that frozen
   12-type set -- i.e. rows that were never edited into something
   narrower since. Any agent whose current ``accepted_types`` is a proper
   subset of that 12-type set (fewer types than the old default) made a
   deliberate choice to restrict itself further at some point, and this
   migration leaves it completely untouched: converting that row to
   accept-everything would silently override an intentional restriction
   the admin/operator chose, which is not this migration's call to make.
   Any row registered AFTER ``e1db7c2e6b70`` with a custom set (neither
   exactly the old 12-type default nor a subset of it -- e.g. one that
   already includes one of the two new TECH-5822 types) is likewise left
   alone for the same reason.

DEPLOYMENT: same posture as ``e1db7c2e6b70`` -- the UPDATE only widens
existing values on a column no currently-running container (old or new)
reads or writes differently because of it; the ``ALTER COLUMN ...
SET DEFAULT`` is equally non-blocking. No stop-then-start required for
this revision considered alone, but as always ``entrypoint.sh`` runs
``alembic upgrade head`` atomically, so a deploy carrying this revision
alongside any still-pending parent is governed by that parent's own
requirements.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d5c8f1a2b4e7"
down_revision: str | None = "c1a2b3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Literal snapshot of e1db7c2e6b70's widened set, copied verbatim (not
# imported -- see module docstring for why frozen migrations never import
# from schemas.py).
_OLD_DEFAULT_TWELVE = (
    "'availability_request', 'availability_response', 'confirm', "
    "'counter_proposal', 'decline', 'needs_clarification', 'note', "
    "'task_assign', 'task_cancel', 'task_complete', 'task_decline', "
    "'task_report'"
)


def upgrade() -> None:
    op.execute("ALTER TABLE public.agents ALTER COLUMN accepted_types SET DEFAULT '{}'::text[]")
    # Only rows whose accepted_types is EXACTLY the frozen old-default
    # 12-type set (order-independent: cardinality equality both ways,
    # since Postgres array equality is order-sensitive but this data was
    # always written pre-sorted by service.register_agent's own
    # `sorted(set(...))` normalization -- the explicit `<@`/`@>` pair below
    # is a deliberate belt-and-suspenders against relying on that
    # incidental ordering).
    op.execute(
        "UPDATE public.agents SET accepted_types = ARRAY[]::text[], updated_at = now() "
        f"WHERE accepted_types <@ ARRAY[{_OLD_DEFAULT_TWELVE}]::text[] "
        f"AND accepted_types @> ARRAY[{_OLD_DEFAULT_TWELVE}]::text[]"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE public.agents ALTER COLUMN accepted_types DROP DEFAULT")
    # Not reversed: same lossy-downgrade posture as e1db7c2e6b70 -- there is
    # no way to recover which rows were widened to '{}' by this migration
    # versus already empty for some other reason. Downgrading this revision
    # leaves any widened row at '{}' rather than restoring the old 12-type
    # default.
