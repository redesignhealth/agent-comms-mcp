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

DEPLOYMENT WARNING (Argus round-1 finding -- this section previously and
WRONGLY claimed the same safe-under-both-versions posture as
``e1db7c2e6b70``; that equivalence does not hold and the failure mode is
actually inverted): ``entrypoint.sh`` runs ``alembic upgrade head`` in the
new container BEFORE the old container drains (no expand/contract split
exists in this pipeline today). Pre-PR enforcement
(``service._enforce_message_type_accepted``, before this same PR's own
code change) is ``if message_type not in accepted`` -- an OLD container
still serving traffic during the drain window reads a row this migration
just backfilled to ``'{}'`` and evaluates ``message_type not in []`` ->
always ``True`` -> denies EVERY message to that agent, the exact opposite
of the "accept everything" meaning the NEW code (already deployed in the
new container, same PR) assigns to that same value. ``e1db7c2e6b70``'s
widening was safe under old code specifically because old code did not
enforce ``accepted_types`` at all yet -- there is no such safety margin
here, since old code in THIS case already enforces it, just with the
opposite sentinel meaning.

This PR must ship as a stop-then-start deploy (every old container fully
stopped, THEN the new container -- carrying both the enforcement code
change and this migration -- starts), or during a confirmed-idle traffic
window. A standard rolling/blue-green deploy of this image is NOT safe for
this specific revision: every currently-registered agent whose row this
migration backfills would have all incoming messages denied for the
entire drain window.
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
    # Argus round-1 finding: a no-op downgrade() here is not merely lossy
    # (e1db7c2e6b70's downgrade posture) -- it is actively unsafe. Before
    # this migration, no row could ever be '{}' (register_agent's
    # validator rejected an empty accepted_types outright), so any row
    # found at '{}' post-downgrade is a row this migration itself
    # backfilled, never a legitimate pre-existing value. Left at '{}',
    # rolled-back application code (which enforces `if message_type not in
    # accepted`, no opt-out-empty-list carve-out) would treat every one of
    # those agents as accepting NOTHING, and -- because the rolled-back
    # validator also still rejects an empty accepted_types -- that agent
    # cannot even self-recover by calling comms_register again; only a
    # manual UPDATE restoring a non-empty accepted_types unblocks it. This
    # restores the exact frozen 12-type set e1db7c2e6b70 established, so a
    # downgrade run promptly after this migration (before any new
    # registration under the new opt-out semantics has landed) is precise,
    # not a guess: every row it touches is one this migration itself just
    # backfilled.
    #
    # KNOWN LIMITATION, not fixable after the fact: once even one new
    # registration/re-registration has legitimately opted into the new
    # accept-everything sentinel (an ordinary '{}' write under the NEW
    # semantics, unrelated to this migration's backfill), this downgrade
    # can no longer tell that row apart from one it backfilled, and will
    # incorrectly "restore" it to the 12-type set too. This is an inherent
    # limitation of rolling back a live semantic flip, not something this
    # migration can detect -- downgrading long after this ships should be
    # treated as data-lossy for any agent that adopted the new default in
    # the interim, and reviewed manually rather than trusted blindly.
    op.execute(
        f"UPDATE public.agents SET accepted_types = ARRAY[{_OLD_DEFAULT_TWELVE}]::text[], "
        "updated_at = now() WHERE accepted_types = ARRAY[]::text[]"
    )
    op.execute("ALTER TABLE public.agents ALTER COLUMN accepted_types DROP DEFAULT")
