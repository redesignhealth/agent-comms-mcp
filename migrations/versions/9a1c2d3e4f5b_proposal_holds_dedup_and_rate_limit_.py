"""proposal_holds dedup unique index + rate-limit indexes

Revision ID: 9a1c2d3e4f5b
Revises: f1a2b3c4d5e6
Create Date: 2026-09-03 00:00:00.000001

TECH-5872/5875 (Argus review, B1/B2/S1): closes two gaps in the create-time
dedup ``service.create_proposal`` added on top of d23b37d4e187's bare table.

B1/B2 -- ``idx_proposal_holds_pending_dedup``: a partial UNIQUE index on
``(kind, proposed_by_bot_id, (action->>'target_id'), (action->>'action_type'))
WHERE status = 'pending'``. This is the DB-level backstop for the SAME dedup
key the app-level SELECT in ``service.create_proposal``/
``service._proposal_dedup_where`` uses (the two must never drift onto
different keys, or they will fight each other) -- scoped to the SUBMITTING
BOT deliberately: a different bot proposing the same ``(kind, target_id,
action_type)`` must get its own row, never silently overwrite another bot's
pending proposal (B1, a security fix -- the app-level SELECT was missing the
``proposed_by_bot_id`` predicate entirely, which let any caller with
``comms:proposals:write`` collide with, and get auto-approved for, another
bot's identity). The partial unique index is what makes the race the
app-level SELECT-then-INSERT can't close on its own (B2 -- two concurrent
submissions for the same dedup key can both miss the SELECT and both
attempt an INSERT) a database-enforced impossibility: the loser's INSERT
raises ``IntegrityError``, and ``service.create_proposal`` catches that
specific violation and re-queries to UPDATE instead (see
``service._dedup_or_insert_proposal``).

S1 -- ``idx_proposal_holds_bot_id_created_at``: backs
``proposed_by_bot_id``-scoped lookups against this table (e.g. an ops/
observability query, or a future per-bot listing) -- the per-bot rate-limit
COUNT itself was moved to ``audit_log`` in this same round (see
``idx_audit_log_actor_sub_action_at`` in the following revision,
``a9faca2517d7``, and ``service._deny_rate_limited_proposals``'s docstring
for why: a dedup-UPDATE never inserts a new ``proposal_holds`` row, so
counting THIS table's rows can never detect a bot resubmitting against its
own already-pending dedup key at unlimited frequency -- only an append-only
log of every attempt, regardless of whether it goes on to INSERT or UPDATE,
can).

Both indexes here are plain (non-concurrent, transactional) ``CREATE INDEX``
statements -- ``proposal_holds`` is a brand-new table as of d23b37d4e187 with
no production traffic yet, so there's no lock-contention concern that would
call for ``CONCURRENTLY`` (contrast with the ``audit_log`` index in the
next revision, which does need it because ``audit_log`` is written on every
tool call/mutation/denial in this service).

Argus review B1 (round 3): the ``audit_log`` concurrent index used to live
in THIS migration, built inside ``op.get_context().autocommit_block()``. That
autocommit block's implicit COMMIT releases ``migrations/env.py``'s
``pg_advisory_xact_lock`` for its duration -- before this migration's own
``alembic_version`` stamp is committed -- so under a rolling deploy with
multiple containers racing to migrate concurrently, a second container could
acquire the lock while the first was mid-autocommit-block and race the same
``CREATE INDEX CONCURRENTLY``, potentially leaving it permanently ``INVALID``.
Splitting the concurrent-index build into its own subsequent revision
(``a9faca2517d7``) doesn't add locking that doesn't already exist -- it
isolates the non-transactional step so THIS migration's two ordinary indexes
commit cleanly under the advisory lock's protection, and only the one
statement that must run non-transactionally is deploy-gated on its own (see
that revision's DEPLOYMENT note).

DEPLOYMENT: NOT safe for a simultaneous/rolling deploy of migration+app
together. ``idx_proposal_holds_pending_dedup`` is the DB-level backstop
that ``POST /proposals`` (``service.create_proposal`` /
``_dedup_or_insert_proposal``) depends on for its race-safety guarantee --
if application containers capable of serving ``POST /proposals`` are
rolled out before (or concurrently with) this migration, duplicate
pending rows can be inserted while the index doesn't yet exist, and the
later ``CREATE UNIQUE INDEX`` will then fail permanently on those
duplicates (requiring a manual data fixup before it can ever build). This
migration MUST run to completion BEFORE any application container that
can serve ``POST /proposals`` is deployed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9a1c2d3e4f5b"
down_revision: str | None = "f1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "idx_proposal_holds_pending_dedup",
        "proposal_holds",
        [
            "kind",
            "proposed_by_bot_id",
            sa.text("(action ->> 'target_id')"),
            sa.text("(action ->> 'action_type')"),
        ],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
        if_not_exists=True,
    )
    op.create_index(
        "idx_proposal_holds_bot_id_created_at",
        "proposal_holds",
        ["proposed_by_bot_id", "created_at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_proposal_holds_bot_id_created_at", table_name="proposal_holds", if_exists=True
    )
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
