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
``idx_audit_log_actor_sub_action_at`` below and
``service._deny_rate_limited_proposals``'s docstring for why: a dedup-UPDATE
never inserts a new ``proposal_holds`` row, so counting THIS table's rows
can never detect a bot resubmitting against its own already-pending dedup
key at unlimited frequency -- only an append-only log of every attempt,
regardless of whether it goes on to INSERT or UPDATE, can).

``idx_audit_log_actor_sub_action_at``: backs that moved rate-limit COUNT
query -- ``audit_log`` had no index on ``actor_sub`` at all before this
revision (only ``conversation_id`` and ``at``), so
``_deny_rate_limited_proposals`` would otherwise full-scan a table every
mutation and denial in the service ever writes to.

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

The two ``proposal_holds`` indexes and the ``audit_log`` index are
otherwise purely additive (no column/table changes), but the
``idx_audit_log_actor_sub_action_at`` index is built with
``postgresql_concurrently=True`` (see ``upgrade()``) specifically because
``audit_log`` is written on every tool call/mutation/denial in this
service -- a plain, lock-taking ``CREATE INDEX`` would hold
``ACCESS EXCLUSIVE`` for the full build and stall all of those writes for
the deploy window. Concurrent index builds cannot run inside a
transaction, so ``upgrade()`` drops out of the ambient migration
transaction via ``op.get_context().autocommit_block()`` for that one
statement, mirroring the only non-transactional pattern this repo's
migration history has needed so far. Building a concurrent index while
holding ``migrations/env.py``'s ``pg_advisory_xact_lock`` is inherently
awkward: the autocommit block's implicit ``COMMIT`` releases that lock for
its duration, so a second ``alembic upgrade head`` invocation started at
exactly the wrong moment is not fully serialized against this one for
this specific statement. Acceptable here because Alembic migrations are
run from a single deploy step, not from arbitrarily many concurrent
callers, but worth knowing if this pattern is copied elsewhere.
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
    # CONCURRENTLY cannot run inside a transaction; drop out of the ambient
    # migration transaction for this one statement (see DEPLOYMENT note
    # above) and let Alembic re-open a transaction afterward.
    with op.get_context().autocommit_block():
        op.create_index(
            "idx_audit_log_actor_sub_action_at",
            "audit_log",
            ["actor_sub", "action", "at"],
            unique=False,
            if_not_exists=True,
            postgresql_concurrently=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "idx_audit_log_actor_sub_action_at",
            table_name="audit_log",
            if_exists=True,
            postgresql_concurrently=True,
        )
    op.drop_index(
        "idx_proposal_holds_bot_id_created_at", table_name="proposal_holds", if_exists=True
    )
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
