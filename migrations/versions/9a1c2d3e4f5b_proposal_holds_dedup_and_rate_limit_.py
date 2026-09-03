"""proposal_holds dedup unique index + rate-limit indexes

Revision ID: 9a1c2d3e4f5b
Revises: d23b37d4e187
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

DEPLOYMENT: safe for a normal rolling deploy -- purely additive (two new
indexes on an existing, currently-empty-in-production table; one new index
on ``audit_log``), same reasoning as every other purely-additive migration
in this directory. The partial unique index CAN fail to build if
``proposal_holds`` already has a real duplicate under the new key by the
time this runs in a real deployment -- vanishingly unlikely (this table has
no readers/writers on `main` before this PR), but see a45f344c9c00's own
DEPLOYMENT note for the general shape of that risk.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9a1c2d3e4f5b"
down_revision: str | None = "d23b37d4e187"
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
    op.create_index(
        "idx_audit_log_actor_sub_action_at",
        "audit_log",
        ["actor_sub", "action", "at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_audit_log_actor_sub_action_at", table_name="audit_log", if_exists=True)
    op.drop_index(
        "idx_proposal_holds_bot_id_created_at", table_name="proposal_holds", if_exists=True
    )
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
