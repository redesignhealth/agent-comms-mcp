"""add applying status to proposal_holds

Revision ID: e2f7a91c5b34
Revises: a9faca2517d7
Create Date: 2026-09-03 00:00:00.000000

TECH-5873 Argus review round-2 B1: closes a double-write race where two
concurrent ``POST /proposals/{id}/decide`` (or a decide racing the
TECH-5877 auto-judge's own synchronous apply) calls could both observe
``status='pending'`` and both call the Linear applier before either
re-acquired the row lock to write a terminal status -- the DB-level dedup
on the terminal write prevented a double DB row update, but not the
double Linear API call itself.

``'applying'`` is a new transient, persisted sentinel: the approve path
now writes ``status='applying'`` (plus ``decided_at``/
``decided_by_actor_id``/``decision_source``, to satisfy
``ck_proposal_holds_decision_consistency``, which already requires those
three whenever ``status != 'pending'``) under the SAME initial
``FOR UPDATE`` that reads/checks ``status == 'pending'``, and commits
before releasing that lock. A second concurrent caller that then acquires
the lock reads ``status='applying'`` (not ``'pending'``) and takes the
existing "not pending" branch, which raises ``HoldAlreadyDecidedError`` ->
409 -- it never reaches the applier. See ``service._apply_or_finalize_proposal_hold``
and its two call sites (``service.decide_proposal``,
``service.create_proposal``) for the full sequencing.

Only ``ck_proposal_holds_status`` needs widening; ``'applying'`` already
satisfies ``ck_proposal_holds_decision_consistency`` (status != 'pending'
branch) once the claiming write sets the three decision fields, and
``ck_proposal_holds_applied_at_consistency`` (``applied_at`` stays NULL
until the row actually reaches ``'applied'``).

Also widens ``idx_proposal_holds_pending_dedup``'s partial-index predicate
from ``status = 'pending'`` to ``status IN ('pending', 'applying')``
(Argus review round-3 B1): the dedup index (and the identical predicate
``service._proposal_dedup_where`` mirrors in the app-level SELECT) is the
ONLY thing that stops a resubmission of the same ``(kind,
proposed_by_bot_id, target_id, action_type)`` from inserting a second row
while the first is mid-flight. A ``'pending'``-only predicate goes BLIND
the instant the claiming write above lands: for the ~10s the row sits at
``'applying'``, it's no longer covered by the index's ``WHERE`` clause,
so a resubmission during that window finds no conflicting row and inserts
a fresh one -- silently defeating dedup for exactly the window this
revision's own claim mechanism holds a row in. PostgreSQL has no
"ALTER INDEX ... SET predicate"; a partial index's ``WHERE`` clause can
only be changed via DROP + CREATE.

DEPLOYMENT: purely additive (widening a CHECK constraint's allowed value
set, not narrowing it; widening a partial index's predicate to cover MORE
rows, not fewer) -- safe for a normal rolling deploy. An old container's
code never writes ``'applying'`` (it doesn't know the value exists) and
reads any row's ``status`` as an opaque string it doesn't branch on
except via equality checks against the OLD 6-value vocabulary, so it
simply treats a rare in-flight ``'applying'`` row the same way it already
treats any other non-`pending`, non-`applied` status it doesn't
special-case (falls through to `HoldAlreadyDecidedError` in the old
`decide_proposal`, if that code path is still live during the rollout
window). The index rebuild uses a plain (non-``CONCURRENTLY``,
transaction-scoped) ``DROP INDEX`` + ``CREATE UNIQUE INDEX`` -- unlike
``a9faca2517d7``'s audit_log index, ``proposal_holds`` has NO production
write traffic yet (TECH-5884, the ReClaw agent that will actually submit
proposals, hasn't been provisioned) -- so there is no live write path
this ACCESS EXCLUSIVE lock could stall, and the near-empty table makes
the rebuild itself near-instant. Revisit this choice (switch to
``CREATE INDEX CONCURRENTLY`` + the ``autocommit_block`` pattern
``a9faca2517d7`` establishes) if this migration is still unapplied by the
time ``proposal_holds`` carries real traffic.

``downgrade()`` first reaps any row still sitting in ``'applying'``
(Argus review round-3 S1) -- PostgreSQL validates ALL existing rows
against a newly-added CHECK constraint by default, so a single stuck
``'applying'`` row (the process died between the claim commit and the
terminal write -- see ``service._apply_or_finalize_proposal_hold``'s
docstring for why this is rare but not impossible) would otherwise make
``downgrade()`` fail non-idempotently on the narrower constraint.
Resolving it to ``'apply_failed'`` is the same terminal state a genuine
Linear failure would have produced -- it stays queryable and retryable
via a fresh proposal resubmission, same as any other ``'apply_failed'``
row (see ``docs/DESIGN.md``'s decide/apply section).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e2f7a91c5b34"
down_revision: str | None = "a9faca2517d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_STATUSES = "'pending', 'approved', 'rejected', 'applied', 'apply_failed', 'stale'"
_NEW_STATUSES = "'pending', 'approved', 'applying', 'rejected', 'applied', 'apply_failed', 'stale'"

_DEDUP_INDEX_COLUMNS = (
    "kind",
    "proposed_by_bot_id",
    sa.text("(action ->> 'target_id')"),
    sa.text("(action ->> 'action_type')"),
)


def upgrade() -> None:
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status",
        "proposal_holds",
        f"status IN ({_NEW_STATUSES})",
    )
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
    op.create_index(
        "idx_proposal_holds_pending_dedup",
        "proposal_holds",
        list(_DEDUP_INDEX_COLUMNS),
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'applying')"),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.execute("UPDATE proposal_holds SET status = 'apply_failed' WHERE status = 'applying'")
    op.drop_index("idx_proposal_holds_pending_dedup", table_name="proposal_holds", if_exists=True)
    op.create_index(
        "idx_proposal_holds_pending_dedup",
        "proposal_holds",
        list(_DEDUP_INDEX_COLUMNS),
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
        if_not_exists=True,
    )
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status",
        "proposal_holds",
        f"status IN ({_OLD_STATUSES})",
    )
