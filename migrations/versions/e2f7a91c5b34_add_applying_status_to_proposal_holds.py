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

DEPLOYMENT: purely additive (widening a CHECK constraint's allowed value
set, not narrowing it) -- safe for a normal rolling deploy. An old
container's code never writes ``'applying'`` (it doesn't know the value
exists) and reads any row's ``status`` as an opaque string it doesn't
branch on except via equality checks against the OLD 6-value vocabulary,
so it simply treats a rare in-flight ``'applying'`` row the same way it
already treats any other non-`pending`, non-`applied` status it doesn't
special-case (falls through to `HoldAlreadyDecidedError` in the old
`decide_proposal`, if that code path is still live during the rollout
window).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "e2f7a91c5b34"
down_revision: str | None = "a9faca2517d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_STATUSES = "'pending', 'approved', 'rejected', 'applied', 'apply_failed', 'stale'"
_NEW_STATUSES = "'pending', 'approved', 'applying', 'rejected', 'applied', 'apply_failed', 'stale'"


def upgrade() -> None:
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status",
        "proposal_holds",
        f"status IN ({_NEW_STATUSES})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status",
        "proposal_holds",
        f"status IN ({_OLD_STATUSES})",
    )
