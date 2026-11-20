"""external resolution of proposal_holds (TECH-9214)

Revision ID: b9214c0e5d17
Revises: 20a7dfa60b73
Create Date: 2026-11-20 00:00:00.000000

TECH-9214: a ``catalog_candidate`` proposal is decided by Arcadia's reviewers,
who report the outcome through ``proposals_admin_resolve_external``. That needs
a terminal status for "changes requested", a decision source for "an external
system decided this", and a place for the external system's own id.

- widens ``ck_proposal_holds_status`` with ``'changes_requested'``;
- widens ``ck_proposal_holds_decision_source`` with ``'external'``;
- adds a nullable ``external_ref`` TEXT column (Arcadia's candidate id).

Both widened CHECKs still satisfy ``ck_proposal_holds_decision_consistency``
(a non-pending row has decided_at/decided_by_actor_id/decision_source all set,
which the resolve call stamps together). Purely additive, safe for a rolling
deploy: an old container never writes the new values and treats an unknown
terminal status as opaque, like ``'withdrawn'`` in f3c9a7e2b1d4.

``downgrade()`` first rewrites rows the narrower CHECKs would reject, as
f3c9a7e2b1d4 does: ``'changes_requested'`` becomes ``'rejected'`` and
``'external'`` decision sources become ``'human'`` (the closest old values),
then drops the column.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b9214c0e5d17"
down_revision: str | None = "20a7dfa60b73"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_STATUSES = (
    "'pending', 'approved', 'applying', 'rejected', 'applied', 'apply_failed', 'stale', 'withdrawn'"
)
_NEW_STATUSES = _OLD_STATUSES + ", 'changes_requested'"
_OLD_DECISION_SOURCES = "'human', 'auto', 'bot'"
_NEW_DECISION_SOURCES = "'human', 'auto', 'bot', 'external'"


def upgrade() -> None:
    op.add_column(
        "proposal_holds",
        sa.Column("external_ref", sa.Text(), nullable=True),
        if_not_exists=True,
    )
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status", "proposal_holds", f"status IN ({_NEW_STATUSES})"
    )
    op.drop_constraint("ck_proposal_holds_decision_source", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_decision_source",
        "proposal_holds",
        f"decision_source IS NULL OR decision_source IN ({_NEW_DECISION_SOURCES})",
    )


def downgrade() -> None:
    op.execute("UPDATE proposal_holds SET status = 'rejected' WHERE status = 'changes_requested'")
    op.execute(
        "UPDATE proposal_holds SET decision_source = 'human' WHERE decision_source = 'external'"
    )
    op.drop_constraint("ck_proposal_holds_decision_source", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_decision_source",
        "proposal_holds",
        f"decision_source IS NULL OR decision_source IN ({_OLD_DECISION_SOURCES})",
    )
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status", "proposal_holds", f"status IN ({_OLD_STATUSES})"
    )
    op.drop_column("proposal_holds", "external_ref", if_exists=True)
