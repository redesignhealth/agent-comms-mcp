"""add apply_result consistency check to proposal_holds

Revision ID: cf72736e07f5
Revises: d88cc7e6e21b
Create Date: 2026-09-09 13:03:00.790537

Argus review round on d88cc7e6e21b: that migration added ``apply_result``
as a plain nullable JSONB column with no CHECK constraint linking it to
``status`` -- unlike ``applied_at`` (``ck_proposal_holds_applied_at_
consistency``, added alongside the table itself in ``d23b37d4e187``),
which enforces the equivalent invariant for that column. Adds the
analogous constraint here, mirroring its exact shape: ``apply_result`` is
only ever written by ``service._apply_or_finalize_proposal_hold`` inside
the SAME branch that sets ``status = "applied"`` (see that function's own
comment -- "only set when the applier actually returned something...
never overwrite with None"), so no existing row can violate this on
apply; safe to add directly, no backfill needed.

DEPLOYMENT: purely additive (a new CHECK constraint on a column no
existing row can violate, per the invariant above) -- safe for a normal
rolling deploy in either direction, same as ``d88cc7e6e21b`` itself.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "cf72736e07f5"
down_revision: str | None = "d88cc7e6e21b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_proposal_holds_apply_result_consistency",
        "proposal_holds",
        "apply_result IS NULL OR status = 'applied'",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_proposal_holds_apply_result_consistency", "proposal_holds", type_="check"
    )
