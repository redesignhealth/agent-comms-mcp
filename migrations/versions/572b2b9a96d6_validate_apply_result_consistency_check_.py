"""validate apply_result consistency check without exclusive lock

Revision ID: 572b2b9a96d6
Revises: cf72736e07f5
Create Date: 2026-09-09 17:39:33.774951

Argus review round on cf72736e07f5: that migration added the CHECK
constraint via a plain ADD CONSTRAINT ... CHECK (...), which acquires
ACCESS EXCLUSIVE on proposal_holds and holds it for the duration of the
table scan.

This follow-up migration replaces it using the safer two-step pattern:
drops the constraint, re-adds it as NOT VALID (acquiring only a brief
ACCESS EXCLUSIVE lock without scanning the table), and then runs
VALIDATE CONSTRAINT (scanning existing rows under SHARE UPDATE EXCLUSIVE,
which does not block concurrent SELECTs/INSERTs/UPDATEs).

DEPLOYMENT: Safe for production. downgrade() drops and re-adds the
plain constraint so the database remains in a valid, constraint-enforced state.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "572b2b9a96d6"
down_revision: str | None = "cf72736e07f5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE proposal_holds DROP CONSTRAINT ck_proposal_holds_apply_result_consistency"
    )
    op.execute(
        "ALTER TABLE proposal_holds ADD CONSTRAINT "
        "ck_proposal_holds_apply_result_consistency "
        "CHECK (apply_result IS NULL OR status = 'applied') NOT VALID"
    )
    op.execute(
        "ALTER TABLE proposal_holds VALIDATE CONSTRAINT ck_proposal_holds_apply_result_consistency"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE proposal_holds DROP CONSTRAINT ck_proposal_holds_apply_result_consistency"
    )
    op.create_check_constraint(
        "ck_proposal_holds_apply_result_consistency",
        "proposal_holds",
        "apply_result IS NULL OR status = 'applied'",
    )
