"""add decision_reason_code to proposal_holds

Revision ID: 5ef4403d7f33
Revises: c7665a1b2d3e
Create Date: 2026-10-30 00:00:00.000000

Adds a nullable decision_reason_code column to proposal_holds, with a CHECK
constraint enforcing the allowed closed vocabulary:
'not_now', 'wrong_target', 'incorrect_facts', 'insufficient_evidence',
'duplicate', 'policy', 'human_will_handle', 'other'.

Nullable with no default, so every existing row is valid and no backfill is needed.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "5ef4403d7f33"
down_revision: str | None = "c7665a1b2d3e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REASON_CODES = (
    "not_now",
    "wrong_target",
    "incorrect_facts",
    "insufficient_evidence",
    "duplicate",
    "policy",
    "human_will_handle",
    "other",
)

_CONSTRAINT_NAME = "ck_proposal_holds_decision_reason_code"
_CONSTRAINT_CONDITION = f"decision_reason_code IS NULL OR decision_reason_code IN {_REASON_CODES!r}"


def upgrade() -> None:
    op.add_column(
        "proposal_holds",
        sa.Column("decision_reason_code", sa.Text(), nullable=True),
        if_not_exists=True,
    )
    op.create_check_constraint(
        _CONSTRAINT_NAME,
        "proposal_holds",
        _CONSTRAINT_CONDITION,
    )


def downgrade() -> None:
    op.execute(f"ALTER TABLE proposal_holds DROP CONSTRAINT IF EXISTS {_CONSTRAINT_NAME}")
    op.drop_column("proposal_holds", "decision_reason_code", if_exists=True)
