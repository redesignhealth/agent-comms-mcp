"""add decision_reason_code to proposal_holds

Revision ID: 5ef4403d7f33
Revises: a56cb01a3ebf
Create Date: 2026-10-30 00:00:00.000000

Adds a nullable decision_reason_code column to proposal_holds, with a CHECK
constraint enforcing the allowed closed vocabulary:
'not_now', 'wrong_target', 'incorrect_facts', 'insufficient_evidence',
'duplicate', 'policy', 'human_will_handle', 'other'.

LOCKING / DEPLOYMENT: added NOT VALID (postgresql_not_valid=True) so adding
the constraint only takes a brief ACCESS EXCLUSIVE lock to record the constraint
in the catalog without scanning existing rows under that lock (which would block
concurrent reads and writes on proposal_holds). Validation of existing rows is
deferred to the follow-up revision fd6d97e05ca5, which validates the constraint
in a separate transaction under SHARE UPDATE EXCLUSIVE lock.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "5ef4403d7f33"
down_revision: str | None = "a56cb01a3ebf"
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
        postgresql_not_valid=True,
    )


def downgrade() -> None:
    op.execute(f"ALTER TABLE proposal_holds DROP CONSTRAINT IF EXISTS {_CONSTRAINT_NAME}")
    op.drop_column("proposal_holds", "decision_reason_code", if_exists=True)
