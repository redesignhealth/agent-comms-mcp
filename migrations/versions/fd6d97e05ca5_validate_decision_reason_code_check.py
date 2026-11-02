"""validate decision_reason_code check constraint without exclusive lock

Revision ID: fd6d97e05ca5
Revises: 5ef4403d7f33
Create Date: 2026-10-30 00:00:00.000000

Validates ``ck_proposal_holds_decision_reason_code`` added ``NOT VALID`` in
``5ef4403d7f33``.

LOCKING / DEPLOYMENT:
Migrations in env.py wrap runs in an ambient transaction. To ensure the
VALIDATE CONSTRAINT does not run under the ACCESS EXCLUSIVE lock acquired by
5ef4403d7f33's ADD CONSTRAINT, this revision drops out of the ambient
transaction using ``op.get_context().autocommit_block()`` (matching the pattern
in 572b2b9a96d6 and ef3600cf1d37).

Under PostgreSQL, VALIDATE CONSTRAINT takes only a SHARE UPDATE EXCLUSIVE lock,
which allows concurrent SELECT, INSERT, UPDATE, and DELETE operations on
proposal_holds to proceed uninterrupted while the table is scanned.

Downgrade is a no-op because PostgreSQL has no command to un-validate a
constraint, and downgrading past 5ef4403d7f33 drops the constraint entirely.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "fd6d97e05ca5"
down_revision: str | None = "5ef4403d7f33"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TABLE proposal_holds VALIDATE CONSTRAINT ck_proposal_holds_decision_reason_code"
        )


def downgrade() -> None:
    pass
