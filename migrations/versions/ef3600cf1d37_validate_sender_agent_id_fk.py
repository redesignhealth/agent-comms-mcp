"""validate sender_agent_id foreign key constraint

Revision ID: ef3600cf1d37
Revises: c74fb78c66e4
Create Date: 2026-09-21 00:00:00.000000

TECH-6668 follow-up: validates ``fk_proposal_holds_sender_agent_id`` added
``NOT VALID`` in ``c74fb78c66e4``.

Runs in its own autocommit block (via ``op.get_context().autocommit_block()``,
matching ``572b2b9a96d6`` / ``a9faca2517d7``) so the constraint validation
takes only ``SHARE UPDATE EXCLUSIVE`` rather than holding an exclusive lock
across the table scan. Because ``c74fb78c66e4`` is already stamped by Alembic
before this revision begins, any validation failure or retry of this revision
is safe and idempotent.

``downgrade()`` is a no-op: PostgreSQL does not support un-validating a foreign
key constraint, and downgrading past ``c74fb78c66e4`` drops the constraint
outright.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "ef3600cf1d37"
down_revision: str | None = "c74fb78c66e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TABLE proposal_holds VALIDATE CONSTRAINT fk_proposal_holds_sender_agent_id"
        )


def downgrade() -> None:
    pass
