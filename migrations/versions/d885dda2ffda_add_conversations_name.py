"""add conversations name

Revision ID: d885dda2ffda
Revises: b3d4e5f6a7c8
Create Date: 2026-09-09 21:20:15.837050

Rebased onto b3d4e5f6a7c8 (the new tip of main after this branch was cut)
during the TECH-6120 PR's rebase -- originally written against 136265b3f22d,
which is no longer the head.

DEPLOYMENT: no stop-then-start needed -- this is a plain additive, nullable
column with no ``server_default`` needed (NULL is itself a valid, correct
value for "no name set"), and ``entrypoint.sh`` already runs
``alembic upgrade head`` before ``agent-comms-mcp`` starts serving,
atomically, on every container startup. A normal rolling deploy is safe:
each new container migrates-then-serves before taking traffic, and an old
container still running (with code that never references ``name``)
tolerates the column's presence fine.

Rollback: dropping the column is lossy -- it discards every name ever set.
Acceptable: the data did not exist before this revision.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d885dda2ffda"
down_revision: str | None = "b3d4e5f6a7c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "conversations",
        # Length hardcoded, not imported from schemas.MAX_CONVERSATION_NAME_LENGTH:
        # a migration is a frozen historical record and must not shift if that
        # constant is later changed. Same posture as 18f2d7735523's varchar(255).
        sa.Column("name", sa.String(length=120), nullable=True),
        if_not_exists=True,
    )


def downgrade() -> None:
    # Lossy: dropping the column discards every name ever set. Acceptable --
    # the data did not exist before this revision.
    op.drop_column("conversations", "name", if_exists=True)
