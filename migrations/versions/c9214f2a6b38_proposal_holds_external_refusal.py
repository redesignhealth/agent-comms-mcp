"""structured external refusal on proposal_holds (TECH-9214)

Revision ID: c9214f2a6b38
Revises: b9214c0e5d17
Create Date: 2026-11-21 00:00:00.000000

TECH-9214: when Arcadia refuses a forwarded ``catalog_candidate`` (HTTP 400/409/422),
the approvals forwarder reports it on ``POST /proposals/{id}/forward-refusal``. The
board closes the proposal as ``rejected`` and keeps Arcadia's structured refusal,
``{"code", "errors": [{"path", "rule", "message"}]}``, so ``proposals_get`` can
return it as a field instead of only flattened text in ``decision_note``.

Adds a nullable ``external_refusal`` JSONB column. Purely additive, safe for a
rolling deploy: an old container never reads or writes it. ``downgrade()`` drops it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c9214f2a6b38"
down_revision: str | None = "b9214c0e5d17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "proposal_holds",
        sa.Column("external_refusal", postgresql.JSONB(), nullable=True),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_column("proposal_holds", "external_refusal", if_exists=True)
