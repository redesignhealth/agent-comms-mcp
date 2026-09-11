"""add apply_result to proposal_holds

Revision ID: d88cc7e6e21b
Revises: d885dda2ffda
Create Date: 2026-09-09 00:00:00.000000

TECH-5873 follow-up: stores the serialized outcome returned by the
configured ``ProposalJudge.apply()`` implementation -- e.g. identifiers or
URLs for externally created resources, so callers can retrieve metadata once
the request that triggered the apply has returned.

Adds a single nullable JSONB column, ``apply_result``, capturing whatever
a kind-scoped applier returns on a successful apply (e.g. metadata for an
externally created resource) -- see ``service._apply_or_finalize_proposal_hold``.
Set only when the applier actually returns something non-``None``; appliers
that do not emit structured results return ``None``, so this stays unset
(``NULL``) for rows where no result metadata was produced, exactly as it
always has been before this column existed.

Pure additive column, no CHECK constraint, no backfill, no index -- unlike
its two predecessors (``e2f7a91c5b34``/``f3c9a7e2b1d4``, which each widened
a CHECK constraint's allowed value set and therefore needed a
reap-before-narrow step in their own ``downgrade()``), there is no
existing row this migration could ever conflict with: a JSONB column with
no ``NOT NULL``/CHECK constraint accepts every existing row's implicit
``NULL`` with nothing to validate. Safe for a normal rolling deploy in
either direction.

``downgrade()`` just drops the column -- discards any apply results
recorded since this migration's ``upgrade()`` ran (in particular, any
recorded apply metadata), same "downgrading
discards recently-recorded data" tone as ``e2f7a91c5b34``'s own
``downgrade()`` discarding an in-flight ``'applying'`` row's eventual
outcome by force-resolving it to ``'apply_failed'``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d88cc7e6e21b"
down_revision: str | None = "d885dda2ffda"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "proposal_holds",
        sa.Column("apply_result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_column("proposal_holds", "apply_result", if_exists=True)
