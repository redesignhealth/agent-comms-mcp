"""proposal_holds composite index for bot-scoped status-filtered listing

Revision ID: b3d4e5f6a7c8
Revises: f3a1b9c7d2e4
Create Date: 2026-09-05 00:00:00.000001

TECH-6018 follow-up (Argus review round-1 BLOCKING catch): backs
``service.list_proposals_for_bot`` (``proposals_list_pending``/
``proposals_list_history`` MCP tools), which queries ``WHERE
proposed_by_bot_id = $1 AND status IN (...) ORDER BY created_at ASC LIMIT
N+1``. The only existing index on this column combination is
``idx_proposal_holds_bot_id_created_at`` (``proposed_by_bot_id,
created_at``, from ``9a1c2d3e4f5b``) -- it has no ``status`` column, so a
bot with a large historical proposal set would force a scan of every one
of its rows to find the handful matching the requested status set. This
mirrors the analogous owner-scoped index
(``idx_proposal_holds_owner_sub_status_created_at``, from
``d23b37d4e187``) that already backs the human-facing
``list_pending_proposal_holds`` the same way.

``9a1c2d3e4f5b``'s own docstring already flagged this: its
``idx_proposal_holds_bot_id_created_at`` comment says it backs
``proposed_by_bot_id``-scoped lookups "e.g. an ops/observability query, or
a future per-bot listing" -- that future listing tool is what this PR
adds, so this index closes the gap that migration anticipated rather than
being a wholly new observation.

Plain (non-concurrent, transactional) ``CREATE INDEX`` -- ``proposal_holds``
is a low-traffic table (no production bot proposal volume yet), same
reasoning ``9a1c2d3e4f5b`` used for its own two indexes, so there's no
lock-contention concern that would call for ``CONCURRENTLY``.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "b3d4e5f6a7c8"
down_revision: str | None = "f3a1b9c7d2e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "idx_proposal_holds_bot_id_status_created_at",
        "proposal_holds",
        ["proposed_by_bot_id", "status", "created_at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_proposal_holds_bot_id_status_created_at",
        table_name="proposal_holds",
        if_exists=True,
    )
