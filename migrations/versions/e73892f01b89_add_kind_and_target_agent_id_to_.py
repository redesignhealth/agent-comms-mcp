"""add kind and target_agent_id to approval_holds

Revision ID: e73892f01b89
Revises: 4f6eb79742ec
Create Date: 2026-08-28 00:00:00.000000

TECH-5735: extends the approval_holds pipeline to cover a second kind of
hold. Previously every hold was implicitly a diverted high-risk MESSAGE
(TECH-5389 PR2). This adds an INVITE hold: inviting a participant into a
conversation that already has free-text (`note`) history now requires
human approval too, since `comms_accept` grants full retroactive history
read the moment a participant is admitted -- the exposure is at invite
time, not at any subsequent message send, so a per-message check can
never catch it. For a `kind='invite'` row, `sender_agent_id` holds the
INVITER's agent id (not a message sender), `target_agent_id` holds the
agent being invited, and `message_type`/`schema_version`/`payload` carry
placeholder/contextual values rather than real message content (see
service._divert_invite_for_approval).

``kind`` defaults to ``'message'`` via server_default so every existing row
(all of which are message holds -- this repo has no other hold kind yet)
gets a concrete, correct value with no separate backfill step, matching
this migration chain's a1b2c3d4e5f6 precedent. ``target_agent_id`` is
nullable -- NULL for every message-kind hold, both existing and future.

DEPLOYMENT: safe for a normal rolling deploy, same reasoning as
a1b2c3d4e5f6 -- two plain additive columns (one with a server_default, one
nullable) plus a CHECK constraint that only restricts the NEW column's
values (every existing row's server-defaulted 'message' already satisfies
it). An old container running alongside a migrated schema never reads or
writes ``kind``/``target_agent_id`` and tolerates their presence fine.
``ADD CONSTRAINT`` has no ``IF NOT EXISTS`` in Postgres (same asymmetry
f4a9c1d2b3e7 already documents and accepts for this table's other CHECKs).

Rollback: dropping both columns is safe -- no other table references
``target_agent_id``, and ``kind`` is pure discriminator bookkeeping this
revision itself introduces.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e73892f01b89"
down_revision: str | None = "4f6eb79742ec"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "approval_holds",
        sa.Column(
            "kind",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'message'"),
        ),
        if_not_exists=True,
    )
    op.add_column(
        "approval_holds",
        sa.Column("target_agent_id", sa.UUID(), nullable=True),
        if_not_exists=True,
    )
    op.create_foreign_key(
        "fk_approval_holds_target_agent_id_agents",
        "approval_holds",
        "agents",
        ["target_agent_id"],
        ["id"],
    )
    op.create_check_constraint(
        "ck_approval_holds_kind",
        "approval_holds",
        "kind IN ('message', 'invite')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_approval_holds_kind", "approval_holds", type_="check")
    op.drop_constraint(
        "fk_approval_holds_target_agent_id_agents", "approval_holds", type_="foreignkey"
    )
    op.drop_column("approval_holds", "target_agent_id", if_exists=True)
    op.drop_column("approval_holds", "kind", if_exists=True)
