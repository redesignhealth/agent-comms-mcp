"""add agents min/max schema_version range

Revision ID: 2cc5185360c7
Revises: bb1ea7d2a0cf
Create Date: 2026-08-14 15:00:00.000000

TECH-5160: adds ``agents.min_schema_version``/``agents.max_schema_version``
— the wire-schema version range an agent declares (at ``comms_register``)
that its own code can correctly interpret. The board uses this range to
negotiate a mutually-supported version when ``comms_start_conversation``
opens a new conversation (see ``service._negotiate_schema_version``);
existing agents backfill to ``[1, 1]`` (today's only version) via the
server_default below, so no separate data migration is needed.

Also adds ``idx_messages_sender_id_created_at`` (Argus round 1, PR #4):
``service._enforce_sender_global_rate_limit``'s ``WHERE sender_id = ... AND
created_at > ...`` query has no ``conversation_id`` predicate, so the
existing ``idx_messages_conversation_id_sender_id_created_at`` index (whose
leading column IS ``conversation_id``) cannot serve it — without this index,
that query sequential-scans ``messages`` on every ``post_message``/
``start_conversation`` call.

NOTE on in-place amendment: like ``18f2d7735523``/``bb1ea7d2a0cf`` before it,
this revision was authored and iterated on entirely within this single
unmerged PR (agent-comms-mcp PR #4) -- it does not exist on `main` and has
never been applied to any persistent or shared database. In-place amendment
during review (adding the index + the `min_schema_version >= 1` bound,
Argus round 1) was therefore safe. Once this PR merges, treat this file as
frozen: any further schema change requires a NEW Alembic revision, never an
edit to this one.

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2cc5185360c7"
down_revision: str | None = "bb1ea7d2a0cf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column(
            "min_schema_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "agents",
        sa.Column(
            "max_schema_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    # >= 1, not just <= max: a 0/negative pair would otherwise pass this
    # constraint and route straight into a broken negotiation (no schema
    # registered below version 1) -- Argus round 1, security.
    op.create_check_constraint(
        "ck_agents_schema_version_range",
        "agents",
        "min_schema_version >= 1 AND min_schema_version <= max_schema_version",
    )
    op.create_index(
        "idx_messages_sender_id_created_at",
        "messages",
        ["sender_id", "created_at"],
        unique=False,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("idx_messages_sender_id_created_at", table_name="messages")
    op.drop_constraint("ck_agents_schema_version_range", "agents", type_="check")
    op.drop_column("agents", "max_schema_version")
    op.drop_column("agents", "min_schema_version")
