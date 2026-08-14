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
    op.create_check_constraint(
        "ck_agents_schema_version_range",
        "agents",
        "min_schema_version <= max_schema_version",
    )


def downgrade() -> None:
    op.drop_constraint("ck_agents_schema_version_range", "agents", type_="check")
    op.drop_column("agents", "max_schema_version")
    op.drop_column("agents", "min_schema_version")
