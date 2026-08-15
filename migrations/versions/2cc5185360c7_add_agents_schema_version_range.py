"""add agents min/max schema_version range

Revision ID: 2cc5185360c7
Revises: bb1ea7d2a0cf
Create Date: 2026-08-14 15:00:00.000000

Adds ``agents.min_schema_version``/``agents.max_schema_version``
— the wire-schema version range an agent declares (at ``comms_register``)
that its own code can correctly interpret. The board uses this range to
negotiate a mutually-supported version when ``comms_start_conversation``
opens a new conversation (see ``service._negotiate_schema_version``);
existing agents backfill to ``[1, 1]`` (today's only version) via the
server_default below, so no separate data migration is needed.

Also adds ``idx_messages_sender_id_created_at`` (PR #4):
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
during review (adding the index + the `min_schema_version >= 1` bound)
was therefore safe. Once this PR merges, treat this file as
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
            # sa.text("1"), not a bare "1" string: the
            # codebase convention for an integer server_default (see
            # ef8394b37c8d's last_read_seq -- server_default=sa.text("0"))
            # is a raw-SQL text() default, not a plain Python string, which
            # SQLAlchemy instead treats as a quoted literal.
            server_default=sa.text("1"),
        ),
        if_not_exists=True,
    )
    op.add_column(
        "agents",
        sa.Column(
            "max_schema_version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        if_not_exists=True,
    )
    # >= 1, not just <= max: a 0/negative pair would otherwise pass this
    # constraint and route straight into a broken negotiation (no schema
    # registered below version 1) -- this constraint is security-relevant.
    # NOT guarded with an if_not_exists-equivalent (verified against the
    # actual installed Alembic that create_check_constraint's if_not_exists
    # kwarg does not exist -- it's silently accepted as an unrecognized
    # dialect kwarg with a SAWarning
    # and has zero effect on the emitted DDL -- and Postgres itself has no
    # `ADD CONSTRAINT IF NOT EXISTS` syntax at all to fall back to, unlike
    # DROP CONSTRAINT). This is the same accepted, already-documented
    # asymmetry as 6d2a8e63e469's own two constraint adds (see that file's
    # docstring): upgrade() only ever needs to run from a clean base (this
    # revision has never been applied anywhere -- see the in-place-
    # amendment note above), so there is no partially-upgraded state for
    # this specific step to resume into, unlike downgrade()'s constraint
    # drop above, which real re-run scenarios during this PR's own review
    # cycle actually exercised.
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
    # Every DROP below is guarded (if_exists=True, or raw `DROP ... IF
    # EXISTS` SQL for the constraint, which has no if_exists kwarg at all
    # -- see 6d2a8e63e469's own comment on that exact limitation).
    # Rationale correction: an earlier version of this comment cited
    # "a downgrade that failed partway between these drops" as the
    # motivation -- that premise doesn't hold. migrations/env.py wraps
    # every migration run in context.begin_transaction() plus
    # pg_advisory_xact_lock, so a single `alembic downgrade` invocation's
    # DDL either all commits or all rolls back; Postgres never leaves this
    # table half-downgraded from one run failing midway. The real
    # motivation for guarding every DROP anyway is protection against
    # OUT-OF-BAND DDL drift -- an admin manually dropping one of these
    # columns/the index/the constraint outside Alembic entirely, or an
    # environment whose migration history diverges from what these
    # guards assume -- the same class of drift 6d2a8e63e469's own
    # docstring already names as its reason for guarding every DROP in
    # that migration's downgrade().
    op.drop_index("idx_messages_sender_id_created_at", table_name="messages", if_exists=True)
    op.execute("ALTER TABLE agents DROP CONSTRAINT IF EXISTS ck_agents_schema_version_range")
    op.drop_column("agents", "max_schema_version", if_exists=True)
    op.drop_column("agents", "min_schema_version", if_exists=True)
