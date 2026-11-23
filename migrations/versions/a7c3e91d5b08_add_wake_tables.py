"""add wake tables (TECH-9905)

Revision ID: a7c3e91d5b08
Revises: c9214f2a6b38
Create Date: 2026-11-23 00:00:00.000000

TECH-9905: schema for waking agents when board messages arrive. Four
brand-new tables and nothing else:

- ``wake_rules``: per-agent rules (which messages wake / only poll the agent).
- ``wake_sessions``: per-agent "open conversation" records.
- ``wake_events``: one row per recipient per delivered message or invite.
- ``wake_targets``: per-agent wake address (URL + encrypted secret).

Purely additive, safe for a rolling deploy: no existing reader or writer
touches these tables. ``downgrade()`` drops all four.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a7c3e91d5b08"
down_revision: str | None = "c9214f2a6b38"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts() -> postgresql.TIMESTAMP:
    return postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "wake_rules",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("agent_id", sa.UUID(), nullable=False),
        sa.Column("is_catch_all", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("match_conversation_id", sa.UUID(), nullable=True),
        sa.Column("match_sender_agent_id", sa.UUID(), nullable=True),
        sa.Column("match_message_type", sa.Text(), nullable=True),
        sa.Column("match_task_action", sa.Text(), nullable=True),
        sa.Column("match_message_priority", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("action IN ('wake', 'poll')", name="ck_wake_rules_action"),
        sa.CheckConstraint(
            "(is_catch_all AND match_conversation_id IS NULL "
            "AND match_sender_agent_id IS NULL AND match_message_type IS NULL "
            "AND match_task_action IS NULL AND match_message_priority IS NULL "
            "AND priority = 0 AND enabled) "
            "OR (NOT is_catch_all AND priority >= 1)",
            name="ck_wake_rules_catch_all_shape",
        ),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_wake_rules_agent_id", "wake_rules", ["agent_id"], if_not_exists=True)
    op.create_index(
        "uq_wake_rules_agent_id_catch_all",
        "wake_rules",
        ["agent_id"],
        unique=True,
        postgresql_where=sa.text("is_catch_all"),
        if_not_exists=True,
    )

    op.create_table(
        "wake_sessions",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("agent_id", sa.UUID(), nullable=False),
        sa.Column("conversation_id", sa.UUID(), nullable=False),
        sa.Column("opened_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_activity_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.Column("closed_at", _ts(), nullable=True),
        sa.Column("closed_reason", sa.Text(), nullable=True),
        sa.Column("session_ref", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "closed_reason IS NULL OR closed_reason IN "
            "('quiet', 'agent_closed', 'conversation_ended')",
            name="ck_wake_sessions_closed_reason",
        ),
        sa.CheckConstraint(
            "session_ref IS NULL OR char_length(session_ref) <= 255",
            name="ck_wake_sessions_session_ref_length",
        ),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "agent_id", "conversation_id", name="uq_wake_sessions_agent_id_conversation_id"
        ),
    )

    op.create_table(
        "wake_events",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("recipient_agent_id", sa.UUID(), nullable=False),
        sa.Column("conversation_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=True),
        sa.Column("message_type", sa.Text(), nullable=True),
        sa.Column("sender_agent_id", sa.UUID(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("next_attempt_at", _ts(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("session_ref_sent", sa.Text(), nullable=True),
        sa.Column("created_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.Column("delivered_at", _ts(), nullable=True),
        sa.CheckConstraint("kind IN ('message', 'invite')", name="ck_wake_events_kind"),
        sa.CheckConstraint("reason IN ('rule', 'open_conversation')", name="ck_wake_events_reason"),
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'retry', 'retry_later', 'failed', 'dead')",
            name="ck_wake_events_status",
        ),
        sa.CheckConstraint(
            "(kind = 'message' AND seq IS NOT NULL) OR (kind = 'invite' AND seq IS NULL)",
            name="ck_wake_events_seq_matches_kind",
        ),
        sa.ForeignKeyConstraint(["recipient_agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"]),
        sa.ForeignKeyConstraint(["sender_agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_wake_events_recipient_agent_id_conversation_id_seq",
        "wake_events",
        ["recipient_agent_id", "conversation_id", "seq"],
        unique=True,
        postgresql_where=sa.text("kind = 'message'"),
        if_not_exists=True,
    )
    op.create_index(
        "idx_wake_events_status_next_attempt_at",
        "wake_events",
        ["status", "next_attempt_at"],
        if_not_exists=True,
    )
    op.create_index(
        "idx_wake_events_recipient_agent_id_conversation_id_seq",
        "wake_events",
        ["recipient_agent_id", "conversation_id", "seq"],
        if_not_exists=True,
    )

    op.create_table(
        "wake_targets",
        sa.Column("agent_id", sa.UUID(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("system_label", sa.Text(), nullable=False),
        sa.Column("created_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", _ts(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("agent_id"),
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS wake_targets")
    op.execute("DROP TABLE IF EXISTS wake_events")
    op.execute("DROP TABLE IF EXISTS wake_sessions")
    op.execute("DROP TABLE IF EXISTS wake_rules")
